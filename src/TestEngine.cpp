#include "TestEngine.h"
#include "Platform.h"
#include "Logger.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include "Utils.h"
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <sstream>
#include <random>
#include <algorithm>
#include <condition_variable>
#include <array>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u {

namespace {

bool isKnownFunctionNameInternal(const std::string& name) {
    return name == "SimpleTest" ||
           name == "MirrorMove" ||
           name == "MirrorMove128" ||
           name == "RefreshStable" ||
           name == "WalkingOnes" ||
           name == "WalkingZeros" ||
           name == "LFSRPattern" ||
           name == "MovingInversion" ||
           name == "MovingInversionLFSR" ||
           name == "MovingInversionWalking" ||
           name == "BlockMove" ||
           name == "RowHammer" ||
           name == "RandomAccess";
}

class ThreadBarrier {
public:
    explicit ThreadBarrier(uint32_t participants)
        : participants_(participants == 0 ? 1 : participants) {}

    void arriveAndWait() {
        std::unique_lock<std::mutex> lock(mutex_);
        const uint32_t generation = generation_;
        if (++arrived_ == participants_) {
            arrived_ = 0;
            generation_++;
            cv_.notify_all();
            return;
        }
        cv_.wait(lock, [&]() { return generation_ != generation; });
    }

private:
    const uint32_t participants_;
    uint32_t arrived_ = 0;
    uint32_t generation_ = 0;
    std::mutex mutex_;
    std::condition_variable cv_;
};

struct WorkerAssignment {
    CpuTarget target;
    size_t offset = 0;
    size_t size = 0;
};

static std::vector<WorkerAssignment> buildWorkerAssignments(const MemoryRegion& region, uint32_t requested_threads) {
    std::vector<CpuTarget> targets = Platform::getPreferredCpuTargets(requested_threads);
    if (targets.empty()) {
        targets.resize(requested_threads == 0 ? 1 : requested_threads);
    }

    if (requested_threads > 0 && targets.size() > requested_threads) {
        targets.resize(requested_threads);
    }

    if (targets.empty()) {
        targets.push_back(CpuTarget{});
    }

    const size_t page_size = 4096;
    const size_t aligned_region_size = (region.size / page_size) * page_size;
    size_t total_pages = aligned_region_size / page_size;
    if (total_pages == 0) total_pages = 1;

    std::vector<WorkerAssignment> assignments(targets.size());
    uint64_t total_weight = 0;
    for (const auto& target : targets) {
        total_weight += std::max<uint32_t>(1, target.weight);
    }
    if (total_weight == 0) total_weight = targets.size();

    size_t assigned_pages = 0;
    size_t running_offset = 0;
    for (size_t i = 0; i < targets.size(); ++i) {
        assignments[i].target = targets[i];
        assignments[i].offset = running_offset;

        size_t pages = 0;
        if (i + 1 == targets.size()) {
            pages = total_pages - assigned_pages;
        } else {
            uint64_t weighted_pages = (static_cast<uint64_t>(total_pages) * std::max<uint32_t>(1, targets[i].weight)) / total_weight;
            pages = static_cast<size_t>(weighted_pages);
            size_t remaining_workers = targets.size() - i;
            size_t remaining_pages = total_pages - assigned_pages;
            if (pages == 0) pages = 1;
            if (pages > remaining_pages - (remaining_workers - 1)) {
                pages = remaining_pages - (remaining_workers - 1);
            }
        }

        assignments[i].size = pages * page_size;
        assigned_pages += pages;
        running_offset += assignments[i].size;
    }

    if (!assignments.empty()) {
        size_t covered = 0;
        for (const auto& assignment : assignments) {
            covered += assignment.size;
        }
        if (covered < region.size) {
            assignments.back().size += region.size - covered;
        }
    }

    return assignments;
}

}

// Static pointer to current TestContext for shutdown handler
static std::atomic<TestContext*> g_current_context{nullptr};
static std::atomic<bool> g_rowhammer_large_page_warning_emitted{false};

std::vector<uint32_t> parseTestSequence(const std::string& sequence) {
    std::vector<uint32_t> result;
    const std::string text = Utils::trim(sequence);
    if (text.empty()) return result;

    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const std::string item = Utils::trim(
            text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (item.empty()) {
            result.clear();
            return result;
        }

        uint32_t parsed = 0;
        if (!Utils::parseUintStrict(item, parsed)) {
            result.clear();
            return result;
        }
        result.push_back(parsed);

        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return result;
}

bool isKnownTestFunctionName(const std::string& name) {
    return isKnownFunctionNameInternal(name);
}

using namespace simd;

// Generate expected pattern value for verification
// mode 0: uniform (val = p0)
// mode 1: XOR pattern (val = p0 ^ (index * p1), wrapping is intentional for address testing)
// mode 2: linear pattern (val = p0 + (index * p1), wrapping is intentional for address testing)
// Note: index * p1 multiplication may overflow 64-bit; this is intentional behavior
// for address line testing where we want to see all bit combinations
static inline void generatePatternValue(uint64_t index, uint8_t mode, uint64_t p0, uint64_t p1, uint64_t& val) {
    if (mode == 0) val = p0;
    else if (mode == 1) val = p0 ^ (index * p1);
    else if (mode == 2) val = p0 + (index * p1);
    else val = index;
}

static inline uint64_t reportAddress(const MemoryRegion& region, const void* ptr) {
    const auto* byte_ptr = static_cast<const uint8_t*>(ptr);
    return static_cast<uint64_t>(region.base_offset_bytes + static_cast<size_t>(byte_ptr - region.base));
}

static inline size_t globalWordStart(const MemoryRegion& region, size_t local_start_idx = 0) {
    return (region.base_offset_bytes / sizeof(uint64_t)) + local_start_idx;
}

static void addUnverifiedOverflow(TestResult& res, size_t total_found, size_t sampled) {
    if (total_found > sampled) {
        res.unverified_errors += static_cast<uint64_t>(total_found - sampled);
    }
}

size_t TestEngine::verifyAndReport(const MemoryRegion& region, const uint64_t* ptr, size_t count, size_t start_idx,
                                   uint8_t pattern_mode, uint64_t param0, uint64_t param1,
                                   TestResult& res, TestContext& ctx, const std::string& test_name, bool halt_on_error,
                                   size_t max_error_samples) {
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(std::min<size_t>(128, max_error_samples));

    const size_t global_start_idx = globalWordStart(region, start_idx);
    size_t found = 0;
    if (pattern_mode == 0) {
        found = verify_uniform(ptr, count, param0, errors, max_error_samples);
    } else if (pattern_mode == 1) {
        found = verify_pattern_xor(ptr, count, global_start_idx, param0, param1, errors, max_error_samples);
    } else {
        found = verify_pattern_linear(ptr, count, global_start_idx, param0, param1, errors, max_error_samples);
    }

    if (found == 0) return 0;

    size_t processed_samples = 0;
    for (size_t i = 0; i < errors.size(); ++i) {
        uint64_t idx = errors[i].first;
        uint64_t first_observed = errors[i].second;
        uint64_t expect;
        generatePatternValue(global_start_idx + idx, pattern_mode, param0, param1, expect);

        // Capture first observed value before the forced re-read so soft errors
        // keep actionable transient-value reporting.
        uint64_t confirmed = simd::safe_read_u64(&ptr[idx]);

        if (confirmed != expect) {
            // Hard Error: Re-read from RAM confirmed the mismatch
            LOG_ERROR_DETAIL((test_name + " (Hard)").c_str(), reportAddress(region, &ptr[idx]), expect, confirmed);
            res.hard_errors++;
        } else {
            // Soft/Transient Error: Initial read failed but RAM now has correct value
            // This indicates a transient bit flip - still a real RAM error.
            uint64_t transient = (first_observed != expect) ? first_observed : confirmed;
            LOG_ERROR_DETAIL((test_name + " (Soft/Transient)").c_str(), reportAddress(region, &ptr[idx]), expect, transient);
            res.soft_errors++;
        }
        ++processed_samples;
        
        if (halt_on_error && res.total_errors() > 0) {
            ctx.requestStop();
            break;
        }
    }

    addUnverifiedOverflow(res, found, processed_samples);
    if (halt_on_error && found > 0) {
        ctx.requestStop();
    }

    return found;
}

TestResult TestEngine::runSimpleTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    size_t word_start = globalWordStart(region);

    bool use_nt = true;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;

        // Write pattern to memory
        if (config.pattern_mode == 0) {
            generate_pattern_uniform(ptr, count, config.pattern_param0, use_nt);
        } else if (config.pattern_mode == 1) {
            generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt, word_start);
        } else {
            generate_pattern_linear(ptr, count, config.pattern_param0, config.pattern_param1, use_nt, word_start);
        }

        simd::flush_cache_region(ptr, region.size);

        // Verify in blocks (2MB chunks)
        size_t block = 256 * 1024;

        for (size_t i = 0; i < count; i += block) {
            if (ctx.shouldStop()) break;
            size_t n = std::min(block, count - i);

            TestEngine::verifyAndReport(region, ptr + i, n, i, config.pattern_mode, config.pattern_param0,
                                        config.pattern_param1, res, ctx, "SimpleTest", stop);

            if (stop && ctx.shouldStop()) break;
        }
    }

    res.bytes_tested = region.size * repeats;
    return res;
}

TestResult TestEngine::runRowHammerTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    std::random_device rd;
    std::mt19937_64 rng(rd());

    size_t dense_points = (region.size / (1024 * 1024)) * 2;
    size_t hammer_points = std::min((size_t)100000, dense_points);
    if (hammer_points < 10) hammer_points = 10;
    
    if (config.parameter > 0) hammer_points = config.parameter;

    const std::array<size_t, 4> row_stride_bytes = {
        8ULL * 1024ULL,
        16ULL * 1024ULL,
        32ULL * 1024ULL,
        64ULL * 1024ULL,
    };
    const size_t hammer_iterations = 200000;

    std::vector<size_t> usable_strides;
    for (size_t stride_bytes : row_stride_bytes) {
        const size_t stride_elements = stride_bytes / sizeof(uint64_t);
        if (stride_elements > 0 && stride_elements * 3 < count) {
            usable_strides.push_back(stride_elements);
        }
    }

    if (usable_strides.empty()) {
        LOG_WARN("Region too small for RowHammer test");
        return res;
    }

    size_t large_page_bytes_in_region = 0;
    if (region.large_page_bytes > region.base_offset_bytes) {
        large_page_bytes_in_region = std::min(region.size, region.large_page_bytes - region.base_offset_bytes);
    }
    if (large_page_bytes_in_region < region.size) {
        bool expected = false;
        if (g_rowhammer_large_page_warning_emitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            LOG_WARN("RowHammer test effectiveness is significantly reduced without full Large Page coverage (2MB pages).");
            LOG_WARN("Try reducing the test size, closing memory-heavy apps, or restarting the system.");
        }
    }

    const uint64_t victim_patterns[2] = { ~0ULL, 0ULL };
    for (int pass = 0; pass < 2 && !ctx.shouldStop(); ++pass) {
        const uint64_t victim_fill  = victim_patterns[pass];
        const uint64_t aggr_toggle0 = ~victim_fill;
        const uint64_t aggr_toggle1 =  victim_fill;

        generate_pattern_uniform(ptr, count, victim_fill, true);
        simd::flush_cache_region(ptr, region.size);

        size_t init_block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += init_block) {
            size_t n = std::min(init_block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 0, victim_fill, 0, res, ctx, "RowHammer (Init)", stop);
            if (stop && ctx.shouldStop()) break;
        }
        if (stop && ctx.shouldStop()) break;

        size_t points_remaining = hammer_points;

        for (size_t stride_index = 0; stride_index < usable_strides.size() && !ctx.shouldStop(); ++stride_index) {
            const size_t row_stride_elements = usable_strides[stride_index];
            const size_t strides_left = usable_strides.size() - stride_index;
            const size_t points_for_stride = std::max<size_t>(1, points_remaining / strides_left);
            points_remaining -= std::min(points_remaining, points_for_stride);
            std::uniform_int_distribution<size_t> hammer_dist(0, count - 3 * row_stride_elements - 1);

            LOG_INFO("RowHammer: Sweeping stride %zu elements (%zu points)",
                     row_stride_elements, points_for_stride);

            for (size_t i = 0; i < points_for_stride && !ctx.shouldStop(); ++i) {
                size_t idxA = hammer_dist(rng);
                size_t idxB = idxA + row_stride_elements;
                size_t idxC = idxA + 2 * row_stride_elements;
                
                if (idxC >= count) continue;

                if (i % 512 == 0) {
                    LOG_DEBUG("RowHammer: Hammering point %zu/%zu (idxA=%zu, idxB=%zu, idxC=%zu, stride=%zu)",
                              i, points_for_stride, idxA, idxB, idxC, row_stride_elements);
                }

                for (size_t k = 0; k < hammer_iterations && !ctx.shouldStop(); ++k) {
                    uint64_t pattern = (k & 1) ? aggr_toggle1 : aggr_toggle0;
#if defined(__x86_64__) || defined(_M_X64)
                    _mm_stream_si64((long long*)&ptr[idxA], (long long)pattern);
                    _mm_stream_si64((long long*)&ptr[idxC], (long long)pattern);
                    _mm_sfence();
#else
                    __atomic_store_n(&ptr[idxA], pattern, __ATOMIC_RELAXED);
                    __atomic_store_n(&ptr[idxC], pattern, __ATOMIC_RELAXED);
                    std::atomic_thread_fence(std::memory_order_release);
#endif
                    simd::flush_cache_line((void*)&ptr[idxA]);
                    simd::flush_cache_line((void*)&ptr[idxC]);
                    simd::memory_fence();
                }

#if defined(__x86_64__) || defined(_M_X64)
                _mm_stream_si64((long long*)&ptr[idxA], (long long)victim_fill);
                _mm_stream_si64((long long*)&ptr[idxC], (long long)victim_fill);
                _mm_sfence();
#else
                __atomic_store_n(&ptr[idxA], victim_fill, __ATOMIC_RELAXED);
                __atomic_store_n(&ptr[idxC], victim_fill, __ATOMIC_RELAXED);
                std::atomic_thread_fence(std::memory_order_release);
#endif
            }
        }

        simd::flush_cache_region(ptr, region.size);
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 0, victim_fill, 0, res, ctx, "RowHammer", stop);
            if (stop && res.total_errors() > 0) break;
        }
    }

    res.bytes_tested = region.size * 2;
    return res;
}

TestResult TestEngine::runMirrorMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    size_t word_start = globalWordStart(region);
    bool use_nt = true;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    size_t block = 256 * 1024;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt, word_start);

        simd::flush_cache_region(ptr, region.size);

        for (size_t i = 0; i < count; i += block) {
            if (ctx.shouldStop()) break;
            size_t n = std::min(block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 1, config.pattern_param0,
                                        config.pattern_param1, res, ctx, "MirrorMove (Init)", stop);
            if (stop && ctx.shouldStop()) break;
        }
        if (stop && ctx.shouldStop()) break;

        invert_array(ptr, count, use_nt);
        sfence();
        
        simd::flush_cache_region(ptr, region.size);

        // Inverted value: ~(param0 ^ (idx * param1)) = (~param0) ^ (idx * param1)
        // This is equivalent to XOR mode (pattern_mode=1) with param0 inverted
        for (size_t i = 0; i < count; i += block) {
            if (ctx.shouldStop()) break;
            size_t n = std::min(block, count - i);

            TestEngine::verifyAndReport(region, ptr + i, n, i, 1, ~config.pattern_param0,
                                        config.pattern_param1, res, ctx, "MirrorMove (Inv)", stop);

            if (stop && ctx.shouldStop()) break;
        }
    }

    res.bytes_tested = region.size * 2 * repeats;
    return res;
}

TestResult TestEngine::runMirrorMove128(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        // Write alternating pattern {param0, param1} using NT stores for true DRAM testing
        {
            size_t i = 0;
#if defined(__AVX512F__)
            if (simd::getCapabilities().has_avx512) {
                __m512i v = _mm512_set_epi64(
                    config.pattern_param1, config.pattern_param0,
                    config.pattern_param1, config.pattern_param0,
                    config.pattern_param1, config.pattern_param0,
                    config.pattern_param1, config.pattern_param0
                );
                for (; i + 8 <= count; i += 8) {
                    _mm512_stream_si512((void*)(ptr + i), v);
                }
            }
#endif
#if defined(__AVX2__)
            if (simd::getCapabilities().has_avx2) {
                __m256i v = _mm256_set_epi64x(
                    config.pattern_param1, config.pattern_param0,
                    config.pattern_param1, config.pattern_param0
                );
                for (; i + 4 <= count; i += 4) {
                    _mm256_stream_si256((__m256i*)(ptr + i), v);
                }
            }
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
            {
                __m128i v = _mm_set_epi64x(config.pattern_param1, config.pattern_param0);
                for (; i + 2 <= count; i += 2) {
                    _mm_stream_si128((__m128i*)(ptr + i), v);
                }
            }
#elif defined(__aarch64__) || defined(_M_ARM64)
            for (; i + 1 < count; i += 2) {
                ptr[i] = config.pattern_param0;
                ptr[i+1] = config.pattern_param1;
            }
#else
            for (; i + 1 < count; i += 2) {
                ptr[i] = config.pattern_param0;
                ptr[i+1] = config.pattern_param1;
            }
#endif
            // Handle odd tail
            if (count % 2 == 1) {
                ptr[count - 1] = config.pattern_param0;
            }
        }
        sfence();
        
        // Flush the region before verification so reads come from DRAM, not CPU cache.
        simd::flush_cache_region(ptr, region.size);

        // Verify using bounded error sampling consistent with other tests.
        // MirrorMove128 uses alternating 128-bit {param0, param1} pairs, so we
        // verify even/odd indices separately against their respective uniform values.
        {
            constexpr size_t VERIFY_BLOCK = 256 * 1024; // elements
            std::vector<std::pair<uint64_t, uint64_t>> errors;
            errors.reserve(128);

            // Verify even indices (param0) in blocks
            for (size_t i = 0; i + 1 < count; i += VERIFY_BLOCK) {
                if (ctx.shouldStop()) break;
                size_t n = std::min(VERIFY_BLOCK, count - i);
                // Scan even positions in this block
                for (size_t j = 0; j < n && j + i + 1 <= count; j += 2) {
                    size_t idx = i + j;
                    uint64_t observed = ptr[idx];
                    if (observed != config.pattern_param0) {
                        uint64_t confirmed = simd::safe_read_u64(&ptr[idx]);
                        if (confirmed != config.pattern_param0) {
                            res.hard_errors++;
                            LOG_ERROR_DETAIL("MirrorMove128 (E - Hard)", reportAddress(region, &ptr[idx]), config.pattern_param0, confirmed);
                        } else {
                            res.soft_errors++;
                            LOG_ERROR_DETAIL("MirrorMove128 (E - Soft)", reportAddress(region, &ptr[idx]), config.pattern_param0, observed);
                        }
                        if (stop && res.total_errors() > 0) { ctx.requestStop(); break; }
                    }
                }
                // Scan odd positions in this block
                for (size_t j = 1; j < n && j + i < count; j += 2) {
                    size_t idx = i + j;
                    uint64_t observed = ptr[idx];
                    if (observed != config.pattern_param1) {
                        uint64_t confirmed = simd::safe_read_u64(&ptr[idx]);
                        if (confirmed != config.pattern_param1) {
                            res.hard_errors++;
                            LOG_ERROR_DETAIL("MirrorMove128 (O - Hard)", reportAddress(region, &ptr[idx]), config.pattern_param1, confirmed);
                        } else {
                            res.soft_errors++;
                            LOG_ERROR_DETAIL("MirrorMove128 (O - Soft)", reportAddress(region, &ptr[idx]), config.pattern_param1, observed);
                        }
                        if (stop && res.total_errors() > 0) { ctx.requestStop(); break; }
                    }
                }
                if (stop && ctx.shouldStop()) break;
            }
        }
    }

    res.bytes_tested = region.size * repeats;
    return res;
}

TestResult TestEngine::runRefreshStable(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    uint32_t delay_ms = config.parameter > 0 ? config.parameter : 100;

    // Test both the configured pattern and its complement for comprehensive
    // DRAM retention coverage. Retention failures can be pattern-dependent.
    const uint64_t patterns[] = { config.pattern_param0, ~config.pattern_param0 };
    const char* phase_names[] = { "RefreshStable", "RefreshStable (Inv)" };

    for (int phase = 0; phase < 2; ++phase) {
        if (ctx.shouldStop()) break;

        uint64_t pattern = patterns[phase];

        generate_pattern_uniform(ptr, count, pattern, true);

        // Flush before the delay so the retention window exercises DRAM rather than CPU cache.
        simd::flush_cache_region(ptr, region.size);
        simd::memory_fence();

        // Sleep in short slices so an async stop (Ctrl+C) is honored promptly.
        // The region is never touched here, so the retention window is preserved.
        for (uint32_t slept = 0; slept < delay_ms && !ctx.shouldStop(); ) {
            uint32_t slice = std::min<uint32_t>(100, delay_ms - slept);
            std::this_thread::sleep_for(std::chrono::milliseconds(slice));
            slept += slice;
        }
        if (ctx.shouldStop()) break;

        // Flush again before verification to ensure we read from DRAM
        simd::flush_cache_region(ptr, region.size);

        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 0, pattern, 0, res, ctx, phase_names[phase], stop);
            if (stop && ctx.shouldStop()) break;
        }
    }

    res.bytes_tested = region.size * 2;
    return res;
}

TestResult TestEngine::runWalkingBit(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop, bool invert) {
    (void)config;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    size_t block = 256 * 1024;

    // Test each bit position
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        // If invert=false (WalkingOnes): pattern = 1 << bit
        // If invert=true (WalkingZeros): pattern = ~(1 << bit)
        uint64_t pattern = 1ULL << bit;
        if (invert) pattern = ~pattern;

        simd::generate_pattern_uniform(ptr, count, pattern, true);
        simd::flush_cache_region(ptr, region.size);

        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            errors.clear();
            size_t found = simd::verify_uniform(ptr + i, n, pattern, errors);
            
            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = i + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);

                    const char* name = invert ? "WalkingZeros" : "WalkingOnes";
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL((std::string(name) + " (Hard)").c_str(), reportAddress(region, &ptr[offset]), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL((std::string(name) + " (Soft)").c_str(), reportAddress(region, &ptr[offset]), pattern, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());
                 
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }

    res.bytes_tested = region.size * 64;
    return res;
}

TestResult TestEngine::runWalkingOnes(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, false);
}

TestResult TestEngine::runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, true);
}

// 64-bit maximal-length Galois LFSR using taps 64, 63, 61, 60.
// The all-zero state is invalid for an LFSR, so callers must seed non-zero.
static uint64_t lfsr_next(uint64_t val) {
    uint64_t lsb = val & 1ULL;
    val >>= 1;
    if (lsb != 0) {
        val ^= 0xD800000000000000ULL;
    }
    return val;
}

#ifdef TESTSMEM4U_TESTING
uint64_t test_lfsr_next(uint64_t val) {
    return lfsr_next(val);
}
#endif

// Shared LFSR write helper: fills ptr[0..count) with LFSR-generated values.
// Uses AVX2 batched NT stores when available, SSE NT stores on x86_64, or
// plain stores as fallback. Returns the final LFSR seed after count iterations.
// Checks ctx.shouldStop() every 0x10000 elements for prompt cancellation.
static uint64_t lfsr_write_pattern(uint64_t* ptr, size_t count, uint64_t seed, TestContext& ctx) {
#if defined(__AVX2__)
    simd::SimdCapabilities caps = simd::getCapabilities();
    size_t i = 0;
    if (caps.has_avx2) {
        // Batch 4 LFSR values into 256-bit AVX2 NT stores for better bandwidth
        for (; i + 4 <= count; i += 4) {
            if ((i & 0xFFFF) == 0 && ctx.shouldStop()) break;
            uint64_t v0 = seed; seed = lfsr_next(seed);
            uint64_t v1 = seed; seed = lfsr_next(seed);
            uint64_t v2 = seed; seed = lfsr_next(seed);
            uint64_t v3 = seed; seed = lfsr_next(seed);
            __m256i vec = _mm256_set_epi64x((long long)v3, (long long)v2, (long long)v1, (long long)v0);
            if (caps.has_nt_stores) {
                _mm256_stream_si256((__m256i*)&ptr[i], vec);
            } else {
                _mm256_storeu_si256((__m256i*)&ptr[i], vec);
            }
        }
    }
    for (; i < count; ++i) {
        if (caps.has_nt_stores) {
            _mm_stream_si64((long long*)&ptr[i], (long long)seed);
        } else {
            ptr[i] = seed;
        }
        seed = lfsr_next(seed);
    }
#elif defined(__x86_64__) || defined(_M_X64)
    for (size_t i = 0; i < count; ++i) {
        if ((i & 0xFFFF) == 0 && ctx.shouldStop()) break;
        _mm_stream_si64((long long*)&ptr[i], (long long)seed);
        seed = lfsr_next(seed);
    }
#else
    for (size_t i = 0; i < count; ++i) {
        if ((i & 0xFFFF) == 0 && ctx.shouldStop()) break;
        ptr[i] = seed;
        seed = lfsr_next(seed);
    }
#endif
    sfence();
    return seed;
}

TestResult TestEngine::runLFSRPattern(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // Use full 64-bit seed for maximal LFSR period
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;

    // Generate pattern using 64-bit LFSR with NT stores to bypass cache
    (void)lfsr_write_pattern(ptr, count, initial_seed, ctx);
    
    // Flush cache for true RAM testing
    simd::flush_cache_region(ptr, region.size);

    // Verify - reset seed and check using pre-allocated buffer
    uint64_t seed = initial_seed;
    constexpr size_t LFSR_BLOCK = 512;
    // Pre-allocate expected buffer once and reuse; 512 * 8 = 4KB fits on stack
    std::array<uint64_t, LFSR_BLOCK> expected_values{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);

    for (size_t i = 0; i < count; i += LFSR_BLOCK) {
        if (ctx.shouldStop()) break;
        size_t n = std::min(LFSR_BLOCK, count - i);

        // Compute expected values for this block
        uint64_t block_seed = seed;
        for (size_t j = 0; j < n; ++j) {
            expected_values[j] = block_seed;
            block_seed = lfsr_next(block_seed);
        }

        // Fast path: compare whole block with memcmp (SIMD-accelerated in libc)
        // Only scan element-by-element on mismatch
        errors.clear();
        if (std::memcmp(ptr + i, expected_values.data(), n * sizeof(uint64_t)) != 0) {
            for (size_t j = 0; j < n; ++j) {
                if (ptr[i + j] != expected_values[j]) {
                    errors.emplace_back(j, ptr[i + j]);
                }
            }
        }

        if (!errors.empty()) {
            for (const auto& err : errors) {
                size_t idx = err.first;
                uint64_t first_observed = err.second;
                // Re-read check for LFSR
                uint64_t actual = simd::safe_read_u64(&ptr[i + idx]);
                
                if (actual != expected_values[idx]) {
                     res.hard_errors++;
                     LOG_ERROR_DETAIL("LFSR (Hard)", reportAddress(region, &ptr[i + idx]), expected_values[idx], actual);
                } else {
                     res.soft_errors++;
                     LOG_ERROR_DETAIL("LFSR (Soft)", reportAddress(region, &ptr[i + idx]), expected_values[idx], first_observed);
                }
            }
            if (stop) {
                ctx.requestStop();
                break;
            }
        }

        // Advance seed for next block
        seed = block_seed;
    }

    res.bytes_tested = region.size;
    return res;
}

// Classic Moving Inversion test (March test algorithm)
// 1. Fill memory with pattern
// 2. Verify pattern
// 3. Invert memory
// 4. Verify inverted pattern
// This stresses RAM by testing both 0->1 and 1->0 transitions at each bit position
TestResult TestEngine::runMovingInversion(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    uint64_t pattern = config.pattern_param0 ? config.pattern_param0 : 0xAAAAAAAAAAAAAAAAULL;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        // Phase 1: Fill with pattern
        generate_pattern_uniform(ptr, count, pattern, true);
        simd::flush_cache_region(ptr, region.size);

        // Phase 2: Verify pattern (forward march)
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        errors.reserve(128);
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            errors.clear();
            size_t found = simd::verify_uniform(ptr + i, n, pattern, errors);
             
            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = i + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Fwd - Hard)", reportAddress(region, &ptr[offset]), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Fwd - Soft)", reportAddress(region, &ptr[offset]), pattern, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());

                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }

        if (ctx.shouldStop()) break;

        // Phase 3: Invert memory
        invert_array(ptr, count, true);
        simd::flush_cache_region(ptr, region.size);

        uint64_t inverted = ~pattern;

        // Phase 4: Verify inverted pattern (backward march for better coverage)
        for (size_t i = count; i > 0 && !ctx.shouldStop(); ) {
            size_t chunk_end = i;
            size_t chunk_start = (i > block) ? (i - block) : 0;
            size_t n = chunk_end - chunk_start;
            i = chunk_start;

            errors.clear();
            size_t found = simd::verify_uniform(ptr + chunk_start, n, inverted, errors);

            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = chunk_start + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != inverted) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Bwd - Hard)", reportAddress(region, &ptr[offset]), inverted, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Bwd - Soft)", reportAddress(region, &ptr[offset]), inverted, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());
                 
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        // Alternate pattern for next iteration
        pattern = ~pattern;
    }
    
    res.bytes_tested = region.size * 2 * repeats;
    return res;
}

TestResult TestEngine::runMovingInversionWalking(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    size_t block = 256 * 1024;

    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        uint64_t pattern = 1ULL << bit;

        // Inline Moving Inversion Logic for this pattern
        // Phase 1: Fill with pattern
        simd::generate_pattern_uniform(ptr, count, pattern, true);
        simd::flush_cache_region(ptr, region.size);

        // Phase 2: Verify pattern (forward march)
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            errors.clear();
            size_t found = simd::verify_uniform(ptr + i, n, pattern, errors);
             
            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = i + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Fwd - Hard)", reportAddress(region, &ptr[offset]), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Fwd - Soft)", reportAddress(region, &ptr[offset]), pattern, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());

                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }

        if (ctx.shouldStop()) break;

        // Phase 3: Invert memory
        simd::invert_array(ptr, count, true);
        simd::flush_cache_region(ptr, region.size);

        uint64_t inverted = ~pattern;

        // Phase 4: Verify inverted pattern (backward march)
        for (size_t i = count; i > 0 && !ctx.shouldStop(); ) {
            size_t chunk_end = i;
            size_t chunk_start = (i > block) ? (i - block) : 0;
            size_t n = chunk_end - chunk_start;
            i = chunk_start;

            errors.clear();
            size_t found = simd::verify_uniform(ptr + chunk_start, n, inverted, errors);

            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = chunk_start + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != inverted) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Bwd - Hard)", reportAddress(region, &ptr[offset]), inverted, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Bwd - Soft)", reportAddress(region, &ptr[offset]), inverted, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());
                 
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }
    }

    res.bytes_tested = region.size * 2 * 64 * repeats;
    return res;
}

TestResult TestEngine::runTest(TestContext& ctx, const std::string& name, const MemoryRegion& region,
                               const TestConfig& config, bool stop) {
    if (name == "SimpleTest") return runSimpleTest(ctx, region, config, stop);
    if (name == "MirrorMove") return runMirrorMove(ctx, region, config, stop);
    if (name == "MirrorMove128") return runMirrorMove128(ctx, region, config, stop);
    if (name == "RefreshStable") return runRefreshStable(ctx, region, config, stop);
    if (name == "WalkingOnes") return runWalkingOnes(ctx, region, config, stop);
    if (name == "WalkingZeros") return runWalkingZeros(ctx, region, config, stop);
    if (name == "LFSRPattern") return runLFSRPattern(ctx, region, config, stop);
    if (name == "MovingInversion") return runMovingInversion(ctx, region, config, stop);
    if (name == "MovingInversionLFSR") return runMovingInversionLFSR(ctx, region, config, stop);
    if (name == "MovingInversionWalking") return runMovingInversionWalking(ctx, region, config, stop);
    if (name == "BlockMove") return runBlockMove(ctx, region, config, stop);
    if (name == "RowHammer") return runRowHammerTest(ctx, region, config, stop);
    if (name == "RandomAccess") return runRandomAccess(ctx, region, config, stop);
    
    ctx.setInfrastructureFailure("Unknown test function in active preset: '" + name + "'");
    LOG_ERROR("Unknown test function name: '%s'", name.c_str());
    return {};
}

TestResult TestEngine::runMovingInversionLFSR(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    bool early_stop = false;
    constexpr size_t LFSR_BLOCK = 512;
    // Pre-allocate expected buffer once and reuse
    std::array<uint64_t, LFSR_BLOCK> expected{};

    // Precompute the LFSR seed at the start of each block once. seed_at_block_start[b]
    // is the LFSR state after b*LFSR_BLOCK iterations. This depends only on
    // initial_seed and count, so it is invariant across repeats and is reused by
    // the Phase 4 backward march (avoids rebuilding an O(count) table every repeat).
    std::vector<uint64_t> seed_at_block_start;
    {
        size_t num_blocks = (count + LFSR_BLOCK - 1) / LFSR_BLOCK;
        seed_at_block_start.resize(num_blocks);
        uint64_t s = initial_seed;
        for (size_t b = 0; b < num_blocks; ++b) {
            seed_at_block_start[b] = s;
            size_t n = std::min(LFSR_BLOCK, count - b * LFSR_BLOCK);
            for (size_t j = 0; j < n; ++j) {
                s = lfsr_next(s);
            }
        }
    }

    for (uint32_t r = 0; r < repeats && !ctx.shouldStop() && !early_stop; ++r) {
        // Phase 1: Fill with LFSR pattern using NT stores to bypass cache
        (void)lfsr_write_pattern(ptr, count, initial_seed, ctx);
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 2: Verify pattern (forward march)
        uint64_t seed = initial_seed;
        for (size_t i = 0; i < count && !ctx.shouldStop() && !early_stop; i += LFSR_BLOCK) {
            size_t n = std::min(LFSR_BLOCK, count - i);
            
            // Compute expected values
            uint64_t block_seed = seed;
            for (size_t j = 0; j < n; ++j) {
                expected[j] = block_seed;
                block_seed = lfsr_next(block_seed);
            }
            
            // Fast path: memcmp whole block before per-element scan
            if (std::memcmp(ptr + i, expected.data(), n * sizeof(uint64_t)) != 0) {
                for (size_t j = 0; j < n; ++j) {
                    if (ptr[i+j] != expected[j]) {
                        uint64_t actual = simd::safe_read_u64(&ptr[i+j]);
                        if (actual != expected[j]) {
                            res.hard_errors++;
                            LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Hard)", reportAddress(region, &ptr[i + j]), expected[j], actual);
                        } else {
                            res.soft_errors++;
                            LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Soft)", reportAddress(region, &ptr[i + j]), expected[j], ptr[i + j]);
                        }
                        if (stop && res.total_errors() > 0) {
                            ctx.requestStop();
                            early_stop = true;
                            break;
                        }
                    }
                }
            }
            seed = block_seed;
        }
        
        if (ctx.shouldStop() || early_stop) break;
        
        // Phase 3: Invert
        simd::invert_array(ptr, count, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 4: Verify Inverted (backward march for better address-line coverage)
        // Uses the precomputed seed_at_block_start table to generate expected
        // values at each backward block start.
        {
            for (size_t i = count; i > 0 && !ctx.shouldStop() && !early_stop; ) {
                size_t chunk_end = i;
                size_t chunk_start = (i > LFSR_BLOCK) ? (i - LFSR_BLOCK) : 0;
                size_t n = chunk_end - chunk_start;
                i = chunk_start;

                // Compute inverted expected values for this block
                size_t block_idx = chunk_start / LFSR_BLOCK;
                uint64_t block_seed = seed_at_block_start[block_idx];
                for (size_t j = 0; j < n; ++j) {
                    expected[j] = ~block_seed;
                    block_seed = lfsr_next(block_seed);
                }

                // Fast path: memcmp whole block before per-element scan
                if (std::memcmp(ptr + chunk_start, expected.data(), n * sizeof(uint64_t)) != 0) {
                    for (size_t j = 0; j < n; ++j) {
                        if (ptr[chunk_start + j] != expected[j]) {
                            uint64_t actual = simd::safe_read_u64(&ptr[chunk_start + j]);
                            if (actual != expected[j]) {
                                res.hard_errors++;
                                LOG_ERROR_DETAIL("MovInvLFSR (Inv - Hard)", reportAddress(region, &ptr[chunk_start + j]), expected[j], actual);
                            } else {
                                res.soft_errors++;
                                LOG_ERROR_DETAIL("MovInvLFSR (Inv - Soft)", reportAddress(region, &ptr[chunk_start + j]), expected[j], ptr[chunk_start + j]);
                            }
                            if (stop && res.total_errors() > 0) {
                                ctx.requestStop();
                                early_stop = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    res.bytes_tested = region.size * 2 * repeats;
    return res;
}


// Xoshiro256** PRNG (fast and high quality)
static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

struct Xoshiro256SS {
    uint64_t s[4];

    Xoshiro256SS(uint64_t seed) {
        // SplitMix64 initialization
        uint64_t z = (seed + 0x9E3779B97F4A7C15ULL);
        for(int i=0; i<4; ++i) {
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            s[i] = z ^ (z >> 31);
            z += 0x9E3779B97F4A7C15ULL;
        }
    }

    uint64_t next() {
        const uint64_t result = rotl(s[1] * 5, 7) * 9;
        const uint64_t t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;
        s[3] = rotl(s[3], 45);

        return result;
    }
};

TestResult TestEngine::runRandomAccess(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8; // Number of uint64_t elements
    size_t word_start = globalWordStart(region);

    if (count == 0) return res;

    // Phase 1: Fill memory with linear pattern (address = value)
    // Use increment pattern: 0, 1, 2, ...
    simd::generate_pattern_increment(ptr, count, word_start, true);
    sfence();
    simd::flush_cache_region(ptr, region.size);

    // Phase 2: Verify initial pattern before random access
    // This ensures we start from a known-good state
    size_t verify_block = 256 * 1024;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += verify_block) {
        size_t n = (std::min)(verify_block, count - i);
        for (size_t j = 0; j < n; ++j) {
            uint64_t expected = word_start + i + j;
            uint64_t actual = ptr[i + j];
            if (actual != expected) {
                // Initial pattern verification failed - memory unstable
                uint64_t reread = simd::safe_read_u64(&ptr[i + j]);
                if (reread != expected) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Init - Hard)", reportAddress(region, &ptr[i + j]), expected, reread);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Init - Soft)", reportAddress(region, &ptr[i + j]), expected, actual);
                }
                if (stop) {
                    ctx.requestStop();
                    res.bytes_tested = (i + j) * 8;
                    return res;
                }
            }
        }
    }

    // Determines duration/intensity
    // Config parameter is usually "Iterations" or "Pass count"
    // If Parameter = 0, default to 1 pass equivalent (count iterations)
    uint64_t iterations = count; 
    if (config.parameter > 0) {
        // If parameter is small (e.g. 1-100), treat as pass count
        if (config.parameter <= 100) iterations = count * config.parameter;
        else iterations = config.parameter; // Treat as explicit count
    }

    uint64_t seed = 0x1234567890ABCDEFULL + (uint64_t)(uintptr_t)ptr; // Unique seed per thread/region
    Xoshiro256SS rng(seed);

    // Bulk Random Access Loop
    // We process in chunks to check for stop flag
    const size_t CHUNK_SIZE = 10000;
    
    for (size_t i = 0; i < iterations; ) {
        if (ctx.shouldStop()) break;
        
        size_t batch = (std::min)(CHUNK_SIZE, (size_t)(iterations - i));
        
        // Random Read-Modify-Write with verification at each step
        for (size_t k = 0; k < batch; ++k) {
            // Generate random index in range [0, count) using fast range reduction
            uint64_t idx;
#if defined(__SIZEOF_INT128__)
            unsigned __int128 r = rng.next();
            idx = (uint64_t)((r * count) >> 64);
#elif defined(_MSC_VER) && defined(_M_X64)
            uint64_t r = rng.next();
            uint64_t high;
            _umul128(r, count, &high);
            idx = high;
#else
            idx = rng.next() % count; // Fallback - has modulo bias but safe
#endif
            
            // Step 1: Verify location contains expected pattern (address = value)
            // This detects read-path errors and any corruption since initialization
            uint64_t expected = word_start + idx;
            uint64_t actual = ptr[idx];
            
            if (actual != expected) {
                // Read-path error detected - classify with re-read
                uint64_t reread_val = simd::safe_read_u64(&ptr[idx]);
                
                if (reread_val != expected) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Read - Hard)", reportAddress(region, &ptr[idx]), expected, reread_val);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Read - Soft)", reportAddress(region, &ptr[idx]), expected, actual);
                }
                // Continue to write test even after read error - don't skip!
            }
            
// Step 2: Write inverted pattern (regardless of read result)
            // This tests the write path
            uint64_t inverted = ~expected;
            ptr[idx] = inverted;
            simd::sfence();
            simd::flush_cache_line((void*)&ptr[idx]);
            simd::memory_fence();
            
            // Step 3: Verify inverted pattern was written correctly
            actual = simd::safe_read_u64(&ptr[idx]);
            if (actual != inverted) {
                res.hard_errors++;
                LOG_ERROR_DETAIL("RandomAccess (WriteCheck - Hard)", reportAddress(region, &ptr[idx]), inverted, actual);
            }
            
            // Step 4: Restore original pattern for next iteration
            ptr[idx] = expected;
            simd::sfence();
            simd::flush_cache_line((void*)&ptr[idx]);
            simd::memory_fence();
            
            if (stop && res.total_errors() > 0) {
                ctx.requestStop();
                break;
            }
        }
        i += batch;
    }

    res.bytes_tested = iterations * 8 * 4; // Read (verify), Read (check), Write, Read (check), Write (approx 4 ops per iteration)
    return res;
}

TestResult TestEngine::runBlockMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    if (count < 2) return res;

    size_t half_count = count / 2;
    uint64_t* src = ptr;
    uint64_t* dst = ptr + half_count;

    uint64_t pattern = config.pattern_param0 ? config.pattern_param0 : 0x5555AAAA5555AAAAULL;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    size_t block = 256 * 1024;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;

        // Fill Src
        simd::generate_pattern_uniform(src, half_count, pattern, true);

        // Move Src -> Dst (non-overlapping regions)
        std::memcpy(dst, src, half_count * 8);
        simd::sfence();
        simd::flush_cache_region(ptr, region.size);

        // Verify Dst
        for (size_t i = 0; i < half_count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, half_count - i);
            errors.clear();
            size_t found = simd::verify_uniform(dst + i, n, pattern, errors);

            if (found > 0) {
                for (size_t k = 0; k < errors.size(); ++k) {
                    uint64_t offset = half_count + i + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("BlockMove (Dst - Hard)", reportAddress(region, &ptr[offset]), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("BlockMove (Dst - Soft)", reportAddress(region, &ptr[offset]), pattern, first_observed);
                    }
                }
                addUnverifiedOverflow(res, found, errors.size());
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }

        // Verify Src (should still be intact)
        if (!ctx.shouldStop()) {
            for (size_t i = 0; i < half_count && !ctx.shouldStop(); i += block) {
                size_t n = std::min(block, half_count - i);
                errors.clear();
                size_t found = simd::verify_uniform(src + i, n, pattern, errors);

                if (found > 0) {
                    for (size_t k = 0; k < errors.size(); ++k) {
                        uint64_t offset = i + errors[k].first;
                        uint64_t first_observed = errors[k].second;
                        uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                        if (actual != pattern) {
                            res.hard_errors++;
                            LOG_ERROR_DETAIL("BlockMove (Src - Hard)", reportAddress(region, &ptr[offset]), pattern, actual);
                        } else {
                            res.soft_errors++;
                            LOG_ERROR_DETAIL("BlockMove (Src - Soft)", reportAddress(region, &ptr[offset]), pattern, first_observed);
                        }
                    }
                    addUnverifiedOverflow(res, found, errors.size());
                    if (stop) {
                        ctx.requestStop();
                        break;
                    }
                }
            }
        }
    }

    res.bytes_tested = region.size * repeats;
    return res;
}

TestResult TestEngine::runRegionWork(TestContext& ctx, const MemoryRegion& region, const TestConfig& test_config,
                                     bool halt_on_error) {
    size_t block_size = (size_t)test_config.block_size_mb * 1024 * 1024;

    if (block_size == 0 || block_size >= region.size) {
        return runTest(ctx, test_config.function, region, test_config, halt_on_error);
    }

    TestResult total = {};
    size_t blocks = (region.size + block_size - 1) / block_size;
    for (size_t i = 0; i < blocks; ++i) {
        if (ctx.shouldStop()) break;
        size_t offset = i * block_size;
        size_t len = std::min(block_size, region.size - offset);

        MemoryRegion sub = region;
        sub.base += offset;
        sub.size = len;
        sub.base_offset_bytes += offset;

        TestResult r = runTest(ctx, test_config.function, sub, test_config, halt_on_error);
        total.merge(r);
        if (total.total_errors() > 0 && halt_on_error) {
            ctx.requestStop();
            break;
        }
    }
    return total;
}

RunResult TestEngine::runTests(const Config& config) {
    RunResult result = {};
    g_rowhammer_large_page_warning_emitted.store(false, std::memory_order_release);

    MemoryRegion region;
    uint64_t needed_bytes = (uint64_t)config.memory_window_mb * 1024 * 1024;
    if (needed_bytes == 0) {
        LOG_ERROR("Configured memory window is 0 MB. Refusing to run an empty RAM test.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "Configured memory window is 0 MB.";
        return result;
    }

    LOG_INFO("Allocating %u MB...", config.memory_window_mb);
    bool try_large = config.use_large_pages;
    bool try_lock = config.use_locked_memory;

    auto prep_start = std::chrono::steady_clock::now();
    std::atomic<bool> prep_done{false};
    std::thread prep_status_thread([&prep_done]() {
        uint64_t seconds = 0;
        while (!prep_done.load(std::memory_order_acquire)) {
            std::ostringstream ss;
            ss << "[Preparation] Optimizing memory layout... " << seconds << "s elapsed";
            ConsoleDisplay::get().updateProgressLine(ss.str());
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++seconds;
        }
    });

    auto guard = Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
    prep_done.store(true, std::memory_order_release);
    if (prep_status_thread.joinable()) prep_status_thread.join();
    auto prep_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - prep_start).count();
    {
        std::ostringstream ss;
        ss << "[Preparation] Completed in " << prep_seconds << "s.";
        ConsoleDisplay::get().printLine(ss.str());
    }

    if (!guard.valid()) {
        LOG_ERROR("Found no suitable memory allocation method. Aborting.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "No suitable memory allocation method succeeded.";
        return result;
    }

    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    if (region.size < needed_bytes) {
        LOG_ERROR("Allocation contract violated: requested %u MB but got only %zu MB. Aborting.",
                  config.memory_window_mb, region.size / (1024 * 1024));
        result.infrastructure_failure = true;
        result.infrastructure_error = "Allocation contract violated: allocator returned fewer bytes than requested.";
        return result;
    }
    if (try_lock && !region.is_locked) {
        LOG_ERROR("Allocation contract violated: requested locked memory but allocation is not locked. Aborting.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "Allocation contract violated: requested locked memory but allocation was not locked.";
        return result;
    }

    ConsoleDisplay::get().printLine("");
    ConsoleDisplay::get().printLine("[Memory Allocation]");
    {
        std::ostringstream ss;
        ss << "  Requested:  " << config.memory_window_mb << " MB";
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Size:       " << (region.size / 1024 / 1024) << " MB";
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Locked:     " << (region.is_locked ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        if (region.large_page_bytes == 0) {
            ss << "  LargePages: No";
        } else if (region.large_page_bytes >= region.size) {
            ss << "  LargePages: Yes (full region)";
        } else {
            ss << "  LargePages: Partial (" << (region.large_page_bytes / 1024 / 1024) << " MB of "
               << (region.size / 1024 / 1024) << " MB)";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        if (region.large_page_bytes >= region.size) {
            ss << "  Method:     Large Pages";
        } else if (region.large_page_bytes > 0 && region.is_locked) {
            ss << "  Method:     Hybrid (Large Pages + Locked Standard Pages)";
        } else if (region.is_locked) {
            ss << "  Method:     VirtualLock/Mlock";
        } else {
            ss << "  Method:     Standard Malloc (Swappable)";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (region.is_locked && region.large_page_bytes < region.size) {
        ConsoleDisplay::get().printLine("  Info:       Testing remains valid with fully locked memory, but full large-page coverage would improve throughput and RowHammer fidelity.");
        ConsoleDisplay::get().printLine("              If you want a full large-page run, try closing memory-heavy apps or restarting Windows before starting the test.");
    }
    ConsoleDisplay::get().printLine("");

    std::string seq_str = config.preset.test_sequence.empty() ? "0" : config.preset.test_sequence;
    std::vector<uint32_t> seq = parseTestSequence(seq_str);

    result = executeSuite(config, region, seq, config.preset.test_configs);

    // guard destructor will free memory
    return result;
}

RunResult TestEngine::executeSuite(const Config& config, const MemoryRegion& region,
                                   const std::vector<uint32_t>& seq,
                                   const std::map<uint32_t, TestConfig>& configs) {
    Platform::confirmNormalProcessPriority();
    RunResult result = {};
    TestContext ctx;
    
    // Set up global stop signal for shutdown handler
    g_current_context.store(&ctx, std::memory_order_release);

    PlatformInfo platform_info = Platform::detectPlatform();
    uint32_t hw_threads = platform_info.cpu_cores;
    if (hw_threads == 0) hw_threads = 1;

    uint32_t threads = config.cores > 0 ? config.cores : hw_threads;
    threads = std::min(threads, hw_threads);
    uint32_t max_threads_for_region = static_cast<uint32_t>(std::max<size_t>(1, region.size / 4096));
    threads = std::min(threads, max_threads_for_region);
    if (threads == 0) threads = 1;

    std::vector<WorkerAssignment> assignments = buildWorkerAssignments(region, threads);
    threads = static_cast<uint32_t>(assignments.size());

    {
        // Report the ISA this binary was compiled to emit (i.e. which variant is
        // running) alongside the CPU's detected capabilities. This makes it easy
        // to confirm that the -v3 (AVX2) / -v4 (AVX-512) optimized binary was
        // actually selected by the auto-relaunch on capable hardware.
#if defined(__AVX512F__)
        const char* built_isa = "AVX-512 (v4)";
#elif defined(__AVX2__)
        const char* built_isa = "AVX2 (v3)";
#else
        const char* built_isa = "SSE2 baseline";
#endif
        const simd::SimdCapabilities caps = simd::getCapabilities();
        LOG_INFO("SIMD: built for %s; CPU supports AVX2=%s AVX-512=%s; worker threads = %u",
                 built_isa,
                 caps.has_avx2 ? "yes" : "no",
                 caps.has_avx512 ? "yes" : "no", threads);
    }

    // Warn if estimated runtime from preset configuration is excessive
    {
        uint64_t total_loop_estimate = 0;
        for (uint32_t test_id : seq) {
            auto it = configs.find(test_id);
            if (it == configs.end()) continue;
            const TestConfig& tc = it->second;
            if (!tc.enabled) continue;
            uint64_t loops = (static_cast<uint64_t>(config.preset.time_percent) * tc.time_percent) / 100;
            if (loops == 0) loops = 1;
            uint64_t internal_reps = tc.parameter > 0 ? tc.parameter : 1;
            total_loop_estimate += loops * internal_reps;
        }
        uint64_t total_cycles = config.cycles == 0 ? 1 : config.cycles;
        total_loop_estimate *= total_cycles;
        constexpr uint64_t kMaxRecommendedLoops = 100000;
        if (total_loop_estimate > kMaxRecommendedLoops) {
            LOG_WARN("Estimated total loops (%llu) exceeds recommended maximum (%llu). "
                     "The preset configuration may produce an extremely long run. "
                     "Consider reducing Time(%%), Parameter, or Cycles values.",
                     (unsigned long long)total_loop_estimate,
                     (unsigned long long)kMaxRecommendedLoops);
        }
    }

    std::vector<std::thread> workers;
    ThreadBarrier barrier(threads);
    // Stop decision latched once per barrier epoch by the leader (t==0) and read
    // by every worker after the barrier, so all workers always perform the same
    // number of barrier arrivals even when an async stop (Ctrl+C) flips the flag
    // mid-loop. Without this, divergent per-thread shouldStop() checks around a
    // barrier could leave some workers waiting on a barrier the others already left.
    std::atomic<bool> epoch_stop{false};

    auto start = std::chrono::high_resolution_clock::now();

    ConsoleDisplay::get().setTestingActive(true);

    std::thread monitor([&]() {
        auto last_update = std::chrono::steady_clock::now();

        while (!ctx.shouldStop()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (ctx.shouldStop()) break;

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() < 500) {
                continue;
            }
            last_update = now;

            StatusInfo info;
            info.cycle = ctx.current_cycle.load(std::memory_order_relaxed);
            info.total_cycles = config.cycles;
            info.test_idx = ctx.current_test_idx.load(std::memory_order_relaxed);
            info.total_tests = seq.size();
            info.test_name = ctx.getActiveTestName();
            info.bytes_tested = ctx.total_bytes.load(std::memory_order_relaxed);
            info.total_bytes = region.size;
            info.errors = ctx.total_hard_errors.load(std::memory_order_relaxed) +
                          ctx.total_soft_errors.load(std::memory_order_relaxed) +
                          ctx.total_unverified_errors.load(std::memory_order_relaxed);
            info.elapsed_seconds = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now - start).count());

            ConsoleDisplay::get().updateStatus(info);
        }
        ConsoleDisplay::get().clearStatus();
    });

    for (uint32_t t = 0; t < threads; ++t) {
        workers.emplace_back([&, t]() {
            const WorkerAssignment& assignment = assignments[t];
            if (!Platform::bindCurrentThread(assignment.target)) {
                LOG_WARN("Worker %u could not bind to target group=%u cpu=%u", t,
                         static_cast<unsigned>(assignment.target.group),
                         static_cast<unsigned>(assignment.target.logical_index));
            }

            MemoryRegion my_region = region;
            my_region.base += assignment.offset;
            my_region.size = assignment.size;
            my_region.base_offset_bytes += assignment.offset;

            uint32_t cycle = 0;
            while (config.cycles == 0 || cycle < config.cycles) {
                if (t == 0) {
                    // Verify memory is still resident before each cycle
                    if (!Platform::checkMemoryResident(region.base, region.size)) {
                        LOG_ERROR("FATAL: Memory region is no longer fully resident! RAM may have been reclaimed by the OS. Halting tests.");
                        ConsoleDisplay::get().printError("*** ERROR: Memory lost! OS reclaimed allocated RAM. ***");
                        ConsoleDisplay::get().printError("*** Test results may be unreliable. Stopping. ***");
                        ctx.setInfrastructureFailure("Memory residency was lost during the test run.");
                    } else {
                        ctx.current_cycle.store(cycle + 1, std::memory_order_release);
                        LOG_INFO("=== Cycle %u Started ===", cycle + 1);
                    }
                    epoch_stop.store(ctx.shouldStop(), std::memory_order_relaxed);
                }
                barrier.arriveAndWait();
                if (epoch_stop.load(std::memory_order_relaxed)) break;

                uint32_t seq_idx = 0;
                for (uint32_t test_id : seq) {
                    if (t == 0) epoch_stop.store(ctx.shouldStop(), std::memory_order_relaxed);
                    barrier.arriveAndWait();

                    if (epoch_stop.load(std::memory_order_relaxed)) break;
                    auto it = configs.find(test_id);
                    if (it == configs.end()) {
                        if (t == 0) {
                            ctx.setInfrastructureFailure("Test Sequence references undefined test ID " + std::to_string(test_id) + ".");
                        }
                        barrier.arriveAndWait();
                        break;
                    }

                    const TestConfig& tc = it->second;
                    if (!tc.enabled) {
                        if (t == 0) {
                            ctx.setActiveTestName("Disabled");
                            ctx.current_test_idx.store(++seq_idx, std::memory_order_release);
                            LOG_INFO("Test %u: %s Skipped (disabled)", seq_idx, tc.function.c_str());
                        }
                        barrier.arriveAndWait();
                        continue;
                    }

                    auto test_start_time = std::chrono::high_resolution_clock::now();
                    if (t == 0) {
                        ctx.setActiveTestName(tc.function);
                        ctx.current_test_idx.store(++seq_idx, std::memory_order_release);
                        LOG_INFO("Test %u: %s Started", seq_idx, tc.function.c_str());
                    }
                    barrier.arriveAndWait();

                    uint64_t loops = (static_cast<uint64_t>(config.preset.time_percent) * tc.time_percent) / 100;
                    if (loops == 0) loops = 1;

                    for (uint64_t L = 0; L < loops; ++L) {
                        if (ctx.shouldStop()) break;
                        TestResult tr = runRegionWork(ctx, my_region, tc, config.halt_on_error);

                        if (ctx.hasInfrastructureFailure()) {
                            break;
                        }

                        ctx.total_hard_errors.fetch_add(tr.hard_errors, std::memory_order_relaxed);
                        ctx.total_soft_errors.fetch_add(tr.soft_errors, std::memory_order_relaxed);
                        ctx.total_unverified_errors.fetch_add(tr.unverified_errors, std::memory_order_relaxed);
                        ctx.total_bytes.fetch_add(tr.bytes_tested, std::memory_order_relaxed);

                        if (tr.total_errors() > 0 && config.halt_on_error) {
                            ctx.requestStop();
                            break;
                        }
                    }

                    barrier.arriveAndWait();
                    if (t == 0) {
                         auto test_end_time = std::chrono::high_resolution_clock::now();
                         double elapsed = std::chrono::duration<double>(test_end_time - test_start_time).count();
                         LOG_INFO("Test %u: %s Completed in %.2fs", seq_idx, tc.function.c_str(), elapsed);
                    }
                }
                barrier.arriveAndWait();
                
                if (t == 0) {
                     if (!ctx.shouldStop()) {
                          ctx.completed_cycles.store(cycle + 1, std::memory_order_release);
                      }
                     LOG_INFO("=== Cycle %u %s ===", cycle + 1, ctx.shouldStop() ? "Stopped" : "Completed");
                }
                barrier.arriveAndWait();
                cycle++;
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    ctx.requestStop();
    if (monitor.joinable()) monitor.join();

    ConsoleDisplay::get().setTestingActive(false);

    auto end = std::chrono::high_resolution_clock::now();
    result.hard_errors = ctx.total_hard_errors.load(std::memory_order_relaxed);
    result.soft_errors = ctx.total_soft_errors.load(std::memory_order_relaxed);
    result.unverified_errors = ctx.total_unverified_errors.load(std::memory_order_relaxed);
    result.bytes_tested = ctx.total_bytes.load(std::memory_order_relaxed);
    result.cycles_completed = ctx.completed_cycles.load(std::memory_order_relaxed);
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    result.infrastructure_failure = ctx.hasInfrastructureFailure();
    result.infrastructure_error = ctx.getInfrastructureFailureMessage();

    // Clear global context pointer before returning
    g_current_context.store(nullptr, std::memory_order_release);

    return result;
}

void TestEngine::requestStop() {
    TestContext* ctx = g_current_context.load(std::memory_order_acquire);
    if (ctx) {
        ctx->requestStop();
    }
}

} // namespace testsmem4u
