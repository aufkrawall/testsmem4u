#include "TestEngine.h"
#include "Platform.h"
#include "Logger.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u {

// Static pointer to current TestContext for shutdown handler
static std::atomic<TestContext*> g_current_context{nullptr};

std::vector<uint32_t> parseTestSequence(const std::string& sequence) {
    std::vector<uint32_t> result;
    std::stringstream ss(sequence);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t start = item.find_first_not_of(" \t");
        if (start != std::string::npos) {
            char* endptr = nullptr;
            unsigned long val = std::strtoul(item.c_str() + start, &endptr, 10);
            if (endptr != item.c_str() + start) {
                result.push_back(static_cast<uint32_t>(val));
            }
        }
    }
    if (result.empty()) result.push_back(0);
    return result;
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

size_t TestEngine::verifyAndReport(const MemoryRegion& region, const uint64_t* ptr, size_t count, size_t start_idx,
                                   uint8_t pattern_mode, uint64_t param0, uint64_t param1,
                                   TestResult& res, TestContext& ctx, const std::string& test_name, bool halt_on_error) {
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128); // Pre-allocate small amount

    if (pattern_mode == 0) {
        verify_uniform(ptr, count, param0, errors);
    } else if (pattern_mode == 1) {
        verify_pattern_xor(ptr, count, start_idx, param0, param1, errors);
    } else {
        verify_pattern_linear(ptr, count, start_idx, param0, param1, errors);
    }

    size_t found = errors.size();
    if (found == 0) return 0;

    for (size_t i = 0; i < found; ++i) {
        uint64_t idx = errors[i].first;
        uint64_t first_observed = errors[i].second;
        uint64_t expect;
        generatePatternValue(start_idx + idx, pattern_mode, param0, param1, expect);

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
        
        if (halt_on_error && res.total_errors() > 0) {
            ctx.requestStop();
            break;
        }
    }

    return found;
}

TestResult TestEngine::runSimpleTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    bool use_nt = true;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;

        // Write pattern to memory
        if (config.pattern_mode == 0) {
            generate_pattern_uniform(ptr, count, config.pattern_param0, use_nt);
        } else if (config.pattern_mode == 1) {
            generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
        } else {
            generate_pattern_linear(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
        }

        // CRITICAL: Flush entire region from cache to ensure verification reads from RAM
        // This is essential for detecting real RAM errors vs cache hits
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
    (void)config;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    std::random_device rd;
    std::mt19937_64 rng(rd());

    size_t dense_points = (region.size / (1024 * 1024)) * 2;
    size_t hammer_points = std::min((size_t)100000, dense_points);
    if (hammer_points < 10) hammer_points = 10;
    
    if (config.parameter > 0) hammer_points = config.parameter;

    // Row size varies by DRAM type: DDR4 typically 8KB, DDR5 typically 32KB
    // Use 8KB as base stride (conservative for DDR4)
    // For DDR5, the actual row may be larger but hammering 8KB apart still
    // creates significant stress on adjacent rows
    const size_t row_stride_elements = 8192 / 8;
    const size_t hammer_iterations = 200000;

    if (row_stride_elements * 3 >= count) {
        LOG_WARN("Region too small for RowHammer test");
        return res;
    }

    if (!region.is_large_pages) {
        LOG_WARN("RowHammer test effectiveness is significantly reduced without Large Pages (2MB).");
        LOG_WARN("Try running with Administrator privileges or enable 'Lock Pages in Memory'.");
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

        std::uniform_int_distribution<size_t> hammer_dist(0, count - 3 * row_stride_elements - 1);
        volatile uint64_t* vptr = reinterpret_cast<volatile uint64_t*>(ptr);

        for (size_t i = 0; i < hammer_points && !ctx.shouldStop(); ++i) {
            size_t idxA = hammer_dist(rng);
            size_t idxB = idxA + row_stride_elements;
            size_t idxC = idxA + 2 * row_stride_elements;
            
            if (idxC >= count) continue;

            for (size_t k = 0; k < hammer_iterations && !ctx.shouldStop(); ++k) {
                uint64_t pattern = (k & 1) ? aggr_toggle1 : aggr_toggle0;
                vptr[idxA] = pattern;
                vptr[idxB] = pattern;
                vptr[idxC] = pattern;
                simd::memory_fence();
                simd::flush_cache_line((void*)&vptr[idxA]);
                simd::flush_cache_line((void*)&vptr[idxB]);
                simd::flush_cache_line((void*)&vptr[idxC]);
                simd::memory_fence();
            }

            vptr[idxA] = victim_fill;
            vptr[idxB] = victim_fill;
            vptr[idxC] = victim_fill;
            simd::sfence();
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
    bool use_nt = true;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    size_t block = 256 * 1024;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);

        // Flush cache before verification for true RAM testing
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
        
        // Flush cache before verification
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
        
        // CRITICAL: Flush entire region from cache before verification
        // This ensures we read from DRAM, not CPU cache
        simd::flush_cache_region(ptr, region.size);

        for (size_t i = 0; i + 1 < count; i += 2) {
            if (ctx.shouldStop()) break;

            // Low word check
            uint64_t lo_observed = ptr[i];
            if (lo_observed != config.pattern_param0) {
                // Re-read from DRAM to classify hard vs soft
                uint64_t confirmed = simd::safe_read_u64(&ptr[i]);

                if (confirmed != config.pattern_param0) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (L - Hard)", reportAddress(region, &ptr[i]), config.pattern_param0, confirmed);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (L - Soft)", reportAddress(region, &ptr[i]), config.pattern_param0, lo_observed);
                }

                if (stop && res.total_errors() > 0) {
                    ctx.requestStop();
                    break;
                }
            }

            // High word check
            uint64_t hi_observed = ptr[i+1];
            if (hi_observed != config.pattern_param1) {
                // Re-read from DRAM to classify hard vs soft
                uint64_t confirmed = simd::safe_read_u64(&ptr[i+1]);

                if (confirmed != config.pattern_param1) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (H - Hard)", reportAddress(region, &ptr[i + 1]), config.pattern_param1, confirmed);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (H - Soft)", reportAddress(region, &ptr[i + 1]), config.pattern_param1, hi_observed);
                }

                if (stop && res.total_errors() > 0) {
                    ctx.requestStop();
                    break;
                }
            }
        }

        // Handle odd tail word if region size not divisible by 16 bytes
        if (count % 2 == 1) {
            size_t last = count - 1;
            uint64_t tail_observed = ptr[last];
            if (tail_observed != config.pattern_param0) {
                // Re-read from DRAM to classify hard vs soft
                uint64_t confirmed = simd::safe_read_u64(&ptr[last]);

                if (confirmed != config.pattern_param0) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (Tail - Hard)", reportAddress(region, &ptr[last]), config.pattern_param0, confirmed);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (Tail - Soft)", reportAddress(region, &ptr[last]), config.pattern_param0, tail_observed);
                }

                if (stop) ctx.requestStop();
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

    generate_pattern_uniform(ptr, count, config.pattern_param0, true);

    // CRITICAL: Flush cache BEFORE the delay to ensure data is in DRAM during refresh test
    // If data stays in CPU cache, it's not a valid retention test
    simd::flush_cache_region(ptr, region.size);
    simd::memory_fence();

    std::this_thread::sleep_for(std::chrono::milliseconds(config.parameter > 0 ? config.parameter : 100));
    
    // Flush again before verification to ensure we read from DRAM
    simd::flush_cache_region(ptr, region.size);

    size_t block = 256 * 1024;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
        size_t n = std::min(block, count - i);
        TestEngine::verifyAndReport(region, ptr + i, n, i, 0, config.pattern_param0, 0, res, ctx, "RefreshStable", stop);
        if (stop && ctx.shouldStop()) break;
    }

    res.bytes_tested = region.size;
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
            simd::verify_uniform(ptr + i, n, pattern, errors);
            
            size_t found = errors.size();
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    uint64_t offset = i + errors[k].first;
                    uint64_t first_observed = errors[k].second;
                    // Re-read from DRAM (safe_read_u64 flushes cache internally)
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

// 64-bit maximal-length Fibonacci LFSR (left-shift)
// Primitive polynomial: x^64 + x^63 + x^61 + x^60 + 1
// (reciprocal of the well-known x^64 + x^4 + x^3 + x + 1)
// Recurrence: s_n = s_{n-1} + s_{n-3} + s_{n-4} + s_{n-64}
// Period: 2^64 - 1
static uint64_t lfsr_next(uint64_t val) {
    uint64_t bit = (val ^ (val >> 2) ^ (val >> 3) ^ (val >> 63)) & 1;
    return (val << 1) | bit;
}

TestResult TestEngine::runLFSRPattern(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // Use full 64-bit seed for maximal LFSR period
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    uint64_t seed = initial_seed;

    // Generate pattern using 64-bit LFSR with NT stores to bypass cache
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
    
    // Flush cache for true RAM testing
    simd::flush_cache_region(ptr, region.size);

    // Verify - reset seed and check
    seed = initial_seed;

    for (size_t i = 0; i < count; i += 512) {
        if (ctx.shouldStop()) break;
        size_t n = std::min((size_t)512, count - i);

        // Store expected values BEFORE checking so we can log correct values
        uint64_t expected_values[512];
        uint64_t block_seed = seed;
        for (size_t j = 0; j < n; ++j) {
            expected_values[j] = block_seed;
            block_seed = lfsr_next(block_seed);
        }

        size_t found = 0;
        std::pair<uint64_t, uint64_t> errors[512];
        for (size_t j = 0; j < n; ++j) {
            uint64_t val = ptr[i + j];
            if (val != expected_values[j]) {
                errors[found++] = {j, val};
            }
        }

        if (found > 0) {
            for (size_t k = 0; k < found; ++k) {
                size_t idx = errors[k].first;
                uint64_t first_observed = errors[k].second;
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
            simd::verify_uniform(ptr + i, n, pattern, errors);
            size_t found = errors.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
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
            simd::verify_uniform(ptr + chunk_start, n, inverted, errors);
            size_t found = errors.size();

            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
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
            simd::verify_uniform(ptr + i, n, pattern, errors);
            size_t found = errors.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
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
            simd::verify_uniform(ptr + chunk_start, n, inverted, errors);
            size_t found = errors.size();

            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
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
    
    // Warn on invalid test name (GPT report item: invalid names silently ignored)
    LOG_WARN("Unknown test function name: '%s' - skipping", name.c_str());
    return {};
}

TestResult TestEngine::runMovingInversionLFSR(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    bool early_stop = false;
    
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop() && !early_stop; ++r) {
        // Phase 1: Fill with LFSR pattern using NT stores to bypass cache
        uint64_t seed = initial_seed;
#if defined(__AVX2__)
        {
            simd::SimdCapabilities caps = simd::getCapabilities();
            size_t i = 0;
            if (caps.has_avx2) {
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
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 2: Verify pattern
        seed = initial_seed;
        for (size_t i = 0; i < count && !ctx.shouldStop() && !early_stop; i += 512) {
            size_t n = std::min((size_t)512, count - i);
            
            uint64_t expected[512];
            for (size_t j = 0; j < n; ++j) {
                expected[j] = seed;
                seed = lfsr_next(seed);
            }
            
            for (size_t j = 0; j < n; ++j) {
                uint64_t first_observed = ptr[i+j];
                if (first_observed != expected[j]) {
                    uint64_t actual = simd::safe_read_u64(&ptr[i+j]);
                    if (actual != expected[j]) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Hard)", reportAddress(region, &ptr[i + j]), expected[j], actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Soft)", reportAddress(region, &ptr[i + j]), expected[j], first_observed);
                    }
                    if (stop && res.total_errors() > 0) {
                        ctx.requestStop();
                        early_stop = true;
                        break;
                    }
                }
            }
        }
        
        if (ctx.shouldStop() || early_stop) break;
        
        // Phase 3: Invert
        simd::invert_array(ptr, count, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 4: Verify Inverted
        seed = initial_seed;
        for (size_t i = 0; i < count && !ctx.shouldStop() && !early_stop; i += 512) {
            size_t n = std::min((size_t)512, count - i);
            
            uint64_t expected[512];
            for (size_t j = 0; j < n; ++j) {
                expected[j] = ~seed;
                seed = lfsr_next(seed);
            }
            
            for (size_t j = 0; j < n; ++j) {
                uint64_t first_observed = ptr[i+j];
                if (first_observed != expected[j]) {
                    uint64_t actual = simd::safe_read_u64(&ptr[i+j]);
                    if (actual != expected[j]) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Inv - Hard)", reportAddress(region, &ptr[i + j]), expected[j], actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Inv - Soft)", reportAddress(region, &ptr[i + j]), expected[j], first_observed);
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

    if (count == 0) return res;

    // Phase 1: Fill memory with linear pattern (address = value)
    // Use increment pattern: 0, 1, 2, ...
    simd::generate_pattern_increment(ptr, count, 0, true);
    sfence();
    simd::flush_cache_region(ptr, region.size);

    // Phase 2: Verify initial pattern before random access
    // This ensures we start from a known-good state
    size_t verify_block = 256 * 1024;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += verify_block) {
        size_t n = (std::min)(verify_block, count - i);
        for (size_t j = 0; j < n; ++j) {
            uint64_t expected = i + j;
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
            uint64_t expected = idx;
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
            uint64_t inverted = ~idx;
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
            ptr[idx] = idx;
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
            simd::verify_uniform(dst + i, n, pattern, errors);
            size_t found = errors.size();

            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
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
                simd::verify_uniform(src + i, n, pattern, errors);
                size_t found = errors.size();

                if (found > 0) {
                    for (size_t k = 0; k < found; ++k) {
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

    MemoryRegion region;
    uint64_t needed_bytes = (uint64_t)config.memory_window_mb * 1024 * 1024;
    if (needed_bytes == 0) {
        LOG_ERROR("Configured memory window is 0 MB. Refusing to run an empty RAM test.");
        result.hard_errors = 1;
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
        result.hard_errors = 1;
        return result;
    }

    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.is_locked = guard.is_locked();

    if (region.size < needed_bytes) {
        LOG_ERROR("Allocation contract violated: requested %u MB but got only %zu MB. Aborting.",
                  config.memory_window_mb, region.size / (1024 * 1024));
        result.hard_errors = 1;
        return result;
    }
    if (try_lock && !region.is_locked) {
        LOG_ERROR("Allocation contract violated: requested locked memory but allocation is not locked. Aborting.");
        result.hard_errors = 1;
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
        ss << "  LargePages: " << (region.is_large_pages ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Method:     " << (region.is_large_pages ? "Large Pages" : (region.is_locked ? "VirtualLock/Mlock" : "Standard Malloc (Swappable)"));
        ConsoleDisplay::get().printLine(ss.str());
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
    RunResult result = {};
    TestContext ctx;
    
    // Set up global stop signal for shutdown handler
    g_current_context.store(&ctx, std::memory_order_release);

    uint32_t hw_threads = std::thread::hardware_concurrency();
    if (hw_threads == 0) hw_threads = 1;

    uint32_t threads = config.cores > 0 ? config.cores : hw_threads;
    threads = std::min(threads, hw_threads);
    uint32_t max_threads_for_region = static_cast<uint32_t>(std::max<size_t>(1, region.size / 4096));
    threads = std::min(threads, max_threads_for_region);
    if (threads == 0) threads = 1;

    std::vector<std::thread> workers;

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
            Platform::setThreadAffinity(t, threads);

            size_t chunk = region.size / threads;
            chunk = (chunk / 4096) * 4096;
            size_t offset = t * chunk;
            size_t size = (t == threads - 1) ? (region.size - offset) : chunk;

            MemoryRegion my_region = region;
            my_region.base += offset;
            my_region.size = size;
            my_region.base_offset_bytes += offset;

            uint32_t cycle = 0;
            while ((config.cycles == 0 || cycle < config.cycles) && !ctx.shouldStop()) {
                if (t == 0) {
                    // Verify memory is still resident before each cycle
                    if (!Platform::checkMemoryResident(region.base, region.size)) {
                        LOG_ERROR("FATAL: Memory region is no longer fully resident! "
                                  "RAM may have been reclaimed by the OS. Halting tests.");
                        ConsoleDisplay::get().printError("*** ERROR: Memory lost! OS reclaimed allocated RAM. ***");
                        ConsoleDisplay::get().printError("*** Test results may be unreliable. Stopping. ***");
                        ctx.requestStop();
                        break;
                    }
                    ctx.current_cycle.store(cycle + 1, std::memory_order_release);
                    LOG_INFO("=== Cycle %u Started ===", cycle + 1);
                }

                uint32_t seq_idx = 0;
                for (uint32_t test_id : seq) {

                    if (ctx.shouldStop()) break;
                    if (configs.count(test_id)) {
                        const TestConfig& tc = configs.at(test_id);
                        if (!tc.enabled) {
                            if (t == 0) {
                                ctx.setActiveTestName("Disabled");
                                ctx.current_test_idx.store(++seq_idx, std::memory_order_release);
                                LOG_INFO("Test %u: %s Skipped (disabled)", seq_idx, tc.function.c_str());
                            }
                            continue;
                        }

                        if (t == 0) {
                            ctx.setActiveTestName(tc.function);
                            ctx.current_test_idx.store(++seq_idx, std::memory_order_release);
                            LOG_INFO("Test %u: %s Started", seq_idx, tc.function.c_str());
                        } else {
                            // Non-main threads just increment local counter if needed, or rely on main thread
                        }
                        
                        auto test_start_time = std::chrono::high_resolution_clock::now();

                        uint32_t loops = (config.preset.time_percent * tc.time_percent) / 100;
                        if (loops == 0) loops = 1;

                        for (uint32_t L = 0; L < loops; ++L) {
                            if (ctx.shouldStop()) break;
                            TestResult tr = runRegionWork(ctx, my_region, tc, config.halt_on_error);

                            ctx.total_hard_errors.fetch_add(tr.hard_errors, std::memory_order_relaxed);
                            ctx.total_soft_errors.fetch_add(tr.soft_errors, std::memory_order_relaxed);
                            ctx.total_unverified_errors.fetch_add(tr.unverified_errors, std::memory_order_relaxed);
                            ctx.total_bytes.fetch_add(tr.bytes_tested, std::memory_order_relaxed);

                            if (tr.total_errors() > 0 && config.halt_on_error) {
                                ctx.requestStop();
                                break;
                            }
                        }
                        
                        if (t == 0) {
                             auto test_end_time = std::chrono::high_resolution_clock::now();
                             double elapsed = std::chrono::duration<double>(test_end_time - test_start_time).count();
                             LOG_INFO("Test %u: %s Completed in %.2fs", seq_idx, tc.function.c_str(), elapsed);
                        }
                    }
                }
                
                if (t == 0) {
                     LOG_INFO("=== Cycle %u Completed ===", cycle + 1);
                }
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
    result.cycles_completed = ctx.current_cycle.load(std::memory_order_relaxed);
    result.duration_seconds = std::chrono::duration<double>(end - start).count();

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
