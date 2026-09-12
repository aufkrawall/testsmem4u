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

#include "TestEngineInternal.h"
namespace testsmem4u {
using namespace simd;
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
            res.bytes_tested += n * sizeof(uint64_t);

            if (stop && ctx.shouldStop()) break;
        }
    }

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
            res.bytes_tested += n * sizeof(uint64_t);
            if (stop && ctx.shouldStop()) break;
        }
        if (stop && ctx.shouldStop()) break;

        invert_array(ptr, count, use_nt);

        simd::flush_cache_region(ptr, region.size);

        // Inverted value: ~(param0 ^ (idx * param1)) = (~param0) ^ (idx * param1)
        // This is equivalent to XOR mode (pattern_mode=1) with param0 inverted
        for (size_t i = 0; i < count; i += block) {
            if (ctx.shouldStop()) break;
            size_t n = std::min(block, count - i);

            TestEngine::verifyAndReport(region, ptr + i, n, i, 1, ~config.pattern_param0,
                                        config.pattern_param1, res, ctx, "MirrorMove (Inv)", stop);
            res.bytes_tested += n * sizeof(uint64_t);

            if (stop && ctx.shouldStop()) break;
        }
    }

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

        constexpr size_t VERIFY_BLOCK = 256 * 1024;
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        errors.reserve(128);
        for (unsigned phase = 0; phase < 3 && !ctx.shouldStop(); ++phase) {
            if (phase && count) {
                if (phase == 1) {
                    const uint64_t first = ptr[0];
                    std::memmove(ptr, ptr + 1, (count - 1) * sizeof(uint64_t));
                    ptr[count - 1] = first;
                } else {
                    const uint64_t last = ptr[count - 1];
                    std::memmove(ptr + 1, ptr, (count - 1) * sizeof(uint64_t));
                    ptr[0] = last;
                }
                simd::flush_cache_region(ptr, region.size);
            }
            testPhase(ctx, phase == 1 ? "Mirror128 moved" : "Mirror128 original", region);
            // The wrapped last word is handled separately on an odd-sized region.
            const size_t paired = phase == 1 && (count & 1) ? count - 1 : count;
            const uint64_t even = phase == 1 ? config.pattern_param1 : config.pattern_param0;
            const uint64_t odd = phase == 1 ? config.pattern_param0 : config.pattern_param1;
            for (size_t i = 0; i < paired && !ctx.shouldStop(); i += VERIFY_BLOCK) {
                const size_t n = std::min(VERIFY_BLOCK, paired - i);
                errors.clear();
                const size_t found = simd::verify_pattern_pair(ptr + i, n, even, odd, errors);
                classifyAndLogErrors(region, ptr, errors, found, i,
                                     [&](size_t offset) { return (offset & 1) ? odd : even; },
                                     res, ctx, "MirrorMove128", stop);
                res.bytes_tested += n * sizeof(uint64_t);
            }
            if (paired != count && !ctx.shouldStop()) {
                verifyAndReport(region, ptr + paired, 1, paired, 0, config.pattern_param0, 0,
                                res, ctx, "MirrorMove128 (Tail)", stop);
                res.bytes_tested += sizeof(uint64_t);
            }
        }
    }

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
    const char* name = invert ? "WalkingZeros" : "WalkingOnes";

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
            classifyAndLogErrors(region, ptr, errors, found, i,
                                 [&](size_t) { return pattern; }, res, ctx, name, stop);
            res.bytes_tested += n * sizeof(uint64_t);
        }
    }

    return res;
}

TestResult TestEngine::runWalkingOnes(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, false);
}

TestResult TestEngine::runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, true);
}

}
