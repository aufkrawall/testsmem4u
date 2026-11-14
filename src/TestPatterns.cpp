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

    const uint64_t global_start_idx = globalWordStart(region, start_idx);
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
    VerificationProgress progress(ctx, res, region);
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    const uint64_t word_start = globalWordStart(region);

    bool use_nt = true;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    RepetitionProgress steps(ctx, repeats);
    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        steps.begin(r);

        testPhase(ctx, "Simple fill", region);
        // Uniform patterns are explicit test values; address patterns get a new
        // offset per pass/repetition (the first repetition of pass 0 is unchanged).
        const uint64_t param0 = config.pattern_mode == 0 ? config.pattern_param0
                                                         : config.pattern_param0 ^ variationMask(config.variation, r);
        // Mode 3 varies its address tag instead of Param0, keeping the configured
        // even/odd (and 32-bit half) complement relations on every pass.
        const BeatPattern beat = simpleBeatPattern(config, r);
        if (config.pattern_mode == 0) {
            generate_pattern_uniform(ptr, count, param0, use_nt);
        } else if (config.pattern_mode == 1) {
            generate_pattern_xor(ptr, count, param0, config.pattern_param1, use_nt, word_start);
        } else if (config.pattern_mode == kPatternModeBeat) {
            generate_pattern_beat(ptr, count, beat, word_start, use_nt);
        } else {
            generate_pattern_linear(ptr, count, param0, config.pattern_param1, use_nt, word_start);
        }

        simd::flush_after_streaming_fill(ptr, region.size);

        testPhase(ctx, "Simple filled", region);
        testPhase(ctx, "Simple verify", region);

        // Verify in blocks (2MB chunks)
        size_t block = size_t{256} * 1024;

        for (size_t i = 0; i < count; i += block) {
            if (ctx.shouldStop()) break;
            size_t n = std::min(block, count - i);

            if (config.pattern_mode == kPatternModeBeat) {
                verifyBeatAndReport(region, ptr, i, n, beat, res, ctx, "SimpleTest", stop);
            } else {
                TestEngine::verifyAndReport(region, ptr + i, n, i, config.pattern_mode, param0,
                                            config.pattern_param1, res, ctx, "SimpleTest", stop);
            }
            progress.addBytes(n * sizeof(uint64_t));

            if (stop && ctx.shouldStop()) break;
        }
    }

    return res;
}

TestResult TestEngine::runWalkingBit(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop, bool invert) {
    (void)config;
    TestResult res = {};
    VerificationProgress progress(ctx, res, region);
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    size_t block = size_t{256} * 1024;
    const char* name = invert ? "WalkingZeros" : "WalkingOnes";

    // Test each bit position
    RepetitionProgress steps(ctx, 64);
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        steps.begin(static_cast<uint64_t>(bit));
        // If invert=false (WalkingOnes): pattern = 1 << bit
        // If invert=true (WalkingZeros): pattern = ~(1 << bit)
        uint64_t pattern = 1ULL << bit;
        if (invert) pattern = ~pattern;

        testPhase(ctx, "Walking fill", region);
        simd::generate_pattern_uniform(ptr, count, pattern, true);
        simd::flush_after_streaming_fill(ptr, region.size);
        testPhase(ctx, "Walking verify", region);

        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            errors.clear();
            size_t found = simd::verify_uniform(ptr + i, n, pattern, errors);
            classifyAndLogErrors(region, ptr, errors, found, i,
                                 [&](size_t) { return pattern; }, res, ctx, name, stop);
            progress.addBytes(n * sizeof(uint64_t));
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
