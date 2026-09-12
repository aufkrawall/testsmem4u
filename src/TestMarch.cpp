#include "TestEngineInternal.h"
#include "MemoryTestKernels.h"
#include <array>

namespace testsmem4u {
namespace {

constexpr size_t march_words = 512;

// A march has already overwritten the cell. Re-reading it cannot classify the
// original mismatch as persistent/transient; preserve and count the observation.
void reportMarchErrors(const MemoryRegion& region, uint64_t* ptr, size_t offset,
                       const uint64_t* expected,
                       const std::vector<std::pair<uint64_t, uint64_t>>& errors,
                       size_t found, TestResult& res, TestContext& ctx, bool stop) {
    res.unverified_errors += found;
    for (const auto& error : errors) {
        LOG_ERROR_DETAIL("March (observed before overwrite)",
                         reportAddress(region, ptr + offset + error.first),
                         expected[error.first], error.second);
    }
    if (found && stop) ctx.requestStop();
}

TestResult runMarch(TestContext& ctx, const MemoryRegion& region,
                    uint64_t seed, bool lfsr, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    std::array<uint64_t, march_words> expected{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    uint64_t end_seed = seed;
    if (lfsr) {
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += march_words) {
            const size_t n = std::min(march_words, count - i);
            for (size_t j = 0; j < n; ++j) {
                ptr[i + j] = end_seed;
                end_seed = simd::lfsrNext(end_seed);
            }
        }
    } else {
        simd::generate_pattern_uniform(ptr, count, seed, true);
    }
    simd::flush_cache_region(ptr, count * sizeof(uint64_t));
    testPhase(ctx, "March filled", region);

    // Forward read/write complement, backward read/write original, final read.
    // Direction applies inside each SIMD block as well as between blocks.
    for (int phase = 0; phase < 3 && !ctx.shouldStop(); ++phase) {
        uint64_t state = phase == 1 ? end_seed : seed;
        for (size_t done = 0; done < count && !ctx.shouldStop(); done += march_words) {
            const size_t n = std::min(march_words, count - done);
            const size_t offset = phase == 1 ? count - done - n : done;
            for (size_t j = 0; j < n; ++j) {
                if (!lfsr) {
                    expected[j] = phase == 1 ? ~seed : seed;
                } else if (phase == 1) {
                    state = simd::lfsrPrevious(state);
                    expected[n - j - 1] = ~state;
                } else {
                    expected[j] = state;
                    state = simd::lfsrNext(state);
                }
            }
            errors.clear();
            const size_t found = simd::verify_words(ptr + offset, expected.data(), n,
                                                     errors, phase != 2, phase == 1);
            if (phase != 2) {
                reportMarchErrors(region, ptr, offset, expected.data(), errors, found, res, ctx, stop);
            } else {
                classifyAndLogErrors(region, ptr, errors, found, offset,
                                     [&](size_t k) { return expected[k - offset]; },
                                     res, ctx, "March (Final)", stop);
            }
            res.bytes_tested += n * sizeof(uint64_t);
        }
        simd::flush_cache_region(ptr, count * sizeof(uint64_t));
        testPhase(ctx, phase == 0 ? "March inverted" : "March restored", region);
    }
    return res;
}

} // namespace

#ifdef TESTSMEM4U_TESTING
uint64_t test_lfsr_next(uint64_t value) { return simd::lfsrNext(value); }
#endif

TestResult TestEngine::runMovingInversion(TestContext& ctx, const MemoryRegion& region,
                                         const TestConfig& config, bool stop) {
    TestResult res;
    uint64_t pattern = config.pattern_param0;
    const uint32_t repeats = config.parameter ? config.parameter : 1;
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        res.merge(runMarch(ctx, region, pattern, false, stop));
        pattern = ~pattern;
    }
    return res;
}

TestResult TestEngine::runMovingInversionWalking(TestContext& ctx, const MemoryRegion& region,
                                                const TestConfig& config, bool stop) {
    TestResult res;
    const uint32_t repeats = config.parameter ? config.parameter : 1;
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        for (unsigned bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
            res.merge(runMarch(ctx, region, 1ULL << bit, false, stop));
        }
    }
    return res;
}

TestResult TestEngine::runMovingInversionLFSR(TestContext& ctx, const MemoryRegion& region,
                                             const TestConfig& config, bool stop) {
    TestResult res;
    const uint64_t seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    const uint32_t repeats = config.parameter ? config.parameter : 1;
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        res.merge(runMarch(ctx, region, seed, true, stop));
    }
    return res;
}

TestResult TestEngine::runLFSRPattern(TestContext& ctx, const MemoryRegion& region,
                                    const TestConfig& config, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    const uint64_t seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    uint64_t state = seed;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += march_words) {
        const size_t n = std::min(march_words, count - i);
        for (size_t j = 0; j < n; ++j) {
            ptr[i + j] = state;
            state = simd::lfsrNext(state);
        }
    }
    simd::flush_cache_region(ptr, count * sizeof(uint64_t));
    testPhase(ctx, "LFSR filled", region);
    state = seed;
    std::array<uint64_t, march_words> expected{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += march_words) {
        const size_t n = std::min(march_words, count - i);
        for (size_t j = 0; j < n; ++j) {
            expected[j] = state;
            state = simd::lfsrNext(state);
        }
        errors.clear();
        const size_t found = simd::verify_words(ptr + i, expected.data(), n, errors);
        classifyAndLogErrors(region, ptr, errors, found, i,
                             [&](size_t k) { return expected[k - i]; }, res, ctx, "LFSR", stop);
        res.bytes_tested += n * sizeof(uint64_t);
    }
    return res;
}

} // namespace testsmem4u
