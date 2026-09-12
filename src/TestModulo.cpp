#include "TestEngineInternal.h"

namespace testsmem4u {

TestResult TestEngine::runModulo20(TestContext& ctx, const MemoryRegion& region,
                                  const TestConfig& config, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    constexpr size_t stride = 20;
    constexpr size_t block = 256 * 1024;
    const uint32_t repeats = config.parameter ? config.parameter : 3;
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    for (unsigned polarity = 0; polarity < 2 && !ctx.shouldStop(); ++polarity) {
        const uint64_t pattern = polarity ? ~config.pattern_param0 : config.pattern_param0;
        for (size_t offset = 0; offset < std::min(stride, count) && !ctx.shouldStop(); ++offset) {
            simd::generate_pattern_uniform(ptr, count, pattern, true);
            simd::flush_cache_region(ptr, region.size);
            // Protect every twentieth word while repeatedly writing its peers.
            // No intervening read or write refreshes the protected words.
            for (uint32_t repeat = 0; repeat < repeats && !ctx.shouldStop(); ++repeat) {
                for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                    const size_t end = std::min(count, i + block);
                    for (size_t j = i; j < end; ++j) {
                        if (j % stride != offset) ptr[j] = ~pattern;
                    }
                }
                simd::flush_cache_region(ptr, region.size);
            }
            testPhase(ctx, "Modulo disturbed", region);
            for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                const size_t n = std::min(block, count - i);
                size_t found = 0;
                errors.clear();
                for (size_t j = 0; j < n; ++j) {
                    const uint64_t expected = (i + j) % stride == offset ? pattern : ~pattern;
                    const uint64_t observed = *static_cast<volatile uint64_t*>(ptr + i + j);
                    if (observed != expected) {
                        ++found;
                        if (errors.size() < simd::MAX_ERROR_SAMPLES_PER_BLOCK) errors.emplace_back(j, observed);
                    }
                }
                classifyAndLogErrors(region, ptr, errors, found, i,
                                     [&](size_t j) { return j % stride == offset ? pattern : ~pattern; },
                                     res, ctx, "Modulo20", stop);
                res.bytes_tested += n * sizeof(uint64_t);
            }
        }
    }
    return res;
}

} // namespace testsmem4u
