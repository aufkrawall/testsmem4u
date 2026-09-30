#include "TestEngineInternal.h"
#include "MemoryTestKernels.h"
#include <array>

namespace testsmem4u {

TestResult TestEngine::runModulo20(TestContext& ctx, const MemoryRegion& region,
                                  const TestConfig& config, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    constexpr size_t stride = 20;
    // A multiple of the stride and of every vector/cache-line width: every
    // period-aligned span shares one expected layout, kept in an L1-sized table.
    constexpr size_t period = 1280;
    constexpr size_t block = period * 200;
    static_assert(period % stride == 0 && block % stride == 0, "period must preserve stride phase");
    const uint32_t repeats = config.parameter ? config.parameter : 3;
    alignas(64) std::array<uint64_t, period> expected{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    const auto started = std::chrono::steady_clock::now();
    for (unsigned polarity = 0; polarity < 2 && !ctx.shouldStop(); ++polarity) {
        const uint64_t pattern = polarity ? ~config.pattern_param0 : config.pattern_param0;
        const uint64_t errors_before = res.total_errors();
        for (size_t offset = 0; offset < std::min(stride, count) && !ctx.shouldStop(); ++offset) {
            for (size_t k = 0; k < period; ++k) expected[k] = k % stride == offset ? pattern : ~pattern;
            simd::generate_pattern_uniform(ptr, count, pattern, true);
            simd::flush_cache_region(ptr, region.size);
            // Software never reads or writes the protected word (every twentieth)
            // while it repeatedly writes the complement into its peers. The peers
            // share its cache line, so at the DRAM interface the protected word
            // is fetched with the line and written back with the value that was
            // fetched: this checks that complement writes into the same burst and
            // neighbouring bursts do not disturb it, not that its row stays closed.
            for (uint32_t repeat = 0; repeat < repeats && !ctx.shouldStop(); ++repeat) {
                for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                    const size_t end = std::min(count, i + block);
                    for (size_t base = i; base < end; base += stride) {
                        const size_t protected_idx = base + offset;
                        const size_t span_end = std::min(end, base + stride);
                        std::fill(ptr + base, ptr + std::min(protected_idx, span_end), ~pattern);
                        if (protected_idx + 1 < span_end) std::fill(ptr + protected_idx + 1, ptr + span_end, ~pattern);
                    }
                }
                simd::flush_cache_region(ptr, region.size);
            }
            testPhase(ctx, "Modulo disturbed", region);
            for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                const size_t n = std::min(block, count - i);
                size_t found = 0;
                errors.clear();
                for (size_t sub = 0; sub < n; sub += period) {
                    const size_t sampled_before = errors.size();
                    found += simd::verify_words(ptr + i + sub, expected.data(), std::min(period, n - sub), errors);
                    for (size_t e = sampled_before; e < errors.size(); ++e) errors[e].first += sub;
                }
                classifyAndLogErrors(region, ptr, errors, found, i,
                                     [&](size_t j) { return j % stride == offset ? pattern : ~pattern; },
                                     res, ctx, "Modulo20", stop);
                res.bytes_tested += n * sizeof(uint64_t);
            }
        }
        LOG_DEBUG("Modulo20: offset=%zu words=%zu polarity=%u pattern=0x%016llx repeats=%u errors=%llu%s",
                  region.base_offset_bytes, count, polarity, static_cast<unsigned long long>(pattern), repeats,
                  static_cast<unsigned long long>(res.total_errors() - errors_before),
                  ctx.shouldStop() ? " [stopped]" : "");
    }
    LOG_DEBUG("Modulo20: offset=%zu completed in %.3fs", region.base_offset_bytes,
              std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count());
    return res;
}

} // namespace testsmem4u
