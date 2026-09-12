#include "TestEngineInternal.h"
#include <array>
#include <chrono>
#include <cstring>
#include <thread>

namespace testsmem4u {
namespace {

MemoryRegion slice(const MemoryRegion& region, size_t offset, size_t bytes) {
    MemoryRegion result = region;
    result.base += offset;
    result.base_offset_bytes += offset;
    result.size = bytes;
    return result;
}

uint64_t randomWord(uint64_t& state) {
    uint64_t value = (state += 0x9E3779B97F4A7C15ULL);
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31);
}

} // namespace

TestResult TestEngine::runRefreshStable(TestContext& ctx, const MemoryRegion& region,
                                       const TestConfig& config, bool stop) {
    TestResult res;
    const size_t split = (region.size / 2 / 64) * 64;
    const uint32_t delay_ms = config.parameter ? config.parameter : 100;
    auto now = [&]() {
#ifdef TESTSMEM4U_TESTING
        if (ctx.retention_clock) return ctx.retention_clock();
#endif
        return std::chrono::steady_clock::now();
    };
    // Keep each held half untouched while the other half performs real
    // write/verify tests. Rotate roles so every word receives both polarities.
    for (unsigned side = 0; side < (split ? 2U : 1U) && !ctx.shouldStop(); ++side) {
        const MemoryRegion held = split ? (side == 0 ? slice(region, 0, split) :
                                           slice(region, split, region.size - split)) : region;
        const MemoryRegion active = split ? (side == 0 ? slice(region, split, region.size - split) :
                                             slice(region, 0, split)) : slice(region, 0, 0);
        auto* ptr = reinterpret_cast<uint64_t*>(held.base);
        const size_t count = held.size / sizeof(uint64_t);
        for (unsigned polarity = 0; polarity < 2 && !ctx.shouldStop(); ++polarity) {
            const uint64_t pattern = polarity ? ~config.pattern_param0 : config.pattern_param0;
            simd::generate_pattern_uniform(ptr, count, pattern, true);
            simd::flush_cache_region(ptr, held.size);
            const auto deadline = now() + std::chrono::milliseconds(delay_ms);
            testPhase(ctx, "Retention held", held);
            TestConfig background;
            background.pattern_mode = 1;
            background.pattern_param0 = ~pattern;
            background.pattern_param1 = 0x9E3779B97F4A7C15ULL;
            while (!ctx.shouldStop() && now() < deadline) {
                if (active.size) {
                    // Bound cancellation and deadline overshoot without shrinking
                    // the retention region or adding compute-only work.
                    constexpr size_t chunk_bytes = 2 * 1024 * 1024;
                    for (size_t offset = 0; offset < active.size && !ctx.shouldStop(); offset += chunk_bytes) {
                        const auto chunk = slice(active, offset, std::min(chunk_bytes, active.size - offset));
                        testPhase(ctx, "Retention active", chunk);
                        res.merge(runSimpleTest(ctx, chunk, background, stop));
                        if (now() >= deadline) break;
                    }
                    background.pattern_param0 = ~background.pattern_param0;
                } else {
                    // Sub-cache-line inputs cannot provide a disjoint active
                    // region. Only this tiny-input fallback deliberately idles.
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            if (ctx.shouldStop()) break;
            testPhase(ctx, "Retention verify", held);
            simd::flush_cache_region(ptr, held.size);
            constexpr size_t block = 256 * 1024;
            for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                const size_t n = std::min(block, count - i);
                verifyAndReport(held, ptr + i, n, i, 0, pattern, 0, res, ctx, "RefreshStable", stop);
                res.bytes_tested += n * sizeof(uint64_t);
            }
        }
    }
    return res;
}

TestResult TestEngine::runRandomAccess(TestContext& ctx, const MemoryRegion& region,
                                      const TestConfig& config, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    const size_t word_start = globalWordStart(region);
    if (!count || ctx.shouldStop()) return res;
    simd::generate_pattern_increment(ptr, count, word_start, true);
    simd::flush_cache_region(ptr, region.size);
    testPhase(ctx, "Random filled", region);
    auto verifyAll = [&]() {
        constexpr size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            const size_t n = std::min(block, count - i);
            verifyAndReport(region, ptr + i, n, i, 2, 0, 1, res, ctx, "RandomAccess (Sweep)", stop);
            res.bytes_tested += n * sizeof(uint64_t);
        }
    };
    verifyAll();
    const uint64_t iterations = config.parameter > 100 ? config.parameter :
                               static_cast<uint64_t>(count) * std::max(1U, config.parameter);
    uint64_t state = 0x1234567890ABCDEFULL ^ word_start;
    constexpr size_t lanes = 16;
    std::array<size_t, lanes> indices{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(lanes);
    const size_t width = std::min(lanes, count);
    for (uint64_t done = 0; done < iterations && !ctx.shouldStop();) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(width, iterations - done));
        // Disjoint address bands guarantee no duplicate outstanding writes.
        // Independent loads and batched flushes expose memory-level parallelism.
        for (size_t lane = 0; lane < n; ++lane) {
            const size_t begin = (count / width) * lane;
            const size_t end = lane + 1 == width ? count : begin + count / width;
            indices[lane] = begin + randomWord(state) % (end - begin);
        }
        for (unsigned phase = 0; phase < 3 && !ctx.shouldStop(); ++phase) {
            errors.clear();
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t idx = indices[lane];
                const uint64_t expected = phase == 1 ? ~(word_start + idx) : word_start + idx;
                const uint64_t observed = *static_cast<volatile uint64_t*>(ptr + idx);
                if (observed != expected) errors.emplace_back(idx, observed);
            }
            classifyAndLogErrors(region, ptr, errors, errors.size(), 0,
                                 [&](size_t idx) { return phase == 1 ? ~(word_start + idx) : word_start + idx; },
                                 res, ctx, "RandomAccess", stop);
            res.bytes_tested += n * sizeof(uint64_t);
            if (phase == 2 || ctx.shouldStop()) break;
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t idx = indices[lane];
                ptr[idx] = phase == 0 ? ~(word_start + idx) : word_start + idx;
            }
            for (size_t lane = 0; lane < n; ++lane) simd::flush_cache_line(ptr + indices[lane]);
            simd::memory_fence();
        }
        done += n;
    }
    // Catch damage to non-selected cells and the last restored values too.
    simd::flush_cache_region(ptr, region.size);
    testPhase(ctx, "Random final", region);
    verifyAll();
    return res;
}

TestResult TestEngine::runBlockMove(TestContext& ctx, const MemoryRegion& region,
                                   const TestConfig& config, bool stop) {
    TestResult res;
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    if (count < 2) return runSimpleTest(ctx, region, config, stop);
    const size_t half = count / 2;
    const size_t start = globalWordStart(region);
    const uint64_t step = 0x9E3779B97F4A7C15ULL;
    const uint32_t repeats = config.parameter ? config.parameter : 1;
    constexpr size_t block = 256 * 1024;
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        const uint64_t pattern = config.pattern_param0 ^ (step * r);
        simd::generate_pattern_linear(ptr, count, pattern, step, true, start);
        simd::flush_cache_region(ptr, region.size);
        for (unsigned direction = 0; direction < 2 && !ctx.shouldStop(); ++direction) {
            auto* source = direction ? ptr + half : ptr;
            auto* destination = direction ? ptr : ptr + half;
            if (direction) {
                // Poison the destination so a failed/no-op copy cannot pass.
                simd::generate_pattern_linear(destination, half, ~pattern, step, true, start);
            }
            std::memcpy(destination, source, half * sizeof(uint64_t));
            simd::flush_cache_region(ptr, region.size);
            testPhase(ctx, "Block moved", region);
            for (size_t side = 0; side < 2 && !ctx.shouldStop(); ++side) {
                for (size_t i = 0; i < half && !ctx.shouldStop(); i += block) {
                    const size_t n = std::min(block, half - i);
                    // Both copies contain the first half's address-dependent data.
                    const auto copy = slice(region, side * half * 8, half * 8);
                    // Error addresses must still identify the actual copy.
                    std::vector<std::pair<uint64_t, uint64_t>> errors;
                    const size_t found = simd::verify_pattern_linear(ptr + side * half + i, n,
                                                                     start + i, pattern, step, errors);
                    classifyAndLogErrors(copy, reinterpret_cast<uint64_t*>(copy.base), errors, found, i,
                                         [&](size_t k) { return pattern + (start + k) * step; },
                                         res, ctx, "BlockMove", stop);
                    res.bytes_tested += n * sizeof(uint64_t);
                }
            }
        }
        if ((count & 1) && !ctx.shouldStop()) {
            verifyAndReport(region, ptr + count - 1, 1, count - 1, 2, pattern, step,
                            res, ctx, "BlockMove (Tail)", stop);
            res.bytes_tested += sizeof(uint64_t);
        }
    }
    return res;
}

} // namespace testsmem4u
