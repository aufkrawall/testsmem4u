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
    VerificationProgress progress(ctx, res, region);
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
    const unsigned sides = split ? 2U : 1U;
    RepetitionProgress steps(ctx, uint64_t{sides} * 2);
    for (unsigned side = 0; side < sides && !ctx.shouldStop(); ++side) {
        const MemoryRegion held = split ? (side == 0 ? slice(region, 0, split) :
                                           slice(region, split, region.size - split)) : region;
        const MemoryRegion active = split ? (side == 0 ? slice(region, split, region.size - split) :
                                             slice(region, 0, split)) : slice(region, 0, 0);
        auto* ptr = reinterpret_cast<uint64_t*>(held.base);
        const size_t count = held.size / sizeof(uint64_t);
        TestConfig background;
        background.pattern_mode = 1;
        background.pattern_param1 = 0x9E3779B97F4A7C15ULL;
        // The background cursor persists across dwell windows so short dwells
        // still sweep the whole active half instead of re-testing its start.
        size_t active_cursor = 0;
        bool background_inverted = false;
        for (unsigned polarity = 0; polarity < 2 && !ctx.shouldStop(); ++polarity) {
            const uint64_t pattern = polarity ? ~config.pattern_param0 : config.pattern_param0;
            steps.begin(uint64_t{side} * 2 + polarity);
            simd::generate_pattern_uniform(ptr, count, pattern, true);
            simd::flush_cache_region(ptr, held.size);
            const auto hold_start = now();
            const auto deadline = hold_start + std::chrono::milliseconds(delay_ms);
            testPhase(ctx, "Retention held", held);
            size_t active_chunks = 0;
            size_t active_wraps = 0;
            while (!ctx.shouldStop() && now() < deadline) {
                if (active.size) {
                    // Bound cancellation and deadline overshoot without shrinking
                    // the retention region or adding compute-only work.
                    constexpr size_t chunk_bytes = size_t{2} * 1024 * 1024;
                    const auto chunk = slice(active, active_cursor,
                                             std::min(chunk_bytes, active.size - active_cursor));
                    background.pattern_param0 = background_inverted ? pattern : ~pattern;
                    testPhase(ctx, "Retention active", chunk);
                    progress.mergeNested(runSimpleTest(ctx, chunk, background, stop));
                    ++active_chunks;
                    active_cursor += chunk.size;
                    if (active_cursor >= active.size) {
                        active_cursor = 0;
                        background_inverted = !background_inverted;
                        ++active_wraps;
                    }
                } else {
                    // Sub-cache-line inputs cannot provide a disjoint active
                    // region. Only this tiny-input fallback deliberately idles.
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            if (ctx.shouldStop()) break;
            const double held_seconds = std::chrono::duration<double>(now() - hold_start).count();
            testPhase(ctx, "Retention verify", held);
            simd::flush_cache_region(ptr, held.size);
            const uint64_t errors_before = res.total_errors();
            constexpr size_t block = size_t{256} * 1024;
            for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
                const size_t n = std::min(block, count - i);
                verifyAndReport(held, ptr + i, n, i, 0, pattern, 0, res, ctx, "RefreshStable", stop);
                progress.addBytes(n * sizeof(uint64_t));
            }
            LOG_DEBUG("RefreshStable: held offset=%zu bytes=%zu pattern=0x%016llx dwell=%.3fs "
                      "(min %ums) active chunks=%zu full sweeps=%zu cursor=%zu errors=%llu",
                      held.base_offset_bytes, held.size, static_cast<unsigned long long>(pattern),
                      held_seconds, delay_ms, active_chunks, active_wraps, active_cursor,
                      static_cast<unsigned long long>(res.total_errors() - errors_before));
        }
    }
    return res;
}

TestResult TestEngine::runRandomAccess(TestContext& ctx, const MemoryRegion& region,
                                      const TestConfig& config, bool stop) {
    TestResult res;
    VerificationProgress progress(ctx, res, region);
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    // 64-bit on every target: on 32-bit builds a size_t complement would leave
    // the upper half of each word unflipped in the inverted phase.
    const uint64_t word_start = globalWordStart(region);
    if (!count || ctx.shouldStop()) return res;
    simd::generate_pattern_increment(ptr, count, word_start, true);
    simd::flush_cache_region(ptr, region.size);
    testPhase(ctx, "Random filled", region);
    auto verifyAll = [&]() {
        constexpr size_t block = size_t{256} * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            const size_t n = std::min(block, count - i);
            verifyAndReport(region, ptr + i, n, i, 2, 0, 1, res, ctx, "RandomAccess (Sweep)", stop);
            progress.addBytes(n * sizeof(uint64_t));
        }
    };
    verifyAll();
    // The sweep leaves its most recent lines cached; random reads must see DRAM.
    simd::flush_cache_region(ptr, region.size);
    const auto started = std::chrono::steady_clock::now();
    const uint64_t iterations = randomAccessIterations(config.parameter, count);
    uint64_t state = 0x1234567890ABCDEFULL ^ word_start;
    constexpr size_t lanes = 16;
    std::array<size_t, lanes> indices{};
    std::array<size_t, lanes> band_starts{};
    std::array<size_t, lanes> band_sizes{};
    std::array<void*, lanes> flush_lines{};
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(lanes);
    const size_t width = std::min(lanes, count);
    const size_t band_words = count / width;
    for (size_t lane = 0; lane < width; ++lane) {
        band_starts[lane] = band_words * lane;
        const size_t span = lane + 1 == width ? count - band_starts[lane] : band_words;
        band_sizes[lane] = span;
    }
    testPhase(ctx, "Random checks", region);
    RepetitionProgress steps(ctx, iterations);
    for (uint64_t done = 0; done < iterations && !ctx.shouldStop();) {
        // One relaxed store per 64Ki accesses keeps status updates off the hot path.
        if ((done & 0xFFFF) < width) steps.begin(done);
        const size_t n = static_cast<size_t>(std::min<uint64_t>(width, iterations - done));
        // Disjoint address bands guarantee no duplicate outstanding writes.
        // Independent loads and batched flushes expose memory-level parallelism.
        for (size_t lane = 0; lane < n; ++lane) {
            indices[lane] = band_starts[lane] + randomWord(state) % band_sizes[lane];
            flush_lines[lane] = ptr + indices[lane];
        }
        for (unsigned phase = 0; phase < 3 && !ctx.shouldStop(); ++phase) {
            errors.clear();
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t idx = indices[lane];
                const uint64_t expected = phase == 1 ? ~(word_start + idx) : word_start + idx;
                const uint64_t observed = *static_cast<volatile uint64_t*>(ptr + idx);
#ifdef TESTSMEM4U_TESTING
                if (ctx.phase_hook) ctx.phase_hook("Random observed", region);
#endif
                if (observed != expected) errors.emplace_back(idx, observed);
            }
            if (!errors.empty()) {
                LOG_DEBUG("RandomAccess mismatch: offset=%zu batch-start=%llu phase=%s lanes=%zu samples=%zu",
                          region.base_offset_bytes, static_cast<unsigned long long>(done),
                          phase == 0 ? "original" : phase == 1 ? "inverted" : "restored", n, errors.size());
            }
            classifyAndLogErrors(region, ptr, errors, errors.size(), 0,
                                 [&](size_t idx) { return phase == 1 ? ~(word_start + idx) : word_start + idx; },
                                 res, ctx, "RandomAccess", stop);
            progress.addBytes(n * sizeof(uint64_t));
            if (phase == 2 || ctx.shouldStop()) break;
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t idx = indices[lane];
                ptr[idx] = phase == 0 ? ~(word_start + idx) : word_start + idx;
            }
            simd::flush_cache_lines(flush_lines.data(), n);
        }
        done += n;
    }
    LOG_DEBUG("RandomAccess: offset=%zu words=%zu accesses=%llu (Parameter=%u) lanes=%zu "
              "flush=batch errors=%llu in %.3fs%s",
              region.base_offset_bytes, count, static_cast<unsigned long long>(iterations), config.parameter,
              width,
              static_cast<unsigned long long>(res.total_errors()),
              std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(),
              ctx.shouldStop() ? " [stopped]" : "");
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
    VerificationProgress progress(ctx, res, region);
    const size_t half = count / 2;
    const size_t start = globalWordStart(region);
    const uint64_t step = 0x9E3779B97F4A7C15ULL;
    const uint32_t repeats = config.parameter ? config.parameter : 1;
    constexpr size_t block = size_t{256} * 1024;
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    errors.reserve(128);
    RepetitionProgress steps(ctx, repeats);
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        steps.begin(r);
        const uint64_t pattern = config.pattern_param0 ^ (step * r);
        simd::generate_pattern_linear(ptr, count, pattern, step, true, start);
        simd::flush_cache_region(ptr, region.size);
        for (unsigned direction = 0; direction < 2 && !ctx.shouldStop(); ++direction) {
            auto* source = direction ? ptr + half : ptr;
            auto* destination = direction ? ptr : ptr + half;
            const uint64_t errors_before = res.total_errors();
            if (direction) {
                // Poison the destination so a failed/no-op copy cannot pass.
                simd::generate_pattern_linear(destination, half, ~pattern, step, true, start);
            }
            std::memcpy(destination, source, half * sizeof(uint64_t));
            simd::flush_cache_region(ptr, region.size);
            testPhase(ctx, "Block moved", region);
            for (size_t side = 0; side < 2 && !ctx.shouldStop(); ++side) {
                // Both copies contain the first half's address-dependent data.
                // Error addresses must still identify the actual copy.
                const auto copy = slice(region, side * half * 8, half * 8);
                for (size_t i = 0; i < half && !ctx.shouldStop(); i += block) {
                    const size_t n = std::min(block, half - i);
                    errors.clear();
                    const size_t found = simd::verify_pattern_linear(ptr + side * half + i, n,
                                                                     start + i, pattern, step, errors);
                    classifyAndLogErrors(copy, reinterpret_cast<uint64_t*>(copy.base), errors, found, i,
                                         [&](size_t k) { return pattern + (start + k) * step; },
                                         res, ctx, "BlockMove", stop);
                    progress.addBytes(n * sizeof(uint64_t));
                }
            }
            LOG_DEBUG("BlockMove: offset=%zu words=%zu repeat=%u direction=%s errors=%llu%s",
                      region.base_offset_bytes, count, r, direction ? "upper->lower" : "lower->upper",
                      static_cast<unsigned long long>(res.total_errors() - errors_before),
                      ctx.shouldStop() ? " [stopped]" : "");
        }
        if ((count & 1) && !ctx.shouldStop()) {
            verifyAndReport(region, ptr + count - 1, 1, count - 1, 2, pattern, step,
                            res, ctx, "BlockMove (Tail)", stop);
            progress.addBytes(sizeof(uint64_t));
        }
    }
    return res;
}

} // namespace testsmem4u
