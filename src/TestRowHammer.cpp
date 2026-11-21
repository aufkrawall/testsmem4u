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
#include <mutex>
#include <tuple>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

#include "TestEngineInternal.h"
namespace testsmem4u {
using namespace simd;
std::atomic<bool> g_rowhammer_large_page_warning_emitted{false};
namespace {
using RowHammerBudgetKey = std::tuple<uint8_t, uint32_t, uint32_t>;
std::mutex g_rowhammer_budget_mutex;
std::vector<RowHammerBudgetKey> g_rowhammer_budget_keys;
} // namespace

bool claimRowHammerBudgetLog(const TestConfig& config) {
    const RowHammerBudgetKey key{config.test_number, config.parameter, config.block_size_mb};
    std::lock_guard<std::mutex> lock(g_rowhammer_budget_mutex);
    if (g_rowhammer_budget_keys.size() >= kRowHammerBudgetLogLimit ||
        std::find(g_rowhammer_budget_keys.begin(), g_rowhammer_budget_keys.end(), key) !=
            g_rowhammer_budget_keys.end()) {
        return false;
    }
    g_rowhammer_budget_keys.push_back(key);
    return true;
}

void resetRowHammerBudgetLog() {
    std::lock_guard<std::mutex> lock(g_rowhammer_budget_mutex);
    g_rowhammer_budget_keys.clear();
}

TestResult TestEngine::runRowHammerTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    VerificationProgress progress(ctx, res, region);
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    std::random_device rd;
    std::mt19937_64 rng(rd());

    const std::array<size_t, 4> row_stride_bytes = {
        kMinRowHammerStrideBytes,
        size_t{16} * 1024,
        size_t{32} * 1024,
        size_t{64} * 1024,
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
        LOG_ERROR("RowHammer: region size %zu bytes is too small (minimum %zu bytes required for %zu KiB stride)",
                  region.size, kMinRowHammerBytes, kMinRowHammerStrideBytes / 1024);
        ctx.setInfrastructureFailure("RowHammer region is too small (minimum > 24 KiB required).");
        return res;
    }

    const size_t hammer_points = rowHammerPoints(region.size, config.parameter, usable_strides.size());
    if (claimRowHammerBudgetLog(config)) {
        // usable_strides ascends; small (sub-)blocks drop the widest strides.
        LOG_INFO("RowHammer (Test %u): %llu points per GiB%s -> %zu points per invocation on %.1f MiB regions "
                 "(%zu strides of %zu-%zu KiB, %zu iterations per point, both victim polarities)",
                 static_cast<unsigned>(config.test_number),
                 static_cast<unsigned long long>(config.parameter ? config.parameter : kRowHammerDefaultPointsPerGiB),
                 config.parameter ? "" : " (default)", hammer_points,
                 static_cast<double>(region.size) / (1024.0 * 1024.0), usable_strides.size(),
                 usable_strides.front() * sizeof(uint64_t) / 1024, usable_strides.back() * sizeof(uint64_t) / 1024,
                 hammer_iterations);
    }
    const auto hammer_start = std::chrono::steady_clock::now();

    // Allocation-wide coverage measured once by runTests; re-measuring here would
    // walk /proc/self/smaps per worker and invocation on Linux.
    const auto& page_coverage = region.page_coverage;
    if (!page_coverage.full()) {
        bool expected = false;
        if (g_rowhammer_large_page_warning_emitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            LOG_WARN("RowHammer: full large-page coverage of the test allocation is not confirmed (bytes=%zu..%zu of %zu, known=%s). Virtual strides do not establish physical row/bank adjacency.",
                     page_coverage.bytes, page_coverage.possible_bytes, page_coverage.total_bytes, page_coverage.known ? "yes" : "no");
            LOG_WARN("Try reducing the test size, closing memory-heavy apps, or restarting the system.");
        }
    }

    const uint64_t victim_patterns[2] = { ~0ULL, 0ULL };
    RepetitionProgress steps(ctx, uint64_t{2} * hammer_points);
    for (int pass = 0; pass < 2 && !ctx.shouldStop(); ++pass) {
        uint64_t points_started = 0;
        steps.begin(uint64_t(pass) * hammer_points);
        const uint64_t victim_fill  = victim_patterns[pass];
        const uint64_t aggr_toggle0 = ~victim_fill;
        const uint64_t aggr_toggle1 =  victim_fill;

        testPhase(ctx, "RowHammer fill", region);
        generate_pattern_uniform(ptr, count, victim_fill, true);
        simd::flush_after_streaming_fill(ptr, region.size);

        testPhase(ctx, "RowHammer verify initial", region);
        size_t init_block = size_t{256} * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += init_block) {
            size_t n = std::min(init_block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 0, victim_fill, 0, res, ctx, "RowHammer (Init)", stop);
            progress.addBytes(n * sizeof(uint64_t));
            if (stop && ctx.shouldStop()) break;
        }
        if (stop && ctx.shouldStop()) break;

        size_t points_remaining = hammer_points;

        for (size_t stride_index = 0; stride_index < usable_strides.size() && !ctx.shouldStop(); ++stride_index) {
            if (!points_remaining) break;
            const size_t row_stride_elements = usable_strides[stride_index];
            const size_t strides_left = usable_strides.size() - stride_index;
            const size_t points_for_stride = std::max<size_t>(1, points_remaining / strides_left);
            points_remaining -= std::min(points_remaining, points_for_stride);
            std::uniform_int_distribution<size_t> hammer_dist(0, count - 3 * row_stride_elements - 1);

            // Per-stride detail is debug-only: interleaved presets run RowHammer
            // on every chunk several times per cycle (hundreds of lines at INFO).
            LOG_DEBUG("RowHammer: Sweeping stride %zu elements (%zu points)",
                      row_stride_elements, points_for_stride);

            for (size_t i = 0; i < points_for_stride && !ctx.shouldStop(); ++i) {
                steps.begin(uint64_t(pass) * hammer_points + std::min<uint64_t>(points_started++, hammer_points));
                size_t idxA = hammer_dist(rng);
                size_t idxB = idxA + row_stride_elements;
                size_t idxC = idxA + 2 * row_stride_elements;

                if (idxC >= count) continue;

                // A new aggressor may previously have been a victim. Check it
                // before overwriting so later points cannot erase an earlier flip.
                testPhase(ctx, "RowHammer before reuse", region);
                for (size_t idx : {idxA, idxC}) {
                    simd::flush_cache_region(ptr + idx, sizeof(uint64_t));
                    TestEngine::verifyAndReport(region, ptr + idx, 1, idx, 0, victim_fill, 0,
                                                res, ctx, "RowHammer (Before reuse)", stop);
                    progress.addBytes(sizeof(uint64_t));
                    if (ctx.shouldStop()) break;
                }
                if (ctx.shouldStop()) break;

                if (i % 512 == 0) {
                    LOG_DEBUG("RowHammer: Hammering point %zu/%zu (idxA=%zu, idxB=%zu, idxC=%zu, stride=%zu)",
                              i, points_for_stride, idxA, idxB, idxC, row_stride_elements);
                }

                testPhase(ctx, "RowHammer disturb", region);
                std::array<void*, 2> aggressor_lines{ptr + idxA, ptr + idxC};
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
                    simd::flush_cache_lines(aggressor_lines.data(), aggressor_lines.size());
                }

                // Observe the selected victim promptly, before another point
                // can reuse it as an aggressor. The final sweep checks all others.
                testPhase(ctx, "RowHammer victim", region);
                const size_t victim_start = (idxB / 8) * 8;
                const size_t victim_count = std::min<size_t>(8, count - victim_start);
                simd::flush_cache_region(ptr + victim_start, victim_count * sizeof(uint64_t));
                if (!ctx.shouldStop()) {
                    TestEngine::verifyAndReport(region, ptr + victim_start, victim_count, victim_start,
                                                0, victim_fill, 0, res, ctx, "RowHammer (Victim)", stop);
                    progress.addBytes(victim_count * sizeof(uint64_t));
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
        testPhase(ctx, "RowHammer final verify", region);
        size_t block = size_t{256} * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            TestEngine::verifyAndReport(region, ptr + i, n, i, 0, victim_fill, 0, res, ctx, "RowHammer", stop);
            progress.addBytes(n * sizeof(uint64_t));
            if (stop && res.total_errors() > 0) break;
        }
    }

    LOG_DEBUG("RowHammer: region offset=%zu bytes=%zu points=%zu elapsed=%.3fs errors=%llu%s",
              region.base_offset_bytes, region.size, hammer_points,
              std::chrono::duration<double>(std::chrono::steady_clock::now() - hammer_start).count(),
              static_cast<unsigned long long>(res.total_errors()), ctx.shouldStop() ? " [stopped]" : "");
    return res;
}

}
