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
std::atomic<bool> g_rowhammer_large_page_warning_emitted{false};
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
            res.bytes_tested += n * sizeof(uint64_t);
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

            LOG_INFO("RowHammer: Sweeping stride %zu elements (%zu points)",
                     row_stride_elements, points_for_stride);

            for (size_t i = 0; i < points_for_stride && !ctx.shouldStop(); ++i) {
                size_t idxA = hammer_dist(rng);
                size_t idxB = idxA + row_stride_elements;
                size_t idxC = idxA + 2 * row_stride_elements;

                if (idxC >= count) continue;

                // A new aggressor may previously have been a victim. Check it
                // before overwriting so later points cannot erase an earlier flip.
                for (size_t idx : {idxA, idxC}) {
                    simd::flush_cache_region(ptr + idx, sizeof(uint64_t));
                    TestEngine::verifyAndReport(region, ptr + idx, 1, idx, 0, victim_fill, 0,
                                                res, ctx, "RowHammer (Before reuse)", stop);
                    res.bytes_tested += sizeof(uint64_t);
                    if (ctx.shouldStop()) break;
                }
                if (ctx.shouldStop()) break;

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

                // Observe the selected victim promptly, before another point
                // can reuse it as an aggressor. The final sweep checks all others.
                testPhase(ctx, "RowHammer victim", region);
                const size_t victim_start = (idxB / 8) * 8;
                const size_t victim_count = std::min<size_t>(8, count - victim_start);
                simd::flush_cache_region(ptr + victim_start, victim_count * sizeof(uint64_t));
                if (!ctx.shouldStop()) {
                    TestEngine::verifyAndReport(region, ptr + victim_start, victim_count, victim_start,
                                                0, victim_fill, 0, res, ctx, "RowHammer (Victim)", stop);
                    res.bytes_tested += victim_count * sizeof(uint64_t);
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
            res.bytes_tested += n * sizeof(uint64_t);
            if (stop && res.total_errors() > 0) break;
        }
    }

    return res;
}

}
