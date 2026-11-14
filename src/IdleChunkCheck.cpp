#include "IdleChunkCheck.h"
#include "TestEngineInternal.h"
#include <algorithm>
#include <cstdio>

namespace testsmem4u {

void IdleCheckStats::recordCheck(double idle_seconds, uint64_t bytes, uint64_t errors) noexcept {
    const uint64_t idle_ms = static_cast<uint64_t>(std::max(0.0, idle_seconds) * 1000.0);
    checks_.fetch_add(1, std::memory_order_relaxed);
    bytes_.fetch_add(bytes, std::memory_order_relaxed);
    errors_.fetch_add(errors, std::memory_order_relaxed);
    idle_ms_total_.fetch_add(idle_ms, std::memory_order_relaxed);
    uint64_t seen = idle_ms_max_.load(std::memory_order_relaxed);
    while (idle_ms > seen && !idle_ms_max_.compare_exchange_weak(seen, idle_ms, std::memory_order_relaxed)) {
    }
    seen = idle_ms_min_.load(std::memory_order_relaxed);
    while (idle_ms < seen && !idle_ms_min_.compare_exchange_weak(seen, idle_ms, std::memory_order_relaxed)) {
    }
}

std::string IdleCheckStats::summary() const {
    const uint64_t checks = checks_.load(std::memory_order_relaxed);
    char line[256];
    if (!checks) {
        std::snprintf(line, sizeof(line), "Idle-chunk checks: none (skipped without idle time: %llu)",
                      static_cast<unsigned long long>(skipped()));
        return line;
    }
    std::snprintf(line, sizeof(line),
                  "Idle-chunk checks: %llu chunks re-verified before reuse, %.2f GiB, idle min/avg/max "
                  "%.1f/%.1f/%.1f s, errors=%llu (skipped without idle time: %llu)",
                  static_cast<unsigned long long>(checks),
                  static_cast<double>(bytes_.load(std::memory_order_relaxed)) / (1024.0 * 1024.0 * 1024.0),
                  static_cast<double>(idle_ms_min_.load(std::memory_order_relaxed)) / 1000.0,
                  static_cast<double>(idle_ms_total_.load(std::memory_order_relaxed)) / 1000.0 /
                      static_cast<double>(checks),
                  static_cast<double>(idle_ms_max_.load(std::memory_order_relaxed)) / 1000.0,
                  static_cast<unsigned long long>(errors_.load(std::memory_order_relaxed)),
                  static_cast<unsigned long long>(skipped()));
    return line;
}

TestResult verifyResidual(TestContext& ctx, const MemoryRegion& chunk, const ResidualPattern& pattern,
                          const std::string& name, bool halt_on_error) {
    TestResult res;
    VerificationProgress progress(ctx, res, chunk);
    auto* ptr = reinterpret_cast<uint64_t*>(chunk.base);
    const size_t count = chunk.size / sizeof(uint64_t);
    testPhase(ctx, "Idle check", chunk);
    // The previous test's last verify blocks may still be cached.
    simd::flush_cache_region(ptr, chunk.size);
    using Kind = ResidualPattern::Kind;
    const simd::BeatPattern beat{pattern.p0, pattern.p1, pattern.salt, pattern.step};
    const uint8_t mode = pattern.kind == Kind::UNIFORM ? 0 : pattern.kind == Kind::XOR ? 1 : 2;
    constexpr size_t block = size_t{256} * 1024;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
        const size_t n = std::min(block, count - i);
        if (pattern.kind == Kind::BEAT) {
            verifyBeatAndReport(chunk, ptr, i, n, beat, res, ctx, name.c_str(), halt_on_error);
        } else {
            TestEngine::verifyAndReport(chunk, ptr + i, n, i, mode, pattern.p0, pattern.p1, res, ctx, name,
                                        halt_on_error);
        }
        progress.addBytes(n * sizeof(uint64_t));
    }
    return res;
}

void checkIdleChunk(TestContext& ctx, IdleChunkState& state, const MemoryRegion& chunk, size_t worker,
                    uint64_t worker_entries, IdleCheckStats& stats, bool halt_on_error) {
    if (!state.pattern.valid()) return;
    const ResidualPattern pattern = state.pattern;
    state.pattern = {}; // consumed: the next test overwrites the chunk
    if (state.writer == worker && state.writer_entries == worker_entries) {
        stats.recordSkip();
        return;
    }
    if (pattern.offset != chunk.base_offset_bytes || pattern.bytes != chunk.size) {
        LOG_WARN("Idle check skipped: leftover data of %s describes offset=%llu bytes=%llu, chunk is offset=%zu "
                 "bytes=%zu", state.function.c_str(), static_cast<unsigned long long>(pattern.offset),
                 static_cast<unsigned long long>(pattern.bytes), chunk.base_offset_bytes, chunk.size);
        return;
    }
    const auto started = std::chrono::steady_clock::now();
    const double idle = std::chrono::duration<double>(started - state.written).count();
    const TestResult result = verifyResidual(ctx, chunk, pattern, "Idle check after " + state.function, halt_on_error);
    // RowHammer that started on another chunk since, or is still running.
    const bool foreign_hammer = ctx.disturbance_starts.load(std::memory_order_acquire) != state.disturbance_starts ||
                                ctx.disturbance_active.load(std::memory_order_acquire) != 0;
    stats.recordCheck(idle, result.bytes_tested, result.total_errors());
    LOG_DEBUG("Idle check: worker %zu chunk offset=%zu after %s idle=%.3fs bytes=%llu errors=%llu in %.3fs%s", worker,
              chunk.base_offset_bytes, state.function.c_str(), idle,
              static_cast<unsigned long long>(result.bytes_tested),
              static_cast<unsigned long long>(result.total_errors()),
              std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(),
              ctx.shouldStop() ? " [stopped]" : "");
    if (result.total_errors()) {
        LOG_WARN("Idle check: %llu error(s) in data %s left in chunk offset=%zu bytes=%zu after %.1f s idle%s",
                 static_cast<unsigned long long>(result.total_errors()), state.function.c_str(),
                 chunk.base_offset_bytes, chunk.size, idle,
                 foreign_hammer ? "; RowHammer ran on another chunk meanwhile and may have caused them" : "");
    }
}

void rememberIdleChunk(IdleChunkState& state, const TestResult& last, const MemoryRegion& chunk,
                       const std::string& function, size_t worker, uint64_t worker_entries,
                       uint64_t disturbance_starts) {
    state.pattern = last.residual.valid() && last.residual.offset == chunk.base_offset_bytes &&
                            last.residual.bytes == chunk.size
                        ? last.residual
                        : ResidualPattern{};
    state.written = std::chrono::steady_clock::now();
    state.function = function;
    state.writer = worker;
    state.writer_entries = worker_entries;
    state.disturbance_starts = disturbance_starts;
}

} // namespace testsmem4u
