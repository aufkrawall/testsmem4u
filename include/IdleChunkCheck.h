#pragma once

#include "TestEngine.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>

namespace testsmem4u {

// Idle-chunk check: when a test on a memory chunk completes with known final
// data (TestResult::residual), the next test that claims the chunk first
// re-verifies that data. Meanwhile the chunk sat untouched for as long as other
// workers ran their tests on other chunks (seconds to minutes under full memory
// load), so this catches charge leakage over long dwells and stray writes from
// elsewhere (address decoding, cross-chunk disturbance) for one read pass and
// no extra writes. Inspired by TestMem5's background pattern, which every test
// checks before overwriting it.
struct IdleChunkState {
    ResidualPattern pattern;
    std::chrono::steady_clock::time_point written{};
    std::string function;              // test that left the data
    size_t writer = std::numeric_limits<size_t>::max();
    uint64_t writer_entries = 0;       // writer's completed entries at that time
    uint64_t disturbance_starts = 0;   // TestContext::disturbance_starts then
};

class IdleCheckStats {
public:
    void recordCheck(double idle_seconds, uint64_t bytes, uint64_t errors) noexcept;
    void recordSkip() noexcept { skipped_.fetch_add(1, std::memory_order_relaxed); }
    std::string summary() const;
    uint64_t checks() const noexcept { return checks_.load(std::memory_order_relaxed); }
    uint64_t skipped() const noexcept { return skipped_.load(std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> checks_{0};
    std::atomic<uint64_t> skipped_{0};
    std::atomic<uint64_t> bytes_{0};
    std::atomic<uint64_t> errors_{0};
    std::atomic<uint64_t> idle_ms_total_{0};
    std::atomic<uint64_t> idle_ms_max_{0};
    std::atomic<uint64_t> idle_ms_min_{std::numeric_limits<uint64_t>::max()};
};

// Verifies the chunk's leftover data (if any) and consumes it. Skipped when the
// claiming worker wrote it and ran nothing since (no idle time: single worker).
// Errors are classified like any other ("Idle check after <test>") and count as
// run errors; halt_on_error requests a stop.
void checkIdleChunk(TestContext& ctx, IdleChunkState& state, const MemoryRegion& chunk, size_t worker,
                    uint64_t worker_entries, IdleCheckStats& stats, bool halt_on_error);

// Records the data the completed entry left in the chunk (cleared when the last
// invocation's residual does not describe the whole chunk).
void rememberIdleChunk(IdleChunkState& state, const TestResult& last, const MemoryRegion& chunk,
                       const std::string& function, size_t worker, uint64_t worker_entries,
                       uint64_t disturbance_starts);

// Re-verifies `chunk` against `pattern` after flushing it from the caches.
TestResult verifyResidual(TestContext& ctx, const MemoryRegion& chunk, const ResidualPattern& pattern,
                          const std::string& name, bool halt_on_error);

} // namespace testsmem4u
