#pragma once
#include "Types.h"
#include "WorkerProgress.h"
#include <algorithm>
#include <atomic>
#include <limits>
#include <vector>

namespace testsmem4u {

// Exactly one worker writes each cache-line-separated slot. Readers sample
// atomics; a live snapshot is approximate, and the joined-worker total is exact.
class alignas(64) ProgressCounters {
public:
    void add(const TestResult& delta) noexcept {
        totals_.merge(delta);
        if (delta.bytes_tested) bytes_.store(totals_.bytes_tested, std::memory_order_relaxed);
        if (delta.hard_errors) hard_.store(totals_.hard_errors, std::memory_order_relaxed);
        if (delta.soft_errors) soft_.store(totals_.soft_errors, std::memory_order_relaxed);
        if (delta.unverified_errors) unverified_.store(totals_.unverified_errors, std::memory_order_relaxed);
    }

    TestResult snapshot() const noexcept {
        TestResult result;
        result.bytes_tested = bytes_.load(std::memory_order_relaxed);
        result.hard_errors = hard_.load(std::memory_order_relaxed);
        result.soft_errors = soft_.load(std::memory_order_relaxed);
        result.unverified_errors = unverified_.load(std::memory_order_relaxed);
        return result;
    }

    void setPhase(const char* phase) noexcept { phase_.store(phase, std::memory_order_relaxed); }
    const char* phase() const noexcept { return phase_.load(std::memory_order_relaxed); }

    // Completed fraction of the worker's current sequence entry, in parts per
    // million. One atomic keeps readers from mixing two tests' denominators.
    static constexpr uint32_t kStepScale = 1000000;
    void setStep(double fraction) noexcept {
        const double clamped = std::clamp(fraction, 0.0, 1.0);
        step_.store(static_cast<uint32_t>(clamped * kStepScale), std::memory_order_relaxed);
    }
    uint32_t step() const noexcept { return step_.load(std::memory_order_relaxed); }

private:
    TestResult totals_;
    std::atomic<uint64_t> bytes_{0}, hard_{0}, soft_{0}, unverified_{0};
    std::atomic<uint32_t> step_{0};
    // Phase names are static string literals, so sampled pointers stay valid.
    std::atomic<const char*> phase_{"Starting"};
};

// Bind all nested kernels on this worker to the same slot without changing the
// shared stop/disturbance context. Restore the previous binding on every exit.
class ProgressBinding {
public:
    ProgressBinding(const void* owner, ProgressCounters& counters) noexcept
        : owner_(owner), counters_(counters), previous_(current) { current = this; }
    ~ProgressBinding() { current = previous_; }
    ProgressBinding(const ProgressBinding&) = delete;
    ProgressBinding& operator=(const ProgressBinding&) = delete;

    static bool publish(const void* owner, const TestResult& delta) noexcept {
        if (!current || current->owner_ != owner) return false;
        current->counters_.add(delta);
        return true;
    }

    static void setPhase(const void* owner, const char* phase) noexcept {
        if (current && current->owner_ == owner) current->counters_.setPhase(phase);
    }

    // Current-test progress = (external loop, configured sub-block, kernel
    // repetition). The worker owns loops, runRegionWork owns sub-blocks and the
    // outermost kernel owns repetitions; nested kernels cannot claim them.
    static void beginLoop(const void* owner, uint64_t loop, uint64_t loops) noexcept {
        ProgressBinding* binding = bound(owner);
        if (!binding) return;
        binding->loop_ = loop;
        binding->loops_ = std::max<uint64_t>(1, loops);
        binding->block_ = 0;
        binding->blocks_ = 1;
        binding->publishStep(0, 1);
    }

    static void beginBlock(const void* owner, uint64_t block, uint64_t blocks) noexcept {
        ProgressBinding* binding = bound(owner);
        if (!binding) return;
        binding->block_ = block;
        binding->blocks_ = std::max<uint64_t>(1, blocks);
        binding->publishStep(0, 1);
    }

    // Called before publishing a completed sequence position, so a reader that
    // observes the new position never pairs it with the previous test's step.
    static void resetStep(const void* owner) noexcept {
        ProgressBinding* binding = bound(owner);
        if (binding) binding->counters_.setStep(0.0);
    }

    static bool claimRepetitions(const void* owner) noexcept {
        ProgressBinding* binding = bound(owner);
        if (!binding || binding->repetitions_claimed_) return false;
        binding->repetitions_claimed_ = true;
        return true;
    }

    static void releaseRepetitions(const void* owner) noexcept {
        if (ProgressBinding* binding = bound(owner)) binding->repetitions_claimed_ = false;
    }

    static void setRepetition(const void* owner, uint64_t repetition, uint64_t repetitions) noexcept {
        if (ProgressBinding* binding = bound(owner)) binding->publishStep(repetition, repetitions);
    }

private:
    static ProgressBinding* bound(const void* owner) noexcept {
        return current && current->owner_ == owner ? current : nullptr;
    }

    void publishStep(uint64_t repetition, uint64_t repetitions) noexcept {
        // Doubles avoid overflow for extreme loop x block x repetition products.
        const double reps = static_cast<double>(std::max<uint64_t>(1, repetitions));
        const double blocks = static_cast<double>(blocks_);
        const double position = static_cast<double>(loop_) * blocks + static_cast<double>(block_) +
                                static_cast<double>(repetition) / reps;
        counters_.setStep(position / (static_cast<double>(loops_) * blocks));
    }

    const void* owner_;
    ProgressCounters& counters_;
    ProgressBinding* previous_;
    uint64_t loop_ = 0, loops_ = 1, block_ = 0, blocks_ = 1;
    bool repetitions_claimed_ = false;
    inline static thread_local ProgressBinding* current = nullptr;
};

// The status line follows the least advanced worker: lowest completed sequence
// position, then lowest current-test step. Positions and steps are sampled once.
struct SlowestWorker {
    size_t worker = 0;
    uint64_t position = 0;
    uint32_t step = 0;
};

inline SlowestWorker findSlowestWorker(const WorkerProgress& progress,
                                       const std::vector<ProgressCounters>& counters) {
    SlowestWorker slowest{0, std::numeric_limits<uint64_t>::max(), ProgressCounters::kStepScale};
    for (size_t i = 0; i < counters.size(); ++i) {
        const uint64_t position = progress.completedTests(i);
        const uint32_t step = counters[i].step();
        if (position < slowest.position || (position == slowest.position && step < slowest.step)) {
            slowest = {i, position, step};
        }
    }
    if (counters.empty()) slowest = {};
    return slowest;
}

} // namespace testsmem4u
