#pragma once
#include "Types.h"
#include <atomic>

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

private:
    TestResult totals_;
    std::atomic<uint64_t> bytes_{0}, hard_{0}, soft_{0}, unverified_{0};
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

private:
    const void* owner_;
    ProgressCounters& counters_;
    ProgressBinding* previous_;
    inline static thread_local ProgressBinding* current = nullptr;
};

} // namespace testsmem4u
