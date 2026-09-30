#pragma once
#include "TestEngine.h"
#include <string>

namespace testsmem4u {

// Tests whose purpose is physical disturbance of neighbouring DRAM rows. Worker
// regions are page-aligned but rows are larger, so their effects can cross into
// a peer region that is running an unrelated test at the same time.
inline bool isCrossRegionDisturbanceTest(const std::string& name) {
    return name == "RowHammer";
}

// Tracks whether a test invocation overlapped another worker's disturbance test,
// so errors can be annotated rather than silently blamed on the wrong test.
// A disturber registers active-then-start; an observer snapshots start-then-active,
// so any disturbance overlapping the observer's window is seen by one of them.
class DisturbanceWindow {
public:
    DisturbanceWindow(TestContext& ctx, bool disturbs) : ctx_(ctx), disturbs_(disturbs) {
        if (disturbs_) {
            ctx_.disturbance_active.fetch_add(1, std::memory_order_acq_rel);
            ctx_.disturbance_starts.fetch_add(1, std::memory_order_acq_rel);
        }
        starts_at_begin_ = ctx_.disturbance_starts.load(std::memory_order_acquire);
        active_at_begin_ = ctx_.disturbance_active.load(std::memory_order_acquire) - (disturbs_ ? 1U : 0U);
    }
    ~DisturbanceWindow() {
        if (disturbs_) ctx_.disturbance_active.fetch_sub(1, std::memory_order_acq_rel);
    }
    DisturbanceWindow(const DisturbanceWindow&) = delete;
    DisturbanceWindow& operator=(const DisturbanceWindow&) = delete;

    // Errors found by a disturbance test are already attributed to it.
    bool overlappedForeignDisturbance() const {
        if (disturbs_) return false;
        return active_at_begin_ > 0 ||
               ctx_.disturbance_starts.load(std::memory_order_acquire) != starts_at_begin_;
    }

private:
    TestContext& ctx_;
    const bool disturbs_;
    uint64_t starts_at_begin_ = 0;
    uint32_t active_at_begin_ = 0;
};

} // namespace testsmem4u
