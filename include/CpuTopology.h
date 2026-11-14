#pragma once
#include "Platform.h"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace testsmem4u {
namespace cpu_topology {

// SMT roles come from the usable targets, not from the hardware core: a thread
// whose lower-numbered sibling is excluded (process affinity, cpuset, reserved
// Windows CPU set) is the only usable thread of its core. Marking it secondary
// from the hardware mask sorted it behind contended siblings and left it with
// no primary to pair with. Targets on one core share (group, core_index).
inline void assignSmtRoles(std::vector<CpuTarget>& targets) {
    for (auto& target : targets) {
        uint32_t sharing = 0;
        bool lower_sibling = false;
        for (const auto& other : targets) {
            if (other.group != target.group || other.core_index != target.core_index) continue;
            ++sharing;
            lower_sibling |= other.logical_index < target.logical_index;
        }
        target.smt = sharing > 1;
        target.smt_secondary = lower_sibling;
    }
}

// Heterogeneity means different core types: Windows efficiency classes or
// Linux cpu_capacity (raw_performance, never SMT-halved). Weights are not
// compared: SMT siblings get halved weights and Windows scheduling classes rank
// otherwise identical cores (AMD preferred cores report 0-6 on a Ryzen 7
// 5700X), so either made every such CPU look heterogeneous.
inline bool heterogeneousCores(const std::vector<CpuTarget>& targets) {
    return std::any_of(targets.begin(), targets.end(), [&](const CpuTarget& target) {
        return target.efficiency_class != targets.front().efficiency_class ||
               target.raw_performance != targets.front().raw_performance;
    });
}

// One Windows CPU-set record reduced to what worker selection needs.
struct CpuSetRecord {
    CpuTarget target;      // topology fields from the record
    bool reserved = false; // Allocated for exclusive use by another process
};

struct CpuSetSelection {
    std::vector<CpuTarget> targets;
    uint32_t reserved = 0;          // records reserved for other processes
    uint32_t affinity_excluded = 0; // unreserved records this process cannot bind to
    // Every usable CPU is reserved for another process (the affinity mask allows
    // no other CPU), so the targets are those reserved CPUs.
    bool reserved_only = false;
};

// Workers use unreserved CPUs the process may bind to. Only when the affinity
// mask leaves nothing else do they fall back to usable reserved CPUs, keeping
// the CPU-set topology: the previous logical-processor fallback re-added those
// CPUs anyway, dropped core pairing and efficiency classes, and still reported
// them as skipped. Empty targets mean CPU sets offered no usable CPU at all.
template <typename Usable>
inline CpuSetSelection selectCpuSetTargets(const std::vector<CpuSetRecord>& records, Usable&& usable) {
    CpuSetSelection selection;
    std::vector<CpuTarget> reserved_usable;
    for (const auto& record : records) {
        const bool can_bind = usable(record.target.group, record.target.logical_index);
        if (record.reserved) {
            ++selection.reserved;
            if (can_bind) reserved_usable.push_back(record.target);
        } else if (!can_bind) {
            ++selection.affinity_excluded;
        } else {
            selection.targets.push_back(record.target);
        }
    }
    if (selection.targets.empty() && !reserved_usable.empty()) {
        selection.targets = std::move(reserved_usable);
        selection.reserved_only = true;
    }
    return selection;
}

// One affinity-mask bit per logical index; indices at or beyond the mask width
// (32 in 32-bit builds) cannot be bound and must never be shifted into a mask.
template <typename Mask>
inline bool affinityBit(uint32_t logical_index, Mask& bit) {
    if (logical_index >= sizeof(Mask) * 8) return false;
    bit = static_cast<Mask>(Mask{1} << logical_index);
    return true;
}

} // namespace cpu_topology
} // namespace testsmem4u
