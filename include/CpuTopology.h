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
