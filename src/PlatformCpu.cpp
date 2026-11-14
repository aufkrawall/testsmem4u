#include "Platform.h"
#include "CpuTopology.h"
#include "Logger.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstdio>
#include <atomic>
#include <cstdlib>
#include <array>
#include <string>
#include <limits>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <memoryapi.h>
#include <ntsecapi.h> // For LSA functions
#include <processtopologyapi.h>
#include <processthreadsapi.h>
#include <winnt.h>


#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <csignal>
#include <fcntl.h>
#include <dirent.h>
#include <fstream>
#endif

namespace testsmem4u {
namespace {
std::atomic<bool> g_cpu_targets_ready{false};
std::vector<CpuTarget> g_cached_cpu_targets;
PlatformInfo g_cached_platform_info{};

#ifdef _WIN32

struct WindowsGroupMask {
    WORD group = 0;
    KAFFINITY mask = 0;
};

using GetSystemCpuSetInformation_t = BOOL (WINAPI*)(PSYSTEM_CPU_SET_INFORMATION, ULONG, PULONG, HANDLE, ULONG);
using SetThreadInformation_t = BOOL (WINAPI*)(HANDLE, THREAD_INFORMATION_CLASS, LPVOID, DWORD);
using SetThreadIdealProcessorEx_t = BOOL (WINAPI*)(HANDLE, PPROCESSOR_NUMBER, PPROCESSOR_NUMBER);

template <typename Fn>
static Fn loadKernel32Proc(const char* name) {
    FARPROC raw = GetProcAddress(GetModuleHandleA("kernel32.dll"), name);
    static_assert(sizeof(Fn) == sizeof(raw), "Unexpected function pointer size mismatch");
    void* p = reinterpret_cast<void*>(raw);
    return reinterpret_cast<Fn>(p);
}

static GetSystemCpuSetInformation_t getGetSystemCpuSetInformationFn() {
    static auto fn = loadKernel32Proc<GetSystemCpuSetInformation_t>("GetSystemCpuSetInformation");
    return fn;
}

static SetThreadInformation_t getSetThreadInformationFn() {
    static auto fn = loadKernel32Proc<SetThreadInformation_t>("SetThreadInformation");
    return fn;
}

static SetThreadIdealProcessorEx_t getSetThreadIdealProcessorExFn() {
    static auto fn = loadKernel32Proc<SetThreadIdealProcessorEx_t>("SetThreadIdealProcessorEx");
    return fn;
}

// Process affinity (start /affinity, job objects) restricts the primary group;
// CPU sets list every CPU in the system regardless. With threads in several
// groups GetProcessAffinityMask reports nothing, so no filter applies then.
struct ProcessAffinity {
    bool known = false;
    WORD group = 0;
    KAFFINITY mask = 0;
};

static ProcessAffinity queryProcessAffinity() {
    ProcessAffinity result;
    HANDLE self = GetCurrentProcess();
    USHORT groups[1] = {};
    USHORT group_count = 1;
    if (!GetProcessGroupAffinity(self, &group_count, groups) || group_count != 1) return result;
    DWORD_PTR process_mask = 0;
    DWORD_PTR system_mask = 0;
    if (!GetProcessAffinityMask(self, &process_mask, &system_mask) || process_mask == 0) return result;
    result.known = true;
    result.group = groups[0];
    result.mask = static_cast<KAFFINITY>(process_mask);
    return result;
}

static std::vector<WindowsGroupMask> queryWindowsCoreMasks() {
    std::vector<WindowsGroupMask> cores;
    DWORD rel_bytes = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &rel_bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || rel_bytes == 0) return cores;
    std::vector<uint8_t> rel_buffer(rel_bytes);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore,
                                         reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(rel_buffer.data()),
                                         &rel_bytes)) {
        return cores;
    }
    uint8_t* current = rel_buffer.data();
    uint8_t* end = current + rel_bytes;
    while (current < end) {
        auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(current);
        if (info->Relationship == RelationProcessorCore && info->Processor.GroupCount > 0) {
            cores.push_back({info->Processor.GroupMask[0].Group, info->Processor.GroupMask[0].Mask});
        }
        current += info->Size;
    }
    return cores;
}

// Fallback core numbering: the lowest logical index of the hardware core, so
// SMT siblings share core_index exactly as CPU-set CoreIndex values do.
static uint16_t fallbackCoreIndex(const std::vector<WindowsGroupMask>& cores, WORD group, uint32_t logical) {
    KAFFINITY bit = 0;
    if (!cpu_topology::affinityBit(logical, bit)) return static_cast<uint16_t>(logical);
    for (const auto& core : cores) {
        if (core.group != group || (core.mask & bit) == 0) continue;
        for (uint32_t idx = 0; idx < sizeof(KAFFINITY) * 8; ++idx) {
            KAFFINITY low = 0;
            if (cpu_topology::affinityBit(idx, low) && (core.mask & low) != 0) return static_cast<uint16_t>(idx);
        }
    }
    return static_cast<uint16_t>(logical);
}

static std::vector<CpuTarget> detectWindowsCpuTargets(PlatformInfo& platform) {
    std::vector<CpuTarget> targets;

    WORD active_groups = GetActiveProcessorGroupCount();
    if (active_groups == 0) {
        platform.cpu_topology_source = "unavailable";
        return targets;
    }

    GetSystemCpuSetInformation_t get_cpu_set_information = getGetSystemCpuSetInformationFn();
    DWORD cpu_set_bytes = 0;
    std::vector<uint8_t> cpu_set_buffer;
    // Query for this process so AllocatedToTargetProcess is meaningful.
    HANDLE self = GetCurrentProcess();
    if (get_cpu_set_information != nullptr &&
        !get_cpu_set_information(nullptr, 0, &cpu_set_bytes, self, 0) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && cpu_set_bytes > 0) {
        cpu_set_buffer.resize(cpu_set_bytes);
        if (!get_cpu_set_information(reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpu_set_buffer.data()),
                                     cpu_set_bytes, &cpu_set_bytes, self, 0)) {
            cpu_set_buffer.clear();
        }
    }

    const ProcessAffinity affinity = queryProcessAffinity();
    // A CPU this process can bind to: inside the affinity-mask width (32 bits
    // in 32-bit builds, where a wider shift was undefined) and, in the
    // restricted primary group, inside the process affinity mask.
    auto usable = [&](WORD group, uint32_t logical) {
        KAFFINITY bit = 0;
        return cpu_topology::affinityBit(logical, bit) &&
               (!affinity.known || group != affinity.group || (affinity.mask & bit) != 0);
    };

    std::vector<cpu_topology::CpuSetRecord> records;
    if (!cpu_set_buffer.empty()) {
        uint8_t* current = cpu_set_buffer.data();
        uint8_t* end = current + cpu_set_bytes;
        while (current < end) {
            auto* info = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(current);
            if (info->Type == CpuSetInformation) {
                const auto& cpu = info->CpuSet;
                cpu_topology::CpuSetRecord record;
                // Allocated means reserved for exclusive use; ordinary CPUs report 0.
                // (Skipping !Allocated discarded every ordinary CPU, so the topology
                // fallback always ran: no core indices or efficiency classes.)
                record.reserved = cpu.Allocated && !cpu.AllocatedToTargetProcess;
                CpuTarget& target = record.target;
                target.group = cpu.Group;
                target.logical_index = cpu.LogicalProcessorIndex;
                target.core_index = cpu.CoreIndex;
                target.numa_node = cpu.NumaNodeIndex;
                target.efficiency_class = cpu.EfficiencyClass;
                target.scheduling_class = cpu.SchedulingClass;
                // Parking is transient idle-state power management: a parked CPU
                // unparks under load, so it stays a target and only sorts last.
                target.parked = cpu.Parked != 0;
                // Core-type performance only; scheduling classes rank cores of one type.
                target.raw_performance = 100U + static_cast<uint32_t>(cpu.EfficiencyClass) * 20U;
                records.push_back(record);
            }
            current += info->Size;
        }
    }

    cpu_topology::CpuSetSelection selection = cpu_topology::selectCpuSetTargets(records, usable);
    targets = std::move(selection.targets);
    uint32_t affinity_excluded = selection.affinity_excluded;
    platform.cpu_sets_reserved_only = selection.reserved_only;
    platform.cpu_topology_source = selection.reserved_only ? "cpu-sets-reserved-only"
                                   : targets.empty()       ? "logical-processor-fallback"
                                                           : "cpu-sets";
    if (targets.empty()) {
        // CPU sets unavailable or none usable. Keep the reserved count: it
        // explains part of why CPU sets yielded nothing.
        affinity_excluded = 0;
        const std::vector<WindowsGroupMask> cores = queryWindowsCoreMasks();
        for (WORD group = 0; group < active_groups; ++group) {
            const DWORD count = GetActiveProcessorCount(group);
            for (DWORD logical = 0; logical < count; ++logical) {
                if (!usable(group, logical)) {
                    ++affinity_excluded;
                    continue;
                }
                CpuTarget target;
                target.group = group;
                target.logical_index = static_cast<uint16_t>(logical);
                target.core_index = fallbackCoreIndex(cores, group, logical);
                targets.push_back(target);
            }
        }
    }
    platform.cpu_sets_reserved = selection.reserved;
    platform.cpu_affinity_excluded = affinity_excluded;
    cpu_topology::assignSmtRoles(targets);

    std::sort(targets.begin(), targets.end(), [](const CpuTarget& lhs, const CpuTarget& rhs) {
        if (lhs.parked != rhs.parked) return !lhs.parked && rhs.parked;
        if (lhs.smt_secondary != rhs.smt_secondary) return !lhs.smt_secondary && rhs.smt_secondary;
        if (lhs.efficiency_class != rhs.efficiency_class) return lhs.efficiency_class > rhs.efficiency_class;
        if (lhs.scheduling_class != rhs.scheduling_class) return lhs.scheduling_class > rhs.scheduling_class;
        if (lhs.numa_node != rhs.numa_node) return lhs.numa_node < rhs.numa_node;
        if (lhs.group != rhs.group) return lhs.group < rhs.group;
        return lhs.logical_index < rhs.logical_index;
    });

    const uint8_t best_efficiency = targets.empty() ? 0 : targets.front().efficiency_class;
    for (auto& target : targets) {
        uint32_t weight = 100;
        if (best_efficiency > 0 || target.efficiency_class > 0) {
            weight += static_cast<uint32_t>(target.efficiency_class) * 20U;
        }
        if (target.scheduling_class > 0) {
            weight += static_cast<uint32_t>(target.scheduling_class) * 2U;
        }
        if (target.smt_secondary) {
            weight = std::max<uint32_t>(40, weight / 2U);
        }
        target.weight = weight;
    }

    return targets;
}

static void applyWindowsWorkerQoS(HANDLE thread_handle) {
    SetThreadInformation_t set_thread_information = getSetThreadInformationFn();
    if (set_thread_information == nullptr) {
        return;
    }
    THREAD_POWER_THROTTLING_STATE throttling{};
    throttling.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
    throttling.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    throttling.StateMask = 0;
    (void)set_thread_information(thread_handle, ThreadPowerThrottling, &throttling, sizeof(throttling));
}

#else

static bool parseUintFile(const std::string& path, uint32_t& value) {
    std::ifstream in(path);
    if (!in.is_open()) return false;
    uint64_t tmp = 0;
    in >> tmp;
    if (!in.fail()) {
        value = static_cast<uint32_t>(tmp);
        return true;
    }
    return false;
}

static bool readCpuCapacity(uint32_t cpu, uint32_t& value) {
    const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpu_capacity";
    return parseUintFile(path, value);
}

static bool readCpuNumaNode(uint32_t cpu, uint32_t& value) {
    const std::string base = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/";
    DIR* dir = opendir(base.c_str());
    if (!dir) return false;

    bool found = false;
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        const std::string name = entry->d_name;
        if (name.size() > 4 && name.rfind("node", 0) == 0) {
            value = static_cast<uint32_t>(std::strtoul(name.c_str() + 4, nullptr, 10));
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

// Parses a sysfs CPU list such as "0-3,8,10-11".
static bool readCpuListFile(const std::string& path, cpu_set_t& set) {
    CPU_ZERO(&set);
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string content;
    std::getline(in, content);
    if (content.empty()) return false;

    size_t pos = 0;
    while (pos < content.size()) {
        size_t next = content.find(',', pos);
        std::string token = content.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        size_t dash = token.find('-');
        if (dash == std::string::npos) {
            uint32_t idx = static_cast<uint32_t>(std::strtoul(token.c_str(), nullptr, 10));
            if (idx < CPU_SETSIZE) CPU_SET(static_cast<int>(idx), &set);
        } else {
            uint32_t start = static_cast<uint32_t>(std::strtoul(token.substr(0, dash).c_str(), nullptr, 10));
            uint32_t end = static_cast<uint32_t>(std::strtoul(token.substr(dash + 1).c_str(), nullptr, 10));
            for (uint32_t idx = start; idx <= end && idx < CPU_SETSIZE; ++idx) {
                CPU_SET(static_cast<int>(idx), &set);
            }
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return true;
}

static bool buildSiblingSet(uint32_t cpu, cpu_set_t& sibling_set) {
    return readCpuListFile("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/thread_siblings_list",
                           sibling_set);
}

static uint32_t firstSiblingIndex(const cpu_set_t& set) {
    for (uint32_t idx = 0; idx < CPU_SETSIZE; ++idx) {
        if (CPU_ISSET(static_cast<int>(idx), &set)) {
            return idx;
        }
    }
    return std::numeric_limits<uint32_t>::max();
}

static std::vector<CpuTarget> detectLinuxCpuTargets(PlatformInfo& platform) {
    std::vector<CpuTarget> targets;

    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        platform.cpu_topology_source = "unavailable";
        return targets;
    }
    // Online CPUs outside the affinity mask/cpuset. Not sysconf: musl derives
    // _SC_NPROCESSORS_ONLN from sched_getaffinity, so it never shows a gap.
    cpu_set_t online;
    if (readCpuListFile("/sys/devices/system/cpu/online", online)) {
        uint32_t excluded = 0;
        for (uint32_t cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            excluded += CPU_ISSET(static_cast<int>(cpu), &online) && !CPU_ISSET(static_cast<int>(cpu), &allowed);
        }
        platform.cpu_affinity_excluded = excluded;
    }

    uint32_t sibling_lists = 0;
    for (uint32_t cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(static_cast<int>(cpu), &allowed)) continue;

        CpuTarget target;
        target.group = 0;
        target.logical_index = static_cast<uint16_t>(cpu);
        target.core_index = static_cast<uint16_t>(cpu);
        target.numa_node = 0;
        target.raw_performance = 100;

        uint32_t capacity = 0;
        if (readCpuCapacity(cpu, capacity) && capacity > 0) {
            target.raw_performance = capacity;
        }

        uint32_t numa_node = 0;
        if (readCpuNumaNode(cpu, numa_node)) {
            target.numa_node = static_cast<uint16_t>(numa_node);
        }

        // The core is named by its lowest hardware thread: unique across
        // packages (core_id repeats per socket) and identical for all siblings.
        // SMT roles are assigned afterwards from the allowed CPUs only.
        cpu_set_t siblings;
        if (buildSiblingSet(cpu, siblings)) {
            const uint32_t first = firstSiblingIndex(siblings);
            if (first != std::numeric_limits<uint32_t>::max()) {
                target.core_index = static_cast<uint16_t>(first);
                ++sibling_lists;
            }
        }

        targets.push_back(target);
    }
    // Without sibling lists every CPU is its own core: no SMT pairing.
    platform.cpu_topology_source = sibling_lists ? "sysfs" : "affinity-only";
    cpu_topology::assignSmtRoles(targets);

    std::sort(targets.begin(), targets.end(), [](const CpuTarget& lhs, const CpuTarget& rhs) {
        if (lhs.smt_secondary != rhs.smt_secondary) return !lhs.smt_secondary && rhs.smt_secondary;
        if (lhs.raw_performance != rhs.raw_performance) return lhs.raw_performance > rhs.raw_performance;
        if (lhs.numa_node != rhs.numa_node) return lhs.numa_node < rhs.numa_node;
        return lhs.logical_index < rhs.logical_index;
    });

    uint32_t best = targets.empty() ? 100 : targets.front().raw_performance;
    if (best == 0) best = 100;
    for (auto& target : targets) {
        uint32_t weight = static_cast<uint32_t>((static_cast<uint64_t>(target.raw_performance) * 100ULL) / best);
        if (weight < 40) weight = 40;
        if (target.smt_secondary) {
            weight = std::max<uint32_t>(40, weight / 2U);
        }
        target.weight = weight;
    }

    return targets;
}

#endif

static std::vector<CpuTarget> detectCpuTargets(PlatformInfo& platform) {
#ifdef _WIN32
    return detectWindowsCpuTargets(platform);
#else
    return detectLinuxCpuTargets(platform);
#endif
}

static void initializeCpuTopologyCache() {
    if (g_cpu_targets_ready.load(std::memory_order_acquire)) {
        return;
    }

    PlatformInfo info{};
    info.large_pages_available = false;

#ifdef _WIN32
    snprintf(info.os_name, sizeof(info.os_name), "Windows");
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    info.page_size = sys_info.dwPageSize;

#ifdef _M_X64
    snprintf(info.arch, sizeof(info.arch), "x86_64");
#elif defined(_M_IX86) || (defined(__i386__) && !defined(__x86_64__))
    snprintf(info.arch, sizeof(info.arch), "x86");
#elif defined(_M_ARM64)
    snprintf(info.arch, sizeof(info.arch), "ARM64");
#else
    snprintf(info.arch, sizeof(info.arch), "Unknown");
#endif

    info.large_pages_available = (GetLargePageMinimum() > 0);
#else
    snprintf(info.os_name, sizeof(info.os_name), "Linux");
    info.page_size = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));

#if defined(__x86_64__) && !defined(__i386__)
    snprintf(info.arch, sizeof(info.arch), "x86_64");
#elif defined(__i386__)
    snprintf(info.arch, sizeof(info.arch), "x86");
#elif defined(__aarch64__)
    snprintf(info.arch, sizeof(info.arch), "ARM64");
#else
    snprintf(info.arch, sizeof(info.arch), "Unknown");
#endif

    info.large_pages_available = Platform::getPreferredLargePageSize() > 0;
#endif

    std::vector<CpuTarget> targets = detectCpuTargets(info);
    info.cpu_targets = targets;
    info.cpu_cores = static_cast<uint32_t>(targets.size());

    info.heterogeneous_cores = cpu_topology::heterogeneousCores(targets);

    g_cached_cpu_targets = std::move(targets);
    g_cached_platform_info = std::move(info);
    g_cpu_targets_ready.store(true, std::memory_order_release);
}

} // namespace

PlatformInfo Platform::detectPlatform() {
    initializeCpuTopologyCache();
    return g_cached_platform_info;
}

std::vector<CpuTarget> Platform::getPreferredCpuTargets(uint32_t max_threads) {
    initializeCpuTopologyCache();
    std::vector<CpuTarget> targets = g_cached_cpu_targets;
    if (max_threads > 0 && targets.size() > max_threads) {
        targets.resize(max_threads);
    }
    return targets;
}

bool Platform::bindCurrentThread(const CpuTarget& target) {
#ifdef _WIN32
    HANDLE hThread = GetCurrentThread();
    GROUP_AFFINITY affinity{};
    affinity.Group = target.group;
    if (!cpu_topology::affinityBit(target.logical_index, affinity.Mask) ||
        !SetThreadGroupAffinity(hThread, &affinity, nullptr)) {
        return false;
    }

    PROCESSOR_NUMBER ideal{};
    ideal.Group = target.group;
    ideal.Number = static_cast<BYTE>(target.logical_index);
    ideal.Reserved = 0;
    if (SetThreadIdealProcessorEx_t set_thread_ideal = getSetThreadIdealProcessorExFn()) {
        (void)set_thread_ideal(hThread, &ideal, nullptr);
    }
    applyWindowsWorkerQoS(hThread);
    return true;
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (target.logical_index >= CPU_SETSIZE) {
        return false;
    }
    CPU_SET(static_cast<int>(target.logical_index), &cpuset);
    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) == 0;
#endif
}

} // namespace testsmem4u
