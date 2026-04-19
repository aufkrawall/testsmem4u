#include "Platform.h"
#include "Logger.h"
#include <iostream>
#include <thread>
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


// Helper for LSA
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

static void InitLsaString(PLSA_UNICODE_STRING LsaString, LPWSTR String) {
    DWORD StringLength;
    if (String == NULL) {
        LsaString->Buffer = NULL;
        LsaString->Length = 0;
        LsaString->MaximumLength = 0;
        return;
    }
    StringLength = lstrlenW(String);
    LsaString->Buffer = String;
    LsaString->Length = (USHORT)(StringLength * sizeof(WCHAR));
    LsaString->MaximumLength = (USHORT)((StringLength + 1) * sizeof(WCHAR));
}

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

static void (*g_shutdown_callback)() = nullptr;
static std::atomic<bool> g_shutdown_initiated{false};
#ifdef _WIN32
static HANDLE g_shutdown_event = nullptr;
#else
// Original hugepage count to restore on exit (-1 = not modified)
static int g_original_hugepages = -1;
#endif

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
    Fn fn = nullptr;
    static_assert(sizeof(fn) == sizeof(raw), "Unexpected function pointer size mismatch");
    std::memcpy(&fn, &raw, sizeof(fn));
    return fn;
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

static uint32_t bitCount64(uint64_t value) {
    uint32_t count = 0;
    while (value != 0) {
        value &= (value - 1);
        ++count;
    }
    return count;
}

static std::vector<CpuTarget> detectWindowsCpuTargets() {
    std::vector<CpuTarget> targets;

    DWORD active_groups = GetActiveProcessorGroupCount();
    if (active_groups == 0) {
        return targets;
    }

    GetSystemCpuSetInformation_t get_cpu_set_information = getGetSystemCpuSetInformationFn();
    DWORD cpu_set_bytes = 0;
    std::vector<uint8_t> cpu_set_buffer;
    if (get_cpu_set_information != nullptr &&
        !get_cpu_set_information(nullptr, 0, &cpu_set_bytes, nullptr, 0) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && cpu_set_bytes > 0) {
        cpu_set_buffer.resize(cpu_set_bytes);
        if (!get_cpu_set_information(reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpu_set_buffer.data()),
                                     cpu_set_bytes, &cpu_set_bytes, nullptr, 0)) {
            cpu_set_buffer.clear();
        }
    }

    std::vector<WindowsGroupMask> smt_masks;
    DWORD rel_bytes = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &rel_bytes);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && rel_bytes > 0) {
        std::vector<uint8_t> rel_buffer(rel_bytes);
        if (GetLogicalProcessorInformationEx(RelationProcessorCore,
                                             reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(rel_buffer.data()),
                                             &rel_bytes)) {
            uint8_t* current = rel_buffer.data();
            uint8_t* end = current + rel_bytes;
            while (current < end) {
                auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(current);
                if (info->Relationship == RelationProcessorCore && info->Processor.GroupCount > 0) {
                    WindowsGroupMask gm;
                    gm.group = info->Processor.GroupMask[0].Group;
                    gm.mask = info->Processor.GroupMask[0].Mask;
                    smt_masks.push_back(gm);
                }
                current += info->Size;
            }
        }
    }

    auto markSmt = [&](CpuTarget& target) {
        for (const auto& gm : smt_masks) {
            if (gm.group != target.group) continue;
            const KAFFINITY bit = (KAFFINITY)1ULL << target.logical_index;
            if ((gm.mask & bit) == 0) continue;
            const uint32_t threads_on_core = bitCount64(static_cast<uint64_t>(gm.mask));
            target.smt = threads_on_core > 1;
            if (target.smt) {
                uint32_t earlier = 0;
                for (uint32_t idx = 0; idx < target.logical_index; ++idx) {
                    const KAFFINITY other_bit = (KAFFINITY)1ULL << idx;
                    if ((gm.mask & other_bit) != 0) {
                        ++earlier;
                    }
                }
                target.smt_secondary = earlier > 0;
            }
            return;
        }
    };

    if (!cpu_set_buffer.empty()) {
        uint8_t* current = cpu_set_buffer.data();
        uint8_t* end = current + cpu_set_bytes;
        while (current < end) {
            auto* info = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(current);
            if (info->Type == CpuSetInformation) {
                const auto& cpu = info->CpuSet;
                if (!cpu.Allocated || cpu.Parked) {
                    current += info->Size;
                    continue;
                }

                CpuTarget target;
                target.group = cpu.Group;
                target.logical_index = cpu.LogicalProcessorIndex;
                target.core_index = cpu.CoreIndex;
                target.numa_node = cpu.NumaNodeIndex;
                target.efficiency_class = cpu.EfficiencyClass;
                target.scheduling_class = cpu.SchedulingClass;
                target.parked = cpu.Parked != 0;
                target.raw_performance = 1000U + static_cast<uint32_t>(cpu.EfficiencyClass) * 100U +
                                         static_cast<uint32_t>(cpu.SchedulingClass);
                markSmt(target);
                targets.push_back(target);
            }
            current += info->Size;
        }
    }

    if (targets.empty()) {
        for (WORD group = 0; group < active_groups; ++group) {
            const DWORD count = GetActiveProcessorCount(group);
            for (DWORD logical = 0; logical < count; ++logical) {
                CpuTarget target;
                target.group = group;
                target.logical_index = static_cast<uint16_t>(logical);
                target.core_index = static_cast<uint16_t>(logical);
                markSmt(target);
                targets.push_back(target);
            }
        }
    }

    std::sort(targets.begin(), targets.end(), [](const CpuTarget& lhs, const CpuTarget& rhs) {
        if (lhs.parked != rhs.parked) return !lhs.parked && rhs.parked;
        if (lhs.efficiency_class != rhs.efficiency_class) return lhs.efficiency_class > rhs.efficiency_class;
        if (lhs.smt_secondary != rhs.smt_secondary) return !lhs.smt_secondary && rhs.smt_secondary;
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
        target.raw_performance = weight;
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

static bool readCpuCoreId(uint32_t cpu, uint32_t& value) {
    const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/core_id";
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

static bool buildSiblingSet(uint32_t cpu, cpu_set_t& sibling_set) {
    CPU_ZERO(&sibling_set);
    const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/thread_siblings_list";
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
            if (idx < CPU_SETSIZE) CPU_SET(static_cast<int>(idx), &sibling_set);
        } else {
            uint32_t start = static_cast<uint32_t>(std::strtoul(token.substr(0, dash).c_str(), nullptr, 10));
            uint32_t end = static_cast<uint32_t>(std::strtoul(token.substr(dash + 1).c_str(), nullptr, 10));
            for (uint32_t idx = start; idx <= end && idx < CPU_SETSIZE; ++idx) {
                CPU_SET(static_cast<int>(idx), &sibling_set);
            }
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return true;
}

static uint32_t firstSiblingIndex(const cpu_set_t& set) {
    for (uint32_t idx = 0; idx < CPU_SETSIZE; ++idx) {
        if (CPU_ISSET(static_cast<int>(idx), &set)) {
            return idx;
        }
    }
    return std::numeric_limits<uint32_t>::max();
}

static uint32_t cpuSetCount(const cpu_set_t& set) {
    uint32_t count = 0;
    for (uint32_t idx = 0; idx < CPU_SETSIZE; ++idx) {
        if (CPU_ISSET(static_cast<int>(idx), &set)) {
            ++count;
        }
    }
    return count;
}

static std::vector<CpuTarget> detectLinuxCpuTargets() {
    std::vector<CpuTarget> targets;

    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        return targets;
    }

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

        uint32_t core_id = 0;
        if (readCpuCoreId(cpu, core_id)) {
            target.core_index = static_cast<uint16_t>(core_id);
        }

        uint32_t numa_node = 0;
        if (readCpuNumaNode(cpu, numa_node)) {
            target.numa_node = static_cast<uint16_t>(numa_node);
        }

        cpu_set_t siblings;
        if (buildSiblingSet(cpu, siblings)) {
            const uint32_t first = firstSiblingIndex(siblings);
            target.smt = first != std::numeric_limits<uint32_t>::max() &&
                         cpuSetCount(siblings) > 1;
            target.smt_secondary = target.smt && cpu != first;
        }

        targets.push_back(target);
    }

    std::sort(targets.begin(), targets.end(), [](const CpuTarget& lhs, const CpuTarget& rhs) {
        if (lhs.raw_performance != rhs.raw_performance) return lhs.raw_performance > rhs.raw_performance;
        if (lhs.smt_secondary != rhs.smt_secondary) return !lhs.smt_secondary && rhs.smt_secondary;
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

static std::vector<CpuTarget> detectCpuTargets() {
#ifdef _WIN32
    return detectWindowsCpuTargets();
#else
    return detectLinuxCpuTargets();
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

    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (fp) {
        int nr_hugepages = 0;
        if (fscanf(fp, "%d", &nr_hugepages) == 1 && nr_hugepages > 0) {
            info.large_pages_available = true;
        }
        fclose(fp);
    }
    if (!info.large_pages_available) {
        void* test = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (test != MAP_FAILED) {
            info.large_pages_available = true;
            munmap(test, 2 * 1024 * 1024);
        }
    }
#endif

    std::vector<CpuTarget> targets = detectCpuTargets();
    info.cpu_targets = targets;
    info.cpu_cores = static_cast<uint32_t>(targets.size());

    uint32_t min_weight = std::numeric_limits<uint32_t>::max();
    uint32_t max_weight = 0;
    for (const auto& target : targets) {
        min_weight = std::min(min_weight, target.weight);
        max_weight = std::max(max_weight, target.weight);
    }
    info.heterogeneous_cores = !targets.empty() && min_weight != max_weight;

    g_cached_cpu_targets = std::move(targets);
    g_cached_platform_info = std::move(info);
    g_cpu_targets_ready.store(true, std::memory_order_release);
}

} // namespace

#ifdef _WIN32
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (g_shutdown_initiated.load(std::memory_order_acquire)) {
        TerminateProcess(GetCurrentProcess(), 0);
        return TRUE;
    }

    g_shutdown_initiated.store(true, std::memory_order_release);

    if (g_shutdown_callback) {
        g_shutdown_callback();
    }
    
    // NOTE: Logger::emergencyFlush() removed - may not be safe during shutdown
    // Rely on normal process exit to flush pending log entries

    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT ||
        dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT || dwCtrlType == CTRL_SHUTDOWN_EVENT) {
        if (g_shutdown_event && g_shutdown_event != INVALID_HANDLE_VALUE) {
            SetEvent(g_shutdown_event);
        }
        return TRUE;
    }
    return FALSE;
}
#pragma clang diagnostic pop
#else
// Restore hugepage count using only async-signal-safe functions.
// Called from signal handler before _exit().
static void restoreHugepagesSignalSafe() {
    if (g_original_hugepages < 0) return;

    // Convert integer to string (no snprintf — not async-signal-safe)
    char buf[16];
    int val = g_original_hugepages;
    int pos = 0;
    if (val == 0) {
        buf[pos++] = '0';
    } else {
        char tmp[16];
        int tpos = 0;
        while (val > 0) { tmp[tpos++] = '0' + (val % 10); val /= 10; }
        while (tpos > 0) buf[pos++] = tmp[--tpos];
    }
    buf[pos++] = '\n';

    // open/write/close are all async-signal-safe
    int fd = open("/proc/sys/vm/nr_hugepages", O_WRONLY);
    if (fd >= 0) {
        (void)write(fd, buf, pos);
        close(fd);
    }
}

// Normal-exit hugepage restoration (uses standard I/O, not signal-safe)
static void restoreHugepages() {
    if (g_original_hugepages < 0) return;

    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "w");
    if (fp) {
        fprintf(fp, "%d\n", g_original_hugepages);
        fclose(fp);
        LOG_INFO("Restored hugepages to original count: %d", g_original_hugepages);
    }
    g_original_hugepages = -1;
}

static void SignalHandlerWrapper(int signum) {
    // Second signal: force immediate exit.
    if (g_shutdown_initiated) {
        _exit(128 + signum);
    }

    // Mark as shutting down (atomic write is async-signal-safe)
    g_shutdown_initiated = true;

    // Callback should only set atomic stop flags.
    if (g_shutdown_callback) {
        g_shutdown_callback();
    }

    // SIGBUS indicates potentially unsafe memory access state.
    // Exit immediately after signal-safe cleanup.
    if (signum == SIGBUS) {
        restoreHugepagesSignalSafe();
        _exit(128 + signum);
    }

    // SIGINT/SIGTERM: return so the normal shutdown path can flush logs,
    // release memory, and report final results.
}
#endif

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
    affinity.Mask = (KAFFINITY)1ULL << target.logical_index;
    if (!SetThreadGroupAffinity(hThread, &affinity, nullptr)) {
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

bool Platform::hasMemoryLockPrivilege() {
#ifdef _WIN32
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID lock_luid;
    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &lock_luid)) {
        CloseHandle(hToken);
        return false;
    }

    DWORD required_size = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &required_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size == 0) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<uint8_t> buffer(required_size);
    auto* token_privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
    if (!GetTokenInformation(hToken, TokenPrivileges, token_privileges, required_size, &required_size)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    for (DWORD i = 0; i < token_privileges->PrivilegeCount; ++i) {
        const LUID& luid = token_privileges->Privileges[i].Luid;
        if (luid.LowPart == lock_luid.LowPart && luid.HighPart == lock_luid.HighPart) {
            return true;
        }
    }
    return false;
#else
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) == 0) {
        return (limit.rlim_cur != 0 && limit.rlim_cur != RLIM_INFINITY) || limit.rlim_max != 0;
    }
    return false;
#endif
}

bool Platform::grantMemoryLockPrivilege() {
#ifdef _WIN32
    LSA_OBJECT_ATTRIBUTES objAttr{};
    LSA_HANDLE policyHandle;
    NTSTATUS status;

    // Open LSA Policy
    status = LsaOpenPolicy(NULL, &objAttr, 
                           POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, 
                           &policyHandle);
    
    if (status != STATUS_SUCCESS) return false;

    // Get current user SID
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        LsaClose(policyHandle);
        return false;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        LsaClose(policyHandle);
        return false;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        LsaClose(policyHandle);
        return false;
    }
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        HeapFree(GetProcessHeap(), 0, pTokenUser);
        CloseHandle(hToken);
        LsaClose(policyHandle);
        return false;
    }

    // Add Right
    LSA_UNICODE_STRING userRights;
    WCHAR rightName[] = L"SeLockMemoryPrivilege"; 
    InitLsaString(&userRights, rightName);

    status = LsaAddAccountRights(policyHandle, pTokenUser->User.Sid, &userRights, 1);

    HeapFree(GetProcessHeap(), 0, pTokenUser);
    CloseHandle(hToken);
    LsaClose(policyHandle);

    return (status == STATUS_SUCCESS);
#else
    LOG_ERROR("Auto-granting privileges is only supported on Windows.");
    return false;
#endif
}

uint64_t Platform::getTotalSystemRAM() {
#ifdef _WIN32
    ULONGLONG mem_kb = 0;
    if (GetPhysicallyInstalledSystemMemory(&mem_kb)) {
        return mem_kb * 1024ULL;
    }
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return status.ullTotalPhys;
    }
    return 0;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return info.totalram * info.mem_unit;
    }
    return 0;
#endif
}

uint64_t Platform::getAvailableSystemRAM() {
#ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return status.ullAvailPhys;
    }
    return 0;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return info.freeram * info.mem_unit;
    }
    return 0;
#endif
}

uint64_t Platform::getMaxTestableMemory(uint64_t total_ram, uint32_t percent_requested) {
    if (percent_requested > 100) percent_requested = 100;
    // Reorder operations to prevent overflow: total_ram / 100 * percent
    // This is safe because total_ram / 100 <= 2^64 / 100 for any realistic RAM size
    uint64_t max_allowed = (total_ram / 100) * percent_requested;
    uint64_t min_reserved = 256ULL * 1024 * 1024; // 256 MB minimum
    if (max_allowed <= min_reserved) return 0;
    return max_allowed - min_reserved;
}

#ifdef _WIN32
bool Platform::enablePrivilege(const char* privilege_name) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilege_name, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (result && GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        result = false;
    }
    CloseHandle(hToken);
    return result;
}

bool Platform::tryAllocateVirtualLock(MemoryRegion& region, size_t size, size_t min_required_bytes) {
    // Enable privilege first
    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) {
        LOG_ERROR("SeLockMemoryPrivilege not available. Cannot lock memory.");
        return false;
    }

    // Set working set size before allocating - CRITICAL for VirtualLock to succeed
    HANDLE hProcess = GetCurrentProcess();
    SIZE_T overhead = 128 * 1024 * 1024;
    SIZE_T min_ws = size + overhead;
    SIZE_T max_ws = size + overhead + (512 * 1024 * 1024);
    
    if (!SetProcessWorkingSetSize(hProcess, min_ws, max_ws)) {
        DWORD err = GetLastError();
        LOG_ERROR("SetProcessWorkingSetSize(min=%zu MB, max=%zu MB) failed: error %lu. "
                  "Cannot guarantee memory lock without sufficient working set.",
                  min_ws / 1024 / 1024, max_ws / 1024 / 1024, err);
        // This is now a critical failure - VirtualLock will likely fail without sufficient working set
        return false;
    }

    // Free any existing allocation before reassigning
    if (region.base) {
        if (region.locked_bytes > 0) {
            VirtualUnlock(region.base + region.locked_offset, region.locked_bytes);
        }
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
    }

    region.base = static_cast<uint8_t*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!region.base) {
        LOG_ERROR("VirtualAlloc failed: error %lu", GetLastError());
        return false;
    }

    size_t locked = 0;
    size_t chunk_sizes[] = {256 * 1024 * 1024, 128 * 1024 * 1024, 64 * 1024 * 1024};
    
    for (size_t chunk : chunk_sizes) {
        while (locked < size) {
            size_t todo = std::min(chunk, size - locked);
            if (!VirtualLock(region.base + locked, todo)) {
                DWORD err = GetLastError();
                LOG_WARN("VirtualLock failed at offset %zu with %zu MB chunk: error %lu", 
                         locked, chunk / 1024 / 1024, err);
                break;
            }
            locked += todo;
        }
        
        if (locked >= min_required_bytes || locked >= size) {
            break;
        }
    }

    region.locked_offset = 0;
    region.locked_bytes = locked;
    region.large_page_bytes = 0;
    region.is_locked = (locked >= min_required_bytes);
    
    double lock_percent = (double)locked / (double)size * 100.0;
    LOG_INFO("Locked %zu of %zu MB (%.1f%%)", locked / 1024 / 1024, size / 1024 / 1024, lock_percent);

    if (locked < min_required_bytes) {
        LOG_ERROR("Could not lock minimum required %.1f%% of memory (%zu MB). Needed %zu MB locked.", 
                  (double)min_required_bytes / (double)size * 100.0,
                  locked / 1024 / 1024,
                  min_required_bytes / 1024 / 1024);
        if (locked > 0) {
            VirtualUnlock(region.base, locked);
        }
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        return false;
    }

    return true;
}

bool Platform::tryAllocateStandard(MemoryRegion& region, size_t size) {
    // Free any existing allocation before reassigning
    if (region.base) {
        if (region.locked_bytes > 0) {
            VirtualUnlock(region.base + region.locked_offset, region.locked_bytes);
        }
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
    }

    region.base = static_cast<uint8_t*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (region.base) {
        LOG_INFO("Allocated %zu MB (Standard)", size / 1024 / 1024);
        region.is_locked = false;
        region.is_large_pages = false;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        return true;
    }
    return false;
}

// Purge the Windows standby list using NtSetSystemInformation.
// The standby list holds cached pages that fragment 2MB regions.
// This is the same mechanism used by Sysinternals RAMMap.
// Requires SE_PROF_SINGLE_PROCESS_NAME privilege.
static void purgeStandbyList() {
    // NtSetSystemInformation is not in public headers, load dynamically
    typedef LONG (NTAPI *NtSetSystemInformation_t)(ULONG, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    FARPROC raw_proc = GetProcAddress(ntdll, "NtSetSystemInformation");
    if (!raw_proc) return;

    NtSetSystemInformation_t NtSetSystemInfo = nullptr;
    static_assert(sizeof(NtSetSystemInfo) == sizeof(raw_proc), "Unexpected function pointer size mismatch");
    std::memcpy(&NtSetSystemInfo, &raw_proc, sizeof(NtSetSystemInfo));
    if (!NtSetSystemInfo) return;

    // Enable required privilege
    Platform::enablePrivilege(SE_PROF_SINGLE_PROCESS_NAME);

    const ULONG SystemMemoryListInformation = 80;

    // Flush modified pages to disk first — dirty pages cannot be reused for
    // large pages until written out. This converts modified → standby.
    ULONG flush_cmd = 3; // MemoryFlushModifiedList
    LONG status = NtSetSystemInfo(SystemMemoryListInformation, &flush_cmd, sizeof(flush_cmd));
    if (status == 0) {
        LOG_INFO("Flushed modified page list to disk");
    }

    // Now purge the standby list — frees both original standby pages and
    // the newly-flushed pages, maximizing free 2MB-aligned regions.
    ULONG purge_cmd = 4; // MemoryPurgeStandbyList
    status = NtSetSystemInfo(SystemMemoryListInformation, &purge_cmd, sizeof(purge_cmd));

    if (status == 0) {
        LOG_INFO("Purged standby list to free physical memory for large pages");
    } else {
        LOG_DEBUG("Standby list purge returned status 0x%08lX (may require higher privileges)", status);
    }
}

// Defragment physical memory by trimming working sets and purging caches.
// This forces the OS to page out scattered 4KB allocations, freeing up
// contiguous 2MB-aligned regions needed for large pages.
static void defragPhysicalMemory() {
    DWORD pids[4096];
    DWORD bytes_returned = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytes_returned)) {
        LOG_WARN("EnumProcesses failed (error %lu), skipping working set trim", GetLastError());
    } else {
        DWORD num_pids = bytes_returned / sizeof(DWORD);
        DWORD my_pid = GetCurrentProcessId();
        uint32_t trimmed = 0;

        for (DWORD i = 0; i < num_pids; ++i) {
            if (pids[i] == 0 || pids[i] == my_pid) continue;

            HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
            if (hProc) {
                if (EmptyWorkingSet(hProc)) {
                    trimmed++;
                }
                CloseHandle(hProc);
            }
        }
        EmptyWorkingSet(GetCurrentProcess());
        LOG_INFO("Trimmed working sets of %u processes", trimmed);
    }

    // Shrink system file cache (requires SE_INCREASE_QUOTA_NAME)
    if (Platform::enablePrivilege(SE_INCREASE_QUOTA_NAME)) {
        // Setting min=0 max=0 with hard disable flags shrinks the cache
        if (SetSystemFileCacheSize(0, 0, FILE_CACHE_MIN_HARD_DISABLE | FILE_CACHE_MAX_HARD_DISABLE)) {
            LOG_INFO("Shrunk system file cache");
            // Re-enable normal cache behavior immediately after allocation attempt
            // (done in allocateMemory after large page success/failure)
        }
    }

    // Purge the standby list — this is the most impactful step
    purgeStandbyList();

    // Give the OS a moment to consolidate freed pages
    Sleep(500);
}

// Restore normal file cache behavior after defrag
static void restoreSystemFileCache() {
    if (Platform::enablePrivilege(SE_INCREASE_QUOTA_NAME)) {
        SetSystemFileCacheSize(0, 0, FILE_CACHE_MIN_HARD_ENABLE | FILE_CACHE_MAX_HARD_ENABLE);
    }
}

bool Platform::tryAllocateLargePages(MemoryRegion& region, size_t size) {
    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) {
        return false;
    }

    SIZE_T large_page_min = GetLargePageMinimum();
    if (large_page_min == 0) {
        return false;
    }

    size_t lp_size = (size + large_page_min - 1) & ~(large_page_min - 1);

    void* ptr = VirtualAlloc(NULL, lp_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (ptr) {
        region.base = static_cast<uint8_t*>(ptr);
        region.size = lp_size;
        region.is_large_pages = true;
        region.large_page_bytes = lp_size;
        region.is_locked = true;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        LOG_INFO("Allocated %zu MB using MEM_LARGE_PAGES", lp_size / 1024 / 1024);
        return true;
    }
    return false;
}

// Chunked large-page allocation: allocates large pages in 1GB chunks within
// a contiguous virtual address range. Each chunk independently needs only 512
// contiguous 2MB physical regions (vs ~11000 for 22GB), making success far
// more likely under physical memory fragmentation.
//
// Strategy: reserve a contiguous VA range, free it, then immediately re-allocate
// each chunk at the same addresses with MEM_LARGE_PAGES. Since we're single-threaded
// and act immediately, the addresses are almost always still available.
bool Platform::tryAllocateLargePagesChunked(MemoryRegion& region, size_t size) {
    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) return false;

    SIZE_T large_page_min = GetLargePageMinimum();
    if (large_page_min == 0) return false;

    // Try progressively smaller chunk sizes. Smaller chunks increase success
    // probability on fragmented systems while preserving contiguous VA layout.
    const size_t chunk_candidates[] = {
        1ULL * 1024 * 1024 * 1024,  // 1GB
        512ULL * 1024 * 1024,       // 512MB
        256ULL * 1024 * 1024,       // 256MB
        128ULL * 1024 * 1024,       // 128MB
        64ULL * 1024 * 1024,        // 64MB
        32ULL * 1024 * 1024,        // 32MB
        16ULL * 1024 * 1024,        // 16MB
        8ULL * 1024 * 1024,         // 8MB
        4ULL * 1024 * 1024,         // 4MB
        2ULL * 1024 * 1024          // 2MB (single large page)
    };

    const size_t candidate_count = sizeof(chunk_candidates) / sizeof(chunk_candidates[0]);
    for (size_t candidate_index = 0; candidate_index < candidate_count; candidate_index++) {
        size_t candidate = chunk_candidates[candidate_index];
        size_t aligned_chunk = (candidate + large_page_min - 1) & ~(large_page_min - 1);
        if (aligned_chunk == 0) continue;
        if (aligned_chunk < static_cast<size_t>(large_page_min)) continue;

        size_t num_chunks = (size + aligned_chunk - 1) / aligned_chunk;
        size_t aligned_total = num_chunks * aligned_chunk;
        size_t reserve_size = aligned_total + large_page_min;
        LOG_INFO("Chunked LP: trying %zu MB chunks (%zu chunks)", aligned_chunk / (1024 * 1024), num_chunks);
        const bool allow_hybrid_tail_lock = (candidate_index == candidate_count - 1); // only at smallest chunk size

        // Retry the whole reserve-free-reallocate sequence a few times.
        for (int attempt = 0; attempt < 3; attempt++) {
            // Step 1: Reserve slightly larger VA space so we can pick a base
            // aligned to large_page_min.
            void* reserved = VirtualAlloc(NULL, reserve_size, MEM_RESERVE, PAGE_NOACCESS);
            if (!reserved) {
                DWORD err = GetLastError();
                LOG_WARN("Chunked LP: failed to reserve %zu MB VA space (error %lu)",
                         reserve_size / (1024 * 1024), err);
                break;
            }

            uintptr_t reserved_addr = reinterpret_cast<uintptr_t>(reserved);
            uintptr_t aligned_addr = (reserved_addr + large_page_min - 1) & ~(static_cast<uintptr_t>(large_page_min) - 1);
            uint8_t* aligned_base = reinterpret_cast<uint8_t*>(aligned_addr);

            // Step 2: Free reservation, then immediately allocate large-page chunks
            // at aligned addresses inside that previously reserved area.
            VirtualFree(reserved, 0, MEM_RELEASE);

            if (!allow_hybrid_tail_lock) {
                bool all_ok = true;
                size_t chunks_allocated = 0;
                for (size_t i = 0; i < num_chunks; i++) {
                    uint8_t* chunk_addr = aligned_base + i * aligned_chunk;
                    void* result = VirtualAlloc(chunk_addr, aligned_chunk,
                                                MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                                PAGE_READWRITE);
                    if (result != chunk_addr) {
                        (void)GetLastError();
                        all_ok = false;
                        break;
                    }
                    chunks_allocated++;
                }

                if (all_ok) {
                    region.base = aligned_base;
                    region.size = aligned_total;
                    region.is_large_pages = true;
                    region.large_page_bytes = aligned_total;
                    region.is_locked = true;
                    region.locked_offset = 0;
                    region.locked_bytes = 0;
                    region.lp_chunk_size = aligned_chunk;

                    LOG_INFO("Allocated %zu MB using chunked large pages (%zu x %zu MB chunks)",
                             aligned_total / (1024 * 1024), num_chunks, aligned_chunk / (1024 * 1024));
                    return true;
                }

                for (size_t j = 0; j < chunks_allocated; j++) {
                    VirtualFree(aligned_base + j * aligned_chunk, 0, MEM_RELEASE);
                }
            } else {
                // Final (2MB) candidate: use a large-page prefix and lock the
                // remaining tail with VirtualLock so reporting and cleanup can
                // distinguish full and hybrid large-page coverage.
                HANDLE hProcess = GetCurrentProcess();
                bool ws_set = false;
                size_t lp_chunks = 0;
                size_t std_locked_chunks = 0;
                size_t chunks_committed = 0;
                bool hybrid_ok = true;

                for (size_t i = 0; i < num_chunks; i++) {
                    uint8_t* chunk_addr = aligned_base + i * aligned_chunk;

                    if (!ws_set) {
                        void* lp_ptr = VirtualAlloc(chunk_addr, aligned_chunk,
                                                    MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                                    PAGE_READWRITE);
                        if (lp_ptr == chunk_addr) {
                            lp_chunks++;
                            chunks_committed++;
                            continue;
                        }

                        SIZE_T remaining_bytes = (num_chunks - i) * aligned_chunk;
                        SIZE_T overhead = 128 * 1024 * 1024;
                        SIZE_T min_ws = remaining_bytes + overhead;
                        SIZE_T max_ws = remaining_bytes + overhead + (512 * 1024 * 1024);
                        if (!SetProcessWorkingSetSize(hProcess, min_ws, max_ws)) {
                            hybrid_ok = false;
                            break;
                        }
                        ws_set = true;
                        LOG_INFO("Chunked LP: full large-page coverage unavailable; locking the remaining %zu MB with VirtualLock",
                                 remaining_bytes / (1024 * 1024));
                    }

                    void* std_ptr = VirtualAlloc(chunk_addr, aligned_chunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    if (std_ptr != chunk_addr) {
                        (void)GetLastError();
                        hybrid_ok = false;
                        break;
                    }

                    if (!VirtualLock(chunk_addr, aligned_chunk)) {
                        (void)GetLastError();
                        VirtualFree(chunk_addr, 0, MEM_RELEASE);
                        hybrid_ok = false;
                        break;
                    }

                    std_locked_chunks++;
                    chunks_committed++;
                }

                if (hybrid_ok && chunks_committed == num_chunks) {
                    region.base = aligned_base;
                    region.size = aligned_total;
                    region.is_large_pages = (lp_chunks > 0);
                    region.large_page_bytes = lp_chunks * aligned_chunk;
                    region.is_locked = true;
                    region.locked_offset = 0;
                    region.locked_bytes = 0; // mixed/sparse locks released by VirtualFree per chunk
                    region.lp_chunk_size = aligned_chunk;

                    LOG_INFO("Allocated %zu MB with hybrid pages (%zu MB large pages + %zu MB VirtualLock)",
                             aligned_total / (1024 * 1024),
                             (lp_chunks * aligned_chunk) / (1024 * 1024),
                             (std_locked_chunks * aligned_chunk) / (1024 * 1024));
                    return true;
                }

                for (size_t j = 0; j < chunks_committed; j++) {
                    if (j >= lp_chunks) {
                        VirtualUnlock(aligned_base + j * aligned_chunk, aligned_chunk);
                    }
                    VirtualFree(aligned_base + j * aligned_chunk, 0, MEM_RELEASE);
                }
            }

            Sleep(100);
        }
    }

    return false;
}

#else

bool Platform::tryAllocateMlock(MemoryRegion& region, size_t size) {
    if (region.base) {
        munmap(region.base, region.size);
        region.base = nullptr;
    }

    region.base = static_cast<uint8_t*>(mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (region.base == MAP_FAILED) {
        region.base = nullptr;
        return false;
    }

    if (mlock(region.base, size) == 0) {
        region.is_locked = true;
        region.large_page_bytes = 0;
        LOG_INFO("Allocated and locked %zu MB using mlock", size / 1024 / 1024);
    } else {
        region.is_locked = false;
        region.large_page_bytes = 0;
        LOG_WARN("mlock failed: %s", strerror(errno));
    }

    return true;
}

bool Platform::tryAllocateStandard(MemoryRegion& region, size_t size) {
    if (region.base) {
        munmap(region.base, region.size);
        region.base = nullptr;
    }

    region.base = static_cast<uint8_t*>(mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (region.base == MAP_FAILED) {
        region.base = nullptr;
        return false;
    }

    region.is_locked = false;
    region.is_large_pages = false;
    region.large_page_bytes = 0;
    region.locked_offset = 0;
    region.locked_bytes = 0;
    LOG_INFO("Allocated %zu MB using standard pages (swappable)", size / 1024 / 1024);
    return true;
}

// Defragment Linux physical memory to maximize hugepage availability.
// Drops filesystem caches and triggers kernel memory compaction.
static void defragLinuxMemory() {
    if (geteuid() != 0) return;  // Requires root

    // Drop page cache, dentries, and inodes to free physical memory
    FILE* fp = fopen("/proc/sys/vm/drop_caches", "w");
    if (fp) {
        fprintf(fp, "3\n");
        fclose(fp);
        LOG_INFO("Dropped filesystem caches to free physical memory");
    }

    // Trigger kernel memory compaction to consolidate free pages into
    // contiguous 2MB regions suitable for hugepages
    fp = fopen("/proc/sys/vm/compact_memory", "w");
    if (fp) {
        fprintf(fp, "1\n");
        fclose(fp);
        LOG_INFO("Triggered kernel memory compaction");
    }

    // Brief pause to let compaction work
    usleep(500000); // 500ms
}

static bool reserveHugepages(size_t size_needed) {
    const size_t hugepage_size = 2ULL * 1024 * 1024;
    int pages_needed = static_cast<int>((size_needed + hugepage_size - 1) / hugepage_size);

    // Read current hugepage count
    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (!fp) return false;

    int current_pages = 0;
    if (fscanf(fp, "%d", &current_pages) != 1) current_pages = 0;
    fclose(fp);

    // Save original count so we can restore on exit
    if (g_original_hugepages < 0) {
        g_original_hugepages = current_pages;
        std::atexit(restoreHugepages);
    }

    // Calculate how many more pages we need
    int additional_pages = pages_needed - current_pages;
    if (additional_pages <= 0) {
        // Already enough hugepages reserved
        return true;
    }

    // Try to reserve hugepages directly first
    int new_total = current_pages + additional_pages + 2; // Add a couple extra

    fp = fopen("/proc/sys/vm/nr_hugepages", "w");
    if (!fp) return false;

    fprintf(fp, "%d\n", new_total);
    fclose(fp);

    // Check how many we actually got
    fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (!fp) return false;
    int actual_pages = 0;
    if (fscanf(fp, "%d", &actual_pages) != 1) actual_pages = 0;
    fclose(fp);

    if (actual_pages >= pages_needed) {
        LOG_INFO("Reserved %d hugepages (requested %d)", actual_pages, pages_needed);
        return true;
    }

    // Not enough — defrag memory and retry
    LOG_INFO("Got %d/%d hugepages, defragmenting memory and retrying...", actual_pages, pages_needed);
    defragLinuxMemory();

    fp = fopen("/proc/sys/vm/nr_hugepages", "w");
    if (!fp) return false;
    fprintf(fp, "%d\n", new_total);
    fclose(fp);

    // Check result
    fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (fp) {
        if (fscanf(fp, "%d", &actual_pages) != 1) actual_pages = 0;
        fclose(fp);
        LOG_INFO("After defrag: got %d/%d hugepages", actual_pages, pages_needed);
    }

    usleep(100000); // 100ms
    return actual_pages >= pages_needed;
}

bool Platform::tryAllocateHugepages(MemoryRegion& region, size_t size) {
    if (region.base) {
        munmap(region.base, region.size);
        region.base = nullptr;
    }

    // Hugepage size is typically 2MB on x86_64 and ARM64
    const size_t hugepage_size = 2ULL * 1024 * 1024;
    
    // Round up to hugepage boundary
    size_t aligned_size = (size + hugepage_size - 1) & ~(hugepage_size - 1);
    
    // Try to allocate with MAP_HUGETLB
    void* ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    
    if (ptr == MAP_FAILED) {
        // Failed to allocate - try to reserve hugepages automatically (requires root)
        if (geteuid() == 0) {  // Running as root
            LOG_INFO("Attempting to reserve hugepages automatically...");
            if (reserveHugepages(aligned_size)) {
                // Try allocation again after reserving
                ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
            }
        }
        
        if (ptr == MAP_FAILED) {
            return false;
        }
    }

    // Lock the hugepages to prevent them from being swapped
    if (mlock(ptr, aligned_size) == 0) {
        region.is_locked = true;
    } else {
        region.is_locked = false;
        LOG_WARN("mlock failed for hugepages: %s", strerror(errno));
    }

    region.base = static_cast<uint8_t*>(ptr);
    region.size = aligned_size;
    region.is_large_pages = true;
    region.large_page_bytes = aligned_size;
    region.locked_bytes = aligned_size;
    
    LOG_INFO("Allocated %zu MB using hugepages (2MB pages)", aligned_size / 1024 / 1024);
    return true;
}

#endif

bool Platform::allocateMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    region.size = size;
    region.base = nullptr;
    region.base_offset_bytes = 0;
    region.is_large_pages = false;
    region.large_page_bytes = 0;
    region.is_locked = false;
    region.locked_offset = 0;
    region.locked_bytes = 0;
    region.lp_chunk_size = 0;

    size_t page_align = 4096;
    region.size = (size + page_align - 1) & ~(page_align - 1);
    
    // Strict requirement: 100% of requested bytes must be locked if locking is requested
#ifdef _WIN32
    size_t min_required_bytes = region.size;
#endif

#ifdef _WIN32
    if (try_large_pages) {
        // Step 1: Pre-defrag to maximize contiguous 2MB regions before first attempt
        LOG_INFO("Defragmenting physical memory before large page allocation...");
        defragPhysicalMemory();

        if (tryAllocateLargePages(region, region.size)) {
            restoreSystemFileCache();
            return true;
        }

        // Step 2: More aggressive defrag — multiple rounds with longer pauses
        LOG_INFO("Large page allocation failed at %zu MB, performing aggressive defragmentation...",
                 region.size / (1024 * 1024));
        for (uint32_t round = 1; round <= 3; ++round) {
            defragPhysicalMemory();
            Sleep(500 * round); // Increasing delay: 500ms, 1s, 1.5s

            if (tryAllocateLargePages(region, region.size)) {
                LOG_INFO("Large page allocation succeeded after defrag round %u", round);
                restoreSystemFileCache();
                return true;
            }
        }
        restoreSystemFileCache();

        // Step 3: Single large-page allocation failed — try chunked allocation (1GB chunks)
        // Each chunk independently finds contiguous 2MB physical regions
        LOG_INFO("Attempting chunked large page allocation (%zu MB in 1GB chunks)...",
                 region.size / (1024 * 1024));
        defragPhysicalMemory();

        if (tryAllocateLargePagesChunked(region, region.size)) {
            restoreSystemFileCache();
            return true;
        }
        restoreSystemFileCache();

        // Large pages failed — fall through to VirtualLock which reliably locks memory
        LOG_INFO("Large page allocation failed at %zu MB after all defrag attempts. "
                 "Falling back to fully locked standard pages.",
                 region.size / (1024 * 1024));
    }

    if (try_lock) {
        // Try strict locking first
        if (tryAllocateVirtualLock(region, region.size, min_required_bytes)) {
            return true;
        }
        
        if (!allow_swappable) {
            LOG_ERROR("Requested STRICT LOCKED memory but could not lock entire region (%zu MB). Aborting.", size / 1024 / 1024);
            return false;
        }
        
        // If swappable is allowed, we can try to allocate swappable memory,
        // BUT we should NOT return partially locked memory as "locked".
        // The previous behavior of falling back to swappable is handled below.
        LOG_WARN("VirtualLock failed, falling back to Swappable allocation (Not Recommended)");
    }

    return tryAllocateStandard(region, region.size);

#else
    // Linux implementation with hugepages support
    if (try_large_pages) {
        if (tryAllocateHugepages(region, region.size)) {
            return true;
        }
        LOG_INFO("Hugepage allocation failed at %zu MB, falling back to locked standard pages",
                 region.size / (1024 * 1024));
    }
    
    // Linux implementation check for strict locking
    if (try_lock) {
         if (tryAllocateMlock(region, region.size)) {
              if (region.is_locked) return true;
               
              if (!allow_swappable) {
                  LOG_ERROR("mlock failed (Limit: %zu bytes). Aborting to avoid swapping.", region.size);
                  freeMemory(region);
                   return false;
               }
           }
          if (region.base != nullptr) {
              return allow_swappable;
          }
          return false;
    }

    return tryAllocateStandard(region, region.size);
#endif
}

MemoryGuard Platform::allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    MemoryRegion region{};
    if (allocateMemory(region, size, try_large_pages, try_lock, allow_swappable)) {
        return MemoryGuard(region.base, region.size, region.is_large_pages, region.large_page_bytes, region.is_locked,
                           region.locked_offset, region.locked_bytes, region.lp_chunk_size);
    }
    return MemoryGuard();
}

void MemoryGuard::freeInternal(uint8_t* base, size_t size, bool large_pages, size_t large_page_bytes, bool locked,
                               size_t locked_offset, size_t locked_bytes, size_t lp_chunk_size) {
     MemoryRegion region;
     region.base = base;
     region.size = size;
     region.is_large_pages = large_pages;
     region.large_page_bytes = large_page_bytes;
     region.is_locked = locked;
     region.locked_offset = locked_offset;
     region.locked_bytes = locked_bytes;
     region.lp_chunk_size = lp_chunk_size;
     Platform::freeMemory(region);
}

void Platform::freeMemory(MemoryRegion& region) {
    if (!region.base) return;

#ifdef _WIN32
    if (region.lp_chunk_size > 0) {
        // Chunked large-page allocation: free each chunk separately
        size_t num_chunks = region.size / region.lp_chunk_size;
        size_t full_large_page_chunks = region.lp_chunk_size > 0 ? (region.large_page_bytes / region.lp_chunk_size) : 0;
        for (size_t i = 0; i < num_chunks; i++) {
            if (region.is_locked && i >= full_large_page_chunks) {
                VirtualUnlock(region.base + i * region.lp_chunk_size, region.lp_chunk_size);
            }
            VirtualFree(region.base + i * region.lp_chunk_size, 0, MEM_RELEASE);
        }
    } else {
        if (region.locked_bytes > 0) {
            VirtualUnlock(region.base + region.locked_offset, region.locked_bytes);
        }
        VirtualFree(region.base, 0, MEM_RELEASE);
    }
#else
    if (region.is_locked) {
        munlock(region.base, region.size);
    }
    munmap(region.base, region.size);

    // Restore hugepage reservation to original count after any hugepage attempt.
    restoreHugepages();
#endif

    region.base = nullptr;
    region.size = 0;
    region.base_offset_bytes = 0;
    region.is_locked = false;
    region.is_large_pages = false;
    region.large_page_bytes = 0;
    region.locked_offset = 0;
    region.locked_bytes = 0;
    region.lp_chunk_size = 0;
}

bool Platform::checkMemoryResident(const uint8_t* base, size_t size) {
#ifdef _WIN32
    // On Windows, VirtualLock'd and Large Pages memory is guaranteed resident
    // Use VirtualQuery to verify the region is still committed
    MEMORY_BASIC_INFORMATION mbi;
    const uint8_t* addr = base;
    size_t remaining = size;
    while (remaining > 0) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        size_t chunk = mbi.RegionSize - (addr - static_cast<const uint8_t*>(mbi.BaseAddress));
        if (chunk >= remaining) break;
        remaining -= chunk;
        addr += chunk;
    }
    return true;
#else
    // Use mincore() to check if pages are resident in physical RAM
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    size_t num_pages = (size + page_size - 1) / page_size;

    std::vector<unsigned char> vec(num_pages);
    // mincore requires page-aligned address
    uintptr_t aligned_base = reinterpret_cast<uintptr_t>(base) & ~(page_size - 1);
    size_t aligned_size = size + (reinterpret_cast<uintptr_t>(base) - aligned_base);
    aligned_size = (aligned_size + page_size - 1) & ~(page_size - 1);
    num_pages = aligned_size / page_size;
    vec.resize(num_pages);

    if (mincore(reinterpret_cast<void*>(aligned_base), aligned_size, vec.data()) != 0) {
        // Fail closed: if residency cannot be verified, test integrity is uncertain.
        LOG_ERROR("mincore() failed: %s", strerror(errno));
        return false;
    }

    size_t non_resident = 0;
    for (size_t i = 0; i < num_pages; ++i) {
        if (!(vec[i] & 1)) {
            non_resident++;
        }
    }

    if (non_resident > 0) {
        double pct = 100.0 * non_resident / num_pages;
        LOG_ERROR("Memory residency check: %zu of %zu pages (%.1f%%) NOT resident in RAM!",
                  non_resident, num_pages, pct);
        return false;
    }
    return true;
#endif
}

bool Platform::setThreadAffinity(uint32_t thread_id, uint32_t num_threads) {
    std::vector<CpuTarget> targets = getPreferredCpuTargets(num_threads);
    if (targets.empty()) return false;
    const CpuTarget& target = targets[thread_id % targets.size()];
    return bindCurrentThread(target);
}

void Platform::registerShutdownHandler(void (*callback)()) {
    g_shutdown_callback = callback;

#ifdef _WIN32
    g_shutdown_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_shutdown_event) {
        g_shutdown_event = INVALID_HANDLE_VALUE;
    }

    SetConsoleCtrlHandler(NULL, FALSE);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#else
    std::signal(SIGINT, SignalHandlerWrapper);
    std::signal(SIGTERM, SignalHandlerWrapper);
    std::signal(SIGBUS, SignalHandlerWrapper);  // Hugepage access fault
#endif
}

} // namespace testsmem4u
