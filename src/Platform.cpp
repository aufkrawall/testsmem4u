#include "Platform.h"
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


// Helper for LSA
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

static void initLsaString(PLSA_UNICODE_STRING LsaString, LPWSTR String) {
    DWORD string_length;
    if (String == nullptr) {
        LsaString->Buffer = nullptr;
        LsaString->Length = 0;
        LsaString->MaximumLength = 0;
        return;
    }
    string_length = lstrlenW(String);
    LsaString->Buffer = String;
    LsaString->Length = (USHORT)(string_length * sizeof(WCHAR));
    LsaString->MaximumLength = (USHORT)((string_length + 1) * sizeof(WCHAR));
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

static std::atomic<void (*)()> g_shutdown_callback{nullptr};
static std::atomic<bool> g_shutdown_initiated{false};


#ifdef _WIN32
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static BOOL WINAPI consoleCtrlHandler(DWORD dwCtrlType) {
    if (g_shutdown_initiated.load(std::memory_order_acquire)) {
        TerminateProcess(GetCurrentProcess(), 0);
        return TRUE;
    }

    g_shutdown_initiated.store(true, std::memory_order_release);

    if (auto cb = g_shutdown_callback.load(std::memory_order_relaxed)) {
        cb();
    }
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT ||
        dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT || dwCtrlType == CTRL_SHUTDOWN_EVENT) {
        return TRUE;
    }
    return FALSE;
}
#pragma clang diagnostic pop
#else
static void SignalHandlerWrapper(int signum) {
    // All allocations are process-owned; the kernel frees them on forced exit.
    if (g_shutdown_initiated.load(std::memory_order_acquire)) {
        _exit(128 + signum);
    }

    // Mark as shutting down (release ensures stop flag is visible to workers)
    g_shutdown_initiated.store(true, std::memory_order_release);

    // Callback should only set atomic stop flags.
    if (auto cb = g_shutdown_callback.load(std::memory_order_relaxed)) {
        cb();
    }

    // SIGBUS indicates unsafe access; SIGABRT must not resume test execution.
    if (signum == SIGBUS || signum == SIGABRT) {
        _exit(128 + signum);
    }

    // SIGINT/SIGTERM/SIGHUP: return so the normal shutdown path can flush
    // logs, release memory and report final results.
}
#endif

bool Platform::hasMemoryLockPrivilege() {
#ifdef _WIN32
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID lock_luid;
    if (!LookupPrivilegeValue(nullptr, SE_LOCK_MEMORY_NAME, &lock_luid)) {
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
    status = LsaOpenPolicy(nullptr, &objAttr,
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
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
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
    initLsaString(&userRights, rightName);

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
    uint64_t min_reserved = size_t{256} * 1024 * 1024; // 256 MB minimum
    if (max_allowed <= min_reserved) return 0;
    return max_allowed - min_reserved;
}

#ifdef _WIN32
bool Platform::enablePrivilege(const char* privilege_name) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LOG_WARN("enablePrivilege(%s): OpenProcessToken failed (error %lu)", 
                 privilege_name, GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, privilege_name, &luid)) {
        DWORD err = GetLastError();
        LOG_WARN("enablePrivilege(%s): LookupPrivilegeValue failed (error %lu)",
                 privilege_name, err);
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    if (result && GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        LOG_WARN("enablePrivilege(%s): AdjustTokenPrivileges returned ERROR_NOT_ALL_ASSIGNED. "
                 "The privilege may not be held by this process.", privilege_name);
        result = false;
    }
    if (!result) {
        LOG_WARN("enablePrivilege(%s): failed (error %lu)", privilege_name, GetLastError());
    }
    CloseHandle(hToken);
    return result;
}


#endif

// The RAM tester is memory-bandwidth bound; elevating the process priority does
// not help and HIGH_PRIORITY_CLASS can freeze Windows when every core is
// saturated. This only confirms/normalizes the process to NORMAL priority.
void Platform::confirmNormalProcessPriority() {
#ifdef _WIN32
    if (SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS)) {
        LOG_INFO("Process priority class confirmed as NORMAL_PRIORITY_CLASS");
    } else {
        LOG_WARN("Failed to confirm process priority class: error %lu", GetLastError());
    }
#else
    LOG_INFO("Process running at default priority (no nice adjustment)");
#endif
}

void Platform::registerShutdownHandler(void (*callback)()) {
    g_shutdown_callback.store(callback, std::memory_order_relaxed);

#ifdef _WIN32
    SetConsoleCtrlHandler(nullptr, FALSE);
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
#else
    std::signal(SIGINT, SignalHandlerWrapper);
    std::signal(SIGTERM, SignalHandlerWrapper);
    std::signal(SIGHUP, SignalHandlerWrapper);  // Closed terminal: stop gracefully
    std::signal(SIGBUS, SignalHandlerWrapper);  // Hugepage access fault
    std::signal(SIGABRT, SignalHandlerWrapper); // Exit on abort
#endif
}

} // namespace testsmem4u
