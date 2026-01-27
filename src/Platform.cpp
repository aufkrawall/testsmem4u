#include "Platform.h"
#include "Logger.h"
#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <memory>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <memoryapi.h>
#include <ntsecapi.h> // For LSA functions


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
#include <filesystem>
#endif

namespace fs = std::filesystem;

namespace testsmem4u {

static void (*g_shutdown_callback)() = nullptr;
static bool g_shutdown_initiated = false;
#ifdef _WIN32
static HANDLE g_shutdown_event = nullptr;
#endif

#ifdef _WIN32
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (g_shutdown_initiated) {
        TerminateProcess(GetCurrentProcess(), 0);
        return TRUE;
    }

    g_shutdown_initiated = true;

    if (g_shutdown_callback) {
        g_shutdown_callback();
    }
    
    // NOTE: Logger::emergencyFlush() removed - may not be safe during shutdown
    // Rely on normal process exit to flush pending log entries

    if (dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT || dwCtrlType == CTRL_SHUTDOWN_EVENT) {
        if (g_shutdown_event && g_shutdown_event != INVALID_HANDLE_VALUE) {
            SetEvent(g_shutdown_event);
        }

        Sleep(500);
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}
#pragma clang diagnostic pop
#else
static void SignalHandlerWrapper(int signum) {
    // Mark as shutting down (atomic write is async-signal-safe)
    g_shutdown_initiated = true;
    
    // Callback sets an atomic flag only, which IS async-signal-safe
    // Note: We assume g_shutdown_callback only manipulates atomics
    if (g_shutdown_callback) {
        g_shutdown_callback();
    }
    
    // NOTE: Logger::emergencyFlush() removed - NOT async-signal-safe
    // FILE* operations can deadlock in signal handlers
    // Use _exit() which IS async-signal-safe (exit() is NOT)
    _exit(128 + signum);
}
#endif

PlatformInfo Platform::detectPlatform() {
    PlatformInfo info = {};
    info.large_pages_available = false;

#ifdef _WIN32
    strcpy(info.os_name, "Windows");
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    info.cpu_cores = sys_info.dwNumberOfProcessors;
    info.page_size = sys_info.dwPageSize;

#ifdef _M_X64
    strcpy(info.arch, "x86_64");
#elif defined(_M_IX86) || (defined(__i386__) && !defined(__x86_64__))
    strcpy(info.arch, "x86");
#elif _M_ARM64
    strcpy(info.arch, "ARM64");
#else
    strcpy(info.arch, "Unknown");
#endif

    info.large_pages_available = (GetLargePageMinimum() > 0);

#else
    strcpy(info.os_name, "Linux");
    info.cpu_cores = std::thread::hardware_concurrency();
    info.page_size = sysconf(_SC_PAGESIZE);

#if defined(__x86_64__) && !defined(__i386__)
    strcpy(info.arch, "x86_64");
#elif (defined(__x86_64__) && !defined(__i386__)) || defined(__i386__)
    strcpy(info.arch, "x86");
#elif __aarch64__
    strcpy(info.arch, "ARM64");
#else
    strcpy(info.arch, "Unknown");
#endif

    info.large_pages_available = false;
#endif

    return info;
}

bool Platform::hasMemoryLockPrivilege() {
#ifdef _WIN32
    // Try to enable the privilege. If it works (or is already enabled), we have it.
    // However, enablePrivilege returns true if AdjustTokenPrivileges succeeds (even if privilege not held? No, check EnablePrivilege logic)
    // Actually EnablePrivilege calls LookupPrivilegeValue and then AdjustTokenPrivileges.
    // If user doesn't have the privilege, AdjustTokenPrivileges sets LastError to ERROR_NOT_ALL_ASSIGNED.
    // We should implement a specific check here.
    return enablePrivilege(SE_LOCK_MEMORY_NAME);
#else
    // On Linux, checking RLIMIT_MEMLOCK is good
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) == 0) {
        return (limit.rlim_cur != 0);
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
            VirtualUnlock(region.base, region.locked_bytes);
        }
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
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

    region.locked_bytes = locked;
    region.is_locked = (locked >= min_required_bytes);
    
    double lock_percent = (double)locked / (double)size * 100.0;
    LOG_INFO("Locked %zu of %zu MB (%.1f%%)", locked / 1024 / 1024, size / 1024 / 1024, lock_percent);

    if (locked < min_required_bytes) {
        LOG_ERROR("Could not lock minimum required %.1f%% of memory (%zu MB). Needed %zu MB locked.", 
                  (double)min_required_bytes / (double)size * 100.0,
                  locked / 1024 / 1024,
                  min_required_bytes / 1024 / 1024);
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
        region.locked_bytes = 0;
        return false;
    }

    return true;
}

bool Platform::tryAllocateStandard(MemoryRegion& region, size_t size) {
    // Free any existing allocation before reassigning
    if (region.base) {
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
    }

    region.base = static_cast<uint8_t*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (region.base) {
        LOG_INFO("Allocated %zu MB (Standard)", size / 1024 / 1024);
        region.is_locked = false;
        region.is_large_pages = false;
        return true;
    }
    return false;
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
        region.is_locked = true;
        region.locked_bytes = lp_size;
        LOG_INFO("Allocated %zu MB using MEM_LARGE_PAGES", lp_size / 1024 / 1024);
        return true;
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
        LOG_INFO("Allocated and locked %zu MB using mlock", size / 1024 / 1024);
    } else {
        region.is_locked = false;
        LOG_WARN("mlock failed: %s", strerror(errno));
    }

    return true;
}

#endif

bool Platform::allocateMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    region.size = size;
    region.base = nullptr;
    region.is_large_pages = false;
    region.is_locked = false;
    region.locked_bytes = 0;

    size_t page_align = 4096;
    region.size = (size + page_align - 1) & ~(page_align - 1);
    
    // Strict requirement: 100% of requested bytes must be locked if locking is requested
#ifdef _WIN32
    size_t min_required_bytes = region.size;
#endif

#ifdef _WIN32
    if (try_large_pages) {
        if (tryAllocateLargePages(region, region.size)) {
            return true;
        }
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
    (void)try_large_pages;
    
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
         return region.base != nullptr;
    }

    return tryAllocateMlock(region, region.size);
#endif
}

MemoryGuard Platform::allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    MemoryRegion region{};
    if (allocateMemory(region, size, try_large_pages, try_lock, allow_swappable)) {
        return MemoryGuard(region.base, region.size, region.is_large_pages, region.is_locked);
    }
    return MemoryGuard();
}

void MemoryGuard::freeInternal(uint8_t* base, size_t size, bool large_pages, bool locked) {
     MemoryRegion region;
     region.base = base;
     region.size = size;
     region.is_large_pages = large_pages;
     region.is_locked = locked;
     Platform::freeMemory(region);
}

void Platform::freeMemory(MemoryRegion& region) {
    if (!region.base) return;

#ifdef _WIN32
    if (region.locked_bytes > 0 && !region.is_large_pages) {
        VirtualUnlock(region.base, region.locked_bytes);
    }

    VirtualFree(region.base, 0, MEM_RELEASE);
#else
    if (region.is_locked) {
        munlock(region.base, region.size);
    }
    munmap(region.base, region.size);
#endif

    region.base = nullptr;
    region.size = 0;
    region.is_locked = false;
    region.is_large_pages = false;
    region.locked_bytes = 0;
}

bool Platform::setThreadAffinity(uint32_t thread_id, uint32_t num_threads) {
#ifdef _WIN32
    DWORD_PTR mask = 0;
    uint32_t num_cores = std::thread::hardware_concurrency();
    if (num_cores == 0) return false;

    if (num_threads <= num_cores) {
        mask = (DWORD_PTR)1 << thread_id;
    } else {
        mask = (DWORD_PTR)1 << (thread_id % num_cores);
    }

    HANDLE hThread = GetCurrentThread();
    return SetThreadAffinityMask(hThread, mask) != 0;
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    uint32_t num_cores = std::thread::hardware_concurrency();

    if (num_threads <= num_cores) {
        CPU_SET(thread_id, &cpuset);
    } else {
        CPU_SET(thread_id % num_cores, &cpuset);
    }

    pthread_t current_thread = pthread_self();
    return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) == 0;
#endif
}

void Platform::setProcessPriorityHigh() {
#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#else
    // Set nice value to -5 for higher priority (requires CAP_SYS_NICE or root)
    // Failure is acceptable - just means we'll run at normal priority
    nice(-5);
#endif
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
#endif
}

} // namespace testsmem4u
