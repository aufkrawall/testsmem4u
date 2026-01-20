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
static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (g_shutdown_initiated) {
        TerminateProcess(GetCurrentProcess(), 0);
        return TRUE;
    }

    g_shutdown_initiated = true;

    if (g_shutdown_callback) {
        g_shutdown_callback();
    }

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
#else
static void SignalHandlerWrapper(int signum) {
    if (g_shutdown_callback) {
        g_shutdown_callback();
    }
    _Exit(1);
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
#elif _M_IX86
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

#if __x86_64__
    strcpy(info.arch, "x86_64");
#elif __i386__
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
    uint64_t max_allowed = total_ram * percent_requested / 100;
    uint64_t min_reserved = 256 * 1024 * 1024; // 256 MB minimum
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

bool Platform::setWorkingSetSize(size_t size) {
    HANDLE hProcess = GetCurrentProcess();

    SIZE_T overhead = 128 * 1024 * 1024;
    SIZE_T min_ws = size + overhead;
    SIZE_T max_ws = size + overhead + (256 * 1024 * 1024);

    if (!SetProcessWorkingSetSize(hProcess, min_ws, max_ws)) {
        DWORD err = GetLastError();
        LOG_WARN("SetProcessWorkingSetSize(min=%zu, max=%zu) failed: error %lu", min_ws, max_ws, err);

        if (!SetProcessWorkingSetSize(hProcess, size, size + overhead)) {
             LOG_ERROR("Could not set minimum working set size for locking!");
             return false;
        }
    }

    return true;
}

bool Platform::tryAllocateLargePages(MemoryRegion& region, size_t size) {
    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) {
        LOG_WARN("SeLockMemoryPrivilege not available for Large Pages");
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
        LOG_INFO("Allocated %zu MB using MEM_LARGE_PAGES", lp_size / 1024 / 1024);
        return true;
    } else {
        LOG_WARN("MEM_LARGE_PAGES allocation failed: error %lu", GetLastError());
        return false;
    }
}

bool Platform::tryAllocateVirtualLock(MemoryRegion& region, size_t size) {
    setWorkingSetSize(size);

    // Free any existing allocation before reassigning
    if (region.base) {
        VirtualFree(region.base, 0, MEM_RELEASE);
        region.base = nullptr;
        region.size = 0;
    }

    region.base = static_cast<uint8_t*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!region.base) {
        LOG_ERROR("VirtualAlloc failed: error %lu", GetLastError());
        return false;
    }

    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) {
        LOG_WARN("SeLockMemoryPrivilege not available for VirtualLock");
        return true; // Still have the memory, just not locked
    }

    size_t chunk = 64 * 1024 * 1024;
    size_t locked = 0;
    bool lock_failed = false;

    while (locked < size) {
        size_t todo = std::min(chunk, size - locked);
        if (!VirtualLock(region.base + locked, todo)) {
            lock_failed = true;
            LOG_WARN("VirtualLock failed at offset %zu: error %lu", locked, GetLastError());
            break;
        }
        locked += todo;
    }

    if (!lock_failed) {
        region.is_locked = true;
        LOG_INFO("Allocated and locked %zu MB using VirtualLock", size / 1024 / 1024);
        return true;
    } else {
        if (locked > 0) {
            VirtualUnlock(region.base, locked);
        }
        region.is_locked = false;
        LOG_WARN("VirtualLock failed, continuing with unlocked memory");
        return true;
    }
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

bool Platform::allocateMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock) {
    region.size = size;
    region.base = nullptr;
    region.is_large_pages = false;
    region.is_locked = false;

    size_t page_align = 4096;
    region.size = (size + page_align - 1) & ~(page_align - 1);

#ifdef _WIN32
    if (try_large_pages) {
        if (tryAllocateLargePages(region, region.size)) {
            return true;
        }
    }

    if (try_lock) {
        if (tryAllocateVirtualLock(region, region.size)) {
            return region.base != nullptr;
        }
    }

    return tryAllocateStandard(region, region.size);

#else
    (void)try_large_pages;
    return tryAllocateMlock(region, region.size);
#endif
}

MemoryGuard Platform::allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock) {
    MemoryRegion region{};
    if (allocateMemory(region, size, try_large_pages, try_lock)) {
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
    if (region.is_locked && !region.is_large_pages) {
        VirtualUnlock(region.base, region.size);
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
