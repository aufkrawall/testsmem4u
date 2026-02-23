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
#include <fcntl.h>
#endif

namespace fs = std::filesystem;

namespace testsmem4u {

static void (*g_shutdown_callback)() = nullptr;
static std::atomic<bool> g_shutdown_initiated{false};
#ifdef _WIN32
static HANDLE g_shutdown_event = nullptr;
#else
// Original hugepage count to restore on exit (-1 = not modified)
static int g_original_hugepages = -1;
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
    PlatformInfo info = {};
    info.large_pages_available = false;

#ifdef _WIN32
    snprintf(info.os_name, sizeof(info.os_name), "Windows");
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    info.cpu_cores = sys_info.dwNumberOfProcessors;
    info.page_size = sys_info.dwPageSize;

#ifdef _M_X64
    snprintf(info.arch, sizeof(info.arch), "x86_64");
#elif defined(_M_IX86) || (defined(__i386__) && !defined(__x86_64__))
    snprintf(info.arch, sizeof(info.arch), "x86");
#elif _M_ARM64
    snprintf(info.arch, sizeof(info.arch), "ARM64");
#else
    snprintf(info.arch, sizeof(info.arch), "Unknown");
#endif

    info.large_pages_available = (GetLargePageMinimum() > 0);

#else
    snprintf(info.os_name, sizeof(info.os_name), "Linux");
    info.cpu_cores = std::thread::hardware_concurrency();
    info.page_size = sysconf(_SC_PAGESIZE);

#if defined(__x86_64__) && !defined(__i386__)
    snprintf(info.arch, sizeof(info.arch), "x86_64");
#elif defined(__i386__)
    snprintf(info.arch, sizeof(info.arch), "x86");
#elif __aarch64__
    snprintf(info.arch, sizeof(info.arch), "ARM64");
#else
    snprintf(info.arch, sizeof(info.arch), "Unknown");
#endif

    // Check for hugepage support on Linux
    // Try to read /proc/sys/vm/nr_hugepages to see if hugepages are configured
    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (fp) {
        int nr_hugepages = 0;
        if (fscanf(fp, "%d", &nr_hugepages) == 1 && nr_hugepages > 0) {
            info.large_pages_available = true;
        }
        fclose(fp);
    }
    // Also check if we can allocate hugepages via MAP_HUGETLB
    // by attempting a small test allocation
    if (!info.large_pages_available) {
        void* test = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (test != MAP_FAILED) {
            info.large_pages_available = true;
            munmap(test, 2 * 1024 * 1024);
        }
    }
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
        region.locked_offset = 0;
        region.locked_bytes = 0;
    }

    region.base = static_cast<uint8_t*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (region.base) {
        LOG_INFO("Allocated %zu MB (Standard)", size / 1024 / 1024);
        region.is_locked = false;
        region.is_large_pages = false;
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
    typedef LONG (NTAPI *NtSetSystemInformation_t)(INT, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    auto NtSetSystemInfo = (NtSetSystemInformation_t)GetProcAddress(ntdll, "NtSetSystemInformation");
    if (!NtSetSystemInfo) return;

    // Enable required privilege
    Platform::enablePrivilege(SE_PROF_SINGLE_PROCESS_NAME);

    const INT SystemMemoryListInformation = 80;

    // Flush modified pages to disk first — dirty pages cannot be reused for
    // large pages until written out. This converts modified → standby.
    INT flush_cmd = 3; // MemoryFlushModifiedList
    LONG status = NtSetSystemInfo(SystemMemoryListInformation, &flush_cmd, sizeof(flush_cmd));
    if (status == 0) {
        LOG_INFO("Flushed modified page list to disk");
    }

    // Now purge the standby list — frees both original standby pages and
    // the newly-flushed pages, maximizing free 2MB-aligned regions.
    INT purge_cmd = 4; // MemoryPurgeStandbyList
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
                        DWORD err = GetLastError();
                        LOG_DEBUG("Chunked LP: chunk %zu/%zu at %p failed (error %lu, chunk %zu MB, attempt %d)",
                                  i + 1, num_chunks, chunk_addr, err, aligned_chunk / (1024 * 1024), attempt + 1);
                        all_ok = false;
                        break;
                    }
                    chunks_allocated++;
                }

                if (all_ok) {
                    region.base = aligned_base;
                    region.size = aligned_total;
                    region.is_large_pages = true;
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
                // Final (2MB) candidate: opportunistically try LP per chunk and fallback
                // only failing chunks to VirtualLock, maximizing LP share while keeping
                // full requested bytes locked.
                HANDLE hProcess = GetCurrentProcess();
                bool ws_set = false;
                bool stop_lp_probing = false;
                size_t probe_lp_attempts = 0;
                size_t probe_lp_successes = 0;
                constexpr size_t PROBE_WINDOW_CHUNKS = 256;
                constexpr size_t MIN_LP_HIT_PERCENT = 2;
                size_t lp_chunks = 0;
                size_t std_locked_chunks = 0;
                size_t chunks_committed = 0;
                bool hybrid_ok = true;

                for (size_t i = 0; i < num_chunks; i++) {
                    uint8_t* chunk_addr = aligned_base + i * aligned_chunk;

                    if (!stop_lp_probing) {
                        void* lp_ptr = VirtualAlloc(chunk_addr, aligned_chunk,
                                                    MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                                    PAGE_READWRITE);
                        if (lp_ptr == chunk_addr) {
                            lp_chunks++;
                            chunks_committed++;
                            if (ws_set) {
                                probe_lp_attempts++;
                                probe_lp_successes++;
                                if (probe_lp_attempts >= PROBE_WINDOW_CHUNKS) {
                                    size_t hit_rate = (probe_lp_successes * 100) / probe_lp_attempts;
                                    if (hit_rate < MIN_LP_HIT_PERCENT) {
                                        stop_lp_probing = true;
                                        size_t remaining_mb = ((num_chunks - i - 1) * aligned_chunk) / (1024 * 1024);
                                        LOG_INFO("Chunked LP: LP hit-rate %zu%% in hybrid window; switching remaining %zu MB to VirtualLock tail",
                                                 hit_rate, remaining_mb);
                                    }
                                    probe_lp_attempts = 0;
                                    probe_lp_successes = 0;
                                }
                            }
                            continue;
                        }

                        if (ws_set) {
                            probe_lp_attempts++;
                            if (probe_lp_attempts >= PROBE_WINDOW_CHUNKS) {
                                size_t hit_rate = (probe_lp_successes * 100) / probe_lp_attempts;
                                if (hit_rate < MIN_LP_HIT_PERCENT) {
                                    stop_lp_probing = true;
                                    size_t remaining_mb = ((num_chunks - i) * aligned_chunk) / (1024 * 1024);
                                    LOG_INFO("Chunked LP: LP hit-rate %zu%% in hybrid window; switching remaining %zu MB to VirtualLock tail",
                                             hit_rate, remaining_mb);
                                }
                                probe_lp_attempts = 0;
                                probe_lp_successes = 0;
                            }
                        }
                    }

                    if (!ws_set) {
                        SIZE_T remaining_bytes = (num_chunks - i) * aligned_chunk;
                        SIZE_T overhead = 128 * 1024 * 1024;
                        SIZE_T min_ws = remaining_bytes + overhead;
                        SIZE_T max_ws = remaining_bytes + overhead + (512 * 1024 * 1024);
                        if (!SetProcessWorkingSetSize(hProcess, min_ws, max_ws)) {
                            DWORD err = GetLastError();
                            LOG_DEBUG("Chunked LP hybrid: SetProcessWorkingSetSize(min=%zu MB, max=%zu MB) failed: error %lu",
                                      min_ws / 1024 / 1024, max_ws / 1024 / 1024, err);
                            hybrid_ok = false;
                            break;
                        }
                        ws_set = true;
                        probe_lp_attempts = 0;
                        probe_lp_successes = 0;
                        LOG_INFO("Chunked LP: entering hybrid mode at chunk %zu/%zu (%zu MB LP already allocated)",
                                 i + 1, num_chunks, (lp_chunks * aligned_chunk) / (1024 * 1024));
                    }

                    void* std_ptr = VirtualAlloc(chunk_addr, aligned_chunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    if (std_ptr != chunk_addr) {
                        DWORD err = GetLastError();
                        LOG_DEBUG("Chunked LP hybrid: standard alloc chunk %zu/%zu at %p failed (error %lu)",
                                  i + 1, num_chunks, chunk_addr, err);
                        hybrid_ok = false;
                        break;
                    }

                    if (!VirtualLock(chunk_addr, aligned_chunk)) {
                        DWORD err = GetLastError();
                        LOG_DEBUG("Chunked LP hybrid: VirtualLock chunk %zu/%zu at %p failed (error %lu)",
                                  i + 1, num_chunks, chunk_addr, err);
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
        LOG_INFO("Allocated and locked %zu MB using mlock", size / 1024 / 1024);
    } else {
        region.is_locked = false;
        LOG_WARN("mlock failed: %s", strerror(errno));
    }

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
        LOG_WARN("Large page allocation failed at %zu MB after all defrag attempts. "
                 "Falling back to VirtualLock to guarantee memory locking.",
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
        LOG_WARN("Hugepage allocation failed at %zu MB, falling back to standard pages with mlock",
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
          return region.base != nullptr;
    }

    return tryAllocateMlock(region, region.size);
#endif
}

MemoryGuard Platform::allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    MemoryRegion region{};
    if (allocateMemory(region, size, try_large_pages, try_lock, allow_swappable)) {
        return MemoryGuard(region.base, region.size, region.is_large_pages, region.is_locked, region.locked_offset, region.locked_bytes, region.lp_chunk_size);
    }
    return MemoryGuard();
}

void MemoryGuard::freeInternal(uint8_t* base, size_t size, bool large_pages, bool locked, size_t locked_offset, size_t locked_bytes, size_t lp_chunk_size) {
     MemoryRegion region;
     region.base = base;
     region.size = size;
     region.is_large_pages = large_pages;
     region.is_locked = locked;
     region.locked_offset = locked_offset;
     region.locked_bytes = locked_bytes;
     region.lp_chunk_size = lp_chunk_size;
     Platform::freeMemory(region);
}

void Platform::freeMemory(MemoryRegion& region) {
    if (!region.base) return;

#ifdef _WIN32
    if (region.locked_bytes > 0) {
        VirtualUnlock(region.base + region.locked_offset, region.locked_bytes);
    }

    if (region.lp_chunk_size > 0) {
        // Chunked large-page allocation: free each chunk separately
        size_t num_chunks = region.size / region.lp_chunk_size;
        for (size_t i = 0; i < num_chunks; i++) {
            VirtualFree(region.base + i * region.lp_chunk_size, 0, MEM_RELEASE);
        }
    } else {
        VirtualFree(region.base, 0, MEM_RELEASE);
    }
#else
    if (region.is_locked) {
        munlock(region.base, region.size);
    }
    munmap(region.base, region.size);

    // Restore hugepage reservation to original count
    if (region.is_large_pages) {
        restoreHugepages();
    }
#endif

    region.base = nullptr;
    region.size = 0;
    region.base_offset_bytes = 0;
    region.is_locked = false;
    region.is_large_pages = false;
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
    if (num_cores == 0) return false;

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
    std::signal(SIGBUS, SignalHandlerWrapper);  // Hugepage access fault
#endif
}

} // namespace testsmem4u
