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

#ifdef _WIN32
namespace testsmem4u {
bool Platform::tryAllocateVirtualLock(MemoryRegion& region, size_t size, size_t min_required_bytes) {
    // Enable privilege first
    if (!enablePrivilege(SE_LOCK_MEMORY_NAME)) {
        LOG_ERROR("SeLockMemoryPrivilege not available. Cannot lock memory.");
        return false;
    }

    // Set working set size before allocating so VirtualLock can reserve enough pages.
    HANDLE hProcess = GetCurrentProcess();
    SIZE_T overhead = size_t{128} * 1024 * 1024;
    SIZE_T min_ws = size + overhead;
    SIZE_T max_ws = size + overhead + (size_t{512} * 1024 * 1024);

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

    region.base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!region.base) {
        LOG_ERROR("VirtualAlloc failed: error %lu", GetLastError());
        return false;
    }

    size_t locked = 0;
    size_t chunk_sizes[] = {size_t{256} * 1024 * 1024, size_t{128} * 1024 * 1024, size_t{64} * 1024 * 1024};

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

    region.base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
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
//
// NOTE: Uses undocumented system-information class 80 (SYSTEM_MEMORY_LIST_INFORMATION)
// which is not part of the public Windows API and may change or be removed in
// future versions. A before/after memory probe verifies the operation had an effect
// and logs a warning if the syscall succeeded but memory did not increase.
//
// Last verified: Windows 10 22H2, Windows 11 24H2 (2026-06-04).
// If this breaks on a future Windows version, the code gracefully falls back:
// purgeStandbyList returns void, defragPhysicalMemory continues, and
// allocateMemory retries with chunked large pages and VirtualLock.
static void purgeStandbyList() {
    // NtSetSystemInformation is not in public headers, load dynamically
    using NtSetSystemInformation_t = LONG (NTAPI *)(ULONG, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    FARPROC raw_proc = GetProcAddress(ntdll, "NtSetSystemInformation");
    if (!raw_proc) return;

    NtSetSystemInformation_t nt_set_system_info = nullptr;
    static_assert(sizeof(nt_set_system_info) == sizeof(raw_proc), "Unexpected function pointer size mismatch");
    void* p = reinterpret_cast<void*>(raw_proc);
    nt_set_system_info = reinterpret_cast<NtSetSystemInformation_t>(p);
    if (!nt_set_system_info) return;

    // Enable required privilege
    Platform::enablePrivilege(SE_PROF_SINGLE_PROCESS_NAME);

    // Probe available memory before the operation to verify effectiveness
    MEMORYSTATUSEX mem_before{};
    mem_before.dwLength = sizeof(mem_before);
    bool have_baseline = GlobalMemoryStatusEx(&mem_before) != 0;
    ULONGLONG free_before = have_baseline ? mem_before.ullAvailPhys : 0;

    const ULONG SYSTEM_MEMORY_LIST_INFORMATION = 80;

    // Flush modified pages to disk first — dirty pages cannot be reused for
    // large pages until written out. This converts modified → standby.
    ULONG flush_cmd = 3; // MemoryFlushModifiedList
    LONG status = nt_set_system_info(SYSTEM_MEMORY_LIST_INFORMATION, &flush_cmd, sizeof(flush_cmd));
    if (status == 0) {
        LOG_INFO("Flushed modified page list to disk");
    }

    // Now purge the standby list — frees both original standby pages and
    // the newly-flushed pages, maximizing free 2MB-aligned regions.
    ULONG purge_cmd = 4; // MemoryPurgeStandbyList
    status = nt_set_system_info(SYSTEM_MEMORY_LIST_INFORMATION, &purge_cmd, sizeof(purge_cmd));

    if (status == 0) {
        LOG_INFO("Purged standby list to free physical memory for large pages");
    } else {
        LOG_DEBUG("Standby list purge returned status 0x%08lX (may require higher privileges)", status);
    }

    // Verify the operation had a measurable effect on available memory
    if (have_baseline) {
        MEMORYSTATUSEX mem_after{};
        mem_after.dwLength = sizeof(mem_after);
        if (GlobalMemoryStatusEx(&mem_after)) {
            ULONGLONG free_after = mem_after.ullAvailPhys;
            if (status == 0 && free_after <= free_before) {
                LOG_WARN("Standby list purge reported success but available memory did not increase "
                         "(before=%llu MB, after=%llu MB). "
                         "This Windows version may have changed or removed the SYSTEM_MEMORY_LIST_INFORMATION interface (syscall 80).",
                         free_before / (size_t{1024} * 1024), free_after / (size_t{1024} * 1024));
            }
        }
    }
}

// RAII guard that disables the system file cache once and re-enables it
// on scope exit (normal return, exception, or early-exit). This eliminates
// the crash-between-disable-and-restore gap that would leave the file cache
// permanently disabled until reboot.
class FileCacheGuard {
    bool active_ = false;
public:
    void disable() {
        if (Platform::enablePrivilege(SE_INCREASE_QUOTA_NAME)) {
            if (SetSystemFileCacheSize(0, 0,
                FILE_CACHE_MIN_HARD_DISABLE | FILE_CACHE_MAX_HARD_DISABLE)) {
                active_ = true;
                LOG_INFO("Disabled system file cache to free physical memory");
            }
        }
    }
    ~FileCacheGuard() {
        if (active_) {
            Platform::enablePrivilege(SE_INCREASE_QUOTA_NAME);
            SetSystemFileCacheSize(0, 0,
                FILE_CACHE_MIN_HARD_ENABLE | FILE_CACHE_MAX_HARD_ENABLE);
            LOG_DEBUG("Restored system file cache");
        }
    }
    FileCacheGuard() = default;
    FileCacheGuard(const FileCacheGuard&) = delete;
    FileCacheGuard& operator=(const FileCacheGuard&) = delete;
};

// Defragment physical memory by trimming working sets and purging caches.
// This forces the OS to page out scattered 4KB allocations, freeing up
// contiguous 2MB-aligned regions needed for large pages.
// NOTE: File cache disable is now handled by FileCacheGuard in allocateMemory.
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

    // Purge the standby list — this is the most impactful step
    purgeStandbyList();

    // Give the OS a moment to consolidate freed pages
    Sleep(500);
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

    void* ptr = VirtualAlloc(nullptr, lp_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
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
        size_t{1} * 1024 * 1024 * 1024,  // 1GB
        size_t{512} * 1024 * 1024,       // 512MB
        size_t{256} * 1024 * 1024,       // 256MB
        size_t{128} * 1024 * 1024,       // 128MB
        size_t{64} * 1024 * 1024,        // 64MB
        size_t{32} * 1024 * 1024,        // 32MB
        size_t{16} * 1024 * 1024,        // 16MB
        size_t{8} * 1024 * 1024,         // 8MB
        size_t{4} * 1024 * 1024,         // 4MB
        size_t{2} * 1024 * 1024          // 2MB (single large page)
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
        LOG_INFO("Chunked LP: trying %zu MB chunks (%zu chunks)", aligned_chunk / (size_t{1024} * 1024), num_chunks);
        const bool allow_hybrid_tail_lock = (candidate_index == candidate_count - 1); // only at smallest chunk size

        // Retry the whole reserve-free-reallocate sequence a few times.
        for (int attempt = 0; attempt < 3; attempt++) {
            // Step 1: Reserve slightly larger VA space so we can pick a base
            // aligned to large_page_min.
            void* reserved = VirtualAlloc(nullptr, reserve_size, MEM_RESERVE, PAGE_NOACCESS);
            if (!reserved) {
                DWORD err = GetLastError();
                LOG_WARN("Chunked LP: failed to reserve %zu MB VA space (error %lu)",
                         reserve_size / (size_t{1024} * 1024), err);
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
                             aligned_total / (size_t{1024} * 1024), num_chunks, aligned_chunk / (size_t{1024} * 1024));
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
                        SIZE_T overhead = size_t{128} * 1024 * 1024;
                        SIZE_T min_ws = remaining_bytes + overhead;
                        SIZE_T max_ws = remaining_bytes + overhead + (size_t{512} * 1024 * 1024);
                        if (!SetProcessWorkingSetSize(hProcess, min_ws, max_ws)) {
                            hybrid_ok = false;
                            break;
                        }
                        ws_set = true;
                        LOG_INFO("Chunked LP: full large-page coverage unavailable; locking the remaining %zu MB with VirtualLock",
                                 remaining_bytes / (size_t{1024} * 1024));
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
                             aligned_total / (size_t{1024} * 1024),
                             (lp_chunks * aligned_chunk) / (size_t{1024} * 1024),
                             (std_locked_chunks * aligned_chunk) / (size_t{1024} * 1024));
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

bool Platform::allocateNativeMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    (void)size;
    // RAII guard: disables system file cache once and re-enables on scope exit.
    // This eliminates the crash-between-disable-and-restore window that would
    // permanently disable the file cache until reboot.
    FileCacheGuard cache_guard;

    if (try_large_pages) {
        if (aggressiveDefragEnabled()) {
            // Disable file cache once before the first defrag. The guard destructor
            // will re-enable it on any exit path (success, failure, or exception).
            cache_guard.disable();

            // Step 1: Pre-defrag to maximize contiguous 2MB regions before first attempt
            LOG_INFO("Defragmenting physical memory before large page allocation...");
            defragPhysicalMemory();

            if (tryAllocateLargePages(region, region.size)) {
                return true;
            }

            // Step 2: More aggressive defrag — multiple rounds with longer pauses
            LOG_INFO("Large page allocation failed at %zu MB, performing aggressive defragmentation...",
                     region.size / (size_t{1024} * 1024));
            for (uint32_t round = 1; round <= 3; ++round) {
                defragPhysicalMemory();
                Sleep(500 * round); // Increasing delay: 500ms, 1s, 1.5s

                if (tryAllocateLargePages(region, region.size)) {
                    LOG_INFO("Large page allocation succeeded after defrag round %u", round);
                    return true;
                }
            }

            // Step 3: Single large-page allocation failed — try chunked allocation (1GB chunks)
            // Each chunk independently finds contiguous 2MB physical regions
            LOG_INFO("Attempting chunked large page allocation (%zu MB in 1GB chunks)...",
                     region.size / (size_t{1024} * 1024));
            defragPhysicalMemory();

            if (tryAllocateLargePagesChunked(region, region.size)) {
                return true;
            }

            // Large pages failed — fall through to VirtualLock which reliably locks memory
            LOG_INFO("Large page allocation failed at %zu MB after all defrag attempts. "
                     "Falling back to fully locked standard pages.",
                     region.size / (size_t{1024} * 1024));
        } else {
            // Non-aggressive mode: try large pages directly without defrag
            LOG_INFO("Attempting large page allocation (defrag disabled, use --aggressive-defrag to enable)...");
            if (tryAllocateLargePages(region, region.size)) {
                return true;
            }
            if (tryAllocateLargePagesChunked(region, region.size)) {
                return true;
            }
            LOG_INFO("Large page allocation failed at %zu MB without defrag. "
                     "Falling back to locked standard pages.",
                     region.size / (size_t{1024} * 1024));
        }
    }

    if (try_lock) {
        // Try strict locking first
        if (tryAllocateVirtualLock(region, region.size, region.size)) {
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

}
} // namespace testsmem4u
#endif
