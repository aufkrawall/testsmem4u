#include "Platform.h"
#include "PlatformMemoryInternal.h"
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
namespace {
#ifdef TESTSMEM4U_TESTING
std::atomic<const platform_detail::WindowsMemoryHooks*> g_memory_hooks{nullptr};
#endif

bool releasePages(void* base) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->free_memory) return hooks->free_memory(base);
#endif
    return VirtualFree(base, 0, MEM_RELEASE) != 0;
}

struct MappingCleanup {
    uint8_t* base;
    size_t count;
    size_t chunk_size;
    void clear() noexcept {
        size_t failures = 0;
        DWORD error = 0;
        for (size_t i = 0; i < count; ++i) {
            if (!releasePages(base + i * chunk_size)) {
                ++failures;
                if (error == 0) error = GetLastError();
            }
        }
        if (failures) std::fprintf(stderr, "Allocation: cleanup failures=%zu error=%lu chunks=%zu chunk-size=%zu\n", failures, error, count, chunk_size);
        count = 0;
    }
    ~MappingCleanup() { clear(); }
};

void* allocatePages(void* base, size_t size, DWORD flags, DWORD protection) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->allocate) return hooks->allocate(base, size, flags, protection);
#endif
    return VirtualAlloc(base, size, flags, protection);
}

bool lockPages(void* base, size_t size) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->lock_memory) return hooks->lock_memory(base, size);
#endif
    return VirtualLock(base, size) != 0;
}

bool setWorkingSet(size_t minimum, size_t maximum) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->working_set) return hooks->working_set(minimum, maximum);
#endif
    return SetProcessWorkingSetSize(GetCurrentProcess(), minimum, maximum) != 0;
}

bool enableMemoryLockPrivilege() {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->lock_privilege) return hooks->lock_privilege();
#endif
    return Platform::enablePrivilege(SE_LOCK_MEMORY_NAME);
}
} // namespace

#ifdef TESTSMEM4U_TESTING
const platform_detail::WindowsMemoryHooks* platform_detail::setWindowsMemoryHooks(const WindowsMemoryHooks* hooks) {
    return g_memory_hooks.exchange(hooks, std::memory_order_acq_rel);
}
#endif

size_t Platform::getNativePageSize() {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return info.dwPageSize;
}

size_t Platform::getPreferredLargePageSize() {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->large_page_size) return hooks->large_page_size();
#endif
    return GetLargePageMinimum();
}

memory_pages::Coverage Platform::queryLargePageCoverage(const MemoryRegion& region) {
    const size_t bytes = region.large_page_bytes > region.base_offset_bytes ?
        std::min(region.size, region.large_page_bytes - region.base_offset_bytes) : 0;
    return {bytes, bytes, getPreferredLargePageSize(), true, false};
}

bool Platform::tryAllocateVirtualLock(MemoryRegion& region, size_t size, size_t min_required_bytes) {
    // Enable privilege first
    if (!enableMemoryLockPrivilege()) {
        LOG_ERROR("SeLockMemoryPrivilege not available. Cannot lock memory.");
        return false;
    }

    // Set working set size before allocating so VirtualLock can reserve enough pages.
    SIZE_T overhead = size_t{128} * 1024 * 1024;
    SIZE_T min_ws = size + overhead;
    SIZE_T max_ws = size + overhead + (size_t{512} * 1024 * 1024);

    if (!setWorkingSet(min_ws, max_ws)) {
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

    region.base = static_cast<uint8_t*>(allocatePages(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!region.base) {
        LOG_ERROR("VirtualAlloc failed: error %lu", GetLastError());
        return false;
    }
    MappingCleanup cleanup{region.base, 1, 0};
    region.size = size;

    size_t locked = 0;
    size_t chunk_sizes[] = {size_t{256} * 1024 * 1024, size_t{128} * 1024 * 1024, size_t{64} * 1024 * 1024};

    for (size_t chunk : chunk_sizes) {
        while (locked < size) {
            size_t todo = std::min(chunk, size - locked);
            if (!lockPages(region.base + locked, todo)) {
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
        cleanup.count = 0;
        region.base = nullptr;
        region.size = 0;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        return false;
    }

    cleanup.count = 0;
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

    region.base = static_cast<uint8_t*>(allocatePages(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (region.base) {
        MappingCleanup cleanup{region.base, 1, 0};
        region.size = size;
        LOG_INFO("Allocated %zu MB (Standard)", size / 1024 / 1024);
        region.is_locked = false;
        region.is_large_pages = false;
        region.large_page_bytes = 0;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        cleanup.count = 0;
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
// future versions. Before/after aggregate availability is diagnostic context;
// concurrent allocations can mask the effect and contiguity is not measured.
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
    } else {
        LOG_DEBUG("Allocation: modified-list flush returned status 0x%08lX", status);
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
                LOG_DEBUG("Allocation: standby purge completed; aggregate availability before=%llu MB after=%llu MB "
                          "(concurrent allocations/cache state can mask changes; contiguity not measured)",
                         free_before / (size_t{1024} * 1024), free_after / (size_t{1024} * 1024));
            }
        }
    }
}

// Flush the current cache working set without changing its size-limit policy.
// FILE_CACHE_*_HARD_DISABLE disables limits, not the cache itself; re-enabling
// those limits at zero would leave an unintended persistent system policy.
static void trimSystemFileCache() {
    if (!Platform::enablePrivilege(SE_INCREASE_QUOTA_NAME)) return;
    const SIZE_T flush = std::numeric_limits<SIZE_T>::max();
    if (SetSystemFileCacheSize(flush, flush, 0)) {
        LOG_INFO("Allocation: system file cache flushed; limit policy preserved");
    } else {
        LOG_WARN("Allocation: system file cache flush failed error=%lu", GetLastError());
    }
}

// Defragment physical memory by trimming working sets and purging caches.
// This forces the OS to page out scattered 4KB allocations, freeing up
// contiguous 2MB-aligned regions needed for large pages.
// Cache working-set flushing is separate and preserves its size-limit policy.
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
}



bool Platform::tryAllocateLargePages(MemoryRegion& region, size_t size) {
    if (!enableMemoryLockPrivilege()) {
        return false;
    }

    SIZE_T large_page_min = getPreferredLargePageSize();
    if (large_page_min == 0) {
        return false;
    }

    if (size % large_page_min != 0) {
        LOG_DEBUG("Allocation: large pages skipped bytes=%zu page-size=%zu (incompatible window)", size, static_cast<size_t>(large_page_min));
        return false;
    }
    const size_t lp_size = size;

    void* ptr = allocatePages(nullptr, lp_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (ptr) {
        MappingCleanup cleanup{static_cast<uint8_t*>(ptr), 1, 0};
        region.base = static_cast<uint8_t*>(ptr);
        region.size = lp_size;
        region.is_large_pages = true;
        region.large_page_bytes = lp_size;
        region.is_locked = true;
        region.locked_offset = 0;
        region.locked_bytes = 0;
        LOG_INFO("Allocated %zu MB using MEM_LARGE_PAGES", lp_size / 1024 / 1024);
        cleanup.count = 0;
        return true;
    }
    LOG_DEBUG("Allocation: MEM_LARGE_PAGES failed bytes=%zu error=%lu", size, GetLastError());
    return false;
}

// Each allocation requires physical contiguity within each native large page,
// not across an entire chunk. Exact-size chunks retain contiguous virtual layout.
// Address collisions are checked and rolled back, with bounded immediate retries.
bool Platform::tryAllocateLargePagesChunked(MemoryRegion& region, size_t size, bool allow_hybrid) {
    if (!enableMemoryLockPrivilege()) return false;

    SIZE_T large_page_min = getPreferredLargePageSize();
    if (large_page_min == 0 || size % large_page_min != 0 || size > std::numeric_limits<size_t>::max() - large_page_min) return false;

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
        size_t{2} * 1024 * 1024,
        static_cast<size_t>(large_page_min) // Native minimum, including non-2-MiB systems.
    };

    const size_t candidate_count = sizeof(chunk_candidates) / sizeof(chunk_candidates[0]);
    size_t last_chunk = 0;
    for (size_t candidate_index = 0; candidate_index < candidate_count; candidate_index++) {
        size_t candidate = chunk_candidates[candidate_index];
        size_t aligned_chunk = 0;
        if (!memory_pages::alignSize(candidate, large_page_min, aligned_chunk) ||
            aligned_chunk > size || size % aligned_chunk != 0) continue;
        if (aligned_chunk == last_chunk) continue;
        last_chunk = aligned_chunk;

        const size_t num_chunks = size / aligned_chunk;
        const size_t aligned_total = size;
        size_t reserve_size = aligned_total + large_page_min;
        LOG_INFO("Chunked LP: trying %zu MB chunks (%zu chunks)", aligned_chunk / (size_t{1024} * 1024), num_chunks);
        const bool allow_hybrid_tail_lock = allow_hybrid && aligned_chunk == large_page_min;

        // Retry the whole reserve-free-reallocate sequence a few times.
        for (int attempt = 0; attempt < 3; attempt++) {
            // Step 1: Reserve slightly larger VA space so we can pick a base
            // aligned to large_page_min.
            void* reserved = allocatePages(nullptr, reserve_size, MEM_RESERVE, PAGE_NOACCESS);
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
            MappingCleanup reservation{static_cast<uint8_t*>(reserved), 1, 0};
            if (!VirtualFree(reserved, 0, MEM_RELEASE)) {
                LOG_WARN("Allocation: reservation release failed error=%lu", GetLastError());
                break;
            }
            reservation.count = 0;
            MappingCleanup cleanup{aligned_base, 0, aligned_chunk};

            if (!allow_hybrid_tail_lock) {
                bool all_ok = true;
                for (size_t i = 0; i < num_chunks; i++) {
                    uint8_t* chunk_addr = aligned_base + i * aligned_chunk;
                    void* result = allocatePages(chunk_addr, aligned_chunk,
                                                MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                                PAGE_READWRITE);
                    if (result != chunk_addr) {
                        LOG_DEBUG("Allocation: chunk address unavailable bytes=%zu error=%lu", aligned_chunk, GetLastError());
                        all_ok = false;
                        break;
                    }
                    ++cleanup.count;
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
                    cleanup.count = 0;
                    return true;
                }
            } else {
                // Native large-page-sized candidate: use a large-page prefix and lock the
                // remaining tail with VirtualLock so reporting and cleanup can
                // distinguish full and hybrid large-page coverage.
                bool ws_set = false;
                size_t lp_chunks = 0;
                size_t std_locked_chunks = 0;
                size_t chunks_committed = 0;
                bool hybrid_ok = true;

                for (size_t i = 0; i < num_chunks; i++) {
                    uint8_t* chunk_addr = aligned_base + i * aligned_chunk;

                    if (!ws_set) {
                        void* lp_ptr = allocatePages(chunk_addr, aligned_chunk,
                                                    MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                                    PAGE_READWRITE);
                        if (lp_ptr == chunk_addr) {
                            ++cleanup.count;
                            lp_chunks++;
                            chunks_committed++;
                            continue;
                        }

                        SIZE_T remaining_bytes = (num_chunks - i) * aligned_chunk;
                        SIZE_T overhead = size_t{128} * 1024 * 1024;
                        SIZE_T min_ws = remaining_bytes + overhead;
                        SIZE_T max_ws = remaining_bytes + overhead + (size_t{512} * 1024 * 1024);
                        if (!setWorkingSet(min_ws, max_ws)) {
                            hybrid_ok = false;
                            break;
                        }
                        ws_set = true;
                        LOG_INFO("Chunked LP: full large-page coverage unavailable; locking the remaining %zu MB with VirtualLock",
                                 remaining_bytes / (size_t{1024} * 1024));
                    }

                    void* std_ptr = allocatePages(chunk_addr, aligned_chunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    if (std_ptr != chunk_addr) {
                        LOG_DEBUG("Allocation: chunk address unavailable bytes=%zu error=%lu", aligned_chunk, GetLastError());
                        hybrid_ok = false;
                        break;
                    }
                    ++cleanup.count;

                    if (!lockPages(chunk_addr, aligned_chunk)) {
                        LOG_DEBUG("Allocation: chunk address unavailable bytes=%zu error=%lu", aligned_chunk, GetLastError());
                        VirtualFree(chunk_addr, 0, MEM_RELEASE);
                        --cleanup.count;
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
                    cleanup.count = 0;
                    return true;
                }
            }

            cleanup.clear();
            LOG_DEBUG("Allocation: chunk attempt failed chunk=%zu attempt=%d; committed chunks rolled back", aligned_chunk, attempt + 1);
        }
    }

    return false;
}

static void prepareWindowsMemory() {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->prepare_memory) {
        hooks->prepare_memory();
        return;
    }
#endif
    trimSystemFileCache();
    defragPhysicalMemory();
}

bool Platform::allocateNativeMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    constexpr size_t working_set_headroom = size_t{640} * 1024 * 1024;
    if (size > std::numeric_limits<size_t>::max() - working_set_headroom) {
        LOG_ERROR("Allocation: requested size cannot include working-set headroom bytes=%zu", size);
        return false;
    }
    if (try_large_pages) {
        LOG_DEBUG("Allocation: trying Windows large pages bytes=%zu aggressive=%s", size, aggressiveDefragEnabled() ? "yes" : "no");
        if (tryAllocateLargePages(region, size)) return true;
        if (tryAllocateLargePagesChunked(region, size, !aggressiveDefragEnabled())) return true;
        if (aggressiveDefragEnabled()) {
            LOG_INFO("Allocation: full large pages unavailable; performing one system-wide preparation");
            prepareWindowsMemory();
            if (tryAllocateLargePages(region, size) || tryAllocateLargePagesChunked(region, size)) return true;
        }
        LOG_INFO("Allocation: large-page attempts exhausted; native-page fallback locked=%s", try_lock ? "yes" : "no");
    }

    if (try_lock) {
        // Try strict locking first
        if (tryAllocateVirtualLock(region, size, size)) {
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

    return tryAllocateStandard(region, size);

}
} // namespace testsmem4u
#endif
