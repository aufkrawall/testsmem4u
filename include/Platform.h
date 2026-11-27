#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "Types.h"
#include "MemoryPages.h"

namespace testsmem4u {

struct CpuTarget {
    uint16_t group = 0;
    uint16_t logical_index = 0;
    uint16_t core_index = 0;
    uint16_t numa_node = 0;
    uint8_t efficiency_class = 0;
    uint8_t scheduling_class = 0;
    bool smt = false;
    bool smt_secondary = false;
    bool parked = false;
    // Core-type performance (Windows efficiency class, Linux cpu_capacity);
    // orders targets and detects heterogeneous CPUs. Memory is split into equal
    // chunks pulled dynamically, so there is no per-CPU weight.
    uint32_t raw_performance = 100;
};

struct PlatformInfo {
    char os_name[32];
    char arch[32];
    uint32_t cpu_cores;
    uint32_t page_size;
    bool large_pages_available;
    bool heterogeneous_cores = false;
    // Static literal naming how targets were discovered (diagnostics only).
    const char* cpu_topology_source = "unknown";
    uint32_t cpu_sets_reserved = 0; // Windows CPU sets reserved for other processes
    // Every usable Windows CPU is reserved for another process, so workers run
    // on those reserved CPUs (the affinity mask allows no others).
    bool cpu_sets_reserved_only = false;
    // Online CPUs this process cannot bind to: outside its affinity mask or
    // cpuset, or (32-bit Windows builds) beyond the 32-bit affinity width.
    uint32_t cpu_affinity_excluded = 0;
    std::vector<CpuTarget> cpu_targets;
};

struct MemoryRegion {
    uint8_t* base = nullptr;
    size_t size = 0;
    size_t base_offset_bytes = 0; // Offset from root test allocation for global error reporting
    bool is_large_pages = false;
    size_t large_page_bytes = 0;
    bool is_locked = false;
    size_t locked_offset = 0; // Offset into base where VirtualUnlock should start
    size_t locked_bytes = 0;
    size_t lp_chunk_size = 0;  // >0 when allocated as chunked large pages (each chunk freed separately)
    // Whole-allocation large-page coverage, measured once after allocation and
    // inherited unchanged by worker/sub-block slices. Linux THP measurement walks
    // /proc/self/smaps, so tests must not re-query it per invocation.
    memory_pages::Coverage page_coverage{};
};

class Platform {
private:
    static bool allocateNativeMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable);
    static bool aggressiveDefragEnabled();

    // Internal allocation path used by allocateMemoryRAII (returns raw region).
    static bool allocateMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable = false);

public:
    // Used by MemoryGuard for cleanup.
    static void freeMemory(MemoryRegion& region);

    // Memory Allocation Strategy - RAII (returns MemoryGuard, auto-cleans)
    [[nodiscard]] static MemoryGuard allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable = false);

    // System Info
    static PlatformInfo detectPlatform();
    static uint64_t getTotalSystemRAM();
    static uint64_t getAvailableSystemRAM();
    // Effective hard memory limit imposed on this process (e.g. Linux cgroup
    // memory.max / RLIMIT_AS), or std::numeric_limits<uint64_t>::max() if unbounded.
    static uint64_t getProcessMemoryLimit();
    // Maximum single contiguous region size this build can map (bounded on
    // 32-bit targets by ptrdiff_t and alignment headroom; unbounded on 64-bit).
    static uint64_t getMaxMappableMemory(bool use_large_pages);
    static size_t getNativePageSize();
    static size_t getPreferredLargePageSize();
    static memory_pages::Coverage queryLargePageCoverage(const MemoryRegion& region);

    // Process Management
    static std::vector<CpuTarget> getPreferredCpuTargets(uint32_t max_threads = 0);
    static bool bindCurrentThread(const CpuTarget& target);
    static void registerShutdownHandler(void (*callback)());
    // Brackets the test run and final result logging. While pending, a Windows
    // console close, logoff or shutdown event requests the stop and then waits
    // in the handler until results are written (setFinalResultsPending(false)),
    // because Windows terminates the process as soon as the handler returns.
    static void setFinalResultsPending(bool pending);
    // Confirms the process runs at NORMAL priority (never elevates it).
    static void confirmNormalProcessPriority();

    // Verify memory is still resident in physical RAM (not swapped/reclaimed).
    // locked=true: any page outside the working set fails (lock guarantee broken).
    // locked=false (Windows): pages Windows trimmed from the working set are read
    // back (data unchanged) and reported; only pages that stay non-resident fail.
    // Linux mincore() non-residency means swapped out and always fails.
    static bool checkMemoryResident(const uint8_t* base, size_t size, bool locked);

    // Memory never tested so the OS keeps running: the preset's "Reserved Memory
    // for Windows (Mb)" (all platforms), but at least this much.
    static constexpr uint32_t kMinOsReserveMB = 256;

    // percent_requested of total_ram minus the OS reserve (0 if nothing is left).
    static uint64_t getMaxTestableMemory(uint64_t total_ram, uint32_t percent_requested,
                                         uint32_t reserve_mb = kMinOsReserveMB);
    
    // Control system-wide memory defragmentation (standby list purge, working set trim, etc.)
    static void setAggressiveDefrag(bool enabled);

    // Capability Check
    static bool hasMemoryLockPrivilege();
    
    // Capability Granting (Windows only, requires Admin)
    static bool grantMemoryLockPrivilege();

#ifdef _WIN32
    // Exposed for use by memory defrag helpers
    static bool enablePrivilege(const char* privilege_name);
private:
    static bool tryAllocateVirtualLock(MemoryRegion& region, size_t size, size_t min_required_bytes);
    static bool tryAllocateLargePages(MemoryRegion& region, size_t size);
    static bool tryAllocateLargePagesChunked(MemoryRegion& region, size_t size, bool allow_hybrid = true);
    static bool tryAllocateStandard(MemoryRegion& region, size_t size);
#else
private:
    static bool tryAllocateHugepages(MemoryRegion& region, size_t size);
#endif
};

} // namespace testsmem4u
