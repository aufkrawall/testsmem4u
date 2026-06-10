#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "Types.h"

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
    uint32_t raw_performance = 100;
    uint32_t weight = 100;
};

struct PlatformInfo {
    char os_name[32];
    char arch[32];
    uint32_t cpu_cores;
    uint32_t page_size;
    bool large_pages_available;
    bool heterogeneous_cores = false;
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
};

class Platform {
private:
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

    // Process Management
    static std::vector<CpuTarget> getPreferredCpuTargets(uint32_t max_threads = 0);
    static bool bindCurrentThread(const CpuTarget& target);
    static void registerShutdownHandler(void (*callback)());
    // Confirms the process runs at NORMAL priority (never elevates it).
    static void confirmNormalProcessPriority();

    // Verify memory is still resident in physical RAM (not swapped/reclaimed)
    static bool checkMemoryResident(const uint8_t* base, size_t size);

    // Safe memory allocation with bounds checking
    static uint64_t getMaxTestableMemory(uint64_t total_ram, uint32_t percent_requested);
    
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
    static bool tryAllocateLargePagesChunked(MemoryRegion& region, size_t size);
    static bool tryAllocateStandard(MemoryRegion& region, size_t size);
#else
private:
    static bool tryAllocateMlock(MemoryRegion& region, size_t size);
    static bool tryAllocateHugepages(MemoryRegion& region, size_t size);
    static bool tryAllocateStandard(MemoryRegion& region, size_t size);
#endif
};

} // namespace testsmem4u
