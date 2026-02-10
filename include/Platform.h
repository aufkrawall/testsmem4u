#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "Types.h"

namespace testsmem4u {

struct PlatformInfo {
    char os_name[32];
    char arch[32];
    uint32_t cpu_cores;
    uint32_t page_size;
    bool large_pages_available;
};

struct MemoryRegion {
    uint8_t* base = nullptr;
    size_t size = 0;
    bool is_large_pages = false;
    bool is_locked = false;
    size_t locked_bytes = 0;
};

class Platform {
public:
    // Memory Allocation Strategy - Legacy (returns raw region, caller must free)
    static bool allocateMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable = false);
    static void freeMemory(MemoryRegion& region);

    // Memory Allocation Strategy - RAII (returns MemoryGuard, auto-cleans)
    [[nodiscard]] static MemoryGuard allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable = false);

    // System Info
    static PlatformInfo detectPlatform();
    static uint64_t getTotalSystemRAM();

    // Process Management
    static bool setThreadAffinity(uint32_t thread_id, uint32_t num_threads);
    static void setProcessPriorityHigh();
    static void registerShutdownHandler(void (*callback)());

    // Verify memory is still resident in physical RAM (not swapped/reclaimed)
    static bool checkMemoryResident(const uint8_t* base, size_t size);

    // Safe memory allocation with bounds checking
    static uint64_t getMaxTestableMemory(uint64_t total_ram, uint32_t percent_requested);
    
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
    static bool tryAllocateStandard(MemoryRegion& region, size_t size);
#else
private:
    static bool tryAllocateMlock(MemoryRegion& region, size_t size);
    static bool tryAllocateHugepages(MemoryRegion& region, size_t size);
#endif
};

} // namespace testsmem4u
