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

#include "PlatformMemoryInternal.h"
namespace testsmem4u {
namespace {
std::atomic<bool> g_aggressive_defrag{false};
}
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

    if (!memory_pages::alignSize(size, getNativePageSize(), region.size)) {
        LOG_ERROR("Allocation: invalid size/alignment bytes=%zu native-page=%zu", size, getNativePageSize());
        return false;
    }

    return allocateNativeMemory(region, region.size, try_large_pages, try_lock, allow_swappable);
}

MemoryGuard Platform::allocateMemoryRAII(size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    MemoryRegion region{};
    if (allocateMemory(region, size, try_large_pages, try_lock, allow_swappable)) {
        MemoryGuard guard(region.base, region.size, region.is_large_pages, region.large_page_bytes, region.is_locked,
                          region.locked_offset, region.locked_bytes, region.lp_chunk_size);
        return guard;
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
    if (region.is_locked && !region.is_large_pages) {
        munlock(region.base, region.size);
    }
    if (munmap(region.base, region.size) != 0) {
        LOG_ERROR("Allocation: munmap failed bytes=%zu error=%d", region.size, errno);
    }
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

void Platform::setAggressiveDefrag(bool enabled) {
    g_aggressive_defrag.store(enabled, std::memory_order_relaxed);
}

bool Platform::aggressiveDefragEnabled() { return g_aggressive_defrag.load(std::memory_order_relaxed); }
} // namespace testsmem4u
