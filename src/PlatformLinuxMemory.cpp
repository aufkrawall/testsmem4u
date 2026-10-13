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
#ifndef _WIN32
namespace testsmem4u {
// Original hugepage count to restore on exit (-1 = not modified). Signal
// handlers read it, so it must be a lock-free atomic.
static std::atomic<int> g_original_hugepages{-1};
static_assert(std::atomic<int>::is_always_lock_free, "signal handlers require lock-free hugepage state");

namespace platform_detail {
// Restore hugepage count using only async-signal-safe functions.
// Called from signal handlers before _exit(), which skips atexit handlers.
// Reducing the pool while this process still maps hugepages is safe: the
// kernel turns in-use pages into surplus pages and frees them on exit.
void restoreHugepagesSignalSafe() {
    int val = g_original_hugepages.exchange(-1, std::memory_order_acq_rel);
    if (val < 0) return;

    // Convert integer to string (no snprintf — not async-signal-safe)
    char buf[16];
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
void restoreHugepages() {
    const int original = g_original_hugepages.exchange(-1, std::memory_order_acq_rel);
    if (original < 0) return;

    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "w");
    if (fp) {
        fprintf(fp, "%d\n", original);
        fclose(fp);
        LOG_INFO("Restored hugepages to original count: %d", original);
    } else {
        LOG_WARN("Could not restore hugepages to original count %d: %s", original, strerror(errno));
    }
}

}
bool Platform::tryAllocateMlock(MemoryRegion& region, size_t size) {
    if (region.base) {
        munmap(region.base, region.size);
        region.base = nullptr;
    }

    region.base = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (region.base == MAP_FAILED) {
        region.base = nullptr;
        return false;
    }

    if (mlock(region.base, size) == 0) {
        region.is_locked = true;
        region.large_page_bytes = 0;
        LOG_INFO("Allocated and locked %zu MB using mlock", size / 1024 / 1024);
    } else {
        region.is_locked = false;
        region.large_page_bytes = 0;
        LOG_WARN("mlock failed: %s", strerror(errno));
    }

    return true;
}

bool Platform::tryAllocateStandard(MemoryRegion& region, size_t size) {
    if (region.base) {
        munmap(region.base, region.size);
        region.base = nullptr;
    }

    region.base = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (region.base == MAP_FAILED) {
        region.base = nullptr;
        return false;
    }

    region.is_locked = false;
    region.is_large_pages = false;
    region.large_page_bytes = 0;
    region.locked_offset = 0;
    region.locked_bytes = 0;
    LOG_INFO("Allocated %zu MB using standard pages (swappable)", size / 1024 / 1024);
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
    const size_t hugepage_size = size_t{2} * 1024 * 1024;
    int pages_needed = static_cast<int>((size_needed + hugepage_size - 1) / hugepage_size);

    // Read current hugepage count
    FILE* fp = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (!fp) return false;

    int current_pages = 0;
    if (fscanf(fp, "%d", &current_pages) != 1) current_pages = 0;
    fclose(fp);

    // Save original count so we can restore on exit
    if (g_original_hugepages.load(std::memory_order_acquire) < 0) {
        g_original_hugepages.store(current_pages, std::memory_order_release);
        static bool restore_registered = false;
        if (!restore_registered) {
            std::atexit(platform_detail::restoreHugepages);
            restore_registered = true;
        }
        LOG_INFO("Registered hugepage restoration (original count: %d; restored on exit, "
                 "SIGINT/SIGTERM/SIGHUP, repeated signals, SIGABRT and SIGBUS)", current_pages);
    }

    // Calculate how many more pages we need
    int additional_pages = pages_needed - current_pages;
    if (additional_pages <= 0) {
        // Already enough hugepages reserved
        return true;
    }

    // Cap additional pages to prevent writing hazardous values to kernel sysfs
    if (additional_pages > 100000) {
        LOG_WARN("Capping hugepage request from %d to 100000 pages to avoid system instability",
                 additional_pages);
        additional_pages = 100000;
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
    const size_t hugepage_size = size_t{2} * 1024 * 1024;

    // Round up to hugepage boundary
    size_t aligned_size = (size + hugepage_size - 1) & ~(hugepage_size - 1);

    // Try to allocate with MAP_HUGETLB
    void* ptr = mmap(nullptr, aligned_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

    if (ptr == MAP_FAILED) {
        // Failed to allocate - try to reserve hugepages automatically (requires root)
        if (geteuid() == 0) {  // Running as root
            LOG_INFO("Attempting to reserve hugepages automatically...");
            if (reserveHugepages(aligned_size)) {
                // Try allocation again after reserving
                ptr = mmap(nullptr, aligned_size, PROT_READ | PROT_WRITE,
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
    region.large_page_bytes = aligned_size;
    region.locked_bytes = aligned_size;

    LOG_INFO("Allocated %zu MB using hugepages (2MB pages)", aligned_size / 1024 / 1024);
    return true;
}

bool Platform::allocateNativeMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    (void)size;
    // Linux implementation with hugepages support
    if (try_large_pages) {
        if (aggressiveDefragEnabled()) {
            if (tryAllocateHugepages(region, region.size)) {
                return true;
            }
            LOG_INFO("Hugepage allocation failed at %zu MB, falling back to locked standard pages",
                     region.size / (size_t{1024} * 1024));
        } else {
            // Non-aggressive: try hugepages once, skip defrag and kernel sysfs writes
            const size_t hugepage_size = size_t{2} * 1024 * 1024;
            size_t aligned_size = (region.size + hugepage_size - 1) & ~(hugepage_size - 1);
            void* ptr = mmap(nullptr, aligned_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
            if (ptr != MAP_FAILED) {
                region.base = static_cast<uint8_t*>(ptr);
                region.size = aligned_size;
                region.is_large_pages = true;
                region.large_page_bytes = aligned_size;
                if (mlock(ptr, aligned_size) == 0) {
                    region.is_locked = true;
                }
                LOG_INFO("Allocated %zu MB using hugepages (2MB pages) without defrag",
                         aligned_size / 1024 / 1024);
                return true;
            }
            LOG_INFO("Hugepage allocation failed at %zu MB (use --aggressive-defrag to enable auto-reservation)",
                     region.size / (size_t{1024} * 1024));
        }
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
          if (region.base != nullptr) {
              return allow_swappable;
          }
          return false;
    }

    return tryAllocateStandard(region, region.size);
}
} // namespace testsmem4u
#endif
