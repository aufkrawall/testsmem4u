#include "Platform.h"
#include "PlatformMemoryInternal.h"
#include "Logger.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>

namespace testsmem4u {
namespace {

using File = std::unique_ptr<FILE, decltype(&std::fclose)>;

#ifdef TESTSMEM4U_TESTING
std::atomic<const platform_detail::LinuxMemoryHooks*> g_memory_hooks{nullptr};
#endif

size_t readPageSize(const char* path) {
    File file(std::fopen(path, "r"), &std::fclose);
    if (!file) return 0;
    char text[64];
    const size_t count = std::fread(text, 1, sizeof(text), file.get());
    size_t size = 0;
    if (std::ferror(file.get()) || count == sizeof(text) || !memory_pages::parsePageSize(text, count, size)) {
        LOG_DEBUG("Allocation: page-size control unreadable or malformed bytes=%zu", count);
        return 0;
    }
    return size;
}

size_t readMeminfoPageSize(const char* key) {
    File file(std::fopen("/proc/meminfo", "r"), &std::fclose);
    if (!file) return 0;
    char line[256];
    uint64_t value = 0;
    while (std::fgets(line, sizeof(line), file.get())) {
        if (std::strncmp(line, key, std::strlen(key)) != 0) continue;
        if (!memory_pages::readKilobytes(line + std::strlen(key), value) ||
            value > std::numeric_limits<size_t>::max() / 1024) return 0;
        const size_t size = static_cast<size_t>(value) * 1024;
        return size != 0 && (size & (size - 1)) == 0 ? size : 0;
    }
    return 0;
}

size_t defaultHugePageSize() {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->hugepage_size) return hooks->hugepage_size();
#endif
    return readMeminfoPageSize("Hugepagesize:");
}

int advise(void* base, size_t size, int advice) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->advise_memory) return hooks->advise_memory(base, size, advice);
#endif
    return madvise(base, size, advice);
}

int lockMemory(const void* base, size_t size) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->lock_memory) return hooks->lock_memory(base, size);
#endif
    return mlock(base, size);
}

void* mapHuge(size_t size) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->map_huge) return hooks->map_huge(size);
#endif
    return mmap(nullptr, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
}

int unmapMemory(void* base, size_t size) {
#ifdef TESTSMEM4U_TESTING
    const auto* hooks = g_memory_hooks.load(std::memory_order_acquire);
    if (hooks && hooks->unmap_memory) return hooks->unmap_memory(base, size);
#endif
    return munmap(base, size);
}

struct MappingCleanup {
    uint8_t* base;
    size_t size;
    ~MappingCleanup() { if (base) unmapMemory(base, size); }
};

uint8_t* mapAligned(size_t size, size_t alignment) {
    const size_t native = Platform::getNativePageSize();
    if (alignment <= native) {
        void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return ptr == MAP_FAILED ? nullptr : static_cast<uint8_t*>(ptr);
    }
    size_t total = 0;
    if (!memory_pages::alignSize(size, native, total) || total > std::numeric_limits<size_t>::max() - alignment) return nullptr;
    total += alignment;
    void* raw = mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return nullptr;
    auto* base = static_cast<uint8_t*>(raw);
    MappingCleanup cleanup{base, total};
    const size_t prefix = (alignment - reinterpret_cast<uintptr_t>(base) % alignment) % alignment;
    const size_t suffix = total - prefix - size;
    // Keep the target mapping reserved throughout; trim only its excess ends.
    if (prefix) {
        if (munmap(base, prefix) != 0) {
            LOG_ERROR("Allocation: alignment prefix trim failed bytes=%zu error=%d", prefix, errno);
            return nullptr;
        }
        cleanup.base += prefix;
        cleanup.size -= prefix;
    }
    if (suffix && munmap(cleanup.base + size, suffix) != 0) {
        LOG_ERROR("Allocation: alignment suffix trim failed bytes=%zu error=%d", suffix, errno);
        return nullptr;
    }
    auto* aligned = cleanup.base;
    cleanup.base = nullptr;
    return aligned;
}

void prefault(uint8_t* base, size_t size) {
    const auto started = std::chrono::steady_clock::now();
    auto* pages = static_cast<volatile uint8_t*>(base);
    const size_t native = Platform::getNativePageSize();
    for (size_t offset = 0; offset < size; offset += native) pages[offset] = 0;
    LOG_DEBUG("Allocation: prefault bytes=%zu native-page=%zu seconds=%.3f", size, native,
              std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count());
}

void writePreparationControl(const char* path, const char* value, const char* label) {
    File file(std::fopen(path, "w"), &std::fclose);
    if (!file) {
        LOG_WARN("Allocation: %s unavailable error=%d", label, errno);
        return;
    }
    const bool written = std::fputs(value, file.get()) >= 0 && std::fflush(file.get()) == 0;
    const int error = errno;
    const int closed = std::fclose(file.release());
    if (written && closed == 0) LOG_INFO("Allocation: %s completed", label);
    else LOG_WARN("Allocation: %s failed error=%d", label, written ? errno : error);
}

void defragLinuxMemory() {
    if (geteuid() != 0) {
        LOG_WARN("Allocation: aggressive preparation requires root; continuing with process-local THP");
        return;
    }
    writePreparationControl("/proc/sys/vm/drop_caches", "3\n", "cache-drop");
    writePreparationControl("/proc/sys/vm/compact_memory", "1\n", "compaction");
}

} // namespace

#ifdef TESTSMEM4U_TESTING
const platform_detail::LinuxMemoryHooks* platform_detail::setLinuxMemoryHooks(const LinuxMemoryHooks* hooks) {
    return g_memory_hooks.exchange(hooks, std::memory_order_acq_rel);
}
#endif

size_t Platform::getNativePageSize() {
    const long size = sysconf(_SC_PAGESIZE);
    return size > 0 ? static_cast<size_t>(size) : 0;
}

size_t Platform::getPreferredLargePageSize() {
    // PMD-sized THPs are process-owned and do not require a persistent pool.
    const size_t thp = readPageSize("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size");
    return thp > 0 ? thp : defaultHugePageSize();
}

memory_pages::Coverage Platform::queryLargePageCoverage(const MemoryRegion& region) {
    if (region.is_large_pages) {
        const size_t bytes = region.large_page_bytes > region.base_offset_bytes ?
            std::min(region.size, region.large_page_bytes - region.base_offset_bytes) : 0;
        return {bytes, bytes, defaultHugePageSize(), true, false};
    }
    File file(std::fopen("/proc/self/smaps", "r"), &std::fclose);
    if (!file) return {};
    memory_pages::SmapsCoverage parser(reinterpret_cast<uintptr_t>(region.base), region.size);
    char line[512];
    bool continuation = false;
    while (std::fgets(line, sizeof(line), file.get())) {
        if (!continuation) parser.consume(line);
        continuation = std::strchr(line, '\n') == nullptr;
    }
    if (std::ferror(file.get())) return {};
    auto result = parser.finish();
    result.page_size = getPreferredLargePageSize();
    return result;
}

bool Platform::tryAllocateHugepages(MemoryRegion& region, size_t size) {
    const size_t huge = defaultHugePageSize();
    // Keep small windows small on ARM64 and systems with 1 GiB HugeTLB pages.
    if (huge == 0 || size % huge != 0) {
        LOG_DEBUG("Allocation: HugeTLB skipped bytes=%zu default-page=%zu (incompatible window)", size, huge);
        return false;
    }
    void* ptr = mapHuge(size);
    if (ptr == MAP_FAILED) {
        LOG_DEBUG("Allocation: HugeTLB unavailable bytes=%zu page-size=%zu error=%d; trying process-local THP", size, huge, errno);
        return false;
    }
    MappingCleanup cleanup{static_cast<uint8_t*>(ptr), size};
    prefault(cleanup.base, size);
    LOG_INFO("Allocation: HugeTLB bytes=%zu page-size=%zu non-swappable=yes (no mlock required)", size, huge);
    region.base = cleanup.base;
    region.size = size;
    region.is_large_pages = true;
    region.large_page_bytes = size;
    region.is_locked = true;
    cleanup.base = nullptr;
    return true;
}

bool Platform::allocateNativeMemory(MemoryRegion& region, size_t size, bool try_large_pages, bool try_lock, bool allow_swappable) {
    if (try_large_pages && tryAllocateHugepages(region, size)) return true;
    const size_t native = getNativePageSize();
    const size_t preferred = try_large_pages ? getPreferredLargePageSize() : native;
    auto* base = mapAligned(size, std::max(native, preferred));
    if (!base) {
        LOG_ERROR("Allocation: anonymous mmap failed bytes=%zu error=%d", size, errno);
        return false;
    }
    MappingCleanup cleanup{base, size};
    const int advice = try_large_pages ? MADV_HUGEPAGE : MADV_NOHUGEPAGE;
    if (advise(base, size, advice) != 0) {
        LOG_DEBUG("Allocation: %s unavailable error=%d; native-page fallback remains valid",
                  try_large_pages ? "MADV_HUGEPAGE" : "MADV_NOHUGEPAGE", errno);
    }
    prefault(base, size);
    bool locked = false;
    if (try_lock) {
        locked = lockMemory(base, size) == 0;
        if (!locked) {
            const int error = errno;
            struct rlimit limit{};
            const bool have_limit = getrlimit(RLIMIT_MEMLOCK, &limit) == 0;
            LOG_ERROR("Allocation: mlock failed bytes=%zu error=%d memlock-limit=%llu strict=%s", size, error,
                      have_limit ? static_cast<unsigned long long>(limit.rlim_cur) : 0ULL,
                      allow_swappable ? "no" : "yes");
            if (!allow_swappable) return false;
        }
    }
    MemoryRegion observed;
    observed.base = base;
    observed.size = size;
    auto coverage = queryLargePageCoverage(observed);
    if (try_large_pages && aggressiveDefragEnabled() && (!coverage.known || coverage.bytes < size)) {
        defragLinuxMemory();
        // Linux 6.1+: synchronous, process-local compaction; older kernels fall
        // back on EINVAL. No sleeps and no persistent hugepage pool writes.
        constexpr int collapse = 25; // MADV_COLLAPSE UAPI, absent in older libc headers.
        if (advise(base, size, collapse) != 0) LOG_DEBUG("Allocation: MADV_COLLAPSE incomplete error=%d", errno);
        coverage = queryLargePageCoverage(observed);
    }
    LOG_INFO("Allocation: anonymous bytes=%zu locked=%s THP=%zu..%zu coverage-known=%s preferred-page=%zu",
             size, locked ? "yes" : "no", coverage.bytes, coverage.possible_bytes,
             coverage.known ? "yes" : "no", preferred);
    region.base = base;
    region.size = size;
    region.is_locked = locked;
    cleanup.base = nullptr;
    return true;
}

} // namespace testsmem4u
#endif
