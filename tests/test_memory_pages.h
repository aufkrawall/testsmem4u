#pragma once

#include "MemoryPages.h"
#include "PlatformMemoryInternal.h"
#ifndef _WIN32
#include <sys/mman.h>
#include <cerrno>
#endif

void testMemoryPageContracts() {
    using namespace memory_pages;
    size_t aligned = 0;
    expect(alignSize(4097, 4096, aligned) && aligned == 8192, "Native allocation rounds to actual page size");
    expect(alignSize(size_t{17} * 1024 * 1024, size_t{32} * 1024 * 1024, aligned) && aligned == size_t{32} * 1024 * 1024,
           "Alignment handles non-2-MiB hugepages");
    expect(!alignSize(0, 4096, aligned) && !alignSize(1, 0, aligned) && !alignSize(1, 3, aligned),
           "Allocation rejects zero and invalid alignment");
    expect(!alignSize(std::numeric_limits<size_t>::max(), 4096, aligned), "Allocation rounding cannot overflow");
    expect(normalizeWindow(17, true, size_t{2} * 1024 * 1024) == 16 &&
           normalizeWindow(17, false, size_t{2} * 1024 * 1024) == 17,
           "Both platforms share the same large-page window normalization");
    expect(normalizeWindow(1, true, size_t{2} * 1024 * 1024) == 1 && normalizeWindow(17, true, 0) == 17,
           "Small explicit windows and unavailable large pages preserve requested sizing");
    expect(normalizeWindow(513, true, size_t{512} * 1024 * 1024) == 512,
           "Window normalization supports ARM64 PMD page sizes");

    SmapsCoverage full(0x200000, 0x400000);
    full.consume("200000-600000 rw-p 00000000 00:00 0");
    full.consume("AnonHugePages: 4096 kB");
    auto result = full.finish();
    expect(result.known && result.bytes == 0x400000 && result.possible_bytes == result.bytes,
           "Full THP coverage is measured exactly");

    SmapsCoverage partial(0x400000, 0x200000);
    partial.consume("200000-600000 rw-p 00000000 00:00 0");
    partial.consume("AnonHugePages: 2048 kB");
    result = partial.finish();
    expect(result.known && result.bytes == 0 && result.possible_bytes == 0x200000,
           "Partial VMA totals cannot invent a THP prefix for a worker slice");

    SmapsCoverage all_huge_slice(0x400000, 0x200000);
    all_huge_slice.consume("200000-600000 rw-p 00000000 00:00 0");
    all_huge_slice.consume("AnonHugePages: 4096 kB");
    expect(all_huge_slice.finish().bytes == 0x200000, "Slice of a fully huge VMA retains full coverage");

    SmapsCoverage mixed(0x200000, 0x400000);
    mixed.consume("200000-400000 rw-p 00000000 00:00 0");
    mixed.consume("AnonHugePages: 2048 kB");
    mixed.consume("400000-600000 rw-p 00000000 00:00 0");
    mixed.consume("AnonHugePages: 0 kB");
    result = mixed.finish();
    expect(result.known && result.bytes == 0x200000 && result.possible_bytes == result.bytes,
           "Coverage aggregates all matching VMAs without losing native-page tails");

    SmapsCoverage absent(0x200000, 0x400000);
    expect(!absent.finish().known, "Missing smaps is unknown rather than a false zero/full result");
    SmapsCoverage invalid(0x200000, 0x200000);
    invalid.consume("200000-400000 rw-p 00000000 00:00 0");
    invalid.consume("AnonHugePages: 4096 kB");
    expect(!invalid.finish().known, "Malformed coverage cannot exceed its VMA");
    SmapsCoverage overflow(0x200000, 0x200000);
    overflow.consume("200000-400000 rw-p 00000000 00:00 0");
    overflow.consume("AnonHugePages: 184467440737095516160 kB");
    expect(!overflow.finish().known, "Out-of-range smaps values are rejected without integer conversion overflow");
    SmapsCoverage negative(0x200000, 0x200000);
    negative.consume("200000-400000 rw-p 00000000 00:00 0");
    negative.consume("AnonHugePages: -1 kB");
    expect(!negative.finish().known, "Negative smaps values cannot become unsigned byte counts");
    SmapsCoverage duplicate(0x200000, 0x400000);
    for (int i = 0; i < 2; ++i) {
        duplicate.consume("200000-400000 rw-p 00000000 00:00 0");
        duplicate.consume("AnonHugePages: 2048 kB");
    }
    expect(!duplicate.finish().known, "Duplicate VMAs cannot conceal an unmeasured gap");

    auto guard = Platform::allocateMemoryRAII(65537, false, false);
    size_t expected_size = 0;
    expect(alignSize(65537, Platform::getNativePageSize(), expected_size) &&
           guard.valid() && guard.size() == expected_size, "Real allocation uses the native page size");
    if (guard.valid()) {
        MemoryRegion region;
        region.base = guard.base();
        region.size = guard.size();
        const auto coverage = Platform::queryLargePageCoverage(region);
        expect(coverage.known && coverage.bytes == 0 && coverage.possible_bytes == 0,
               "Explicit no-large-pages allocation has no reported huge-page coverage");
        expect(Platform::checkMemoryResident(region.base, region.size), "Real fresh mapping is materialized before residency checks");
    }
}

#ifndef _WIN32
size_t g_fixture_huge_size = 0;
size_t g_fixture_map_size = 0;
uint32_t g_fixture_map_calls = 0;
uint32_t g_fixture_lock_calls = 0;
int g_fixture_advice = 0;
uint8_t* g_fixture_base = nullptr;
size_t g_fixture_size = 0;

size_t fixtureHugeSize() { return g_fixture_huge_size; }
void* fixtureHugeMap(size_t size) {
    ++g_fixture_map_calls;
    g_fixture_map_size = size;
    return mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
void* fixtureHugeUnavailable(size_t) {
    ++g_fixture_map_calls;
    errno = ENOMEM;
    return MAP_FAILED;
}
int fixtureLockFailure(const void*, size_t) {
    ++g_fixture_lock_calls;
    errno = ENOMEM;
    return -1;
}
int fixtureAdviceFailure(void* base, size_t size, int advice) {
    g_fixture_advice = advice;
    g_fixture_base = static_cast<uint8_t*>(base);
    g_fixture_size = size;
    errno = EINVAL;
    return -1;
}

class LinuxMemoryHookScope {
    const platform_detail::LinuxMemoryHooks* previous_;
public:
    explicit LinuxMemoryHookScope(const platform_detail::LinuxMemoryHooks& hooks)
        : previous_(platform_detail::setLinuxMemoryHooks(&hooks)) {}
    ~LinuxMemoryHookScope() { platform_detail::setLinuxMemoryHooks(previous_); }
};

void testLinuxMemoryFallbacks() {
    Platform::setAggressiveDefrag(false);
    platform_detail::LinuxMemoryHooks hooks;
    hooks.hugepage_size = fixtureHugeSize;
    hooks.map_huge = fixtureHugeMap;
    hooks.lock_memory = fixtureLockFailure;
    hooks.advise_memory = fixtureAdviceFailure;
    LinuxMemoryHookScope scope(hooks);
    g_fixture_huge_size = size_t{8} * 1024 * 1024;
    g_fixture_lock_calls = g_fixture_map_calls = 0;
    {
        auto guard = Platform::allocateMemoryRAII(g_fixture_huge_size, true, true);
        expect(guard.valid() && guard.is_locked() && guard.is_large_pages(),
               "HugeTLB non-swappable status does not depend on redundant mlock");
        expect(guard.size() == g_fixture_huge_size && g_fixture_map_size == g_fixture_huge_size,
               "HugeTLB mapping and cleanup retain the actual non-2-MiB page size");
        expect(g_fixture_lock_calls == 0, "HugeTLB success never calls mlock");
    }
    g_fixture_huge_size = size_t{1024} * 1024 * 1024;
    g_fixture_map_calls = 0;
    {
        auto guard = Platform::allocateMemoryRAII(size_t{2} * 1024 * 1024, true, false);
        expect(guard.valid() && guard.size() == size_t{2} * 1024 * 1024 && !guard.is_large_pages(),
               "Small windows avoid allocating a 1-GiB default HugeTLB page");
        expect(g_fixture_map_calls == 0 && g_fixture_advice == MADV_HUGEPAGE,
               "Incompatible HugeTLB windows request THP rather than changing a global pool");
        expect(reinterpret_cast<uintptr_t>(guard.base()) % Platform::getPreferredLargePageSize() == 0,
               "THP fallback is naturally aligned even when advice is unsupported");
    }
    g_fixture_huge_size = size_t{2} * 1024 * 1024;
    hooks.map_huge = fixtureHugeUnavailable;
    g_fixture_lock_calls = 0;
    auto failed = Platform::allocateMemoryRAII(g_fixture_huge_size, true, true);
    expect(!failed.valid() && g_fixture_lock_calls == 1, "Failed strict mlock aborts without accepting pageable memory");
    std::vector<unsigned char> resident(g_fixture_size / Platform::getNativePageSize());
    errno = 0;
    expect(mincore(g_fixture_base, g_fixture_size, resident.data()) != 0 && errno == ENOMEM,
           "Failed strict allocation unmaps its entire anonymous mapping");
    auto unlocked = Platform::allocateMemoryRAII(g_fixture_huge_size, true, true, true);
    expect(unlocked.valid() && !unlocked.is_locked(), "Explicit allow-swappable fallback reports unlocked memory honestly");
    g_fixture_map_calls = 0;
    auto standard = Platform::allocateMemoryRAII(g_fixture_huge_size, false, false);
    expect(standard.valid() && g_fixture_map_calls == 0 && g_fixture_advice == MADV_NOHUGEPAGE,
           "Disabling large pages also disables THP advice and skips HugeTLB");
}
#endif
