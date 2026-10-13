#pragma once

#include "MemoryPages.h"
#include "PlatformMemoryInternal.h"
#ifndef _WIN32
#include <sys/mman.h>
#include <cerrno>
#endif

#ifdef _WIN32
enum class WindowsFixtureMode : uint8_t { DIRECT, CHUNKED, HYBRID, THROW_CHUNK, FAIL_LOCK };
WindowsFixtureMode g_windows_mode = WindowsFixtureMode::DIRECT;
size_t g_windows_target = 0;
size_t g_windows_largest_commit = 0;
size_t g_windows_large_chunks = 0;
uint32_t g_windows_preparations = 0;
std::array<void*, 16> g_windows_owned{};
std::array<bool, 16> g_windows_released{};
size_t g_windows_page_size = size_t{2} * 1024 * 1024;

size_t fixtureWindowsPageSize() { return g_windows_page_size; }
bool fixtureWindowsPrivilege() { return true; }
bool fixtureWindowsWorkingSet(size_t, size_t) { return true; }
bool fixtureWindowsLock(void*, size_t) { return g_windows_mode != WindowsFixtureMode::FAIL_LOCK; }
void fixtureWindowsPreparation() { ++g_windows_preparations; }
bool fixtureWindowsRelease(void* base) {
    const bool freed = VirtualFree(base, 0, MEM_RELEASE) != 0;
    for (size_t i = 0; i < g_windows_large_chunks; ++i) {
        if (g_windows_owned[i] == base) g_windows_released[i] = freed;
    }
    return freed;
}

void* fixtureWindowsAllocate(void* base, size_t size, uint32_t flags, uint32_t protection) {
    if ((flags & MEM_COMMIT) != 0) g_windows_largest_commit = std::max(g_windows_largest_commit, size);
    if ((flags & MEM_LARGE_PAGES) != 0) {
        if (g_windows_mode == WindowsFixtureMode::FAIL_LOCK ||
            (base == nullptr && g_windows_mode != WindowsFixtureMode::DIRECT) ||
            (base != nullptr && g_windows_mode == WindowsFixtureMode::HYBRID && g_windows_large_chunks >= 3)) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return nullptr;
        }
        if (base && g_windows_mode == WindowsFixtureMode::THROW_CHUNK && g_windows_large_chunks == 3) {
            throw std::runtime_error("injected chunk allocation exception");
        }
        // Simulate API success with real, releasable native mappings; this test
        // verifies allocation contracts and cleanup, not physical LP availability.
        void* result = VirtualAlloc(base, size, flags & ~MEM_LARGE_PAGES, protection);
        if (result && base && g_windows_large_chunks < g_windows_owned.size()) {
            g_windows_owned[g_windows_large_chunks++] = result;
        }
        return result;
    }
    return VirtualAlloc(base, size, flags, protection);
}

class WindowsMemoryHookScope {
    const platform_detail::WindowsMemoryHooks* previous_;
public:
    explicit WindowsMemoryHookScope(const platform_detail::WindowsMemoryHooks& hooks)
        : previous_(platform_detail::setWindowsMemoryHooks(&hooks)) {}
    ~WindowsMemoryHookScope() {
        Platform::setAggressiveDefrag(false);
        platform_detail::setWindowsMemoryHooks(previous_);
    }
};

void resetWindowsFixture(WindowsFixtureMode mode, size_t target) {
    g_windows_mode = mode;
    g_windows_target = target;
    g_windows_large_chunks = g_windows_largest_commit = 0;
    g_windows_preparations = 0;
    g_windows_owned.fill(nullptr);
    g_windows_released.fill(false);
    g_windows_page_size = size_t{2} * 1024 * 1024;
}

void testWindowsMemoryFallbacks() {
    platform_detail::WindowsMemoryHooks hooks;
    hooks.allocate = fixtureWindowsAllocate;
    hooks.lock_memory = fixtureWindowsLock;
    hooks.working_set = fixtureWindowsWorkingSet;
    hooks.lock_privilege = fixtureWindowsPrivilege;
    hooks.large_page_size = fixtureWindowsPageSize;
    hooks.prepare_memory = fixtureWindowsPreparation;
    hooks.free_memory = fixtureWindowsRelease;
    WindowsMemoryHookScope scope(hooks);
    const size_t size = size_t{18} * 1024 * 1024;
    Platform::setAggressiveDefrag(true);
    resetWindowsFixture(WindowsFixtureMode::DIRECT, size);
    {
        auto guard = Platform::allocateMemoryRAII(size, true, true);
        expect(guard.valid() && guard.size() == size && guard.large_page_bytes() == size,
               "Direct Windows LP success retains the requested footprint");
        expect(g_windows_preparations == 0, "Aggressive Windows mode first tries ordinary allocation without global cleanup");
    }
    Platform::setAggressiveDefrag(false);
    resetWindowsFixture(WindowsFixtureMode::CHUNKED, size);
    {
        auto guard = Platform::allocateMemoryRAII(size, true, true);
        expect(guard.valid() && guard.size() == size && guard.large_page_bytes() == size && g_windows_large_chunks == 9,
               "Windows chunk fallback uses exact-size large-page chunks");
        expect(g_windows_largest_commit <= g_windows_target,
               "Chunk fallback never rounds an 18-MiB window up to a 1-GiB allocation");
    }
    resetWindowsFixture(WindowsFixtureMode::HYBRID, size);
    {
        auto guard = Platform::allocateMemoryRAII(size, true, true);
        expect(guard.valid() && guard.is_locked() && guard.size() == size &&
               guard.large_page_bytes() == size_t{6} * 1024 * 1024,
               "Hybrid Windows fallback reports only its real large-page prefix");
    }
    resetWindowsFixture(WindowsFixtureMode::THROW_CHUNK, size);
    bool caught = false;
    try {
        auto guard = Platform::allocateMemoryRAII(size, true, true);
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "injected chunk allocation exception";
    }
    expect(caught && g_windows_large_chunks == 3, "Injected chunk failure reaches the caller after partial allocation");
    for (size_t i = 0; i < g_windows_large_chunks; ++i) {
        expect(g_windows_released[i],
               "Chunk exception rolls back every committed mapping");
    }
    resetWindowsFixture(WindowsFixtureMode::FAIL_LOCK, size);
    auto failed = Platform::allocateMemoryRAII(size, false, true);
    expect(!failed.valid(), "Windows strict lock failure never returns pageable memory");
    auto pageable = Platform::allocateMemoryRAII(size, false, true, true);
    expect(pageable.valid() && !pageable.is_locked() && pageable.size() == size,
           "Explicit Windows pageable fallback retains its original requested size");
    resetWindowsFixture(WindowsFixtureMode::DIRECT, size_t{1024} * 1024);
    auto small = Platform::allocateMemoryRAII(size_t{1024} * 1024, true, false);
    expect(small.valid() && small.size() == size_t{1024} * 1024 && !small.is_large_pages(),
           "Small Windows windows fall back instead of growing to the large-page minimum");
    const size_t native_window = size_t{192} * 1024;
    resetWindowsFixture(WindowsFixtureMode::CHUNKED, native_window);
    g_windows_page_size = size_t{64} * 1024;
    auto native = Platform::allocateMemoryRAII(native_window, true, true);
    expect(native.valid() && native.size() == native_window && native.large_page_bytes() == native_window && g_windows_large_chunks == 3,
           "Windows chunk fallback reaches the actual native large-page minimum");
}
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
    expect(workerLimit(65536, 65536) == 1 && workerLimit(size_t{4} * 65536, 65536) == 4 &&
           workerLimit(65536, 4096) == 16 && workerLimit(1024, 65536) == 1 && workerLimit(65536, 0) == 0,
           "Worker caps follow native pages and cannot outnumber 64-KiB pages on ARM64");

    size_t page_size = 0;
    for (const char* text : {"2097152", "2097152\n", "536870912\r\n", "4096\n"}) {
        expect(parsePageSize(text, std::strlen(text), page_size) && page_size >= 4096,
               "Page-size controls accept one power-of-two value with an optional line ending");
    }
    for (const char* text : {"", "\n", "-1\n", "3\n", "512\n", " 2097152\n", "2097152 \n", "2097152\ngarbage\n",
                             "2097152\n\n", "18446744073709551616\n"}) {
        expect(!parsePageSize(text, std::strlen(text), page_size),
               "Malformed, tiny, non-power-of-two or overflowing page-size controls are rejected");
    }

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
bool g_fixture_unmapped = false;

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
    g_fixture_unmapped = false;
    errno = EINVAL;
    return -1;
}
int fixtureUnmap(void* base, size_t size) {
    const int result = munmap(base, size);
    if (base == g_fixture_base && size == g_fixture_size && result == 0) g_fixture_unmapped = true;
    return result;
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
    hooks.unmap_memory = fixtureUnmap;
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
    expect(g_fixture_unmapped,
           "Failed strict allocation unmaps its entire anonymous mapping");
    auto unlocked = Platform::allocateMemoryRAII(g_fixture_huge_size, true, true, true);
    expect(unlocked.valid() && !unlocked.is_locked(), "Explicit allow-swappable fallback reports unlocked memory honestly");
    g_fixture_map_calls = 0;
    auto standard = Platform::allocateMemoryRAII(g_fixture_huge_size, false, false);
    expect(standard.valid() && g_fixture_map_calls == 0 && g_fixture_advice == MADV_NOHUGEPAGE,
           "Disabling large pages also disables THP advice and skips HugeTLB");
}
#endif
