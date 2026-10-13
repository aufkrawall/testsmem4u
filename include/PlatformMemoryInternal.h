#pragma once
#include <cstddef>
#include <cstdint>

namespace testsmem4u::platform_detail {
#if defined(TESTSMEM4U_TESTING) && defined(_WIN32)
struct WindowsMemoryHooks {
    void* (*allocate)(void*, size_t, uint32_t, uint32_t) = nullptr;
    bool (*lock_memory)(void*, size_t) = nullptr;
    bool (*working_set)(size_t, size_t) = nullptr;
    bool (*lock_privilege)() = nullptr;
    size_t (*large_page_size)() = nullptr;
    void (*prepare_memory)() = nullptr;
    bool (*free_memory)(void*) = nullptr;
};
const WindowsMemoryHooks* setWindowsMemoryHooks(const WindowsMemoryHooks* hooks);
#endif
#if defined(TESTSMEM4U_TESTING) && !defined(_WIN32)
struct LinuxMemoryHooks {
    size_t (*hugepage_size)() = nullptr;
    void* (*map_huge)(size_t) = nullptr;
    int (*lock_memory)(const void*, size_t) = nullptr;
    int (*advise_memory)(void*, size_t, int) = nullptr;
    int (*unmap_memory)(void*, size_t) = nullptr;
};
const LinuxMemoryHooks* setLinuxMemoryHooks(const LinuxMemoryHooks* hooks);
#endif
}
