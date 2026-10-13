#pragma once
#include <cstddef>

namespace testsmem4u::platform_detail {
#if defined(TESTSMEM4U_TESTING) && !defined(_WIN32)
struct LinuxMemoryHooks {
    size_t (*hugepage_size)() = nullptr;
    void* (*map_huge)(size_t) = nullptr;
    int (*lock_memory)(const void*, size_t) = nullptr;
    int (*advise_memory)(void*, size_t, int) = nullptr;
};
const LinuxMemoryHooks* setLinuxMemoryHooks(const LinuxMemoryHooks* hooks);
#endif
}
