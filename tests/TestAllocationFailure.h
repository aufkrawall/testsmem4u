#pragma once
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <new>

// Include in the test runner's translation unit only. Other threads and normal
// test allocations keep their usual malloc/free behavior; a selected thread can
// make all subsequent ordinary new allocations fail until that thread exits.
namespace testsmem4u::testing {
inline thread_local std::atomic<uint64_t>* failed_allocation_count = nullptr;
}

void* operator new(std::size_t size) {
    if (testsmem4u::testing::failed_allocation_count) {
        testsmem4u::testing::failed_allocation_count->fetch_add(1, std::memory_order_relaxed);
        throw std::bad_alloc();
    }
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }
