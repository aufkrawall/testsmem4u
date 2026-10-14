#pragma once

#include <cstddef>
#include <cstdint>

namespace testsmem4u::simd::detail {

// CPUID.01H:EBX[15:8] specifies the CLFLUSH/CLFLUSHOPT granule in
// eight-byte units when EDX.CLFSH is set, on both Intel and AMD x86.
// It is the relevant stride for flushing, rather than cache capacity/topology.
constexpr size_t x86FlushLineSize(uint32_t leaf1_ebx, uint32_t leaf1_edx) noexcept {
    const size_t bytes = static_cast<size_t>((leaf1_ebx >> 8) & 0xFFU) * 8;
    constexpr uint32_t clflush_bit = uint32_t{1} << 19;
    return (leaf1_edx & clflush_bit) && bytes && (bytes & (bytes - 1)) == 0 ? bytes : 64;
}

} // namespace testsmem4u::simd::detail
