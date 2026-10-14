#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace testsmem4u::simd::detail {

// Largest stride the flush loops use. Flushing an address evicts its whole
// line, so a stride at or below the real line size flushes every line (larger
// lines are merely flushed more than once). A stride above it skips lines and
// would let verification read stale cached data instead of DRAM.
constexpr size_t kMaxFlushStride = 64;

// CPUID.01H:EBX[15:8] specifies the CLFLUSH/CLFLUSHOPT granule in
// eight-byte units when EDX.CLFSH is set, on both Intel and AMD x86.
// Returns 0 when the feature is absent or the field is not a power of two.
constexpr size_t x86AdvertisedFlushGranule(uint32_t leaf1_ebx, uint32_t leaf1_edx) noexcept {
    const size_t bytes = static_cast<size_t>((leaf1_ebx >> 8) & 0xFFU) * 8;
    constexpr uint32_t clflush_bit = uint32_t{1} << 19;
    return (leaf1_edx & clflush_bit) && bytes && (bytes & (bytes - 1)) == 0 ? bytes : 0;
}

// Flush-loop stride: the advertised granule, capped at kMaxFlushStride so an
// over-reported granule (e.g. a misconfigured hypervisor CPUID) cannot skip
// lines. Smaller advertised granules are honored; they only cost time.
constexpr size_t x86FlushLineSize(uint32_t leaf1_ebx, uint32_t leaf1_edx) noexcept {
    const size_t granule = x86AdvertisedFlushGranule(leaf1_ebx, leaf1_edx);
    return granule ? std::min(granule, kMaxFlushStride) : kMaxFlushStride;
}

} // namespace testsmem4u::simd::detail
