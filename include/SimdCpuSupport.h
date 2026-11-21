#pragma once

#include <cstdint>

namespace testsmem4u::simd::detail {

struct X86CpuFeatures {
    uint32_t max_leaf = 0;
    uint32_t max_ext_leaf = 0;
    uint32_t leaf1_ecx = 0;
    uint32_t leaf1_edx = 0;
    uint32_t leaf7_ebx = 0;
    uint32_t ext1_ecx = 0;
    uint64_t xcr0 = 0;
};

constexpr bool hasBit(uint32_t reg, unsigned bit) {
    return (reg & (uint32_t{1} << bit)) != 0;
}

constexpr bool supportsSse41(const X86CpuFeatures& features) {
    return features.max_leaf >= 1 && hasBit(features.leaf1_ecx, 19);
}

constexpr bool osSupportsAvxState(const X86CpuFeatures& features) {
    return features.max_leaf >= 1 && hasBit(features.leaf1_ecx, 27) &&
           (features.xcr0 & 0x6ULL) == 0x6ULL;
}

constexpr bool osSupportsAvx512State(const X86CpuFeatures& features) {
    return osSupportsAvxState(features) && (features.xcr0 & 0xE0ULL) == 0xE0ULL;
}

constexpr bool supportsX8664V2(const X86CpuFeatures& features) {
    if (features.max_leaf < 1) return false;
    const bool leaf1_ok =
        hasBit(features.leaf1_ecx, 0) &&   // SSE3
        hasBit(features.leaf1_ecx, 9) &&   // SSSE3
        hasBit(features.leaf1_ecx, 13) &&  // CMPXCHG16B
        hasBit(features.leaf1_ecx, 19) &&  // SSE4.1
        hasBit(features.leaf1_ecx, 20) &&  // SSE4.2
        hasBit(features.leaf1_ecx, 23);    // POPCNT
    const bool ext_ok =
        features.max_ext_leaf >= 0x80000001U && hasBit(features.ext1_ecx, 0); // LAHF/SAHF
    return leaf1_ok && ext_ok;
}

constexpr bool supportsX8664V3(const X86CpuFeatures& features) {
    if (!supportsX8664V2(features) || features.max_leaf < 7 || !osSupportsAvxState(features)) {
        return false;
    }
    const bool leaf1_ok =
        hasBit(features.leaf1_ecx, 12) &&  // FMA
        hasBit(features.leaf1_ecx, 22) &&  // MOVBE
        hasBit(features.leaf1_ecx, 28) &&  // AVX
        hasBit(features.leaf1_ecx, 29);    // F16C
    const bool leaf7_ok =
        hasBit(features.leaf7_ebx, 3) &&   // BMI1
        hasBit(features.leaf7_ebx, 5) &&   // AVX2
        hasBit(features.leaf7_ebx, 8);     // BMI2
    const bool lzcnt_ok =
        features.max_ext_leaf >= 0x80000001U && hasBit(features.ext1_ecx, 5); // LZCNT
    return leaf1_ok && leaf7_ok && lzcnt_ok;
}

constexpr bool supportsX8664V4(const X86CpuFeatures& features) {
    if (!supportsX8664V3(features) || !osSupportsAvx512State(features)) {
        return false;
    }
    return hasBit(features.leaf7_ebx, 16) && // AVX512F
           hasBit(features.leaf7_ebx, 17) && // AVX512DQ
           hasBit(features.leaf7_ebx, 28) && // AVX512CD
           hasBit(features.leaf7_ebx, 30) && // AVX512BW
           hasBit(features.leaf7_ebx, 31);   // AVX512VL
}

} // namespace testsmem4u::simd::detail
