#pragma once
#if defined(__AVX2__)
#include <immintrin.h>

namespace testsmem4u::simd {
// Low 64 bits of each product, using AVX2's 32-bit multiply primitives.
inline __m256i mul64_avx2(__m256i a, __m256i b) {
    const __m256i lo = _mm256_mul_epu32(a, b);
    const __m256i cross1 = _mm256_mul_epu32(a, _mm256_srli_epi64(b, 32));
    const __m256i cross2 = _mm256_mul_epu32(_mm256_srli_epi64(a, 32), b);
    return _mm256_add_epi64(lo, _mm256_slli_epi64(_mm256_add_epi64(cross1, cross2), 32));
}
} // namespace testsmem4u::simd
#endif
