#include "MemoryTestKernels.h"
#include <algorithm>
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {

void fill_modulo20(uint64_t* memory, size_t count, size_t protected_offset, uint64_t value) {
    const size_t prefix = std::min(count, protected_offset);
    std::fill(memory, memory + prefix, value);
#if defined(__AVX512F__)
    const __m512i wide = _mm512_set1_epi64(static_cast<long long>(value));
#elif defined(__AVX2__)
    const __m256i wide = _mm256_set1_epi64x(static_cast<long long>(value));
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    const __m128i pair = _mm_set1_epi64x(static_cast<long long>(value));
#endif
    for (size_t protected_idx = protected_offset; protected_idx < count; protected_idx += 20) {
        auto* span = memory + protected_idx + 1;
        const size_t remaining = count - protected_idx - 1;
        if (remaining < 19) {
            std::fill(span, span + remaining, value);
            break;
        }
        // Exactly nineteen cached stores' worth of data, with no masked
        // read/modify/write of the protected word in either neighbour.
#if defined(__AVX512F__)
        _mm512_storeu_si512(span, wide);
        _mm512_storeu_si512(span + 8, wide);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(span + 16), pair);
        span[18] = value;
#elif defined(__AVX2__)
        for (size_t i = 0; i < 16; i += 4) _mm256_storeu_si256(reinterpret_cast<__m256i*>(span + i), wide);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(span + 16), pair);
        span[18] = value;
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
        for (size_t i = 0; i < 18; i += 2) _mm_storeu_si128(reinterpret_cast<__m128i*>(span + i), pair);
        span[18] = value;
#else
        std::fill(span, span + 19, value);
#endif
    }
}

} // namespace testsmem4u::simd
