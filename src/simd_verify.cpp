#include "MemoryTestKernels.h"
#include <algorithm>
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {

size_t verify_words(uint64_t* memory, const uint64_t* expected, size_t count,
                    std::vector<std::pair<uint64_t, uint64_t>>& errors,
                    bool march, bool reverse, size_t max_samples) {
    size_t found = 0;
    auto record = [&](size_t offset, uint64_t actual) {
        if (actual != expected[offset]) {
            ++found;
            if (errors.size() < max_samples) errors.emplace_back(offset, actual);
        }
    };
    size_t done = 0;
    while (done < count) {
#if defined(__AVX512F__)
        constexpr size_t width = 8;
#elif defined(__AVX2__)
        constexpr size_t width = 4;
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
        constexpr size_t width = 2;
#else
        constexpr size_t width = 1;
#endif
        const size_t n = std::min(width, count - done);
        const size_t offset = reverse ? count - done - n : done;
        alignas(64) uint64_t observed[width];
        bool mismatch = false;
        if (n == width) {
#if defined(__AVX512F__)
            const __m512i actual = _mm512_loadu_si512(memory + offset);
            const __m512i want = _mm512_loadu_si512(expected + offset);
            mismatch = _mm512_cmpneq_epi64_mask(actual, want) != 0;
            if (mismatch) _mm512_store_si512(observed, actual);
            if (march) _mm512_storeu_si512(memory + offset, _mm512_xor_si512(want, _mm512_set1_epi64(-1)));
#elif defined(__AVX2__)
            const __m256i actual = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(memory + offset));
            const __m256i want = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(expected + offset));
            mismatch = _mm256_movemask_epi8(_mm256_cmpeq_epi64(actual, want)) != -1;
            if (mismatch) _mm256_store_si256(reinterpret_cast<__m256i*>(observed), actual);
            if (march) _mm256_storeu_si256(reinterpret_cast<__m256i*>(memory + offset),
                                         _mm256_xor_si256(want, _mm256_set1_epi64x(-1)));
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
            const __m128i actual = _mm_loadu_si128(reinterpret_cast<const __m128i*>(memory + offset));
            const __m128i want = _mm_loadu_si128(reinterpret_cast<const __m128i*>(expected + offset));
            mismatch = _mm_movemask_epi8(_mm_cmpeq_epi32(actual, want)) != 0xFFFF;
            if (mismatch) _mm_store_si128(reinterpret_cast<__m128i*>(observed), actual);
            if (march) _mm_storeu_si128(reinterpret_cast<__m128i*>(memory + offset),
                                      _mm_xor_si128(want, _mm_set1_epi32(-1)));
#else
            observed[0] = *static_cast<volatile uint64_t*>(memory + offset);
            mismatch = observed[0] != expected[offset];
            if (march) memory[offset] = ~expected[offset];
#endif
        } else {
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t k = reverse ? n - lane - 1 : lane;
                observed[k] = *static_cast<volatile uint64_t*>(memory + offset + k);
                mismatch |= observed[k] != expected[offset + k];
                if (march) memory[offset + k] = ~expected[offset + k];
            }
        }
        if (mismatch) {
            for (size_t lane = 0; lane < n; ++lane) {
                const size_t k = reverse ? n - lane - 1 : lane;
                record(offset + k, observed[k]);
            }
        }
        done += n;
    }
    return found;
}

} // namespace testsmem4u::simd
