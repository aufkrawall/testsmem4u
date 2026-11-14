// Mirror moves: converge from both ends of a block and swap what is read.
#include "simd_ops.h"
#include <cstdint>
#include <utility>
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {
namespace {

inline void storeWord(uint64_t* dst, uint64_t value, [[maybe_unused]] bool nt) {
#if defined(__x86_64__) || defined(_M_X64)
    if (nt) {
        _mm_stream_si64(reinterpret_cast<long long*>(dst), static_cast<long long>(value));
        return;
    }
#endif
    *dst = value;
}

// Scalar reference: unit i <-> unit units-1-i, Pairs: 2-word units, else words.
template <bool Pairs>
void mirrorScalar(uint64_t* data, size_t count, bool nt) {
    constexpr size_t unit = Pairs ? 2 : 1;
    const size_t units = count / unit;
    for (size_t i = 0; i < units / 2; ++i) {
        uint64_t* front = data + i * unit;
        uint64_t* back = data + (units - 1 - i) * unit;
        uint64_t a[unit];
        uint64_t b[unit];
        for (size_t k = 0; k < unit; ++k) {
            a[k] = front[k];
            b[k] = back[k];
        }
        for (size_t k = 0; k < unit; ++k) {
            storeWord(front + k, b[k], nt);
            storeWord(back + k, a[k], nt);
        }
    }
}

#if defined(__AVX512F__)
template <bool Pairs>
inline __m512i reverseLine512(__m512i line) {
    // Word reversal: lane i <- 7-i. Unit reversal keeps each word pair in order.
    const __m512i index = Pairs ? _mm512_set_epi64(1, 0, 3, 2, 5, 4, 7, 6) : _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7);
    return _mm512_permutexvar_epi64(index, line);
}
#endif

#if defined(__AVX2__)
template <bool Pairs>
inline __m256i reverseHalf256(__m256i v) {
    // Words: [3,2,1,0]. Pairs: swap the two 128-bit units.
    return Pairs ? _mm256_permute4x64_epi64(v, 0x4E) : _mm256_permute4x64_epi64(v, 0x1B);
}
#endif

#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
template <bool Pairs>
inline __m128i reverseQuarter128(__m128i v) {
    // Words: swap the two 64-bit lanes. Pairs: a vector is one unit.
    return Pairs ? v : _mm_shuffle_epi32(v, 0x4E);
}
#endif

// Whole 64-byte lines from both ends; a middle line (odd line count) is
// reversed in place. Requires 64-byte alignment and count % 8 == 0.
template <bool Pairs>
bool mirrorLines([[maybe_unused]] uint64_t* data, [[maybe_unused]] size_t count) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    const SimdCapabilities caps = getCapabilities();
    if (!caps.has_nt_stores || count < 8 || count % 8 != 0 || reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    size_t front = 0;
    size_t back = count - 8;
#if defined(__AVX512F__)
    if (caps.has_avx512) {
        for (; front < back; front += 8, back -= 8) {
            const __m512i f = _mm512_load_si512(static_cast<const void*>(data + front));
            const __m512i b = _mm512_load_si512(static_cast<const void*>(data + back));
            _mm512_stream_si512(static_cast<void*>(data + front), reverseLine512<Pairs>(b));
            _mm512_stream_si512(static_cast<void*>(data + back), reverseLine512<Pairs>(f));
        }
        if (front == back) {
            const __m512i m = _mm512_load_si512(static_cast<const void*>(data + front));
            _mm512_stream_si512(static_cast<void*>(data + front), reverseLine512<Pairs>(m));
        }
        sfence();
        return true;
    }
#endif
#if defined(__AVX2__)
    if (caps.has_avx2) {
        auto* v = reinterpret_cast<__m256i*>(data);
        for (; front < back; front += 8, back -= 8) {
            const __m256i f0 = _mm256_load_si256(v + front / 4);
            const __m256i f1 = _mm256_load_si256(v + front / 4 + 1);
            const __m256i b0 = _mm256_load_si256(v + back / 4);
            const __m256i b1 = _mm256_load_si256(v + back / 4 + 1);
            _mm256_stream_si256(v + front / 4, reverseHalf256<Pairs>(b1));
            _mm256_stream_si256(v + front / 4 + 1, reverseHalf256<Pairs>(b0));
            _mm256_stream_si256(v + back / 4, reverseHalf256<Pairs>(f1));
            _mm256_stream_si256(v + back / 4 + 1, reverseHalf256<Pairs>(f0));
        }
        if (front == back) {
            const __m256i m0 = _mm256_load_si256(v + front / 4);
            const __m256i m1 = _mm256_load_si256(v + front / 4 + 1);
            _mm256_stream_si256(v + front / 4, reverseHalf256<Pairs>(m1));
            _mm256_stream_si256(v + front / 4 + 1, reverseHalf256<Pairs>(m0));
        }
        sfence();
        return true;
    }
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1) {
        auto* v = reinterpret_cast<__m128i*>(data);
        auto swapLines = [&](size_t a, size_t b) {
            __m128i fa[4];
            __m128i fb[4];
            for (size_t k = 0; k < 4; ++k) {
                fa[k] = _mm_load_si128(v + a / 2 + k);
                fb[k] = _mm_load_si128(v + b / 2 + k);
            }
            for (size_t k = 0; k < 4; ++k) {
                _mm_stream_si128(v + a / 2 + k, reverseQuarter128<Pairs>(fb[3 - k]));
                if (a != b) _mm_stream_si128(v + b / 2 + k, reverseQuarter128<Pairs>(fa[3 - k]));
            }
        };
        for (; front < back; front += 8, back -= 8) swapLines(front, back);
        if (front == back) swapLines(front, front);
        sfence();
        return true;
    }
#endif
#endif
    return false;
}

template <bool Pairs>
void mirrorReverse(uint64_t* data, size_t count) {
    if (mirrorLines<Pairs>(data, count)) return;
    const bool nt = getCapabilities().has_nt_stores;
    mirrorScalar<Pairs>(data, count, nt);
    sfence();
}

} // namespace

void mirror_reverse_words(uint64_t* data, size_t count) {
    mirrorReverse<false>(data, count);
}

void mirror_reverse_pairs(uint64_t* data, size_t count) {
    mirrorReverse<true>(data, count & ~size_t{1});
}

} // namespace testsmem4u::simd
