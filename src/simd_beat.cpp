// Per-beat complement pattern (BeatPattern): generation and verification.
#include "simd_ops.h"
#include <cstdint>
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {
namespace {

bool alignedTo(const void* ptr, size_t bytes) {
    return reinterpret_cast<uintptr_t>(ptr) % bytes == 0;
}

// Scalar store that keeps the non-temporal contract on x86-64.
inline void storeWord(uint64_t* dst, uint64_t value, [[maybe_unused]] bool nt) {
#if defined(__x86_64__) || defined(_M_X64)
    if (nt) {
        _mm_stream_si64(reinterpret_cast<long long*>(dst), static_cast<long long>(value));
        return;
    }
#endif
    *dst = value;
}

// Tag accumulator value for the pair holding global word `word` (even).
inline uint64_t pairBase(const BeatPattern& p, uint64_t word) {
    return p.salt + (word >> 1) * p.step;
}

} // namespace

void generate_pattern_beat(uint64_t* dst, size_t count, const BeatPattern& p, uint64_t start_word, bool use_nt) {
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
    const bool nt = use_nt && caps.has_nt_stores;
    size_t i = 0;
    // Vector lanes start at an even global word (even value first).
    if (count && (start_word & 1)) {
        storeWord(dst, beat_value(p, start_word), nt);
        i = 1;
    }

#if defined(__AVX512F__)
    if (caps.has_avx512 && i + 8 <= count && alignedTo(dst + i, 64)) {
        const uint64_t b = pairBase(p, start_word + i);
        const uint64_t s = p.step;
        __m512i acc = _mm512_set_epi64(static_cast<long long>(b + 3 * s), static_cast<long long>(b + 3 * s),
                                       static_cast<long long>(b + 2 * s), static_cast<long long>(b + 2 * s),
                                       static_cast<long long>(b + s), static_cast<long long>(b + s),
                                       static_cast<long long>(b), static_cast<long long>(b));
        const __m512i inc = _mm512_set1_epi64(static_cast<long long>(4 * s));
        const __m512i words = _mm512_set_epi64(
            static_cast<long long>(p.odd), static_cast<long long>(p.even), static_cast<long long>(p.odd),
            static_cast<long long>(p.even), static_cast<long long>(p.odd), static_cast<long long>(p.even),
            static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 8 <= count; i += 8) {
            const __m512i value = _mm512_xor_si512(words, _mm512_shuffle_epi32(acc, static_cast<_MM_PERM_ENUM>(0xA0)));
            if (nt) _mm512_stream_si512(static_cast<void*>(dst + i), value);
            else _mm512_store_si512(static_cast<void*>(dst + i), value);
            acc = _mm512_add_epi64(acc, inc);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2 && i + 4 <= count && alignedTo(dst + i, 32)) {
        const uint64_t b = pairBase(p, start_word + i);
        __m256i acc = _mm256_set_epi64x(static_cast<long long>(b + p.step), static_cast<long long>(b + p.step),
                                        static_cast<long long>(b), static_cast<long long>(b));
        const __m256i inc = _mm256_set1_epi64x(static_cast<long long>(2 * p.step));
        const __m256i words = _mm256_set_epi64x(static_cast<long long>(p.odd), static_cast<long long>(p.even),
                                                static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 4 <= count; i += 4) {
            // Shuffle copies each lane's low dword into its high dword (beat_tag).
            const __m256i value = _mm256_xor_si256(words, _mm256_shuffle_epi32(acc, 0xA0));
            if (nt) _mm256_stream_si256(reinterpret_cast<__m256i*>(dst + i), value);
            else _mm256_store_si256(reinterpret_cast<__m256i*>(dst + i), value);
            acc = _mm256_add_epi64(acc, inc);
        }
    }
#endif

#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1 && i + 2 <= count && alignedTo(dst + i, 16)) {
        __m128i acc = _mm_set1_epi64x(static_cast<long long>(pairBase(p, start_word + i)));
        const __m128i inc = _mm_set1_epi64x(static_cast<long long>(p.step));
        const __m128i words = _mm_set_epi64x(static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 2 <= count; i += 2) {
            const __m128i value = _mm_xor_si128(words, _mm_shuffle_epi32(acc, 0xA0));
            if (nt) _mm_stream_si128(reinterpret_cast<__m128i*>(dst + i), value);
            else _mm_store_si128(reinterpret_cast<__m128i*>(dst + i), value);
            acc = _mm_add_epi64(acc, inc);
        }
    }
#endif

    for (; i < count; ++i) storeWord(dst + i, beat_value(p, start_word + i), nt);
    sfence();
}

size_t verify_pattern_beat(const uint64_t* src, size_t count, const BeatPattern& p, uint64_t start_word,
                           std::vector<std::pair<uint64_t, uint64_t>>& errors, size_t max_error_samples) {
    size_t i = 0;
    size_t mismatches = 0;
    auto record_error = [&](size_t offset, uint64_t observed) {
        ++mismatches;
        if (errors.size() < max_error_samples) errors.push_back({offset, observed});
    };
    if (count && (start_word & 1)) {
        const uint64_t observed = src[0];
        if (observed != beat_value(p, start_word)) record_error(0, observed);
        i = 1;
    }
    // Mismatches are recorded from the loaded register, never from a second read.
#if defined(__AVX512F__) || defined(__AVX2__) || defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512 && i + 8 <= count) {
        const uint64_t b = pairBase(p, start_word + i);
        const uint64_t s = p.step;
        __m512i acc = _mm512_set_epi64(static_cast<long long>(b + 3 * s), static_cast<long long>(b + 3 * s),
                                       static_cast<long long>(b + 2 * s), static_cast<long long>(b + 2 * s),
                                       static_cast<long long>(b + s), static_cast<long long>(b + s),
                                       static_cast<long long>(b), static_cast<long long>(b));
        const __m512i inc = _mm512_set1_epi64(static_cast<long long>(4 * s));
        const __m512i words = _mm512_set_epi64(
            static_cast<long long>(p.odd), static_cast<long long>(p.even), static_cast<long long>(p.odd),
            static_cast<long long>(p.even), static_cast<long long>(p.odd), static_cast<long long>(p.even),
            static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 8 <= count; i += 8) {
            const __m512i actual = _mm512_loadu_si512(static_cast<const void*>(src + i));
            const __m512i expect = _mm512_xor_si512(words, _mm512_shuffle_epi32(acc, static_cast<_MM_PERM_ENUM>(0xA0)));
            const __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, expect);
            if (mask) {
                alignas(64) uint64_t lanes[8];
                _mm512_store_si512(static_cast<void*>(lanes), actual);
                for (int k = 0; k < 8; ++k) {
                    if ((mask >> k) & 1) record_error(i + static_cast<size_t>(k), lanes[k]);
                }
            }
            acc = _mm512_add_epi64(acc, inc);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2 && i + 4 <= count) {
        const uint64_t b = pairBase(p, start_word + i);
        __m256i acc = _mm256_set_epi64x(static_cast<long long>(b + p.step), static_cast<long long>(b + p.step),
                                        static_cast<long long>(b), static_cast<long long>(b));
        const __m256i inc = _mm256_set1_epi64x(static_cast<long long>(2 * p.step));
        const __m256i words = _mm256_set_epi64x(static_cast<long long>(p.odd), static_cast<long long>(p.even),
                                                static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 4 <= count; i += 4) {
            const __m256i actual = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
            const __m256i expect = _mm256_xor_si256(words, _mm256_shuffle_epi32(acc, 0xA0));
            if (static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi64(actual, expect))) != 0xFFFFFFFFU) {
                alignas(32) uint64_t lanes[4];
                alignas(32) uint64_t expected[4];
                _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), actual);
                _mm256_store_si256(reinterpret_cast<__m256i*>(expected), expect);
                for (size_t k = 0; k < 4; ++k) {
                    if (lanes[k] != expected[k]) record_error(i + k, lanes[k]);
                }
            }
            acc = _mm256_add_epi64(acc, inc);
        }
    }
#endif

#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1 && i + 2 <= count) {
        __m128i acc = _mm_set1_epi64x(static_cast<long long>(pairBase(p, start_word + i)));
        const __m128i inc = _mm_set1_epi64x(static_cast<long long>(p.step));
        const __m128i words = _mm_set_epi64x(static_cast<long long>(p.odd), static_cast<long long>(p.even));
        for (; i + 2 <= count; i += 2) {
            const __m128i actual = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src + i));
            const __m128i expect = _mm_xor_si128(words, _mm_shuffle_epi32(acc, 0xA0));
            // SSE2 64-bit equality: both 32-bit halves of each lane must match.
            if (_mm_movemask_epi8(_mm_cmpeq_epi32(actual, expect)) != 0xFFFF) {
                alignas(16) uint64_t lanes[2];
                alignas(16) uint64_t expected[2];
                _mm_store_si128(reinterpret_cast<__m128i*>(lanes), actual);
                _mm_store_si128(reinterpret_cast<__m128i*>(expected), expect);
                for (size_t k = 0; k < 2; ++k) {
                    if (lanes[k] != expected[k]) record_error(i + k, lanes[k]);
                }
            }
            acc = _mm_add_epi64(acc, inc);
        }
    }
#endif

    for (; i < count; ++i) {
        const uint64_t observed = src[i];
        if (observed != beat_value(p, start_word + i)) record_error(i, observed);
    }
    return mismatches;
}

} // namespace testsmem4u::simd
