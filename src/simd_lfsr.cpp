#include "MemoryTestKernels.h"
#include "SimdPatternMath.h"
#include <array>
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {
namespace {

// T^-4 is linear over GF(2): the shifted-out high nibble selects the
// feedback contribution. The small table is derived from the scalar inverse,
// not a seed table proportional to the tested region.
constexpr auto makeInverseTable() {
    std::array<uint64_t, 16> table{};
    for (size_t i = 0; i < table.size(); ++i) {
        uint64_t value = static_cast<uint64_t>(i) << 60;
        for (unsigned step = 0; step < 4; ++step) value = lfsrPrevious(value);
        table[i] = value;
    }
    return table;
}
constexpr auto inverse_four = makeInverseTable();

#if defined(__AVX2__)
// lfsrOutput in four lanes.
inline __m256i mixLanes(__m256i value) {
    value = mul64_avx2(_mm256_xor_si256(value, _mm256_set1_epi64x(static_cast<long long>(kLfsrOutputSalt))),
                       _mm256_set1_epi64x(static_cast<long long>(0xBF58476D1CE4E5B9ULL)));
    return _mm256_xor_si256(value, _mm256_srli_epi64(value, 32));
}
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
// Pre-AVX2 builds: two lanes with SSE2's 32x32->64 multiply. Generating the
// expected table is serialized with verification, so its compute cost shows up
// directly as lost bandwidth; the scalar path was measurably slower.
inline __m128i mul64Lanes(__m128i a, __m128i b) {
    const __m128i lo = _mm_mul_epu32(a, b);
    const __m128i cross = _mm_add_epi64(_mm_mul_epu32(a, _mm_srli_epi64(b, 32)),
                                        _mm_mul_epu32(_mm_srli_epi64(a, 32), b));
    return _mm_add_epi64(lo, _mm_slli_epi64(cross, 32));
}

inline __m128i mixLanes(__m128i value) {
    value = mul64Lanes(_mm_xor_si128(value, _mm_set1_epi64x(static_cast<long long>(kLfsrOutputSalt))),
                       _mm_set1_epi64x(static_cast<long long>(0xBF58476D1CE4E5B9ULL)));
    return _mm_xor_si128(value, _mm_srli_epi64(value, 32));
}
#endif

// One word outside the vector loop; MOVNTI keeps x86-64 streaming fills uncached.
template <bool streaming>
inline void storeWord(uint64_t* target, uint64_t value) {
#if defined(__x86_64__) || defined(_M_X64)
    if constexpr (streaming) {
        _mm_stream_si64(reinterpret_cast<long long*>(target), static_cast<long long>(value));
        return;
    }
#endif
    *target = value;
}

template <bool streaming, bool inverted>
uint64_t generateForward(uint64_t* memory, size_t count, uint64_t seed) {
    size_t i = 0;
#if defined(__AVX2__)
    if constexpr (streaming) {
        // NT vector stores require alignment. Keep MOVNTI for a short prefix.
        for (; i < count && (reinterpret_cast<uintptr_t>(memory + i) & 31); ++i) {
            storeWord<true>(memory + i, inverted ? ~lfsrOutput(seed) : lfsrOutput(seed));
            seed = lfsrNext(seed);
        }
    }
    if (count - i >= 4) {
        alignas(32) uint64_t states[4];
        uint64_t state = seed;
        for (auto& lane : states) { lane = state; state = lfsrNext(state); }
        __m256i values = _mm256_load_si256(reinterpret_cast<const __m256i*>(states));
        const __m256i mask = _mm256_set1_epi64x(15);
        for (; count - i >= 4; i += 4) {
            __m256i output = mixLanes(values);
            if constexpr (inverted) output = _mm256_xor_si256(output, _mm256_set1_epi64x(-1));
            if constexpr (streaming) _mm256_stream_si256(reinterpret_cast<__m256i*>(memory + i), output);
            else _mm256_storeu_si256(reinterpret_cast<__m256i*>(memory + i), output);
            // T^4(v) = v>>4 XOR carryless(low4(v), 0xD8) shifted to bit 56.
            // Four lanes advance independently by four scalar recurrence steps.
            const __m256i low = _mm256_and_si256(values, mask);
            const __m256i high = _mm256_xor_si256(_mm256_slli_epi64(low, 60), _mm256_slli_epi64(low, 59));
            const __m256i lower = _mm256_xor_si256(_mm256_slli_epi64(low, 57), _mm256_slli_epi64(low, 56));
            values = _mm256_xor_si256(_mm256_srli_epi64(values, 4), _mm256_xor_si256(high, lower));
        }
        seed = static_cast<uint64_t>(_mm256_extract_epi64(values, 0));
    }
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if constexpr (streaming) {
        for (; i < count && (reinterpret_cast<uintptr_t>(memory + i) & 15); ++i) {
            storeWord<true>(memory + i, inverted ? ~lfsrOutput(seed) : lfsrOutput(seed));
            seed = lfsrNext(seed);
        }
    }
    if (count - i >= 2) {
        alignas(16) uint64_t states[2] = {seed, lfsrNext(seed)};
        __m128i values = _mm_load_si128(reinterpret_cast<const __m128i*>(states));
        const __m128i one = _mm_set1_epi64x(1);
        const __m128i zero = _mm_setzero_si128();
        const __m128i tap = _mm_set1_epi64x(static_cast<long long>(0xD800000000000000ULL));
        const __m128i tap_shifted = _mm_set1_epi64x(static_cast<long long>(0xD800000000000000ULL >> 1));
        for (; count - i >= 2; i += 2) {
            __m128i output = mixLanes(values);
            if constexpr (inverted) output = _mm_xor_si128(output, _mm_set1_epi64x(-1));
            if constexpr (streaming) _mm_stream_si128(reinterpret_cast<__m128i*>(memory + i), output);
            else _mm_storeu_si128(reinterpret_cast<__m128i*>(memory + i), output);
            // T^2(v) = v>>2 ^ (bit0 ? taps>>1 : 0) ^ (bit1 ? taps : 0); the taps
            // have no bit 0, so the first step never changes the second shifted-out bit.
            const __m128i bit0 = _mm_sub_epi64(zero, _mm_and_si128(values, one));
            const __m128i bit1 = _mm_sub_epi64(zero, _mm_and_si128(_mm_srli_epi64(values, 1), one));
            values = _mm_xor_si128(_mm_srli_epi64(values, 2),
                                   _mm_xor_si128(_mm_and_si128(bit0, tap_shifted), _mm_and_si128(bit1, tap)));
        }
        _mm_store_si128(reinterpret_cast<__m128i*>(states), values);
        seed = states[0];
    }
#endif
    for (; i < count; ++i) {
        storeWord<streaming>(memory + i, inverted ? ~lfsrOutput(seed) : lfsrOutput(seed));
        seed = lfsrNext(seed);
    }
    return seed;
}

} // namespace

uint64_t fill_lfsr(uint64_t* memory, size_t count, uint64_t seed) {
    const uint64_t next = generateForward<true, false>(memory, count, seed);
    sfence();
    return next;
}

uint64_t generate_lfsr_expected(uint64_t* memory, size_t count, uint64_t seed,
                               bool reverse, bool inverted) {
    if (reverse) {
        size_t remaining = count;
        for (; remaining >= 4; remaining -= 4) seed = (seed << 4) ^ inverse_four[seed >> 60];
        for (; remaining; --remaining) seed = lfsrPrevious(seed);
    }
    const uint64_t next = inverted ? generateForward<false, true>(memory, count, seed)
                                   : generateForward<false, false>(memory, count, seed);
    return reverse ? seed : next;
}

} // namespace testsmem4u::simd
