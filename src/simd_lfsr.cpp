#include "MemoryTestKernels.h"
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

template <bool streaming, bool inverted>
uint64_t generateForward(uint64_t* memory, size_t count, uint64_t seed) {
    size_t i = 0;
#if defined(__AVX2__)
    if constexpr (streaming) {
        // NT vector stores require alignment. Keep MOVNTI for a short prefix.
        for (; i < count && (reinterpret_cast<uintptr_t>(memory + i) & 31); ++i) {
            _mm_stream_si64(reinterpret_cast<long long*>(memory + i), static_cast<long long>(seed));
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
            __m256i output = values;
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
#endif
    for (; i < count; ++i) {
        const uint64_t output = inverted ? ~seed : seed;
#if defined(__x86_64__) || defined(_M_X64)
        if constexpr (streaming) _mm_stream_si64(reinterpret_cast<long long*>(memory + i), static_cast<long long>(output));
        else memory[i] = output;
#else
        memory[i] = output;
#endif
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
