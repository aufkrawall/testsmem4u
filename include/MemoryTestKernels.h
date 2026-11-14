#pragma once
#include "simd_ops.h"

namespace testsmem4u::simd {

// Compare each loaded word exactly once, retaining that observation on failure.
// March mode replaces each vector with the complement of the expected values
// immediately after reading it. Reverse mode visits vectors and lanes backwards.
size_t verify_words(uint64_t* memory, const uint64_t* expected, size_t count,
                    std::vector<std::pair<uint64_t, uint64_t>>& errors,
                    bool march = false, bool reverse = false,
                    size_t max_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

// Uniform march/read specialization: expected data stays in registers rather
// than being written to and loaded from a per-block expected-value table.
size_t verify_uniform_words(uint64_t* memory, uint64_t expected, size_t count,
                            std::vector<std::pair<uint64_t, uint64_t>>& errors,
                            bool march = false, bool reverse = false,
                            size_t max_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

constexpr uint64_t lfsrNext(uint64_t value) {
    return (value >> 1) ^ ((0ULL - (value & 1)) & 0xD800000000000000ULL);
}

constexpr uint64_t lfsrPrevious(uint64_t value) {
    const uint64_t bit = value >> 63;
    return ((value ^ ((0ULL - bit) & 0xD800000000000000ULL)) << 1) | bit;
}

// SplitMix64 finalizer: a bijective 64-bit mixer.
constexpr uint64_t mix64(uint64_t value) {
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31);
}

// Word stored for an LFSR state. The recurrence shifts one bit per step, so raw
// consecutive states are shifted copies (bit j of word i+1 = bit j+1 of word i)
// and neighbouring data lines see the same stream one word apart. A bijective
// mixer (XOR, odd multiply, fold) keeps the state sequence (period, reverse
// traversal) but decorrelates the words. The XOR first is required: odd
// multiplies and xor-shift-right commute with a one-bit right shift about half
// the time each, so even the two-multiply mix64(state) left ~3% exact shifted
// copies and neighbour bit correlations of 0.24. With the XOR, pairwise and
// three-bit correlations within and between words are at noise level (60k-100k
// words). One multiply keeps pre-AVX2 builds memory-bound: the two-multiply
// mixer cost the SSE2 baseline ~7% LFSR throughput even with two SIMD lanes.
constexpr uint64_t kLfsrOutputSalt = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t lfsrOutput(uint64_t state) {
    const uint64_t product = (state ^ kLfsrOutputSalt) * 0xBF58476D1CE4E5B9ULL;
    return product ^ (product >> 32);
}

// Writes lfsrOutput of count consecutive LFSR states starting at seed with
// non-temporal stores where available (AVX2 vectors or scalar MOVNTI), then
// fences. Returns the state following the last written word.
uint64_t fill_lfsr(uint64_t* memory, size_t count, uint64_t seed);

// Cached expected-data generation preserves the same output sequence. In
// reverse mode seed is the state after the block and the return value is its
// first state. Values are still laid out in ascending memory order.
uint64_t generate_lfsr_expected(uint64_t* memory, size_t count, uint64_t seed,
                               bool reverse = false, bool inverted = false);

#if defined(__AVX2__)
constexpr size_t kLfsrGenerationLanes = 4;
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
constexpr size_t kLfsrGenerationLanes = 2;
#else
constexpr size_t kLfsrGenerationLanes = 1;
#endif

// Cached complement writes to all words except protected_offset modulo 20.
// No protected word is loaded or stored, including partial final spans.
void fill_modulo20(uint64_t* memory, size_t count, size_t protected_offset, uint64_t value);

} // namespace testsmem4u::simd
