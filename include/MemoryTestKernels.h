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

// Writes count consecutive LFSR states starting at seed with non-temporal
// stores where available (AVX2 vectors or scalar MOVNTI), then fences. Returns
// the state following the last written word.
uint64_t fill_lfsr(uint64_t* memory, size_t count, uint64_t seed);

// Cached expected-data generation preserves the same scalar sequence. In
// reverse mode seed is the state after the block and the return value is its
// first state. Values are still laid out in ascending memory order.
uint64_t generate_lfsr_expected(uint64_t* memory, size_t count, uint64_t seed,
                               bool reverse = false, bool inverted = false);

#if defined(__AVX2__)
constexpr size_t kLfsrGenerationLanes = 4;
#else
constexpr size_t kLfsrGenerationLanes = 1;
#endif

} // namespace testsmem4u::simd
