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

inline uint64_t lfsrNext(uint64_t value) {
    return (value >> 1) ^ ((0ULL - (value & 1)) & 0xD800000000000000ULL);
}

inline uint64_t lfsrPrevious(uint64_t value) {
    const uint64_t bit = value >> 63;
    return ((value ^ ((0ULL - bit) & 0xD800000000000000ULL)) << 1) | bit;
}

} // namespace testsmem4u::simd
