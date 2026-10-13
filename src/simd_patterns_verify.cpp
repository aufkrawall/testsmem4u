#include "simd_ops.h"
#include "SimdPatternMath.h"
#include <cstring>
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u::simd {

#if defined(__AVX2__)
static inline __m256i load_verify_u256(const uint64_t* src) {
    return _mm256_loadu_si256((const __m256i*)src);
}
#endif

#if defined(__AVX512F__)
static inline __m512i load_verify_u512(const uint64_t* src) {
    return _mm512_loadu_si512((const void*)src);
}
#endif

template<>
size_t verify_pattern_linear<uint64_t>(const uint64_t* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1,
                                       std::vector<std::pair<uint64_t, uint64_t>>& errors, size_t max_error_samples) {
    size_t i = 0;
    size_t mismatches = 0;
    auto record_error = [&](size_t offset, uint64_t observed) {
        ++mismatches;
        if (errors.size() < max_error_samples) {
            errors.push_back({offset, observed});
        }
    };

#if defined(__AVX512F__) || defined(__AVX2__)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_step8 = _mm512_set1_epi64(param1 * 8);
        __m512i v_expect = _mm512_set_epi64(
            param0 + (start_idx + 7) * param1, param0 + (start_idx + 6) * param1,
            param0 + (start_idx + 5) * param1, param0 + (start_idx + 4) * param1,
            param0 + (start_idx + 3) * param1, param0 + (start_idx + 2) * param1,
            param0 + (start_idx + 1) * param1, param0 + (start_idx + 0) * param1
        );

        for (; i + 8 <= count; i += 8) {
            __m512i actual = load_verify_u512(src + i);

            __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
            if (mask) {
                // Record from the already-loaded register, never from a second
                // memory read: a transient flip seen by the SIMD compare must be
                // counted even if the memory cell reads back correct by now.
                alignas(64) uint64_t lanes[8];
                _mm512_store_si512((void*)lanes, actual);
                for (int k = 0; k < 8; ++k) {
                    if ((mask >> k) & 1) {
                         record_error(i + k, lanes[k]);
                    }
                }
            }
            v_expect = _mm512_add_epi64(v_expect, v_step8);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
        __m256i v_step4 = _mm256_set1_epi64x(param1 * 4);
        __m256i v_expect = _mm256_set_epi64x(
            param0 + (start_idx + i + 3) * param1,
            param0 + (start_idx + i + 2) * param1,
            param0 + (start_idx + i + 1) * param1,
            param0 + (start_idx + i + 0) * param1
        );

        for (; i + 4 <= count; i += 4) {
            __m256i actual = load_verify_u256(src + i);

            __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
            int mask = _mm256_movemask_epi8(eq);
            if ((uint32_t)mask != 0xFFFFFFFF) {
                // Compare register lanes, never re-read memory (see AVX-512 note).
                alignas(32) uint64_t lanes[4];
                alignas(32) uint64_t expect_lanes[4];
                _mm256_store_si256((__m256i*)lanes, actual);
                _mm256_store_si256((__m256i*)expect_lanes, v_expect);
                for (size_t k = 0; k < 4; ++k) {
                    if (lanes[k] != expect_lanes[k]) {
                       record_error(i + k, lanes[k]);
                    }
                }
            }
            v_expect = _mm256_add_epi64(v_expect, v_step4);
        }
    }
#endif

    for (; i < count; ++i) {
        const uint64_t observed = src[i];
        if (observed != (param0 + (start_idx + i) * param1)) {
            record_error(i, observed);
        }
    }
    return mismatches;
}

template<>
size_t verify_pattern_xor<uint64_t>(const uint64_t* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1,
                                    std::vector<std::pair<uint64_t, uint64_t>>& errors, size_t max_error_samples) {
    size_t i = 0;
    size_t mismatches = 0;
    auto record_error = [&](size_t offset, uint64_t observed) {
        ++mismatches;
        if (errors.size() < max_error_samples) {
            errors.push_back({offset, observed});
        }
    };

    // NOTE: AVX2 doesn't have native 64-bit integer multiply.
    // Only AVX512 has _mm512_mullo_epi64, so use that if available.
    // Hoist caps outside the preprocessor blocks to avoid duplicate declaration when
    // both __AVX512F__ and __AVX2__ are defined simultaneously (e.g. v4 builds).
#if defined(__AVX512F__) || defined(__AVX2__)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512 && count >= 8) {
        __m512i v_param0 = _mm512_set1_epi64(param0);
        __m512i v_param1 = _mm512_set1_epi64(param1);

        __m512i v_idx = _mm512_set_epi64(start_idx + 7, start_idx + 6, start_idx + 5, start_idx + 4,
                                         start_idx + 3, start_idx + 2, start_idx + 1, start_idx);
        __m512i v_idx_step = _mm512_set1_epi64(8);

        for (; i + 8 <= count; i += 8) {
            __m512i actual = load_verify_u512(src + i);
            __m512i v_mul = _mm512_mullo_epi64(v_idx, v_param1);
            __m512i v_expect = _mm512_xor_si512(v_param0, v_mul);
            __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
            if (mask) {
                // Record from the already-loaded register, never from a second
                // memory read: a transient flip seen by the SIMD compare must be
                // counted even if the memory cell reads back correct by now.
                alignas(64) uint64_t lanes[8];
                _mm512_store_si512((void*)lanes, actual);
                for (int k = 0; k < 8; ++k) {
                    if ((mask >> k) & 1) {
                        record_error(i + k, lanes[k]);
                    }
                }
            }
            v_idx = _mm512_add_epi64(v_idx, v_idx_step);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2 && i + 4 <= count) {
        __m256i v_param0 = _mm256_set1_epi64x(param0);
        __m256i v_param1 = _mm256_set1_epi64x(param1);

        // Must account for elements already processed by AVX-512 (i may be > 0).
        // Compute initial term = (start_idx + i) * param1 for each lane.
        __m256i v_base = _mm256_set_epi64x((int64_t)(start_idx + i + 3), (int64_t)(start_idx + i + 2),
                                           (int64_t)(start_idx + i + 1), (int64_t)(start_idx + i));
        __m256i v_term = mul64_avx2(v_base, v_param1);
        __m256i v_term_step = _mm256_slli_epi64(v_param1, 2); // 4 * param1

        for (; i + 4 <= count; i += 4) {
            __m256i actual = load_verify_u256(src + i);

            __m256i v_expect = _mm256_xor_si256(v_param0, v_term);
            __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
            int mask = _mm256_movemask_epi8(eq);

            if ((uint32_t)mask != 0xFFFFFFFF) {
                // Compare register lanes, never re-read memory (see AVX-512 note).
                alignas(32) uint64_t lanes[4];
                alignas(32) uint64_t expect_lanes[4];
                _mm256_store_si256((__m256i*)lanes, actual);
                _mm256_store_si256((__m256i*)expect_lanes, v_expect);
                for (size_t k = 0; k < 4; ++k) {
                    if (lanes[k] != expect_lanes[k]) {
                        record_error(i + k, lanes[k]);
                    }
                }
            }
            v_term = _mm256_add_epi64(v_term, v_term_step);
        }
    }
#endif

    // Scalar fallback - guaranteed correct
    for (; i < count; ++i) {
        const uint64_t observed = src[i];
        if (observed != (param0 ^ ((start_idx + i) * param1))) {
            record_error(i, observed);
        }
    }
    return mismatches;
}

template<>
size_t verify_uniform<uint64_t>(const uint64_t* src, size_t count, uint64_t val,
                                std::vector<std::pair<uint64_t, uint64_t>>& errors, size_t max_error_samples) {
    size_t i = 0;
    size_t mismatches = 0;
    auto record_error = [&](size_t offset, uint64_t observed) {
        ++mismatches;
        if (errors.size() < max_error_samples) {
            errors.push_back({offset, observed});
        }
    };
#if defined(__AVX512F__) || defined(__AVX2__)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_expect = _mm512_set1_epi64(val);
        for (; i + 8 <= count; i += 8) {
             __m512i actual = load_verify_u512(src + i);

             __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
             if (mask) {
                 // Record from the already-loaded register, never from a second
                 // memory read: a transient flip seen by the SIMD compare must be
                 // counted even if the memory cell reads back correct by now.
                 alignas(64) uint64_t lanes[8];
                 _mm512_store_si512((void*)lanes, actual);
                 for (int k = 0; k < 8; ++k) {
                     if ((mask >> k) & 1) {
                         record_error(i + k, lanes[k]);
                     }
                 }
             }
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
        __m256i v_expect = _mm256_set1_epi64x(val);
        for (; i + 4 <= count; i += 4) {
            __m256i actual = load_verify_u256(src + i);

            __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
            int mask = _mm256_movemask_epi8(eq);
            if ((uint32_t)mask != 0xFFFFFFFF) {
                // Compare register lanes, never re-read memory (see AVX-512 note).
                alignas(32) uint64_t lanes[4];
                _mm256_store_si256((__m256i*)lanes, actual);
                for (size_t k = 0; k < 4; ++k) {
                    if (lanes[k] != val) {
                        record_error(i + k, lanes[k]);
                    }
                }
            }
        }
    }
#endif
    for (; i < count; ++i) {
        const uint64_t observed = src[i];
        if (observed != val) {
            record_error(i, observed);
        }
    }
    return mismatches;
}

template<>
size_t verify_pattern_pair<uint64_t>(const uint64_t* src, size_t count, uint64_t even_val, uint64_t odd_val,
                                     std::vector<std::pair<uint64_t, uint64_t>>& errors, size_t max_error_samples) {
    size_t i = 0;
    size_t mismatches = 0;
    auto record_error = [&](size_t offset, uint64_t observed) {
        ++mismatches;
        if (errors.size() < max_error_samples) {
            errors.push_back({offset, observed});
        }
    };
    // All SIMD strides below are even, so i keeps even parity and lane 0 always
    // expects even_val. Mismatches are recorded from the loaded register, never
    // from a second memory read (see verify_uniform).
#if defined(__AVX512F__) || defined(__AVX2__) || defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_expect = _mm512_set_epi64(
            (long long)odd_val, (long long)even_val, (long long)odd_val, (long long)even_val,
            (long long)odd_val, (long long)even_val, (long long)odd_val, (long long)even_val);
        for (; i + 8 <= count; i += 8) {
            __m512i actual = load_verify_u512(src + i);
            __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
            if (mask) {
                alignas(64) uint64_t lanes[8];
                _mm512_store_si512((void*)lanes, actual);
                for (int k = 0; k < 8; ++k) {
                    if ((mask >> k) & 1) {
                        record_error(i + k, lanes[k]);
                    }
                }
            }
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
        __m256i v_expect = _mm256_set_epi64x(
            (long long)odd_val, (long long)even_val, (long long)odd_val, (long long)even_val);
        for (; i + 4 <= count; i += 4) {
            __m256i actual = load_verify_u256(src + i);
            __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
            int mask = _mm256_movemask_epi8(eq);
            if ((uint32_t)mask != 0xFFFFFFFF) {
                alignas(32) uint64_t lanes[4];
                _mm256_store_si256((__m256i*)lanes, actual);
                if (lanes[0] != even_val) record_error(i + 0, lanes[0]);
                if (lanes[1] != odd_val)  record_error(i + 1, lanes[1]);
                if (lanes[2] != even_val) record_error(i + 2, lanes[2]);
                if (lanes[3] != odd_val)  record_error(i + 3, lanes[3]);
            }
        }
    } else
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1) {
        __m128i v_expect = _mm_set_epi64x((long long)odd_val, (long long)even_val);
        for (; i + 2 <= count; i += 2) {
            __m128i actual = _mm_loadu_si128((const __m128i*)(src + i));
            // SSE2-compatible 64-bit compare: both 32-bit halves of a lane must
            // match, so all-bytes-equal in the movemask means both lanes match.
            __m128i eq = _mm_cmpeq_epi32(actual, v_expect);
            int mask = _mm_movemask_epi8(eq);
            if (mask != 0xFFFF) {
                alignas(16) uint64_t lanes[2];
                _mm_store_si128((__m128i*)lanes, actual);
                if (lanes[0] != even_val) record_error(i + 0, lanes[0]);
                if (lanes[1] != odd_val)  record_error(i + 1, lanes[1]);
            }
        }
    }
#endif

    for (; i < count; ++i) {
        const uint64_t observed = src[i];
        const uint64_t expect = (i & 1) ? odd_val : even_val;
        if (observed != expect) {
            record_error(i, observed);
        }
    }
    return mismatches;
}

} // namespace testsmem4u::simd
