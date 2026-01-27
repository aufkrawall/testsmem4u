#include "simd_ops.h"
#include <cstring>
#include <iostream>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <nmmintrin.h>
#if defined(_M_IX86) || defined(_M_X64)
#include <intrin.h>
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

namespace testsmem4u {
namespace simd {

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#if defined(_MSC_VER)
    #include <intrin.h>
#else
    #include <cpuid.h>
    static inline void call_cpuidex(int* cpuInfo, int function_id, int subfunction_id) {
        __cpuid_count(function_id, subfunction_id, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    }
    #define __cpuidex(info, func, sub) call_cpuidex(info, func, sub)
#endif

static SimdCapabilities detect_x86_capabilities() {
    SimdCapabilities caps;

    int info[4];
    __cpuidex(info, 1, 0);
    if (info[3] & (1 << 19)) caps.has_clflush = true;
    
    // Check for CLFLUSHOPT (Leaf 7, Subleaf 0, EBX bit 23)
    __cpuidex(info, 7, 0);
    if (info[1] & (1 << 23)) caps.has_clflushopt = true;

#if defined(__AVX512F__)
    __cpuidex(info, 7, 0);
    if (info[1] & (1 << 16)) {
        caps.level = SimdLevel::AVX512;
        caps.has_avx512 = true;
        caps.has_avx2 = true;
        caps.has_sse4_1 = true;
        caps.has_nt_stores = true;
        caps.vector_width = 64;
    } else
#endif
    {
        __cpuidex(info, 7, 0);
        if (info[1] & (1 << 5)) {
            caps.level = SimdLevel::AVX2;
            caps.has_avx2 = true;
            caps.has_sse4_1 = true;
            caps.has_nt_stores = true;
            caps.vector_width = 32;
        } else {
            __cpuidex(info, 1, 0);
            if (info[2] & (1 << 19)) {
                caps.level = SimdLevel::SSE4_1;
                caps.has_sse4_1 = true;
                caps.has_nt_stores = true;
                caps.vector_width = 16;
            }
        }
    }
    caps.nt_store_width = caps.vector_width;
    return caps;
}

#ifdef __clang__
__attribute__((target("clflushopt")))
static inline void do_clflushopt(void* ptr) {
    _mm_clflushopt(ptr);
}
#else
static inline void do_clflushopt(void* ptr) {
    _mm_clflushopt(ptr);
}
#endif

void flush_cache_line(void* ptr) {
    if (getCapabilities().has_clflushopt) {
        do_clflushopt(ptr);
    } else {
        _mm_clflush(ptr);
    }
}

void flush_cache_region(void* ptr, size_t bytes) {
    // Cache line size is typically 64 bytes on modern x86
    constexpr size_t CACHE_LINE_SIZE = 64;
    uint8_t* p = static_cast<uint8_t*>(ptr);
    uint8_t* end = p + bytes;
    
    for (; p < end; p += CACHE_LINE_SIZE) {
        if (getCapabilities().has_clflushopt) {
            do_clflushopt(p);
        } else {
            _mm_clflush(p);
        }
    }
    _mm_sfence(); // Ensure all flushes complete before returning
}

#elif defined(__aarch64__) || defined(_M_ARM64)

static SimdCapabilities detect_arm_capabilities() {
    SimdCapabilities caps;
    caps.has_neon = true;
    caps.vector_width = 16;
    caps.nt_store_width = 16;
    caps.level = SimdLevel::NEON;
    return caps;
}

void flush_cache_line(void* ptr) {
#if defined(__GNUC__) || defined(__clang__)
     __asm__ __volatile__("dc civac, %0" :: "r" (ptr) : "memory");
#endif
}

void flush_cache_region(void* ptr, size_t bytes) {
    // Cache line size is typically 64 bytes on ARM64
    constexpr size_t CACHE_LINE_SIZE = 64;
    uint8_t* p = static_cast<uint8_t*>(ptr);
    uint8_t* end = p + bytes;
    
    for (; p < end; p += CACHE_LINE_SIZE) {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dc civac, %0" :: "r" (p) : "memory");
#endif
    }
    // Data synchronization barrier
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("dsb sy" ::: "memory");
#endif
}

#else

static SimdCapabilities detect_fallback_capabilities() {
    SimdCapabilities caps;
    return caps;
}

void flush_cache_line(void* ptr) {
    (void)ptr;
}

void flush_cache_region(void* ptr, size_t bytes) {
    (void)ptr;
    (void)bytes;
    // No cache flush available on this platform
}

#endif

SimdCapabilities getCapabilities() {
    static SimdCapabilities caps = []() -> SimdCapabilities {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        return detect_x86_capabilities();
#elif defined(__aarch64__) || defined(_M_ARM64)
        return detect_arm_capabilities();
#else
        return detect_fallback_capabilities();
#endif
    }();
    return caps;
}

const char* getSimdLevelName(SimdLevel level) {
    switch (level) {
        case SimdLevel::NONE: return "Scalar";
        case SimdLevel::SSE4_1: return "SSE4.1";
        case SimdLevel::AVX2: return "AVX2";
        case SimdLevel::AVX512: return "AVX-512";
        case SimdLevel::NEON: return "NEON";
        default: return "Unknown";
    }
}

void memory_fence() {
#if defined(__x86_64__) || defined(_M_X64)
    _mm_mfence();
#else
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

void sfence() {
#if defined(__x86_64__) || defined(_M_X64)
    _mm_sfence();
#else
    std::atomic_thread_fence(std::memory_order_release);
#endif
}

void lfence() {
#if defined(__x86_64__) || defined(_M_X64)
    _mm_lfence();
#else
    std::atomic_thread_fence(std::memory_order_acquire);
#endif
}

template<>
void nt_store_128<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__SSE2__) || defined(__x86_64__)
    for (size_t i = 0; i < count; i += 2) {
        __m128i v = _mm_loadu_si128((const __m128i*)(src + i));
        _mm_stream_si128((__m128i*)(dst + i), v);
    }
#elif defined(__aarch64__)
    for (size_t i = 0; i < count; i += 2) {
        uint64x2_t v = vld1q_u64(src + i);
        vst1q_u64(dst + i, v);
    }
#else
    for(size_t i=0; i<count; ++i) dst[i] = src[i];
#endif
}

template<>
void nt_store_256<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__AVX2__)
    for (size_t i = 0; i < count; i += 4) {
        __m256i v = _mm256_loadu_si256((const __m256i*)(src + i));
        _mm256_stream_si256((__m256i*)(dst + i), v);
    }
#elif defined(__SSE2__)
    nt_store_128(dst, src, count);
#else
    for(size_t i=0; i<count; ++i) dst[i] = src[i];
#endif
}

template<>
void nt_store_512<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__AVX512F__)
    for (size_t i = 0; i < count; i += 8) {
        __m512i v = _mm512_loadu_si512((const __m512i*)(src + i));
        _mm512_stream_si512((void*)(dst + i), v);
    }
#else
    nt_store_256(dst, src, count);
#endif
}

template<>
void stream_load_128<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__SSE4_1__)
    for (size_t i = 0; i < count; i += 2) {
        __m128i v = _mm_stream_load_si128((__m128i*)(src + i));
        _mm_storeu_si128((__m128i*)(dst + i), v);
    }
#else
    for(size_t i=0; i<count; ++i) dst[i] = src[i];
#endif
}

template<>
void stream_load_256<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__AVX2__)
    for (size_t i = 0; i < count; i += 4) {
        __m256i v = _mm256_stream_load_si256((__m256i*)(src + i));
        _mm256_storeu_si256((__m256i*)(dst + i), v);
    }
#else
    stream_load_128(dst, src, count);
#endif
}

template<>
void stream_load_512<uint64_t>(uint64_t* dst, const uint64_t* src, size_t count) {
#if defined(__AVX512F__)
    for (size_t i = 0; i < count; i += 8) {
        // AVX512 doesn't have a specific stream_load, but we can use VMOVNTDQA if available (AVX512_F is sufficient usually for standard vector load, but strictly speaking MOVNTDQA is SSE4.1 rooted, expanded in AVX2/512).
        // Actually for AVX512, _mm512_stream_load_si512 exists in some extensions (AVL512VL), but let's stick to intrinsic _mm512_load_si512 if no explicit stream.
        // HOWEVER, the specific instruction for NT load is VMOVNTDQA. 
        // Intel Intrinsics Guide says _mm512_stream_load_si512 corresponds to VMOVNTDQA.
        __m512i v = _mm512_stream_load_si512((void*)(src + i));
        _mm512_storeu_si512((void*)(dst + i), v);
    }
#else
    stream_load_256(dst, src, count);
#endif
}

template<>
void generate_pattern_linear<uint64_t>(uint64_t* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt) {
    SimdCapabilities caps = getCapabilities();
    (void)caps;
    size_t i = 0;

#if defined(__AVX2__)
    if (use_nt && caps.has_nt_stores) {
        __m256i v_val = _mm256_set_epi64x(
            param0 + 3 * param1,
            param0 + 2 * param1,
            param0 + 1 * param1,
            param0 + 0 * param1
        );
        __m256i v_idx_step = _mm256_set1_epi64x(4 * param1);

        for (; i + 4 <= count; i += 4) {
            if (use_nt && caps.has_nt_stores) {
                _mm256_stream_si256((__m256i*)(dst + i), v_val);
            } else {
                _mm256_storeu_si256((__m256i*)(dst + i), v_val);
            }
            v_val = _mm256_add_epi64(v_val, v_idx_step);
        }
    }
#endif

#if defined(__AVX512F__)
    if (use_nt && caps.has_nt_stores && caps.has_avx512) {
        __m512i v_val = _mm512_set_epi64(
            param0 + 7 * param1, param0 + 6 * param1, param0 + 5 * param1, param0 + 4 * param1,
            param0 + 3 * param1, param0 + 2 * param1, param0 + 1 * param1, param0 + 0 * param1
        );
        __m512i v_idx_step = _mm512_set1_epi64(8 * param1);

        for (; i + 8 <= count; i += 8) {
            _mm512_stream_si512((void*)(dst + i), v_val);
            v_val = _mm512_add_epi64(v_val, v_idx_step);
        }
    }
#endif

    for (; i < count; ++i) {
        dst[i] = param0 + (i * param1);
    }
}

#if defined(__AVX2__)
// Helper: Emulate 64-bit multiplication using AVX2 32-bit primitives
// Returns (a * b) & 0xFFFFFFFFFFFFFFFF
static inline __m256i mul64_avx2(__m256i a, __m256i b) {
    // lo_prod = a_lo * b_lo (64-bit result)
    __m256i lo_prod = _mm256_mul_epu32(a, b);
    
    // hi_prod1 = a_lo * b_hi
    __m256i b_hi = _mm256_srli_epi64(b, 32);
    __m256i hi_prod1 = _mm256_mul_epu32(a, b_hi);
    
    // hi_prod2 = a_hi * b_lo
    __m256i a_hi = _mm256_srli_epi64(a, 32);
    __m256i hi_prod2 = _mm256_mul_epu32(a_hi, b);
    
    // Combine cross terms: (a_lo*b_hi + a_hi*b_lo) << 32
    __m256i sum_hi = _mm256_add_epi64(hi_prod1, hi_prod2);
    __m256i scaled_hi = _mm256_slli_epi64(sum_hi, 32);
    
    return _mm256_add_epi64(lo_prod, scaled_hi);
}
#endif

template<>
void generate_pattern_xor<uint64_t>(uint64_t* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt) {
    size_t i = 0;
    SimdCapabilities caps = getCapabilities();

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_param0 = _mm512_set1_epi64(param0);
        __m512i v_param1 = _mm512_set1_epi64(param1);
        __m512i v_idx = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0);
        __m512i v_idx_step = _mm512_set1_epi64(8);

        for (; i + 8 <= count; i += 8) {
            __m512i v_mul = _mm512_mullo_epi64(v_idx, v_param1);
            __m512i v_val = _mm512_xor_si512(v_param0, v_mul);
            
            if (use_nt && caps.has_nt_stores) {
                _mm512_stream_si512((void*)(dst + i), v_val);
            } else {
                _mm512_storeu_si512((void*)(dst + i), v_val);
            }
            v_idx = _mm512_add_epi64(v_idx, v_idx_step);
        }
    }
#endif

#if defined(__AVX2__)
    // Optimized AVX2 path - FIXED: removed undefined start_idx dependency
    if (caps.has_avx2 && i + 4 <= count) {
        __m256i v_param0 = _mm256_set1_epi64x(param0);
        __m256i v_param1 = _mm256_set1_epi64x(param1);
        
        // Start indices from current position i: {i+3, i+2, i+1, i}
        __m256i v_idx = _mm256_set_epi64x(
            static_cast<int64_t>(i + 3), 
            static_cast<int64_t>(i + 2), 
            static_cast<int64_t>(i + 1), 
            static_cast<int64_t>(i)
        );
        __m256i v_idx_step = _mm256_set1_epi64x(4);
        
        // Calculate initial term: (idx * param1)
        __m256i v_term = mul64_avx2(v_idx, v_param1);
        
        // Step for the Term is (4 * param1)
        __m256i v_term_step = _mm256_slli_epi64(v_param1, 2); // param1 * 4
        
        for (; i + 4 <= count; i += 4) {
             // val = param0 ^ (term)
             __m256i v_val = _mm256_xor_si256(v_param0, v_term);

             if (use_nt && caps.has_nt_stores) {
                 _mm256_stream_si256((__m256i*)(dst + i), v_val);
             } else {
                 _mm256_storeu_si256((__m256i*)(dst + i), v_val);
             }
             
             // Advance term by adding the step (4 * param1)
             v_term = _mm256_add_epi64(v_term, v_term_step);
        }
    }
#endif

    // Scalar fallback - guaranteed correct
    for (; i < count; ++i) {
        dst[i] = param0 ^ (i * param1);
    }
    sfence();
}

// NOTE: generate_pattern_moving_inv removed - unused (MovingInversion test uses generate_pattern_uniform)

template<>
void generate_pattern_uniform<uint64_t>(uint64_t* dst, size_t count, uint64_t val, bool use_nt) {
    SimdCapabilities caps = getCapabilities();
    (void)caps;
    size_t i = 0;

#if defined(__AVX2__)
    __m256i v = _mm256_set1_epi64x(val);
    for (; i + 4 <= count; i += 4) {
        if (use_nt && caps.has_nt_stores) {
            _mm256_stream_si256((__m256i*)(dst + i), v);
        } else {
            _mm256_storeu_si256((__m256i*)(dst + i), v);
        }
    }
#elif defined(__SSE2__)
    __m128i v = _mm_set1_epi64x(val);
    for (; i + 2 <= count; i += 2) {
        if (use_nt && caps.has_nt_stores) {
            _mm_stream_si128((__m128i*)(dst + i), v);
        } else {
            _mm_storeu_si128((__m128i*)(dst + i), v);
        }
    }
#endif

    for (; i < count; ++i) dst[i] = val;
}

template<>
void generate_pattern_increment<uint64_t>(uint64_t* dst, size_t count, uint64_t start, bool use_nt) {
    SimdCapabilities caps = getCapabilities();
    (void)caps;
    size_t i = 0;

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        // v_curr = {start+7, start+6, ..., start+0} (little endian load order)
        // Set: [7, 6, 5, 4, 3, 2, 1, 0]
        __m512i v_idx = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0);
        __m512i v_base = _mm512_set1_epi64(start);
        __m512i v_curr = _mm512_add_epi64(v_base, v_idx);
        __m512i v_step = _mm512_set1_epi64(8);

        for (; i + 8 <= count; i += 8) {
            if (use_nt && caps.has_nt_stores) {
                _mm512_stream_si512((void*)(dst + i), v_curr);
            } else {
                _mm512_storeu_si512((void*)(dst + i), v_curr);
            }
            v_curr = _mm512_add_epi64(v_curr, v_step);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
        // AVX2 logic
        __m256i v_idx = _mm256_set_epi64x(3, 2, 1, 0);
        __m256i v_base = _mm256_set1_epi64x(start + i); // Start from current i
        __m256i v_curr = _mm256_add_epi64(v_base, v_idx);
        __m256i v_step = _mm256_set1_epi64x(4);
        
        for (; i + 4 <= count; i += 4) {
            if (use_nt && caps.has_nt_stores) {
                _mm256_stream_si256((__m256i*)(dst + i), v_curr);
            } else {
                _mm256_storeu_si256((__m256i*)(dst + i), v_curr);
            }
            v_curr = _mm256_add_epi64(v_curr, v_step);
        }
    }
#endif

    // Scalar fallback
    for (; i < count; ++i) {
        dst[i] = start + i;
    }
    sfence();
}

template<>
void verify_pattern_linear<uint64_t>(const uint64_t* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1, std::vector<uint64_t>& error_indices) {
    size_t i = 0;

#if defined(__AVX512F__)
    SimdCapabilities caps = getCapabilities();
    if (caps.has_avx512) {
        __m512i v_step8 = _mm512_set1_epi64(param1 * 8);
        __m512i v_expect = _mm512_set_epi64(
            param0 + (start_idx + 7) * param1, param0 + (start_idx + 6) * param1,
            param0 + (start_idx + 5) * param1, param0 + (start_idx + 4) * param1,
            param0 + (start_idx + 3) * param1, param0 + (start_idx + 2) * param1,
            param0 + (start_idx + 1) * param1, param0 + (start_idx + 0) * param1
        );

        for (; i + 8 <= count; i += 8) {
            // Try to use NT load if aligned (common case with our allocator)
            __m512i actual;
            if (((uintptr_t)(src + i) & 63) == 0) {
                 actual = _mm512_stream_load_si512((void*)(src + i)); 
            } else {
                 actual = _mm512_loadu_si512((const void*)(src + i));
            }

            __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
            if (mask) {
                for (int k = 0; k < 8; ++k) {
                    if ((mask >> k) & 1) {
                         error_indices.push_back(i + k);
                    }
                }
            }
            v_expect = _mm512_add_epi64(v_expect, v_step8);
        }
    }
#endif

#if defined(__AVX2__)
    __m256i v_step4 = _mm256_set1_epi64x(param1 * 4);
    __m256i v_expect = _mm256_set_epi64x(
        param0 + (start_idx + 3) * param1,
        param0 + (start_idx + 2) * param1,
        param0 + (start_idx + 1) * param1,
        param0 + (start_idx + 0) * param1
    );

    for (; i + 4 <= count; i += 4) {
        __m256i actual;
        // Use stream load if aligned to 32 bytes
        if (((uintptr_t)(src + i) & 31) == 0) {
            actual = _mm256_stream_load_si256((__m256i*)(src + i));
        } else {
            actual = _mm256_loadu_si256((const __m256i*)(src + i));
        }

        __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
        int mask = _mm256_movemask_epi8(eq);
        if ((uint32_t)mask != 0xFFFFFFFF) {
            for (size_t k = 0; k < 4; ++k) {
                if (src[i+k] != (param0 + (start_idx + i + k) * param1)) {
                   error_indices.push_back(i + k);
                }
            }
        }
        v_expect = _mm256_add_epi64(v_expect, v_step4);
    }
#endif

    for (; i < count; ++i) {
        if (src[i] != (param0 + (start_idx + i) * param1)) {
            error_indices.push_back(i);
        }
    }
}

template<>
void verify_pattern_xor<uint64_t>(const uint64_t* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1, std::vector<uint64_t>& error_indices) {
    size_t i = 0;

    // NOTE: AVX2 doesn't have native 64-bit integer multiply.
    // Previous SIMD emulation was incorrect. For RAM testing, correctness > speed.
    // Only AVX512 has _mm512_mullo_epi64, so use that if available.

#if defined(__AVX512F__)
    SimdCapabilities caps = getCapabilities();
    if (caps.has_avx512 && count >= 8) {
        __m512i v_param0 = _mm512_set1_epi64(param0);
        __m512i v_param1 = _mm512_set1_epi64(param1);

        __m512i v_idx = _mm512_set_epi64(start_idx + 7, start_idx + 6, start_idx + 5, start_idx + 4,
                                         start_idx + 3, start_idx + 2, start_idx + 1, start_idx);
        __m512i v_idx_step = _mm512_set1_epi64(8);

        for (; i + 8 <= count; i += 8) {
            __m512i actual = _mm512_loadu_si512((const __m512i*)(src + i));
            __m512i v_mul = _mm512_mullo_epi64(v_idx, v_param1);
            __m512i v_expect = _mm512_xor_si512(v_param0, v_mul);
            __mmask8 mask = _mm512_cmpeq_epi64_mask(actual, v_expect);
            if (mask != 0xFF) {
                // Scalar verification for mismatches
                for (size_t k = 0; k < 8; ++k) {
                    if (!(mask & (1 << k))) {
                        if (src[i+k] != (param0 ^ ((start_idx + i + k) * param1))) {
                            error_indices.push_back(i + k);
                        }
                    }
                }
            }
            v_idx = _mm512_add_epi64(v_idx, v_idx_step);
        }
    }
#endif

#if defined(__AVX2__)
    // Optimized AVX2 Path
    SimdCapabilities caps = getCapabilities();
    if (caps.has_avx2 && count >= 4) {
        __m256i v_param0 = _mm256_set1_epi64x(param0);
        __m256i v_param1 = _mm256_set1_epi64x(param1);
        __m256i v_idx = _mm256_set_epi64x(start_idx + 3, start_idx + 2, start_idx + 1, start_idx);
        __m256i v_idx_step = _mm256_set1_epi64x(4);
        
        // Initialize term = idx * param1 using the expensive mul once
        __m256i v_term = mul64_avx2(v_idx, v_param1);
        // Step = 4 * param1
        __m256i v_term_step = _mm256_slli_epi64(v_param1, 2);
        
        for (; i + 4 <= count; i += 4) {
            
            __m256i actual;
            if (((uintptr_t)(src + i) & 31) == 0) {
                 actual = _mm256_stream_load_si256((__m256i*)(src + i));
            } else {
                 actual = _mm256_loadu_si256((const __m256i*)(src + i));
            }
            
            // Calculate expected using Add instead of Mul
            // v_expect = param0 ^ v_term
            __m256i v_expect = _mm256_xor_si256(v_param0, v_term);
            
            __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
            int mask = _mm256_movemask_epi8(eq);
            
            // 0xFFFFFFFF means all bytes equal
            if ((uint32_t)mask != 0xFFFFFFFF) {
                 for (size_t k = 0; k < 4; ++k) {
                     if (src[i+k] != (param0 ^ ((start_idx + i + k) * param1))) {
                         error_indices.push_back(i + k);
                     }
                 }
            }
            v_term = _mm256_add_epi64(v_term, v_term_step);
        }
    }
#endif

    // Scalar fallback - guaranteed correct
    for (; i < count; ++i) {
        if (src[i] != (param0 ^ ((start_idx + i) * param1))) {
            error_indices.push_back(i);
        }
    }
}

template<>
void verify_uniform<uint64_t>(const uint64_t* src, size_t count, uint64_t val, std::vector<uint64_t>& error_indices) {
    size_t i = 0;
#if defined(__AVX512F__)
    SimdCapabilities caps = getCapabilities();
    if (caps.has_avx512) {
        __m512i v_expect = _mm512_set1_epi64(val);
        for (; i + 8 <= count; i += 8) {
             __m512i actual;
             if (((uintptr_t)(src + i) & 63) == 0) {
                 actual = _mm512_stream_load_si512((void*)(src + i));
             } else {
                 actual = _mm512_loadu_si512((const void*)(src + i));
             }

             __mmask8 mask = _mm512_cmpneq_epi64_mask(actual, v_expect);
             if (mask) {
                 for (int k = 0; k < 8; ++k) {
                     if ((mask >> k) & 1) {
                         error_indices.push_back(i + k);
                     }
                 }
             }
        }
    }
#endif

#if defined(__AVX2__)
    __m256i v_expect = _mm256_set1_epi64x(val);
    for (; i + 4 <= count; i += 4) {
        __m256i actual;
        // Use stream load if aligned to 32 bytes
        if (((uintptr_t)(src + i) & 31) == 0) {
            actual = _mm256_stream_load_si256((__m256i*)(src + i));
        } else {
            actual = _mm256_loadu_si256((const __m256i*)(src + i));
        }

        __m256i eq = _mm256_cmpeq_epi64(actual, v_expect);
        int mask = _mm256_movemask_epi8(eq);
        if ((uint32_t)mask != 0xFFFFFFFF) {
            for (size_t k = 0; k < 4; ++k) {
                if (src[i+k] != val) {
                    error_indices.push_back(i + k);
                }
            }
        }
    }
#endif
    for (; i < count; ++i) {
        if (src[i] != val) {
            error_indices.push_back(i);
        }
    }
}

template<>
void invert_array<uint64_t>(uint64_t* dst, size_t count, bool use_nt) {
    SimdCapabilities caps = getCapabilities();
    (void)caps;
    size_t i = 0;
#if defined(__AVX2__)
    __m256i ones = _mm256_set1_epi64x(~0ULL);
    for (; i + 4 <= count; i += 4) {
        __m256i v = _mm256_loadu_si256((const __m256i*)(dst + i));
        v = _mm256_xor_si256(v, ones);
        if (use_nt && caps.has_nt_stores) {
            _mm256_stream_si256((__m256i*)(dst + i), v);
        } else {
            _mm256_storeu_si256((__m256i*)(dst + i), v);
        }
    }
#endif
    for (; i < count; ++i) dst[i] = ~dst[i];
}

template<>
void verify_moving_inv<uint64_t>(const uint64_t* src, size_t count, uint64_t val, std::vector<uint64_t>& error_indices) {
    verify_uniform(src, count, val, error_indices);
}

// Safe forced memory read after cache flush
// Avoids undefined behavior of volatile casts
// Performs: flush cache line, memory fence, read value
uint64_t safe_read_u64(const uint64_t* ptr) {
    // Flush the cache line to ensure we read from RAM
    flush_cache_line((void*)ptr);
    memory_fence();  // Ensure flush completes before read
    
    // Use compiler barrier to prevent optimization
    // This is safer than volatile cast which is technically UB
#if defined(__aarch64__) || defined(_M_ARM64)
    // ARM64 implementation
    uint64_t val;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "ldr %0, [%1]"
        : "=r" (val)
        : "r" (ptr)
        : "memory"
    );
#else // MSVC ARM64
    // MSVC doesn't support inline asm on ARM64, use volatile
    val = *(volatile uint64_t*)ptr;
#endif
    return val;
#elif defined(__x86_64__) || defined(_M_X64)
    // x86-64 implementation
#if defined(__GNUC__) || defined(__clang__)
    uint64_t val;
    __asm__ volatile(
        "movq (%1), %0"
        : "=r" (val)
        : "r" (ptr)
        : "memory"
    );
    return val;
#else // MSVC x64
    _ReadWriteBarrier();
    uint64_t val = *ptr;
    _ReadWriteBarrier();
    return val;
#endif
#else
    // Fallback for other architectures
    return *(volatile uint64_t*)ptr;
#endif
}

uint32_t safe_read_u32(const uint32_t* ptr) {
    flush_cache_line((void*)ptr);
    memory_fence();
    
#if defined(__aarch64__) || defined(_M_ARM64)
    // ARM64 implementation
    uint32_t val;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "ldr %w0, [%1]"
        : "=r" (val)
        : "r" (ptr)
        : "memory"
    );
#else // MSVC ARM64
    val = *(volatile uint32_t*)ptr;
#endif
    return val;
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    // x86/x64 implementation
#if defined(__GNUC__) || defined(__clang__)
    uint32_t val;
    __asm__ volatile(
        "movl (%1), %0"
        : "=r" (val)
        : "r" (ptr)
        : "memory"
    );
    return val;
#else // MSVC
    _ReadWriteBarrier();
    uint32_t val = *ptr;
    _ReadWriteBarrier();
    return val;
#endif
#else
    // Fallback
    return *(volatile uint32_t*)ptr;
#endif
}

}} // namespace testsmem4u::simd
