#include "simd_ops.h"
#include "SimdPatternMath.h"
#include "SimdCacheGeometry.h"
#include <atomic>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <nmmintrin.h>
#elif defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

namespace testsmem4u {
namespace simd {

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#if defined(_MSC_VER)
    #include <intrin.h>
    static inline void queryCpuId(int* cpuInfo, int function_id, int subfunction_id) {
        __cpuidex(cpuInfo, function_id, subfunction_id);
    }
#else
    #include <cpuid.h>
    static inline void queryCpuId(int* cpuInfo, int function_id, int subfunction_id) {
        __cpuid_count(function_id, subfunction_id, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    }
#endif

static inline uint64_t read_xcr0() {
#if defined(_MSC_VER)
    return _xgetbv(0);
#elif defined(__GNUC__) || defined(__clang__)
    uint32_t eax = 0;
    uint32_t edx = 0;
    __asm__ volatile (".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return (static_cast<uint64_t>(edx) << 32) | eax;
#else
    return 0;
#endif
}

static SimdCapabilities detect_x86_capabilities() {
    SimdCapabilities caps;

    int info[4] = {0, 0, 0, 0};
    queryCpuId(info, 0, 0);
    const int max_leaf = info[0];

    queryCpuId(info, 1, 0);
    const bool cpu_has_sse41 = (info[2] & (1 << 19)) != 0;
    const bool cpu_has_avx = (info[2] & (1 << 28)) != 0;
    const bool cpu_has_osxsave = (info[2] & (1 << 27)) != 0;
    caps.has_clflush = (info[3] & (1 << 19)) != 0;
    caps.flush_granule_advertised = detail::x86AdvertisedFlushGranule(static_cast<uint32_t>(info[1]),
                                                                      static_cast<uint32_t>(info[3]));
    caps.cache_line_size = detail::x86FlushLineSize(static_cast<uint32_t>(info[1]),
                                                  static_cast<uint32_t>(info[3]));

    // Detect XSAVE-enabled OS state support. AVX-512 state is probed
    // unconditionally (not behind __AVX512F__) so baseline/v3 binaries can tell
    // the user when the -v4 sibling variant would match their hardware.
    bool os_has_avx_state = false;
    bool os_has_avx512_state = false;
    if (cpu_has_osxsave) {
        const uint64_t xcr0 = read_xcr0();
        os_has_avx_state = (xcr0 & 0x6ULL) == 0x6ULL;        // XMM + YMM state
        os_has_avx512_state = os_has_avx_state && ((xcr0 & 0xE0ULL) == 0xE0ULL); // Opmask + ZMM_Hi256 + Hi16_ZMM
    }

    bool cpu_has_avx2 = false;
    bool cpu_has_avx512f = false;
    if (max_leaf >= 7) {
        queryCpuId(info, 7, 0);
        caps.has_clflushopt = (info[1] & (1 << 23)) != 0;
        cpu_has_avx2 = (info[1] & (1 << 5)) != 0;
        cpu_has_avx512f = (info[1] & (1 << 16)) != 0;
    }

    // Report true CPU+OS AVX-512 support regardless of the instruction set this
    // binary was compiled for. This flag drives the use-the-v4-binary hint; it is
    // only acted on for code generation where guarded by __AVX512F__, so the
    // baseline/v3 binaries never emit AVX-512 instructions even when it is true.
    caps.has_avx512 = cpu_has_avx512f && cpu_has_avx && os_has_avx512_state;

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        caps.level = SimdLevel::AVX512;
        caps.has_avx2 = true;
        caps.has_sse4_1 = true;
        caps.has_nt_stores = true;
        caps.vector_width = 64;
    } else
#endif
    if (cpu_has_avx2 && cpu_has_avx && os_has_avx_state) {
        caps.level = SimdLevel::AVX2;
        caps.has_avx2 = true;
        caps.has_sse4_1 = true;
        caps.has_nt_stores = true;
        caps.vector_width = 32;
    } else if (cpu_has_sse41) {
        caps.level = SimdLevel::SSE4_1;
        caps.has_sse4_1 = true;
        caps.has_nt_stores = true;
        caps.vector_width = 16;
    }
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

// Keep the complete loops in the target-specific function. Calling the
// single-line helper here costs a call/return (and sometimes VZEROUPPER) for
// every 64 bytes even in ThinLTO release builds.
#ifdef __clang__
__attribute__((target("clflushopt")))
#endif
static void flushRegionOpt(uint8_t* ptr, size_t bytes, size_t line_size) {
    for (size_t offset = 0; offset < bytes; offset += line_size) {
        _mm_clflushopt(ptr + offset);
    }
    _mm_mfence();
}

#ifdef __clang__
__attribute__((target("clflushopt")))
#endif
static void flushLinesOpt(void* const* lines, size_t count) {
    for (size_t i = 0; i < count; ++i) _mm_clflushopt(lines[i]);
    _mm_mfence();
}

void flush_cache_line(void* ptr) {
    if (getCapabilities().has_clflushopt) {
        do_clflushopt(ptr);
    } else {
        _mm_clflush(ptr);
    }
}

void flush_cache_lines(void* const* lines, size_t count) {
    if (getCapabilities().has_clflushopt) {
        flushLinesOpt(lines, count);
    } else {
        for (size_t i = 0; i < count; ++i) _mm_clflush(lines[i]);
        _mm_mfence();
    }
}

void flush_cache_region(void* ptr, size_t bytes) {
    // Cache capabilities once to avoid repeated function call overhead
    const SimdCapabilities caps = getCapabilities();
    const size_t cache_line_size = caps.cache_line_size;
    const uintptr_t address = reinterpret_cast<uintptr_t>(ptr);
    const size_t prefix = address % cache_line_size;
    auto* first = reinterpret_cast<uint8_t*>(address - prefix);
    const size_t span = bytes ? bytes + prefix : 0;
    if (caps.has_clflushopt) {
        flushRegionOpt(first, span, cache_line_size);
    } else {
        for (size_t offset = 0; offset < span; offset += cache_line_size) {
            _mm_clflush(first + offset);
        }
        _mm_mfence();
    }
}

#elif defined(__aarch64__) || defined(_M_ARM64)

static SimdCapabilities detect_arm_capabilities() {
    SimdCapabilities caps;
    caps.has_neon = true;
    caps.vector_width = 16;
    caps.level = SimdLevel::NEON;
    // ARM64 cache line size is typically 64 bytes (could also be 128 on some CPUs)
    caps.cache_line_size = 64;
    return caps;
}

void flush_cache_line(void* ptr) {
#if defined(__GNUC__) || defined(__clang__)
     __asm__ __volatile__("dc civac, %0" :: "r" (ptr) : "memory");
#endif
}

void flush_cache_region(void* ptr, size_t bytes) {
    const SimdCapabilities caps = getCapabilities();
    const size_t cache_line_size = caps.cache_line_size;
    uint8_t* p = static_cast<uint8_t*>(ptr);
    uint8_t* end = p + bytes;
    
    for (; p < end; p += cache_line_size) {
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
    // cache_line_size detection is irrelevant here
}

#endif

#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__i386__) && !defined(_M_IX86)
void flush_cache_lines(void* const* lines, size_t count) {
    for (size_t i = 0; i < count; ++i) flush_cache_line(lines[i]);
    memory_fence();
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

void memory_fence() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    _mm_mfence();
#else
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

void sfence() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    _mm_sfence();
#else
    std::atomic_thread_fence(std::memory_order_release);
#endif
}

template<>
void generate_pattern_linear<uint64_t>(uint64_t* dst, size_t count, uint64_t param0, uint64_t param1, [[maybe_unused]] bool use_nt, uint64_t start_idx) {
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
    size_t i = 0;

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_val = _mm512_set_epi64(
            param0 + (start_idx + 7) * param1, param0 + (start_idx + 6) * param1,
            param0 + (start_idx + 5) * param1, param0 + (start_idx + 4) * param1,
            param0 + (start_idx + 3) * param1, param0 + (start_idx + 2) * param1,
            param0 + (start_idx + 1) * param1, param0 + (start_idx + 0) * param1
        );
        __m512i v_idx_step = _mm512_set1_epi64(8 * param1);

        for (; i + 8 <= count; i += 8) {
            if (use_nt && caps.has_nt_stores) {
                _mm512_stream_si512((void*)(dst + i), v_val);
            } else {
                _mm512_storeu_si512((void*)(dst + i), v_val);
            }
            v_val = _mm512_add_epi64(v_val, v_idx_step);
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2 && i + 4 <= count) {
        // Initialize from current i (may be non-zero after AVX512 processed bulk)
        __m256i v_val = _mm256_set_epi64x(
            param0 + (start_idx + i + 3) * param1,
            param0 + (start_idx + i + 2) * param1,
            param0 + (start_idx + i + 1) * param1,
            param0 + (start_idx + i + 0) * param1
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

#if defined(__x86_64__) || defined(_M_X64)
    // NT-store scalar fallback keeps DRAM write stress on baseline binaries,
    // where no wider SIMD path for this pattern was compiled in.
    if (use_nt && caps.has_nt_stores) {
        for (; i < count; ++i) {
            _mm_stream_si64((long long*)(dst + i), (long long)(param0 + ((start_idx + i) * param1)));
        }
    }
#endif
    for (; i < count; ++i) {
        dst[i] = param0 + ((start_idx + i) * param1);
    }
    sfence();
}

template<>
void generate_pattern_xor<uint64_t>(uint64_t* dst, size_t count, uint64_t param0, uint64_t param1, [[maybe_unused]] bool use_nt, uint64_t start_idx) {
    size_t i = 0;
#if defined(__AVX512F__) || defined(__AVX2__) || defined(__x86_64__) || defined(_M_X64)
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
#endif

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v_param0 = _mm512_set1_epi64(param0);
        __m512i v_param1 = _mm512_set1_epi64(param1);
        __m512i v_idx = _mm512_set_epi64(start_idx + 7, start_idx + 6, start_idx + 5, start_idx + 4,
                                         start_idx + 3, start_idx + 2, start_idx + 1, start_idx);
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
    // Optimized AVX2 path.
    if (caps.has_avx2 && i + 4 <= count) {
        __m256i v_param0 = _mm256_set1_epi64x(param0);
        __m256i v_param1 = _mm256_set1_epi64x(param1);
        
        // Start indices from current position i: {i+3, i+2, i+1, i}
        __m256i v_idx = _mm256_set_epi64x(
            static_cast<int64_t>(start_idx + i + 3),
            static_cast<int64_t>(start_idx + i + 2),
            static_cast<int64_t>(start_idx + i + 1),
            static_cast<int64_t>(start_idx + i)
        );
        
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

#if defined(__x86_64__) || defined(_M_X64)
    // NT-store scalar fallback keeps DRAM write stress on baseline binaries,
    // where no wider SIMD path for this pattern was compiled in.
    if (use_nt && caps.has_nt_stores) {
        for (; i < count; ++i) {
            _mm_stream_si64((long long*)(dst + i), (long long)(param0 ^ ((start_idx + i) * param1)));
        }
    }
#endif
    // Scalar fallback - guaranteed correct
    for (; i < count; ++i) {
        dst[i] = param0 ^ ((start_idx + i) * param1);
    }
    sfence();
}

template<>
void generate_pattern_uniform<uint64_t>(uint64_t* dst, size_t count, uint64_t val, [[maybe_unused]] bool use_nt) {
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
    size_t i = 0;

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i v = _mm512_set1_epi64(val);
        for (; i + 8 <= count; i += 8) {
            if (use_nt && caps.has_nt_stores) {
                _mm512_stream_si512((void*)(dst + i), v);
            } else {
                _mm512_storeu_si512((void*)(dst + i), v);
            }
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
        __m256i v = _mm256_set1_epi64x(val);
        for (; i + 4 <= count; i += 4) {
            if (use_nt && caps.has_nt_stores) {
                _mm256_stream_si256((__m256i*)(dst + i), v);
            } else {
                _mm256_storeu_si256((__m256i*)(dst + i), v);
            }
        }
    } else
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1) {
        __m128i v = _mm_set1_epi64x(val);
        for (; i + 2 <= count; i += 2) {
            if (use_nt && caps.has_nt_stores) {
                _mm_stream_si128((__m128i*)(dst + i), v);
            } else {
                _mm_storeu_si128((__m128i*)(dst + i), v);
            }
        }
    }
#endif

    for (; i < count; ++i) dst[i] = val;
    sfence();
}

template<>
void generate_pattern_increment<uint64_t>(uint64_t* dst, size_t count, uint64_t start, [[maybe_unused]] bool use_nt) {
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
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

#if defined(__x86_64__) || defined(_M_X64)
    // NT-store scalar fallback keeps DRAM write stress on baseline binaries,
    // where no wider SIMD path for this pattern was compiled in.
    if (use_nt && caps.has_nt_stores) {
        for (; i < count; ++i) {
            _mm_stream_si64((long long*)(dst + i), (long long)(start + i));
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
void invert_array<uint64_t>(uint64_t* dst, size_t count, [[maybe_unused]] bool use_nt) {
    [[maybe_unused]] const SimdCapabilities caps = getCapabilities();
    size_t i = 0;

#if defined(__AVX512F__)
    if (caps.has_avx512) {
        __m512i ones = _mm512_set1_epi64(~0ULL);
        for (; i + 8 <= count; i += 8) {
            __m512i v = _mm512_loadu_si512((const void*)(dst + i));
            v = _mm512_xor_si512(v, ones);
            if (use_nt && caps.has_nt_stores) {
                _mm512_stream_si512((void*)(dst + i), v);
            } else {
                _mm512_storeu_si512((void*)(dst + i), v);
            }
        }
    }
#endif

#if defined(__AVX2__)
    if (caps.has_avx2) {
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
    } else
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
    if (caps.has_sse4_1) {
        __m128i ones = _mm_set1_epi64x(~0ULL);
        for (; i + 2 <= count; i += 2) {
            __m128i v = _mm_loadu_si128((const __m128i*)(dst + i));
            v = _mm_xor_si128(v, ones);
            if (use_nt && caps.has_nt_stores) {
                _mm_stream_si128((__m128i*)(dst + i), v);
            } else {
                _mm_storeu_si128((__m128i*)(dst + i), v);
            }
        }
    }
#endif

    for (; i < count; ++i) dst[i] = ~dst[i];
    sfence();
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

}} // namespace testsmem4u::simd
