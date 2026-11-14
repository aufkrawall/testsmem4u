#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <utility>

namespace testsmem4u {
namespace simd {

enum class SimdLevel : uint8_t {
    NONE = 0,
    SSE4_1 = 1,
    AVX2 = 2,
    AVX512 = 3,
    NEON = 4
};

struct SimdCapabilities {
    SimdLevel level = SimdLevel::NONE;
    bool has_nt_stores = false;
    bool has_avx512 = false;
    bool has_avx2 = false;
    bool has_sse4_1 = false;
    bool has_neon = false;
    bool has_sve = false;
    bool has_clflush = false;
    bool has_clflushopt = false;
    size_t vector_width = 16;
    size_t cache_line_size = 64; // Flush-loop stride; x86: CPUID granule capped at 64
    size_t flush_granule_advertised = 0; // x86 CPUID.1 CLFLUSH granule (0 = none/invalid)
};

// Maximum mismatch samples retained per verification block. The verifier still
// counts every mismatch, but stores only this many observed values for logging
// and hard/soft re-read classification.
constexpr size_t MAX_ERROR_SAMPLES_PER_BLOCK = 4096;

SimdCapabilities getCapabilities();

// Memory Fences
void memory_fence();
void sfence();

// Cache Management
void flush_cache_line(void* ptr);

// Flush a batch with one capability dispatch and one fence. Entries may share
// a cache line; callers must finish all stores before calling this function.
void flush_cache_lines(void* const* lines, size_t count);

// Flush entire memory region from cache - essential for true RAM testing
// This ensures subsequent reads come from DRAM, not CPU cache
void flush_cache_region(void* ptr, size_t bytes);

// True when generate_pattern_* / fill_lfsr with use_nt=true write every word
// with a non-temporal store: x86-64 with SSE4.1-era NT support. Such stores
// evict any cached copy of the line (Intel SDM Vol. 1, "Caching of Temporal vs.
// Non-Temporal Data"; measured on Zen 3 with tools/probes/nt_fill_cache_probe.cpp),
// so after the generator's SFENCE the region is not cache-resident. Older CPUs
// may update a cached line in place and have no SSE4.1, so they report false, as
// do ARM64 and 32-bit x86 builds, whose scalar fills use cached stores.
bool streaming_fill_bypasses_cache();

// Call after a streaming fill (use_nt=true) and before verifying it: flushes
// the region only where such a fill can leave lines cached. Never use it after
// loads or cached stores (verify passes, march replace, memcpy, mirror moves):
// those leave lines cached, and prefetchers trained by loads can refill lines.
void flush_after_streaming_fill(void* ptr, size_t bytes);

// Pattern Generators (Write to Memory)
template<typename T>
void generate_pattern_linear(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt, uint64_t start_idx = 0);

template<typename T>
void generate_pattern_xor(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt, uint64_t start_idx = 0);

template<typename T>
void generate_pattern_uniform(T* dst, size_t count, uint64_t val, bool use_nt);

// Verification (Read from Memory)
// Returns the total mismatch count and stores at most max_error_samples pairs
// of (offset, observed_value). Uses SIMD comparison for speed where possible.
template<typename T>
size_t verify_pattern_linear(const T* src, size_t count, uint64_t start_idx, uint64_t param0, uint64_t param1,
                             std::vector<std::pair<uint64_t, uint64_t>>& errors,
                             size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

template<typename T>
size_t verify_pattern_xor(const T* src, size_t count, uint64_t start_idx, uint64_t param0, uint64_t param1,
                          std::vector<std::pair<uint64_t, uint64_t>>& errors,
                          size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

template<typename T>
size_t verify_uniform(const T* src, size_t count, uint64_t val,
                      std::vector<std::pair<uint64_t, uint64_t>>& errors,
                      size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

// Verifies an alternating two-value pattern: src[k] must equal even_val for
// even k and odd_val for odd k (k relative to src, so callers must pass
// block pointers that start at an even pattern index).
template<typename T>
size_t verify_pattern_pair(const T* src, size_t count, uint64_t even_val, uint64_t odd_val,
                           std::vector<std::pair<uint64_t, uint64_t>>& errors,
                           size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

// Per-beat complement ("beat") pattern. Global word g holds
//   (g odd ? odd : even) ^ beat_tag(salt + (g >> 1) * step)
// where beat_tag copies the low 32 bits into both halves. With odd == ~even
// every second 64-bit bus beat is the exact complement of the one before (all
// DQ lines toggle), and the symmetric tag also keeps any complement relation
// between the two 32-bit halves of even/odd (DDR5 32-bit sub-channel beats).
// An odd step gives every 16-byte unit within 64 GiB its own tag, so moved or
// aliased data is detectable.
struct BeatPattern {
    uint64_t even = 0;
    uint64_t odd = 0;
    uint64_t salt = 0;
    uint64_t step = 0;
};

constexpr uint64_t beat_tag(uint64_t x) { return (x & 0xFFFFFFFFULL) | (x << 32); }

constexpr uint64_t beat_value(const BeatPattern& p, uint64_t global_word) {
    return ((global_word & 1) ? p.odd : p.even) ^ beat_tag(p.salt + (global_word >> 1) * p.step);
}

// The pattern held after mirror_reverse_pairs on `pairs` 16-byte units starting
// at the even global word g0: unit q then holds the former unit pairs-1-q.
constexpr BeatPattern beat_mirrored(const BeatPattern& p, uint64_t g0, uint64_t pairs) {
    return BeatPattern{p.even, p.odd, p.salt + (g0 + pairs - 1) * p.step, 0 - p.step};
}

// Writes beat_value(p, start_word + k) to dst[k]; with use_nt every word is a
// non-temporal store on x86-64 (streaming_fill_bypasses_cache contract). Fences.
void generate_pattern_beat(uint64_t* dst, size_t count, const BeatPattern& p, uint64_t start_word, bool use_nt);

// Verifies dst[k] == beat_value(p, start_word + k); same sampling contract as
// the other verifiers (each word read once, samples from the loaded register).
size_t verify_pattern_beat(const uint64_t* src, size_t count, const BeatPattern& p, uint64_t start_word,
                           std::vector<std::pair<uint64_t, uint64_t>>& errors,
                           size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

// Mirror moves: two streams converge from both ends of the block and swap what
// they read, so each step reads and writes two far-apart rows (row conflicts and
// read/write turnarounds in one thread). Writes are non-temporal where
// available and fenced; callers must flush before verifying (the loads cached
// the lines). 64-byte aligned blocks of whole lines take the SIMD path.
// mirror_reverse_words: word i <-> word count-1-i (the block is reversed).
// mirror_reverse_pairs: 16-byte unit i <-> unit units-1-i, each unit kept in
// order (units = count / 2; an odd final word stays in place).
void mirror_reverse_words(uint64_t* data, size_t count);
void mirror_reverse_pairs(uint64_t* data, size_t count);

// Safe forced memory read after cache flush
// Use this instead of volatile casts (which are UB in C++)
// Performs: flush cache line, memory fence, read value
uint64_t safe_read_u64(const uint64_t* ptr);

}} // namespace testsmem4u::simd
