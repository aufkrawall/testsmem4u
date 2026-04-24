#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <utility>

namespace testsmem4u {
namespace simd {

enum class SimdLevel {
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
    size_t nt_store_width = 16;
};

// Maximum mismatch samples retained per verification block. The verifier still
// counts every mismatch, but stores only this many observed values for logging
// and hard/soft re-read classification.
constexpr size_t MAX_ERROR_SAMPLES_PER_BLOCK = 4096;

SimdCapabilities getCapabilities();
const char* getSimdLevelName(SimdLevel level);

// Memory Fences
void memory_fence();
void sfence();
void lfence();

// Cache Management
void flush_cache_line(void* ptr);

// Flush entire memory region from cache - essential for true RAM testing
// This ensures subsequent reads come from DRAM, not CPU cache
void flush_cache_region(void* ptr, size_t bytes);

// Pattern Generators (Write to Memory)
template<typename T>
void generate_pattern_linear(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt, size_t start_idx = 0);

template<typename T>
void generate_pattern_xor(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt, size_t start_idx = 0);

template<typename T>
void generate_pattern_increment(T* dst, size_t count, uint64_t start, bool use_nt);

template<typename T>
void generate_pattern_uniform(T* dst, size_t count, uint64_t val, bool use_nt);

// Utility
template<typename T>
void invert_array(T* dst, size_t count, bool use_nt);

// Verification (Read from Memory)
// Returns the total mismatch count and stores at most max_error_samples pairs
// of (offset, observed_value). Uses SIMD comparison for speed where possible.
template<typename T>
size_t verify_pattern_linear(const T* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1,
                             std::vector<std::pair<uint64_t, uint64_t>>& errors,
                             size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

template<typename T>
size_t verify_pattern_xor(const T* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1,
                          std::vector<std::pair<uint64_t, uint64_t>>& errors,
                          size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

template<typename T>
size_t verify_uniform(const T* src, size_t count, uint64_t val,
                      std::vector<std::pair<uint64_t, uint64_t>>& errors,
                      size_t max_error_samples = MAX_ERROR_SAMPLES_PER_BLOCK);

// Safe forced memory read after cache flush
// Use this instead of volatile casts (which are UB in C++)
// Performs: flush cache line, memory fence, read value
uint64_t safe_read_u64(const uint64_t* ptr);
uint32_t safe_read_u32(const uint32_t* ptr);

}} // namespace testsmem4u::simd
