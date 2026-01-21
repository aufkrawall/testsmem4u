#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace testsmem4u {
namespace simd {

enum class SimdLevel {
    NONE = 0,
    SSE4_1 = 1,
    AVX2 = 2,
    AVX512 = 3,
    NEON = 4,
    NEON_SVE = 5
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
    size_t vector_width = 16;
    size_t nt_store_width = 16;
};

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

// Non-Temporal Stores (Bypass Cache for Writes)
template<typename T>
void nt_store_128(T* dst, const T* src, size_t count);

template<typename T>
void nt_store_256(T* dst, const T* src, size_t count);

template<typename T>
void nt_store_512(T* dst, const T* src, size_t count);

// Aligned Stores (Standard)
template<typename T>
void aligned_store(T* dst, const T* src, size_t count);

// Aligned Loads (Standard)
template<typename T>
void aligned_load(T* dst, const T* src, size_t count);

// Non-Temporal Loads (Bypass Cache for Reads) - Requires Memory Alignment!
template<typename T>
void stream_load_128(T* dst, const T* src, size_t count);

template<typename T>
void stream_load_256(T* dst, const T* src, size_t count);

template<typename T>
void stream_load_512(T* dst, const T* src, size_t count);

// Pattern Generators (Write to Memory)
template<typename T>
void generate_pattern_linear(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt);

template<typename T>
void generate_pattern_xor(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt);

template<typename T>
void generate_pattern_moving_inv(T* dst, size_t count, uint64_t val, bool use_nt);

template<typename T>
void generate_pattern_lfsr(T* dst, size_t count, uint64_t param0, uint64_t param1, bool use_nt);

template<typename T>
void generate_pattern_increment(T* dst, size_t count, uint64_t start, bool use_nt);

template<typename T>
void generate_pattern_uniform(T* dst, size_t count, uint64_t val, bool use_nt);

// Utility
template<typename T>
void invert_array(T* dst, size_t count, bool use_nt);

// Verification (Read from Memory)
// Returns number of errors found. Populates error_indices with offsets of failing words.
// Uses SIMD comparison for speed where possible.
template<typename T>
size_t verify_pattern_linear(const T* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1, uint64_t* error_indices, size_t max_errors);

template<typename T>
size_t verify_pattern_xor(const T* src, size_t count, size_t start_idx, uint64_t param0, uint64_t param1, uint64_t* error_indices, size_t max_errors);

template<typename T>
size_t verify_uniform(const T* src, size_t count, uint64_t val, uint64_t* error_indices, size_t max_errors);

template<typename T>
size_t verify_moving_inv(const T* src, size_t count, uint64_t val, uint64_t* error_indices, size_t max_errors);

}} // namespace testsmem4u::simd
