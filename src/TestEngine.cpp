#include "TestEngine.h"
#include "Logger.h"
#include "simd_ops.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <iomanip>
#include <sstream>
#include <random>

#ifdef _WIN32
#include <windows.h>
#endif

namespace testsmem4u {

// Static pointer to current TestContext for shutdown handler
static std::atomic<TestContext*> g_current_context{nullptr};

std::vector<uint32_t> parseTestSequence(const std::string& sequence) {
    std::vector<uint32_t> result;
    std::stringstream ss(sequence);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t start = item.find_first_not_of(" \t");
        if (start != std::string::npos) {
            char* endptr = nullptr;
            unsigned long val = std::strtoul(item.c_str() + start, &endptr, 10);
            if (endptr != item.c_str() + start) {
                result.push_back(static_cast<uint32_t>(val));
            }
        }
    }
    if (result.empty()) result.push_back(0);
    return result;
}

using namespace simd;

static inline void generatePatternValue(uint64_t index, uint8_t mode, uint64_t p0, uint64_t p1, uint64_t& val) {
    if (mode == 0) val = p0;
    else if (mode == 1) val = p0 ^ (index * p1);
    else if (mode == 2) val = p0 + (index * p1);
    else val = index;
}

size_t TestEngine::verifyAndReport(const uint64_t* ptr, size_t count, size_t start_idx,
                                   uint8_t pattern_mode, uint64_t param0, uint64_t param1,
                                   TestResult& res, TestContext& ctx, const std::string& test_name, bool halt_on_error) {
    std::vector<uint64_t> error_indices;
    error_indices.reserve(128); // Pre-allocate small amount

    if (pattern_mode == 0) {
        verify_uniform(ptr, count, param0, error_indices);
    } else if (pattern_mode == 1) {
        verify_pattern_xor(ptr, count, start_idx, param0, param1, error_indices);
    } else {
        verify_pattern_linear(ptr, count, start_idx, param0, param1, error_indices);
    }

    size_t found = error_indices.size();
    if (found == 0) return 0;

    for (size_t i = 0; i < found; ++i) {
        uint64_t idx = error_indices[i];
        uint64_t expect;
        generatePatternValue(start_idx + idx, pattern_mode, param0, param1, expect);
        
        // CRITICAL: Use safe_read which flushes cache and forces RAM read
        // This is essential for accurate soft vs hard error detection
        uint64_t actual = simd::safe_read_u64(&ptr[idx]);

        if (actual != expect) {
            // Hard Error: Re-read from RAM confirmed the mismatch
            LOG_ERROR_DETAIL((test_name + " (Hard)").c_str(), (uint64_t)((start_idx + idx) * 8), expect, actual);
            res.hard_errors++;
        } else {
            // Soft/Transient Error: Initial read failed but RAM now has correct value
            // This indicates a transient bit flip - still a real RAM error
            LOG_ERROR_DETAIL((test_name + " (Soft/Transient)").c_str(), (uint64_t)((start_idx + idx) * 8), expect, actual);
            res.soft_errors++;
        }
        
        if (halt_on_error && res.total_errors() > 0) {
            ctx.requestStop();
            break;
        }
    }

    return found;
}

TestResult TestEngine::runSimpleTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    bool use_nt = true;

    // Write pattern to memory
    if (config.pattern_mode == 0) {
        generate_pattern_uniform(ptr, count, config.pattern_param0, use_nt);
    } else if (config.pattern_mode == 1) {
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
    } else {
        generate_pattern_linear(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
    }

    sfence();
    
    // CRITICAL: Flush entire region from cache to ensure verification reads from RAM
    // This is essential for detecting real RAM errors vs cache hits
    simd::flush_cache_region(ptr, region.size);

    // Verify in blocks (2MB chunks)
    size_t block = 256 * 1024; 

    for (size_t i = 0; i < count; i += block) {
        if (ctx.shouldStop()) break;
        size_t n = std::min(block, count - i);

        TestEngine::verifyAndReport(ptr + i, n, i, config.pattern_mode, config.pattern_param0, 
                                    config.pattern_param1, res, ctx, "SimpleTest", stop);

        if (stop && ctx.shouldStop()) break;
    }

    res.bytes_tested = region.size;  // Count once at the end (was double-counted before)
    return res;
}

TestResult TestEngine::runRowHammerTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    (void)config;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // Initialize random number generator with high-quality seed
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_int_distribution<size_t> dist(0, count - 1);

    // RowHammer test parameters (Aggressive)
    // Scale hammer points based on region size
    // 5000 points was too low for large memory. 
    // New cap: 100,000 points (covers ~50GB at dense 2/MB rate)
    // Scale down for smaller regions.
    // Minimum 10 points to ensure some testing.
    size_t dense_points = (region.size / (1024 * 1024)) * 2; // ~2 points per MB
    size_t hammer_points = std::min((size_t)100000, dense_points);
    if (hammer_points < 10) hammer_points = 10;
    
    // Allow override via parameter if needed
    if (config.parameter > 0) hammer_points = config.parameter;

    const size_t stride_elements = 65536 / 8; // 64KB stride in 64-bit words (typical row structure alignment)
    const size_t hammer_iterations = 200000;

    if (stride_elements * 2 >= count) {
        LOG_WARN("Region too small for double-sided RowHammer test");
        return res;
    }

    // Fill memory with solid pattern (all ones - most susceptible to RowHammer)
    generate_pattern_uniform(ptr, count, ~0ULL, true);
    sfence();
    
    // Flush to RAM before initial verification
    simd::flush_cache_region(ptr, region.size);
    
    if (!region.is_large_pages) {
        LOG_WARN("RowHammer test effectiveness is significantly reduced without Large Pages (2MB).");
        LOG_WARN("Try running with Administrator privileges or enable 'Lock Pages in Memory'.");
    }

    // Verify initial write before hammering
    std::vector<uint64_t> initial_errors_vec;
    simd::verify_uniform(ptr, count, ~0ULL, initial_errors_vec);
    size_t initial_errors = initial_errors_vec.size();
    if (initial_errors > 0) {
        LOG_ERROR("Initial pattern verification failed - memory may be unstable");
        res.hard_errors += initial_errors;
        return res;
    }

    // Perform hammering on random address triplets (double-sided hammering)
    // FIXED: Proper RowHammer requires TOGGLING aggressor rows (0->1->0->1...)
    // Just reading repeatedly doesn't induce bit flips effectively
    for (size_t i = 0; i < hammer_points && !ctx.shouldStop(); ++i) {
        // Double-sided hammering: hammer rows above and below a target row
        // We pick idxA as the "bottom" row
        size_t idxA = dist(rng) % (count - 2 * stride_elements);
        size_t idxB = idxA + stride_elements;     // Target row (not hammered)
        size_t idxC = idxA + 2 * stride_elements; // "Top" row
        
        // Ensure we don't go out of bounds
        if (idxC >= count) continue;

        // Hammer the two aggressor rows repeatedly to stress the victim row (idxB)
        // Use toggling pattern: write 0, flush, write 1, flush, repeat
        // This creates the rapid charge/discharge that induces bit flips
        volatile uint64_t* vptr = reinterpret_cast<volatile uint64_t*>(ptr);
        bool toggle_state = false;
        
        for (size_t k = 0; k < hammer_iterations && !ctx.shouldStop(); ++k) {
            uint64_t pattern = toggle_state ? 0ULL : ~0ULL;
            
            // Write to both aggressor rows
            vptr[idxA] = pattern;
            vptr[idxC] = pattern;
            
            // Memory fence to ensure writes are ordered
            simd::memory_fence();
            
            // Flush to force DRAM access (by passing volatile* to non-volatile param)
            simd::flush_cache_line((void*)&vptr[idxA]);
            simd::flush_cache_line((void*)&vptr[idxC]);
            
            // Toggle for next iteration
            toggle_state = !toggle_state;
        }
        
        // Restore aggressor rows to all-ones to match victim row pattern for verification
        vptr[idxA] = ~0ULL;
        vptr[idxC] = ~0ULL;
        simd::sfence();
    }
    
    // Flush entire region before verification to ensure we read from RAM
    simd::flush_cache_region(ptr, region.size);
    
    // Verify memory still contains the pattern
    size_t block = 256 * 1024;
    for (size_t i = 0; i < count; i += block) {
        if (ctx.shouldStop()) break;
        size_t n = std::min(block, count - i);
        
        TestEngine::verifyAndReport(ptr + i, n, i, 0, ~0ULL, 0, res, ctx, "RowHammer", stop);
    }
    
    res.bytes_tested = region.size;
    return res;
}

TestResult TestEngine::runMirrorMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    bool use_nt = true;
    std::vector<uint64_t> errors;
    errors.reserve(128);
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
        sfence();
        
        // Flush cache before verification for true RAM testing
        simd::flush_cache_region(ptr, region.size);

        errors.clear();
        verify_pattern_xor(ptr, count, 0, config.pattern_param0, config.pattern_param1, errors);
        size_t found = errors.size();
        if (found > 0) {
            for (size_t k = 0; k < found; ++k) {
                uint64_t idx = errors[k];
                uint64_t expect = config.pattern_param0 ^ (idx * config.pattern_param1);
                
                // Re-read check using safe read
                uint64_t actual = simd::safe_read_u64(&ptr[idx]);
                
                if (actual != expect) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove (Init - Hard)", (uint64_t)(idx * 8), expect, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove (Init - Soft)", (uint64_t)(idx * 8), expect, actual);
                }
            }
            
            if (stop && res.total_errors() > 0) {
                ctx.requestStop();
                break;
            }
        }

        invert_array(ptr, count, use_nt);
        sfence();
        
        // Flush cache before verification
        simd::flush_cache_region(ptr, region.size);

        // So inverted value = ~(param0 ^ (idx * param1))
        // We need to verify each location individually since verify_pattern_xor can't express this
        // FIXED: Removed incorrect 'found < 128' check that limited verification after many phase 1 errors
        size_t found_inv = 0;
        for (size_t i = 0; i < count; ++i) {
            uint64_t expect = ~(config.pattern_param0 ^ (i * config.pattern_param1));
            if (ptr[i] != expect) {
                errors.push_back(i);
                found_inv++;
            }
        }
        found = found_inv;  // Update found for error reporting below
        
        if (found > 0) {
            for (size_t k = 0; k < found; ++k) {
                uint64_t idx = errors[k];
                uint64_t expect = ~(config.pattern_param0 ^ (idx * config.pattern_param1));
                
                // Re-read check using safe read
                uint64_t actual = simd::safe_read_u64(&ptr[idx]);

                if (actual != expect) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove (Inv - Hard)", (uint64_t)(idx * 8), expect, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove (Inv - Soft)", (uint64_t)(idx * 8), expect, actual);
                }
            }

            if (stop && res.total_errors() > 0) {
                ctx.requestStop();
                break;
            }
        }
    }

    res.bytes_tested = region.size * 2 * repeats;
    return res;
}

TestResult TestEngine::runMirrorMove128(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        // Use SIMD-optimized pattern generation for better performance
        // Write alternating pattern_param0, pattern_param1
        for (size_t i = 0; i + 1 < count; i += 2) {
            ptr[i] = config.pattern_param0;
            ptr[i+1] = config.pattern_param1;
        }
        sfence();
        
        // CRITICAL: Flush entire region from cache before verification
        // This ensures we read from DRAM, not CPU cache
        simd::flush_cache_region(ptr, region.size);

        for (size_t i = 0; i + 1 < count; i += 2) {
            if (ctx.shouldStop()) break;
            
            // Low word check
            if (ptr[i] != config.pattern_param0) {
                // Re-read check using safe read
                uint64_t actual = simd::safe_read_u64(&ptr[i]);
                
                if (actual != config.pattern_param0) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (L - Hard)", (uint64_t)(i * 8), config.pattern_param0, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (L - Soft)", (uint64_t)(i * 8), config.pattern_param0, actual);
                }

                if (stop && res.total_errors() > 0) {
                    ctx.requestStop();
                    break;
                }
            }
            
            // High word check
            if (ptr[i+1] != config.pattern_param1) {
                // Re-read check using safe read
                uint64_t actual = simd::safe_read_u64(&ptr[i+1]);

                if (actual != config.pattern_param1) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (H - Hard)", (uint64_t)((i+1) * 8), config.pattern_param1, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (H - Soft)", (uint64_t)((i+1) * 8), config.pattern_param1, actual);
                }

                if (stop && res.total_errors() > 0) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        // Handle odd tail word if region size not divisible by 16 bytes
        if (count % 2 == 1) {
            size_t last = count - 1;
            if (ptr[last] != config.pattern_param0) {
                // Re-read check using safe read
                uint64_t actual = simd::safe_read_u64(&ptr[last]);

                if (actual != config.pattern_param0) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (Tail - Hard)", (uint64_t)(last * 8), config.pattern_param0, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("MirrorMove128 (Tail - Soft)", (uint64_t)(last * 8), config.pattern_param0, actual);
                }

                if (stop) ctx.requestStop();
            }
        }
    }

    res.bytes_tested = region.size * repeats;
    return res;
}

TestResult TestEngine::runRefreshStable(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    (void)stop;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    generate_pattern_uniform(ptr, count, config.pattern_param0, true);
    sfence();
    
    // CRITICAL: Flush cache BEFORE the delay to ensure data is in DRAM during refresh test
    // If data stays in CPU cache, it's not a valid retention test
    simd::flush_cache_region(ptr, region.size);
    simd::memory_fence();

    std::this_thread::sleep_for(std::chrono::milliseconds(config.parameter > 0 ? config.parameter : 100));
    
    // Flush again before verification to ensure we read from DRAM
    simd::flush_cache_region(ptr, region.size);

    std::vector<uint64_t> errors;
    errors.reserve(128);
    simd::verify_uniform(ptr, count, config.pattern_param0, errors);
    size_t found = errors.size();
    if (found > 0) {
        for (size_t k = 0; k < found; ++k) {
            uint64_t idx = errors[k];
            
            // Re-read check
            simd::flush_cache_line((void*)&ptr[idx]);
            simd::memory_fence();
            uint64_t actual = simd::safe_read_u64(&ptr[idx]);
            
            if (actual != config.pattern_param0) {
                res.hard_errors++;
                LOG_ERROR_DETAIL("RefreshStable (Hard)", (uint64_t)(idx * 8), config.pattern_param0, actual);
            } else {
                res.soft_errors++;
                LOG_ERROR_DETAIL("RefreshStable (Soft)", (uint64_t)(idx * 8), config.pattern_param0, actual);
            }
        }
    }

    res.bytes_tested = region.size;
    return res;
}

TestResult TestEngine::runWalkingBit(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop, bool invert) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // Test each bit position
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        // If invert=false (WalkingOnes): pattern = 1 << bit
        // If invert=true (WalkingZeros): pattern = ~(1 << bit)
        uint64_t pattern = 1ULL << bit;
        if (invert) pattern = ~pattern;
        
        simd::generate_pattern_uniform(ptr, count, pattern, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        std::vector<uint64_t> error_indices;
        error_indices.reserve(128);
        size_t block = 256 * 1024;
        
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            error_indices.clear();
            simd::verify_uniform(ptr + i, n, pattern, error_indices);
            
            size_t found = error_indices.size();
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    uint64_t offset = i + error_indices[k];
                    // Re-read check
                    simd::flush_cache_line((void*)&ptr[offset]);
                    simd::memory_fence();
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    
                    const char* name = invert ? "WalkingZeros" : "WalkingOnes";
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL((std::string(name) + " (Hard)").c_str(), (uint64_t)(offset * 8), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL((std::string(name) + " (Soft)").c_str(), (uint64_t)(offset * 8), pattern, actual);
                    }
                }
                
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }

    res.bytes_tested = region.size * 64;
    return res;
}

TestResult TestEngine::runWalkingOnes(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, false);
}

TestResult TestEngine::runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    return runWalkingBit(ctx, region, config, stop, true);
}

// 64-bit LFSR with maximal period polynomial: x^64 + x^63 + x^61 + x^60 + 1
// Period: 2^64 - 1, ensuring no pattern repetition for any practical memory size
static uint64_t lfsr_next(uint64_t val) {
    uint64_t bit = ((val >> 63) ^ (val >> 62) ^ (val >> 60) ^ (val >> 59)) & 1;
    return (val << 1) | bit;
}

TestResult TestEngine::runLFSRPattern(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // Use full 64-bit seed for maximal LFSR period
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0xACE1ACE2DEADBEEFULL;
    uint64_t seed = initial_seed;

    // Generate pattern using 64-bit LFSR
    for (size_t i = 0; i < count; ++i) {
        if (ctx.shouldStop()) break;
        ptr[i] = seed;
        seed = lfsr_next(seed);
    }
    sfence();
    
    // Flush cache for true RAM testing
    simd::flush_cache_region(ptr, region.size);

    // Verify - reset seed and check
    seed = initial_seed;

    for (size_t i = 0; i < count; i += 512) {
        if (ctx.shouldStop()) break;
        size_t n = std::min((size_t)512, count - i);

        // Store expected values BEFORE checking so we can log correct values
        uint64_t expected_values[512];
        uint64_t block_seed = seed;
        for (size_t j = 0; j < n; ++j) {
            expected_values[j] = block_seed;
            block_seed = lfsr_next(block_seed);
        }

        size_t found = 0;
        uint64_t error_indices[128];
        for (size_t j = 0; j < n && found < 128; ++j) {
            if (ptr[i + j] != expected_values[j]) {
                error_indices[found++] = j;
            }
        }

        if (found > 0) {
            for (size_t k = 0; k < found; ++k) {
                size_t idx = error_indices[k];
                // Re-read check for LFSR
                uint64_t actual = simd::safe_read_u64(&ptr[i + idx]);
                
                if (actual != expected_values[idx]) {
                     res.hard_errors++;
                     LOG_ERROR_DETAIL("LFSR (Hard)", (uint64_t)((i + idx) * 8), expected_values[idx], actual);
                } else {
                     res.soft_errors++;
                     LOG_ERROR_DETAIL("LFSR (Soft)", (uint64_t)((i + idx) * 8), expected_values[idx], actual);
                }
            }
            if (stop) {
                ctx.requestStop();
                break;
            }
        }

        // Advance seed for next block
        seed = block_seed;
    }

    res.bytes_tested = region.size;
    return res;
}

// Classic Moving Inversion test (March test algorithm)
// 1. Fill memory with pattern
// 2. Verify pattern
// 3. Invert memory
// 4. Verify inverted pattern
// This stresses RAM by testing both 0->1 and 1->0 transitions at each bit position
TestResult TestEngine::runMovingInversion(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    uint64_t pattern = config.pattern_param0 ? config.pattern_param0 : 0xAAAAAAAAAAAAAAAAULL;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop(); ++r) {
        // Phase 1: Fill with pattern
        generate_pattern_uniform(ptr, count, pattern, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 2: Verify pattern (forward march)
        std::vector<uint64_t> error_indices;
        error_indices.reserve(128);
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            error_indices.clear();
            simd::verify_uniform(ptr + i, n, pattern, error_indices);
            size_t found = error_indices.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    simd::flush_cache_line((void*)&ptr[i + error_indices[k]]);
                    simd::memory_fence();
                    uint64_t actual = simd::safe_read_u64(&ptr[i + error_indices[k]]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Fwd - Hard)", (uint64_t)((i + error_indices[k]) * 8), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Fwd - Soft)", (uint64_t)((i + error_indices[k]) * 8), pattern, actual);
                    }
                }
                
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        if (ctx.shouldStop()) break;
        
        // Phase 3: Invert memory
        invert_array(ptr, count, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        uint64_t inverted = ~pattern;
        
        // Phase 4: Verify inverted pattern (backward march for better coverage)
        for (size_t i = count; i > 0 && !ctx.shouldStop(); ) {
            size_t chunk_end = i;
            size_t chunk_start = (i > block) ? (i - block) : 0;
            size_t n = chunk_end - chunk_start;
            i = chunk_start;
            
            error_indices.clear();
            simd::verify_uniform(ptr + chunk_start, n, inverted, error_indices);
            size_t found = error_indices.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    simd::flush_cache_line((void*)&ptr[chunk_start + error_indices[k]]);
                    simd::memory_fence();
                    uint64_t actual = simd::safe_read_u64(&ptr[chunk_start + error_indices[k]]);
                    if (actual != inverted) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Bwd - Hard)", (uint64_t)((chunk_start + error_indices[k]) * 8), inverted, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovingInv (Bwd - Soft)", (uint64_t)((chunk_start + error_indices[k]) * 8), inverted, actual);
                    }
                }
                // All errors have been individually logged above
                
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        // Alternate pattern for next iteration
        pattern = ~pattern;
    }
    
    res.bytes_tested = region.size * 2 * repeats;
    return res;
}

TestResult TestEngine::runMovingInversionWalking(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    // Default to 1 iteration per bit if not specified
    // But Memtest86+ does "iterations" per pass?
    // We'll just do 1 pass per bit.
    
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        uint64_t pattern = 1ULL << bit;
        
        // Inline Moving Inversion Logic for this pattern
        // Phase 1: Fill with pattern
        simd::generate_pattern_uniform(ptr, count, pattern, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 2: Verify pattern (forward march)
        std::vector<uint64_t> error_indices;
        error_indices.reserve(128);
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            error_indices.clear();
            simd::verify_uniform(ptr + i, n, pattern, error_indices);
            size_t found = error_indices.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    simd::flush_cache_line((void*)&ptr[i + error_indices[k]]);
                    simd::memory_fence();
                    uint64_t actual = simd::safe_read_u64(&ptr[i + error_indices[k]]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Fwd - Hard)", (uint64_t)((i + error_indices[k]) * 8), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Fwd - Soft)", (uint64_t)((i + error_indices[k]) * 8), pattern, actual);
                    }
                }
                
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        if (ctx.shouldStop()) break;
        
        // Phase 3: Invert memory
        simd::invert_array(ptr, count, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        uint64_t inverted = ~pattern;
        
        // Phase 4: Verify inverted pattern (backward march)
        for (size_t i = count; i > 0 && !ctx.shouldStop(); ) {
            size_t chunk_end = i;
            size_t chunk_start = (i > block) ? (i - block) : 0;
            size_t n = chunk_end - chunk_start;
            i = chunk_start;
            
            error_indices.clear();
            simd::verify_uniform(ptr + chunk_start, n, inverted, error_indices);
            size_t found = error_indices.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    simd::flush_cache_line((void*)&ptr[chunk_start + error_indices[k]]);
                    simd::memory_fence();
                    uint64_t actual = simd::safe_read_u64(&ptr[chunk_start + error_indices[k]]);
                    if (actual != inverted) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Bwd - Hard)", (uint64_t)((chunk_start + error_indices[k]) * 8), inverted, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvWalk (Bwd - Soft)", (uint64_t)((chunk_start + error_indices[k]) * 8), inverted, actual);
                    }
                }
                
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }
    
    res.bytes_tested = region.size * 2 * 64; // 2 passes (fwd/bwd) * 64 bits
    return res;
}

TestResult TestEngine::runTest(TestContext& ctx, const std::string& name, const MemoryRegion& region,
                               const TestConfig& config, bool stop) {
    if (name == "SimpleTest") return runSimpleTest(ctx, region, config, stop);
    if (name == "MirrorMove") return runMirrorMove(ctx, region, config, stop);
    if (name == "MirrorMove128") return runMirrorMove128(ctx, region, config, stop);
    if (name == "RefreshStable") return runRefreshStable(ctx, region, config, stop);
    if (name == "WalkingOnes") return runWalkingOnes(ctx, region, config, stop);
    if (name == "WalkingZeros") return runWalkingZeros(ctx, region, config, stop);
    if (name == "LFSRPattern") return runLFSRPattern(ctx, region, config, stop);
    if (name == "MovingInversion") return runMovingInversion(ctx, region, config, stop);
    if (name == "MovingInversionLFSR") return runMovingInversionLFSR(ctx, region, config, stop);
    if (name == "MovingInversionWalking") return runMovingInversionWalking(ctx, region, config, stop);
    if (name == "BlockMove") return runBlockMove(ctx, region, config, stop);
    if (name == "RowHammer") return runRowHammerTest(ctx, region, config, stop);
    if (name == "RandomAccess") return runRandomAccess(ctx, region, config, stop);
    
    // Warn on invalid test name (GPT report item: invalid names silently ignored)
    LOG_WARN("Unknown test function name: '%s' - skipping", name.c_str());
    return {};
}

TestResult TestEngine::runMovingInversionLFSR(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint32_t* ptr = reinterpret_cast<uint32_t*>(region.base);
    size_t count = region.size / 4;
    
    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0x12345678;
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;
    bool early_stop = false;
    
    for (uint32_t r = 0; r < repeats && !ctx.shouldStop() && !early_stop; ++r) {
        // Phase 1: Fill with LFSR pattern
        uint64_t seed = initial_seed;
        for (size_t i = 0; i < count; ++i) {
            if (ctx.shouldStop()) break;
            ptr[i] = static_cast<uint32_t>(seed);
            seed = lfsr_next(seed);
        }
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 2: Verify pattern
        seed = initial_seed;
        for (size_t i = 0; i < count && !ctx.shouldStop() && !early_stop; i += 1024) {
            size_t n = std::min((size_t)1024, count - i);
            
            uint32_t expected[1024];
            for (size_t j = 0; j < n; ++j) {
                expected[j] = static_cast<uint32_t>(seed);
                seed = lfsr_next(seed);
            }
            
            for (size_t j = 0; j < n; ++j) {
                if (ptr[i+j] != expected[j]) {
                    // Re-read
                    uint32_t actual = simd::safe_read_u32(&ptr[i+j]);
                    if (actual != expected[j]) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Hard)", (uint64_t)((i+j)*4), expected[j], actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Fwd - Soft)", (uint64_t)((i+j)*4), expected[j], actual);
                    }
                    if (stop && res.total_errors() > 0) {
                        ctx.requestStop();
                        early_stop = true;
                        break;
                    }
                }
            }
        }
        
        if (ctx.shouldStop() || early_stop) break;
        
        // Phase 3: Invert
        simd::invert_array(reinterpret_cast<uint64_t*>(ptr), region.size / 8, true);
        sfence();
        simd::flush_cache_region(ptr, region.size);
        
        // Phase 4: Verify Inverted
        seed = initial_seed;
        for (size_t i = 0; i < count && !ctx.shouldStop() && !early_stop; i += 1024) {
            size_t n = std::min((size_t)1024, count - i);
            
            uint32_t expected[1024];
            for (size_t j = 0; j < n; ++j) {
                expected[j] = ~static_cast<uint32_t>(seed); // Expect inverted
                seed = lfsr_next(seed);
            }
            
            for (size_t j = 0; j < n; ++j) {
                if (ptr[i+j] != expected[j]) {
                    uint32_t actual = simd::safe_read_u32(&ptr[i+j]);
                    if (actual != expected[j]) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Inv - Hard)", (uint64_t)((i+j)*4), expected[j], actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("MovInvLFSR (Inv - Soft)", (uint64_t)((i+j)*4), expected[j], actual);
                    }
                    if (stop && res.total_errors() > 0) {
                        ctx.requestStop();
                        early_stop = true;
                        break;
                    }
                }
            }
        }
    }
    res.bytes_tested = region.size * 2 * repeats;
    return res;
}


// Xoshiro256** PRNG (fast and high quality)
static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

struct Xoshiro256SS {
    uint64_t s[4];

    Xoshiro256SS(uint64_t seed) {
        // SplitMix64 initialization
        uint64_t z = (seed + 0x9E3779B97F4A7C15ULL);
        for(int i=0; i<4; ++i) {
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            s[i] = z ^ (z >> 31);
            z += 0x9E3779B97F4A7C15ULL;
        }
    }

    uint64_t next() {
        const uint64_t result = rotl(s[1] * 5, 7) * 9;
        const uint64_t t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;
        s[3] = rotl(s[3], 45);

        return result;
    }
};

TestResult TestEngine::runRandomAccess(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8; // Number of uint64_t elements

    if (count == 0) return res;

    // Phase 1: Fill memory with linear pattern (address = value)
    // Use increment pattern: 0, 1, 2, ...
    simd::generate_pattern_increment(ptr, count, 0, true);
    sfence();
    simd::flush_cache_region(ptr, region.size);

    // Phase 2: Verify initial pattern before random access
    // This ensures we start from a known-good state
    size_t verify_block = 256 * 1024;
    for (size_t i = 0; i < count && !ctx.shouldStop(); i += verify_block) {
        size_t n = (std::min)(verify_block, count - i);
        for (size_t j = 0; j < n; ++j) {
            uint64_t expected = i + j;
            uint64_t actual = ptr[i + j];
            if (actual != expected) {
                // Initial pattern verification failed - memory unstable
                simd::flush_cache_line((void*)&ptr[i + j]);
                simd::memory_fence();
                uint64_t reread = ptr[i + j];
                if (reread != expected) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Init - Hard)", (i + j) * 8, expected, reread);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Init - Soft)", (i + j) * 8, expected, actual);
                }
                if (stop) {
                    ctx.requestStop();
                    res.bytes_tested = (i + j) * 8;
                    return res;
                }
            }
        }
    }

    // Determines duration/intensity
    // Config parameter is usually "Iterations" or "Pass count"
    // If Parameter = 0, default to 1 pass equivalent (count iterations)
    uint64_t iterations = count; 
    if (config.parameter > 0) {
        // If parameter is small (e.g. 1-100), treat as pass count
        if (config.parameter <= 100) iterations = count * config.parameter;
        else iterations = config.parameter; // Treat as explicit count
    }

    uint64_t seed = 0x1234567890ABCDEFULL + (uint64_t)(uintptr_t)ptr; // Unique seed per thread/region
    Xoshiro256SS rng(seed);

    // Bulk Random Access Loop
    // We process in chunks to check for stop flag
    const size_t CHUNK_SIZE = 10000;
    
    for (size_t i = 0; i < iterations; ) {
        if (ctx.shouldStop()) break;
        
        size_t batch = (std::min)(CHUNK_SIZE, (size_t)(iterations - i));
        
        // Random Read-Modify-Write with verification at each step
        for (size_t k = 0; k < batch; ++k) {
            // Generate random index in range [0, count) using fast range reduction
            uint64_t idx;
#if defined(__SIZEOF_INT128__)
            unsigned __int128 r = rng.next();
            idx = (uint64_t)((r * count) >> 64);
#elif defined(_MSC_VER) && defined(_M_X64)
            uint64_t r = rng.next();
            uint64_t high;
            _umul128(r, count, &high);
            idx = high;
#else
            idx = rng.next() % count; // Fallback - has modulo bias but safe
#endif
            
            // Step 1: Verify location contains expected pattern (address = value)
            // This detects read-path errors and any corruption since initialization
            uint64_t expected = idx;
            uint64_t actual = ptr[idx];
            
            if (actual != expected) {
                // Read-path error detected - classify with re-read
                simd::flush_cache_line((void*)&ptr[idx]);
                simd::memory_fence();
                uint64_t reread_val = ptr[idx];
                
                if (reread_val != expected) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Read - Hard)", idx * 8, expected, reread_val);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (Read - Soft)", idx * 8, expected, actual);
                }
                // Continue to write test even after read error - don't skip!
            }
            
            // Step 2: Write inverted pattern (regardless of read result)
            // This tests the write path
            uint64_t inverted = ~idx;
            ptr[idx] = inverted;
            simd::sfence();
            
            // Step 3: Verify inverted pattern was written correctly
            // This tests write-to-read coherence
            actual = ptr[idx];
            if (actual != inverted) {
                simd::flush_cache_line((void*)&ptr[idx]);
                simd::memory_fence();
                uint64_t reread_val = ptr[idx];
                
                if (reread_val != inverted) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (WriteCheck - Hard)", idx * 8, inverted, reread_val);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("RandomAccess (WriteCheck - Soft)", idx * 8, inverted, actual);
                }
            }
            
            // Step 4: Restore original pattern for next iteration
            ptr[idx] = idx;
            simd::flush_cache_line((void*)&ptr[idx]);
            simd::sfence();
            
            if (stop && res.total_errors() > 0) {
                ctx.requestStop();
                break;
            }
        }
        i += batch;
    }

    res.bytes_tested = iterations * 8 * 4; // Read (verify), Read (check), Write, Read (check), Write (approx 4 ops per iteration)
    return res;
}

TestResult TestEngine::runBlockMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    
    if (count < 2) return res;
    
    size_t half_count = count / 2;
    uint64_t* src = ptr;
    uint64_t* dst = ptr + half_count;
    
    uint64_t pattern = config.pattern_param0 ? config.pattern_param0 : 0x5555AAAA5555AAAAULL;
    
    // Fill Src
    simd::generate_pattern_uniform(src, half_count, pattern, true);
    sfence();
    
    // Move Src -> Dst using std::memcpy (optimized)
    // Note: overlapping regions not an issue here as we split perfectly, but memmove safer if we ever change logic
    std::memmove(dst, src, half_count * 8);
    sfence();
    simd::flush_cache_region(ptr, region.size);
    
    // Verify Dst
    std::vector<uint64_t> error_indices;
    error_indices.reserve(128);
    size_t block = 256 * 1024;
    for (size_t i = 0; i < half_count && !ctx.shouldStop(); i += block) {
        size_t n = std::min(block, half_count - i);
        error_indices.clear();
        simd::verify_uniform(dst + i, n, pattern, error_indices);
        size_t found = error_indices.size();
        
        if (found > 0) {
            for (size_t k = 0; k < found; ++k) {
                uint64_t offset = half_count + i + error_indices[k];
                simd::flush_cache_line((void*)&ptr[offset]);
                simd::memory_fence();
                uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                if (actual != pattern) {
                    res.hard_errors++;
                    LOG_ERROR_DETAIL("BlockMove (Dst - Hard)", (uint64_t)(offset * 8), pattern, actual);
                } else {
                    res.soft_errors++;
                    LOG_ERROR_DETAIL("BlockMove (Dst - Soft)", (uint64_t)(offset * 8), pattern, actual);
                }
            }
            // All errors have been individually logged above
            if (stop) {
                ctx.requestStop();
                break;
            }
        }
    }
    
    // Verify Src (should still be intact)
    if (!ctx.shouldStop()) {
        for (size_t i = 0; i < half_count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, half_count - i);
            error_indices.clear();
            simd::verify_uniform(src + i, n, pattern, error_indices);
            size_t found = error_indices.size();
            
            if (found > 0) {
                for (size_t k = 0; k < found; ++k) {
                    uint64_t offset = i + error_indices[k];
                    uint64_t actual = simd::safe_read_u64(&ptr[offset]);
                    if (actual != pattern) {
                        res.hard_errors++;
                        LOG_ERROR_DETAIL("BlockMove (Src - Hard)", (uint64_t)(offset * 8), pattern, actual);
                    } else {
                        res.soft_errors++;
                        LOG_ERROR_DETAIL("BlockMove (Src - Soft)", (uint64_t)(offset * 8), pattern, actual);
                    }
                }
                // All errors have been individually logged above
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }

    res.bytes_tested = region.size; // Effectively tested whole region (half src, half dst)
    return res;
}

TestResult TestEngine::runRegionWork(TestContext& ctx, const MemoryRegion& region, const TestConfig& test_config,
                                     bool halt_on_error) {
    size_t block_size = (size_t)test_config.block_size_mb * 1024 * 1024;

    if (block_size == 0 || block_size >= region.size) {
        return runTest(ctx, test_config.function, region, test_config, halt_on_error);
    }

    TestResult total = {};
    size_t blocks = (region.size + block_size - 1) / block_size;
    for (size_t i = 0; i < blocks; ++i) {
        if (ctx.shouldStop()) break;
        size_t offset = i * block_size;
        size_t len = std::min(block_size, region.size - offset);

        MemoryRegion sub = region;
        sub.base += offset;
        sub.size = len;

        TestResult r = runTest(ctx, test_config.function, sub, test_config, halt_on_error);
        total.merge(r);
        if (total.total_errors() > 0 && halt_on_error) {
            ctx.requestStop();
            break;
        }
    }
    return total;
}

RunResult TestEngine::runTests(const Config& config) {
    RunResult result = {};

    MemoryRegion region;
    uint64_t needed_bytes = (uint64_t)config.memory_window_mb * 1024 * 1024;

    LOG_INFO("Allocating %u MB...", config.memory_window_mb);
    bool try_large = config.use_large_pages;
    bool try_lock = config.use_locked_memory;

    auto guard = Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
    if (!guard.valid()) {
        LOG_ERROR("Found no suitable memory allocation method. Aborting.");
        return result;
    }

    region.base = guard.base();
    region.size = guard.size();
    region.is_large_pages = guard.is_large_pages();
    region.is_locked = guard.is_locked();

    // User requested explicit console output for locking status
    {
        std::lock_guard<std::mutex> lock(Logger::get().getConsoleMutex());
        std::cout << "\n[Memory Allocation]\n";
        std::cout << "  Size:       " << (region.size / 1024 / 1024) << " MB\n";
        std::cout << "  Locked:     " << (region.is_locked ? "Yes" : "No") << "\n";
        std::cout << "  LargePages: " << (region.is_large_pages ? "Yes" : "No") << "\n";
        std::cout << "  Method:     " << (region.is_large_pages ? "Large Pages" : (region.is_locked ? "VirtualLock/Mlock" : "Standard Malloc (Swappable)")) << "\n" << std::endl;
    }

    std::string seq_str = config.preset.test_sequence.empty() ? "0" : config.preset.test_sequence;
    std::vector<uint32_t> seq = parseTestSequence(seq_str);

    result = executeSuite(config, region, seq, config.preset.test_configs);

    // guard destructor will free memory
    return result;
}

RunResult TestEngine::executeSuite(const Config& config, const MemoryRegion& region,
                                   const std::vector<uint32_t>& seq,
                                   const std::map<uint32_t, TestConfig>& configs) {
    RunResult result = {};
    TestContext ctx;
    
    // Set up global stop signal for shutdown handler
    g_current_context.store(&ctx, std::memory_order_release);

    uint32_t threads = config.cores > 0 ? config.cores : 1;
    std::vector<std::thread> workers;

    auto start = std::chrono::high_resolution_clock::now();

    std::thread monitor([&]() {
        std::string last_line;
        char buffer[256];
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        COORD cursorPos;
#endif

        auto last_update = std::chrono::steady_clock::now();

        while (!ctx.shouldStop()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (ctx.shouldStop()) break;

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() < 1000) {
                continue;
            }
            last_update = now;

            // Fetch status outside of lock to avoid deadlock
            uint64_t h_errs = ctx.total_hard_errors.load(std::memory_order_relaxed);
            uint64_t s_errs = ctx.total_soft_errors.load(std::memory_order_relaxed);
            uint64_t u_errs = ctx.total_unverified_errors.load(std::memory_order_relaxed);
            uint64_t bytes = ctx.total_bytes.load(std::memory_order_relaxed);
            double gb = bytes / (1024.0 * 1024.0 * 1024.0);

            std::string name = ctx.getActiveTestName();
            uint32_t cycle = ctx.current_cycle.load(std::memory_order_relaxed);
            uint32_t test_idx = ctx.current_test_idx.load(std::memory_order_relaxed);

            auto elapsed_duration = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            uint32_t hours = static_cast<uint32_t>(elapsed_duration / 3600);
            uint32_t minutes = static_cast<uint32_t>((elapsed_duration % 3600) / 60);
            uint32_t seconds = static_cast<uint32_t>(elapsed_duration % 60);

            int len = snprintf(buffer, sizeof(buffer),
                "[Cycle %u/%s] Test %u/%zu (%s): %.2f GB | Err: %llu | %02u:%02u:%02u",
                cycle,
                config.cycles ? std::to_string(config.cycles).c_str() : "inf",
                test_idx,
                seq.size(),
                name.c_str(),
                gb,
                (unsigned long long)(h_errs + s_errs + u_errs),
                hours, minutes, seconds);

#ifdef _WIN32
            if (len > 0 && last_line != buffer) {
                // Only lock for the actual console I/O
                std::lock_guard<std::mutex> lock(Logger::get().getMutex());
                GetConsoleScreenBufferInfo(hOut, &csbi);
                int width = csbi.dwSize.X;
                
                // Prevent line wrapping by limiting to width - 1
                if (width > 1) {
                    cursorPos = csbi.dwCursorPosition;
                    cursorPos.X = 0;
                    SetConsoleCursorPosition(hOut, cursorPos);

                    int max_len = width - 1;
                    int actual_len = std::min(len, max_len);
                    
                    DWORD written;
                    WriteConsoleA(hOut, buffer, static_cast<DWORD>(actual_len), &written, nullptr);

                    // Clear remaining part of line up to width - 1
                    int cellsToClear = max_len - actual_len;
                    if (cellsToClear > 0) {
                        std::string spaces(cellsToClear, ' ');
                        WriteConsoleA(hOut, spaces.c_str(), static_cast<DWORD>(cellsToClear), &written, nullptr);
                    }
                }
                last_line = buffer;
            }
#else
            if (len > 0 && last_line != buffer) {
                // Only lock for the actual console I/O
                std::lock_guard<std::mutex> lock(Logger::get().getMutex());
                // Simple carriage return + clear line (ANSI)
                printf("\r\033[K%s", buffer);
                fflush(stdout);
                last_line = buffer;
            }
#endif
        }

#ifdef _WIN32
        {
             std::lock_guard<std::mutex> lock(Logger::get().getMutex());
             GetConsoleScreenBufferInfo(hOut, &csbi);
             cursorPos = csbi.dwCursorPosition;
             cursorPos.X = 0;
             SetConsoleCursorPosition(hOut, cursorPos);
             printf("\n");
        }
#else
         printf("\n");
#endif
    });

    for (uint32_t t = 0; t < threads; ++t) {
        workers.emplace_back([&, t]() {
            Platform::setThreadAffinity(t, threads);

            size_t chunk = region.size / threads;
            chunk = (chunk / 4096) * 4096;
            size_t offset = t * chunk;
            size_t size = (t == threads - 1) ? (region.size - offset) : chunk;

            MemoryRegion my_region = region;
            my_region.base += offset;
            my_region.size = size;

            uint32_t cycle = 0;
            while ((config.cycles == 0 || cycle < config.cycles) && !ctx.shouldStop()) {
                if (t == 0) {
                    ctx.current_cycle.store(cycle + 1, std::memory_order_release);
                    LOG_INFO("=== Cycle %u Started ===", cycle + 1);
                }

                uint32_t seq_idx = 0;
                for (uint32_t test_id : seq) {

                    if (ctx.shouldStop()) break;
                    if (configs.count(test_id)) {
                        const TestConfig& tc = configs.at(test_id);
                        if (t == 0) {
                            ctx.setActiveTestName(tc.function);
                            ctx.current_test_idx.store(++seq_idx, std::memory_order_release);
                            LOG_INFO("Test %u: %s Started", seq_idx, tc.function.c_str());
                        } else {
                            // Non-main threads just increment local counter if needed, or rely on main thread
                        }
                        
                        auto test_start_time = std::chrono::high_resolution_clock::now();

                        uint32_t loops = (config.preset.time_percent * tc.time_percent) / 100;
                        if (loops == 0) loops = 1;

                        for (uint32_t L = 0; L < loops; ++L) {
                            if (ctx.shouldStop()) break;
                            TestResult tr = runRegionWork(ctx, my_region, tc, config.halt_on_error);

                            ctx.total_hard_errors.fetch_add(tr.hard_errors, std::memory_order_relaxed);
                            ctx.total_soft_errors.fetch_add(tr.soft_errors, std::memory_order_relaxed);
                            ctx.total_unverified_errors.fetch_add(tr.unverified_errors, std::memory_order_relaxed);
                            ctx.total_bytes.fetch_add(tr.bytes_tested, std::memory_order_relaxed);

                            if (tr.total_errors() > 0 && config.halt_on_error) {
                                ctx.requestStop();
                                break;
                            }
                        }
                        
                        if (t == 0) {
                             auto test_end_time = std::chrono::high_resolution_clock::now();
                             double elapsed = std::chrono::duration<double>(test_end_time - test_start_time).count();
                             LOG_INFO("Test %u: %s Completed in %.2fs", seq_idx, tc.function.c_str(), elapsed);
                        }
                    }
                }
                
                if (t == 0) {
                     LOG_INFO("=== Cycle %u Completed ===", cycle + 1);
                }
                cycle++;
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    ctx.requestStop();
    if (monitor.joinable()) monitor.join();

    auto end = std::chrono::high_resolution_clock::now();
    result.hard_errors = ctx.total_hard_errors.load(std::memory_order_relaxed);
    result.soft_errors = ctx.total_soft_errors.load(std::memory_order_relaxed);
    result.unverified_errors = ctx.total_unverified_errors.load(std::memory_order_relaxed);
    result.duration_seconds = std::chrono::duration<double>(end - start).count();

    // Clear global context pointer before returning
    g_current_context.store(nullptr, std::memory_order_release);

    return result;
}

void TestEngine::requestStop() {
    TestContext* ctx = g_current_context.load(std::memory_order_acquire);
    if (ctx) {
        ctx->requestStop();
    }
}

} // namespace testsmem4u
