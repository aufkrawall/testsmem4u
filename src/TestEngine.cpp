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
        try {
            size_t start = item.find_first_not_of(" \t");
            if (start != std::string::npos) {
                result.push_back(std::stoul(item.substr(start)));
            }
        } catch (...) {
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
    uint64_t error_indices[128];
    size_t max_errors = 128;
    size_t found = 0;

    if (pattern_mode == 0) {
        found = verify_uniform(ptr, count, param0, error_indices, max_errors);
    } else if (pattern_mode == 1) {
        found = verify_pattern_xor(ptr, count, start_idx, param0, param1, error_indices, max_errors);
    } else {
        found = verify_pattern_linear(ptr, count, start_idx, param0, param1, error_indices, max_errors);
    }

    if (found == 0) return 0;

    for (size_t i = 0; i < found; ++i) {
        uint64_t idx = error_indices[i];
        uint64_t expect;
        generatePatternValue(start_idx + idx, pattern_mode, param0, param1, expect);
        
        // CRITICAL: Flush cache line before re-read to ensure we read from RAM, not cache
        // This is essential for accurate soft vs hard error detection
        simd::flush_cache_line((void*)&ptr[idx]);
        simd::lfence(); // Serialize to ensure flush completes before read
        
        uint64_t actual = ptr[idx]; // Re-read from RAM (not cache)

        if (actual != expect) {
            // Hard Error: Re-read from RAM confirmed the mismatch
            LOG_ERROR_DETAIL((test_name + " (Hard)").c_str(), (uint64_t)((start_idx + idx) * 8), expect, actual);
            res.errors++;
        } else {
            // Soft/Transient Error: Initial read failed but RAM now has correct value
            // This indicates a transient bit flip - still a real RAM error
            LOG_ERROR_DETAIL((test_name + " (Soft/Transient)").c_str(), (uint64_t)((start_idx + idx) * 8), expect, actual);
            res.errors++;
        }
        
        if (halt_on_error && res.errors > 0) {
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

    // RowHammer test parameters
    const size_t hammer_points = 100;
    const size_t stride_elements = 1024 * 1024 / 8; // 1MB stride in 64-bit words
    const size_t hammer_iterations = 500000;

    if (stride_elements >= count) {
        LOG_WARN("Region too small for RowHammer test (need at least 1MB)");
        return res;
    }

    // Fill memory with solid pattern (all ones - most susceptible to RowHammer)
    generate_pattern_uniform(ptr, count, ~0ULL, true);
    sfence();
    
    // Flush to RAM before initial verification
    simd::flush_cache_region(ptr, region.size);

    // Verify initial write before hammering
    size_t initial_errors = simd::verify_uniform(ptr, count, ~0ULL, nullptr, 0);
    if (initial_errors > 0) {
        LOG_ERROR("Initial pattern verification failed - memory may be unstable");
        res.errors += initial_errors;
        return res;
    }

    // Perform hammering on random address pairs
    for (size_t i = 0; i < hammer_points && !ctx.shouldStop(); ++i) {
        size_t idxA = dist(rng) % (count - stride_elements);
        size_t idxB = idxA + stride_elements;
        
        // Ensure we don't go out of bounds
        if (idxB >= count) continue;

        // Hammer the two rows repeatedly
        volatile uint64_t* vptr = reinterpret_cast<volatile uint64_t*>(ptr);
        for (size_t k = 0; k < hammer_iterations; ++k) {
            (void)vptr[idxA];
            (void)vptr[idxB];
            simd::flush_cache_line((void*)&vptr[idxA]); // Flush to force DRAM access
            simd::flush_cache_line((void*)&vptr[idxB]);
        }
    }
    
    // Flush entire region before verification to ensure we read from RAM
    simd::flush_cache_region(ptr, region.size);
    
    // Verify memory still contains the pattern
    size_t block = 256 * 1024;
    for (size_t i = 0; i < count; i += block) {
        if (ctx.shouldStop()) break;
        size_t n = std::min(block, count - i);
        size_t errors_in_block = simd::verify_uniform(ptr + i, n, ~0ULL, nullptr, 0);
        if (errors_in_block > 0) {
            // Report the first few errors with details
            uint64_t error_indices[128];
            size_t found = simd::verify_uniform(ptr + i, n, ~0ULL, error_indices, 128);
            for (size_t j = 0; j < found && j < 10; ++j) {  // Log max 10 errors per block
                uint64_t idx = error_indices[j];
                LOG_ERROR_DETAIL("RowHammer", (uint64_t)((i + idx) * 8), ~0ULL, ptr[i + idx]);
            }
            if (found > 10) {
                LOG_ERROR("RowHammer: %zu additional errors suppressed", found - 10);
            }
            res.errors += found;
        }
    }
    
    res.bytes_tested = region.size;
    return res;
}

TestResult TestEngine::runMirrorMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;
    bool use_nt = true;
    uint64_t errors[128];
    uint32_t repeats = config.parameter > 0 ? config.parameter : 1;

    for (uint32_t r = 0; r < repeats; ++r) {
        if (ctx.shouldStop()) break;
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
        sfence();
        
        // Flush cache before verification for true RAM testing
        simd::flush_cache_region(ptr, region.size);

        size_t found = verify_pattern_xor(ptr, count, 0, config.pattern_param0, config.pattern_param1, errors, 128);
        if (found > 0) {
            res.errors += found;
            size_t limit = std::min(found, (size_t)128);
            for (size_t k = 0; k < limit; ++k) {
                uint64_t idx = errors[k];
                uint64_t expect = config.pattern_param0 ^ (idx * config.pattern_param1);
                LOG_ERROR_DETAIL("MirrorMove (Init)", (uint64_t)(idx * 8), expect, ptr[idx]);
            }
            if (stop) {
                ctx.requestStop();
                break;
            }
        }

        invert_array(ptr, count, use_nt);
        sfence();
        
        // Flush cache before verification
        simd::flush_cache_region(ptr, region.size);

        found = verify_pattern_xor(ptr, count, 0, ~config.pattern_param0, config.pattern_param1, errors, 128);
        if (found > 0) {
            res.errors += found;
            size_t limit = std::min(found, (size_t)128);
            for (size_t k = 0; k < limit; ++k) {
                uint64_t idx = errors[k];
                uint64_t expect = ~(config.pattern_param0 ^ (idx * config.pattern_param1));
                LOG_ERROR_DETAIL("MirrorMove (Inv)", (uint64_t)(idx * 8), expect, ptr[idx]);
            }
            if (stop) {
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
        for (size_t i = 0; i + 1 < count; i += 2) {
            ptr[i] = config.pattern_param0;
            ptr[i+1] = config.pattern_param1;
        }
        sfence();
        
        // Flush cache before verification
        simd::flush_cache_region(ptr, region.size);

        for (size_t i = 0; i + 1 < count; i += 2) {
            if (ctx.shouldStop()) break;
            if (ptr[i] != config.pattern_param0) {
                res.errors++;
                LOG_ERROR_DETAIL("MirrorMove128 (L)", (uint64_t)(i * 8), config.pattern_param0, ptr[i]);
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
            if (ptr[i+1] != config.pattern_param1) {
                res.errors++;
                LOG_ERROR_DETAIL("MirrorMove128 (H)", (uint64_t)((i+1) * 8), config.pattern_param1, ptr[i+1]);
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
        
        // Handle odd tail word if region size not divisible by 16 bytes
        if (count % 2 == 1) {
            size_t last = count - 1;
            if (ptr[last] != config.pattern_param0) {
                res.errors++;
                LOG_ERROR_DETAIL("MirrorMove128 (Tail)", (uint64_t)(last * 8), config.pattern_param0, ptr[last]);
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

    std::this_thread::sleep_for(std::chrono::milliseconds(config.parameter > 0 ? config.parameter : 100));
    
    // Flush cache to ensure verification reads from RAM
    simd::flush_cache_region(ptr, region.size);

    uint64_t errors[128];
    size_t found = verify_uniform(ptr, count, config.pattern_param0, errors, 128);
    if (found > 0) {
        res.errors += found;
        size_t limit = std::min(found, (size_t)128);
        for (size_t k = 0; k < limit; ++k) {
            LOG_ERROR_DETAIL("RefreshStable", (uint64_t)(errors[k] * 8), config.pattern_param0, ptr[errors[k]]);
        }
    }

    res.bytes_tested = region.size;
    return res;
}

TestResult TestEngine::runWalkingOnes(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    (void)config;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // SIMD-optimized Walking Ones: Test each bit position across entire memory
    // For each bit position (0-63), write pattern with that bit set, flush, verify
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        uint64_t pattern = 1ULL << bit;
        
        // Fill memory with walking one pattern
        generate_pattern_uniform(ptr, count, pattern, true);
        sfence();
        
        // Flush cache to ensure verification reads from RAM
        simd::flush_cache_region(ptr, region.size);
        
        // Verify in blocks
        uint64_t error_indices[128];
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            size_t found = simd::verify_uniform(ptr + i, n, pattern, error_indices, 128);
            
            if (found > 0) {
                res.errors += found;
                for (size_t k = 0; k < found && k < 10; ++k) {
                    // Flush before re-read for accurate logging
                    simd::flush_cache_line((void*)&ptr[i + error_indices[k]]);
                    simd::lfence();
                    LOG_ERROR_DETAIL("WalkingOnes", (uint64_t)((i + error_indices[k]) * 8), pattern, ptr[i + error_indices[k]]);
                }
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }

    res.bytes_tested = region.size * 64; // Tested each bit position
    return res;
}

TestResult TestEngine::runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    (void)config;
    TestResult res = {};
    uint64_t* ptr = reinterpret_cast<uint64_t*>(region.base);
    size_t count = region.size / 8;

    // SIMD-optimized Walking Zeros: Test each bit position with that bit clear
    // Pattern is all 1s except for one bit position
    for (int bit = 0; bit < 64 && !ctx.shouldStop(); ++bit) {
        uint64_t pattern = ~(1ULL << bit);
        
        // Fill memory with walking zero pattern
        generate_pattern_uniform(ptr, count, pattern, true);
        sfence();
        
        // Flush cache to ensure verification reads from RAM
        simd::flush_cache_region(ptr, region.size);
        
        // Verify in blocks
        uint64_t error_indices[128];
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            size_t found = simd::verify_uniform(ptr + i, n, pattern, error_indices, 128);
            
            if (found > 0) {
                res.errors += found;
                for (size_t k = 0; k < found && k < 10; ++k) {
                    simd::flush_cache_line((void*)&ptr[i + error_indices[k]]);
                    simd::lfence();
                    LOG_ERROR_DETAIL("WalkingZeros", (uint64_t)((i + error_indices[k]) * 8), pattern, ptr[i + error_indices[k]]);
                }
                if (stop) {
                    ctx.requestStop();
                    break;
                }
            }
        }
    }

    res.bytes_tested = region.size * 64; // Tested each bit position
    return res;
}

static uint64_t lfsr_next(uint64_t val) {
    uint64_t bit = (val ^ (val >> 1) ^ (val >> 3) ^ (val >> 4)) & 1;
    return (val >> 1) | (bit << 31);
}

TestResult TestEngine::runLFSRPattern(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res = {};
    uint32_t* ptr = reinterpret_cast<uint32_t*>(region.base);
    size_t count = region.size / 4;

    uint64_t initial_seed = config.pattern_param0 ? config.pattern_param0 : 0x12345678;
    uint64_t seed = initial_seed;

    // Generate pattern
    for (size_t i = 0; i < count; ++i) {
        if (ctx.shouldStop()) break;
        ptr[i] = static_cast<uint32_t>(seed);
        seed = lfsr_next(seed);
    }
    sfence();
    
    // Flush cache for true RAM testing
    simd::flush_cache_region(ptr, region.size);

    // Verify - reset seed and check
    seed = initial_seed;

    for (size_t i = 0; i < count; i += 1024) {
        if (ctx.shouldStop()) break;
        size_t n = std::min((size_t)1024, count - i);

        // Store expected values BEFORE checking so we can log correct values
        uint32_t expected_values[1024];
        uint64_t block_seed = seed;
        for (size_t j = 0; j < n; ++j) {
            expected_values[j] = static_cast<uint32_t>(block_seed);
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
            res.errors += found;
            for (size_t k = 0; k < found; ++k) {
                size_t idx = error_indices[k];
                // BUG FIX: Use pre-computed expected values, not current seed
                LOG_ERROR_DETAIL("LFSR", (uint64_t)((i + idx) * 4), expected_values[idx], ptr[i + idx]);
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
        uint64_t error_indices[128];
        size_t block = 256 * 1024;
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += block) {
            size_t n = std::min(block, count - i);
            size_t found = simd::verify_uniform(ptr + i, n, pattern, error_indices, 128);
            
            if (found > 0) {
                res.errors += found;
                for (size_t k = 0; k < found && k < 10; ++k) {
                    simd::flush_cache_line((void*)&ptr[i + error_indices[k]]);
                    simd::lfence();
                    LOG_ERROR_DETAIL("MovingInv (Fwd)", (uint64_t)((i + error_indices[k]) * 8), pattern, ptr[i + error_indices[k]]);
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
            
            size_t found = simd::verify_uniform(ptr + chunk_start, n, inverted, error_indices, 128);
            
            if (found > 0) {
                res.errors += found;
                for (size_t k = 0; k < found && k < 10; ++k) {
                    simd::flush_cache_line((void*)&ptr[chunk_start + error_indices[k]]);
                    simd::lfence();
                    LOG_ERROR_DETAIL("MovingInv (Bwd)", (uint64_t)((chunk_start + error_indices[k]) * 8), inverted, ptr[chunk_start + error_indices[k]]);
                }
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
    if (name == "RowHammer") return runRowHammerTest(ctx, region, config, stop);
    
    // Warn on invalid test name (GPT report item: invalid names silently ignored)
    LOG_WARN("Unknown test function name: '%s' - skipping", name.c_str());
    return {};
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
        if (r.errors > 0 && halt_on_error) {
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
    bool try_large = true;
    bool try_lock = config.use_locked_memory;

    auto guard = Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
    if (!guard.valid()) {
        LOG_ERROR("Allocation failed!");
        throw std::runtime_error("Found no suitable memory allocation method");
    }

    region.base = guard.base();
    region.size = guard.size();
    region.is_large_pages = guard.is_large_pages();
    region.is_locked = guard.is_locked();

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
            uint64_t errs = ctx.total_errors.load(std::memory_order_relaxed);
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
                "[Cycle %u/%s] Test %u/%zu (%s): %.2f GB, %llu errors | Time: %02u:%02u:%02u",
                cycle,
                config.cycles ? std::to_string(config.cycles).c_str() : "inf",
                test_idx,
                seq.size(),
                name.c_str(),
                gb,
                (unsigned long long)errs,
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
                if (t == 0) ctx.current_cycle.store(cycle + 1, std::memory_order_release);

                uint32_t seq_idx = 0;
                for (uint32_t test_id : seq) {
                    if (ctx.shouldStop()) break;
                    if (t == 0) ctx.current_test_idx.store(++seq_idx, std::memory_order_release);

                    if (configs.count(test_id)) {
                        const TestConfig& tc = configs.at(test_id);
                        if (t == 0) ctx.setActiveTestName(tc.function);

                        uint32_t loops = (config.preset.time_percent * tc.time_percent) / 100;
                        if (loops == 0) loops = 1;

                        for (uint32_t L = 0; L < loops; ++L) {
                            if (ctx.shouldStop()) break;
                            TestResult tr = runRegionWork(ctx, my_region, tc, config.halt_on_error);

                            ctx.total_errors.fetch_add(tr.errors, std::memory_order_relaxed);
                            ctx.total_bytes.fetch_add(tr.bytes_tested, std::memory_order_relaxed);

                            if (tr.errors > 0 && config.halt_on_error) {
                                ctx.requestStop();
                                break;
                            }
                        }
                    }
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
    result.total_errors = ctx.total_errors.load(std::memory_order_relaxed);
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
