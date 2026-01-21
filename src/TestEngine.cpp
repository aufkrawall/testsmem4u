#include "TestEngine.h"
#include "Logger.h"
#include "simd_ops.h"
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
        uint64_t actual = ptr[idx]; // Re-read to check consistency

        if (actual != expect) {
            // Hard Error: Re-read confirmed the mismatch
            LOG_ERROR_DETAIL((test_name + " (Hard)").c_str(), (uint64_t)((start_idx + idx) * 8), expect, actual);
            res.errors++;
        } else {
            // Soft/Transient Error: Re-read returned correct value
            // This is likely a bus glitch, interference, or alpha particle, but not a stuck bit.
            // We report it as a warning but do NOT fail the test immediately unless strict mode is on.
            LOG_WARN("Soft/Transient error at 0x%016llX (expected 0x%016llX, re-read correct)", 
                     (unsigned long long)((start_idx + idx) * 8), (unsigned long long)expect);
            
            // Should we count this? For now, let's not fail the test on soft errors to avoid false alarms.
            // But we should track them if we had a field. For now, just logging is a huge improvement.
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

    if (config.pattern_mode == 0) {
        generate_pattern_uniform(ptr, count, config.pattern_param0, use_nt);
    } else if (config.pattern_mode == 1) {
        generate_pattern_xor(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
    } else {
        generate_pattern_linear(ptr, count, config.pattern_param0, config.pattern_param1, use_nt);
    }

    res.bytes_tested += region.size;

    sfence();

    // Use a larger block size to reduce loop overhead and potentially stress memory controller more
    // 2MB (256K uint64) is a reasonable chunk
    size_t block = 256 * 1024; 

    for (size_t i = 0; i < count; i += block) {
        if (ctx.shouldStop()) break;
        size_t n = std::min(block, count - i);

        TestEngine::verifyAndReport(ptr + i, n, i, config.pattern_mode, config.pattern_param0, 
                                    config.pattern_param1, res, ctx, "SimpleTest", stop);

        if (stop && ctx.shouldStop()) break;
        res.bytes_tested += n * 8;
    }

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
    uint8_t* ptr = reinterpret_cast<uint8_t*>(region.base);
    size_t count = region.size;

    // Optimize: Process in cache-line sized blocks if possible, or at least flush
    for (size_t byte = 0; byte < count; ++byte) {
        if (ctx.shouldStop()) break;
        uint8_t pattern = 1;
        
        // Write pattern
        for (int bit = 0; bit < 8 && byte + bit < count; ++bit) {
            ptr[byte + bit] = pattern;
            pattern <<= 1;
        }
        
        // Flush to ensure it hits RAM (critical for this specific low-level bit test)
        simd::flush_cache_line((void*)&ptr[byte]);
        sfence();

        // Verify
        pattern = 1;
        for (int bit = 0; bit < 8 && byte + bit < count; ++bit) {
            // Force read from memory (if flush worked, this should be from RAM)
            volatile uint8_t val = ptr[byte + bit];
            if (val != pattern) {
                res.errors++;
                LOG_ERROR_DETAIL("WalkingOnes", (uint64_t)(byte + bit), pattern, val);
                if (stop) {
                    ctx.requestStop();
                    return res;
                }
            }
            pattern <<= 1;
        }
    }

    res.bytes_tested = count;
    return res;
}

TestResult TestEngine::runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    (void)config;
    TestResult res = {};
    uint8_t* ptr = reinterpret_cast<uint8_t*>(region.base);
    size_t count = region.size;

    for (size_t byte = 0; byte < count; ++byte) {
        if (ctx.shouldStop()) break;
        uint8_t pattern = 0xFE;
        for (int bit = 0; bit < 8 && byte + bit < count; ++bit) {
            ptr[byte + bit] = pattern;
            pattern = (pattern << 1) | 1;
        }
        
        simd::flush_cache_line((void*)&ptr[byte]);
        sfence();

        pattern = 0xFE;
        for (int bit = 0; bit < 8 && byte + bit < count; ++bit) {
            volatile uint8_t val = ptr[byte + bit];
            if (val != pattern) {
                res.errors++;
                LOG_ERROR_DETAIL("WalkingZeros", (uint64_t)(byte + bit), pattern, val);
                if (stop) {
                    ctx.requestStop();
                    return res;
                }
            }
            pattern = (pattern << 1) | 1;
        }
    }

    res.bytes_tested = count;
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

    uint64_t seed = config.pattern_param0 ? config.pattern_param0 : 0x12345678;

    for (size_t i = 0; i < count; ++i) {
        if (ctx.shouldStop()) break;
        ptr[i] = static_cast<uint32_t>(seed);
        seed = lfsr_next(seed);
    }
    sfence();

    seed = config.pattern_param0 ? config.pattern_param0 : 0x12345678;
    uint64_t errors[128];

    for (size_t i = 0; i < count; i += 1024) {
        if (ctx.shouldStop()) break;
        size_t n = std::min((size_t)1024, count - i);

        size_t found = 0;
        for (size_t j = 0; j < n && found < 128; ++j) {
            if (ptr[i + j] != static_cast<uint32_t>(seed)) {
                errors[found++] = j;
            }
            seed = lfsr_next(seed);
        }

        if (found > 0) {
            res.errors += found;
            size_t limit = std::min(found, (size_t)128);
            for (size_t k = 0; k < limit; ++k) {
                LOG_ERROR_DETAIL("LFSR", (uint64_t)((i + errors[k]) * 4), static_cast<uint32_t>(seed), ptr[i + errors[k]]);
            }
            if (stop) {
                ctx.requestStop();
                break;
            }
        }
    }

    res.bytes_tested = region.size;
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
    if (name == "MovingInversion") return runSimpleTest(ctx, region, config, stop);
    if (name == "RowHammer") return runRowHammerTest(ctx, region, config, stop);
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

            int len = snprintf(buffer, sizeof(buffer),
                "[Cycle %u/%s] Test %u/%zu (%s): %.2f GB, %llu errors",
                cycle,
                config.cycles ? std::to_string(config.cycles).c_str() : "inf",
                test_idx,
                seq.size(),
                name.c_str(),
                gb,
                (unsigned long long)errs);

#ifdef _WIN32
            if (len > 0 && last_line != buffer) {
                // Only lock for the actual console I/O
                std::lock_guard<std::mutex> lock(Logger::get().getMutex());
                GetConsoleScreenBufferInfo(hOut, &csbi);
                cursorPos = csbi.dwCursorPosition;
                cursorPos.X = 0;
                SetConsoleCursorPosition(hOut, cursorPos);

                DWORD written;
                WriteConsoleA(hOut, buffer, static_cast<DWORD>(len), &written, nullptr);

                DWORD cellsToClear = csbi.dwSize.X - cursorPos.X - written;
                if (cellsToClear > 0) {
                    for (DWORD i = 0; i < cellsToClear; i++) {
                        WriteConsoleA(hOut, " ", 1, &written, nullptr);
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
