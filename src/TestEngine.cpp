#include "TestEngine.h"
#include "Platform.h"
#include "Logger.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include "Utils.h"
#include "WorkerProgress.h"
#include "TestEngineInternal.h"
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <sstream>
#include <random>
#include <algorithm>
#include <condition_variable>
#include <array>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace testsmem4u {

namespace {

bool isKnownFunctionNameInternal(const std::string& name) {
    return name == "SimpleTest" ||
           name == "MirrorMove" ||
           name == "MirrorMove128" ||
           name == "RefreshStable" ||
           name == "WalkingOnes" ||
           name == "WalkingZeros" ||
           name == "LFSRPattern" ||
           name == "MovingInversion" ||
           name == "MovingInversionLFSR" ||
           name == "MovingInversionWalking" ||
           name == "BlockMove" ||
           name == "RowHammer" ||
           name == "RandomAccess" ||
           name == "Modulo20";
}

struct WorkerAssignment {
    CpuTarget target;
    size_t offset = 0;
    size_t size = 0;
};

static std::vector<WorkerAssignment> buildWorkerAssignments(const MemoryRegion& region, uint32_t requested_threads) {
    std::vector<CpuTarget> targets = Platform::getPreferredCpuTargets(requested_threads);
    if (targets.empty()) {
        targets.resize(requested_threads == 0 ? 1 : requested_threads);
    }

    if (requested_threads > 0 && targets.size() > requested_threads) {
        targets.resize(requested_threads);
    }

    if (targets.empty()) {
        targets.push_back(CpuTarget{});
    }
    targets.resize(std::min(targets.size(), std::max<size_t>(1, region.size / 4096)));

    const size_t page_size = 4096;
    if (region.size < page_size) return {{targets.front(), 0, region.size}};
    const size_t aligned_region_size = (region.size / page_size) * page_size;
    size_t total_pages = aligned_region_size / page_size;
    if (total_pages == 0) total_pages = 1;

    std::vector<WorkerAssignment> assignments(targets.size());
    uint64_t total_weight = 0;
    for (const auto& target : targets) {
        total_weight += std::max<uint32_t>(1, target.weight);
    }
    if (total_weight == 0) total_weight = targets.size();

    size_t assigned_pages = 0;
    size_t running_offset = 0;
    for (size_t i = 0; i < targets.size(); ++i) {
        assignments[i].target = targets[i];
        assignments[i].offset = running_offset;

        size_t pages = 0;
        if (i + 1 == targets.size()) {
            pages = total_pages - assigned_pages;
        } else {
            uint64_t weighted_pages = (static_cast<uint64_t>(total_pages) * std::max<uint32_t>(1, targets[i].weight)) / total_weight;
            pages = static_cast<size_t>(weighted_pages);
            size_t remaining_workers = targets.size() - i;
            size_t remaining_pages = total_pages - assigned_pages;
            if (pages == 0) pages = 1;
            if (pages > remaining_pages - (remaining_workers - 1)) {
                pages = remaining_pages - (remaining_workers - 1);
            }
        }

        assignments[i].size = pages * page_size;
        assigned_pages += pages;
        running_offset += assignments[i].size;
    }

    if (!assignments.empty()) {
        size_t covered = 0;
        for (const auto& assignment : assignments) {
            covered += assignment.size;
        }
        if (covered < region.size) {
            assignments.back().size += region.size - covered;
        }
    }

    return assignments;
}

}

extern std::atomic<bool> g_rowhammer_large_page_warning_emitted;
// Static lifetime keeps asynchronous shutdown safe during teardown.
static std::atomic<bool> g_stop_requested{false};

std::vector<uint32_t> parseTestSequence(const std::string& sequence) {
    std::vector<uint32_t> result;
    const std::string text = Utils::trim(sequence);
    if (text.empty()) return result;

    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const std::string item = Utils::trim(
            text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (item.empty()) {
            result.clear();
            return result;
        }

        uint32_t parsed = 0;
        if (!Utils::parseUintStrict(item, parsed)) {
            result.clear();
            return result;
        }
        result.push_back(parsed);

        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return result;
}

bool isKnownTestFunctionName(const std::string& name) {
    return isKnownFunctionNameInternal(name);
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
    if (name == "Modulo20") return runModulo20(ctx, region, config, stop);
    if (name == "RandomAccess") return runRandomAccess(ctx, region, config, stop);
    
    ctx.setInfrastructureFailure("Unknown test function in active preset: '" + name + "'");
    LOG_ERROR("Unknown test function name: '%s'", name.c_str());
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
        sub.base_offset_bytes += offset;

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
    g_rowhammer_large_page_warning_emitted.store(false, std::memory_order_release);
    g_stop_requested.store(false, std::memory_order_release);

    MemoryRegion region;
    uint64_t needed_bytes = (uint64_t)config.memory_window_mb * 1024 * 1024;
    if (needed_bytes == 0) {
        LOG_ERROR("Configured memory window is 0 MB. Refusing to run an empty RAM test.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "Configured memory window is 0 MB.";
        return result;
    }

    LOG_INFO("Allocating %u MB...", config.memory_window_mb);
    bool try_large = config.use_large_pages;
    bool try_lock = config.use_locked_memory;

    auto prep_start = std::chrono::steady_clock::now();
    std::atomic<bool> prep_done{false};
    std::thread prep_status_thread([&prep_done]() {
        uint64_t seconds = 0;
        while (!prep_done.load(std::memory_order_acquire)) {
            std::ostringstream ss;
            ss << "[Preparation] Optimizing memory layout... " << seconds << "s elapsed";
            ConsoleDisplay::get().updateProgressLine(ss.str());
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++seconds;
        }
    });

    auto guard = Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
    prep_done.store(true, std::memory_order_release);
    if (prep_status_thread.joinable()) prep_status_thread.join();
    auto prep_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - prep_start).count();
    {
        std::ostringstream ss;
        ss << "[Preparation] Completed in " << prep_seconds << "s.";
        ConsoleDisplay::get().printLine(ss.str());
    }

    if (!guard.valid()) {
        LOG_ERROR("Found no suitable memory allocation method. Aborting.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "No suitable memory allocation method succeeded.";
        return result;
    }

    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    if (region.size < needed_bytes) {
        LOG_ERROR("Allocation contract violated: requested %u MB but got only %zu MB. Aborting.",
                  config.memory_window_mb, region.size / (1024 * 1024));
        result.infrastructure_failure = true;
        result.infrastructure_error = "Allocation contract violated: allocator returned fewer bytes than requested.";
        return result;
    }
    if (try_lock && !region.is_locked) {
        LOG_ERROR("Allocation contract violated: requested locked memory but allocation is not locked. Aborting.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "Allocation contract violated: requested locked memory but allocation was not locked.";
        return result;
    }

    ConsoleDisplay::get().printLine("");
    ConsoleDisplay::get().printLine("[Memory Allocation]");
    {
        std::ostringstream ss;
        ss << "  Requested:  " << config.memory_window_mb << " MB";
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Size:       " << (region.size / 1024 / 1024) << " MB";
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Locked:     " << (region.is_locked ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        if (region.large_page_bytes == 0) {
            ss << "  LargePages: No";
        } else if (region.large_page_bytes >= region.size) {
            ss << "  LargePages: Yes (full region)";
        } else {
            ss << "  LargePages: Partial (" << (region.large_page_bytes / 1024 / 1024) << " MB of "
               << (region.size / 1024 / 1024) << " MB)";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        if (region.large_page_bytes >= region.size) {
            ss << "  Method:     Large Pages";
        } else if (region.large_page_bytes > 0 && region.is_locked) {
            ss << "  Method:     Hybrid (Large Pages + Locked Standard Pages)";
        } else if (region.is_locked) {
            ss << "  Method:     VirtualLock/Mlock";
        } else {
            ss << "  Method:     Standard Malloc (Swappable)";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (region.is_locked && region.large_page_bytes < region.size) {
        ConsoleDisplay::get().printLine("  Info:       Testing remains valid with fully locked memory, but full large-page coverage would improve throughput and RowHammer fidelity.");
        ConsoleDisplay::get().printLine("              If you want a full large-page run, try closing memory-heavy apps or restarting Windows before starting the test.");
    }
    ConsoleDisplay::get().printLine("");

    std::string seq_str = config.preset.test_sequence.empty() ? "0" : config.preset.test_sequence;
    std::vector<uint32_t> seq = parseTestSequence(seq_str);

    result = executeSuite(config, region, seq, config.preset.test_configs);

    // guard destructor will free memory
    return result;
}

RunResult TestEngine::executeSuite(const Config& config, const MemoryRegion& region,
                                   const std::vector<uint32_t>& seq,
                                   const std::map<uint32_t, TestConfig>& configs
#ifdef TESTSMEM4U_TESTING
                                   , TestContext* instrumentation
#endif
                                   ) {
    Platform::confirmNormalProcessPriority();
    RunResult result = {};
    TestContext own_ctx;
#ifdef TESTSMEM4U_TESTING
    TestContext& ctx = instrumentation ? *instrumentation : own_ctx;
#else
    TestContext& ctx = own_ctx;
#endif
    
    // Set up global stop signal for shutdown handler
    ctx.external_stop = &g_stop_requested;

    PlatformInfo platform_info = Platform::detectPlatform();
    uint32_t hw_threads = platform_info.cpu_cores;
    if (hw_threads == 0) hw_threads = 1;

    uint32_t threads = config.cores > 0 ? config.cores : hw_threads;
    threads = std::min(threads, hw_threads);
    uint32_t max_threads_for_region = static_cast<uint32_t>(std::max<size_t>(1, region.size / 4096));
    threads = std::min(threads, max_threads_for_region);
    if (threads == 0) threads = 1;

    std::vector<WorkerAssignment> assignments = buildWorkerAssignments(region, threads);
    threads = static_cast<uint32_t>(assignments.size());

    {
        // Report the ISA this binary was compiled to emit (i.e. which variant is
        // running) alongside the CPU's detected capabilities. Picking the binary
        // variant that matches the CPU is the user's responsibility (there is no
        // auto-relaunch); warn when a faster sibling variant would fit.
#if defined(__AVX512F__)
        const char* built_isa = "AVX-512 (v4)";
#elif defined(__AVX2__)
        const char* built_isa = "AVX2 (v3)";
#else
        const char* built_isa = "SSE2 baseline";
#endif
        const simd::SimdCapabilities caps = simd::getCapabilities();
        LOG_INFO("SIMD: built for %s; CPU supports AVX2=%s AVX-512=%s; worker threads = %u",
                 built_isa,
                 caps.has_avx2 ? "yes" : "no",
                 caps.has_avx512 ? "yes" : "no", threads);
#if !defined(__AVX512F__)
        if (caps.has_avx512) {
            LOG_WARN("This CPU supports AVX-512: use the -v4 binary variant for maximum RAM-test throughput.");
        }
#if !defined(__AVX2__)
        else if (caps.has_avx2) {
            LOG_WARN("This CPU supports AVX2: use the -v3 binary variant for maximum RAM-test throughput.");
        }
#endif
#endif
    }

    // Warn if estimated runtime from preset configuration is excessive
    {
        uint64_t total_loop_estimate = 0;
        for (uint32_t test_id : seq) {
            auto it = configs.find(test_id);
            if (it == configs.end()) continue;
            const TestConfig& tc = it->second;
            if (!tc.enabled) continue;
            uint64_t loops = (static_cast<uint64_t>(config.preset.time_percent) * tc.time_percent) / 100;
            if (loops == 0) loops = 1;
            uint64_t internal_reps = tc.parameter > 0 ? tc.parameter : 1;
            total_loop_estimate += loops * internal_reps;
        }
        uint64_t total_cycles = config.cycles == 0 ? 1 : config.cycles;
        total_loop_estimate *= total_cycles;
        constexpr uint64_t kMaxRecommendedLoops = 100000;
        if (total_loop_estimate > kMaxRecommendedLoops) {
            LOG_WARN("Estimated total loops (%llu) exceeds recommended maximum (%llu). "
                     "The preset configuration may produce an extremely long run. "
                     "Consider reducing Time(%%), Parameter, or Cycles values.",
                     (unsigned long long)total_loop_estimate,
                     (unsigned long long)kMaxRecommendedLoops);
        }
    }

    if (seq.empty() || std::none_of(seq.begin(), seq.end(), [&](uint32_t id) {
            auto it = configs.find(id);
            return it != configs.end() && it->second.enabled;
        })) {
        result.infrastructure_failure = true;
        result.infrastructure_error = "No enabled tests in the sequence.";
        return result;
    }
    for (uint32_t id : seq) {
        if (configs.find(id) == configs.end()) {
            result.infrastructure_failure = true;
            result.infrastructure_error = "Test Sequence references undefined test ID " + std::to_string(id) + ".";
            return result;
        }
    }
    std::vector<std::thread> workers;
    workers.reserve(threads);
    WorkerProgress progress(threads);
    LOG_INFO("Scheduling: independent workers; progress reports minimum completed coverage. "
             "Faster workers continue genuine tests until every region completes the requested cycles.");
    LOG_INFO("Retention: alternate untouched halves while testing the other half; no whole-run sleep.");

    auto start = std::chrono::steady_clock::now();

    ConsoleDisplay::get().setTestingActive(true);

    std::thread monitor([&]() {
        auto last_update = std::chrono::steady_clock::now();

        while (!ctx.shouldStop()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (ctx.shouldStop()) break;

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() < 500) {
                continue;
            }
            last_update = now;

            StatusInfo info;
            const uint64_t position = progress.minimum();
            info.cycle = static_cast<uint32_t>(position / seq.size() + 1);
            info.total_cycles = config.cycles;
            info.test_idx = static_cast<uint32_t>(position % seq.size() + 1);
            info.total_tests = seq.size();
            info.test_name = configs.at(seq[position % seq.size()]).function;
            info.bytes_tested = ctx.total_bytes.load(std::memory_order_relaxed);
            info.errors = ctx.total_hard_errors.load(std::memory_order_relaxed) +
                          ctx.total_soft_errors.load(std::memory_order_relaxed) +
                          ctx.total_unverified_errors.load(std::memory_order_relaxed);
            info.elapsed_seconds = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now - start).count());

            ConsoleDisplay::get().updateStatus(info);
        }
        ConsoleDisplay::get().clearStatus();
    });

    try {
        for (uint32_t t = 0; t < threads; ++t) {
            workers.emplace_back([&, t]() {
                try {
                    const WorkerAssignment& assignment = assignments[t];
                    if (!Platform::bindCurrentThread(assignment.target)) {
                        LOG_WARN("Worker %u could not bind to target group=%u cpu=%u", t,
                                 static_cast<unsigned>(assignment.target.group),
                                 static_cast<unsigned>(assignment.target.logical_index));
                    }
                    MemoryRegion my_region = region;
                    my_region.base += assignment.offset;
                    my_region.size = assignment.size;
                    my_region.base_offset_bytes += assignment.offset;
                    LOG_DEBUG("Worker %u owns offset=%zu bytes=%zu weight=%u", t,
                              my_region.base_offset_bytes, my_region.size, assignment.target.weight);
                    uint64_t cycle = 0;
                    while (!ctx.shouldStop()) {
                        if (!Platform::checkMemoryResident(my_region.base, my_region.size)) {
                            ctx.setInfrastructureFailure("Worker memory residency check failed.");
                            break;
                        }
                        for (size_t seq_idx = 0; seq_idx < seq.size() && !ctx.shouldStop(); ++seq_idx) {
                            const TestConfig& tc = configs.at(seq[seq_idx]);
                            const auto test_start = std::chrono::steady_clock::now();
                            if (tc.enabled) {
                                testPhase(ctx, "Worker test start", my_region);
                                LOG_DEBUG("Worker %u cycle %llu test %zu: %s started", t,
                                          static_cast<unsigned long long>(cycle + 1), seq_idx + 1, tc.function.c_str());
                                const uint64_t loops = std::max<uint64_t>(1,
                                    (static_cast<uint64_t>(config.preset.time_percent) * tc.time_percent) / 100);
                                for (uint64_t loop = 0; loop < loops && !ctx.shouldStop(); ++loop) {
                                    TestResult tr = runRegionWork(ctx, my_region, tc, config.halt_on_error);
                                    ctx.total_hard_errors.fetch_add(tr.hard_errors, std::memory_order_relaxed);
                                    ctx.total_soft_errors.fetch_add(tr.soft_errors, std::memory_order_relaxed);
                                    ctx.total_unverified_errors.fetch_add(tr.unverified_errors, std::memory_order_relaxed);
                                    ctx.total_bytes.fetch_add(tr.bytes_tested, std::memory_order_relaxed);
                                    if (tr.total_errors() && config.halt_on_error) ctx.requestStop();
                                }
                            }
                            if (ctx.shouldStop()) break;
                            progress.publish(t, cycle * seq.size() + seq_idx + 1);
                            LOG_DEBUG("Worker %u cycle %llu test %zu: %s completed in %.3fs", t,
                                      static_cast<unsigned long long>(cycle + 1), seq_idx + 1, tc.function.c_str(),
                                      std::chrono::duration<double>(std::chrono::steady_clock::now() - test_start).count());
                            if (config.cycles && progress.minimum() / seq.size() >= config.cycles) {
                                ctx.requestStop();
                                break;
                            }
                        }
                        ++cycle;
                    }
                } catch (const std::exception& error) {
                    LOG_ERROR("Worker %u failed: %s", t, error.what());
                    ctx.setInfrastructureFailure("RAM-test worker failed: " + std::string(error.what()));
                } catch (...) {
                    ctx.setInfrastructureFailure("RAM-test worker failed with an unknown exception.");
                }
            });
        }
    } catch (const std::exception& error) {
        ctx.setInfrastructureFailure("Could not start RAM-test workers: " + std::string(error.what()));
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    ctx.requestStop();
    if (monitor.joinable()) monitor.join();

    ConsoleDisplay::get().setTestingActive(false);

    auto end = std::chrono::steady_clock::now();
    result.hard_errors = ctx.total_hard_errors.load(std::memory_order_relaxed);
    result.soft_errors = ctx.total_soft_errors.load(std::memory_order_relaxed);
    result.unverified_errors = ctx.total_unverified_errors.load(std::memory_order_relaxed);
    result.bytes_tested = ctx.total_bytes.load(std::memory_order_relaxed);
    result.cycles_completed = progress.minimum() / seq.size();
    LOG_INFO("Coverage: %llu complete cycles across every worker region",
             static_cast<unsigned long long>(result.cycles_completed));
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    result.infrastructure_failure = ctx.hasInfrastructureFailure();
    result.infrastructure_error = ctx.getInfrastructureFailureMessage();

    return result;
}

void TestEngine::requestStop() {
    g_stop_requested.store(true, std::memory_order_release);
}

} // namespace testsmem4u
