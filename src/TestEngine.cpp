#include "TestEngine.h"
#include "Platform.h"
#include "Logger.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include "Utils.h"
#include "RegionScheduler.h"
#include "SequenceTimings.h"
#include "DisturbanceWindow.h"
#include "PreparationStatus.h"
#include "TestEngineInternal.h"
#include "MemoryTestKernels.h"
#include "ProgressDiagnostics.h"
#include "InfrastructureFailure.h"
#include "InputSpec.h"
#include "RunDeadline.h"
#include "IdleChunkCheck.h"
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
#include <optional>

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

struct ChunkLayout {
    size_t offset = 0;
    size_t size = 0;
};

static std::vector<CpuTarget> selectWorkerTargets(const MemoryRegion& region, uint32_t requested_threads,
                                                  size_t page_size) {
    std::vector<CpuTarget> targets = Platform::getPreferredCpuTargets(requested_threads);
    if (targets.empty()) targets.resize(requested_threads == 0 ? 1 : requested_threads);
    if (requested_threads > 0 && targets.size() > requested_threads) targets.resize(requested_threads);
    if (targets.empty()) targets.push_back(CpuTarget{});
    targets.resize(std::min(targets.size(), memory_pages::workerLimit(region.size, page_size)));
    return targets;
}

// Equal page-aligned chunks, two more than the worker count when the window has
// the pages: a finishing worker then always has at least one idle chunk besides
// its own to choose from, and choosing the least advanced of them keeps chunks
// within a few tests of each other (one spare chunk only rotates them FIFO and
// lets them drift apart). Remainder pages go to the first chunks; any sub-page
// tail to the last one.
constexpr size_t kSpareChunks = 2;

static std::vector<ChunkLayout> buildChunkLayout(const MemoryRegion& region, size_t workers, size_t page_size) {
    const size_t pages = memory_pages::workerLimit(region.size, page_size);
    const size_t chunks = std::min(pages, workers > 1 ? workers + kSpareChunks : size_t{1});
    if (region.size < page_size || chunks <= 1) return {{0, region.size}};
    const size_t total_pages = region.size / page_size;
    std::vector<ChunkLayout> layout(chunks);
    size_t offset = 0;
    for (size_t i = 0; i < chunks; ++i) {
        const size_t chunk_pages = total_pages / chunks + (i < total_pages % chunks ? 1 : 0);
        layout[i] = {offset, chunk_pages * page_size};
        offset += layout[i].size;
    }
    layout.back().size += region.size - offset;
    return layout;
}

} // namespace

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
    size_t block_size = (size_t)test_config.block_size_mb * size_t{1024} * 1024;

    if (block_size == 0 || block_size >= region.size) {
        return runTest(ctx, test_config.function, region, test_config, halt_on_error);
    }

    TestResult total = {};
    size_t blocks = (region.size + block_size - 1) / block_size;
    // Keep a tiny sub-24-KiB RowHammer tail attached to the preceding block so
    // configured block splitting cannot create an untestable tail slice.
    if (test_config.function == "RowHammer" && blocks > 1) {
        const size_t tail = region.size - (blocks - 1) * block_size;
        if (tail < kMinRowHammerBytes) --blocks;
    }
    // The chunk's leftover data is known only if every block left the same
    // global-address data (SimpleTest), not block-relative data (mirror moves).
    bool residual_consistent = true;
    size_t blocks_done = 0;
    for (size_t i = 0; i < blocks; ++i) {
        if (ctx.shouldStop()) break;
        size_t offset = i * block_size;
        size_t len = (i + 1 == blocks) ? (region.size - offset) : std::min(block_size, region.size - offset);

        ProgressBinding::beginBlock(&ctx, i, blocks);
        MemoryRegion sub = region;
        sub.base += offset;
        sub.size = len;
        sub.base_offset_bytes += offset;

        TestResult r = runTest(ctx, test_config.function, sub, test_config, halt_on_error);
        total.merge(r);
        residual_consistent &= r.residual.valid() && r.residual.offset == sub.base_offset_bytes &&
                               r.residual.bytes == sub.size && (i == 0 || r.residual.sameData(total.residual));
        if (i == 0) total.residual = r.residual;
        ++blocks_done;
        if (total.total_errors() > 0 && halt_on_error) {
            ctx.requestStop();
            break;
        }
    }
    if (residual_consistent && blocks_done == blocks) {
        total.residual.offset = region.base_offset_bytes;
        total.residual.bytes = region.size;
    } else {
        total.residual = {};
    }
    return total;
}

RunResult TestEngine::runTests(const Config& config
#ifdef TESTSMEM4U_TESTING
                               , std::function<MemoryGuard(size_t, bool, bool)> allocator
#endif
                               ) {
    RunResult result = {};
    g_rowhammer_large_page_warning_emitted.store(false, std::memory_order_release);
    resetRowHammerBudgetLog();
    // The stop request is a process-lifetime latch and is never cleared here.
    // Clearing it at run start discarded a Ctrl+C or console close that arrived
    // during the startup countdown, wizard or prompts: the handler had already
    // marked shutdown as initiated, so the whole suite then ran, the next Ctrl+C
    // force-quit without results, and a close event lost the results.
    if (g_stop_requested.load(std::memory_order_acquire)) {
        LOG_WARN("Stop requested before testing started (Ctrl+C or console close during startup); "
                 "no memory allocated or tested");
        result.stop_reason = "stop request";
        return result;
    }

    MemoryRegion region;
    uint64_t needed_bytes = static_cast<uint64_t>(config.memory_window_mb) * uint64_t{1024} * 1024;
    if (needed_bytes == 0) {
        LOG_ERROR("Configured memory window is 0 MB. Refusing to run an empty RAM test.");
        result.infrastructure_failure = true;
        result.infrastructure_error = "Configured memory window is 0 MB.";
        return result;
    }
    if (needed_bytes > std::numeric_limits<size_t>::max()) {
        LOG_ERROR("Configured memory window (%u MB) exceeds platform addressable size_t range.",
                  config.memory_window_mb);
        result.infrastructure_failure = true;
        result.infrastructure_error = "Configured memory window exceeds platform addressable size.";
        return result;
    }

    LOG_INFO("Allocating %u MB...", config.memory_window_mb);
    bool try_large = config.use_large_pages;
    bool try_lock = config.use_locked_memory;

    auto prep_start = std::chrono::steady_clock::now();
    PreparationStatus prep_status([](uint64_t seconds) {
        std::ostringstream ss;
        ss << "[Preparation] Optimizing memory layout... " << seconds << "s elapsed";
        ConsoleDisplay::get().updateProgressLine(ss.str());
    });

    LOG_DEBUG("Allocation starting: bytes=%llu large-pages=%s locked=%s",
              static_cast<unsigned long long>(needed_bytes), try_large ? "yes" : "no", try_lock ? "yes" : "no");
#ifdef TESTSMEM4U_TESTING
    auto guard = allocator ? allocator(needed_bytes, try_large, try_lock) :
                             Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
#else
    auto guard = Platform::allocateMemoryRAII(needed_bytes, try_large, try_lock);
#endif
    prep_status.finish();
    LOG_DEBUG("Allocation preparation finished: valid=%s bytes=%zu", guard.valid() ? "yes" : "no", guard.size());
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
    const auto page_coverage = Platform::queryLargePageCoverage(region);
    region.page_coverage = page_coverage;
    LOG_DEBUG("Allocation: coverage bytes=%zu..%zu known=%s transparent=%s page-size=%zu total=%zu",
              page_coverage.bytes, page_coverage.possible_bytes, page_coverage.known ? "yes" : "no",
              page_coverage.transparent ? "yes" : "no", page_coverage.page_size, region.size);

    if (region.size < needed_bytes) {
        LOG_ERROR("Allocation contract violated: requested %u MB but got only %zu MB. Aborting.",
                  config.memory_window_mb, region.size / (size_t{1024} * 1024));
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
        if (!page_coverage.known) {
            ss << "  LargePages: Unknown (coverage inspection unavailable)";
        } else if (page_coverage.bytes == 0 && page_coverage.possible_bytes == 0) {
            ss << "  LargePages: No";
        } else if (page_coverage.bytes >= region.size) {
            ss << "  LargePages: Yes (full region)";
        } else {
            ss << "  LargePages: Partial (" << (page_coverage.bytes / 1024 / 1024);
            if (page_coverage.bytes != page_coverage.possible_bytes) ss << "-" << (page_coverage.possible_bytes / 1024 / 1024);
            ss << " MB of " << (region.size / 1024 / 1024) << " MB)";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (config.use_large_pages && page_coverage.page_size > 0) {
        ConsoleDisplay::get().printLine("  Page size:  " + std::to_string(page_coverage.page_size / 1024) + " KiB (large-page allocation target)");
    }
    {
        std::ostringstream ss;
        if (page_coverage.transparent && page_coverage.possible_bytes > 0) {
            ss << "  Method:     Transparent Huge Pages" << (region.is_locked ? " + mlock" : " (Swappable)");
        } else if (region.large_page_bytes >= region.size) {
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
    if (region.is_locked && (!page_coverage.known || page_coverage.bytes < region.size)) {
        ConsoleDisplay::get().printLine("  Info:       Testing remains valid with fully locked memory; more large-page coverage can improve address translation and physical contiguity within each page.");
#ifdef _WIN32
        ConsoleDisplay::get().printLine("              If you want a full large-page run, try closing memory-heavy apps or restarting Windows before starting the test.");
#else
        ConsoleDisplay::get().printLine("              For more huge-page coverage, check Linux THP policy or configure a matching HugeTLB pool; --aggressive-defrag permits system-wide preparation.");
#endif
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
    const size_t native_page_size = Platform::getNativePageSize();
    if (native_page_size == 0) {
        result.infrastructure_failure = true;
        result.infrastructure_error = "Native page size is unavailable.";
        return result;
    }
    uint32_t max_threads_for_region = static_cast<uint32_t>(std::min(
        memory_pages::workerLimit(region.size, native_page_size), size_t{std::numeric_limits<uint32_t>::max()}));
    threads = std::min(threads, max_threads_for_region);
    if (threads == 0) threads = 1;

    const bool has_enabled_rowhammer = std::any_of(seq.begin(), seq.end(), [&](uint32_t id) {
        const auto it = configs.find(id);
        return it != configs.end() && it->second.enabled && it->second.function == "RowHammer";
    });
    if (has_enabled_rowhammer) {
        const uint32_t max_rh_threads = maxWorkersForRowHammer(region.size, native_page_size, kSpareChunks);
        if (max_rh_threads == 0) {
            LOG_ERROR("RowHammer requires a memory region of at least %zu bytes (got %zu bytes).",
                      kMinRowHammerBytes, region.size);
            result.infrastructure_failure = true;
            result.infrastructure_error = "Memory region is too small for RowHammer (minimum > 24 KiB).";
            return result;
        }
        if (threads > max_rh_threads) {
            LOG_WARN("RowHammer: capping worker threads from %u to %u so every memory chunk stays above 24 KiB "
                     "(window=%zu KiB)",
                     threads, max_rh_threads, region.size / 1024);
            threads = max_rh_threads;
        }
    }

    const std::vector<CpuTarget> targets = selectWorkerTargets(region, threads, native_page_size);
    threads = static_cast<uint32_t>(targets.size());
    const std::vector<ChunkLayout> layout = buildChunkLayout(region, threads, native_page_size);
    std::vector<MemoryRegion> chunk_regions(layout.size(), region);
    for (size_t i = 0; i < layout.size(); ++i) {
        chunk_regions[i].base += layout[i].offset;
        chunk_regions[i].size = layout[i].size;
        chunk_regions[i].base_offset_bytes += layout[i].offset;
    }
    {
        const size_t smt_siblings = static_cast<size_t>(std::count_if(
            platform_info.cpu_targets.begin(), platform_info.cpu_targets.end(),
            [](const CpuTarget& target) { return target.smt_secondary; }));
        LOG_DEBUG("CPU topology: source=%s usable-cpus=%u smt-siblings=%zu reserved-skipped=%u "
                  "affinity-excluded=%u heterogeneous=%s workers=%u",
                  platform_info.cpu_topology_source, platform_info.cpu_cores, smt_siblings,
                  platform_info.cpu_sets_reserved, platform_info.cpu_affinity_excluded,
                  platform_info.heterogeneous_cores ? "yes" : "no", threads);
        if (platform_info.cpu_sets_reserved_only) {
            LOG_WARN("CPU topology: all %u CPUs this process may use are reserved for other processes (Windows CPU "
                     "sets); workers run on them anyway because the affinity mask allows no other CPU",
                     platform_info.cpu_cores);
        }
    }
    LOG_DEBUG("Chunks: count=%zu first-bytes=%zu last-bytes=%zu (equal page-aligned slices served dynamically)",
              layout.size(), layout.front().size, layout.back().size);

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
        LOG_DEBUG("Kernels: uniform-march=register-pattern flush-stride=%zu advertised-granule=%zu flush=%s "
                  "LFSR-lanes=%zu post-fill-flush=%s",
                  caps.cache_line_size, caps.flush_granule_advertised, caps.has_clflushopt ? "CLFLUSHOPT region/batch" :
                  caps.has_clflush ? "CLFLUSH" : "platform fallback", simd::kLfsrGenerationLanes,
                  simd::streaming_fill_bypasses_cache() ? "skipped (non-temporal fills evict lines)" : "region flush");
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
        const uint64_t total_loop_estimate = estimatedTotalLoops(config, seq, configs);
        LOG_DEBUG("Run-length estimate: %llu loop repetitions over all cycles (warning above %llu)",
                  static_cast<unsigned long long>(total_loop_estimate),
                  static_cast<unsigned long long>(kMaxRecommendedLoops));
        if (total_loop_estimate > kMaxRecommendedLoops) {
            LOG_WARN("Estimated total loops (%llu) exceeds recommended maximum (%llu). "
                     "The preset configuration may produce an extremely long run. "
                     "Consider reducing Time(%%), Parameter, or Cycles values.",
                     (unsigned long long)total_loop_estimate,
                     (unsigned long long)kMaxRecommendedLoops);
        }
        // RandomAccess overloads Parameter: <= 100 is a pass count, larger is an
        // absolute access count, so raising 100 to 150 means far fewer accesses.
        for (const auto& [test_id, tc] : configs) {
            if (tc.enabled && tc.function == "RandomAccess" && tc.parameter > kRandomAccessPassLimit) {
                LOG_WARN("Test %u (RandomAccess): Parameter=%u exceeds %u, so it is an explicit access count "
                         "per memory chunk, not a pass multiplier. Use 1-%u for full-region passes.",
                         test_id, tc.parameter, kRandomAccessPassLimit, kRandomAccessPassLimit);
            }
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
    std::vector<size_t> enabled_entries;
    size_t first_disabled = 0;
    for (size_t i = 0; i < seq.size(); ++i) {
        if (configs.at(seq[i]).enabled) {
            enabled_entries.push_back(i);
        } else if (!first_disabled) {
            first_disabled = i + 1;
        }
    }
    const bool staggered = staggeredSequenceStart(config);
    const EnabledSequence enabled(std::move(enabled_entries), seq, chunk_regions.size(), staggered);
    if (first_disabled) {
        LOG_DEBUG("Sequence: %zu of %zu entries enabled; disabled entries are not scheduled (first disabled #%zu)",
                  enabled.size(), seq.size(), first_disabled);
    }
    LOG_INFO("%s", describeSequence(enabled, seq, configs).c_str());
    std::vector<std::thread> workers;
    workers.reserve(threads);
    RegionScheduler scheduler(chunk_regions.size(), threads);
    ctx.worker_progress = std::vector<ProgressCounters>(threads);
    LOG_INFO("Scheduling: %u workers pull %zu equal memory chunks; each chunk runs the sequence in order and a free "
             "worker takes the least advanced idle chunk, so coverage stays even however fast each CPU runs.",
             threads, chunk_regions.size());
    {
        const bool disturbs = std::any_of(enabled.entries.begin(), enabled.entries.end(), [&](size_t index) {
            return isCrossRegionDisturbanceTest(configs.at(seq[index]).function);
        });
        const char* source = config.sequence_start == SequenceStart::PRESET ? "preset" : "--sequence-start";
        LOG_INFO("%s", describeSequenceStart(enabled, seq.size(), source, disturbs).c_str());
    }
    LOG_INFO("Retention: alternate untouched halves while testing the other half; no whole-run sleep.");
    LOG_INFO("Idle-chunk checks: a test's final data is re-verified when the next test claims its chunk "
             "(the data sat untouched while other chunks were tested).");
    // Per chunk; only the worker holding the chunk's lease touches its entry.
    std::vector<IdleChunkState> idle_chunks(chunk_regions.size());
    IdleCheckStats idle_stats;
    LOG_DEBUG("Progress: verified blocks publish to separate worker counters; completed cycles require every chunk.");
    if (config.time_limit_seconds) {
        LOG_INFO("Time limit: %s; testing stops when it expires%s", formatTimeLimit(config.time_limit_seconds).c_str(),
                 config.cycles ? " or after the configured cycles, whichever is first" : " (no cycle limit)");
    }

    auto start = std::chrono::steady_clock::now();
    SequenceTimings timings(seq.size(), start);
    RunDeadline deadline;

    ConsoleDisplay::get().setTestingActive(true);

    const uint64_t initial_bytes = ctx.progressSnapshot().bytes_tested;
    auto monitor_work = [&]() {
#ifdef TESTSMEM4U_TESTING
        if (ctx.monitor_hook) ctx.monitor_hook();
#endif
        std::optional<ProgressDiagnostics> diagnostics;
        if (config.debug_mode) diagnostics.emplace(threads, start, initial_bytes);
        auto last_update = std::chrono::steady_clock::now();
        RegionScheduler::Snapshot regions;

        while (!ctx.shouldStop()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (ctx.shouldStop()) break;

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() < 500) {
                continue;
            }
            last_update = now;

            StatusInfo info;
            scheduler.snapshot(regions);
            const SlowestRegion slowest = findSlowestRegion(regions, ctx.worker_progress);
            const uint64_t position = slowest.position;
            const size_t seq_idx = enabled.entry(position, slowest.chunk);
            info.test_step = slowest.step;
            info.cycle = static_cast<uint32_t>(enabled.cycle(position) + 1);
            info.total_cycles = config.cycles;
            info.test_idx = static_cast<uint32_t>(seq_idx + 1);
            info.total_tests = seq.size();
            info.test_name = configs.at(seq[seq_idx]).function;
            const auto totals = ctx.progressSnapshot();
            info.bytes_tested = totals.bytes_tested;
            info.errors = totals.total_errors();
            info.elapsed_seconds = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now - start).count());
            info.time_limit_seconds = config.time_limit_seconds;

            ConsoleDisplay::get().updateStatus(info);
            if (diagnostics) {
                const auto diagnostic = diagnostics->update(now, totals, ctx.worker_progress, regions, enabled);
                if (!diagnostic.empty()) LOG_DEBUG("%s", diagnostic.c_str());
            }
        }
    };
    std::thread monitor([&]() noexcept {
        try {
            monitor_work();
        } catch (const std::exception& error) {
            reportInfrastructureFailure(ctx, "Progress monitor failed", error.what());
        } catch (...) {
            reportInfrastructureFailure(ctx, "Progress monitor failed", "unknown exception");
        }
        try {
            ConsoleDisplay::get().clearStatus();
        } catch (const std::exception& error) {
            reportInfrastructureFailure(ctx, "Progress monitor status cleanup failed", error.what());
        } catch (...) {
            reportInfrastructureFailure(ctx, "Progress monitor status cleanup failed", "unknown exception");
        }
    });

    try {
        if (config.time_limit_seconds) {
            deadline.start(start + std::chrono::seconds(config.time_limit_seconds), [&ctx, &config]() {
                ctx.requestStop(); // first: logging may throw
                LOG_INFO("Time limit of %s reached; stopping the test workers",
                         formatTimeLimit(config.time_limit_seconds).c_str());
            });
        }
        for (uint32_t t = 0; t < threads; ++t) {
            workers.emplace_back([&, t]() noexcept {
                ProgressBinding binding(&ctx, ctx.worker_progress[t]);
                try {
                    const CpuTarget& target = targets[t];
                    if (!Platform::bindCurrentThread(target)) {
                        LOG_WARN("Worker %u could not bind to target group=%u cpu=%u", t,
                                 static_cast<unsigned>(target.group), static_cast<unsigned>(target.logical_index));
                    }
                    LOG_DEBUG("Worker %u bound cpu=%u:%u core=%u eff=%u sched=%u smt-sibling=%s parked=%s", t,
                              static_cast<unsigned>(target.group), static_cast<unsigned>(target.logical_index),
                              static_cast<unsigned>(target.core_index), static_cast<unsigned>(target.efficiency_class),
                              static_cast<unsigned>(target.scheduling_class), target.smt_secondary ? "yes" : "no",
                              target.parked ? "yes" : "no");
                    uint64_t completed_entries = 0;
                    while (!ctx.shouldStop()) {
                        const RegionScheduler::Claim claim = scheduler.claim(t);
                        if (claim.chunk == RegionScheduler::kNone) {
                            ctx.setInfrastructureFailure("Scheduler found no idle memory chunk for a free worker.");
                            break;
                        }
                        ChunkLease lease(scheduler, t, claim.chunk);
                        const MemoryRegion& chunk = chunk_regions[claim.chunk];
                        const uint64_t cycle = enabled.cycle(claim.position);
                        const size_t seq_idx = enabled.entry(claim.position, claim.chunk);
                        const uint64_t data_pass = enabled.pass(claim.position, claim.chunk);
                        if (enabled.startsCycle(claim.position)) {
                            testPhase(ctx, "Memory residency", chunk);
                            if (!Platform::checkMemoryResident(chunk.base, chunk.size)) {
                                ctx.setInfrastructureFailure("Worker memory residency check failed.");
                                break;
                            }
                        }
                        checkIdleChunk(ctx, idle_chunks[claim.chunk], chunk, t, completed_entries, idle_stats,
                                       config.halt_on_error);
                        if (ctx.shouldStop()) break;
                        const TestConfig& tc = configs.at(seq[seq_idx]);
                        const auto test_start = std::chrono::steady_clock::now();
                        const uint64_t bytes_before = ctx.worker_progress[t].snapshot().bytes_tested;
                        testPhase(ctx, "Worker test start", chunk);
                        const uint64_t loops = std::max<uint64_t>(1,
                            (static_cast<uint64_t>(config.preset.time_percent) * tc.time_percent) / 100);
                        const size_t slot = enabled.slot(claim.position, claim.chunk);
                        LOG_DEBUG("Worker %u chunk %zu cycle %llu test %zu: %s started loops=%llu occurrence=%u/%u "
                                  "variation=%llu",
                                  t, claim.chunk, static_cast<unsigned long long>(cycle + 1), seq_idx + 1,
                                  tc.function.c_str(), static_cast<unsigned long long>(loops),
                                  enabled.occurrence[slot] + 1, enabled.occurrences[slot],
                                  static_cast<unsigned long long>(passVariation(data_pass, loops, 0)));
                        const bool disturbs = isCrossRegionDisturbanceTest(tc.function);
                        TestConfig pass = tc;
                        TestResult last_loop;
                        for (uint64_t loop = 0; loop < loops && !ctx.shouldStop(); ++loop) {
                            ProgressBinding::beginLoop(&ctx, loop, loops);
                            DisturbanceWindow window(ctx, disturbs);
                            pass.variation = passVariation(data_pass, loops, loop);
                            TestResult tr = runRegionWork(ctx, chunk, pass, config.halt_on_error);
                            if (tr.total_errors() && window.overlappedForeignDisturbance()) {
                                LOG_WARN("Worker %u: %llu error(s) in %s (region offset=%zu bytes=%zu) while "
                                         "RowHammer ran on another memory chunk. Rows can span chunk "
                                         "boundaries, so cross-chunk hammering may have caused them.",
                                         t, static_cast<unsigned long long>(tr.total_errors()),
                                         tc.function.c_str(), chunk.base_offset_bytes, chunk.size);
                            }
                            if (tr.total_errors() && config.halt_on_error) ctx.requestStop();
                            last_loop = tr;
                        }
                        const auto test_end = std::chrono::steady_clock::now();
                        const uint64_t verified = ctx.worker_progress[t].snapshot().bytes_tested - bytes_before;
                        // A cancelled test must not count as covered; the lease returns the chunk.
                        if (ctx.shouldStop()) {
                            timings.record(seq_idx, test_start, test_end, verified, false);
                            break;
                        }
                        if (verified == 0) {
                            LOG_ERROR("Worker %u chunk %zu cycle %llu test %zu: %s completed without verifying any memory",
                                      t, claim.chunk, static_cast<unsigned long long>(cycle + 1), seq_idx + 1,
                                      tc.function.c_str());
                            timings.record(seq_idx, test_start, test_end, verified, false);
                            ctx.setInfrastructureFailure("Test '" + tc.function + "' completed without verifying any memory.");
                            break;
                        }
                        timings.record(seq_idx, test_start, test_end, verified, true);
                        ProgressBinding::resetStep(&ctx);
                        rememberIdleChunk(idle_chunks[claim.chunk], last_loop, chunk, tc.function, t,
                                          ++completed_entries, ctx.disturbance_starts.load(std::memory_order_acquire));
                        lease.complete(claim.position + 1);
                        LOG_DEBUG("Worker %u chunk %zu cycle %llu test %zu: %s completed in %.3fs verified-bytes=%llu",
                                  t, claim.chunk, static_cast<unsigned long long>(cycle + 1), seq_idx + 1,
                                  tc.function.c_str(), std::chrono::duration<double>(test_end - test_start).count(),
                                  static_cast<unsigned long long>(verified));
                        const uint64_t completed_cycles = scheduler.minimum() / enabled.size();
                        for (const auto& milestone : timings.cycleMilestones(completed_cycles, test_end)) {
                            LOG_INFO("%s", milestone.c_str());
                        }
                        if (config.cycles && completed_cycles >= config.cycles) {
                            ctx.requestStop();
                            break;
                        }
                    }
                } catch (const std::exception& error) {
                    reportInfrastructureFailure(ctx, "RAM-test worker failed", error.what(), t);
                } catch (...) {
                    reportInfrastructureFailure(ctx, "RAM-test worker failed", "unknown exception", t);
                }
            });
        }
    } catch (const std::exception& error) {
        reportInfrastructureFailure(ctx, "Could not start RAM-test workers", error.what());
    } catch (...) {
        reportInfrastructureFailure(ctx, "Could not start RAM-test workers", "unknown exception");
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }
    deadline.finish();

    ctx.requestStop();
    if (monitor.joinable()) monitor.join();

    ConsoleDisplay::get().setTestingActive(false);
    ctx.finishProgress();

    auto end = std::chrono::steady_clock::now();
    result.hard_errors = ctx.total_hard_errors.load(std::memory_order_relaxed);
    result.soft_errors = ctx.total_soft_errors.load(std::memory_order_relaxed);
    result.unverified_errors = ctx.total_unverified_errors.load(std::memory_order_relaxed);
    result.bytes_tested = ctx.total_bytes.load(std::memory_order_relaxed);
    result.cycles_completed = scheduler.minimum() / enabled.size();
    for (const auto& line : timings.summary(seq, configs, threads, chunk_regions.size(), chunk_regions.front().size,
                                            std::chrono::duration<double>(end - start).count())) {
        LOG_INFO("%s", line.c_str());
    }
    for (const auto& line : timings.functionSummary(seq, configs)) LOG_INFO("%s", line.c_str());
    LOG_INFO("%s", idle_stats.summary().c_str());
    LOG_INFO("Coverage: %llu complete cycles across every memory chunk",
             static_cast<unsigned long long>(result.cycles_completed));
    result.duration_seconds = std::chrono::duration<double>(end - start).count();
    result.infrastructure_failure = ctx.hasInfrastructureFailure();
    result.infrastructure_error = ctx.getInfrastructureFailureMessage();
    // Fixed precedence keeps the reason deterministic when two limits coincide.
    if (result.infrastructure_failure) result.stop_reason = "infrastructure failure";
    else if (config.cycles && result.cycles_completed >= config.cycles) result.stop_reason = "cycles";
    else if (deadline.expired()) result.stop_reason = "time limit";
    else if (config.halt_on_error && result.total_errors()) result.stop_reason = "halt on error";
    else result.stop_reason = "stop request"; // Ctrl+C, console close or a caller's stop
    LOG_INFO("Run end: reason=%s elapsed=%.1fs time-limit=%s complete-cycles=%llu cycle-limit=%u",
             result.stop_reason.c_str(), result.duration_seconds, formatTimeLimit(config.time_limit_seconds).c_str(),
             static_cast<unsigned long long>(result.cycles_completed), config.cycles);

    return result;
}

void TestEngine::requestStop() {
    g_stop_requested.store(true, std::memory_order_release);
}

#ifdef TESTSMEM4U_TESTING
void TestEngine::clearStopRequestForTesting() {
    g_stop_requested.store(false, std::memory_order_release);
}
#endif

} // namespace testsmem4u
