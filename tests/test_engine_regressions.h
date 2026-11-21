#pragma once

void testEngineRegressions() {
    alignas(64) std::array<uint64_t, 2048> memory{};
    auto regionFor = [&](size_t count) {
        MemoryRegion region{};
        region.base = reinterpret_cast<uint8_t*>(memory.data());
        region.size = count * sizeof(uint64_t);
        region.base_offset_bytes = 0x10000;
        return region;
    };
    TestConfig tc;
    tc.parameter = 1;
    tc.pattern_param0 = 0xACE1ACE2DEADBEEFULL;
    tc.pattern_param1 = ~tc.pattern_param0;

    for (size_t count : {1U, 2U, 3U, 7U, 8U, 511U, 512U, 513U, 1027U}) {
        const auto region = regionFor(count);
        TestContext ctx;
        const auto result = TestEngine::runMovingInversionLFSR(ctx, region, tc, false);
        expect(result.total_errors() == 0, "LFSR march: partial reverse blocks do not invent errors");
        expect(result.bytes_tested == count * 8 * 3, "LFSR march: three verified passes");
        uint64_t value = regionSeed(tc.pattern_param0, region.base_offset_bytes, tc.variation, 0);
        for (size_t i = 0; i < count; ++i) {
            expect(memory[i] == simd::lfsrOutput(value), "LFSR march: backward writes restore original data");
            expect(simd::lfsrPrevious(simd::lfsrNext(value)) == value, "LFSR inverse round trip");
            value = simd::lfsrNext(value);
        }
        const auto mirror = TestEngine::runMirrorMove128(ctx, region, tc, false);
        expect(mirror.total_errors() == 0, "Mirror128: bidirectional overlapping moves include odd tails");
        const auto move = TestEngine::runBlockMove(ctx, region, tc, false);
        expect(move.total_errors() == 0, "Block move: non-power-of-two regions and tails");
        const auto modulo = TestEngine::runModulo20(ctx, region, tc, false);
        expect(modulo.total_errors() == 0, "Modulo20 covers partial strides and regions");
        tc.parameter = 101;
        const auto random = TestEngine::runRandomAccess(ctx, region, tc, false);
        expect(random.total_errors() == 0, "Random batches: unique lanes and partial final batches");
        tc.parameter = 1;
    }

    // Kernel samples retain the originally-loaded data, even after a destructive
    // march replaces it. Bounded samples must not bound the mismatch count.
    std::array<uint64_t, 19> expected{};
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = 17 * i;
    for (bool reverse : {false, true}) {
        for (size_t i = 0; i < expected.size(); ++i) memory[i + 1] = expected[i] ^ 1;
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        const size_t found = simd::verify_words(memory.data() + 1, expected.data(), expected.size(),
                                                errors, true, reverse, 3);
        expect(found == expected.size() && errors.size() == 3, "March kernel: bounded samples count all mismatches");
        expect(errors.front().first == (reverse ? expected.size() - 1 : 0), "March kernel: actual reverse traversal");
        for (const auto& error : errors) {
            expect(error.second == (expected[error.first] ^ 1), "March kernel: original observation survives overwrite");
        }
        for (size_t i = 0; i < expected.size(); ++i) {
            expect(memory[i + 1] == ~expected[i], "March kernel: expected complement is written");
        }
    }

    const auto region = regionFor(1027);
    for (const std::string phase : {"LFSR filled", "March filled", "March inverted", "March restored",
                                    "Block moved", "Mirror128 moved", "Random final", "Modulo disturbed"}) {
        TestContext ctx;
        bool injected = false;
        ctx.phase_hook = [&](const char* name, const MemoryRegion& part) {
            if (!injected && name == phase) {
                reinterpret_cast<uint64_t*>(part.base)[part.size / 8 - 1] ^= 1;
                injected = true;
            }
        };
        TestResult result;
        if (phase == "LFSR filled") result = TestEngine::runLFSRPattern(ctx, region, tc, true);
        else if (phase == "Block moved") result = TestEngine::runBlockMove(ctx, region, tc, true);
        else if (phase == "Mirror128 moved") result = TestEngine::runMirrorMove128(ctx, region, tc, true);
        else if (phase == "Modulo disturbed") result = TestEngine::runModulo20(ctx, region, tc, true);
        else if (phase == "Random final") result = TestEngine::runRandomAccess(ctx, region, tc, true);
        else result = TestEngine::runMovingInversionLFSR(ctx, region, tc, true);
        expect(injected && result.total_errors() == 1 && ctx.shouldStop(), "Fault injection: " + phase);
    }

    // A zero pattern is a valid moving-inversion input, not an unset sentinel.
    {
        TestContext ctx;
        TestConfig zero;
        const auto result = TestEngine::runMovingInversion(ctx, region, zero, false);
        expect(result.total_errors() == 0 && memory[0] == 0, "March honors all-zero configuration");
    }

    // Virtual time makes retention tests deterministic without sleeping. The
    // callback verifies held data during each useful background-test operation.
    {
        TestContext ctx;
        auto time = std::chrono::steady_clock::time_point{};
        ctx.retention_clock = [&]() { time += std::chrono::milliseconds(1); return time; };
        MemoryRegion held{};
        uint64_t held_pattern = 0;
        size_t holds = 0;
        size_t active_tests = 0;
        ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
            const std::string name = phase;
            if (name == "Retention held") {
                held = part;
                held_pattern = *reinterpret_cast<const uint64_t*>(part.base);
                ++holds;
            } else if (name == "Retention active") {
                ++active_tests;
                expect(part.base + part.size <= held.base || held.base + held.size <= part.base,
                       "Retention background memory is disjoint");
                const auto* ptr = reinterpret_cast<const uint64_t*>(held.base);
                for (size_t i = 0; i < held.size / 8; ++i) {
                    expect(ptr[i] == held_pattern, "Retention held memory remains untouched");
                }
            }
        };
        tc.parameter = 6;
        const auto result = TestEngine::runRefreshStable(ctx, region, tc, false);
        expect(result.total_errors() == 0 && holds == 4 && active_tests >= 4,
               "Retention covers both halves and polarities with useful active work");
        expect(result.bytes_tested > region.size * 2, "Retention counts active verifications too");
        ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
            if (std::string(phase) == "Retention verify") reinterpret_cast<uint64_t*>(part.base)[0] ^= 1;
        };
        const auto faulty = TestEngine::runRefreshStable(ctx, region, tc, true);
        expect(faulty.total_errors() == 1 && ctx.shouldStop(), "Retention still detects held-region errors");
        tc.parameter = 1;
    }

    // Pre-cancelled calls must not claim planned work as verified coverage.
    {
        TestContext ctx;
        ctx.requestStop();
        expect(TestEngine::runSimpleTest(ctx, region, tc, false).bytes_tested == 0, "Stopped simple: zero coverage");
        expect(TestEngine::runWalkingOnes(ctx, region, tc, false).bytes_tested == 0, "Stopped walking: zero coverage");
        expect(TestEngine::runRandomAccess(ctx, region, tc, false).bytes_tested == 0, "Stopped random: zero coverage");
        expect(TestEngine::runMirrorMove128(ctx, region, tc, false).bytes_tested == 0, "Stopped mirror: zero coverage");
    }

    {
        auto guard = Platform::allocateMemoryRAII(size_t{256} * 1024, false, false, true);
        expect(guard.valid(), "RowHammer regression allocation");
        if (guard.valid()) {
            MemoryRegion hammer{};
            hammer.base = guard.base();
            hammer.size = guard.size();
            TestContext ctx;
            size_t points = 0;
            ctx.phase_hook = [&](const char* phase, const MemoryRegion&) {
                if (std::string(phase) == "RowHammer victim") ++points;
            };
            g_rowhammer_large_page_warning_emitted.store(false);
            hammer.page_coverage = {hammer.size, hammer.size, size_t{2} * 1024 * 1024, true, true, hammer.size};
            // Parameter 1 point per GiB rounds to zero on 256 KiB; the floor is one
            // point per usable stride (all four fit), per victim polarity.
            const auto result = TestEngine::runRowHammerTest(ctx, hammer, tc, false);
            expect(result.total_errors() == 0 && points == size_t{2} * 4,
                   "RowHammer runs one point per usable stride and polarity when the density rounds lower");
            expect(!g_rowhammer_large_page_warning_emitted.load(),
                   "RowHammer trusts allocation-wide coverage measured once instead of re-querying the OS");
            hammer.page_coverage = {};
            TestEngine::runRowHammerTest(ctx, hammer, tc, false);
            expect(g_rowhammer_large_page_warning_emitted.load(),
                   "Unmeasured allocation coverage still produces the RowHammer warning");

            // Regions at or below 24 KiB cannot run any RowHammer stride and must
            // fail closed instead of completing a cycle with zero verified bytes.
            MemoryRegion tiny = hammer;
            tiny.size = size_t{24} * 1024;
            TestContext tiny_ctx;
            const auto tiny_direct = TestEngine::runRowHammerTest(tiny_ctx, tiny, tc, false);
            expect(tiny_ctx.hasInfrastructureFailure() && tiny_direct.bytes_tested == 0,
                   "Direct RowHammer on <=24 KiB fails closed instead of silently skipping");

            Config tiny_cfg;
            tiny_cfg.cores = 4;
            tiny_cfg.cycles = 1;
            tiny_cfg.preset.time_percent = 100;
            TestConfig rh_tc = tc;
            rh_tc.function = "RowHammer";
            rh_tc.time_percent = 1;
            const auto tiny_suite = TestEngine::executeSuite(tiny_cfg, tiny, {0}, {{0, rh_tc}});
            expect(tiny_suite.infrastructure_failure && tiny_suite.cycles_completed == 0 &&
                       tiny_suite.bytes_tested == 0,
                   "Engine fails closed when the whole window is too small for RowHammer");

            // A 64 KiB window with 4 requested workers used to split into 8-12 KiB
            // chunks and credit 1 completed cycle with 0 verified bytes; capping
            // chunks keeps every chunk above 24 KiB so memory is actually tested.
            MemoryRegion small_suite_region = hammer;
            small_suite_region.size = size_t{64} * 1024;
            const auto capped_suite = TestEngine::executeSuite(tiny_cfg, small_suite_region, {0}, {{0, rh_tc}});
            expect(!capped_suite.infrastructure_failure && capped_suite.cycles_completed == 1 &&
                       capped_suite.bytes_tested > 0 && capped_suite.total_errors() == 0,
                   "Multi-worker RowHammer caps chunks above 24 KiB and actually verifies memory");

            expect(maxWorkersForRowHammer(size_t{1024} * 1024, 4096, 2) == 34 &&
                       maxWorkersForRowHammer(size_t{24} * 1024, 4096, 2) == 0,
                   "RowHammer worker cap keeps 1 MiB chunks above 24 KiB and rejects <=24 KiB");
        }
    }

    {
        StatusInfo info;
        info.cycle = 1;
        info.total_cycles = 3;
        info.test_idx = 14;
        info.total_tests = 18;
        info.test_name = std::string(120, 'x');
        info.errors = 42;
        info.elapsed_seconds = 61;
        std::ostringstream output;
        auto* previous = std::cout.rdbuf(output.rdbuf());
        ConsoleDisplay::get().updateStatus(info);
        ConsoleDisplay::get().clearStatus();
        std::cout.rdbuf(previous);
        expect(output.str().find("Err: 42") != std::string::npos &&
               output.str().find("01:01") != std::string::npos,
               "Long test names cannot hide errors or elapsed time");
    }

    // Streaming LFSR fill writes the exact recurrence and returns the next state.
    {
        std::array<uint64_t, 7> filled{};
        const uint64_t next = simd::fill_lfsr(filled.data(), filled.size(), tc.pattern_param0);
        uint64_t value = tc.pattern_param0;
        for (uint64_t word : filled) {
            expect(word == simd::lfsrOutput(value), "fill_lfsr writes the output of consecutive LFSR states");
            value = simd::lfsrNext(value);
        }
        expect(next == value, "fill_lfsr returns the state after the last word");
    }

    expect(randomAccessIterations(0, 50) == 50 && randomAccessIterations(100, 50) == 5000 &&
           randomAccessIterations(101, 50) == 101,
           "RandomAccess Parameter: <=100 passes, larger explicit access count");

    // Short dwells must still sweep the whole active half across windows. With
    // one background chunk per dwell, each 3 MiB active half needs two windows.
    {
        auto guard = Platform::allocateMemoryRAII(size_t{6} * 1024 * 1024, false, false, true);
        expect(guard.valid(), "Retention cursor allocation");
        if (guard.valid()) {
            MemoryRegion big{};
            big.base = guard.base();
            big.size = guard.size();
            TestContext ctx;
            auto time = std::chrono::steady_clock::time_point{};
            ctx.retention_clock = [&]() { time += std::chrono::milliseconds(1); return time; };
            std::set<size_t> active_offsets;
            ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
                if (std::string(phase) == "Retention active") active_offsets.insert(part.base_offset_bytes);
            };
            TestConfig retention = tc;
            retention.parameter = 2;
            const auto result = TestEngine::runRefreshStable(ctx, big, retention, false);
            expect(result.total_errors() == 0 && active_offsets.size() == 4,
                   "Retention background cursor advances across dwell windows");
        }
    }

    // Cross-worker disturbance attribution: any overlap with a peer's RowHammer
    // window is reported; a disturbance that ended earlier, or a test's own
    // hammering, is not.
    {
        TestContext ctx;
        expect(isCrossRegionDisturbanceTest("RowHammer") && !isCrossRegionDisturbanceTest("Modulo20"),
               "Only RowHammer is a cross-region disturbance test");
        {
            DisturbanceWindow observer(ctx, false);
            expect(!observer.overlappedForeignDisturbance(), "No disturbance: no overlap");
            {
                DisturbanceWindow hammer(ctx, true);
                expect(!hammer.overlappedForeignDisturbance(), "Own hammering is not foreign");
            }
            expect(observer.overlappedForeignDisturbance(), "Hammer started during window overlaps");
        }
        {
            DisturbanceWindow hammer(ctx, true);
            DisturbanceWindow observer(ctx, false);
            expect(observer.overlappedForeignDisturbance(), "Hammer active at window start overlaps");
        }
        DisturbanceWindow later(ctx, false);
        expect(!later.overlappedForeignDisturbance(), "Finished hammer does not overlap a later window");
    }

    RegionScheduler progress(3, 3);
    progress.complete(0, 0, 50);
    progress.complete(1, 1, 20);
    expect(progress.minimum() == 0, "Progress cannot skip an untested chunk");
    progress.complete(2, 2, 4);
    expect(progress.minimum() == 4, "Progress reports minimum full-window coverage");
}

void testIndependentWorkerExecution() {
    const auto platform = Platform::detectPlatform();
    if (platform.cpu_cores < 2 || Platform::getNativePageSize() == 0) return;
    const size_t page = Platform::getNativePageSize();
    // Four chunks need four pages: a fixed 64 KiB window gave one worker on
    // 64 KiB-page kernels (deadlocking the hook below) and two chunks on 32 KiB.
    auto guard = Platform::allocateMemoryRAII(std::max(size_t{64} * 1024, 4 * page), false, false, true);
    expect(guard.valid(), "Scheduler test allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 2;
    config.cycles = 1;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "SimpleTest";
    tc.time_percent = 1;
    std::map<uint32_t, TestConfig> configs{{0, tc}, {1, tc}};
    std::mutex mutex;
    std::condition_variable cv;
    unsigned fast_starts = 0;
    bool slow_seen = false;
    std::thread::id slow_thread;
    std::set<std::pair<uint8_t*, size_t>> chunks;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) != "Worker test start") return;
        std::unique_lock<std::mutex> lock(mutex);
        chunks.insert({part.base, part.size});
        if (!slow_seen) {
            // The first worker to start a test holds its chunk until the other
            // worker has started two tests: it must find another idle chunk.
            // No sleeps, performance threshold, or scheduler timing.
            slow_seen = true;
            slow_thread = std::this_thread::get_id();
            cv.wait(lock, [&]() { return fast_starts >= 2; });
        } else if (std::this_thread::get_id() != slow_thread) {
            ++fast_starts;
            cv.notify_all();
        }
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1}, configs, &ctx);
    expect(!result.infrastructure_failure && result.total_errors() == 0 && result.cycles_completed == 1,
           "Workers complete every chunk without a phase barrier");
    expect(fast_starts >= 2, "A free worker takes another idle chunk while its peer still holds one");
    // Two workers get four equal page-aligned chunks that tile the window.
    size_t covered = 0;
    uint8_t* next = region.base;
    bool equal = true;
    for (const auto& [base, size] : chunks) {
        equal &= base == next && size % page == 0 && size + page >= chunks.begin()->second &&
                 size <= chunks.begin()->second;
        next = base + size;
        covered += size;
    }
    expect(chunks.size() == 4 && covered == region.size && equal,
           "Two workers share four equal page-aligned chunks that exactly tile the window");
    TestContext cancelled;
    cancelled.phase_hook = [&](const char*, const MemoryRegion&) { cancelled.requestStop(); };
    const auto stopped = TestEngine::executeSuite(config, region, {0, 1}, configs, &cancelled);
    expect(stopped.cycles_completed == 0, "Mid-test stop does not count an incomplete cycle");
    TestContext failed;
    failed.phase_hook = [&](const char*, const MemoryRegion&) { throw std::runtime_error("injected worker failure"); };
    const auto failure = TestEngine::executeSuite(config, region, {0, 1}, configs, &failed);
    expect(failure.infrastructure_failure && failure.cycles_completed == 0,
           "Worker exception stops peers and joins without termination or deadlock");
}

void testDisabledEntriesAreNotScheduled() {
    const EnabledSequence sequence({1, 3});
    expect(sequence.cycle(5) == 2 && sequence.entry(5, 0) == 3 && sequence.entry(4, 0) == 1 && sequence.startsCycle(4) &&
               !sequence.startsCycle(5),
           "Positions count enabled entries and map back to their sequence index");

    // Disabled entries used to be claimed and released like tests. Each release
    // replaced the worker's just-finished chunk, so a worker that skipped a
    // disabled entry on another chunk could re-claim the chunk it had just
    // tested. Deterministic: the first worker holds its chunk until its peer
    // has started six tests; the peer's other two chunks then sit at the
    // sequence's disabled third entry. No sleeps or timing assumptions.
    const auto platform = Platform::detectPlatform();
    if (platform.cpu_cores < 2 || Platform::getNativePageSize() == 0) return;
    const size_t page = Platform::getNativePageSize();
    auto guard = Platform::allocateMemoryRAII(std::max(size_t{64} * 1024, 4 * page), false, false, true);
    expect(guard.valid(), "Disabled-entry scheduler allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 2;
    config.cycles = 1;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "SimpleTest";
    tc.time_percent = 1;
    TestConfig off = tc;
    off.enabled = false;
    const std::map<uint32_t, TestConfig> configs{{0, tc}, {1, tc}, {2, off}};
    std::mutex mutex;
    std::condition_variable cv;
    std::map<std::thread::id, std::vector<uint8_t*>> starts;
    std::thread::id first;
    bool first_seen = false;
    bool first_restarted = false;
    unsigned peer_starts = 0;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) != "Worker test start") return;
        std::unique_lock<std::mutex> lock(mutex);
        const auto self = std::this_thread::get_id();
        auto& mine = starts[self];
        mine.push_back(part.base);
        if (!first_seen) {
            first_seen = true;
            first = self;
            cv.wait(lock, [&]() { return peer_starts >= 6; });
        } else if (self == first) {
            if (mine.size() == 2) {
                first_restarted = true;
                cv.notify_all();
            }
        } else if (++peer_starts == 6) {
            cv.notify_all();
            cv.wait(lock, [&]() { return first_restarted; });
        }
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1, 2}, configs, &ctx);
    expect(!result.infrastructure_failure && result.total_errors() == 0 && result.cycles_completed == 1,
           "A sequence with a disabled entry completes its cycle");
    const auto& held = starts[first];
    expect(held.size() >= 2 && held[1] != held[0],
           "After a test, a worker takes another idle chunk even when disabled entries follow");
}
