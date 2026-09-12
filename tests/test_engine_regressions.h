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
        uint64_t value = tc.pattern_param0;
        for (size_t i = 0; i < count; ++i) {
            expect(memory[i] == value, "LFSR march: backward writes restore original data");
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
        auto guard = Platform::allocateMemoryRAII(256 * 1024, false, false, true);
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
            const auto result = TestEngine::runRowHammerTest(ctx, hammer, tc, false);
            expect(result.total_errors() == 0 && points == 2,
                   "RowHammer respects one-point budget per polarity and checks victims");
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

    WorkerProgress progress(3);
    progress.publish(0, 50);
    progress.publish(1, 20);
    expect(progress.minimum() == 0, "Progress cannot skip an untested worker");
    progress.publish(2, 4);
    expect(progress.minimum() == 4, "Progress reports minimum full-region coverage");
}

void testIndependentWorkerExecution() {
    const auto platform = Platform::detectPlatform();
    if (platform.cpu_cores < 2) return;
    auto guard = Platform::allocateMemoryRAII(64 * 1024, false, false, true);
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
    bool slow_started = false;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) != "Worker test start") return;
        std::unique_lock<std::mutex> lock(mutex);
        if (part.base == region.base) {
            ++fast_starts;
            cv.notify_all();
            if (fast_starts == 1) cv.wait(lock, [&]() { return slow_started; });
        } else {
            slow_started = true;
            cv.notify_all();
            // Fast worker must cross a test boundary before the slow worker is
            // released. No sleeps, performance threshold, or scheduler timing.
            cv.wait(lock, [&]() { return fast_starts >= 2; });
        }
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1}, configs, &ctx);
    expect(!result.infrastructure_failure && result.total_errors() == 0 && result.cycles_completed == 1,
           "Independent workers complete every region without a phase barrier");
    expect(fast_starts >= 2, "Fast worker proceeds while peer is still in preceding test");
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
