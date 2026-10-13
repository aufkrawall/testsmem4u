#pragma once

void expectProgressMatches(const TestContext& ctx, const TestResult& result, const std::string& name) {
    const auto totals = ctx.progressSnapshot();
    expect(totals.bytes_tested == result.bytes_tested &&
           totals.hard_errors == result.hard_errors &&
           totals.soft_errors == result.soft_errors &&
           totals.unverified_errors == result.unverified_errors, name + ": exact published totals");
}

void testLiveProgressAndCancellation() {
    auto guard = Platform::allocateMemoryRAII(size_t{64} * 1024, false, false, true);
    expect(guard.valid(), "Live progress allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 1;
    config.cycles = 1;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "MovingInversion";
    tc.time_percent = 1;
    tc.parameter = 150;
    for (uint64_t gib : {uint64_t{0}, uint64_t{5000}, uint64_t{8000}}) {
        for (unsigned outcome = 0; outcome < 3; ++outcome) {
            TestContext ctx;
            const uint64_t initial = gib * (uint64_t{1} << 30);
            ctx.total_bytes.store(initial);
            unsigned repetitions = 0;
            unsigned forward_passes = 0;
            ctx.phase_hook = [&](const char* phase, const MemoryRegion&) {
                const std::string name = phase;
                if (name == "March filled") ++repetitions;
                if (name != "March inverted") return;
                ++forward_passes;
                const uint64_t completed_passes = uint64_t{3} * (repetitions - 1) + 1;
                expect(ctx.progressSnapshot().bytes_tested == initial + completed_passes * region.size,
                       "March publishes verified bytes before invocation return");
                if (outcome == 1 && repetitions == 10) ctx.requestStop();
                if (outcome == 2) throw std::runtime_error("injected failure after verification");
            };
            const auto result = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &ctx);
            const uint64_t passes = outcome == 0 ? 450 : outcome == 1 ? 28 : 1;
            expect(result.bytes_tested == initial + passes * region.size,
                   "Completion, cancellation and exception preserve exact bytes without double counting");
            expect(result.cycles_completed == (outcome == 0 ? 1U : 0U), "Partial run credits no complete cycle");
            expect(result.infrastructure_failure == (outcome == 2) && result.total_errors() == 0,
                   "Injected exception remains an infrastructure failure");
            expect(forward_passes == (outcome == 0 ? 150U : outcome == 1 ? 10U : 1U),
                   "Long test executes the expected repetitions");
            expect(ctx.total_bytes.load() == result.bytes_tested && ctx.worker_progress.empty(),
                   "Joined progress folds into context totals and releases worker slots");
        }
    }

    TestContext failed;
    failed.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) == "March filled") *reinterpret_cast<uint64_t*>(part.base) ^= 1;
        if (std::string(phase) == "Verified block") throw std::runtime_error("injected failure after mismatch");
    };
    const auto failure = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &failed);
    expect(failure.infrastructure_failure && failure.bytes_tested == 4096 &&
           failure.unverified_errors == 1 && failure.cycles_completed == 0,
           "Worker exception preserves completed verification and its observed mismatch");
}

void testAllKernelProgress() {
    auto guard = Platform::allocateMemoryRAII(size_t{256} * 1024, false, false, true);
    expect(guard.valid(), "Kernel progress allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    TestConfig tc;
    tc.parameter = 1;
    tc.pattern_param0 = 0xAAAAAAAAAAAAAAAAULL;
    tc.pattern_param1 = 0x9E3779B97F4A7C15ULL;
    for (const std::string name : {"SimpleTest", "MirrorMove", "MirrorMove128", "RefreshStable",
                                  "WalkingOnes", "WalkingZeros", "LFSRPattern", "MovingInversion",
                                  "MovingInversionLFSR", "MovingInversionWalking", "BlockMove",
                                  "RowHammer", "RandomAccess", "Modulo20"}) {
        TestContext ctx;
        auto time = std::chrono::steady_clock::time_point{};
        ctx.retention_clock = [&]() { time += std::chrono::milliseconds(1); return time; };
        uint64_t previous_bytes = 0;
        unsigned observations = 0;
        ctx.phase_hook = [&](const char* phase, const MemoryRegion&) {
            if (std::string(phase) != "Verified block") return;
            const uint64_t bytes = ctx.progressSnapshot().bytes_tested;
            expect(bytes > previous_bytes, name + ": progress visible after each verified block");
            previous_bytes = bytes;
            ++observations;
        };
        const auto result = TestEngine::runTest(ctx, name, region, tc, false);
        expect(result.total_errors() == 0 && observations > 0, name + ": valid kernel work ran");
        expectProgressMatches(ctx, result, name);
    }

    // A failing nested background test must not be counted again by retention.
    TestContext ctx;
    auto time = std::chrono::steady_clock::time_point{};
    ctx.retention_clock = [&]() { time += std::chrono::milliseconds(1); return time; };
    bool injected = false;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (!injected && std::string(phase) == "Simple filled") {
            *reinterpret_cast<uint64_t*>(part.base) ^= 1;
            injected = true;
        }
    };
    tc.parameter = 4;
    const auto result = TestEngine::runRefreshStable(ctx, region, tc, true);
    expect(injected && ctx.shouldStop() && result.total_errors() == 1,
           "Nested retention error stops the run");
    expectProgressMatches(ctx, result, "Nested retention cancellation");
}

void testSubBlockAndConcurrentProgress() {
    auto guard = Platform::allocateMemoryRAII(size_t{2} * 1024 * 1024, false, false, true);
    expect(guard.valid(), "Sub-block progress allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 1;
    config.cycles = 1;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "SimpleTest";
    tc.time_percent = 2;
    tc.parameter = 2;
    tc.block_size_mb = 1;
    TestContext ctx;
    uint64_t previous = 0;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion&) {
        if (std::string(phase) != "Verified block") return;
        const uint64_t bytes = ctx.progressSnapshot().bytes_tested;
        expect(bytes == previous + size_t{1024} * 1024, "Configured sub-block publishes once per verification");
        previous = bytes;
    };
    const auto result = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &ctx);
    expect(result.bytes_tested == uint64_t{4} * region.size && result.bytes_tested == previous &&
           result.cycles_completed == 1, "Internal/external repeats and configured sub-blocks have exact totals");

    if (Platform::detectPlatform().cpu_cores < 2) return;
    region.size = size_t{64} * 1024;
    config.cores = 2;
    tc.time_percent = 1;
    tc.parameter = 1;
    tc.block_size_mb = 0;
    TestContext concurrent;
    std::mutex mutex;
    std::condition_variable cv;
    bool verified = false;
    bool observed = false;
    std::atomic<uint64_t> checked_bytes{0};
    concurrent.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        const std::string name = phase;
        if (name == "Verified block") checked_bytes.fetch_add(part.size);
        std::unique_lock<std::mutex> lock(mutex);
        if (part.base == region.base && name == "Verified block" && !verified) {
            verified = true;
            cv.notify_all();
            cv.wait(lock, [&]() { return observed; });
        } else if (part.base != region.base && name == "Worker test start" && !observed) {
            cv.wait(lock, [&]() { return verified; });
            expect(concurrent.progressSnapshot().bytes_tested > 0,
                   "Peer observes verified bytes while originating worker is still inside its test");
            observed = true;
            cv.notify_all();
        }
    };
    const auto multi = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &concurrent);
    expect(observed && multi.cycles_completed == 1 && multi.bytes_tested == checked_bytes.load(),
           "Concurrent worker snapshots and final totals agree without aggregate double counting");
}
