#pragma once

// Current-test progress: worker loops, configured sub-blocks and the outermost
// kernel's repetitions combine into one per-worker step for the status line.

bool stepNear(uint32_t actual, double fraction) {
    const double expected = fraction * ProgressCounters::kStepScale;
    return std::abs(static_cast<double>(actual) - expected) <= 1.0;
}

void testStepProgressContracts() {
    {
        TestContext ctx, other;
        ProgressCounters counters;
        ProgressBinding binding(&ctx, counters);
        ProgressBinding::beginLoop(&ctx, 1, 4);
        expect(stepNear(counters.step(), 0.25), "Loop start publishes its share of the test");
        ProgressBinding::beginBlock(&ctx, 1, 2);
        expect(stepNear(counters.step(), 3.0 / 8), "Sub-block start subdivides the current loop");
        {
            RepetitionProgress outer(ctx, 10);
            outer.begin(5);
            expect(stepNear(counters.step(), 3.5 / 8), "Kernel repetitions subdivide the current sub-block");
            {
                RepetitionProgress nested(ctx, 3);
                nested.begin(2);
                expect(stepNear(counters.step(), 3.5 / 8), "Nested kernels cannot override the outer kernel");
            }
            outer.begin(6);
            expect(stepNear(counters.step(), 3.6 / 8), "Outer kernel keeps ownership after a nested kernel");
        }
        {
            RepetitionProgress next(ctx, 2);
            next.begin(1);
            expect(stepNear(counters.step(), 3.5 / 8), "Repetition ownership is released after the kernel");
        }
        ProgressBinding::beginLoop(&other, 3, 4);
        expect(stepNear(counters.step(), 3.5 / 8), "Another context cannot update this worker's step");
        ProgressBinding::resetStep(&ctx);
        expect(counters.step() == 0, "Completed tests reset the step before publishing the next position");
        ProgressBinding::beginLoop(&ctx, std::numeric_limits<uint64_t>::max() - 1,
                                   std::numeric_limits<uint64_t>::max());
        expect(counters.step() <= ProgressCounters::kStepScale, "Extreme loop counts stay within the step scale");
    }

    {
        std::vector<ProgressCounters> counters(3);
        WorkerProgress progress(3);
        progress.publish(0, 5);
        progress.publish(1, 4);
        progress.publish(2, 4);
        counters[1].setStep(0.7);
        counters[2].setStep(0.3);
        const auto slowest = findSlowestWorker(progress, counters);
        expect(slowest.worker == 2 && slowest.position == 4 && stepNear(slowest.step, 0.3),
               "Status follows the lowest position, then the least advanced current test");
        expect(findSlowestWorker(WorkerProgress(0), {}).position == 0, "No workers report position zero");
    }

    {
        StatusInfo info;
        info.cycle = 1;
        info.total_cycles = 3;
        info.test_idx = 4;
        info.total_tests = 18;
        info.test_name = "MovingInversion";
        info.test_step = 375000;
        expect(ConsoleDisplay::formatStatus(info, 198).find("T4/18 37% | MovingInversion") != std::string::npos,
               "Status line shows the current test's completed percentage");
    }

    auto guard = Platform::allocateMemoryRAII(size_t{64} * 1024, false, false, true);
    expect(guard.valid(), "Step progress allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 1;
    config.cycles = 1;
    config.preset.time_percent = 100;
    TestConfig simple;
    simple.function = "SimpleTest";
    simple.time_percent = 4;  // max(1, 100 * 4 / 100) = four loops
    TestConfig march;
    march.function = "MovingInversion";
    march.time_percent = 1;
    march.parameter = 150;
    march.pattern_param0 = 0xAAAAAAAAAAAAAAAAULL;
    TestConfig retention;
    retention.function = "RefreshStable";
    retention.time_percent = 1;
    retention.parameter = 1;
    TestContext ctx;
    unsigned fills = 0, marches = 0, holds = 0, active = 0;
    bool steps_match = true;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion&) {
        const std::string name = phase;
        const uint32_t step = ctx.worker_progress[0].step();
        if (name == "Simple fill" && holds == 0) {
            steps_match &= stepNear(step, fills++ / 4.0);
        } else if (name == "March filled") {
            steps_match &= stepNear(step, marches++ / 150.0);
        } else if (name == "Retention held") {
            steps_match &= stepNear(step, holds++ / 4.0);
        } else if (name == "Retention active") {
            ++active;
            steps_match &= stepNear(step, (holds - 1) / 4.0);
        }
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1, 2},
                                                 {{0, simple}, {1, march}, {2, retention}}, &ctx);
    expect(result.cycles_completed == 1 && result.total_errors() == 0 && fills == 4 && marches == 150 &&
           holds == 4 && active > 0, "Step progress suite completes every loop, repetition and retention dwell");
    expect(steps_match, "Worker steps track loops, march repetitions and retention dwells without nested resets");
}
