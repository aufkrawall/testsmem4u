#pragma once

// InputSpec.h is included at the top of test_internal.cpp (outside the anonymous namespace).

void testMemoryAndTimeInput() {
    struct Case {
        const char* text;
        uint32_t mb;
        uint32_t percent;
        uint64_t seconds;
    };
    for (const Case& c : {Case{"50MB", 50, 0, 0}, Case{"27GB", 27648, 0, 0}, Case{"50MB30m", 50, 0, 1800},
                          Case{"27GB4h", 27648, 0, 14400}, Case{"85%2h", 0, 85, 7200}, Case{"2048", 2048, 0, 0},
                          Case{"2048m", 2048, 0, 0}, Case{"2048 30m", 2048, 0, 1800}, Case{"8gb1h30m", 8192, 0, 5400},
                          Case{" 16 MB 2h 15m ", 16, 0, 8100}, Case{"1G90s", 1024, 0, 90}}) {
        MemoryTimeInput parsed;
        std::string error;
        expect(parseMemoryAndTime(c.text, parsed, error) && parsed.memory_mb == c.mb &&
                   parsed.memory_percent == c.percent && parsed.time_limit_seconds == c.seconds,
               std::string("Memory/time input parses '") + c.text + "' " + error);
    }
    for (const char* bad : {"", "MB", "0MB", "0%", "27TB", "2048 30", "27GB4x", "27GB0m", "50MB30", "4194304GB",
                            "27GB-1h", "99999999999999999999MB"}) {
        MemoryTimeInput parsed;
        std::string error;
        expect(!parseMemoryAndTime(bad, parsed, error) && !error.empty(),
               std::string("Memory/time input rejects '") + bad + "'");
    }

    uint64_t seconds = 0;
    std::string error;
    expect(parseTimeLimit("4h", seconds, error, false) && seconds == 14400, "Time limit 4h");
    expect(parseTimeLimit("1h30m", seconds, error, false) && seconds == 5400, "Time limit 1h30m");
    expect(parseTimeLimit("45", seconds, error, true) && seconds == 2700, "CLI bare time limit is minutes");
    expect(!parseTimeLimit("45", seconds, error, false), "Wizard time limit needs a unit");
    expect(!parseTimeLimit("1h 45", seconds, error, true), "Only a lone bare number means minutes");
    expect(!parseTimeLimit("9000h", seconds, error, false), "Time limits above one year are rejected");
    expect(formatTimeLimit(14400) == "4h" && formatTimeLimit(5400) == "1h30m" && formatTimeLimit(90) == "1m30s" &&
               formatTimeLimit(3605) == "1h5s" && formatTimeLimit(0) == "none",
           "Time limits print compactly");
}

void testWizardTimeLimit() {
    WizardFixture fixture;
    std::string prompts;
    // Memory plus time: the cycle prompt is skipped (one fewer answer line).
    Config config = fixture.run("50MB30m\n2\ny\nn\nn\n", prompts);
    expect(config.memory_window_mb == 50 && config.memory_window_percent == 0 && config.time_limit_seconds == 1800 &&
               config.cycles == 0 && config.cores == 2 && config.use_locked_memory && !config.use_large_pages &&
               !config.halt_on_error,
           "Wizard '50MB30m' sets 50 MB, a 30 minute limit and no cycle limit");
    expect(prompts.find("Time limit 30m") != std::string::npos &&
               prompts.find("Enter number of cycles") == std::string::npos,
           "Wizard announces the time limit instead of asking for cycles");
    config = fixture.run("27GB4h\n\n\n\n\n", prompts);
    expect(config.memory_window_mb == 27648 && config.time_limit_seconds == 14400 && config.cycles == 0,
           "Wizard '27GB4h' sets 27 GB and a 4 hour limit");
    config = fixture.run("27GB\n\n2\n\n\n\n", prompts);
    expect(config.memory_window_mb == 27648 && config.time_limit_seconds == 0 && config.cycles == 2,
           "Wizard '27GB' keeps the cycle prompt");
    config = fixture.run("27GB4x\n\n\n\n\n\n", prompts);
    expect(config.memory_window_percent == 85 && config.memory_window_mb == 0 && config.time_limit_seconds == 0 &&
               config.cycles == 3 && prompts.find("Unknown time unit") != std::string::npos,
           "Invalid wizard memory/time input falls back to 85% without a limit and says why");

    const auto path = uniqueTempPath("_time.ini");
    config.time_limit_seconds = 14400;
    config.cycles = 0;
    Config loaded;
    expect(saveConfig(path, config) && loadConfig(path, loaded) && loaded.time_limit_seconds == 14400 &&
               loaded.cycles == 0,
           "Saved configuration keeps the time limit");
    {
        std::ofstream file(path);
        file << "TimeLimitSeconds=forever\n";
    }
    expect(loadConfigWithStatus(path, loaded) == ConfigLoadStatus::INVALID, "Invalid saved time limit is rejected");
    cleanupFile(path);
}

void testTimeLimitStopsRun() {
    auto guard = Platform::allocateMemoryRAII(size_t{1024} * 1024, false, false, true);
    expect(guard.valid(), "Time limit allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 2;
    config.cycles = 0;
    config.time_limit_seconds = 1;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "SimpleTest";
    tc.time_percent = 1;
    tc.parameter = 1;
    // Unlimited cycles: only the time limit can end this run.
    TestContext ctx;
    const auto timed = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &ctx);
    expect(!timed.infrastructure_failure && timed.total_errors() == 0 && timed.stop_reason == "time limit" &&
               timed.cycles_completed > 0 && timed.duration_seconds >= 0.99 && timed.duration_seconds < 30.0,
           "A time limit ends an unlimited-cycle run after about that long");

    // Cycles first: the timer must not delay the end of the run.
    config.cycles = 1;
    config.time_limit_seconds = 3600;
    TestContext quick;
    const auto start = std::chrono::steady_clock::now();
    const auto cycled = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &quick);
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    expect(!cycled.infrastructure_failure && cycled.stop_reason == "cycles" && cycled.cycles_completed == 1 &&
               seconds < 30.0,
           "Reaching the cycle count first ends the run without waiting for the time limit");
}
