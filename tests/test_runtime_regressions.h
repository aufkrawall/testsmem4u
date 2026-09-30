#pragma once

void testConfigLoadStatuses() {
    Config config;
    config.memory_window_mb = 128;
    const auto path = uniqueTempPath("_load_status.ini");
    expect(loadConfigWithStatus(path, config) == ConfigLoadStatus::NOT_FOUND,
           "Missing optional config is distinct from invalid config");
    {
        std::ofstream file(path);
        file << "MemoryWindowMB=16\nCores=invalid\n";
    }
    expect(loadConfigWithStatus(path, config) == ConfigLoadStatus::INVALID,
           "Malformed config has invalid status");
    expect(config.memory_window_mb == 128, "Invalid status preserves configuration transaction");
    {
        std::ofstream file(path);
        file << "MemoryWindowMB=16\nCores=1\n";
    }
    expect(loadConfigWithStatus(path, config) == ConfigLoadStatus::LOADED && config.memory_window_mb == 16,
           "Valid config has loaded status and applies values");
    cleanupFile(path);
    std::filesystem::create_directory(path);
    expect(loadConfigWithStatus(path, config) == ConfigLoadStatus::INVALID,
           "Unreadable config directory cannot be treated as a missing file");
    std::filesystem::remove(path);
}

void testPreparationExceptionCleanup() {
    Config config;
    config.memory_window_mb = 1;
    bool caught = false;
    try {
        TestEngine::runTests(config, [](size_t, bool, bool) -> MemoryGuard {
            throw std::runtime_error("injected allocation failure");
        });
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "injected allocation failure";
    }
    expect(caught, "Allocation exception joins preparation thread and reaches caller");

    std::promise<void> entered;
    auto ready = entered.get_future();
    PreparationStatus status([&](uint64_t) {
        entered.set_value();
        throw std::runtime_error("injected preparation display failure");
    });
    ready.get();
    caught = false;
    try {
        status.finish();
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "injected preparation display failure";
    }
    expect(caught, "Preparation display exception is propagated after joining");
}

void testFreshUnlockedRun() {
    Config config;
    config.memory_window_mb = 1;
    config.cores = 1;
    config.cycles = 1;
    config.use_locked_memory = false;
    config.use_large_pages = false;
    config.preset.test_sequence = "0";
    TestConfig test;
    test.function = "SimpleTest";
    test.pattern_mode = 2;
    test.pattern_param1 = 1;
    config.preset.test_configs.emplace(0, test);
    const auto result = TestEngine::runTests(config);
    expect(!result.infrastructure_failure && result.total_errors() == 0 && result.cycles_completed == 1,
           "Fresh unlocked allocation completes its first cycle without prior writes");
    expect(result.bytes_tested >= 1024ULL * 1024ULL, "Fresh unlocked run verifies its entire allocation");
}
