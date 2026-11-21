#pragma once
#include "CgroupMemoryLimit.h"

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

void testStopBeforeRunIsKept() {
    // Ctrl+C or a console close during the startup countdown or wizard reaches
    // the shutdown handler before runTests. runTests used to clear the request,
    // so the whole suite ran and a second Ctrl+C force-quit without results.
    Config config;
    config.memory_window_mb = 1;
    config.cores = 1;
    config.cycles = 1;
    config.preset.test_sequence = "0";
    TestConfig test;
    test.function = "SimpleTest";
    config.preset.test_configs.emplace(0, test);
    bool allocated = false;
    TestEngine::requestStop();
    const auto result = TestEngine::runTests(config, [&](size_t, bool, bool) -> MemoryGuard {
        allocated = true;
        return MemoryGuard();
    });
    TestEngine::clearStopRequestForTesting();
    expect(!allocated && result.bytes_tested == 0 && result.cycles_completed == 0 && !result.infrastructure_failure,
           "A stop requested before the run starts is kept: nothing is allocated or tested");
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

void testRunExitCodeContracts() {
    Config finite_cycles{};
    finite_cycles.cycles = 1;

    RunResult completed{};
    completed.bytes_tested = 1024;
    completed.cycles_completed = 1;
    completed.stop_reason = "cycles";
    expect(resolveRunExitCode(finite_cycles, completed) == 0, "Completed finite cycle run exits 0");

    Config finite_timed{};
    finite_timed.time_limit_seconds = 60;
    RunResult timed_done{};
    timed_done.bytes_tested = 1024;
    timed_done.stop_reason = "time limit";
    expect(resolveRunExitCode(finite_timed, timed_done) == 0, "Completed time-limited run exits 0");

    RunResult stopped_zero{};
    stopped_zero.stop_reason = "stop request";
    expect(resolveRunExitCode(finite_cycles, stopped_zero) == 2,
           "Interrupted finite run with zero verified bytes exits 2");

    RunResult stopped_early{};
    stopped_early.bytes_tested = 1024;
    stopped_early.stop_reason = "stop request";
    expect(resolveRunExitCode(finite_cycles, stopped_early) == 2,
           "Interrupted finite cycle run before completion exits 2");
    expect(resolveRunExitCode(finite_timed, stopped_early) == 2,
           "Interrupted time-limited run before time limit exits 2");

    RunResult pre_start_stop{};
    expect(resolveRunExitCode(finite_cycles, pre_start_stop) == 2,
           "Stop before testing started exits 2");

    Config infinite{};
    expect(resolveRunExitCode(infinite, stopped_zero) == 2,
           "Infinite run interrupted with zero verified bytes exits 2");
    expect(resolveRunExitCode(infinite, stopped_early) == 0,
           "Infinite run stopped cleanly after verifying memory with zero errors exits 0");

    RunResult stopped_with_error = stopped_early;
    stopped_with_error.hard_errors = 1;
    expect(resolveRunExitCode(finite_cycles, stopped_with_error) == 1,
           "Interrupted run that already detected errors exits 1");

    RunResult infra = completed;
    infra.infrastructure_failure = true;
    expect(resolveRunExitCode(finite_cycles, infra) == 2, "Infrastructure failure exits 2");
}

void testMemoryLimitAnd32BitSizing() {
    using namespace testsmem4u::cgroup_limit;
    auto mapReader = [](const std::map<std::string, std::string>& files) {
        return [&files](const std::string& path, std::string& out) -> bool {
            const auto it = files.find(path);
            if (it == files.end()) return false;
            out = it->second;
            return true;
        };
    };

    const std::string mountinfo =
        "28 22 0:25 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n"
        "29 22 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";

    // cgroup v2: parent slice holds memory.max while leaf says "max".
    {
        const std::map<std::string, std::string> files{
            {"/sys/fs/cgroup/memory.max", "max\n"},
            {"/sys/fs/cgroup/system.slice/memory.max", "805306368\n"}, // 768 MiB
            {"/sys/fs/cgroup/system.slice/test.service/memory.max", "max\n"},
        };
        const uint64_t limit = resolveCgroupMemoryLimit(
            "0::/system.slice/test.service\n", mountinfo, mapReader(files));
        expect(limit == uint64_t{768} * 1024 * 1024,
               "cgroup v2 inherits tighter parent-slice memory.max when leaf is max");
    }

    // cgroup v2 with cgroupns=host (mount root strips container prefix).
    {
        const std::string ns_mountinfo =
            "40 22 0:25 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        const std::map<std::string, std::string> files{
            {"/sys/fs/cgroup/memory.max", "536870912\n"}, // 512 MiB
        };
        const uint64_t limit = resolveCgroupMemoryLimit(
            "0::/docker/abc\n", ns_mountinfo, mapReader(files));
        expect(limit == uint64_t{512} * 1024 * 1024,
               "cgroup v2 resolves host-mounted container root without duplicating path");
    }

    // cgroup v1: ignores huge sentinel and reads hierarchical_memory_limit.
    {
        const std::map<std::string, std::string> files{
            {"/sys/fs/cgroup/memory/memory.limit_in_bytes", "9223372036854771712\n"},
            {"/sys/fs/cgroup/memory/app/memory.limit_in_bytes", "9223372036854771712\n"},
            {"/sys/fs/cgroup/memory/app/memory.stat", "cache 0\nhierarchical_memory_limit 805306368\n"},
        };
        const uint64_t limit = resolveCgroupMemoryLimit(
            "4:memory:/app\n", mountinfo, mapReader(files));
        expect(limit == uint64_t{768} * 1024 * 1024,
               "cgroup v1 reads hierarchical_memory_limit and ignores kernel unlimited sentinel");
    }

    // Unbounded cgroup files leave limit unlimited.
    {
        const std::map<std::string, std::string> files{
            {"/sys/fs/cgroup/memory.max", "max\n"},
            {"/sys/fs/cgroup/user.slice/memory.max", "max\n"},
        };
        expect(resolveCgroupMemoryLimit("0::/user.slice\n", mountinfo, mapReader(files)) == kUnlimitedMemory,
               "Unbounded cgroups report unlimited memory");
    }

    // 32-bit mappable cap stays below 2 GiB (PTRDIFF_MAX) and fits alignment,
    // while percentage sizing clamps smoothly instead of overflowing size_t.
    const uint64_t max_lp = Platform::getMaxMappableMemory(true);
    const uint64_t max_std = Platform::getMaxMappableMemory(false);
    if (sizeof(size_t) == 4) {
        expect(max_lp < (uint64_t{2} << 30) && max_std < (uint64_t{2} << 30) && max_lp <= max_std,
               "32-bit mappable limit stays strictly below 2 GiB ptrdiff_t ceiling");
        const uint32_t pct_mb = computeWindowMBFromPercent(uint64_t{16} << 30, 85, true, 512);
        expect(pct_mb > 0 && static_cast<uint64_t>(pct_mb) * 1024ULL * 1024ULL <= max_lp,
               "32-bit percentage sizing on >=4 GiB host caps cleanly to mappable memory");
    } else {
        expect(max_lp == std::numeric_limits<uint64_t>::max() &&
                   max_std == std::numeric_limits<uint64_t>::max(),
               "64-bit builds have no 32-bit addressable cap");
    }
    expect(Platform::getTotalSystemRAM() > 0, "Total system RAM query succeeds");
}
