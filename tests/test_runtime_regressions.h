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

void testConfigSaveAndRecoveryContracts() {
    const std::string path = uniqueTempPath("_config_recovery.ini");
    const std::string tmp_path = path + ".tmp";
    std::error_code ec;
    cleanupFile(path);
    cleanupFile(tmp_path);

    // 1. Truncated first-save .tmp ending at Cycles=0 must be discarded, not promoted into an infinite run.
    {
        std::ofstream f(tmp_path);
        f << "[Settings]\nMemoryWindowPercent=0\nMemoryWindowMB=64\nCores=1\nCycles=0\n";
    }
    Config loaded;
    loaded.cycles = 3;
    loaded.time_limit_seconds = 90;
    expect(loadConfigWithStatus(path, loaded) == ConfigLoadStatus::NOT_FOUND,
           "Truncated orphaned .tmp file ending at Cycles=0 is discarded");
    expect(!std::filesystem::exists(path, ec) && !std::filesystem::exists(tmp_path, ec),
           "Incomplete .tmp is deleted rather than promoted to target");
    expect(loaded.cycles == 3 && loaded.time_limit_seconds == 90,
           "Discarding incomplete .tmp preserves caller defaults");

    // 2. .tmp with all keys but missing completion marker must also be rejected.
    {
        std::ofstream f(tmp_path);
        f << "[Settings]\nMemoryWindowPercent=0\nMemoryWindowMB=64\nCores=1\n"
          << "Cycles=0\nTimeLimitSeconds=120\nUseLockedMemory=1\n"
          << "UseLargePages=0\nHaltOnError=1\nPresetFile=default.cfg\n";
    }
    expect(loadConfigWithStatus(path, loaded) == ConfigLoadStatus::NOT_FOUND &&
               !std::filesystem::exists(path, ec) && !std::filesystem::exists(tmp_path, ec),
           "Orphaned .tmp without completion marker is rejected");

    // 3. Complete valid .tmp created by saveConfig is safely recovered when target is absent.
    const std::string src_path = uniqueTempPath("_config_src.ini");
    Config timed;
    timed.memory_window_percent = 0;
    timed.memory_window_mb = 64;
    timed.cores = 2;
    timed.cycles = 0;
    timed.time_limit_seconds = 120;
    timed.use_locked_memory = true;
    timed.use_large_pages = false;
    timed.halt_on_error = false;
    timed.preset_file = "default.cfg";
    expect(saveConfig(src_path, timed), "Helper config save succeeds");
    std::filesystem::rename(src_path, tmp_path, ec);
    expect(!ec, "Renamed complete config into .tmp");
    Config recovered;
    expect(loadConfigWithStatus(path, recovered) == ConfigLoadStatus::LOADED &&
               recovered.cycles == 0 && recovered.time_limit_seconds == 120 &&
               recovered.cores == 2 && !recovered.halt_on_error,
           "Complete orphaned .tmp with end marker is promoted when target is absent");
    expect(std::filesystem::exists(path, ec) && !std::filesystem::exists(tmp_path, ec),
           "Promoted .tmp becomes authoritative target config");

    // 4. Truncated/corrupt .tmp alongside an existing target leaves the good target untouched.
    {
        std::ofstream f(tmp_path);
        f << "[Settings]\nCycles=999\n";
    }
    Config reloaded;
    expect(loadConfigWithStatus(path, reloaded) == ConfigLoadStatus::LOADED &&
               reloaded.cycles == 0 && reloaded.time_limit_seconds == 120 &&
               !std::filesystem::exists(tmp_path, ec),
           "Stale .tmp alongside existing target is removed without altering target");

    // 5. Failed saveConfig preserves the previous good config file.
    Config updated = timed;
    updated.cycles = 7;
    updated.time_limit_seconds = 0;
    std::filesystem::create_directory(tmp_path, ec);
    expect(!ec, "Setup directory collision at .tmp path succeeds");
    expect(!saveConfig(path, updated), "saveConfig fails cleanly when .tmp cannot be opened");
    std::filesystem::remove(tmp_path, ec);
    Config after_fail;
    expect(loadConfigWithStatus(path, after_fail) == ConfigLoadStatus::LOADED &&
               after_fail.cycles == 0 && after_fail.time_limit_seconds == 120,
           "Failed saveConfig leaves the previous good configuration intact");

#ifndef _WIN32
    // 6. Real write/flush truncation via 32-byte RLIMIT_FSIZE preserves existing target and cleans up .tmp.
    const pid_t child = ::fork();
    expect(child >= 0, "fork() succeeds for RLIMIT_FSIZE saveConfig check");
    if (child == 0) {
        std::signal(SIGXFSZ, SIG_IGN);
        struct rlimit rl{};
        rl.rlim_cur = 32;
        rl.rlim_max = 32;
        if (::setrlimit(RLIMIT_FSIZE, &rl) != 0) _exit(2);
        const bool ok = saveConfig(path, updated);
        _exit(ok ? 3 : 0);
    }
    int status = 0;
    const pid_t waited = ::waitpid(child, &status, 0);
    expect(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "saveConfig under 32-byte RLIMIT_FSIZE fails cleanly without returning success");
    Config after_rlimit;
    expect(loadConfigWithStatus(path, after_rlimit) == ConfigLoadStatus::LOADED &&
               after_rlimit.cycles == 0 && after_rlimit.time_limit_seconds == 120 &&
               !std::filesystem::exists(tmp_path, ec),
           "Failed 32-byte write preserves previous good config and removes partial .tmp");
#endif

    cleanupFile(path);
    cleanupFile(tmp_path);
    cleanupFile(src_path);
}

void testPrivilegePromptAndDeferredLog() {
    {
        std::istringstream eof_input("");
        std::ostringstream out;
        bool granted = false;
        expect(!promptMemoryLockPrivilegeOffer(eof_input, out, [&]() { granted = true; return true; }),
               "Closed/EOF stdin must not auto-confirm privilege grant");
        expect(!granted, "Privilege grant callback is not invoked on EOF");
    }
    {
        std::istringstream no_input("no\n");
        std::ostringstream out;
        bool granted = false;
        expect(!promptMemoryLockPrivilegeOffer(no_input, out, [&]() { granted = true; return true; }),
               "Negative answer declines privilege grant");
        expect(!granted, "Privilege grant callback is not invoked when declined");
    }
    {
        std::istringstream yes_input(" yes \n");
        std::ostringstream out;
        bool granted = false;
        expect(promptMemoryLockPrivilegeOffer(yes_input, out, [&]() { granted = true; return true; }) && granted,
               "Explicit affirmative answer invokes privilege grant");
    }
    {
        std::istringstream enter_input("\n");
        std::ostringstream out;
        bool granted = false;
        expect(promptMemoryLockPrivilegeOffer(enter_input, out, [&]() { granted = true; return true; }) && granted,
               "Live empty newline (Enter) invokes default-Yes privilege grant");
    }

    const std::string log_path = uniqueTempPath("_deferred.log");
    {
        std::ofstream prior(log_path);
        prior << "previous results preserved\n";
    }
    auto& log = Logger::get();
    log.init("", LogLevel::INFO, true);
    log.info("dry-run buffered diagnostic");
    log.deinit();
    {
        std::ifstream after_dry(log_path);
        std::string content((std::istreambuf_iterator<char>(after_dry)), std::istreambuf_iterator<char>());
        expect(content == "previous results preserved\n",
               "Deferred logger without attachFile leaves existing log file untouched");
    }

    log.init("", LogLevel::INFO, true);
    log.info("buffered startup line");
    expect(log.attachFile(log_path, true), "attachFile opens deferred log file");
    log.info("attached runtime line");
    log.deinit();
    {
        std::ifstream after_run(log_path);
        std::string content((std::istreambuf_iterator<char>(after_run)), std::istreambuf_iterator<char>());
        expect(content.find("buffered startup line") != std::string::npos &&
                   content.find("attached runtime line") != std::string::npos,
               "attachFile flushes buffered pre-attach messages plus subsequent runtime logs");
    }
    cleanupFile(log_path);
}
