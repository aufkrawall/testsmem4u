#pragma once

#include "Platform.h"
#include "testsmem4u.h"
#include "Types.h"
#include <vector>
#include <map>
#include <atomic>

namespace testsmem4u {

struct TestContext {
    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> total_hard_errors{0};
    std::atomic<uint64_t> total_soft_errors{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint32_t> current_cycle{0};
    std::atomic<uint32_t> current_test_idx{0};

    std::mutex status_mutex;
    char active_test_name[64] = "Idle";

    void setActiveTestName(const std::string& name) {
        std::lock_guard<std::mutex> lock(status_mutex);
        size_t len = name.copy(active_test_name, sizeof(active_test_name) - 1);
        active_test_name[len] = '\0';
    }

    std::string getActiveTestName() {
        std::lock_guard<std::mutex> lock(status_mutex);
        return std::string(active_test_name);
    }

    void requestStop() {
        stop_flag.store(true, std::memory_order_release);
    }

    bool shouldStop() {
        return stop_flag.load(std::memory_order_acquire);
    }
};

class TestEngine {
public:
    static RunResult runTests(const Config& config);
    static void requestStop();

    static TestResult runSimpleTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runMirrorMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runMirrorMove128(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runRefreshStable(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runWalkingOnes(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runWalkingZeros(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runLFSRPattern(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runRowHammerTest(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runMovingInversion(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runMovingInversionLFSR(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runMovingInversionWalking(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);
    static TestResult runBlockMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop);

    static size_t verifyAndReport(const uint64_t* ptr, size_t count, size_t start_idx,
                                   uint8_t pattern_mode, uint64_t param0, uint64_t param1,
                                   TestResult& res, TestContext& ctx, const std::string& test_name, bool halt_on_error);

private:
    static RunResult executeSuite(const Config& config, const MemoryRegion& region,
                                  const std::vector<uint32_t>& seq,
                                  const std::map<uint32_t, TestConfig>& configs);

    static TestResult runRegionWork(TestContext& ctx, const MemoryRegion& region, const TestConfig& test_config,
                                    bool halt_on_error);

    static TestResult runTest(TestContext& ctx, const std::string& name, const MemoryRegion& region,
                              const TestConfig& config, bool stop);
};

} // namespace testsmem4u
