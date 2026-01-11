// testsmem4u - Memory Testing Utility
// C++ header definitions

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>

namespace testsmem4u {

// Platform info
struct PlatformInfo {
    char os_name[32];
    char arch[32];
    uint32_t cpu_cores;
    uint32_t page_size;
};

// Test result structure
struct TestResult {
    uint64_t errors = 0;
    uint64_t bytes_tested = 0;
    uint64_t cycles_completed = 0;
};

// Test configuration
struct TestConfig {
    uint8_t test_number = 0;
    std::string function;
    uint8_t pattern_mode = 0;
    uint64_t pattern_param0 = 0;
    uint64_t pattern_param1 = 0;
    uint32_t time_percent = 0;
    uint32_t parameter = 0;
    uint32_t block_size_mb = 0;
};

// Preset file structure
struct PresetInfo {
    std::string config_name;
    std::string config_author;
    uint32_t cores = 0;
    uint32_t tests = 0;
    uint32_t time_percent = 0;
    uint32_t cycles = 0;
    uint32_t memory_window_mb = 0;
    std::string test_sequence;
    std::map<uint32_t, TestConfig> test_configs;
};

// Memory region to test
struct MemoryRegion {
    uint8_t* base = nullptr;
    size_t size = 0;
};

// Main configuration
struct Config {
    uint32_t memory_window_mb = 0;  // 0 = use percentage
    uint32_t memory_window_percent = 85;  // Default 85% of RAM
    uint32_t cycles = 0;  // 0 = infinite
    uint32_t cores = 0;
    bool halt_on_error = false;
    bool use_locked_memory = true;
    bool debug_mode = false;
    std::string preset_file;  // Path to preset file
    PresetInfo preset;  // Loaded preset data
};

// Overall test run result
struct RunResult {
    uint64_t total_errors = 0;
    uint64_t bytes_tested = 0;
    uint64_t cycles_completed = 0;
    double duration_seconds = 0.0;
};

// Platform detection
PlatformInfo detectPlatform();

// Memory allocation
bool allocateMemory(MemoryRegion& region, size_t size, bool lock);
void freeMemory(MemoryRegion& region);

// Parse test sequence
std::vector<uint32_t> parseTestSequence(const std::string& sequence);

// Configuration wizard
Config runConfigWizard();

// Test functions
TestResult runSimpleTest(const MemoryRegion& region, const TestConfig& config, bool stop_on_error);
TestResult runMirrorMove(const MemoryRegion& region, const TestConfig& config, bool stop_on_error);
TestResult runMirrorMove128(const MemoryRegion& region, const TestConfig& config, bool stop_on_error);
TestResult runRefreshStable(const MemoryRegion& region, const TestConfig& config, bool stop_on_error);
TestResult runTest(const std::string& test_name, const MemoryRegion& region,
                   const TestConfig& config, bool stop_on_error);

// Test engine
TestResult runSingleTest(int test_num, const MemoryRegion& region,
                         const TestConfig& test_config, bool halt_on_error);
RunResult runTests(const Config& config);

// Default configurations
std::map<uint32_t, TestConfig> getDefaultTestConfigs();

// Preset file loading
PresetInfo loadPreset(const std::string& filepath);
std::vector<std::string> listPresets(const std::string& directory);

} // namespace testsmem4u
