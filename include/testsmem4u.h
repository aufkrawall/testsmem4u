// testsmem4u - Memory Testing Utility
// Master header including Types and Platform abstractions

#pragma once

#include "Types.h"
#include "Platform.h"
#include "Logger.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>

namespace testsmem4u {

// Constants for memory testing
constexpr size_t WORD_SIZE = 8;
constexpr size_t DEFAULT_PATTERN_WORDS = 256;
constexpr size_t DEFAULT_VERIFY_WORDS = 256;
constexpr size_t MEMORY_LOCK_CHUNK_SIZE = 64 * 1024 * 1024;
constexpr size_t WORKING_SET_BUFFER = 64 * 1024 * 1024;
constexpr uint64_t DEFAULT_PATTERN = 0xAAAAAAAA55555555ULL;
constexpr uint64_t DEFAULT_PATTERN_ODD = 0xAAAAAAAAAAAAAAAAULL;
constexpr uint64_t DEFAULT_PATTERN_EVEN = 0x5555555555555555ULL;
constexpr uint32_t DEFAULT_PASSES = 2;
constexpr uint32_t DEFAULT_DELAY_MS = 100;

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

    // TestMem5 extended fields
    uint32_t channels = 2;
    uint32_t interleave_type = 1;
    uint32_t reserved_memory_mb = 256;
    uint32_t lock_memory_granularity_mb = 16;
    uint32_t single_dimm_width_bits = 64;
    uint32_t operation_block_bytes = 64;
    uint32_t debug_level = 1;
    int32_t language = -1;
};

// Main configuration
struct Config {
    uint32_t memory_window_mb = 0;
    uint32_t memory_window_percent = 85;
    uint32_t cycles = 0;
    uint32_t cores = 0;
    bool halt_on_error = false;
    bool use_locked_memory = true;
    bool use_large_pages = true;  // Linux hugepages / Windows large pages
    bool debug_mode = false;
    std::string preset_file;
    PresetInfo preset;
};

// Overall test run result
struct RunResult {
    uint64_t hard_errors = 0;
    uint64_t soft_errors = 0;
    uint64_t unverified_errors = 0;  // Errors detected but not re-read verified (due to limits)
    uint64_t bytes_tested = 0;
    uint64_t cycles_completed = 0;
    double duration_seconds = 0.0;
    
    uint64_t total_errors() const { return hard_errors + soft_errors + unverified_errors; }
    uint64_t verified_errors() const { return hard_errors + soft_errors; }
};

// Parse test sequence helper
std::vector<uint32_t> parseTestSequence(const std::string& sequence);

// Preset file operations
PresetInfo loadPreset(const std::string& filepath);
std::vector<std::string> listPresets(const std::string& directory);

// UI / Wizard
Config runConfigWizard();

} // namespace testsmem4u
