#pragma once

#include "testsmem4u.h"
#include "Platform.h"
#include <string>

namespace testsmem4u {
inline constexpr const char* kProgramName = "testsmem4u";
inline constexpr const char* kProgramVersion = "1.8";
inline constexpr const char* kDefaultConfigPath = "config.ini";
inline constexpr const char* kDefaultPresetPath = "default.cfg";

struct CliOptions {
    bool show_help = false;
    bool show_version = false;
    bool debug = false;
    bool no_elevation = false;
    bool non_interactive = false;
    bool no_pause = false;
    bool list_presets = false;
    bool show_config = false;
    bool dry_run = false;
    bool no_config = false;
    bool aggressive_defrag = false;

    bool config_path_set = false;
    bool preset_specified = false;
    bool memory_overridden = false;
    bool cores_overridden = false;
    bool cycles_overridden = false;
    bool halt_overridden = false;
    bool locked_memory_overridden = false;
    bool large_pages_overridden = false;

    std::string config_path = kDefaultConfigPath;
    std::string preset_path;
    uint32_t memory_window_mb = 0;
    uint32_t memory_window_percent = 0;
    uint32_t cores = 0;
    uint32_t cycles = 0;
    bool halt_on_error = false;
    bool use_locked_memory = true;
    bool use_large_pages = true;

    bool hasRuntimeOverrides() const {
        return memory_overridden || cores_overridden || cycles_overridden ||
               halt_overridden || locked_memory_overridden || large_pages_overridden;
    }

    bool requestsDirectRun() const {
        return preset_specified || hasRuntimeOverrides() || show_config || dry_run;
    }
};

struct ConfigResolution {
    Config config;
    PlatformInfo platform = {};
    uint64_t sizing_ram = 0;
    uint32_t requested_window_mb = 0;
    bool config_loaded = false;
    std::string config_path = kDefaultConfigPath;
    std::string config_source = "defaults";
};


bool parseUint32Strict(const std::string& value, uint32_t& result);
bool parseUintOrDefault(const std::string& str, uint32_t& result, uint32_t default_val);
void printVersion();
void printUsage();
int printPresetList(const std::string& directory);
bool parseCliOptions(int argc, char* argv[], CliOptions& options, std::string& error);
Config makeDefaultConfig(const PlatformInfo& plat);
bool prepareConfigForRun(Config& config, const PlatformInfo& plat, uint64_t& sizing_ram, uint32_t& requested_window_mb, std::string& error);
bool resolveConfiguration(const CliOptions& cli, bool automation_mode, ConfigResolution& resolution, std::string& error);
void reportMemoryWindowAdjustment(uint32_t requested_mb, uint32_t actual_mb);
void printConfigSummary(const ConfigResolution& resolution, const CliOptions& cli, bool automation_mode);
Config runConfigWizard();
uint64_t getSizingBaselineRAM();
uint32_t normalizeWindowMBForLargePages(uint32_t memory_window_mb, bool use_large_pages);
uint32_t computeWindowMBFromPercent(uint64_t sizing_ram, uint32_t percent, bool use_large_pages);
} // namespace testsmem4u
