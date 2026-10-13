#include "TestEngine.h"
#include "Logger.h"
#include "Platform.h"
#include "ConfigManager.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <csignal>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <exception>
#include <limits>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <conio.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <termios.h>
#include <fcntl.h>
#endif

#include "RunConfiguration.h"
namespace testsmem4u {
Config makeDefaultConfig(const PlatformInfo& plat) {
    Config config;
    config.memory_window_mb = 0;
    config.memory_window_percent = 85;
    config.cores = plat.cpu_cores > 0 ? plat.cpu_cores : 1;
    config.cycles = 3;
    config.halt_on_error = true;
    config.use_locked_memory = true;
    config.use_large_pages = true;
    config.debug_mode = false;
    config.preset_file = kDefaultPresetPath;
    return config;
}

bool prepareConfigForRun(Config& config, const PlatformInfo& plat,
                                uint64_t& sizing_ram, uint32_t& requested_window_mb,
                                std::string& error) {
    uint32_t available_cores = plat.cpu_cores > 0 ? plat.cpu_cores : 1;
    if (config.cores == 0 || config.cores > available_cores) {
        config.cores = available_cores;
    }

    if (config.memory_window_mb > 0) {
        config.memory_window_percent = 0;
    } else if (config.memory_window_percent == 0) {
        config.memory_window_percent = 85;
    } else if (config.memory_window_percent > 100) {
        config.memory_window_percent = 100;
    }

    if (config.preset_file.empty()) config.preset_file = kDefaultPresetPath;
    config.preset = loadPreset(config.preset_file);
    if (!config.preset.valid) {
        error = "Invalid preset '" + config.preset_file + "': " + config.preset.validation_error;
        return false;
    }
    if (config.preset.test_configs.empty()) {
        error = "Failed to load preset '" + config.preset_file + "'.";
        return false;
    }

    sizing_ram = getSizingBaselineRAM();
    if (sizing_ram == 0) {
        error = "Unable to detect available system memory for sizing.";
        return false;
    }

    if (config.memory_window_mb == 0) {
        config.memory_window_mb = computeWindowMBFromPercent(
            sizing_ram, config.memory_window_percent, config.use_large_pages);
    }

    requested_window_mb = config.memory_window_mb;
    uint32_t normalized_window_mb = normalizeWindowMBForLargePages(
        config.memory_window_mb, config.use_large_pages);
    if (normalized_window_mb != 0) {
        config.memory_window_mb = normalized_window_mb;
    }

    if (config.memory_window_mb == 0) {
        error = "Memory window resolved to 0 MB. Increase the requested memory or disable large pages.";
        return false;
    }

    uint64_t max_safe_bytes = Platform::getMaxTestableMemory(sizing_ram, 100);
    if (max_safe_bytes > 0) {
        uint64_t requested_bytes = static_cast<uint64_t>(config.memory_window_mb) * size_t{1024} * 1024;
        if (requested_bytes > max_safe_bytes) {
            std::ostringstream ss;
            ss << "Requested memory window (" << config.memory_window_mb
               << " MB) exceeds the safe maximum ("
               << (max_safe_bytes / 1024ULL / 1024ULL)
               << " MB) for this system.";
            error = ss.str();
            return false;
        }
    }

    return true;
}

bool resolveConfiguration(const CliOptions& cli, bool automation_mode,
                                 ConfigResolution& resolution, std::string& error) {
    resolution.platform = Platform::detectPlatform();
    if (resolution.platform.cpu_cores == 0) {
        resolution.platform.cpu_cores = 1;
    }

    resolution.config_path = cli.config_path_set ? cli.config_path : kDefaultConfigPath;
    resolution.config_source = cli.no_config ? "disabled (--no-config)" : "defaults";
    resolution.config = makeDefaultConfig(resolution.platform);

    if (!cli.no_config) {
        const auto load_status = loadConfigWithStatus(resolution.config_path, resolution.config);
        if (load_status == ConfigLoadStatus::LOADED) {
            resolution.config_loaded = true;
            resolution.config_source = resolution.config_path;
        } else if (load_status == ConfigLoadStatus::INVALID) {
            error = "Configuration is invalid or unreadable: " + resolution.config_path;
            LOG_ERROR("Configuration resolution stopped; refusing to substitute defaults for an invalid file");
            return false;
        } else if (cli.config_path_set && automation_mode) {
            error = "Config file not found: " + resolution.config_path;
            return false;
        } else if (cli.config_path_set) {
            ConsoleDisplay::get().printError(
                std::string("[!] Config file not found. Using defaults: ") + resolution.config_path);
        }
    }

    if (cli.preset_specified) {
        resolution.config.preset_file = cli.preset_path;
    }
    if (cli.memory_overridden) {
        resolution.config.memory_window_mb = cli.memory_window_mb;
        resolution.config.memory_window_percent = cli.memory_window_percent;
    }
    if (cli.cores_overridden) {
        resolution.config.cores = cli.cores;
    }
    if (cli.cycles_overridden) {
        resolution.config.cycles = cli.cycles;
    }
    if (cli.halt_overridden) {
        resolution.config.halt_on_error = cli.halt_on_error;
    }
    if (cli.locked_memory_overridden) {
        resolution.config.use_locked_memory = cli.use_locked_memory;
    }
    if (cli.large_pages_overridden) {
        resolution.config.use_large_pages = cli.use_large_pages;
    }

    return prepareConfigForRun(
        resolution.config,
        resolution.platform,
        resolution.sizing_ram,
        resolution.requested_window_mb,
        error);
}

void reportMemoryWindowAdjustment(uint32_t requested_mb, uint32_t actual_mb) {
    if (requested_mb == actual_mb) return;

    std::ostringstream ss;
    ss << "Adjusted memory window from " << requested_mb
       << " MB to " << actual_mb << " MB to match large-page granularity.";
    ConsoleDisplay::get().printLine(ss.str());
}

void printConfigSummary(const ConfigResolution& resolution, const CliOptions& cli,
                               bool automation_mode) {
    const Config& config = resolution.config;

    ConsoleDisplay::get().printLine("");
    ConsoleDisplay::get().printLine("[Resolved Configuration]");

    {
        std::ostringstream ss;
        ss << "  Config source:   " << resolution.config_source;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Preset file:     " << config.preset_file;
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (!config.preset.config_name.empty()) {
        std::ostringstream ss;
        ss << "  Preset name:     " << config.preset.config_name;
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (!config.preset.config_author.empty()) {
        std::ostringstream ss;
        ss << "  Preset author:   " << config.preset.config_author;
        ConsoleDisplay::get().printLine(ss.str());
    }
    if ((config.preset.cores > 0 && config.preset.cores != config.cores) ||
        (config.preset.cycles > 0 && config.preset.cycles != config.cycles) ||
        (config.preset.memory_window_mb > 0 && config.preset.memory_window_mb != config.memory_window_mb)) {
        ConsoleDisplay::get().printLine("  Preset note:     Preset Cores/Cycles/Testing Window fields are informational only in this release.");
    }
    {
        std::ostringstream ss;
        if (config.memory_window_percent > 0) {
            ss << "  Memory window:   " << config.memory_window_percent << "% -> "
               << config.memory_window_mb << " MB";
        } else {
            ss << "  Memory window:   " << config.memory_window_mb << " MB";
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (resolution.requested_window_mb != config.memory_window_mb) {
        std::ostringstream ss;
        ss << "  Alignment:       " << resolution.requested_window_mb
           << " MB requested, " << config.memory_window_mb << " MB effective";
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Threads:         " << config.cores;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Cycles:          ";
        if (config.cycles == 0) {
            ss << "infinite";
        } else {
            ss << config.cycles;
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Halt on error:   " << (config.halt_on_error ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Locked memory:   " << (config.use_locked_memory ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Large pages:     " << (config.use_large_pages ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Debug logging:   " << (cli.debug ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Interactive:     " << (automation_mode ? "No" : "Yes");
        ConsoleDisplay::get().printLine(ss.str());
    }
}

} // namespace testsmem4u
