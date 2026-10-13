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
bool parseUintOrDefault(const std::string& str, uint32_t& result, uint32_t default_val) {
    if (str.empty()) {
        result = default_val;
        return true;
    }
    uint32_t parsed = 0;
    if (Utils::parseUintStrict(str, parsed)) {
        result = parsed;
        return true;
    }
    return false;
}

uint64_t getSizingBaselineRAM() {
    uint64_t total_ram = Platform::getTotalSystemRAM();
    if (total_ram != 0) return total_ram;
    return Platform::getAvailableSystemRAM();
}

uint32_t normalizeWindowMBForLargePages(uint32_t memory_window_mb, bool use_large_pages) {
    return memory_pages::normalizeWindow(memory_window_mb, use_large_pages, Platform::getPreferredLargePageSize());
}

uint32_t computeWindowMBFromPercent(uint64_t sizing_ram, uint32_t percent, bool use_large_pages) {
    uint64_t max_mem = Platform::getMaxTestableMemory(sizing_ram, percent);
    uint32_t window_mb = static_cast<uint32_t>(max_mem / 1024 / 1024);
    return normalizeWindowMBForLargePages(window_mb, use_large_pages);
}

Config runConfigWizard(std::istream& input_stream, std::ostream& output_stream) {
    PlatformInfo plat = Platform::detectPlatform();
    Config config = makeDefaultConfig(plat);
    uint64_t total_ram = Platform::getTotalSystemRAM();
    uint64_t sizing_ram = getSizingBaselineRAM();
    if (sizing_ram == 0) sizing_ram = total_ram;

    output_stream << "\n--- testsmem4u Configuration Wizard ---\n";
    output_stream << "Detected " << plat.cpu_cores << " cores, " << (total_ram / 1024 / 1024) << " MB RAM";
    if (sizing_ram > 0 && sizing_ram != total_ram) {
        output_stream << " (" << (sizing_ram / 1024 / 1024) << " MB currently available)";
    }
    output_stream << ".\n\n";

    std::string input;

    output_stream << "Enter memory to test (e.g. '85%', '2048' for MB) [Default: 85%]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);

    if (input.empty()) {
        config.memory_window_percent = 85;
        config.memory_window_mb = 0;
    } else if (input.back() == '%') {
        std::string num_part = input.substr(0, input.size() - 1);
        uint32_t pct;
        if (parseUint32Strict(num_part, pct)) {
            if (pct > 100) pct = 100;
            config.memory_window_percent = pct;
            config.memory_window_mb = 0;
        } else {
            ConsoleDisplay::get().printLine("[!] Invalid percentage value. Using default 85%.");
            config.memory_window_percent = 85;
            config.memory_window_mb = 0;
        }
    } else {
        uint32_t mb;
        if (parseUint32Strict(input, mb) && mb > 0) {
            config.memory_window_mb = mb;
            config.memory_window_percent = 0;
        } else {
            ConsoleDisplay::get().printLine("[!] Invalid MB value. Using default 85%.");
            config.memory_window_mb = 0;
            config.memory_window_percent = 85;
        }
    }

    output_stream << "Enter number of threads to use (1-" << plat.cpu_cores << ") [Default: all]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);

    uint32_t cores;
    if (input.empty()) {
        config.cores = 0; // Persist the all-core policy; resolution chooses the actual count.
    } else if (parseUintOrDefault(input, cores, plat.cpu_cores)) {
        if (cores < 1) cores = 1;
        if (cores > plat.cpu_cores && plat.cpu_cores > 0) cores = plat.cpu_cores;
        config.cores = cores;
    } else {
        config.cores = 0; // Same portable all-core policy as the default.
        output_stream << "[!] Invalid thread count. Using all threads.\n";
    }

    output_stream << "Enter number of cycles (0 for infinite) [Default: 3]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);

    if (!parseUintOrDefault(input, config.cycles, 3)) {
        config.cycles = 3;
        output_stream << "[!] Invalid cycle count. Using default 3.\n";
    }

    output_stream << "Use locked memory? (y/n) [Default: y]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);
    config.use_locked_memory = (input != "n" && input != "N");

    output_stream << "Prefer large pages (hugepages)? (y/n) [Default: y]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);
    config.use_large_pages = (input != "n" && input != "N");

    output_stream << "Halt on detected errors? (y/n) [Default: y]: ";
    std::getline(input_stream, input);
    input = Utils::trim(input);
    config.halt_on_error = (input.empty() || (input != "n" && input != "N"));

    std::vector<std::string> presets = listPresets(".");
    size_t default_choice = 0;
    for (size_t i = 0; i < presets.size(); ++i) {
        if (presets[i] == kDefaultPresetPath) {
            default_choice = i;
            break;
        }
    }

    if (presets.empty()) {
        output_stream << "No preset files were found in the current directory.\n";
        output_stream << "Enter preset file path [" << kDefaultPresetPath << "]: ";
        std::getline(input_stream, input);
        config.preset_file = Utils::trim(input);
    } else {
        output_stream << "Select Preset:\n";
        for (size_t i = 0; i < presets.size(); ++i) {
            output_stream << (i + 1) << ". " << presets[i];
            if (presets[i] == kDefaultPresetPath) {
                output_stream << " (Recommended)";
            }
            output_stream << "\n";
        }
        size_t custom_choice = presets.size() + 1;
        output_stream << custom_choice << ". Custom config file\n";
        output_stream << "Enter selection [" << (default_choice + 1) << "]: ";

        std::getline(input_stream, input);
        input = Utils::trim(input);

        uint32_t selection = 0;
        if (!parseUintOrDefault(input, selection, static_cast<uint32_t>(default_choice + 1))) {
            selection = static_cast<uint32_t>(default_choice + 1);
        }

        if (selection >= 1 && selection <= presets.size()) {
            config.preset_file = presets[selection - 1];
        } else if (selection == custom_choice) {
            output_stream << "Enter preset file path: ";
            std::getline(input_stream, input);
            config.preset_file = Utils::trim(input);
        } else {
            config.preset_file = presets[default_choice];
        }
    }

    if (config.preset_file.empty()) config.preset_file = kDefaultPresetPath;
    config.preset = loadPreset(config.preset_file);
    if (!config.preset.valid) {
        ConsoleDisplay::get().printError(std::string("[!] Invalid preset: ") + config.preset.validation_error);
        config.preset = PresetInfo();
        config.preset_file = kDefaultPresetPath;
        config.preset = loadPreset(config.preset_file);
    }

    LOG_DEBUG("Wizard: memory-percent=%u requested-MB=%u cores=%u (0=all) cycles=%u locked=%s large-pages=%s halt=%s",
              config.memory_window_percent, config.memory_window_mb, config.cores, config.cycles,
              config.use_locked_memory ? "yes" : "no", config.use_large_pages ? "yes" : "no",
              config.halt_on_error ? "yes" : "no");

    return config;
}

} // namespace testsmem4u
