#include "ConfigManager.h"
#include "Logger.h"
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace {

bool parseBoolValue(const std::string& raw, bool& value) {
    std::string text = testsmem4u::Utils::trim(raw);
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (text == "1" || text == "true" || text == "yes") {
        value = true;
        return true;
    }
    if (text == "0" || text == "false" || text == "no") {
        value = false;
        return true;
    }
    return false;
}

} // namespace

namespace testsmem4u {

// Local helpers removed, using Utils:: instead


bool saveConfig(const std::string& filename, const Config& config) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config file for writing: %s", filename.c_str());
        return false;
    }

    file << "[Settings]\n";
    file << "MemoryWindowPercent=" << config.memory_window_percent << "\n";
    file << "MemoryWindowMB=" << config.memory_window_mb << "\n";
    file << "Cores=" << config.cores << "\n";
    file << "Cycles=" << config.cycles << "\n";
    file << "UseLockedMemory=" << (config.use_locked_memory ? "1" : "0") << "\n";
    file << "UseLargePages=" << (config.use_large_pages ? "1" : "0") << "\n";
    file << "HaltOnError=" << (config.halt_on_error ? "1" : "0") << "\n";
    file << "PresetFile=" << config.preset_file << "\n";

    file.close();
    LOG_INFO("Configuration saved to %s", filename.c_str());
    return true;
}

bool loadConfig(const std::string& filename, Config& config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    LOG_INFO("Loading configuration from %s", filename.c_str());
    
    std::string line;
    while (std::getline(file, line)) {
        line = Utils::trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') continue; // Skip sections for now

        std::string key, value;
        if (!Utils::parseKeyValue(line, key, value)) continue;

        if (key == "MemoryWindowPercent") {
            if (!Utils::parseUintStrict(value, config.memory_window_percent)) {
                LOG_ERROR("Invalid config value for MemoryWindowPercent in %s", filename.c_str());
                return false;
            }
        } else if (key == "MemoryWindowMB") {
            if (!Utils::parseUintStrict(value, config.memory_window_mb)) {
                LOG_ERROR("Invalid config value for MemoryWindowMB in %s", filename.c_str());
                return false;
            }
        } else if (key == "Cores") {
            if (!Utils::parseUintStrict(value, config.cores)) {
                LOG_ERROR("Invalid config value for Cores in %s", filename.c_str());
                return false;
            }
        } else if (key == "Cycles") {
            if (!Utils::parseUintStrict(value, config.cycles)) {
                LOG_ERROR("Invalid config value for Cycles in %s", filename.c_str());
                return false;
            }
        } else if (key == "UseLockedMemory") {
            if (!parseBoolValue(value, config.use_locked_memory)) {
                LOG_ERROR("Invalid config value for UseLockedMemory in %s", filename.c_str());
                return false;
            }
        } else if (key == "UseLargePages") {
            if (!parseBoolValue(value, config.use_large_pages)) {
                LOG_ERROR("Invalid config value for UseLargePages in %s", filename.c_str());
                return false;
            }
        } else if (key == "HaltOnError") {
            if (!parseBoolValue(value, config.halt_on_error)) {
                LOG_ERROR("Invalid config value for HaltOnError in %s", filename.c_str());
                return false;
            }
        } else if (key == "PresetFile") {
            config.preset_file = value;
        }
    }

    file.close();
    return true;
}

} // namespace testsmem4u
