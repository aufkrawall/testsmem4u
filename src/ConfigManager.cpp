#include "ConfigManager.h"
#include "Logger.h"
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>

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

        char* endptr = nullptr;
        if (key == "MemoryWindowPercent") {
            config.memory_window_percent = std::strtoul(value.c_str(), &endptr, 10);
        } else if (key == "MemoryWindowMB") {
            config.memory_window_mb = std::strtoul(value.c_str(), &endptr, 10);
        } else if (key == "Cores") {
            config.cores = std::strtoul(value.c_str(), &endptr, 10);
        } else if (key == "Cycles") {
            config.cycles = std::strtoul(value.c_str(), &endptr, 10);
        } else if (key == "UseLockedMemory") {
            config.use_locked_memory = (value == "1" || value == "true");
        } else if (key == "HaltOnError") {
            config.halt_on_error = (value == "1" || value == "true");
        } else if (key == "PresetFile") {
            config.preset_file = value;
        }
    }

    file.close();
    return true;
}

} // namespace testsmem4u
