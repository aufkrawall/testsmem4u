#include "ConfigManager.h"
#include "Logger.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace testsmem4u {

static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static bool parseKeyValue(const std::string& line, std::string& key, std::string& value) {
    size_t pos = line.find('=');
    if (pos == std::string::npos) return false;
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

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
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') continue; // Skip sections for now

        std::string key, value;
        if (!parseKeyValue(line, key, value)) continue;

        try {
            if (key == "MemoryWindowPercent") {
                config.memory_window_percent = std::stoul(value);
            } else if (key == "MemoryWindowMB") {
                config.memory_window_mb = std::stoul(value);
            } else if (key == "Cores") {
                config.cores = std::stoul(value);
            } else if (key == "Cycles") {
                config.cycles = std::stoul(value);
            } else if (key == "UseLockedMemory") {
                config.use_locked_memory = (value == "1" || value == "true");
            } else if (key == "HaltOnError") {
                config.halt_on_error = (value == "1" || value == "true");
            } else if (key == "PresetFile") {
                config.preset_file = value;
            }
        } catch (...) {
            LOG_WARN("Failed to parse config line: %s", line.c_str());
        }
    }

    file.close();
    return true;
}

} // namespace testsmem4u
