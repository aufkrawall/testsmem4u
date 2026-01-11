// Preset file loader for testsmem4u
// Parses memory test configuration files

#include "testsmem4u.h"
#include "Logger.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

namespace testsmem4u {

// Trim whitespace from string
static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

// Parse a key=value line
static bool parseKeyValue(const std::string& line, std::string& key, std::string& value) {
    size_t pos = line.find('=');
    if (pos == std::string::npos) return false;
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

// Parse hexadecimal value (with or without 0x prefix)
static uint64_t parseHex(const std::string& str) {
    std::string s = trim(str);
    if (s.empty()) return 0;
    
    // Remove 0x prefix if present
    if (s.size() > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
        s = s.substr(2);
    }
    
    try {
        return std::stoull(s, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

// Parse decimal value
static uint32_t parseUint(const std::string& str) {
    std::string s = trim(str);
    if (s.empty()) return 0;
    
    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

// Load a preset file
PresetInfo loadPreset(const std::string& filepath) {
    PresetInfo preset;
    
    LOG_INFO("Loading preset file: %s", filepath.c_str());
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open preset file: %s", filepath.c_str());
        return preset;
    }
    
    std::string line;
    uint32_t current_test = UINT32_MAX;
    
    while (std::getline(file, line)) {
        line = trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        
        // Check for section headers
        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                std::string section = trim(line.substr(1, end - 1));
                
                // Parse test section [Test0], [Test1], etc.
                if (section.rfind("Test", 0) == 0) {
                    std::string test_num_str = section.substr(4);
                    try {
                        current_test = static_cast<uint32_t>(std::stoul(test_num_str));
                        if (current_test < 256) {
                            preset.test_configs[current_test] = TestConfig();
                            preset.test_configs[current_test].test_number = static_cast<uint8_t>(current_test);
                        } else {
                            current_test = UINT32_MAX;
                        }
                    } catch (...) {
                        current_test = UINT32_MAX;
                    }
                } else {
                    current_test = UINT32_MAX;
                }
            }
            continue;
        }
        
        // Parse key=value pairs
        std::string key, value;
        if (!parseKeyValue(line, key, value)) continue;
        
        // Main section keys
        if (key == "Config Name") {
            preset.config_name = value;
            LOG_INFO("Preset name: %s", value.c_str());
        } else if (key == "Config Author") {
            preset.config_author = value;
            LOG_INFO("Preset author: %s", value.c_str());
        } else if (key == "Cores") {
            preset.cores = parseUint(value);
        } else if (key == "Tests") {
            preset.tests = parseUint(value);
        } else if (key == "Time (%)") {
            if (current_test == UINT32_MAX) {
                preset.time_percent = parseUint(value);
            }
        } else if (key == "Cycles") {
            preset.cycles = parseUint(value);
        } else if (key == "Testing Window Size (Mb)" || key == "Memory Window Size") {
            preset.memory_window_mb = parseUint(value);
        } else if (key == "Test Sequence") {
            preset.test_sequence = value;
        }
        
        // Per-test section keys
        if (current_test != UINT32_MAX && preset.test_configs.count(current_test)) {
            TestConfig& tc = preset.test_configs[current_test];
            
            if (key == "Enable") {
                // If Enable=0, we could skip this test, but keep it for now
            } else if (key == "Time (%)") {
                tc.time_percent = parseUint(value);
            } else if (key == "Function") {
                tc.function = value;
                LOG_DEBUG("Test %u function: %s", current_test, value.c_str());
            } else if (key == "Pattern Mode") {
                tc.pattern_mode = static_cast<uint8_t>(parseUint(value));
            } else if (key == "Pattern Param0") {
                tc.pattern_param0 = parseHex(value);
            } else if (key == "Pattern Param1") {
                tc.pattern_param1 = parseHex(value);
            } else if (key == "Parameter") {
                tc.parameter = parseUint(value);
            } else if (key == "Test Block Size (Mb)" || key == "Block Size") {
                tc.block_size_mb = parseUint(value);
            }
        }
    }
    
    file.close();
    
    LOG_INFO("Preset loaded: %u tests, %u cycles, window=%u MB",
             preset.tests, preset.cycles, preset.memory_window_mb);
    LOG_INFO("Test sequence: %s", preset.test_sequence.c_str());
    
    return preset;
}

// List available preset files in a directory
std::vector<std::string> listPresets(const std::string& directory) {
    std::vector<std::string> presets;
    
#ifdef _WIN32
    std::string search_path = directory + "\\*.cfg";
    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path.c_str(), &find_data);
    
    if (handle != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = find_data.cFileName;
            if (filename.size() > 4) {
                std::string ext = filename.substr(filename.size() - 4);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".cfg") {
                    presets.push_back(filename);
                }
            }
        } while (FindNextFileA(handle, &find_data));
        FindClose(handle);
    }
#else
    DIR* dir = opendir(directory.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            if (filename.size() > 4) {
                std::string ext = filename.substr(filename.size() - 4);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".cfg") {
                    presets.push_back(filename);
                }
            }
        }
        closedir(dir);
    }
#endif
    
    std::sort(presets.begin(), presets.end());
    return presets;
}

} // namespace testsmem4u
