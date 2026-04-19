#include "testsmem4u.h"
#include "Logger.h"
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cerrno>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#endif

namespace testsmem4u {

static bool hasUnsafePathCharacters(const std::string& path) {
    return path.empty() ||
           path.find('\0') != std::string::npos ||
           path.find('\x1b') != std::string::npos;
}

PresetInfo loadPreset(const std::string& filepath) {
    PresetInfo preset;
    auto invalidate = [&](const std::string& message) {
        if (preset.valid) {
            preset.valid = false;
            preset.validation_error = message;
        }
        LOG_ERROR("Invalid preset '%s': %s", filepath.c_str(), message.c_str());
    };

    if (hasUnsafePathCharacters(filepath)) {
        invalidate("preset path contains unsafe characters");
        return preset;
    }

    LOG_INFO("Loading preset file: %s", filepath.c_str());

    std::ifstream file(filepath);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open preset file: %s", filepath.c_str());
        return preset;
    }

    std::string line;
    uint32_t line_number = 0;
    uint32_t current_test = UINT32_MAX;

    while (std::getline(file, line)) {
        line_number++;
        line = Utils::trim(line);

        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                std::string section = Utils::trim(line.substr(1, end - 1));

                if (section.size() > 4 && section.substr(0, 4) == "Test") {
                    std::string test_num_str = section.substr(4);
                    uint32_t parsed_test = 0;
                    if (Utils::parseUintStrict(test_num_str, parsed_test) && parsed_test < 256) {
                        current_test = parsed_test;
                        preset.test_configs[current_test] = TestConfig();
                        preset.test_configs[current_test].test_number = static_cast<uint8_t>(current_test);
                    } else {
                        current_test = UINT32_MAX;
                        invalidate("invalid test section header at line " + std::to_string(line_number));
                    }
                } else {
                    current_test = UINT32_MAX;
                }
            }
            continue;
        }

        std::string key, value;
        if (!Utils::parseKeyValue(line, key, value)) continue;

        auto parseUintField = [&](uint32_t& target) {
            uint32_t parsed = 0;
            if (!Utils::parseUintStrict(value, parsed)) {
                invalidate("invalid numeric value for '" + key + "' at line " + std::to_string(line_number));
                return false;
            }
            target = parsed;
            return true;
        };

        auto parseHexField = [&](uint64_t& target) {
            uint64_t parsed = 0;
            if (!Utils::parseHexStrict(value, parsed)) {
                invalidate("invalid hexadecimal value for '" + key + "' at line " + std::to_string(line_number));
                return false;
            }
            target = parsed;
            return true;
        };

        if (key == "Config Name") {
            preset.config_name = value;
            LOG_INFO("Preset name: %s", value.c_str());
        } else if (key == "Config Author") {
            preset.config_author = value;
            LOG_INFO("Preset author: %s", value.c_str());
        } else if (key == "Cores") {
            parseUintField(preset.cores);
        } else if (key == "Tests") {
            parseUintField(preset.tests);
        } else if (key == "Time (%)") {
            if (current_test == UINT32_MAX) {
                parseUintField(preset.time_percent);
            }
        } else if (key == "Cycles") {
            parseUintField(preset.cycles);
        } else if (key == "Testing Window Size (Mb)" || key == "Memory Window Size") {
            parseUintField(preset.memory_window_mb);
        } else if (key == "Test Sequence") {
            preset.test_sequence = value;
        } else if (key == "Language") {
            uint32_t parsed = 0;
            if (Utils::parseUintStrict(value, parsed)) {
                preset.language = static_cast<int32_t>(parsed);
            } else if (Utils::trim(value) == "-1") {
                preset.language = -1;
            } else {
                invalidate("invalid numeric value for '" + key + "' at line " + std::to_string(line_number));
            }
        } else if (key == "Channels") {
            parseUintField(preset.channels);
        } else if (key == "Interleave Type") {
            parseUintField(preset.interleave_type);
        } else if (key == "Reserved Memory for Windows (Mb)") {
            parseUintField(preset.reserved_memory_mb);
        } else if (key == "Lock Memory Granularity (Mb)") {
            parseUintField(preset.lock_memory_granularity_mb);
        } else if (key == "Single DIMM width, bits") {
            parseUintField(preset.single_dimm_width_bits);
        } else if (key == "Operation Block, byts") {
            parseUintField(preset.operation_block_bytes);
        } else if (key == "Debug Level") {
            parseUintField(preset.debug_level);
        }

        if (current_test != UINT32_MAX && preset.test_configs.count(current_test)) {
            TestConfig& tc = preset.test_configs[current_test];

            if (key == "Enable") {
                uint32_t parsed = 0;
                if (parseUintField(parsed)) tc.enabled = (parsed != 0);
            } else if (key == "Time (%)") {
                parseUintField(tc.time_percent);
            } else if (key == "Function") {
                tc.function = value;
                if (!tc.function.empty() && !isKnownTestFunctionName(tc.function)) {
                    invalidate("unknown Function='" + tc.function + "' in [Test" + std::to_string(current_test) + "]");
                }
                LOG_DEBUG("Test %u function: %s", current_test, value.c_str());
            } else if (key == "Pattern Mode") {
                uint32_t parsed = 0;
                if (parseUintField(parsed)) tc.pattern_mode = static_cast<uint8_t>(parsed);
            } else if (key == "Pattern Param0") {
                parseHexField(tc.pattern_param0);
            } else if (key == "Pattern Param1") {
                parseHexField(tc.pattern_param1);
            } else if (key == "Parameter") {
                parseUintField(tc.parameter);
            } else if (key == "Test Block Size (Mb)" || key == "Block Size") {
                parseUintField(tc.block_size_mb);
            }
        }
    }

    file.close();

    std::vector<uint32_t> sequence = parseTestSequence(preset.test_sequence);
    if (sequence.empty()) {
        invalidate("preset has an empty or invalid Test Sequence");
    }

    bool has_enabled_test = false;
    for (uint32_t test_id : sequence) {
        auto it = preset.test_configs.find(test_id);
        if (it == preset.test_configs.end()) {
            invalidate("Test Sequence references undefined [Test" + std::to_string(test_id) + "]");
            break;
        }
        if (it->second.function.empty()) {
            invalidate("[Test" + std::to_string(test_id) + "] is missing Function=");
            break;
        }
        if (!isKnownTestFunctionName(it->second.function)) {
            invalidate("[Test" + std::to_string(test_id) + "] uses unsupported Function='" + it->second.function + "'");
            break;
        }
        if (it->second.enabled) has_enabled_test = true;
    }

    if (!preset.test_configs.empty() && !has_enabled_test) {
        invalidate("preset enables no runnable tests in its Test Sequence");
    }

    LOG_INFO("Preset loaded: %u tests, %u cycles, window=%u MB",
             preset.tests, preset.cycles, preset.memory_window_mb);
    LOG_INFO("Test sequence: %s", preset.test_sequence.c_str());

    return preset;
}

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
                for (size_t i = 0; i < ext.size(); i++) ext[i] = static_cast<char>(tolower(ext[i]));
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
                for (size_t i = 0; i < ext.size(); i++) ext[i] = static_cast<char>(tolower(ext[i]));
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
