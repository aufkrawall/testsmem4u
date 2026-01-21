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
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#endif

namespace testsmem4u {

static std::string trim(const std::string& str) {
    size_t start = 0;
    while (start < str.size() && (str[start] == ' ' || str[start] == '\t' || str[start] == '\r' || str[start] == '\n')) start++;
    if (start >= str.size()) return "";
    size_t end = str.size() - 1;
    while (end > start && (str[end] == ' ' || str[end] == '\t' || str[end] == '\r' || str[end] == '\n')) end--;
    return str.substr(start, end - start + 1);
}

static bool parseKeyValue(const std::string& line, std::string& key, std::string& value) {
    size_t pos = line.find('=');
    if (pos == std::string::npos) return false;
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

static uint64_t parseHex(const std::string& str) {
    std::string s = trim(str);
    if (s.empty()) return 0;

    if (s.size() > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
        s = s.substr(2);
    }

    try {
        return std::stoull(s, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

static uint32_t parseUint(const std::string& str) {
    std::string s = trim(str);
    if (s.empty()) return 0;

    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

static bool isPathTraversalAttempt(const std::string& path) {
    // Check for null bytes or other suspicious characters
    if (path.find('\0') != std::string::npos || path.find('\x1b') != std::string::npos) {
        return true;
    }

    // Normalize path separators for consistent checking
    std::string normalized = path;
    for (char& c : normalized) {
        if (c == '\\') c = '/';
    }

    // Check for parent directory references
    if (normalized.find("../") != std::string::npos || normalized.find("/..") != std::string::npos) {
        return true;
    }
    
    // Check for current directory tricks
    if (normalized.find("./") != std::string::npos || normalized.find("/.") != std::string::npos) {
        // But allow single .cfg files like "./config.cfg"
        if (normalized.length() > 2 && (normalized.substr(0, 2) == "./" || normalized.substr(0, 2) == ".\\")) {
            std::string rest = normalized.substr(2);
            if (rest.find('/') != std::string::npos || rest.find("\\") != std::string::npos) {
                return true; // Has additional path separators after ./
            }
        }
    }

    // Check for absolute paths
    if (!path.empty() && (path[0] == '/' || path[0] == '\\')) {
        return true;
    }

    // Check for Windows drive letter paths
    if (path.size() >= 2 && path[1] == ':') {
        return true;
    }

    // Check for UNC paths (Windows network paths)
    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\') {
        return true;
    }

    // Check for URL-encoded traversal attempts
    if (path.find("%2e%2e%2f") != std::string::npos || path.find("%252e%252e%252f") != std::string::npos) {
        return true;
    }
    if (path.find("..%2f") != std::string::npos || path.find("%2e%2e") != std::string::npos) {
        return true;
    }

    return false;
}

static bool isValidPath(const std::string& path_str) {
    if (path_str.empty()) return false;

    if (isPathTraversalAttempt(path_str)) {
        return false;
    }

    std::string full_path;
#ifdef _WIN32
    char buffer[MAX_PATH];
    if (GetFullPathNameA(path_str.c_str(), MAX_PATH, buffer, nullptr) == 0) {
        return false;
    }
    full_path = buffer;

    char current_dir[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, current_dir) == 0) {
        return false;
    }

    std::string full_current = current_dir;
    if (full_current.back() != '\\') full_current += '\\';

    if (full_path.size() < full_current.size()) return false;
    if (full_path.substr(0, full_current.size()) != full_current) return false;
#else
    char buffer[PATH_MAX];
    if (realpath(path_str.c_str(), buffer) == nullptr) {
        return false;
    }
    full_path = buffer;

    char current_dir[PATH_MAX];
    if (getcwd(current_dir, sizeof(current_dir)) == nullptr) {
        return false;
    }

    std::string full_current = current_dir;
    if (full_current.back() != '/') full_current += '/';

    if (full_path.size() < full_current.size()) return false;
    if (full_path.substr(0, full_current.size()) != full_current) return false;
#endif

    return true;
}

PresetInfo loadPreset(const std::string& filepath) {
    PresetInfo preset;

    if (!isValidPath(filepath)) {
        LOG_ERROR("Invalid preset path (path traversal attempt or invalid path): %s", filepath.c_str());
        return preset;
    }

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

        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                std::string section = trim(line.substr(1, end - 1));

                if (section.size() > 4 && section.substr(0, 4) == "Test") {
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

        std::string key, value;
        if (!parseKeyValue(line, key, value)) continue;

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
        } else if (key == "Language") {
            preset.language = static_cast<int32_t>(parseUint(value));
        } else if (key == "Channels") {
            preset.channels = parseUint(value);
        } else if (key == "Interleave Type") {
            preset.interleave_type = parseUint(value);
        } else if (key == "Reserved Memory for Windows (Mb)") {
            preset.reserved_memory_mb = parseUint(value);
        } else if (key == "Lock Memory Granularity (Mb)") {
            preset.lock_memory_granularity_mb = parseUint(value);
        } else if (key == "Single DIMM width, bits") {
            preset.single_dimm_width_bits = parseUint(value);
        } else if (key == "Operation Block, byts") {
            preset.operation_block_bytes = parseUint(value);
        } else if (key == "Debug Level") {
            preset.debug_level = parseUint(value);
        }

        if (current_test != UINT32_MAX && preset.test_configs.count(current_test)) {
            TestConfig& tc = preset.test_configs[current_test];

            if (key == "Enable") {
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
