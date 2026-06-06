#include "ConfigManager.h"
#include "Logger.h"
#include "Utils.h"
#include <cctype>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

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

// Recover from a crash during saveConfig: if the .tmp file exists and the
// target file does not, rename .tmp → target. If both exist, remove stale .tmp.
static void recoverOrphanedTempFile(const std::string& filename) {
    std::string tmp_filename = filename + ".tmp";
    std::error_code ec;

    bool tmp_exists = std::filesystem::exists(tmp_filename, ec);
    if (ec || !tmp_exists) return;

    bool target_exists = std::filesystem::exists(filename, ec);
    if (!ec && !target_exists) {
        // Crash after write, before rename: .tmp is the only copy — recover it.
        std::filesystem::rename(tmp_filename, filename, ec);
        if (!ec) {
            LOG_INFO("Recovered saved config from orphaned .tmp file: %s", filename.c_str());
            return;
        }
    }

    // Either both exist (crash during rename) or target exists:
    // remove stale .tmp, the target file is authoritative.
    std::filesystem::remove(tmp_filename, ec);
}

bool saveConfig(const std::string& filename, const Config& config) {
    if (Utils::hasUnsafePathControlCharacters(filename)) {
        LOG_ERROR("Refusing to save config to unsafe path");
        return false;
    }

    // Atomic write: write to temporary file first, then rename over target.
    // This prevents partial/corrupted config files on crash or power loss.
    recoverOrphanedTempFile(filename);

    std::string tmp_filename = filename + ".tmp";
    std::ofstream file(tmp_filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config temp file for writing: %s", tmp_filename.c_str());
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

    file.flush();
    file.close();

#ifdef _WIN32
    // Flush file buffers to storage before renaming
    HANDLE hFile = CreateFileA(tmp_filename.c_str(), GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }

    // Atomic rename: ReplaceFile or MoveFileEx with MOVEFILE_REPLACE_EXISTING
    if (!MoveFileExA(tmp_filename.c_str(), filename.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DWORD err = GetLastError();
        LOG_ERROR("Failed to rename config file: error %lu", err);
        std::remove(tmp_filename.c_str());
        return false;
    }
#else
    // Flush to disk before rename
    if (std::rename(tmp_filename.c_str(), filename.c_str()) != 0) {
        LOG_ERROR("Failed to rename config file: %s", strerror(errno));
        std::remove(tmp_filename.c_str());
        return false;
    }
#endif

    LOG_INFO("Configuration saved to %s", filename.c_str());
    return true;
}

bool loadConfig(const std::string& filename, Config& config) {
    if (Utils::hasUnsafePathControlCharacters(filename)) {
        LOG_ERROR("Refusing to load config from unsafe path");
        return false;
    }

    recoverOrphanedTempFile(filename);

    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    LOG_INFO("Loading configuration from %s", filename.c_str());

    Config parsed = config;
    
    std::string line;
    while (std::getline(file, line)) {
        line = Utils::trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') continue; // Skip sections for now

        std::string key, value;
        if (!Utils::parseKeyValue(line, key, value)) continue;

        if (key == "MemoryWindowPercent") {
            if (!Utils::parseUintStrict(value, parsed.memory_window_percent)) {
                LOG_ERROR("Invalid config value for MemoryWindowPercent in %s", filename.c_str());
                return false;
            }
        } else if (key == "MemoryWindowMB") {
            if (!Utils::parseUintStrict(value, parsed.memory_window_mb)) {
                LOG_ERROR("Invalid config value for MemoryWindowMB in %s", filename.c_str());
                return false;
            }
        } else if (key == "Cores") {
            if (!Utils::parseUintStrict(value, parsed.cores)) {
                LOG_ERROR("Invalid config value for Cores in %s", filename.c_str());
                return false;
            }
        } else if (key == "Cycles") {
            if (!Utils::parseUintStrict(value, parsed.cycles)) {
                LOG_ERROR("Invalid config value for Cycles in %s", filename.c_str());
                return false;
            }
        } else if (key == "UseLockedMemory") {
            if (!parseBoolValue(value, parsed.use_locked_memory)) {
                LOG_ERROR("Invalid config value for UseLockedMemory in %s", filename.c_str());
                return false;
            }
        } else if (key == "UseLargePages") {
            if (!parseBoolValue(value, parsed.use_large_pages)) {
                LOG_ERROR("Invalid config value for UseLargePages in %s", filename.c_str());
                return false;
            }
        } else if (key == "HaltOnError") {
            if (!parseBoolValue(value, parsed.halt_on_error)) {
                LOG_ERROR("Invalid config value for HaltOnError in %s", filename.c_str());
                return false;
            }
        } else if (key == "PresetFile") {
            if (Utils::hasUnsafePathControlCharacters(value)) {
                LOG_ERROR("Invalid config value for PresetFile in %s", filename.c_str());
                return false;
            }
            parsed.preset_file = value;
        }
    }

    file.close();
    config = parsed;
    return true;
}

} // namespace testsmem4u
