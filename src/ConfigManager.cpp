#include "ConfigManager.h"
#include "InputSpec.h"
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
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
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

constexpr const char* kConfigEndMarker = "; End of configuration";

struct ParsedConfigMetadata {
    bool saw_settings_section = false;
    bool saw_end_marker = false;
    bool saw_memory_window_percent = false;
    bool saw_memory_window_mb = false;
    bool saw_cores = false;
    bool saw_cycles = false;
    bool saw_time_limit_seconds = false;
    bool saw_use_locked_memory = false;
    bool saw_use_large_pages = false;
    bool saw_halt_on_error = false;
    bool saw_preset_file = false;

    bool hasCompleteStructure() const {
        return saw_settings_section && saw_end_marker && saw_memory_window_percent &&
               saw_memory_window_mb && saw_cores && saw_cycles && saw_time_limit_seconds &&
               saw_use_locked_memory && saw_use_large_pages && saw_halt_on_error &&
               saw_preset_file;
    }
};

std::string serializeConfig(const testsmem4u::Config& config) {
    std::ostringstream ss;
    ss << "[Settings]\n"
       << "MemoryWindowPercent=" << config.memory_window_percent << "\n"
       << "MemoryWindowMB=" << config.memory_window_mb << "\n"
       << "Cores=" << config.cores << "\n"
       << "Cycles=" << config.cycles << "\n"
       << "TimeLimitSeconds=" << config.time_limit_seconds << "\n"
       << "UseLockedMemory=" << (config.use_locked_memory ? "1" : "0") << "\n"
       << "UseLargePages=" << (config.use_large_pages ? "1" : "0") << "\n"
       << "HaltOnError=" << (config.halt_on_error ? "1" : "0") << "\n"
       << "PresetFile=" << config.preset_file << "\n"
       << kConfigEndMarker << "\n";
    return ss.str();
}

bool parseConfigStream(std::istream& file, const std::string& label,
                       testsmem4u::Config& config, ParsedConfigMetadata& meta) {
    testsmem4u::Config parsed = config;
    std::string line;
    while (std::getline(file, line)) {
        line = testsmem4u::Utils::trim(line);
        if (line.empty()) continue;
        if (line == kConfigEndMarker) {
            meta.saw_end_marker = true;
            continue;
        }
        if (meta.saw_end_marker) {
            meta.saw_end_marker = false;
        }
        if (line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') {
            if (line == "[Settings]") {
                meta.saw_settings_section = true;
            }
            continue;
        }

        std::string key, value;
        if (!testsmem4u::Utils::parseKeyValue(line, key, value)) continue;

        if (key == "MemoryWindowPercent") {
            if (!testsmem4u::Utils::parseUintStrict(value, parsed.memory_window_percent)) {
                testsmem4u::Logger::get().error("Invalid config value for MemoryWindowPercent in %s", label.c_str());
                return false;
            }
            meta.saw_memory_window_percent = true;
        } else if (key == "MemoryWindowMB") {
            if (!testsmem4u::Utils::parseUintStrict(value, parsed.memory_window_mb)) {
                testsmem4u::Logger::get().error("Invalid config value for MemoryWindowMB in %s", label.c_str());
                return false;
            }
            meta.saw_memory_window_mb = true;
        } else if (key == "Cores") {
            if (!testsmem4u::Utils::parseUintStrict(value, parsed.cores)) {
                testsmem4u::Logger::get().error("Invalid config value for Cores in %s", label.c_str());
                return false;
            }
            meta.saw_cores = true;
        } else if (key == "Cycles") {
            if (!testsmem4u::Utils::parseUintStrict(value, parsed.cycles)) {
                testsmem4u::Logger::get().error("Invalid config value for Cycles in %s", label.c_str());
                return false;
            }
            meta.saw_cycles = true;
        } else if (key == "TimeLimitSeconds") {
            uint32_t seconds = 0;
            if (!testsmem4u::Utils::parseUintStrict(value, seconds) || seconds > testsmem4u::kMaxTimeLimitSeconds) {
                testsmem4u::Logger::get().error("Invalid config value for TimeLimitSeconds in %s", label.c_str());
                return false;
            }
            parsed.time_limit_seconds = seconds;
            meta.saw_time_limit_seconds = true;
        } else if (key == "UseLockedMemory") {
            if (!parseBoolValue(value, parsed.use_locked_memory)) {
                testsmem4u::Logger::get().error("Invalid config value for UseLockedMemory in %s", label.c_str());
                return false;
            }
            meta.saw_use_locked_memory = true;
        } else if (key == "UseLargePages") {
            if (!parseBoolValue(value, parsed.use_large_pages)) {
                testsmem4u::Logger::get().error("Invalid config value for UseLargePages in %s", label.c_str());
                return false;
            }
            meta.saw_use_large_pages = true;
        } else if (key == "HaltOnError") {
            if (!parseBoolValue(value, parsed.halt_on_error)) {
                testsmem4u::Logger::get().error("Invalid config value for HaltOnError in %s", label.c_str());
                return false;
            }
            meta.saw_halt_on_error = true;
        } else if (key == "PresetFile") {
            if (testsmem4u::Utils::hasUnsafePathControlCharacters(value)) {
                testsmem4u::Logger::get().error("Invalid config value for PresetFile in %s", label.c_str());
                return false;
            }
            parsed.preset_file = value;
            meta.saw_preset_file = true;
        }
    }

    if (file.bad() || (file.fail() && !file.eof())) {
        testsmem4u::Logger::get().error("Configuration read failed: %s", label.c_str());
        return false;
    }
    config = parsed;
    return true;
}

} // namespace

namespace testsmem4u {

// Recover from a crash during saveConfig only when the orphaned .tmp file is a
// complete, valid file produced by saveConfig (otherwise discard it).
static void recoverOrphanedTempFile(const std::string& filename) {
    const std::string tmp_filename = filename + ".tmp";
    std::error_code ec;

    const auto tmp_link_status = std::filesystem::symlink_status(tmp_filename, ec);
    if (tmp_link_status.type() == std::filesystem::file_type::not_found &&
        (!ec || ec == std::errc::no_such_file_or_directory)) {
        return;
    }
    if (ec) {
        LOG_WARN("Config recovery: unable to inspect temp file %s: %s", tmp_filename.c_str(), ec.message().c_str());
        return;
    }
    if (tmp_link_status.type() != std::filesystem::file_type::regular) {
        LOG_WARN("Removing non-regular config temp entry: %s", tmp_filename.c_str());
        if (tmp_link_status.type() != std::filesystem::file_type::directory) {
            std::filesystem::remove(tmp_filename, ec);
        }
        return;
    }

    std::error_code target_ec;
    const auto target_link_status = std::filesystem::symlink_status(filename, target_ec);
    const bool target_missing =
        target_link_status.type() == std::filesystem::file_type::not_found &&
        (!target_ec || target_ec == std::errc::no_such_file_or_directory);
    if (!target_missing) {
        if (target_ec) {
            LOG_WARN("Config recovery: unable to inspect target %s: %s", filename.c_str(), target_ec.message().c_str());
            return;
        }
        LOG_DEBUG("Config recovery: discarding stale .tmp because target exists: %s", tmp_filename.c_str());
        std::filesystem::remove(tmp_filename, ec);
        return;
    }

    std::ifstream tmp_file(tmp_filename);
    Config candidate;
    ParsedConfigMetadata meta;
    const bool complete = tmp_file.is_open() &&
                          parseConfigStream(tmp_file, tmp_filename, candidate, meta) &&
                          meta.hasCompleteStructure();
    tmp_file.close();
    if (!complete) {
        LOG_WARN("Discarding incomplete or corrupt config temp file: %s "
                 "(settings=%s cycles=%s time-limit=%s end-marker=%s)",
                 tmp_filename.c_str(),
                 meta.saw_settings_section ? "yes" : "no",
                 meta.saw_cycles ? "yes" : "no",
                 meta.saw_time_limit_seconds ? "yes" : "no",
                 meta.saw_end_marker ? "yes" : "no");
        std::filesystem::remove(tmp_filename, ec);
        return;
    }

    std::filesystem::rename(tmp_filename, filename, ec);
    if (!ec) {
        LOG_INFO("Recovered complete saved config from orphaned .tmp file: %s", filename.c_str());
        return;
    }
    LOG_WARN("Failed to promote complete config temp file %s: %s",
             tmp_filename.c_str(), ec.message().c_str());
    std::filesystem::remove(tmp_filename, ec);
}

bool saveConfig(const std::string& filename, const Config& config) {
    if (Utils::hasUnsafePathControlCharacters(filename)) {
        LOG_ERROR("Refusing to save config to unsafe path");
        return false;
    }
    if (Utils::hasUnsafePathControlCharacters(config.preset_file)) {
        LOG_ERROR("Refusing to save config with unsafe PresetFile path");
        return false;
    }

    // Atomic write: write to temporary file first, then rename over target.
    // Any failure removes .tmp and preserves any existing target config.
    recoverOrphanedTempFile(filename);

    const std::string tmp_filename = filename + ".tmp";
    std::error_code pre_ec;
    const auto tmp_status = std::filesystem::symlink_status(tmp_filename, pre_ec);
    if (!pre_ec && tmp_status.type() != std::filesystem::file_type::not_found) {
        if (tmp_status.type() == std::filesystem::file_type::directory ||
            tmp_status.type() == std::filesystem::file_type::symlink) {
            LOG_ERROR("Refusing to overwrite non-regular config temp path: %s", tmp_filename.c_str());
            return false;
        }
    }

    const std::string payload = serializeConfig(config);
    {
        std::ofstream file(tmp_filename, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open config temp file for writing: %s", tmp_filename.c_str());
            return false;
        }
        file.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        file.flush();
        const bool write_ok = !file.fail() && !file.bad();
        file.close();
        if (!write_ok || file.fail() || file.bad()) {
            LOG_ERROR("Failed to write or flush config temp file %s (disk full, permission, or size limit); "
                      "previous configuration preserved.", tmp_filename.c_str());
            std::error_code remove_ec;
            std::filesystem::remove(tmp_filename, remove_ec);
            return false;
        }
    }

#ifdef _WIN32
    HANDLE hFile = CreateFileA(tmp_filename.c_str(), GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open config temp file for disk flush: error %lu", GetLastError());
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }
    const bool flushed = FlushFileBuffers(hFile) != 0;
    const DWORD flush_err = flushed ? 0 : GetLastError();
    CloseHandle(hFile);
    if (!flushed) {
        LOG_ERROR("Failed to flush config temp file buffers to disk: error %lu", flush_err);
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }

    if (!MoveFileExA(tmp_filename.c_str(), filename.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DWORD err = GetLastError();
        LOG_ERROR("Failed to rename config file: error %lu", err);
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }
#else
    const int fd = ::open(tmp_filename.c_str(), O_RDWR);
    if (fd < 0) {
        LOG_ERROR("Failed to open config temp file for fsync: %s", std::strerror(errno));
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }
    if (::fsync(fd) != 0 && errno != EINVAL && errno != ENOTSUP) {
        const int sync_err = errno;
        ::close(fd);
        LOG_ERROR("Failed to fsync config temp file: %s", std::strerror(sync_err));
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }
    if (::close(fd) != 0) {
        LOG_ERROR("Failed to close config temp file after fsync: %s", std::strerror(errno));
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }

    if (std::rename(tmp_filename.c_str(), filename.c_str()) != 0) {
        LOG_ERROR("Failed to rename config file: %s", std::strerror(errno));
        std::error_code remove_ec;
        std::filesystem::remove(tmp_filename, remove_ec);
        return false;
    }
#endif

    LOG_INFO("Configuration saved to %s", filename.c_str());
    return true;
}

ConfigLoadStatus loadConfigWithStatus(const std::string& filename, Config& config) {
    if (Utils::hasUnsafePathControlCharacters(filename)) {
        LOG_ERROR("Refusing to load config from unsafe path");
        return ConfigLoadStatus::INVALID;
    }

    recoverOrphanedTempFile(filename);

    // Some standard libraries can open a directory and report EOF rather than
    // a read error. Reject non-files before opening (also avoids blocking FIFOs).
    std::error_code ec;
    const auto link_status = std::filesystem::symlink_status(filename, ec);
    if (link_status.type() == std::filesystem::file_type::not_found &&
        (!ec || ec == std::errc::no_such_file_or_directory)) {
        LOG_DEBUG("Optional configuration is missing: %s", filename.c_str());
        return ConfigLoadStatus::NOT_FOUND;
    }
    if (ec || !std::filesystem::is_regular_file(std::filesystem::status(filename, ec)) || ec) {
        LOG_ERROR("Configuration is not a readable regular file: %s", filename.c_str());
        return ConfigLoadStatus::INVALID;
    }

    std::ifstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Cannot open configuration for reading: %s", filename.c_str());
        return ConfigLoadStatus::INVALID;
    }

    LOG_INFO("Loading configuration from %s", filename.c_str());

    ParsedConfigMetadata meta;
    if (!parseConfigStream(file, filename, config, meta)) {
        return ConfigLoadStatus::INVALID;
    }
    file.close();
    LOG_DEBUG("Configuration parsed successfully: %s", filename.c_str());
    return ConfigLoadStatus::LOADED;
}

bool loadConfig(const std::string& filename, Config& config) {
    return loadConfigWithStatus(filename, config) == ConfigLoadStatus::LOADED;
}

} // namespace testsmem4u
