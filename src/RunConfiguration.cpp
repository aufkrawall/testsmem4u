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
#include "InputSpec.h"
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

    const uint64_t total_ram = Platform::getTotalSystemRAM();
    const uint64_t process_limit = Platform::getProcessMemoryLimit();
    const bool process_limit_active =
        process_limit != std::numeric_limits<uint64_t>::max() && (total_ram == 0 || process_limit < total_ram);
    sizing_ram = getSizingBaselineRAM();
    if (sizing_ram == 0) {
        error = "Unable to detect available system memory for sizing.";
        return false;
    }

    // Honor the preset's "Reserved Memory for Windows (Mb)" (OS reserve on every
    // platform); it used to be parsed and ignored in favor of a fixed 256 MB.
    const uint32_t reserve_mb = effectiveOsReserveMB(config.preset);
    const uint64_t max_mappable_bytes = Platform::getMaxMappableMemory(config.use_large_pages);
    const std::string process_limit_text = process_limit == std::numeric_limits<uint64_t>::max()
        ? std::string("none")
        : std::to_string(process_limit / 1024 / 1024) + " MB";
    const std::string mappable_cap_text = max_mappable_bytes == std::numeric_limits<uint64_t>::max()
        ? std::string("unlimited")
        : std::to_string(max_mappable_bytes / 1024 / 1024) + " MB";
    LOG_DEBUG("Sizing: host-RAM=%llu MB process-limit=%s sizing-RAM=%llu MB mappable-cap=%s "
              "OS-reserve=%u MB (preset %u MB, minimum %u MB) request=%u MB / %u%%",
              static_cast<unsigned long long>(total_ram / 1024 / 1024),
              process_limit_text.c_str(),
              static_cast<unsigned long long>(sizing_ram / 1024 / 1024),
              mappable_cap_text.c_str(),
              reserve_mb, config.preset.reserved_memory_mb, Platform::kMinOsReserveMB,
              config.memory_window_mb, config.memory_window_percent);
    if (config.preset.reserved_memory_mb < Platform::kMinOsReserveMB) {
        LOG_WARN("Preset reserves %u MB for the OS; keeping the %u MB minimum instead",
                 config.preset.reserved_memory_mb, Platform::kMinOsReserveMB);
    }

    if (config.memory_window_mb == 0) {
        config.memory_window_mb = computeWindowMBFromPercent(
            sizing_ram, config.memory_window_percent, config.use_large_pages, reserve_mb);
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

    const uint64_t max_safe_bytes = Platform::getMaxTestableMemory(sizing_ram, 100, reserve_mb);
    const uint64_t requested_bytes = static_cast<uint64_t>(config.memory_window_mb) * uint64_t{1024} * 1024;
    if (requested_bytes > max_safe_bytes) {
        std::ostringstream ss;
        ss << "Requested memory window (" << config.memory_window_mb
           << " MB) exceeds the safe maximum ("
           << (max_safe_bytes / 1024ULL / 1024ULL)
           << " MB = " << (sizing_ram / 1024ULL / 1024ULL) << " MB "
           << (process_limit_active ? "process memory limit" : "RAM") << " minus the " << reserve_mb
           << " MB OS reserve from the preset's 'Reserved Memory for Windows (Mb)') for this system.";
        error = ss.str();
        return false;
    }
    if (requested_bytes > max_mappable_bytes) {
        std::ostringstream ss;
        ss << "Requested memory window (" << config.memory_window_mb
           << " MB) exceeds this 32-bit build's mappable address-space limit ("
           << (max_mappable_bytes / 1024ULL / 1024ULL)
           << " MB). Use a 64-bit build to test more memory.";
        error = ss.str();
        return false;
    }

    return true;
}

uint32_t effectiveOsReserveMB(const PresetInfo& preset) {
    return std::max(preset.reserved_memory_mb, Platform::kMinOsReserveMB);
}

int resolveRunExitCode(const Config& config, const RunResult& res) {
    if (res.infrastructure_failure) return 2;
    if (res.total_errors() > 0) return 1;
    const bool finite_run = config.cycles > 0 || config.time_limit_seconds > 0;
    const bool interrupted = res.stop_reason == "stop request" || res.stop_reason.empty();
    if (res.bytes_tested == 0 || (finite_run && interrupted)) return 2;
    return 0;
}

bool promptMemoryLockPrivilegeOffer(std::istream& input, std::ostream& output,
                                    const std::function<bool()>& grant_privilege) {
    output << "    [Y/n]: " << std::flush;

    std::string raw_answer;
    if (!std::getline(input, raw_answer)) {
        output << "    No answer received; skipping automatic privilege grant.\n";
        LOG_DEBUG("Privilege setup: input closed; no privilege grant");
        return false;
    }

    std::string answer = Utils::trim(raw_answer);
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (!answer.empty() && answer != "y" && answer != "yes") {
        output << "    Privilege grant declined.\n";
        LOG_DEBUG("Privilege setup: offer declined answer-length=%zu", raw_answer.size());
        return false;
    }

    if (grant_privilege && grant_privilege()) {
        output << "\n[+] Privilege granted successfully!\n"
               << "    PLEASE SIGN OUT AND SIGN BACK IN for the changes to take effect. A reboot is not required.\n"
               << "    The program will now exit.\n";
        return true;
    }

    output << "[-] Failed to grant privilege. You may need to run as Administrator manually.\n";
    return false;
}

bool shouldRelaunchInTerminal(int argc, const CliOptions& cli,
                              bool stdin_tty, bool stdout_tty, bool stderr_tty,
                              bool graphical_session, bool stdout_is_fifo) {
    if (argc > 1 || cli.non_interactive || cli.no_pause || cli.requestsDirectRun()) {
        return false;
    }
    if (!graphical_session || stdin_tty || stdout_tty || stderr_tty || stdout_is_fifo) {
        return false;
    }
    return true;
}

bool relaunchElevatedKeepingStartupLog(Logger& log, const std::function<bool(int&)>& relaunch,
                                       int& child_exit_code) {
    // The elevated child creates testsmem4u.log itself. A deferred logger has no
    // file open, so it need not be shut down first; shutting it down discarded
    // the buffered startup/config/sizing diagnostics, leaving them out of the log
    // whenever elevation was declined or unavailable and this process continued.
    if (log.isFileAttached()) {
        LOG_ERROR("Elevation: log file already attached; refusing privileged relaunch so two processes never write it");
        return false;
    }
    LOG_DEBUG("Elevation: requesting privileged relaunch (startup log lines buffered=%zu)",
              log.bufferedMessageCount());
    if (relaunch && relaunch(child_exit_code)) {
        log.deinit();
        return true;
    }
    LOG_DEBUG("Elevation: relaunch unavailable; keeping %zu buffered startup log lines for this process",
              log.bufferedMessageCount());
    return false;
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
    if (cli.time_limit_overridden) {
        resolution.config.time_limit_seconds = cli.time_limit_seconds;
        // A time limit alone means "test for this long", as in the wizard: a
        // saved or default cycle count must not end the run early.
        if (cli.time_limit_seconds && !cli.cycles_overridden) resolution.config.cycles = 0;
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
    if (cli.sequence_start_overridden) {
        resolution.config.sequence_start = cli.sequence_start;
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
        ss << "  OS reserve:      " << effectiveOsReserveMB(config.preset) << " MB (preset 'Reserved Memory for Windows (Mb)')";
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
            ss << (config.time_limit_seconds ? "unlimited (until the time limit)" : "infinite");
        } else {
            ss << config.cycles;
        }
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Time limit:      " << formatTimeLimit(config.time_limit_seconds);
        if (config.time_limit_seconds && config.cycles) ss << " (or " << config.cycles << " cycles, whichever is first)";
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
        ss << "  Sequence start:  " << (staggeredSequenceStart(config) ? "staggered" : "aligned")
           << (config.sequence_start == SequenceStart::PRESET ? " (preset)" : " (--sequence-start)");
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
