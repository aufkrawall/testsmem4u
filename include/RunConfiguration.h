#pragma once

#include "testsmem4u.h"
#include "Platform.h"
#include <functional>
#include <string>
#include <iosfwd>

namespace testsmem4u {
inline constexpr const char* kProgramName = "testsmem4u";
inline constexpr const char* kProgramVersion = "1.11";
inline constexpr const char* kDefaultConfigPath = "config.ini";
inline constexpr const char* kDefaultPresetPath = "default.cfg";

struct CliOptions {
    bool show_help = false;
    bool show_version = false;
    bool debug = false;
    bool no_elevation = false;
    bool non_interactive = false;
    bool no_pause = false;
    bool list_presets = false;
    bool show_config = false;
    bool dry_run = false;
    bool no_config = false;
    bool aggressive_defrag = false;

    bool config_path_set = false;
    bool preset_specified = false;
    bool memory_overridden = false;
    bool cores_overridden = false;
    bool cycles_overridden = false;
    bool halt_overridden = false;
    bool locked_memory_overridden = false;
    bool large_pages_overridden = false;
    bool sequence_start_overridden = false;
    bool time_limit_overridden = false;

    std::string config_path = kDefaultConfigPath;
    std::string preset_path;
    uint32_t memory_window_mb = 0;
    uint32_t memory_window_percent = 0;
    uint32_t cores = 0;
    uint32_t cycles = 0;
    uint64_t time_limit_seconds = 0; // with time_limit_overridden; 0 clears a saved limit
    bool halt_on_error = false;
    bool use_locked_memory = true;
    bool use_large_pages = true;
    SequenceStart sequence_start = SequenceStart::PRESET;

    bool hasRuntimeOverrides() const {
        return memory_overridden || cores_overridden || cycles_overridden ||
               halt_overridden || locked_memory_overridden || large_pages_overridden ||
               sequence_start_overridden || time_limit_overridden;
    }

    bool requestsDirectRun() const {
        return preset_specified || hasRuntimeOverrides() || show_config || dry_run;
    }
};

struct ConfigResolution {
    Config config;
    PlatformInfo platform = {};
    uint64_t sizing_ram = 0;
    uint32_t requested_window_mb = 0;
    bool config_loaded = false;
    std::string config_path = kDefaultConfigPath;
    std::string config_source = "defaults";
};


bool parseUint32Strict(const std::string& value, uint32_t& result);
bool parseUintOrDefault(const std::string& str, uint32_t& result, uint32_t default_val);
void printVersion();
void printUsage();
int printPresetList(const std::string& directory);
bool parseCliOptions(int argc, char* argv[], CliOptions& options, std::string& error);
Config makeDefaultConfig(const PlatformInfo& plat);
bool prepareConfigForRun(Config& config, const PlatformInfo& plat, uint64_t& sizing_ram, uint32_t& requested_window_mb, std::string& error);
bool resolveConfiguration(const CliOptions& cli, bool automation_mode, ConfigResolution& resolution, std::string& error);
void reportMemoryWindowAdjustment(uint32_t requested_mb, uint32_t actual_mb);
void printConfigSummary(const ConfigResolution& resolution, const CliOptions& cli, bool automation_mode);
Config runConfigWizard(std::istream& input_stream, std::ostream& output_stream);
uint64_t getSizingBaselineRAM();
// Wizard suffix explaining a sizing baseline below total RAM: the process memory
// limit when that is what applies, otherwise the available-RAM fallback; empty
// when sizing uses total RAM.
std::string sizingBaselineNote(uint64_t total_ram, uint64_t process_limit, uint64_t sizing_ram);
uint32_t normalizeWindowMBForLargePages(uint32_t memory_window_mb, bool use_large_pages);
uint32_t computeWindowMBFromPercent(uint64_t sizing_ram, uint32_t percent, bool use_large_pages,
                                    uint32_t reserve_mb = Platform::kMinOsReserveMB);
// The preset's OS reserve with the Platform::kMinOsReserveMB floor applied.
uint32_t effectiveOsReserveMB(const PresetInfo& preset);
// Resolves the process exit code: 0 only when the requested run completed
// cleanly with verified bytes; 1 when RAM errors were detected; 2 on
// infrastructure failure, zero verified bytes, or an interrupted finite run.
int resolveRunExitCode(const Config& config, const RunResult& res);
// Reads confirmation for granting SeLockMemoryPrivilege; closed/EOF input never counts as confirmation.
bool promptMemoryLockPrivilegeOffer(std::istream& input, std::ostream& output,
                                    const std::function<bool()>& grant_privilege);
// Returns true only for bare graphical file-manager launches (no args, no TTY, non-pipe stdout).
bool shouldRelaunchInTerminal(int argc, const CliOptions& cli,
                              bool stdin_tty, bool stdout_tty, bool stderr_tty,
                              bool graphical_session, bool stdout_is_fifo);
class Logger;
// Runs the privileged relaunch while the deferred logger keeps its startup
// diagnostics buffered. Returns true (logger shut down, child_exit_code set)
// when the elevated child ran; false when this process continues, with the
// buffered diagnostics still pending for the later attachFile. Refuses to
// relaunch while a log file is attached so two processes never write it.
bool relaunchElevatedKeepingStartupLog(Logger& log, const std::function<bool(int&)>& relaunch,
                                       int& child_exit_code);
} // namespace testsmem4u
