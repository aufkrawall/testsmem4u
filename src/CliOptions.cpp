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
namespace testsmem4u {
static std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool parseUint32Strict(const std::string& value, uint32_t& result) {
    std::string trimmed = Utils::trim(value);
    if (trimmed.empty()) return false;

    errno = 0;
    char* endptr = nullptr;
    unsigned long long parsed = std::strtoull(trimmed.c_str(), &endptr, 10);
    if (errno != 0 || endptr == trimmed.c_str() || *endptr != '\0' ||
        parsed > std::numeric_limits<uint32_t>::max()) {
        return false;
    }

    result = static_cast<uint32_t>(parsed);
    return true;
}

static bool readOptionValue(const std::string& arg, const char* option_name,
                            int argc, char* argv[], int& index,
                            std::string& value, bool& matched,
                            std::string& error) {
    matched = false;
    std::string prefix = std::string(option_name) + "=";

    if (arg == option_name) {
        matched = true;
        if (index + 1 >= argc) {
            error = std::string("Missing value for ") + option_name + ".";
            return false;
        }
        value = argv[++index];
        return true;
    }

    if (arg.rfind(prefix, 0) == 0) {
        matched = true;
        value = arg.substr(prefix.size());
        if (value.empty()) {
            error = std::string("Missing value for ") + option_name + ".";
            return false;
        }
    }

    return true;
}

static bool parseMemoryOverride(const std::string& raw, uint32_t& memory_mb,
                                uint32_t& memory_percent, std::string& error) {
    std::string value = toLowerCopy(Utils::trim(raw));
    if (value.empty()) {
        error = "Memory value cannot be empty.";
        return false;
    }

    memory_mb = 0;
    memory_percent = 0;

    if (value.back() == '%') {
        uint32_t percent = 0;
        if (!parseUint32Strict(value.substr(0, value.size() - 1), percent) || percent == 0 || percent > 100) {
            error = "Memory percentage must be between 1% and 100%.";
            return false;
        }
        memory_percent = percent;
        return true;
    }

    if (value.size() >= 2 && value.substr(value.size() - 2) == "mb") {
        value = Utils::trim(value.substr(0, value.size() - 2));
    } else if (!value.empty() && value.back() == 'm') {
        value = Utils::trim(value.substr(0, value.size() - 1));
    }

    uint32_t mb = 0;
    if (!parseUint32Strict(value, mb) || mb == 0) {
        error = "Memory override must be a positive MB value or a percentage like 85%.";
        return false;
    }

    memory_mb = mb;
    return true;
}

static bool parseCoresOverride(const std::string& raw, uint32_t& cores, std::string& error) {
    std::string value = toLowerCopy(Utils::trim(raw));
    if (value == "all") {
        cores = 0;
        return true;
    }

    uint32_t parsed = 0;
    if (!parseUint32Strict(value, parsed) || parsed == 0) {
        error = "Core count must be a positive integer or 'all'.";
        return false;
    }

    cores = parsed;
    return true;
}

static bool parseCyclesOverride(const std::string& raw, uint32_t& cycles, std::string& error) {
    std::string value = toLowerCopy(Utils::trim(raw));
    if (value == "inf" || value == "infinite") {
        cycles = 0;
        return true;
    }

    if (!parseUint32Strict(value, cycles)) {
        error = "Cycle count must be a non-negative integer or 'infinite'.";
        return false;
    }

    return true;
}

static std::string joinPath(const std::string& base, const std::string& leaf) {
    if (base.empty() || base == ".") return leaf;

#ifdef _WIN32
    const char sep = '\\';
#else
    const char sep = '/';
#endif

    if (!base.empty() && (base.back() == '/' || base.back() == '\\')) {
        return base + leaf;
    }
    return base + sep + leaf;
}

void printUsage() {
    std::cout << kProgramName << " " << kProgramVersion << "\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << kProgramName << " [options] [preset.cfg]\n\n";
    std::cout << "Default behavior:\n";
    std::cout << "  With no run-specific options, the program loads " << kDefaultConfigPath
              << " if available, shows a 3-second startup delay, and enters\n";
    std::cout << "  the configuration wizard if a key is pressed.\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help               Show this help and exit\n";
    std::cout << "  -v, --version            Show the version and exit\n";
    std::cout << "  -d, --debug              Enable debug logging\n";
    std::cout << "  -y, --yes                Run non-interactively and skip exit pause\n";
    std::cout << "      --non-interactive    Same as --yes\n";
    std::cout << "      --no-pause           Do not wait for a key press on exit\n";
    std::cout << "      --no-elevation       Do not relaunch as Administrator/root\n";
    std::cout << "      --list-presets       List preset files in the current directory and exit\n";
    std::cout << "      --config FILE        Load or save configuration using FILE\n";
    std::cout << "      --no-config          Ignore config files and do not save wizard output\n";
    std::cout << "      --preset FILE        Use FILE as the preset and skip the wizard\n";
    std::cout << "      --memory VALUE       Override memory window, e.g. 85%, 2048, 2048MB\n";
    std::cout << "      --cores VALUE        Override thread count, e.g. 8 or all\n";
    std::cout << "      --cycles VALUE       Override cycles, e.g. 3, 0, or infinite\n";
    std::cout << "      --halt-on-error      Stop after the first detected error\n";
    std::cout << "      --no-halt-on-error   Continue running after errors\n";
    std::cout << "      --locked-memory      Request locked memory\n";
    std::cout << "      --no-locked-memory   Allow swappable memory\n";
    std::cout << "      --large-pages        Prefer large pages / hugepages\n";
    std::cout << "      --no-large-pages     Disable large pages / hugepages\n";
    std::cout << "      --show-config        Print the resolved configuration before execution\n";
    std::cout << "      --dry-run            Validate inputs, print config, and exit\n";
    std::cout << "      --aggressive-defrag  Enable system-wide memory defragmentation (standby list purge,\n";
    std::cout << "                             working set trim, file cache disable). May impact other\n";
    std::cout << "                             running processes. Off by default.\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << kProgramName << " --yes --preset default.cfg\n";
    std::cout << "  " << kProgramName << " --memory 80% --cycles 5 --show-config\n";
    std::cout << "  " << kProgramName << " --config nightly.ini --yes\n";
}

void printVersion() {
    std::cout << kProgramName << " " << kProgramVersion << "\n";
}

int printPresetList(const std::string& directory) {
    std::vector<std::string> presets = listPresets(directory);
    if (presets.empty()) {
        std::cout << "No preset files found in " << directory << ".\n";
        return 0;
    }

    std::cout << "Available presets in " << directory << ":\n";
    for (const auto& preset_name : presets) {
        PresetInfo preset = loadPreset(joinPath(directory, preset_name));
        std::cout << "  " << preset_name;
        if (!preset.config_name.empty()) {
            std::cout << " - " << preset.config_name;
        }
        if (!preset.config_author.empty()) {
            std::cout << " (author: " << preset.config_author << ")";
        }
        if (preset.tests > 0) {
            std::cout << ", tests=" << preset.tests;
        }
        if (preset.cycles > 0) {
            std::cout << ", cycles=" << preset.cycles;
        }
        std::cout << "\n";
    }

    return 0;
}

static bool hasUnsafeConfigPathCharacters(const std::string& path) {
    return Utils::hasUnsafePathControlCharacters(path);
}

bool parseCliOptions(int argc, char* argv[], CliOptions& options, std::string& error) {
    bool saw_preset_source = false;
    bool saw_config_source = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        std::string value;
        bool matched = false;

        if (arg == "--") {
            if (i + 2 < argc) {
                error = "Only one positional preset path is supported.";
                return false;
            }
            if (i + 1 < argc) {
                if (saw_preset_source) {
                    error = "Preset path specified more than once.";
                    return false;
                }
                options.preset_path = argv[++i];
                options.preset_specified = true;
                saw_preset_source = true;
            }
            break;
        }

        if (arg == "--help" || arg == "-h") {
            options.show_help = true;
            continue;
        }
        if (arg == "--version" || arg == "-v") {
            options.show_version = true;
            continue;
        }
        if (arg == "--debug" || arg == "-d") {
            options.debug = true;
            continue;
        }
        if (arg == "--yes" || arg == "-y" || arg == "--non-interactive") {
            options.non_interactive = true;
            options.no_pause = true;
            continue;
        }
        if (arg == "--no-pause") {
            options.no_pause = true;
            continue;
        }
        if (arg == "--no-elevation") {
            options.no_elevation = true;
            continue;
        }
        if (arg == "--list-presets") {
            options.list_presets = true;
            continue;
        }
        if (arg == "--show-config") {
            options.show_config = true;
            continue;
        }
        if (arg == "--dry-run") {
            options.dry_run = true;
            options.show_config = true;
            options.non_interactive = true;
            options.no_pause = true;
            continue;
        }
        if (arg == "--no-config") {
            options.no_config = true;
            continue;
        }
        if (arg == "--aggressive-defrag") {
            options.aggressive_defrag = true;
            continue;
        }
        if (arg == "--halt-on-error") {
            options.halt_on_error = true;
            options.halt_overridden = true;
            continue;
        }
        if (arg == "--no-halt-on-error") {
            options.halt_on_error = false;
            options.halt_overridden = true;
            continue;
        }
        if (arg == "--locked-memory") {
            options.use_locked_memory = true;
            options.locked_memory_overridden = true;
            continue;
        }
        if (arg == "--no-locked-memory") {
            options.use_locked_memory = false;
            options.locked_memory_overridden = true;
            continue;
        }
        if (arg == "--large-pages") {
            options.use_large_pages = true;
            options.large_pages_overridden = true;
            continue;
        }
        if (arg == "--no-large-pages") {
            options.use_large_pages = false;
            options.large_pages_overridden = true;
            continue;
        }

        if (!readOptionValue(arg, "--config", argc, argv, i, value, matched, error)) {
            return false;
        }
        if (matched) {
            if (saw_config_source) {
                error = "Config file specified more than once.";
                return false;
            }
            options.config_path = Utils::trim(value);
            if (options.config_path.empty()) {
                error = "Config file path cannot be empty.";
                return false;
            }
            if (hasUnsafeConfigPathCharacters(options.config_path)) {
                error = "Config file path contains unsafe characters (null byte or ESC).";
                return false;
            }
            options.config_path_set = true;
            saw_config_source = true;
            continue;
        }

        if (!readOptionValue(arg, "--preset", argc, argv, i, value, matched, error)) {
            return false;
        }
        if (matched) {
            if (saw_preset_source) {
                error = "Preset path specified more than once.";
                return false;
            }
            options.preset_path = Utils::trim(value);
            if (options.preset_path.empty()) {
                error = "Preset path cannot be empty.";
                return false;
            }
            options.preset_specified = true;
            saw_preset_source = true;
            continue;
        }

        if (!readOptionValue(arg, "--memory", argc, argv, i, value, matched, error)) {
            return false;
        }
        if (matched) {
            if (!parseMemoryOverride(value, options.memory_window_mb, options.memory_window_percent, error)) {
                return false;
            }
            options.memory_overridden = true;
            continue;
        }

        if (!readOptionValue(arg, "--cores", argc, argv, i, value, matched, error)) {
            return false;
        }
        if (matched) {
            if (!parseCoresOverride(value, options.cores, error)) {
                return false;
            }
            options.cores_overridden = true;
            continue;
        }

        if (!readOptionValue(arg, "--cycles", argc, argv, i, value, matched, error)) {
            return false;
        }
        if (matched) {
            if (!parseCyclesOverride(value, options.cycles, error)) {
                return false;
            }
            options.cycles_overridden = true;
            continue;
        }

        if (!arg.empty() && arg[0] != '-') {
            if (saw_preset_source) {
                error = "Preset path specified more than once.";
                return false;
            }
            options.preset_path = arg;
            options.preset_specified = true;
            saw_preset_source = true;
            continue;
        }

        error = "Unknown argument: " + arg;
        return false;
    }

    if (options.no_config && options.config_path_set) {
        error = "--config and --no-config cannot be used together.";
        return false;
    }

    return true;
}

} // namespace testsmem4u
