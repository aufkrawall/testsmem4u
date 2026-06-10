#include "TestEngine.h"
#include "Logger.h"
#include "Platform.h"
#include "ConfigManager.h"
#include "ConsoleDisplay.h"
#include "simd_ops.h"
#include "Utils.h"
#include <iostream>
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

namespace testsmem4u {

static constexpr const char* kProgramName = "testsmem4u";
static constexpr const char* kProgramVersion = "1.5";
static constexpr const char* kDefaultConfigPath = "config.ini";
static constexpr const char* kDefaultPresetPath = "default.cfg";

#ifdef _WIN32
// Build a properly escaped command-line string from argv[1..argc) suitable for
// ShellExecuteExA / CreateProcess. Handles spaces, tabs, embedded quotes, and
// trailing backslashes using the CommandLineToArgvW-compatible quoting rules.
// This follows the standard Windows command-line parsing convention used by
// CommandLineToArgvW.
static std::string quoteWindowsArg(const std::string& arg) {
    const bool needs_quoting = (arg.find_first_of(" \t\"") != std::string::npos || arg.empty());
    if (!needs_quoting) return arg;

    std::string quoted;
    quoted.reserve(arg.size() + 2);
    quoted.push_back('"');
    size_t backslashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }
        if (c == '"') {
            quoted.append(backslashes * 2 + 1, '\\');
            quoted.push_back('"');
        } else {
            quoted.append(backslashes, '\\');
            quoted.push_back(c);
        }
        backslashes = 0;
    }
    quoted.append(backslashes * 2, '\\');
    quoted.push_back('"');
    return quoted;
}

static std::string buildArgsString(int argc, char* argv[]) {
    std::string result;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) result += " ";
        result += quoteWindowsArg(argv[i]);
    }
    return result;
}
#endif

#ifdef _WIN32
static bool isInputAvailable() {
    return _kbhit() != 0;
}

static void clearInput() {
    while (_kbhit()) _getch();
}
#else

static bool isInputAvailable() {
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

static void clearInput() {
    // Non-blocking read to clear buffer
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    char c;
    while (read(STDIN_FILENO, &c, 1) > 0);
    fcntl(STDIN_FILENO, F_SETFL, flags);
}

// Check if running inside a terminal
static bool isRunningInTerminal() {
    return isatty(STDOUT_FILENO) != 0;
}

// Check if in a graphical session
static bool isGraphicalSession() {
    const char* display = getenv("DISPLAY");
    const char* wayland = getenv("WAYLAND_DISPLAY");
    return (display != nullptr && strlen(display) > 0) ||
           (wayland != nullptr && strlen(wayland) > 0);
}

// Get desktop environment
static std::string getDesktopEnvironment() {
    const char* de = getenv("XDG_CURRENT_DESKTOP");
    if (de) return std::string(de);
    return "";
}

// Check if command exists in PATH
static bool commandExists(const char* cmd) {
    char* path = getenv("PATH");
    if (!path) return false;

    std::string pathStr(path);
    size_t start = 0;
    size_t end = pathStr.find(':');

    while (end != std::string::npos) {
        std::string dir = pathStr.substr(start, end - start);
        std::string fullPath = dir + "/" + cmd;
        if (access(fullPath.c_str(), X_OK) == 0) {
            return true;
        }
        start = end + 1;
        end = pathStr.find(':', start);
    }

    // Check last segment
    std::string dir = pathStr.substr(start);
    std::string fullPath = dir + "/" + cmd;
    return access(fullPath.c_str(), X_OK) == 0;
}

// Terminal emulator entry with execution argument
struct TerminalEntry {
    const char* cmd;
    const char* exec_arg;  // Argument to pass command to execute, nullptr if not needed
    const char* desktop;   // Preferred desktop, or nullptr for universal
};

// Find best terminal emulator
static TerminalEntry findTerminalEmulator() {
    std::string desktop = getDesktopEnvironment();

    TerminalEntry terminals[] = {
        {"xdg-terminal-exec", nullptr, nullptr},  // Freedesktop standard
        {"konsole", "-e", "KDE"},
        {"gnome-terminal", "--", "GNOME"},
        {"xfce4-terminal", "-e", "XFCE"},
        {"mate-terminal", "-e", "MATE"},
        {"lxterminal", "-e", nullptr},
        {"terminator", "-e", nullptr},
        {"alacritty", "-e", nullptr},
        {"kitty", nullptr, nullptr},  // kitty doesn't need exec arg before command
        {"xterm", "-e", nullptr},
        {nullptr, nullptr, nullptr}
    };

    // First pass: desktop-specific terminals
    if (!desktop.empty()) {
        for (const auto& term : terminals) {
            if (term.cmd == nullptr) break;
            if (term.desktop != nullptr && desktop.find(term.desktop) != std::string::npos) {
                if (commandExists(term.cmd)) {
                    return term;
                }
            }
        }
    }

    // Second pass: any available terminal
    for (const auto& term : terminals) {
        if (term.cmd == nullptr) break;
        if (commandExists(term.cmd)) {
            return term;
        }
    }

    return {nullptr, nullptr, nullptr};
}

// Relaunch in terminal emulator
static void relaunchInTerminal(int argc, char* argv[]) {
    TerminalEntry terminal = findTerminalEmulator();
    if (terminal.cmd == nullptr) {
        // No terminal found, continue anyway
        return;
    }

    // Build command arguments
    std::vector<char*> new_argv;
    new_argv.push_back(const_cast<char*>(terminal.cmd));

    // Add terminal-specific execution argument if needed
    if (terminal.exec_arg != nullptr) {
        new_argv.push_back(const_cast<char*>(terminal.exec_arg));
    }

    // Add the current executable and its arguments
    new_argv.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        new_argv.push_back(argv[i]);
    }
    new_argv.push_back(nullptr);

    execvp(terminal.cmd, new_argv.data());
    // If execvp fails, just continue with current process
}
#endif

// Returns true if user pressed a key, false if timeout
static bool waitForInput(int seconds, const char* startMessage) {
    auto start = std::chrono::steady_clock::now();
    int last_print = -1;

    clearInput();

    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < seconds) {
        auto remaining = seconds - std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
        
        if (remaining != last_print) {
            std::string line = std::string(startMessage) + " " + std::to_string(remaining) + "s... Press any key to configure.";
            ConsoleDisplay::get().updateProgressLine(line);
            last_print = (int)remaining;
        }

        if (isInputAvailable()) {
            ConsoleDisplay::get().printLine("");
            #ifdef _WIN32
            _getch();
            #else
            getchar();
            #endif
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ConsoleDisplay::get().printLine("Starting tests...");
    return false;
}

static bool parseUintOrDefault(const std::string& str, uint32_t& result, uint32_t default_val) {
    if (str.empty()) {
        result = default_val;
        return true;
    }
    uint32_t parsed = 0;
    if (Utils::parseUintStrict(str, parsed)) {
        result = parsed;
        return true;
    }
    return false;
}

static uint64_t getSizingBaselineRAM() {
    uint64_t total_ram = Platform::getTotalSystemRAM();
    if (total_ram != 0) return total_ram;
    return Platform::getAvailableSystemRAM();
}

static uint32_t normalizeWindowMBForLargePages(uint32_t memory_window_mb, bool use_large_pages) {
#ifdef _WIN32
    if (!use_large_pages || memory_window_mb == 0) return memory_window_mb;
    SIZE_T large_page_min = GetLargePageMinimum();
    if (large_page_min == 0) return memory_window_mb;

    uint64_t bytes = static_cast<uint64_t>(memory_window_mb) * 1024ULL * 1024ULL;
    uint64_t aligned = (bytes / large_page_min) * large_page_min;
    if (aligned == 0) return memory_window_mb;
    return static_cast<uint32_t>(aligned / 1024ULL / 1024ULL);
#else
    (void)use_large_pages;
    return memory_window_mb;
#endif
}

static uint32_t computeWindowMBFromPercent(uint64_t sizing_ram, uint32_t percent, bool use_large_pages) {
    uint64_t max_mem = Platform::getMaxTestableMemory(sizing_ram, percent);
    uint32_t window_mb = static_cast<uint32_t>(max_mem / 1024 / 1024);
    return normalizeWindowMBForLargePages(window_mb, use_large_pages);
}

static bool isPrivileged() {
#ifdef _WIN32
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            fRet = elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
#else
    return geteuid() == 0;
#endif
}

// Relaunches this binary with elevated privileges. On success returns true and
// stores the elevated child's exit code in exit_code so scripted runs see the
// real memory-test result instead of an unconditional success from the parent.
static bool relaunchAsPrivileged(int argc, char* argv[], int& exit_code) {
#ifdef _WIN32
    // Re-launch with ShellExecute and "runas" verb
    std::string args = buildArgsString(argc, argv);

    // Get current executable path
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path for elevation." << std::endl;
        return false;
    }

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = exePath;
    sei.lpParameters = args.c_str();
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            std::cerr << "Elevation refused by user." << std::endl;
        } else {
            std::cerr << "Failed to elevate: Error " << err << std::endl;
        }
        return false;
    }
    if (!sei.hProcess) {
        // Launched but no process handle to wait on; cannot observe the result.
        exit_code = 0;
        return true;
    }
    DWORD wait_result = WaitForSingleObject(sei.hProcess, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        std::cerr << "Failed to wait for elevated process: error " << GetLastError() << std::endl;
        CloseHandle(sei.hProcess);
        exit_code = 2;
        return true;
    }
    DWORD child_exit_code = 0;
    if (!GetExitCodeProcess(sei.hProcess, &child_exit_code)) {
        std::cerr << "Failed to read elevated process exit code: error " << GetLastError() << std::endl;
        CloseHandle(sei.hProcess);
        exit_code = 2;
        return true;
    }
    CloseHandle(sei.hProcess);
    exit_code = static_cast<int>(child_exit_code);
    return true;
#else
    (void)exit_code;
    // Re-launch with sudo
    std::vector<char*> new_argv;
    new_argv.push_back((char*)"sudo");
    // Find absolute path of current executable if possible, or use argv[0]
    new_argv.push_back(argv[0]); 
    for (int i = 1; i < argc; ++i) {
        new_argv.push_back(argv[i]);
    }
    new_argv.push_back(nullptr);

    execvp("sudo", new_argv.data());
    std::cerr << "Failed to run sudo: " << strerror(errno) << std::endl;
    return false;
#endif
}

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

    std::string config_path = kDefaultConfigPath;
    std::string preset_path;
    uint32_t memory_window_mb = 0;
    uint32_t memory_window_percent = 0;
    uint32_t cores = 0;
    uint32_t cycles = 0;
    bool halt_on_error = false;
    bool use_locked_memory = true;
    bool use_large_pages = true;

    bool hasRuntimeOverrides() const {
        return memory_overridden || cores_overridden || cycles_overridden ||
               halt_overridden || locked_memory_overridden || large_pages_overridden;
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

static bool isStdinInteractive() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

static bool isStdoutInteractive() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

static std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static bool parseUint32Strict(const std::string& value, uint32_t& result) {
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

static void printUsage() {
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

static void printVersion() {
    std::cout << kProgramName << " " << kProgramVersion << "\n";
}

static int printPresetList(const std::string& directory) {
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

static bool parseCliOptions(int argc, char* argv[], CliOptions& options, std::string& error) {
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

static Config makeDefaultConfig(const PlatformInfo& plat) {
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

static bool prepareConfigForRun(Config& config, const PlatformInfo& plat,
                                uint64_t& sizing_ram, uint32_t& requested_window_mb,
                                std::string& error) {
    uint32_t available_cores = plat.cpu_cores > 0 ? plat.cpu_cores : 1;
    if (config.cores == 0) {
        config.cores = available_cores;
    } else if (available_cores > 0 && config.cores > available_cores) {
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

    sizing_ram = getSizingBaselineRAM();
    if (sizing_ram == 0) {
        error = "Unable to detect available system memory for sizing.";
        return false;
    }

    if (config.memory_window_mb == 0) {
        config.memory_window_mb = computeWindowMBFromPercent(
            sizing_ram, config.memory_window_percent, config.use_large_pages);
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

    uint64_t max_safe_bytes = Platform::getMaxTestableMemory(sizing_ram, 100);
    if (max_safe_bytes > 0) {
        uint64_t requested_bytes = static_cast<uint64_t>(config.memory_window_mb) * 1024ULL * 1024ULL;
        if (requested_bytes > max_safe_bytes) {
            std::ostringstream ss;
            ss << "Requested memory window (" << config.memory_window_mb
               << " MB) exceeds the safe maximum ("
               << (max_safe_bytes / 1024ULL / 1024ULL)
               << " MB) for this system.";
            error = ss.str();
            return false;
        }
    }

    return true;
}

static bool resolveConfiguration(const CliOptions& cli, bool automation_mode,
                                 ConfigResolution& resolution, std::string& error) {
    resolution.platform = Platform::detectPlatform();
    if (resolution.platform.cpu_cores == 0) {
        resolution.platform.cpu_cores = 1;
    }

    resolution.config_path = cli.config_path_set ? cli.config_path : kDefaultConfigPath;
    resolution.config_source = cli.no_config ? "disabled (--no-config)" : "defaults";
    resolution.config = makeDefaultConfig(resolution.platform);

    if (!cli.no_config) {
        if (loadConfig(resolution.config_path, resolution.config)) {
            resolution.config_loaded = true;
            resolution.config_source = resolution.config_path;
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

    return prepareConfigForRun(
        resolution.config,
        resolution.platform,
        resolution.sizing_ram,
        resolution.requested_window_mb,
        error);
}

static void reportMemoryWindowAdjustment(uint32_t requested_mb, uint32_t actual_mb) {
    if (requested_mb == actual_mb) return;

    std::ostringstream ss;
    ss << "Adjusted memory window from " << requested_mb
       << " MB to " << actual_mb << " MB to match large-page granularity.";
    ConsoleDisplay::get().printLine(ss.str());
}

static void printConfigSummary(const ConfigResolution& resolution, const CliOptions& cli,
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
        ss << "  Threads:         " << config.cores;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Cycles:          ";
        if (config.cycles == 0) {
            ss << "infinite";
        } else {
            ss << config.cycles;
        }
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
        ss << "  Debug logging:   " << (cli.debug ? "Yes" : "No");
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Interactive:     " << (automation_mode ? "No" : "Yes");
        ConsoleDisplay::get().printLine(ss.str());
    }
}

Config runConfigWizard() {
    Config config;
    PlatformInfo plat = Platform::detectPlatform();
    uint64_t total_ram = Platform::getTotalSystemRAM();
    uint64_t sizing_ram = getSizingBaselineRAM();
    if (sizing_ram == 0) sizing_ram = total_ram;

    std::cout << "\n--- testsmem4u Configuration Wizard ---\n";
    std::cout << "Detected " << plat.cpu_cores << " cores, " << (total_ram / 1024 / 1024) << " MB RAM";
    if (sizing_ram > 0 && sizing_ram != total_ram) {
        std::cout << " (" << (sizing_ram / 1024 / 1024) << " MB currently available)";
    }
    std::cout << ".\n\n";

    std::string input;

    std::cout << "Enter memory to test (e.g. '85%', '2048' for MB) [Default: 85%]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);

    if (input.empty()) {
        config.memory_window_percent = 85;
        config.memory_window_mb = 0;
    } else if (input.back() == '%') {
        std::string num_part = input.substr(0, input.size() - 1);
        uint32_t pct;
        if (parseUint32Strict(num_part, pct)) {
            if (pct > 100) pct = 100;
            config.memory_window_percent = pct;
            config.memory_window_mb = 0;
        } else {
            ConsoleDisplay::get().printLine("[!] Invalid percentage value. Using default 85%.");
            config.memory_window_percent = 85;
            config.memory_window_mb = 0;
        }
    } else {
        uint32_t mb;
        if (parseUint32Strict(input, mb) && mb > 0) {
            config.memory_window_mb = mb;
            config.memory_window_percent = 0;
        } else {
            ConsoleDisplay::get().printLine("[!] Invalid MB value. Using default 85%.");
            config.memory_window_mb = 0;
            config.memory_window_percent = 85;
        }
    }

    std::cout << "Enter number of threads to use (1-" << plat.cpu_cores << ") [Default: all]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);

    uint32_t cores;
    if (parseUintOrDefault(input, cores, plat.cpu_cores)) {
        if (cores < 1) cores = 1;
        if (cores > plat.cpu_cores && plat.cpu_cores > 0) cores = plat.cpu_cores;
        config.cores = cores;
    } else {
        config.cores = plat.cpu_cores;
    }

    std::cout << "Enter number of cycles (0 for infinite) [Default: 3]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);

    parseUintOrDefault(input, config.cycles, 3);

    std::cout << "Use locked memory? (y/n) [Default: y]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);
    config.use_locked_memory = (input != "n" && input != "N");

#ifndef _WIN32
    // Linux hugepages option
    std::cout << "Use large pages (hugepages)? Improves RowHammer test effectiveness. (y/n) [Default: y]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);
    config.use_large_pages = (input != "n" && input != "N");
#endif

    std::cout << "Halt on detected errors? (y/n) [Default: y]: ";
    std::getline(std::cin, input);
    input = Utils::trim(input);
    config.halt_on_error = (input.empty() || (input != "n" && input != "N"));

    std::vector<std::string> presets = listPresets(".");
    size_t default_choice = 0;
    for (size_t i = 0; i < presets.size(); ++i) {
        if (presets[i] == kDefaultPresetPath) {
            default_choice = i;
            break;
        }
    }

    if (presets.empty()) {
        std::cout << "No preset files were found in the current directory.\n";
        std::cout << "Enter preset file path [" << kDefaultPresetPath << "]: ";
        std::getline(std::cin, input);
        config.preset_file = Utils::trim(input);
    } else {
        std::cout << "Select Preset:\n";
        for (size_t i = 0; i < presets.size(); ++i) {
            std::cout << (i + 1) << ". " << presets[i];
            if (presets[i] == kDefaultPresetPath) {
                std::cout << " (Recommended)";
            }
            std::cout << "\n";
        }
        size_t custom_choice = presets.size() + 1;
        std::cout << custom_choice << ". Custom config file\n";
        std::cout << "Enter selection [" << (default_choice + 1) << "]: ";

        std::getline(std::cin, input);
        input = Utils::trim(input);

        uint32_t selection = 0;
        if (!parseUintOrDefault(input, selection, static_cast<uint32_t>(default_choice + 1))) {
            selection = static_cast<uint32_t>(default_choice + 1);
        }

        if (selection >= 1 && selection <= presets.size()) {
            config.preset_file = presets[selection - 1];
        } else if (selection == custom_choice) {
            std::cout << "Enter preset file path: ";
            std::getline(std::cin, input);
            config.preset_file = Utils::trim(input);
        } else {
            config.preset_file = presets[default_choice];
        }
    }

    if (config.preset_file.empty()) config.preset_file = kDefaultPresetPath;
    config.preset = loadPreset(config.preset_file);
    if (!config.preset.valid) {
        ConsoleDisplay::get().printError(std::string("[!] Invalid preset: ") + config.preset.validation_error);
        config.preset = PresetInfo();
        config.preset_file = kDefaultPresetPath;
        config.preset = loadPreset(config.preset_file);
    }

    if (config.memory_window_mb == 0) {
        config.memory_window_mb = computeWindowMBFromPercent(sizing_ram, config.memory_window_percent, config.use_large_pages);
        if (config.memory_window_mb == 0) {
            uint32_t fallback_mb = static_cast<uint32_t>(sizing_ram / 1024 / 1024 / 2);
            config.memory_window_mb = normalizeWindowMBForLargePages(fallback_mb, config.use_large_pages);
        }
    }

    return config;
}

void onShutdown() {
    TestEngine::requestStop();
}

int main(int argc, char* argv[]) {
#ifndef _WIN32
    // Auto-terminal launch check for Linux - must be first
    if (!isRunningInTerminal() && isGraphicalSession()) {
        relaunchInTerminal(argc, argv);
        // If relaunch failed, continue anyway
    }
#endif

    ConsoleDisplay::get().init();
    Platform::registerShutdownHandler(onShutdown);

    CliOptions cli;
    std::string cli_error;
    if (!parseCliOptions(argc, argv, cli, cli_error)) {
        std::cerr << "Error: " << cli_error << "\n\n";
        printUsage();
        return 2;
    }

    if (cli.show_help) {
        printUsage();
        return 0;
    }
    if (cli.show_version) {
        printVersion();
        return 0;
    }
    if (cli.list_presets) {
        return printPresetList(".");
    }

    bool input_interactive = isStdinInteractive();
    bool output_interactive = isStdoutInteractive();
    bool automation_mode = cli.non_interactive || !input_interactive || cli.requestsDirectRun();
    bool should_pause_on_exit = !cli.no_pause && input_interactive && output_interactive && !automation_mode;

    // Initialize the logger before configuration/preset resolution so their
    // diagnostics reach the log file (pre-init messages are dropped).
    auto& log = Logger::get();
    log.init("testsmem4u.log", cli.debug ? LogLevel::DEBUG : LogLevel::INFO, true);
    log.setErrorRateLimit(100);
    log.info("%s %s starting...", kProgramName, kProgramVersion);

    ConfigResolution resolution;
    std::string resolution_error;
    if (!resolveConfiguration(cli, automation_mode, resolution, resolution_error)) {
        ConsoleDisplay::get().printError(std::string("[!] ") + resolution_error);
        log.deinit();
        return 2;
    }

    if (cli.show_config) {
        printConfigSummary(resolution, cli, automation_mode);
    }
    if (cli.dry_run) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("Dry run complete. No tests executed.");
        log.deinit();
        return 0;
    }

    if (!cli.no_elevation && !isPrivileged()) {
        ConsoleDisplay::get().printLine("Requesting elevation... (Use --no-elevation to skip)");
        // Close the log before the elevated child re-creates it; both processes
        // writing the same file would interleave/truncate each other's output.
        log.deinit();
        int elevated_exit_code = 0;
        if (relaunchAsPrivileged(argc, argv, elevated_exit_code)) {
            return elevated_exit_code;
        }
        log.init("testsmem4u.log", cli.debug ? LogLevel::DEBUG : LogLevel::INFO, false);
        ConsoleDisplay::get().printLine("[!] Elevation unavailable. Continuing without elevation.");
    }

    Config config = resolution.config;

    if (automation_mode) {
        ConsoleDisplay::get().printLine("Non-interactive mode enabled; skipping prompts.");
    }

#ifdef _WIN32
    if ((config.use_locked_memory || config.use_large_pages) && !Platform::hasMemoryLockPrivilege()) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("[!] 'Lock Pages in Memory' privilege (SeLockMemoryPrivilege) is MISSING.");
        ConsoleDisplay::get().printLine("    Locked memory and large-page allocations may fail or fall back.");
        ConsoleDisplay::get().printLine("    Do you want to grant this privilege to the current user now?");
        ConsoleDisplay::get().printLine("    (Requires 'Yes' and then a Sign-out/Reboot to take effect)");
        
        if (automation_mode) {
            ConsoleDisplay::get().printLine("    Direct/non-interactive mode: skipping automatic privilege grant.");
        } else {
            std::cout << "    [Y/n]: ";

            std::string answer;
            std::getline(std::cin, answer);
            if (answer.empty() || answer == "y" || answer == "Y") {
                if (Platform::grantMemoryLockPrivilege()) {
                    ConsoleDisplay::get().printLine("");
                    ConsoleDisplay::get().printLine("[+] Privilege granted successfully!");
                    ConsoleDisplay::get().printLine("    PLEASE SIGN OUT AND SIGN BACK IN for the changes to take effect.");
                    ConsoleDisplay::get().printLine("    The program will now exit.");
                    Logger::get().deinit();
                    return 0;
                }
                ConsoleDisplay::get().printError("[-] Failed to grant privilege. You may need to run as Administrator manually.");
            }
        }
    }
#else
    if ((config.use_locked_memory || config.use_large_pages) && !Platform::hasMemoryLockPrivilege()) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("[!] Memory locking or hugepage privileges appear limited.");
        ConsoleDisplay::get().printLine("    Locked memory and hugepage allocations may fall back depending on system policy.");
        ConsoleDisplay::get().printLine("    Raise RLIMIT_MEMLOCK, configure hugepages, or run with sufficient privileges for the most reliable results.");
    }
#endif

    uint32_t requested_window_mb = resolution.requested_window_mb;
    if (!automation_mode) {
        const char* msg = resolution.config_loaded
            ? "Starting with saved settings..."
            : "Starting with default settings...";

        if (waitForInput(3, msg)) {
            std::string wizard_error;
            config = runConfigWizard();
            if (!prepareConfigForRun(
                    config,
                    resolution.platform,
                    resolution.sizing_ram,
                    requested_window_mb,
                    wizard_error)) {
                ConsoleDisplay::get().printError(std::string("[!] ") + wizard_error);
                Logger::get().deinit();
                return 2;
            }

            if (!cli.no_config) {
                const std::string save_path = cli.config_path_set ? cli.config_path : kDefaultConfigPath;
                if (!saveConfig(save_path, config)) {
                    ConsoleDisplay::get().printError(
                        std::string("[!] Failed to save configuration to ") + save_path);
                }
            }
        }
    }

    reportMemoryWindowAdjustment(requested_window_mb, config.memory_window_mb);
    config.debug_mode = cli.debug;
    Platform::setAggressiveDefrag(cli.aggressive_defrag);

    {
        std::ostringstream ss;
        ss << "Starting tests with " << config.cores << " threads, " << config.memory_window_mb << " MB memory.";
        ConsoleDisplay::get().printLine(ss.str());
    }
    ConsoleDisplay::get().printLine("Tip: Press Ctrl+C to stop and save results.");
    ConsoleDisplay::get().printLine("");

    if (config.preset.test_configs.empty()) {
        {
            std::ostringstream ss;
            ss << "[!] ERROR: No tests loaded! Please verify " << config.preset_file << " exists and is valid.";
            ConsoleDisplay::get().printError(ss.str());
        }
#ifdef _WIN32
        if (should_pause_on_exit) {
            ConsoleDisplay::get().printLine("Press any key to exit...");
            _getch();
        }
#endif
        Logger::get().deinit();
        return 2;
    }

    RunResult res = {};
    try {
        res = TestEngine::runTests(config);
    } catch (const std::exception& e) {
        log.error("FATAL: Uncaught exception during test execution: %s", e.what());
        {
            std::ostringstream ss;
            ss << "[!] FATAL ERROR: " << e.what();
            ConsoleDisplay::get().printError(ss.str());
        }
        res.infrastructure_failure = true;
        res.infrastructure_error = e.what();
    } catch (...) {
        log.error("FATAL: Unknown exception caught during test execution");
        ConsoleDisplay::get().printError("[!] FATAL ERROR: Unknown exception occurred.");
        res.infrastructure_failure = true;
        res.infrastructure_error = "Unknown exception occurred during test execution.";
    }

    ConsoleDisplay::get().printLine("");
    ConsoleDisplay::get().printLine("--- Results ---");
    {
        std::ostringstream ss;
        ss << "Total Errors: " << res.total_errors();
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Hard (confirmed):   " << res.hard_errors;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Soft (transient):   " << res.soft_errors;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "  Unverified:         " << res.unverified_errors;
        ConsoleDisplay::get().printLine(ss.str());
    }
    {
        std::ostringstream ss;
        ss << "Time: " << res.duration_seconds << "s";
        ConsoleDisplay::get().printLine(ss.str());
    }
    if (res.infrastructure_failure) {
        ConsoleDisplay::get().printError("Infrastructure failure: " + res.infrastructure_error);
    }

    Logger::get().deinit();

#ifdef _WIN32
    if (should_pause_on_exit) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("Press any key to exit...");
        _getch();
    }
#else
    if (should_pause_on_exit && isGraphicalSession()) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("Press Enter to exit...");
        getchar();
    }
#endif

    if (res.infrastructure_failure) return 2;
    return res.total_errors() == 0 ? 0 : 1;
}

} // namespace testsmem4u

int main(int argc, char* argv[]) {
    return testsmem4u::main(argc, argv);
}
