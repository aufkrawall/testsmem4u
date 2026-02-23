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
#include <csignal>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <conio.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <termios.h>
#include <fcntl.h>
#endif

namespace testsmem4u {

#ifdef _WIN32
static bool isInputAvailable() {
    return _kbhit() != 0;
}

static void clearInput() {
    while (_kbhit()) _getch();
}
#else
#include <cstring>

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
    char* endptr = nullptr;
    unsigned long val = std::strtoul(str.c_str(), &endptr, 10);
    if (endptr && *endptr == '\0') {
        result = static_cast<uint32_t>(val);
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

static void relaunchAsPrivileged(int argc, char* argv[]) {
#ifdef _WIN32
    // Re-launch with ShellExecute and "runas" verb
    std::string args;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) args += " ";
        // Simple quoting - sophisticated quoting might be needed for paths with spaces
        std::string arg = argv[i];
        if (arg.find(' ') != std::string::npos) {
            args += "\"" + arg + "\"";
        } else {
            args += arg;
        }
    }

    // Get current executable path
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path for elevation." << std::endl;
        return;
    }

    SHELLEXECUTEINFOA sei = {}; 
    sei.cbSize = sizeof(sei);
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
    }
#else
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
#endif
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
        if (parseUintOrDefault(num_part, pct, 85)) {
            if (pct > 100) pct = 100;
            config.memory_window_percent = pct;
            config.memory_window_mb = 0;
        } else {
            config.memory_window_percent = 85;
            config.memory_window_mb = 0;
        }
    } else {
        uint32_t mb;
        if (parseUintOrDefault(input, mb, 0)) {
            config.memory_window_mb = mb;
            config.memory_window_percent = 0;
        } else {
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

    std::cout << "Select Preset:\n";
    std::cout << "1. default.cfg (Recommended)\n";
    std::cout << "2. anta777extreme.cfg\n";
    std::cout << "3. memtest86+.cfg\n";
    std::cout << "4. Custom config file\n";
    std::cout << "Enter selection [1]: ";
    
    std::getline(std::cin, input);
    input = Utils::trim(input);
    
    if (input == "2") {
        config.preset_file = "anta777extreme.cfg";
    } else if (input == "3") {
        config.preset_file = "memtest86+.cfg";
    } else if (input == "4") {
        std::cout << "Enter preset file path: ";
        std::getline(std::cin, input);
        config.preset_file = Utils::trim(input);
    } else {
        config.preset_file = "default.cfg";
    }

    if (config.preset_file.empty()) config.preset_file = "default.cfg";
    config.preset = loadPreset(config.preset_file);

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

    Config config = {};
    bool debug = false;
    bool skip_wizard = false;
    bool no_elevation = false;
    std::string preset_path = "";
    bool config_loaded = false;

    for(int i=1; i<argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--debug" || arg == "-d") debug = true;
        else if (arg == "--no-elevation") no_elevation = true;
        else if (arg == "--preset" && i+1 < argc) { preset_path = argv[++i]; skip_wizard = true; }
        else if (arg == "--yes" || arg == "-y") skip_wizard = true;
        else if (arg[0] != '-') { preset_path = arg; skip_wizard = true; }
    }

if (!no_elevation && !isPrivileged()) {
        ConsoleDisplay::get().printLine("Requesting elevation... (Use --no-elevation to skip)");
        relaunchAsPrivileged(argc, argv);
        return 0;
    }

    Logger::get().init("testsmem4u.log", debug ? LogLevel::DEBUG : LogLevel::INFO, true);
    auto& log = Logger::get();
    log.setErrorRateLimit(100);

    if (!Platform::hasMemoryLockPrivilege()) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("[!] 'Lock Pages in Memory' privilege (SeLockMemoryPrivilege) is MISSING.");
        ConsoleDisplay::get().printLine("    This is required for reliable RAM testing to prevent swapping.");
        ConsoleDisplay::get().printLine("    Do you want to grant this privilege to the current user now?");
        ConsoleDisplay::get().printLine("    (Requires 'Yes' and then a Sign-out/Reboot to take effect)");
        std::cout << "    [Y/n]: ";
        
        std::string answer;
        if (!skip_wizard) {
             std::getline(std::cin, answer);
        } else {
             ConsoleDisplay::get().printLine("N (Non-interactive mode)");
             answer = "n";
        }

        if (answer.empty() || answer == "y" || answer == "Y") {
            if (Platform::grantMemoryLockPrivilege()) {
                ConsoleDisplay::get().printLine("");
                ConsoleDisplay::get().printLine("[+] Privilege granted successfully!");
                ConsoleDisplay::get().printLine("    PLEASE SIGN OUT AND SIGN BACK IN for the changes to take effect.");
                ConsoleDisplay::get().printLine("    The program will now exit.");
                return 0;
            } else {
                ConsoleDisplay::get().printError("[-] Failed to grant privilege. You may need to run as Administrator manually.");
            }
        }
    }

    log.info("testsmem4u starting...");
    PlatformInfo plat = Platform::detectPlatform();

    // Try to load config; if fails or doesn't exist, we will setup defaults but allow override
    bool loaded_from_file = false;
    
    // Always attempt to load config file first
    if (loadConfig("config.ini", config)) {
        loaded_from_file = true;
        config_loaded = true;
    }

    if (!skip_wizard) {
        if (!loaded_from_file) {
            // Setup defaults if no config found
            config.memory_window_percent = 85;
            config.memory_window_mb = 0;
            config.cores = plat.cpu_cores;
            config.cycles = 3;
            config.use_locked_memory = true;
            config.use_large_pages = true;
            config.halt_on_error = true;
            config.preset_file = "default.cfg";
        }

        // Ensure calculations are correct based on current config (loaded or default)
        // Recompute percent-based memory windows on each run from total system RAM.
        if (config.memory_window_percent > 0 || config.memory_window_mb == 0) {
            uint64_t sizing_ram = getSizingBaselineRAM();
            uint32_t percent = config.memory_window_percent > 0 ? config.memory_window_percent : 85;
            config.memory_window_mb = computeWindowMBFromPercent(sizing_ram, percent, config.use_large_pages);
        }

        if (config.preset_file.empty()) config.preset_file = "default.cfg";
        config.preset = loadPreset(config.preset_file);

        // Show appropriate message
        const char* msg = loaded_from_file ? "Starting with saved settings..." : "Starting with default settings...";

        if (skip_wizard) {
            std::cout << msg << std::endl;
        } else {
            // Wait for user input
            if (waitForInput(3, msg)) {
                skip_wizard = false;
                config_loaded = false; // Force re-run wizard
            } else {
                skip_wizard = true;
                config_loaded = true; // Use the current config
            }
        }
    }

    if (skip_wizard) {
        if (!config_loaded) {
            if (!preset_path.empty()) config.preset_file = preset_path;
            else if (config.preset_file.empty()) config.preset_file = "default.cfg";

            config.preset = loadPreset(config.preset_file);
            
            config.cores = plat.cpu_cores;
            uint64_t sizing_ram = getSizingBaselineRAM();
            config.memory_window_mb = computeWindowMBFromPercent(sizing_ram, 85, config.use_large_pages);
            config.use_locked_memory = true;
            config.use_large_pages = true;
            config.halt_on_error = false;
            config.cycles = 0;
        }
    } else {
        config = runConfigWizard();
        saveConfig("config.ini", config);
    }

    uint32_t normalized_window_mb = normalizeWindowMBForLargePages(config.memory_window_mb, config.use_large_pages);
    if (normalized_window_mb != config.memory_window_mb) {
        LOG_INFO("Adjusted memory window from %u MB to %u MB to match large-page granularity",
                 config.memory_window_mb, normalized_window_mb);
        config.memory_window_mb = normalized_window_mb;
    }

    {
        std::ostringstream ss;
        ss << "Starting tests with " << config.cores << " threads, " << config.memory_window_mb << " MB memory.";
        ConsoleDisplay::get().printLine(ss.str());
    }
    ConsoleDisplay::get().printLine("Tip: Press Ctrl+C to stop and save results.");
    ConsoleDisplay::get().printLine("");

    config.debug_mode = debug;

    if (config.preset.test_configs.empty()) {
        {
            std::ostringstream ss;
            ss << "[!] ERROR: No tests loaded! Please verify " << config.preset_file << " exists and is valid.";
            ConsoleDisplay::get().printError(ss.str());
        }
#ifdef _WIN32
        ConsoleDisplay::get().printLine("Press any key to exit...");
        _getch();
#endif
        return 1;
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
        res.hard_errors++;
    } catch (...) {
        log.error("FATAL: Unknown exception caught during test execution");
        ConsoleDisplay::get().printError("[!] FATAL ERROR: Unknown exception occurred.");
        res.hard_errors++;
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

    Logger::get().deinit();

#ifdef _WIN32
    ConsoleDisplay::get().printLine("");
    ConsoleDisplay::get().printLine("Press any key to exit...");
    _getch();
#else
    if (isGraphicalSession()) {
        ConsoleDisplay::get().printLine("");
        ConsoleDisplay::get().printLine("Press Enter to exit...");
        getchar();
    }
#endif

    return res.total_errors() == 0 ? 0 : 1;
}

} // namespace testsmem4u

int main(int argc, char* argv[]) {
    return testsmem4u::main(argc, argv);
}
