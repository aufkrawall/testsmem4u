#include "TestEngine.h"
#include "Logger.h"
#include "Platform.h"
#include "ConfigManager.h"
#include "simd_ops.h" // Added include
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
static void enableVirtualTerminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            dwMode &= ~ENABLE_QUICK_EDIT_MODE; // Disable QuickEdit to prevent pausing on selection
            dwMode |= ENABLE_EXTENDED_FLAGS; // Required when disabling QuickEdit
            SetConsoleMode(hOut, dwMode);
        }
    }
}

static bool isInputAvailable() {
    return _kbhit() != 0;
}

static void clearInput() {
    while (_kbhit()) _getch();
}
#else
#include <cstring>

static void enableVirtualTerminal() {}

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

    // Flush any pending input
    clearInput();

    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < seconds) {
        auto remaining = seconds - std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
        
        if (remaining != last_print) {
            std::cout << "\r" << startMessage << " " << remaining << "s... Press any key to configure.   " << std::flush;
            last_print = (int)remaining;
        }

        if (isInputAvailable()) {
            std::cout << std::endl;
            // Consume the key
            #ifdef _WIN32
            _getch();
            #else
            getchar();
            #endif
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::cout << "\rStarting tests...                                             " << std::endl;
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

[[maybe_unused]] static bool parseIntOrDefault(const std::string& str, int32_t& result, int32_t default_val) {
    if (str.empty()) {
        result = default_val;
        return true;
    }
    char* endptr = nullptr;
    long val = std::strtol(str.c_str(), &endptr, 10);
    if (endptr && *endptr == '\0') {
        result = static_cast<int32_t>(val);
        return true;
    }
    return false;
}

static std::string trimString(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
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

    std::cout << "\n--- testsmem4u Configuration Wizard ---\n";
    std::cout << "Detected " << plat.cpu_cores << " cores, " << (total_ram / 1024 / 1024) << " MB RAM.\n\n";

    std::string input;

    std::cout << "Enter memory to test (e.g. '85%', '2048' for MB) [Default: 85%]: ";
    std::getline(std::cin, input);
    input = trimString(input);

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
    input = trimString(input);

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
    input = trimString(input);

    parseUintOrDefault(input, config.cycles, 3);

    std::cout << "Use locked memory? (y/n) [Default: y]: ";
    std::getline(std::cin, input);
    input = trimString(input);
    config.use_locked_memory = (input != "n" && input != "N");

    std::cout << "Halt on detected errors? (y/n) [Default: y]: ";
    std::getline(std::cin, input);
    input = trimString(input);
    config.halt_on_error = (input.empty() || (input != "n" && input != "N"));

    std::cout << "Select Preset:\n";
    std::cout << "1. default.cfg (Recommended)\n";
    std::cout << "2. anta777extreme.cfg\n";
    std::cout << "3. memtest86+.cfg\n";
    std::cout << "4. Custom config file\n";
    std::cout << "Enter selection [1]: ";
    
    std::getline(std::cin, input);
    input = trimString(input);
    
    if (input == "2") {
        config.preset_file = "anta777extreme.cfg";
    } else if (input == "3") {
        config.preset_file = "memtest86+.cfg";
    } else if (input == "4") {
        std::cout << "Enter preset file path: ";
        std::getline(std::cin, input);
        config.preset_file = trimString(input);
    } else {
        config.preset_file = "default.cfg";
    }

    if (config.preset_file.empty()) config.preset_file = "default.cfg";
    config.preset = loadPreset(config.preset_file);

    if (config.memory_window_mb == 0) {
        uint64_t max_mem = Platform::getMaxTestableMemory(total_ram, config.memory_window_percent);
        config.memory_window_mb = static_cast<uint32_t>(max_mem / 1024 / 1024);
        if (config.memory_window_mb == 0) {
            config.memory_window_mb = static_cast<uint32_t>(total_ram / 1024 / 1024 / 2);
        }
    }

    return config;
}

void onShutdown() {
    LOG_INFO("Shutdown request received. Stopping tests...");
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

    enableVirtualTerminal();
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
        std::cout << "Requesting elevation... (Use --no-elevation to skip)" << std::endl;
        relaunchAsPrivileged(argc, argv);
        return 0; // Exit this instance, the elevated one should take over
    }

    Logger::get().init("testsmem4u.log", debug ? LogLevel::DEBUG : LogLevel::INFO, true);
    auto& log = Logger::get();
    log.setErrorRateLimit(100); // Allow more detailed error logging for diagnostic purposes

    // Check for SeLockMemoryPrivilege (Strict Requirement)
    if (!Platform::hasMemoryLockPrivilege()) {
        std::cout << "\n[!] 'Lock Pages in Memory' privilege (SeLockMemoryPrivilege) is MISSING.\n"
                  << "    This is required for reliable RAM testing to prevent swapping.\n"
                  << "    Do you want to grant this privilege to the current user now?\n"
                  << "    (Requires 'Yes' and then a Sign-out/Reboot to take effect)\n"
                  << "    [Y/n]: ";
        
        std::string answer;
        if (!skip_wizard) {
             std::getline(std::cin, answer);
        } else {
             std::cout << "N (Non-interactive mode)" << std::endl;
             answer = "n";
        }

        if (answer.empty() || answer == "y" || answer == "Y") {
            if (Platform::grantMemoryLockPrivilege()) {
                std::cout << "\n[+] Privilege granted successfully!\n"
                          << "    PLEASE SIGN OUT AND SIGN BACK IN for the changes to take effect.\n"
                          << "    The program will now exit." << std::endl;
                return 0;
            } else {
                std::cerr << "\n[-] Failed to grant privilege. You may need to run as Administrator manually or use the Group Policy Editor." << std::endl;
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
            config.halt_on_error = true;
            config.preset_file = "default.cfg";
        }

        // Ensure calculations are correct based on current config (loaded or default)
        if (config.memory_window_mb == 0) {
            uint64_t total_ram = Platform::getTotalSystemRAM();
            uint64_t max_mem = Platform::getMaxTestableMemory(total_ram, config.memory_window_percent);
            config.memory_window_mb = static_cast<uint32_t>(max_mem / 1024 / 1024);
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
            uint64_t total_ram = Platform::getTotalSystemRAM();
            uint64_t max_mem = Platform::getMaxTestableMemory(total_ram, 85);
            config.memory_window_mb = static_cast<uint32_t>(max_mem / 1024 / 1024);
            config.use_locked_memory = true;
            config.halt_on_error = false;
            config.cycles = 0;
        }
    } else {
        config = runConfigWizard();
        saveConfig("config.ini", config);
    }

    std::cout << "\nStarting tests with " << config.cores << " threads, " << config.memory_window_mb << " MB memory." << std::endl;
    std::cout << "Tip: Press Ctrl+C to stop and save results.\n" << std::endl;

    if (config.preset.test_configs.empty()) {
        std::cerr << "\n[!] ERROR: No tests loaded! Please verify " << config.preset_file << " exists and is valid." << std::endl;
#ifdef _WIN32
        std::cout << "Press any key to exit..." << std::endl;
        _getch();
#endif
        return 1;
    }

    RunResult res = {};
    try {
        res = TestEngine::runTests(config);
    } catch (const std::exception& e) {
        log.error("FATAL: Uncaught exception during test execution: %s", e.what());
        std::cerr << "\n[!] FATAL ERROR: " << e.what() << std::endl;
        res.hard_errors++; // Count this as a failure
    } catch (...) {
        log.error("FATAL: Unknown exception caught during test execution");
        std::cerr << "\n[!] FATAL ERROR: Unknown exception occurred." << std::endl;
        res.hard_errors++;
    }

    std::cout << "\n--- Results ---" << std::endl;
    std::cout << "Total Errors: " << res.total_errors() << std::endl;
    std::cout << "  Hard (confirmed):   " << res.hard_errors << std::endl;
    std::cout << "  Soft (transient):   " << res.soft_errors << std::endl;
    std::cout << "  Unverified:         " << res.unverified_errors << std::endl;
    std::cout << "Time: " << res.duration_seconds << "s" << std::endl;

    // Ensure logger flushes all pending messages before exit
    Logger::get().deinit();

#ifdef _WIN32
    std::cout << "\nPress any key to exit..." << std::endl;
    _getch();
#else
    // On Linux, if we auto-launched in a terminal, wait for keypress so user can see results
    if (isGraphicalSession()) {
        std::cout << "\nPress Enter to exit..." << std::endl;
        getchar();
    }
#endif

    return res.total_errors() == 0 ? 0 : 1;
}

} // namespace testsmem4u

int main(int argc, char* argv[]) {
    return testsmem4u::main(argc, argv);
}
