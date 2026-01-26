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
    try {
        size_t pos;
        uint32_t val = std::stoul(str, &pos);
        if (pos == str.size()) {
            result = val;
            return true;
        }
    } catch (...) {
    }
    return false;
}

[[maybe_unused]] static bool parseIntOrDefault(const std::string& str, int32_t& result, int32_t default_val) {
    if (str.empty()) {
        result = default_val;
        return true;
    }
    try {
        size_t pos;
        int32_t val = std::stoi(str, &pos);
        if (pos == str.size()) {
            result = val;
            return true;
        }
    } catch (...) {
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

    try {
        config.preset = loadPreset(config.preset_file);
    } catch (...) {
        LOG_WARN("Could not load preset '%s', using internal defaults", config.preset_file.c_str());
    }

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
    log.setErrorRateLimit(10); // Limit error reporting to 10/sec to avoid log spam

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
    if (!skip_wizard) {
        if (loadConfig("config.ini", config)) {
            loaded_from_file = true;
        } else {
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

        // Load the preset referenced in the config
        try {
            if (config.preset_file.empty()) config.preset_file = "default.cfg";
            config.preset = loadPreset(config.preset_file);
        } catch (...) {
            LOG_WARN("Could not load preset '%s', using internal defaults", config.preset_file.c_str());
        }

        // Show appropriate message
        const char* msg = loaded_from_file ? "Starting with saved settings..." : "Starting with default settings...";

        // Wait for user input
        if (waitForInput(3, msg)) {
            skip_wizard = false;
            config_loaded = false; // Force re-run wizard
        } else {
            skip_wizard = true;
            config_loaded = true; // Use the current config
        }
    }

    if (skip_wizard) {
        if (!config_loaded) {
            if (!preset_path.empty()) config.preset_file = preset_path;
            else if (config.preset_file.empty()) config.preset_file = "default.cfg";

            try {
                config.preset = loadPreset(config.preset_file);
            } catch (...) {
                LOG_WARN("Could not load preset '%s'", config.preset_file.c_str());
            }
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

    try {
        RunResult res = TestEngine::runTests(config);

        std::cout << "\n--- Results ---" << std::endl;
        std::cout << "Errors: " << res.total_errors() << " (Hard: " << res.hard_errors << ", Soft: " << res.soft_errors << ")" << std::endl;
        std::cout << "Time: " << res.duration_seconds << "s" << std::endl;

        // Ensure logger flushes all pending messages before exit
        Logger::get().deinit();

#ifdef _WIN32
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
#endif

        return res.total_errors() == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "CRITICAL ERROR: " << e.what() << std::endl;
        Logger::get().deinit();
#ifdef _WIN32
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
#endif
        return 1;
    }
}

} // namespace testsmem4u

int main(int argc, char* argv[]) {
    return testsmem4u::main(argc, argv);
}
