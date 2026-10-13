#include "TestEngine.h"
#include "RunConfiguration.h"
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

namespace testsmem4u {

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
    select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
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

static bool isPrivileged() {
#ifdef _WIN32
    BOOL fRet = FALSE;
    HANDLE hToken = nullptr;
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
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path for elevation." << '\n';
        return false;
    }

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = exePath;
    sei.lpParameters = args.c_str();
    sei.hwnd = nullptr;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            std::cerr << "Elevation refused by user." << '\n';
        } else {
            std::cerr << "Failed to elevate: Error " << err << '\n';
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
        std::cerr << "Failed to wait for elevated process: error " << GetLastError() << '\n';
        CloseHandle(sei.hProcess);
        exit_code = 2;
        return true;
    }
    DWORD child_exit_code = 0;
    if (!GetExitCodeProcess(sei.hProcess, &child_exit_code)) {
        std::cerr << "Failed to read elevated process exit code: error " << GetLastError() << '\n';
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
    std::cerr << "Failed to run sudo: " << strerror(errno) << '\n';
    return false;
#endif
}

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
        ss << "Tested memory: " << std::fixed << std::setprecision(2)
           << res.bytes_tested / (1024.0 * 1024.0 * 1024.0)
           << " GiB (" << res.bytes_tested << " bytes verified; repeated reads included)";
        ConsoleDisplay::get().printLine(ss.str());
        ConsoleDisplay::get().printLine("Completed cycles: " + std::to_string(res.cycles_completed));
    }
    LOG_INFO("Results: verified-bytes=%llu complete-cycles=%llu errors=%llu duration=%.3fs infrastructure-failure=%s",
             static_cast<unsigned long long>(res.bytes_tested),
             static_cast<unsigned long long>(res.cycles_completed),
             static_cast<unsigned long long>(res.total_errors()), res.duration_seconds,
             res.infrastructure_failure ? "yes" : "no");
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

int main(int argc, char* argv[]) try {
    return testsmem4u::main(argc, argv);
} catch (const std::exception& error) {
    // Startup/configuration can throw before the normal runtime handler exists.
    // Use an allocation-free diagnostic when even the logger may be unavailable.
    std::fprintf(stderr, "FATAL: application startup failed: %s\n", error.what());
    return 2;
} catch (...) {
    std::fputs("FATAL: application startup failed with an unknown exception\n", stderr);
    return 2;
}
