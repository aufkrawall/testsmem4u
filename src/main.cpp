    // Add include for exception handling
#include <stdexcept>
// Multi-threaded implementation compiled with Zig LLVM

#include "testsmem4u.h"
#include "Logger.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <algorithm>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <winreg.h>  // For registry functions
#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <errno.h>
#endif

namespace testsmem4u {

// Global atomic for thread coordination
static std::atomic<bool> g_stop_flag(false);
static std::atomic<uint64_t> g_total_errors(0);
static std::atomic<uint64_t> g_total_bytes_tested(0);

// Get total system RAM in bytes
uint64_t getTotalSystemRAM() {
#ifdef _WIN32
    ULONGLONG mem_kb = 0;
    if (GetPhysicallyInstalledSystemMemory(&mem_kb)) {
        return mem_kb * 1024ULL;
    }
    return 0;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return info.totalram * info.mem_unit;
    }
    return 0;
#endif
}

// Parse memory size input (e.g., "1024", "50%")
uint32_t parseMemorySize(const std::string& input, uint64_t system_ram_bytes) {
    if (input.empty()) {
        // Default: 85% of system RAM
        return static_cast<uint32_t>((system_ram_bytes / 1024 / 1024) * 85 / 100);
    }
    
    // Check for percentage format
    if (input.back() == '%') {
        std::string percent_str = input.substr(0, input.size() - 1);
        try {
            uint32_t percent = std::stoi(percent_str);
            return static_cast<uint32_t>((system_ram_bytes / 1024 / 1024) * percent / 100);
        } catch (...) {
            return 1024;  // Fallback
        }
    }
    
    // Otherwise, treat as MB
    try {
        return std::stoi(input);
    } catch (...) {
        return 1024;  // Fallback
    }
}

// Platform detection
PlatformInfo detectPlatform() {
    PlatformInfo info = {};

#ifdef _WIN32
    strcpy(info.os_name, "Windows");
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    info.cpu_cores = sys_info.dwNumberOfProcessors;
    info.page_size = sys_info.dwPageSize;

#ifdef _M_X64
    strcpy(info.arch, "x86_64");
#elif _M_IX86
    strcpy(info.arch, "x86");
#elif _M_ARM64
    strcpy(info.arch, "ARM64");
#else
    strcpy(info.arch, "Unknown");
#endif
#else
    strcpy(info.os_name, "Linux");
    info.cpu_cores = std::thread::hardware_concurrency();
    info.page_size = sysconf(_SC_PAGESIZE);

#if __x86_64__
    strcpy(info.arch, "x86_64");
#elif __i386__
    strcpy(info.arch, "x86");
#elif __aarch64__
    strcpy(info.arch, "ARM64");
#else
    strcpy(info.arch, "Unknown");
#endif
#endif

    LOG_INFO("Platform detected: %s %s (%u cores, %u KB page)",
        info.os_name, info.arch, info.cpu_cores, info.page_size);

    return info;
}

#ifdef _WIN32

// Check Windows LockedPageLimit registry value (read-only)
uint64_t getLockedPageLimitKB() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(value);
    
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueExA(hKey, "LockedPageLimit", nullptr, nullptr, 
                                   reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(hKey);
        
        if (result == ERROR_SUCCESS) {
            return static_cast<uint64_t>(value);
        }
    }
    
    return 0;
}

bool restoreLockedPageLimit(bool& requires_reboot) {
    requires_reboot = false;
    HKEY hKey;

    const char* reg_path = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    const char* value_name = "LockedPageLimit";

    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ | KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Error: Could not open registry key for writing" << std::endl;
        LOG_ERROR("Cannot open registry key: error %lu", result);
        return false;
    }

    result = RegDeleteValueA(hKey, value_name);
    if (result == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(hKey);
        return true;
    }

    if (result == ERROR_SUCCESS) {
        std::cout << "*** LockedPageLimit restored to default (deleted). ***" << std::endl;
        std::cout << "*** YOU MUST REBOOT YOUR SYSTEM for changes to take effect! ***" << std::endl;
        LOG_INFO("LockedPageLimit deleted (restore default)");
        RegCloseKey(hKey);
        requires_reboot = true;
        return true;
    }

    DWORD zero = 0;
    LONG set_result = RegSetValueExA(hKey, value_name, 0, REG_DWORD,
                                    reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
    if (set_result == ERROR_SUCCESS) {
        std::cout << "*** LockedPageLimit restored to default (set to 0). ***" << std::endl;
        std::cout << "*** YOU MUST REBOOT YOUR SYSTEM for changes to take effect! ***" << std::endl;
        LOG_INFO("LockedPageLimit set to 0 (restore default)");
        RegCloseKey(hKey);
        requires_reboot = true;
        return true;
    }

    LOG_ERROR("Failed to restore LockedPageLimit: delete=%lu set=%lu", result, set_result);
    RegCloseKey(hKey);
    return false;
}

// Check Windows LockedPageLimit registry value and optionally fix it
bool checkAndFixLockedPageLimit(uint64_t requested_size_bytes, bool& requires_reboot) {
    requires_reboot = false;
    HKEY hKey;
    DWORD current_value = 0;
    DWORD size = sizeof(current_value);
    
    const char* reg_path = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    const char* value_name = "LockedPageLimit";
    
    // Try to read current value
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        if (result == ERROR_ACCESS_DENIED) {
            LOG_INFO("Registry key not readable without elevation (skipping LockedPageLimit check)");
            std::cout << "Note: Cannot read LockedPageLimit (access denied). Run elevated if you want registry diagnostics." << std::endl;
            return true;
        }
        LOG_WARN("Cannot open registry key (KEY_READ): error %lu", result);
        return true;
    }
    
    // Read current value
    result = RegQueryValueExA(hKey, value_name, nullptr, nullptr, 
                              reinterpret_cast<LPBYTE>(&current_value), &size);
    
    uint64_t requested_kb = requested_size_bytes / 1024;
    
    if (result == ERROR_SUCCESS && current_value > 0) {
        if (current_value >= requested_kb) {
            std::cout << "LockedPageLimit: " << (current_value / 1024) << " MB (" << current_value << " KB)" << std::endl;
            LOG_INFO("LockedPageLimit sufficient: %lu KB", current_value);
            RegCloseKey(hKey);
            return true;
        } else {
            std::cout << "LockedPageLimit: " << (current_value / 1024) << " MB (" << current_value << " KB)" << std::endl;
            std::cout << "Required: " << (requested_kb / 1024) << " MB" << std::endl;
        }
    } else {
        std::cout << "LockedPageLimit: NOT SET" << std::endl;
        std::cout << "Required: " << (requested_kb / 1024) << " MB" << std::endl;
    }
    
    // Ask user if they want to fix
    std::cout << "\nDo you want to set LockedPageLimit to " << (requested_kb / 1024) << " MB? (y/n): ";
    std::string input;
    std::getline(std::cin, input);
    
    if (input == "y" || input == "Y") {
        RegCloseKey(hKey);
        result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ | KEY_WRITE, &hKey);
        if (result != ERROR_SUCCESS) {
            if (result == ERROR_ACCESS_DENIED) {
                LOG_INFO("Registry write requires elevation (skipping LockedPageLimit set)");
                std::cout << "Note: Setting LockedPageLimit requires admin. Run elevated to apply it." << std::endl;
                return true;
            }
            LOG_WARN("Cannot open registry key (KEY_WRITE): error %lu", result);
            return false;
        }

        std::cout << "Setting LockedPageLimit to " << requested_kb << " KB..." << std::endl;
 
        DWORD requested_kb_dword = (requested_kb > 0xFFFFFFFFULL) ? 0xFFFFFFFFUL : static_cast<DWORD>(requested_kb);
        result = RegSetValueExA(hKey, value_name, 0, REG_DWORD,
                                reinterpret_cast<const BYTE*>(&requested_kb_dword), sizeof(requested_kb_dword));
        
        if (result == ERROR_SUCCESS) {
            std::cout << "*** LockedPageLimit set successfully! ***" << std::endl;
            std::cout << "*** YOU MUST REBOOT YOUR SYSTEM for changes to take effect! ***" << std::endl;
            LOG_INFO("LockedPageLimit set to %lu KB", requested_kb);
            RegCloseKey(hKey);
            requires_reboot = true;
            return true;
        } else {
            std::cerr << "Failed to set LockedPageLimit: error " << result << std::endl;
            LOG_ERROR("Failed to set LockedPageLimit: error %lu", result);
            RegCloseKey(hKey);
            return false;
        }
    } else {
        std::cout << "Skipping LockedPageLimit fix." << std::endl;
        RegCloseKey(hKey);
        return false;
    }
}

// Print Windows-specific memory lock diagnostics and requirements
void printLockDiagnostics(uint64_t requested_size_bytes) {
    uint64_t locked_limit_kb = getLockedPageLimitKB();
    uint64_t requested_kb = requested_size_bytes / 1024;

    std::cout << "\n=== Windows VirtualLock Analysis ===" << std::endl;
    std::cout << "Requested lock size: " << (requested_kb / 1024) << " MB (" << requested_kb << " KB)" << std::endl;

    if (locked_limit_kb > 0) {
        std::cout << "LockedPageLimit: " << (locked_limit_kb / 1024) << " MB (" << locked_limit_kb << " KB)" << std::endl;

        if (locked_limit_kb >= requested_kb) {
            std::cout << "Status: OK - Limit sufficient for requested size" << std::endl;
        } else {
            std::cout << "Status: INSUFFICIENT - Limit too small!" << std::endl;
        }
    } else {
        std::cout << "LockedPageLimit: Not set" << std::endl;
        std::cout << "Status: Note: VirtualLock limits are primarily based on the process working set." << std::endl;
    }
    std::cout << "=======================================" << std::endl;
}

// Get detailed memory information for diagnostics
void logMemoryDiagnostics(const char* context, size_t requested_size) {
    HANDLE hProcess = GetCurrentProcess();
    PROCESS_MEMORY_COUNTERS pmc;

    LOG_INFO("=== VirtualLock Diagnostics: %s ===", context);
    LOG_INFO("Requested lock size: %zu MB (%zu bytes)",
             requested_size / (1024 * 1024), requested_size);

    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        LOG_INFO("Current process memory usage:");
        LOG_INFO("  WorkingSetSize: %zu KB (%zu MB)",
                 pmc.WorkingSetSize / 1024, pmc.WorkingSetSize / (1024 * 1024));
        LOG_INFO("  PeakWorkingSetSize: %zu KB (%zu MB)",
                 pmc.PeakWorkingSetSize / 1024, pmc.PeakWorkingSetSize / (1024 * 1024));
        LOG_INFO("  PagefileUsage: %zu KB (%zu MB)",
                 pmc.PagefileUsage / 1024, pmc.PagefileUsage / (1024 * 1024));
    }

    BOOL is_elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD len = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len)) {
            is_elevated = elevation.TokenIsElevated;
            LOG_INFO("  Process elevated: %s", is_elevated ? "Yes" : "No");
        }
        CloseHandle(token);
    }

    LOG_INFO("Current LockedPageLimit: %llu KB (%llu MB)",
             (unsigned long long)getLockedPageLimitKB(),
             (unsigned long long)(getLockedPageLimitKB() / 1024));
    LOG_INFO("=========================================");
}

// Enable SeLockMemoryPrivilege for VirtualLock
bool enableLockMemoryPrivilege() {
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    
    // Open the process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LOG_WARN("OpenProcessToken failed: %lu", GetLastError());
        return false;
    }
    
    // Lookup the privilege value
    if (!LookupPrivilegeValue(nullptr, TEXT("SeLockMemoryPrivilege"), &luid)) {
        LOG_WARN("LookupPrivilegeValue failed: %lu", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    
    // Prepare the privilege structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    // Enable the privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        LOG_WARN("AdjustTokenPrivileges failed: %lu", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    
    // Check if the privilege was successfully enabled
    DWORD error = GetLastError();
    if (error == ERROR_SUCCESS) {
        LOG_INFO("SeLockMemoryPrivilege enabled successfully");
        CloseHandle(hToken);
        return true;
    } else if (error == ERROR_NOT_ALL_ASSIGNED) {
        LOG_WARN("SeLockMemoryPrivilege not assigned to token");
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    return false;
}

#endif // _WIN32

#ifndef _WIN32

void printLockDiagnostics(uint64_t requested_size_bytes) {
    const uint64_t requested_kb = requested_size_bytes / 1024;
    std::cout << "\n=== Linux mlock Analysis ===" << std::endl;
    std::cout << "Requested lock size: " << (requested_kb / 1024) << " MB (" << requested_kb << " KB)" << std::endl;

    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY) {
            std::cout << "RLIMIT_MEMLOCK: unlimited" << std::endl;
        } else {
            std::cout << "RLIMIT_MEMLOCK: " << (static_cast<uint64_t>(rl.rlim_cur) / 1024 / 1024) << " MB" << std::endl;
        }

        if (rl.rlim_cur != RLIM_INFINITY && static_cast<uint64_t>(rl.rlim_cur) < requested_size_bytes) {
            std::cout << "Status: INSUFFICIENT - mlock will likely fail with ENOMEM" << std::endl;
            std::cout << "Hint: Increase memlock limit (ulimit -l), configure /etc/security/limits.conf, or grant CAP_IPC_LOCK." << std::endl;
        } else {
            std::cout << "Status: OK (limit appears sufficient)" << std::endl;
        }
    } else {
        std::cout << "RLIMIT_MEMLOCK: unavailable (getrlimit failed: " << errno << ")" << std::endl;
    }

    std::cout << "=======================================" << std::endl;
}

#endif

// Exception for fatal errors that should abort the program
class FatalErrorException : public std::exception {
private:
    std::string message;
public:
    FatalErrorException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};

// Memory allocation with proper VirtualLock handling - throws on lock failure if requested
bool allocateMemory(MemoryRegion& region, size_t size, bool lock, bool& locked_successfully, bool fail_on_lock_error = false) {
    locked_successfully = false;
    region.size = size;

    LOG_MEM_ALLOC(nullptr, size, lock);

#ifdef _WIN32
    // Log diagnostics before allocation attempt
    if (lock) {
        logMemoryDiagnostics("before VirtualAlloc", size);
    }
    
    // Allocate memory first
    region.base = (uint8_t*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!region.base) {
        uint32_t error = GetLastError();
        LOG_MEM_ERROR("VirtualAlloc", error);
        std::cerr << "VirtualAlloc failed: " << error << std::endl;
        return false;
    }
    LOG_INFO("VirtualAlloc succeeded: 0x%016llX", (unsigned long long)(uintptr_t)region.base);

    if (lock) {
        (void)enableLockMemoryPrivilege();

        HANDLE hProcess = GetCurrentProcess();
        SIZE_T cur_min_ws = 0, cur_max_ws = 0;
        if (GetProcessWorkingSetSize(hProcess, &cur_min_ws, &cur_max_ws)) {
            const SIZE_T buffer = 64 * 1024 * 1024;
            SIZE_T desired_min_ws = size + buffer;
            SIZE_T desired_max_ws = size + (buffer * 2);
            if (desired_min_ws > cur_min_ws || desired_max_ws > cur_max_ws) {
                if (!SetProcessWorkingSetSize(hProcess, desired_min_ws, desired_max_ws)) {
                    DWORD ws_error = GetLastError();
                    LOG_WARN("SetProcessWorkingSetSize failed: %lu", ws_error);
                } else {
                    LOG_INFO("Working set adjusted: min=%zu MB max=%zu MB",
                             desired_min_ws / (1024 * 1024), desired_max_ws / (1024 * 1024));
                }
            }
        }

        const size_t chunk_size = 64 * 1024 * 1024;
        size_t locked_bytes = 0;
        while (locked_bytes < size) {
            size_t to_lock = size - locked_bytes;
            if (to_lock > chunk_size) to_lock = chunk_size;

            uint8_t* lock_ptr = region.base + locked_bytes;
            if (!VirtualLock(lock_ptr, to_lock)) {
                uint32_t error = GetLastError();
                LOG_MEM_ERROR("VirtualLock", error);

                std::cerr << "\n*** ERROR ***" << std::endl;
                std::cerr << "Memory locking failed (error " << error << ")!" << std::endl;

                if (error == ERROR_WORKING_SET_QUOTA) {
                    std::cerr << "Working set quota too small for requested lock size." << std::endl;
                } else if (error == ERROR_PRIVILEGE_NOT_HELD || error == ERROR_ACCESS_DENIED) {
                    std::cerr << "Insufficient privileges to lock that much memory. Try running elevated." << std::endl;
                }

                if (locked_bytes > 0) {
                    VirtualUnlock(region.base, locked_bytes);
                }

                if (fail_on_lock_error) {
                    VirtualFree(region.base, 0, MEM_RELEASE);
                    region.base = nullptr;
                    region.size = 0;
                    return false;
                }

                VirtualFree(region.base, 0, MEM_RELEASE);
                region.base = nullptr;
                region.size = 0;
                throw FatalErrorException("Memory lock failed - aborting as requested");
            }

            locked_bytes += to_lock;
        }

        locked_successfully = true;
        LOG_INFO("VirtualLock succeeded (%zu MB)", size / (1024 * 1024));
    }
#else
    region.base = (uint8_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region.base == MAP_FAILED) {
        LOG_ERROR("mmap failed", 0);
        region.base = nullptr;
        return false;
    }
    LOG_INFO("mmap succeeded: 0x%016llX", (unsigned long long)(uintptr_t)region.base);

    if (lock) {
        if (mlock(region.base, size) == 0) {
            locked_successfully = true;
            LOG_INFO("mlock succeeded");
        } else {
            int error = errno;
            LOG_MEM_ERROR("mlock", error);
            std::cerr << "\n*** ERROR ***" << std::endl;
            std::cerr << "Memory locking failed! Error code: " << error << std::endl;
            LOG_ERROR("Memory locking failed: %d", error);
            
            // Free the memory
            munmap(region.base, region.size);
            region.base = nullptr;
            region.size = 0;
            
            if (fail_on_lock_error) {
                return false;
            }
        }
    }
#endif

    std::cout << "Allocated " << (size / (1024 * 1024)) << " MB at 0x"
              << std::hex << (uintptr_t)region.base << std::dec << std::endl;
    return true;
}

// Free memory
void freeMemory(MemoryRegion& region) {
    if (region.base) {
        LOG_MEM_FREE(region.base);

#ifdef _WIN32
        VirtualUnlock(region.base, region.size);
        VirtualFree(region.base, 0, MEM_RELEASE);
#else
        munlock(region.base, region.size);
        munmap(region.base, region.size);
#endif
        region.base = nullptr;
        region.size = 0;
        LOG_INFO("Memory released", 0);
    }
}

// Parse test sequence from string
std::vector<uint32_t> parseTestSequence(const std::string& sequence) {
    std::vector<uint32_t> tests;
    size_t pos = 0;
    while (pos < sequence.size()) {
        size_t comma = sequence.find(',', pos);
        std::string token = (comma == std::string::npos) ?
            sequence.substr(pos) : sequence.substr(pos, comma - pos);
        try {
            size_t start = token.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) {
                pos = (comma == std::string::npos) ? sequence.size() : comma + 1;
                continue;
            }
            size_t end = token.find_last_not_of(" \t\r\n");
            std::string trimmed = token.substr(start, end - start + 1);
            tests.push_back(static_cast<uint32_t>(std::stoul(trimmed)));
        } catch (...) {
        }
        pos = (comma == std::string::npos) ? sequence.size() : comma + 1;
    }
    LOG_DEBUG("Parsed test sequence: %zu tests", tests.size());
    return tests;
}

bool allocateMemory(MemoryRegion& region, size_t size, bool lock) {
    bool locked_successfully = false;
    return allocateMemory(region, size, lock, locked_successfully, true);
}

// Configuration wizard
Config runConfigWizard() {
    Config config = {};

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  testsmem4u Configuration Wizard\n";
    std::cout << "========================================\n\n";

    // List available presets
    std::vector<std::string> presets = listPresets(".");
    
    std::cout << "Available presets:" << std::endl;
    for (size_t i = 0; i < presets.size(); i++) {
        std::cout << "  " << (i + 1) << ". " << presets[i] << std::endl;
    }
    
    // Preset selection - default preset
    std::cout << "\nSelect preset [default.cfg]: ";
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) {
        config.preset_file = "default.cfg";
    } else {
        // Check if input is a number (index) or filename
        bool is_number = true;
        for (char c : input) {
            if (!isdigit(c)) {
                is_number = false;
                break;
            }
        }
        
        if (is_number && !input.empty()) {
            size_t idx = std::stoul(input);
            if (idx > 0 && idx <= presets.size()) {
                config.preset_file = presets[idx - 1];
            } else {
                config.preset_file = "default.cfg";
            }
        } else {
            // Assume it's a filename
            config.preset_file = input;
        }
    }
    
    // Load the preset
    config.preset = loadPreset(config.preset_file);
    
    if (config.preset.test_configs.empty()) {
        std::cerr << "Warning: Failed to load preset or preset is empty!" << std::endl;
        LOG_WARN("Preset loading failed or empty");
    }

    // Get system RAM for display
    uint64_t system_ram = getTotalSystemRAM();
    uint32_t system_ram_mb = static_cast<uint32_t>(system_ram / 1024 / 1024);
    uint32_t max_test_mb = static_cast<uint32_t>((system_ram / 1024 / 1024) * 85 / 100);
    uint64_t lock_target_bytes = (system_ram * 90) / 100;

    // Memory window size - use preset value as default
    uint32_t default_mem_mb = config.preset.memory_window_mb > 0 ? config.preset.memory_window_mb : max_test_mb;
    if (default_mem_mb > max_test_mb) default_mem_mb = max_test_mb;
    std::cout << "\nMemory Window Size [" << default_mem_mb << " MB]: ";
    std::getline(std::cin, input);
    if (input.empty()) {
        config.memory_window_mb = default_mem_mb;
    } else {
        config.memory_window_mb = parseMemorySize(input, system_ram);
    }
    if (config.memory_window_mb > max_test_mb) {
        std::cout << "Note: Capping memory window to 85% of installed RAM (" << max_test_mb << " MB)." << std::endl;
        config.memory_window_mb = max_test_mb;
    }
    LOG_INFO("Memory window: %u MB", config.memory_window_mb);

    // Number of cores - use preset value as default
    PlatformInfo platform = detectPlatform();
    uint32_t default_cores = config.preset.cores > 0 ? config.preset.cores : platform.cpu_cores;
    std::cout << "Number of CPU cores (0 = auto, max " << platform.cpu_cores << ") [" << default_cores << "]: ";
    std::getline(std::cin, input);
    if (!input.empty()) {
        config.cores = std::stoi(input);
        if (config.cores == 0) config.cores = platform.cpu_cores;
    } else {
        config.cores = default_cores;
    }
    LOG_INFO("Using %u cores", config.cores);

    // Test cycles - use preset value as default
    uint32_t default_cycles = config.preset.cycles > 0 ? config.preset.cycles : 0;
    std::cout << "Number of test cycles (0 = infinite) [" << default_cycles << "]: ";
    std::getline(std::cin, input);
    if (!input.empty()) {
        config.cycles = std::stoi(input);
    } else {
        config.cycles = default_cycles;
    }
    LOG_INFO("Cycles: %u", config.cycles);

    // Halt on error
    std::cout << "Halt on error (y/n) [n]: ";
    std::getline(std::cin, input);
    bool user_halt = (input == "y" || input == "Y");
    config.halt_on_error = user_halt;
    LOG_INFO("Halt on error: %d", config.halt_on_error);

    // Lock memory - MUST abort if user requests lock but it fails
    std::cout << "Lock memory to prevent paging (y/n) [y]: ";
    std::getline(std::cin, input);
    config.use_locked_memory = (input.empty() || input == "y" || input == "Y");
    LOG_INFO("Lock memory: %d", config.use_locked_memory);
    
    if (config.use_locked_memory) {
        printLockDiagnostics(static_cast<uint64_t>(config.memory_window_mb) * 1024 * 1024);

#ifdef _WIN32
        std::cout << "Restore LockedPageLimit registry value to default (y/n) [n]: ";
        std::getline(std::cin, input);
        bool restore_locked_limit = (input == "y" || input == "Y");
        if (restore_locked_limit) {
            bool restore_requires_reboot = false;
            bool restore_ok = restoreLockedPageLimit(restore_requires_reboot);
            if (restore_ok && restore_requires_reboot) {
                std::cout << "\n*** IMPORTANT: REBOOT NOW and run testsmem4u again ***" << std::endl;
                std::cout << "After reboot, memory locking will work properly." << std::endl;

                Logger::get().deinit();
                exit(0);
            }
        }
#endif
        
#ifdef _WIN32
        bool requires_reboot = false;
        bool fixed = checkAndFixLockedPageLimit(lock_target_bytes, requires_reboot);
        
        if (requires_reboot) {
            std::cout << "\n*** IMPORTANT: REBOOT NOW and run testsmem4u again ***" << std::endl;
            std::cout << "After reboot, memory locking will work properly." << std::endl;
            
            // Cleanup logging
            Logger::get().deinit();
            
            exit(0);  // Exit gracefully, user needs to reboot
        }
        
        if (!fixed) {
            std::cout << "\n*** NOTE ***" << std::endl;
            std::cout << "On modern Windows, VirtualLock limits are mostly governed by the process working set." << std::endl;
            std::cout << "If locking fails, try running elevated, reducing the memory window, or closing other apps." << std::endl;
            std::cout << "If locking fails, the program will ABORT as requested." << std::endl << std::endl;
        }
#else
        (void)lock_target_bytes;
#endif
    }

    std::cout << "\n";
    return config;
}

// Worker thread function for parallel testing
void workerThread(uint32_t thread_id, uint32_t num_threads,
                  const MemoryRegion& region, const TestConfig& test_config,
                  bool halt_on_error, size_t block_size_bytes) {
    LOG_THREAD_START(thread_id);

    TestResult result = {};
    const size_t size = region.size;

    if (block_size_bytes == 0 || block_size_bytes >= size) {
        size_t chunk_size = (size / num_threads) & ~static_cast<size_t>(7);
        if (chunk_size == 0) {
            chunk_size = size;
            num_threads = 1;
            thread_id = 0;
        }
        size_t start_offset = thread_id * chunk_size;
        size_t end_offset = (thread_id == num_threads - 1) ? size : start_offset + chunk_size;

        LOG_DEBUG("Thread %u: testing range 0x%016llX - 0x%016llX (%zu bytes)",
            thread_id, (unsigned long long)start_offset, (unsigned long long)end_offset, end_offset - start_offset);

        MemoryRegion thread_region;
        thread_region.base = region.base + start_offset;
        thread_region.size = end_offset - start_offset;

        result = runTest(test_config.function, thread_region, test_config, halt_on_error);
    } else {
        size_t block_size_aligned = block_size_bytes & ~static_cast<size_t>(7);
        if (block_size_aligned == 0) {
            block_size_aligned = 8;
        }

        const size_t blocks = (size + block_size_aligned - 1) / block_size_aligned;

        for (size_t b = thread_id; b < blocks && !g_stop_flag; b += num_threads) {
            const size_t start_offset = b * block_size_aligned;
            if (start_offset >= size) break;

            size_t this_size = size - start_offset;
            if (this_size > block_size_aligned) this_size = block_size_aligned;
            this_size &= ~static_cast<size_t>(7);
            if (this_size == 0) continue;

            MemoryRegion block_region;
            block_region.base = region.base + start_offset;
            block_region.size = this_size;

            TestResult r = runTest(test_config.function, block_region, test_config, halt_on_error);
            result.errors += r.errors;
            result.bytes_tested += r.bytes_tested;

            if (halt_on_error && r.errors > 0) {
                g_stop_flag = true;
                break;
            }
        }
    }

    // Accumulate errors and bytes
    g_total_errors.fetch_add(result.errors, std::memory_order_relaxed);
    g_total_bytes_tested.fetch_add(result.bytes_tested, std::memory_order_relaxed);
    if (halt_on_error && result.errors > 0) {
        g_stop_flag = true;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = 0; // We would need to track start time properly

    LOG_THREAD_COMPLETE(thread_id, duration);
    LOG_DEBUG("Thread %u completed: %llu errors", thread_id, (unsigned long long)result.errors);
}

static TestResult runThreadWork(uint32_t thread_id, uint32_t num_threads,
                               const MemoryRegion& region, const TestConfig& test_config,
                               bool halt_on_error, size_t block_size_bytes) {
    TestResult result = {};
    const size_t size = region.size;

    if (block_size_bytes == 0 || block_size_bytes >= size) {
        size_t chunk_size = (size / num_threads) & ~static_cast<size_t>(7);
        if (chunk_size == 0) {
            chunk_size = size;
            num_threads = 1;
            thread_id = 0;
        }
        size_t start_offset = thread_id * chunk_size;
        size_t end_offset = (thread_id == num_threads - 1) ? size : start_offset + chunk_size;

        MemoryRegion thread_region;
        thread_region.base = region.base + start_offset;
        thread_region.size = end_offset - start_offset;

        result = runTest(test_config.function, thread_region, test_config, halt_on_error);
        return result;
    }

    size_t block_size_aligned = block_size_bytes & ~static_cast<size_t>(7);
    if (block_size_aligned == 0) {
        block_size_aligned = 8;
    }

    const size_t blocks = (size + block_size_aligned - 1) / block_size_aligned;
    for (size_t b = thread_id; b < blocks && !g_stop_flag; b += num_threads) {
        const size_t start_offset = b * block_size_aligned;
        if (start_offset >= size) break;

        size_t this_size = size - start_offset;
        if (this_size > block_size_aligned) this_size = block_size_aligned;
        this_size &= ~static_cast<size_t>(7);
        if (this_size == 0) continue;

        MemoryRegion block_region;
        block_region.base = region.base + start_offset;
        block_region.size = this_size;

        TestResult r = runTest(test_config.function, block_region, test_config, halt_on_error);
        result.errors += r.errors;
        result.bytes_tested += r.bytes_tested;

        if (halt_on_error && r.errors > 0) {
            g_stop_flag = true;
            break;
        }
    }

    return result;
}

static TestResult runRegionWork(const MemoryRegion& region, const TestConfig& test_config,
                               bool halt_on_error, size_t block_size_bytes) {
    TestResult result = {};
    const size_t size = region.size;

    if (block_size_bytes == 0 || block_size_bytes >= size) {
        return runTest(test_config.function, region, test_config, halt_on_error);
    }

    size_t block_size_aligned = block_size_bytes & ~static_cast<size_t>(7);
    if (block_size_aligned == 0) {
        block_size_aligned = 8;
    }

    const size_t blocks = (size + block_size_aligned - 1) / block_size_aligned;
    for (size_t b = 0; b < blocks && !g_stop_flag; b++) {
        const size_t start_offset = b * block_size_aligned;
        if (start_offset >= size) break;

        size_t this_size = size - start_offset;
        if (this_size > block_size_aligned) this_size = block_size_aligned;
        this_size &= ~static_cast<size_t>(7);
        if (this_size == 0) continue;

        MemoryRegion block_region;
        block_region.base = region.base + start_offset;
        block_region.size = this_size;

        TestResult r = runTest(test_config.function, block_region, test_config, halt_on_error);
        result.errors += r.errors;
        result.bytes_tested += r.bytes_tested;

        if (halt_on_error && r.errors > 0) {
            g_stop_flag = true;
            break;
        }
    }

    return result;
}

// Run tests with multi-threading
RunResult runTestsMultiThreaded(const Config& config, const MemoryRegion& region,
                                 const std::vector<uint32_t>& test_sequence,
                                 const std::map<uint32_t, TestConfig>& test_configs) {
    RunResult result = {};
    uint32_t num_threads = config.cores;
    uint64_t words = static_cast<uint64_t>(region.size / 8);
    if (words > 0 && num_threads > words) {
        num_threads = static_cast<uint32_t>(words);
    }
    if (num_threads == 0) num_threads = 1;

    LOG_INFO("=== Starting Multi-Threaded Test Run ===", 0);
    LOG_INFO("Memory window: %u MB", config.memory_window_mb);
    LOG_INFO("Cycles: %u", config.cycles);
    LOG_INFO("Threads: %u", num_threads);
    LOG_INFO("Halt on error: %d", config.halt_on_error);
    LOG_INFO("Lock memory: %d", config.use_locked_memory);

    auto start_time = std::chrono::high_resolution_clock::now();

    struct ThreadProgress {
        std::atomic<uint32_t> cycle{0};
        std::atomic<uint32_t> test_idx{0};
        std::atomic<uint32_t> rep{0};
        std::atomic<uint32_t> cycles_completed{0};
        std::atomic<bool> done{false};
    };

    std::vector<ThreadProgress> progress(num_threads);

    std::atomic<uint32_t> threads_done(0);
    g_total_errors = 0;
    g_total_bytes_tested = 0;
    g_stop_flag = false;

    bool infinite = (config.cycles == 0);

    auto worker_fn = [&](uint32_t thread_id) {
        const size_t size = region.size;
        size_t chunk_size = (size / num_threads) & ~static_cast<size_t>(7);
        if (chunk_size == 0) {
            chunk_size = size;
        }
        size_t start_offset = thread_id * chunk_size;
        size_t end_offset = (thread_id == num_threads - 1) ? size : start_offset + chunk_size;
        if (start_offset >= size) {
            progress[thread_id].done.store(true, std::memory_order_release);
            threads_done.fetch_add(1, std::memory_order_acq_rel);
            return;
        }
        if (end_offset > size) end_offset = size;

        MemoryRegion thread_region;
        thread_region.base = region.base + start_offset;
        thread_region.size = end_offset - start_offset;

        uint32_t cycle = 0;
        while (!g_stop_flag && (infinite || cycle < config.cycles)) {
            progress[thread_id].cycle.store(cycle, std::memory_order_relaxed);

            for (uint32_t test_idx = 0; test_idx < test_sequence.size() && !g_stop_flag; test_idx++) {
                progress[thread_id].test_idx.store(test_idx, std::memory_order_relaxed);

                uint32_t test_num = test_sequence[test_idx];
                if (!test_configs.count(test_num)) {
                    continue;
                }

                TestConfig test_config = test_configs.at(test_num);
                test_config.test_number = test_num;

                uint32_t global_time = (config.preset.time_percent > 0) ? config.preset.time_percent : 100;
                uint32_t test_time = (test_config.time_percent > 0) ? test_config.time_percent : 100;
                uint64_t repeats64 = (static_cast<uint64_t>(global_time) * static_cast<uint64_t>(test_time) + 9999ULL) / 10000ULL;
                if (repeats64 == 0) repeats64 = 1;
                uint32_t repeats = (repeats64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : static_cast<uint32_t>(repeats64);

                size_t block_size_bytes = 0;
                if (test_config.block_size_mb > 0) {
                    block_size_bytes = static_cast<size_t>(test_config.block_size_mb) * 1024 * 1024;
                    block_size_bytes &= ~static_cast<size_t>(7);
                    if (block_size_bytes == 0) block_size_bytes = 8;
                }

                for (uint32_t rep = 0; rep < repeats && !g_stop_flag; rep++) {
                    progress[thread_id].rep.store(rep, std::memory_order_relaxed);

                    TestResult tr = runRegionWork(thread_region, test_config, config.halt_on_error, block_size_bytes);

                    g_total_errors.fetch_add(tr.errors, std::memory_order_relaxed);
                    g_total_bytes_tested.fetch_add(tr.bytes_tested, std::memory_order_relaxed);

                    if (config.halt_on_error && tr.errors > 0) {
                        g_stop_flag = true;
                        break;
                    }
                }
            }

            progress[thread_id].cycles_completed.fetch_add(1, std::memory_order_relaxed);
            cycle++;
        }

        progress[thread_id].done.store(true, std::memory_order_release);
        threads_done.fetch_add(1, std::memory_order_acq_rel);
    };

    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (uint32_t t = 0; t < num_threads; t++) {
        workers.emplace_back(worker_fn, t);
    }

    auto last_report = std::chrono::high_resolution_clock::now();
    while (threads_done.load(std::memory_order_acquire) < num_threads && !g_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        auto now = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();

        uint32_t min_cycle = UINT32_MAX;
        uint32_t min_test = UINT32_MAX;
        uint32_t max_cycle = 0;
        uint32_t max_test = 0;
        for (uint32_t t = 0; t < num_threads; t++) {
            uint32_t c = progress[t].cycle.load(std::memory_order_relaxed);
            uint32_t ti = progress[t].test_idx.load(std::memory_order_relaxed);
            if (!progress[t].done.load(std::memory_order_relaxed)) {
                if (c < min_cycle) min_cycle = c;
                if (ti < min_test) min_test = ti;
                if (c > max_cycle) max_cycle = c;
                if (ti > max_test) max_test = ti;
            }
        }
        if (min_cycle == UINT32_MAX) {
            min_cycle = max_cycle;
            min_test = max_test;
        }

        uint64_t errors = g_total_errors.load(std::memory_order_relaxed);
        uint64_t bytes_tested = g_total_bytes_tested.load(std::memory_order_relaxed);

        std::cout << "\rProgress: cycle~" << (min_cycle + 1)
                  << " test~" << (min_test + 1) << "/" << test_sequence.size()
                  << " (fastest " << (max_cycle + 1) << ":" << (max_test + 1) << ")"
                  << "  errors=" << errors
                  << "  tested=" << (bytes_tested / (1024.0 * 1024.0)) << " MB"
                  << "  time=" << elapsed << "s" << std::string(24, ' ') << std::flush;

        last_report = now;
    }
    std::cout << std::endl;

    for (auto& t : workers) {
        t.join();
    }

    result.total_errors = g_total_errors.load(std::memory_order_relaxed);
    result.bytes_tested = g_total_bytes_tested.load(std::memory_order_relaxed);

    uint32_t min_cycles_completed = UINT32_MAX;
    for (uint32_t t = 0; t < num_threads; t++) {
        uint32_t cc = progress[t].cycles_completed.load(std::memory_order_relaxed);
        if (cc < min_cycles_completed) min_cycles_completed = cc;
    }
    if (min_cycles_completed == UINT32_MAX) min_cycles_completed = 0;
    result.cycles_completed = min_cycles_completed;

    auto end_time = std::chrono::high_resolution_clock::now();
    result.duration_seconds = std::chrono::duration<double>(end_time - start_time).count();

    LOG_INFO("=== Test Run Complete ===", 0);
    LOG_INFO("Total errors: %llu", (unsigned long long)result.total_errors);
    LOG_INFO("Duration: %.3f seconds", result.duration_seconds);

    return result;
}

// Run tests single-threaded (fallback)
RunResult runTestsSingleThreaded(const Config& config, const MemoryRegion& region,
                                  const std::vector<uint32_t>& test_sequence,
                                  const std::map<uint32_t, TestConfig>& test_configs) {
    RunResult result = {};

    LOG_INFO("=== Starting Single-Threaded Test Run ===", 0);
    LOG_INFO("Memory window: %u MB", config.memory_window_mb);
    LOG_INFO("Cycles: %u", config.cycles);
    LOG_INFO("Threads: 1 (fallback)", 0);

    auto start_time = std::chrono::high_resolution_clock::now();

    bool infinite = (config.cycles == 0);
    uint32_t cycle = 0;
    
    while (infinite || cycle < config.cycles) {
        if (g_stop_flag) break;

        std::cout << "=== Cycle " << (cycle + 1) << (infinite ? " (infinite)" : "") << " ===" << std::endl;
        LOG_INFO("=== Cycle %u of %s ===", cycle + 1, infinite ? "infinite" : std::to_string(config.cycles).c_str());

        for (uint32_t test_idx = 0; test_idx < test_sequence.size(); test_idx++) {
            uint32_t test_num = test_sequence[test_idx];
            if (!test_configs.count(test_num)) {
                LOG_ERROR("Test #%u not found in preset configs", test_num);
                continue;
            }
            TestConfig test_config = test_configs.at(test_num);
            test_config.test_number = test_num;

            uint32_t global_time = (config.preset.time_percent > 0) ? config.preset.time_percent : 100;
            uint32_t test_time = (test_config.time_percent > 0) ? test_config.time_percent : 100;
            uint64_t repeats64 = (static_cast<uint64_t>(global_time) * static_cast<uint64_t>(test_time) + 9999ULL) / 10000ULL;
            if (repeats64 == 0) repeats64 = 1;
            uint32_t repeats = (repeats64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : static_cast<uint32_t>(repeats64);

            size_t block_size_bytes = 0;
            if (test_config.block_size_mb > 0) {
                block_size_bytes = static_cast<size_t>(test_config.block_size_mb) * 1024 * 1024;
                block_size_bytes &= ~static_cast<size_t>(7);
                if (block_size_bytes == 0) block_size_bytes = 8;
            }

            std::cout << "Running Test " << test_num << ": " << test_config.function << std::endl;

            auto test_start = std::chrono::high_resolution_clock::now();
            TestResult test_result = {};
            for (uint32_t rep = 0; rep < repeats && !g_stop_flag; rep++) {
                if (block_size_bytes == 0 || block_size_bytes >= region.size) {
                    TestResult r = runTest(test_config.function, region, test_config, config.halt_on_error);
                    test_result.errors += r.errors;
                    test_result.bytes_tested += r.bytes_tested;
                } else {
                    size_t block_size_aligned = block_size_bytes & ~static_cast<size_t>(7);
                    if (block_size_aligned == 0) block_size_aligned = 8;
                    const size_t blocks = (region.size + block_size_aligned - 1) / block_size_aligned;
                    for (size_t b = 0; b < blocks && !g_stop_flag; b++) {
                        const size_t start_offset = b * block_size_aligned;
                        size_t this_size = region.size - start_offset;
                        if (this_size > block_size_aligned) this_size = block_size_aligned;
                        this_size &= ~static_cast<size_t>(7);
                        if (this_size == 0) continue;

                        MemoryRegion block_region;
                        block_region.base = region.base + start_offset;
                        block_region.size = this_size;

                        TestResult r = runTest(test_config.function, block_region, test_config, config.halt_on_error);
                        test_result.errors += r.errors;
                        test_result.bytes_tested += r.bytes_tested;
                        if (config.halt_on_error && r.errors > 0) {
                            g_stop_flag = true;
                            break;
                        }
                    }
                }
            }
            auto test_end = std::chrono::high_resolution_clock::now();

            double test_duration = std::chrono::duration<double>(test_end - test_start).count();
            result.total_errors += test_result.errors;
            result.bytes_tested += test_result.bytes_tested;

            std::cout << "Test " << test_num << " completed: " << test_result.errors
                      << " errors, " << (test_result.bytes_tested / (1024.0 * 1024.0))
                      << " MB in " << test_duration << "s" << std::endl;

            if (test_result.errors > 0) {
                LOG_ERROR("Test #%u completed with %llu errors", test_num, (unsigned long long)test_result.errors);
            } else {
                LOG_INFO("Test #%u passed", test_num);
            }

            if (config.halt_on_error && test_result.errors > 0) {
                LOG_WARN("Halting test run due to errors", 0);
                g_stop_flag = true;
                break;
            }
        }
        result.cycles_completed++;
        cycle++;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    result.duration_seconds = std::chrono::duration<double>(end_time - start_time).count();

    LOG_INFO("=== Test Run Complete ===", 0);
    LOG_INFO("Total errors: %llu", (unsigned long long)result.total_errors);
    LOG_INFO("Duration: %.3f seconds", result.duration_seconds);

    return result;
}

// Main test engine
RunResult runTests(const Config& config) {
    RunResult result = {};

    // Allocate memory
    MemoryRegion region = {};
    size_t memory_size = static_cast<size_t>(config.memory_window_mb) * 1024 * 1024;

    bool memory_locked = false;
    
    // First attempt with locking if requested
    if (config.use_locked_memory) {
        if (allocateMemory(region, memory_size, true, memory_locked)) {
            if (memory_locked) {
                LOG_INFO("Memory allocated and locked successfully", 0);
            } else {
                LOG_WARN("Memory allocated but locking failed - continuing without lock", 0);
            }
        } else {
            // Allocation or locking failed entirely
            std::cerr << "\n*** FATAL ERROR ***" << std::endl;
            std::cerr << "Memory allocation or locking failed." << std::endl;
            LOG_ERROR("Memory allocation failed", 0);
            
            // Throw exception to abort
            throw FatalErrorException("Memory allocation failed");
        }
    } else {
        if (allocateMemory(region, memory_size, false, memory_locked)) {
            LOG_INFO("Memory allocated without locking", 0);
        } else {
            std::cerr << "\n*** MEMORY ALLOCATION FAILED ***" << std::endl;
            std::cerr << "Could not allocate the requested memory." << std::endl;
            std::cerr << "Please try reducing the memory window size.\n" << std::endl;
            LOG_ERROR("Memory allocation failed", 0);
            return result;
        }
    }

    LOG_INFO("Memory allocated successfully", 0);

    // Get test sequence and configs from preset
    std::string test_sequence_str = config.preset.test_sequence.empty() ? 
        "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15" : config.preset.test_sequence;
    std::vector<uint32_t> test_sequence = parseTestSequence(test_sequence_str);
    LOG_INFO("Test sequence has %zu tests", test_sequence.size());

    // Use test configs from preset
    std::map<uint32_t, TestConfig> test_configs = config.preset.test_configs;
    
    // Display test sequence
    std::cout << "\nTest sequence: ";
    for (size_t i = 0; i < test_sequence.size(); i++) {
        uint32_t test_num = test_sequence[i];
        std::cout << test_num;
        if (i < test_sequence.size() - 1) std::cout << ", ";
        
        // Display test function info
        if (test_configs.count(test_num)) {
            const TestConfig& tc = test_configs[test_num];
            LOG_DEBUG("Test %u: %s (mode=%u, param=%u)", 
                      test_num, tc.function.c_str(), tc.pattern_mode, tc.parameter);
        }
    }
    std::cout << "\n\n" << std::endl;

    // Run with multi-threading if cores > 1
    if (config.cores > 1) {
        LOG_INFO("Using multi-threaded mode with %u threads", config.cores);
        result = runTestsMultiThreaded(config, region, test_sequence, test_configs);
    } else {
        LOG_INFO("Using single-threaded mode", 0);
        result = runTestsSingleThreaded(config, region, test_sequence, test_configs);
    }

    // Free memory
    freeMemory(region);

    return result;
}

// Default test configurations (kept for backward compatibility, not used by default)
std::map<uint32_t, TestConfig> getDefaultTestConfigs() {
    std::map<uint32_t, TestConfig> configs;

    // Test 0: RefreshStable
    configs[0] = {0, "RefreshStable", 0, 0, 0, 100, 0, 0};

    // Test 1: MirrorMove
    configs[1] = {1, "MirrorMove", 0, 0, 0, 100, 4, 0};

    // Test 2: MirrorMove128
    configs[2] = {2, "MirrorMove128", 0, 0, 0, 100, 2, 0};

    // Test 3: SimpleTest with pattern mode 1
    configs[3] = {3, "SimpleTest", 1, 0x1E5F, 0x45357354, 100, 256, 4};

    // Test 4-15: SimpleTest with various modes
    configs[4] = {4, "SimpleTest", 0, 0, 0, 100, 0, 4};
    configs[5] = {5, "SimpleTest", 0, 0, 0, 100, 0, 0};
    configs[6] = {6, "SimpleTest", 0, 0, 0, 100, 2, 4};
    configs[7] = {7, "SimpleTest", 0, 0, 0, 100, 2, 0};
    configs[8] = {8, "SimpleTest", 2, 0x1E5F, 0x45357354, 100, 0, 4};
    configs[9] = {9, "SimpleTest", 2, 0x2305B, 0x97893FB2, 100, 2, 4};
    configs[10] = {10, "SimpleTest", 2, 0x98FB, 0x552FE552, 100, 0, 0};
    configs[11] = {11, "SimpleTest", 2, 0xC51C, 0xC5052FE6, 100, 2, 0};
    configs[12] = {12, "SimpleTest", 0, 0, 0, 100, 256, 4};
    configs[13] = {13, "SimpleTest", 0, 0, 0, 100, 256, 0};
    configs[14] = {14, "SimpleTest", 2, 0xB79D9, 0x253B69D4, 100, 256, 4};
    configs[15] = {15, "SimpleTest", 2, 0x2305A, 0x1789AB54, 100, 256, 0};

    return configs;
}

// Parse command line arguments
bool parseArgs(int argc, char* argv[], bool& debug_mode, std::string& preset_file) {
    debug_mode = false;
    preset_file = "";
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--debug" || arg == "-d") {
            debug_mode = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: testsmem4u [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --debug, -d       Enable debug logging\n";
            std::cout << "  --preset <file>   Use specified preset file\n";
            std::cout << "  --help, -h        Show this help message\n";
            return false;
        } else if (arg == "--preset" && i + 1 < argc) {
            preset_file = argv[i + 1];
            i++; // Skip next arg
        } else {
            // Assume it's a preset file
            preset_file = arg;
        }
    }
    return true;
}

} // namespace testsmem4u

// Test function implementations
namespace testsmem4u {

// SimpleTest implementation
TestResult runSimpleTest(const MemoryRegion& region, const TestConfig& config, bool stop_on_error) {
    TestResult result = {};
    volatile uint64_t* word_ptr = reinterpret_cast<volatile uint64_t*>(region.base);
    size_t num_words = region.size / 8;
    
    auto generatePattern = [&](size_t offset, uint64_t& val) {
        switch (config.pattern_mode) {
            case 0: // All zeros
                val = 0;
                break;
            case 1: // Fixed pattern
                val = config.pattern_param0 ^ (offset * config.pattern_param1);
                break;
            case 2: // Incremental
                val = config.pattern_param0 + (offset * config.pattern_param1);
                break;
            default:
                val = offset;
        }
    };

    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        uint64_t pattern;
        generatePattern(i * 8, pattern);
        word_ptr[i] = pattern;
        result.bytes_tested += 8;
    }

    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        uint64_t pattern;
        generatePattern(i * 8, pattern);
        uint64_t actual = word_ptr[i];
        if (actual != pattern) {
            result.errors++;
            LOG_ERROR_DETAIL("SimpleTest verify", (uint64_t)(&word_ptr[i]), pattern, actual);
            if (stop_on_error) break;
        }
        result.bytes_tested += 8;
    }

    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        uint64_t pattern;
        generatePattern(i * 8, pattern);
        word_ptr[i] = ~pattern;
        result.bytes_tested += 8;
    }

    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        uint64_t pattern;
        generatePattern(i * 8, pattern);
        uint64_t expected = ~pattern;
        uint64_t actual = word_ptr[i];
        if (actual != expected) {
            result.errors++;
            LOG_ERROR_DETAIL("SimpleTest verify inv", (uint64_t)(&word_ptr[i]), expected, actual);
            if (stop_on_error) break;
        }
        result.bytes_tested += 8;
    }
    
    return result;
}

// MirrorMove implementation - tests memory with moving inversions
TestResult runMirrorMove(const MemoryRegion& region, const TestConfig& config, bool stop_on_error) {
    TestResult result = {};
    uint8_t* ptr = region.base;
    uint8_t* end = region.base + region.size;
    
    // Write phase - fill with pattern
    uint64_t pattern = 0xAAAAAAAA55555555ULL;
    volatile uint64_t* word_ptr = reinterpret_cast<volatile uint64_t*>(ptr);
    size_t num_words = region.size / 8;
    
    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        word_ptr[i] = pattern;
        result.bytes_tested += 8;
    }
    
    uint32_t passes = (config.parameter > 0) ? config.parameter : 2;

    for (uint32_t pass = 0; pass < passes && !g_stop_flag; pass++) {
        uint64_t expected = (pass % 2 == 0) ? pattern : ~pattern;

        for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
            uint64_t actual = word_ptr[i];
            if (actual != expected) {
                result.errors++;
                LOG_ERROR_DETAIL("MirrorMove", (uint64_t)(&word_ptr[i]), expected, actual);
                if (stop_on_error) break;
            }
            result.bytes_tested += 8;
        }

        if (stop_on_error && result.errors > 0) break;

        for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
            word_ptr[i] = ~expected;
            result.bytes_tested += 8;
        }
    }
    
    return result;
}

// MirrorMove128 - tests with 128-bit patterns
TestResult runMirrorMove128(const MemoryRegion& region, const TestConfig& config, bool stop_on_error) {
    TestResult result = {};
    uint8_t* ptr = region.base;
    uint8_t* end = region.base + region.size;
    
    volatile uint64_t* word_ptr = reinterpret_cast<volatile uint64_t*>(ptr);
    size_t num_words = region.size / 8;
    
    uint64_t pattern1 = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t pattern2 = 0x5555555555555555ULL;
    
    // Write phase
    size_t pairs = num_words / 2;
    for (size_t p = 0; p < pairs && !g_stop_flag; p++) {
        size_t i = p * 2;
        word_ptr[i] = pattern1;
        word_ptr[i + 1] = pattern2;
        result.bytes_tested += 16;
    }
    if ((num_words % 2) != 0 && !g_stop_flag) {
        word_ptr[num_words - 1] = pattern1;
        result.bytes_tested += 8;
    }
    
    uint32_t passes = (config.parameter > 0) ? config.parameter : 2;

    for (uint32_t pass = 0; pass < passes && !g_stop_flag; pass++) {
        uint64_t exp1 = (pass % 2 == 0) ? pattern1 : ~pattern1;
        uint64_t exp2 = (pass % 2 == 0) ? pattern2 : ~pattern2;

        for (size_t p = 0; p < pairs && !g_stop_flag; p++) {
            size_t i = p * 2;
            uint64_t a0 = word_ptr[i];
            uint64_t a1 = word_ptr[i + 1];
            if (a0 != exp1 || a1 != exp2) {
                result.errors++;
                if (a0 != exp1) {
                    LOG_ERROR_DETAIL("MirrorMove128[0]", (uint64_t)(&word_ptr[i]), exp1, a0);
                }
                if (a1 != exp2) {
                    LOG_ERROR_DETAIL("MirrorMove128[1]", (uint64_t)(&word_ptr[i + 1]), exp2, a1);
                }
                if (stop_on_error) break;
            }
            result.bytes_tested += 16;
        }
        if ((num_words % 2) != 0 && !g_stop_flag) {
            size_t last = num_words - 1;
            uint64_t a = word_ptr[last];
            if (a != exp1) {
                result.errors++;
                LOG_ERROR_DETAIL("MirrorMove128[last]", (uint64_t)(&word_ptr[last]), exp1, a);
            }
            result.bytes_tested += 8;
        }

        if (stop_on_error && result.errors > 0) break;

        for (size_t p = 0; p < pairs && !g_stop_flag; p++) {
            size_t i = p * 2;
            word_ptr[i] = ~exp1;
            word_ptr[i + 1] = ~exp2;
            result.bytes_tested += 16;
        }
        if ((num_words % 2) != 0 && !g_stop_flag) {
            word_ptr[num_words - 1] = ~exp1;
            result.bytes_tested += 8;
        }
    }

    return result;
}

// RefreshStable - memory refresh stability test
TestResult runRefreshStable(const MemoryRegion& region, const TestConfig& config, bool stop_on_error) {
    TestResult result = {};
    uint8_t* ptr = region.base;
    uint8_t* end = region.base + region.size;
    
    // Write all zeros first
    memset(ptr, 0, region.size);
    result.bytes_tested = 0;
    
    // Small delay to let memory refresh
    // Then verify all zeros
    uint32_t delay_ms = (config.parameter > 0) ? config.parameter : 100;
    auto delay_start = std::chrono::high_resolution_clock::now();
    volatile uint64_t* w = reinterpret_cast<volatile uint64_t*>(ptr);
    size_t num_words = region.size / 8;
    volatile uint64_t heat_acc = 0;
    while (!g_stop_flag) {
        for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
            heat_acc ^= w[i];
        }
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t elapsed_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now - delay_start).count();
        if (elapsed_ms >= delay_ms) break;
    }
    if (heat_acc == 0xFFFFFFFFFFFFFFFFULL) {
        result.bytes_tested += 0;
    }

    for (size_t i = 0; i < num_words && !g_stop_flag; i++) {
        uint64_t actual = w[i];
        if (actual != 0) {
            result.errors++;
            LOG_ERROR_DETAIL("RefreshStable", (uint64_t)(&w[i]), 0, actual);
            if (stop_on_error) break;
        }
        result.bytes_tested += 8;
    }
    
    return result;
}

// Dispatcher function to run the appropriate test
TestResult runTest(const std::string& test_name, const MemoryRegion& region,
                   const TestConfig& config, bool stop_on_error) {
    if (test_name == "SimpleTest") {
        return runSimpleTest(region, config, stop_on_error);
    } else if (test_name == "MirrorMove") {
        return runMirrorMove(region, config, stop_on_error);
    } else if (test_name == "MirrorMove128") {
        return runMirrorMove128(region, config, stop_on_error);
    } else if (test_name == "RefreshStable") {
        return runRefreshStable(region, config, stop_on_error);
    } else {
        std::cerr << "Unknown test function: " << test_name << std::endl;
        return TestResult{};
    }
}

} // namespace testsmem4u

// Main entry point
int main(int argc, char* argv[]) {
    using namespace testsmem4u;

    // Parse command line arguments first (before any logging)
    bool debug_mode = false;
    std::string cmdline_preset;
    if (!parseArgs(argc, argv, debug_mode, cmdline_preset)) {
        return 0;
    }

    // Initialize logging - always create log file at INFO level
    // --debug enables additional DEBUG level logging
    if (debug_mode) {
        Logger::get().init("testsmem4u.log", LogLevel::DEBUG, true);
    } else {
        Logger::get().init("testsmem4u.log", LogLevel::INFO, true);
    }
    auto& log = Logger::get();

    log.info("========================================", 0);
    log.info("  testsmem4u v0.1.0 - Memory Testing", 0);
    log.info("========================================", 0);
    log.info("Session ID: %u", log.getSessionId());
    log.info("Debug mode: %s", debug_mode ? "enabled" : "disabled");

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  testsmem4u v0.1.0 - Memory Testing\n";
    std::cout << "========================================\n\n";

    // Detect platform
    PlatformInfo platform = detectPlatform();
    std::cout << "Platform: " << platform.os_name << " " << platform.arch
              << " (" << platform.cpu_cores << " cores)\n" << std::endl;

    // Run configuration wizard (which loads the preset)
    Config config = runConfigWizard();

    // Override preset file if specified on command line
    // IMPORTANT: Only override preset file, not the wizard-configured values
    if (!cmdline_preset.empty()) {
        config.preset_file = cmdline_preset;
        config.preset = loadPreset(config.preset_file);
        if (debug_mode) log.info("Preset loaded from command line: %s", config.preset_file.c_str());
    }

    // Display preset info
    std::cout << "\nConfiguration:" << std::endl;
    std::cout << "  Preset: " << config.preset_file << std::endl;
    if (!config.preset.config_name.empty()) {
        std::cout << "  Preset Name: " << config.preset.config_name << std::endl;
    }
    if (!config.preset.config_author.empty()) {
        std::cout << "  Preset Author: " << config.preset.config_author << std::endl;
    }
    std::cout << "  Memory Window: " << config.memory_window_mb << " MB" << std::endl;
    std::cout << "  Test Sequence: " << config.preset.test_sequence << std::endl;
    std::cout << "  Tests Defined: " << config.preset.test_configs.size() << std::endl;
    std::cout << "  Cycles: " << config.cycles << std::endl;
    std::cout << "  Cores: " << config.cores << std::endl;
    std::cout << "  Halt on Error: " << (config.halt_on_error ? "Yes" : "No") << std::endl;
    std::cout << "  Lock Memory: " << (config.use_locked_memory ? "Yes" : "No") << std::endl;
    std::cout << std::endl;

    std::cout << "Starting memory tests..." << std::endl;

    RunResult result = {};
    try {
        result = runTests(config);
    } catch (const FatalErrorException& e) {
        std::cerr << "\n*** TEST ABORTED ***" << std::endl;
        std::cerr << "Reason: " << e.what() << std::endl;
        log.error("TEST ABORTED: %s", e.what());
        
        std::cout << "\nLog file: " << log.getLogPath() << std::endl;
        log.info("Log file: %s", log.getLogPath().c_str());
        log.info("Total runtime: %.3f seconds", log.getElapsedSeconds());
        
        // Cleanup
        Logger::get().deinit();
        
        return 1;
    }

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "           Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total Errors: " << result.total_errors << std::endl;
    std::cout << "Duration: " << result.duration_seconds << " seconds" << std::endl;

    if (result.total_errors == 0) {
        std::cout << "\n*** PASSED - No errors detected! ***\n" << std::endl;
        log.info("=== TEST PASSED - No errors detected ===", 0);
    } else {
        std::cout << "\n*** FAILED - " << result.total_errors << " errors detected ***\n" << std::endl;
        log.error("=== TEST FAILED - %llu errors detected ===", (unsigned long long)result.total_errors);
    }

    std::cout << "Log file: " << log.getLogPath() << std::endl;
    log.info("Log file: %s", log.getLogPath().c_str());
    log.info("Total runtime: %.3f seconds", log.getElapsedSeconds());

    // Cleanup
    Logger::get().deinit();

    return (result.total_errors == 0) ? 0 : 1;
}
