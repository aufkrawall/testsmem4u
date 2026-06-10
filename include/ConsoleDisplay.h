#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#endif

namespace testsmem4u {

extern std::atomic<bool> g_testing_active;

struct StatusInfo {
    uint32_t cycle = 0;
    uint32_t total_cycles = 0;
    uint32_t test_idx = 0;
    size_t total_tests = 0;
    std::string test_name;
    uint64_t bytes_tested = 0;
    uint64_t errors = 0;
    uint64_t elapsed_seconds = 0;
};

class ConsoleDisplay {
public:
    static ConsoleDisplay& get() {
        static ConsoleDisplay instance;
        return instance;
    }

    void init();
    
    void printLine(const std::string& line);
    
    void updateProgressLine(const std::string& line);
    
    void updateStatus(const StatusInfo& info);
    
    void clearStatus();
    
    void printError(const std::string& line);
    
    void setTestingActive(bool active) {
        g_testing_active.store(active, std::memory_order_release);
    }
    bool isTestingActive() const {
        return g_testing_active.load(std::memory_order_acquire);
    }
    
private:
    ConsoleDisplay() = default;
    ~ConsoleDisplay() = default;
    ConsoleDisplay(const ConsoleDisplay&) = delete;
    ConsoleDisplay& operator=(const ConsoleDisplay&) = delete;

    std::mutex mutex_;
    int console_width_ = 80;
    bool status_active_ = false;
    bool initialized_ = false;

    void detectConsoleWidth();
    std::string formatStatus(const StatusInfo& info);
    std::string formatTime(uint64_t total_seconds);
};

}
