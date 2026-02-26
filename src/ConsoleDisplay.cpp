#include "ConsoleDisplay.h"
#include "Logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>

#ifndef _WIN32
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace testsmem4u {

std::atomic<bool> g_testing_active{false};

void ConsoleDisplay::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return;
    
    initialized_ = true;
    start_time_ = std::chrono::high_resolution_clock::now();
    
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hIn, &dwMode)) {
            dwMode &= ~ENABLE_QUICK_EDIT_MODE;
            dwMode |= ENABLE_EXTENDED_FLAGS;
            SetConsoleMode(hIn, dwMode);
        }
    }
#endif
    
    detectConsoleWidth();
}

void ConsoleDisplay::detectConsoleWidth() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
            console_width_ = csbi.dwSize.X;
            if (console_width_ < 40) console_width_ = 40;
            if (console_width_ > 200) console_width_ = 200;
            return;
        }
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        console_width_ = ws.ws_col;
        if (console_width_ < 40) console_width_ = 40;
        if (console_width_ > 200) console_width_ = 200;
        return;
    }
#endif
    console_width_ = 80;
}

void ConsoleDisplay::printLine(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (status_active_) {
        std::cout << "\r\033[K" << line << "\n";
        last_rendered_len_ = 0;
        status_active_ = false;
    } else {
        std::cout << line << "\n";
    }
    std::cout << std::flush;
}

void ConsoleDisplay::updateProgressLine(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (status_active_) {
        std::cout << "\r" << line << "\033[K" << std::flush;
    } else {
        std::cout << line << std::flush;
        status_active_ = true;
    }
    last_rendered_len_ = static_cast<int>(line.size());
}

void ConsoleDisplay::printError(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (status_active_) {
        std::cout << "\r\033[K";
    }
    
    std::cout << "\033[31m" << line << "\033[0m\n";
    
    if (status_active_) {
        last_rendered_len_ = 0;
        status_active_ = false;
    }
    std::cout << std::flush;
}

void ConsoleDisplay::clearStatus() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (status_active_) {
        std::cout << "\r\033[K" << std::flush;
        last_rendered_len_ = 0;
        status_active_ = false;
    }
}

std::string ConsoleDisplay::formatTime(uint64_t total_seconds) {
    uint32_t hours = static_cast<uint32_t>(total_seconds / 3600);
    uint32_t minutes = static_cast<uint32_t>((total_seconds % 3600) / 60);
    uint32_t seconds = static_cast<uint32_t>(total_seconds % 60);
    
    std::ostringstream ss;
    if (hours > 0) {
        ss << hours << ":" << std::setfill('0') << std::setw(2) << minutes << ":" << std::setw(2) << seconds;
    } else {
        ss << std::setfill('0') << std::setw(2) << minutes << ":" << std::setw(2) << seconds;
    }
    return ss.str();
}

std::string ConsoleDisplay::formatStatus(const StatusInfo& info) {
    std::ostringstream ss;
    
    double gb = info.bytes_tested / (1024.0 * 1024.0 * 1024.0);
    
    ss << "[Cycle " << info.cycle;
    if (info.total_cycles > 0) {
        ss << "/" << info.total_cycles;
    } else {
        ss << "/inf";
    }
    ss << "] Test " << info.test_idx << "/" << info.total_tests;
    ss << " (" << info.test_name << "): ";
    ss << std::fixed << std::setprecision(2) << gb << " GB";
    ss << " | Err: " << info.errors;
    ss << " | " << formatTime(info.elapsed_seconds);
    
    std::string result = ss.str();
    
    if (static_cast<int>(result.size()) > console_width_ - 2) {
        result = result.substr(0, console_width_ - 2);
    }
    
    return result;
}

void ConsoleDisplay::updateStatus(const StatusInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string status = formatStatus(info);
    
    if (!status_active_) {
        std::cout << "\n";
        status_active_ = true;
    }
    
    std::cout << "\r" << status << "\033[K" << std::flush;
    last_rendered_len_ = static_cast<int>(status.size());
}

}
