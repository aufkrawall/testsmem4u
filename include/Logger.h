// testsmem4u Logger - Debug logging utility

#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <cstdarg>

namespace testsmem4u {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    static Logger& get() {
        static Logger instance;
        return instance;
    }

    void init(const std::string& filename, LogLevel level = LogLevel::DEBUG, bool purge = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        log_filename_ = filename;
        log_level_ = level;
        enabled_ = true;
        session_id_ = generateSessionId();
        start_time_ = std::chrono::high_resolution_clock::now();
        
        // Only open file if filename is not empty
        if (!filename.empty()) {
            if (purge) {
                log_file_.open(filename, std::ios::out | std::ios::trunc);
            } else {
                log_file_.open(filename, std::ios::out | std::ios::app);
            }
        }
    }

    void deinit() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_.close();
        }
        enabled_ = false;
    }

    void setLevel(LogLevel level) {
        log_level_ = level;
    }

    // Main logging function using printf-style format
    void log(LogLevel level, const char* format, ...) {
        va_list args;
        va_start(args, format);
        logv(level, format, args);
        va_end(args);
    }

    // Convenience methods
    void debug(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logv(LogLevel::DEBUG, format, args);
        va_end(args);
    }

    void info(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logv(LogLevel::INFO, format, args);
        va_end(args);
    }

    void warn(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logv(LogLevel::WARN, format, args);
        va_end(args);
    }

    void error(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logv(LogLevel::ERROR, format, args);
        va_end(args);
    }

    // Memory allocation logging
    void logMemoryAllocation(void* ptr, size_t size, bool locked) {
        debug("MEMORY ALLOC: ptr=0x%016llX size=%zu locked=%d", (unsigned long long)ptr, size, locked);
    }

    void logMemoryFree(void* ptr) {
        debug("MEMORY FREE: ptr=0x%016llX", (unsigned long long)ptr);
    }

    void logMemoryError(const std::string& operation, uint32_t error_code) {
        error("MEMORY ERROR: %s failed with code %u", operation.c_str(), error_code);
    }

    // Test execution logging
    void logTestStart(uint32_t test_num, const std::string& func, uint32_t pattern_mode) {
        info("TEST START: #%02u func=%s pattern_mode=%u", test_num, func.c_str(), pattern_mode);
    }

    void logTestProgress(uint32_t test_num, size_t bytes_tested, size_t total, double elapsed) {
        float percent = (total > 0) ? (100.0f * bytes_tested / total) : 0.0f;
        debug("TEST PROGRESS: #%02u %zu/%zu (%.1f%%) %.3fs", test_num, bytes_tested, total, percent, elapsed);
    }

    void logTestComplete(uint32_t test_num, uint64_t errors, size_t bytes_tested, double duration) {
        if (errors == 0) {
            info("TEST PASS: #%02u %zu bytes in %.3fs", test_num, bytes_tested, duration);
        } else {
            error("TEST FAIL: #%02u %llu errors, %zu bytes in %.3fs", test_num, (unsigned long long)errors, bytes_tested, duration);
        }
    }

    // Thread logging
    void logThreadStart(uint32_t thread_id) {
        debug("THREAD START: id=%u", thread_id);
    }

    void logThreadComplete(uint32_t thread_id, double duration) {
        debug("THREAD DONE: id=%u completed in %.3fs", thread_id, duration);
    }

    // Error logging
    void logError(const std::string& context, uint64_t address, uint64_t expected, uint64_t actual) {
        error("ERROR: %s at 0x%016llX: expected 0x%016llX, got 0x%016llX",
            context.c_str(), (unsigned long long)address, (unsigned long long)expected, (unsigned long long)actual);
    }

    // Session info
    uint32_t getSessionId() const { return session_id_; }
    double getElapsedSeconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(now - start_time_).count();
    }

    std::string getLogPath() const { return log_filename_; }

private:
    Logger() : enabled_(false), log_level_(LogLevel::DEBUG), session_id_(0) {}
    ~Logger() { deinit(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::mutex mutex_;
    std::ofstream log_file_;
    std::string log_filename_;
    LogLevel log_level_;
    bool enabled_;
    uint32_t session_id_;
    std::chrono::high_resolution_clock::time_point start_time_;

    uint32_t generateSessionId() {
        auto now = std::chrono::high_resolution_clock::now();
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    }

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ERROR: return "ERROR";
        }
        return "UNKNOWN";
    }

    std::string formatLogLine(LogLevel level, const std::string& message) {
        std::stringstream ss;
        ss << "[" << getTimestamp() << "]";
        ss << "[" << levelToString(level) << "]";
        ss << "[T" << std::this_thread::get_id() << "]";
        ss << "[" << std::fixed << std::setprecision(3) << getElapsedSeconds() << "s]";
        ss << " " << message;
        return ss.str();
    }

    void logv(LogLevel level, const char* format, va_list args) {
        if (!enabled_ || level < log_level_) return;

        std::lock_guard<std::mutex> lock(mutex_);

        char buffer[4096];
        vsnprintf(buffer, sizeof(buffer), format, args);

        std::string message(buffer);
        std::string line = formatLogLine(level, message);

        if (log_file_.is_open()) {
            log_file_ << line << std::endl;
        }
        std::cout << line << std::endl;
    }
};

} // namespace testsmem4u

// Compile-time optimization: disable debug logging in release builds
#ifdef NDEBUG
    #define LOG_DEBUG(...) ((void)0)
    #define LOG_TEST_PROGRESS(...) ((void)0)
    #define LOG_THREAD_START(...) ((void)0)
    #define LOG_THREAD_COMPLETE(...) ((void)0)
#else
    #define LOG_DEBUG(...) testsmem4u::Logger::get().debug(__VA_ARGS__)
    #define LOG_TEST_PROGRESS(num, done, total, time) testsmem4u::Logger::get().logTestProgress(num, done, total, time)
    #define LOG_THREAD_START(id)  testsmem4u::Logger::get().logThreadStart(id)
    #define LOG_THREAD_COMPLETE(id, duration) testsmem4u::Logger::get().logThreadComplete(id, duration)
#endif

// Info/warn/error logging always enabled
#define LOG_INFO(...)  testsmem4u::Logger::get().info(__VA_ARGS__)
#define LOG_WARN(...)  testsmem4u::Logger::get().warn(__VA_ARGS__)
#define LOG_ERROR(...) testsmem4u::Logger::get().error(__VA_ARGS__)

// Memory logging macros
#define LOG_MEM_ALLOC(ptr, size, locked) testsmem4u::Logger::get().logMemoryAllocation(ptr, size, locked)
#define LOG_MEM_FREE(ptr)                testsmem4u::Logger::get().logMemoryFree(ptr)
#define LOG_MEM_ERROR(op, code)          testsmem4u::Logger::get().logMemoryError(op, code)

// Test logging macros
#define LOG_TEST_START(num, func, mode)  testsmem4u::Logger::get().logTestStart(num, func, mode)
#define LOG_TEST_DONE(num, errors, bytes, time) testsmem4u::Logger::get().logTestComplete(num, errors, bytes, time)
#define LOG_ERROR_DETAIL(ctx, addr, exp, act) testsmem4u::Logger::get().logError(ctx, addr, exp, act)
