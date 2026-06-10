// testsmem4u Logger - Debug logging utility

#pragma once

#include <string>
#include <mutex>
#include <chrono>
#include <thread>
#include <cstdarg>
#include <cstdio>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <vector>
#include <utility>

namespace testsmem4u {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERR
};

class Logger {
public:
    static Logger& get() {
        static Logger instance;
        return instance;
    }

    void init(const std::string& filename, LogLevel level = LogLevel::DEBUG, bool purge = true);
    void deinit();
    void setErrorRateLimit(uint32_t errors_per_second);

    // Use format attribute to enable compile-time format string checking
    #ifdef __GNUC__
        #define LOG_FORMAT_ATTR __attribute__((format(printf, 2, 3)))
    #else
        #define LOG_FORMAT_ATTR
    #endif

    void debug(const char* format, ...) LOG_FORMAT_ATTR;
    void info(const char* format, ...) LOG_FORMAT_ATTR;
    void warn(const char* format, ...) LOG_FORMAT_ATTR;
    void error(const char* format, ...) LOG_FORMAT_ATTR;

    #undef LOG_FORMAT_ATTR

    void logError(const std::string& context, uint64_t address, uint64_t expected, uint64_t actual);

    double getElapsedSeconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(now - start_time_).count();
    }

private:
    Logger() : running_(false), file_handle_(nullptr), log_filename_(), log_level_(LogLevel::DEBUG),
               start_time_(std::chrono::high_resolution_clock::now()),
               error_count_(0), error_rate_limit_(500), suppressed_count_(0),
               last_summary_time_(start_time_) {}

    ~Logger() { deinit(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void handleConsoleOutput(const std::string& message);
    void pushMessage(LogLevel level, const std::string& formatted_message);
    void logv(LogLevel level, const char* format, va_list args);
    void writerThreadFunc();

    std::string getTimestamp();
    std::string levelToString(LogLevel level);
    std::string formatLogLine(LogLevel level, const std::string& message);

    std::mutex init_mutex_;
    std::mutex rate_limit_mutex_;

    std::mutex queue_mutex_;
    std::condition_variable writer_cv_;
    std::queue<std::pair<LogLevel, std::string>> log_queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_;

    FILE* file_handle_;
    std::string log_filename_;
    std::atomic<LogLevel> log_level_;
    std::atomic<uint64_t> dropped_critical_messages_{0};
    std::atomic<uint64_t> dropped_noncritical_messages_{0};

    std::chrono::high_resolution_clock::time_point start_time_;

    uint32_t error_count_;
    std::atomic<uint32_t> error_rate_limit_;
    uint32_t suppressed_count_;
    std::chrono::high_resolution_clock::time_point last_summary_time_;
};

} // namespace testsmem4u

#define LOG_DEBUG(...) testsmem4u::Logger::get().debug(__VA_ARGS__)
#define LOG_INFO(...)  testsmem4u::Logger::get().info(__VA_ARGS__)
#define LOG_WARN(...)  testsmem4u::Logger::get().warn(__VA_ARGS__)
#define LOG_ERROR(...) testsmem4u::Logger::get().error(__VA_ARGS__)
#define LOG_ERROR_DETAIL(ctx, addr, exp, act) testsmem4u::Logger::get().logError(ctx, addr, exp, act)
