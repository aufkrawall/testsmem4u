// testsmem4u Logger - Debug logging utility

#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <vector>

namespace testsmem4u {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERR
};

extern std::atomic<bool> g_testing_active;

class Logger {
public:
    static Logger& get() {
        static Logger instance;
        return instance;
    }

    void init(const std::string& filename, LogLevel level = LogLevel::DEBUG, bool purge = true) {
        std::lock_guard<std::mutex> lock(init_mutex_);

        if (running_) {
            return; // Already initialized
        }

        log_filename_ = filename;
        log_level_ = level;
        
        start_time_ = std::chrono::high_resolution_clock::now();
        error_count_ = 0;
        error_rate_limit_ = 100;
        suppressed_count_ = 0;
        dropped_critical_messages_.store(0, std::memory_order_relaxed);
        dropped_noncritical_messages_.store(0, std::memory_order_relaxed);
        last_summary_time_ = std::chrono::high_resolution_clock::now();

        if (!filename.empty()) {
            // Use C-style file I/O for robustness
            file_handle_ = fopen(filename.c_str(), purge ? "w" : "a");
            if (!file_handle_) {
                std::cerr << "[-] Failed to open log file: " << filename << std::endl;
            }
        }

        running_ = true;
        writer_thread_ = std::thread(&Logger::writerThreadFunc, this);
    }

    void setErrorRateLimit(uint32_t errors_per_second) {
        std::lock_guard<std::mutex> lock(init_mutex_);
        error_rate_limit_ = errors_per_second;
    }

    void deinit() {
        std::lock_guard<std::mutex> lock(init_mutex_);
        if (!running_) return;

        running_ = false;
        writer_cv_.notify_one();
        
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        if (file_handle_) {
            uint64_t dropped_critical = dropped_critical_messages_.load(std::memory_order_relaxed);
            uint64_t dropped_noncritical = dropped_noncritical_messages_.load(std::memory_order_relaxed);
            if (dropped_critical > 0 || dropped_noncritical > 0) {
                fprintf(file_handle_,
                        "[LOGGER] Dropped %llu critical and %llu non-critical log messages due to queue backpressure. Final error totals remain authoritative.\n",
                        (unsigned long long)dropped_critical,
                        (unsigned long long)dropped_noncritical);
            }
            fflush(file_handle_);
            fclose(file_handle_);
            file_handle_ = nullptr;
        }
    }

    void setLevel(LogLevel level) {
        log_level_ = level;
    }

    static void emergencyFlush() {
        // Safe flush for crash handlers - avoid locks and complex logic
        // Only flush standard streams which are generally safer
        fflush(stdout);
        fflush(stderr);
    }

    // Use format attribute to enable compile-time format string checking
    #ifdef __GNUC__
        #define LOG_FORMAT_ATTR __attribute__((format(printf, 2, 3)))
    #else
        #define LOG_FORMAT_ATTR
    #endif

    void debug(const char* format, ...) LOG_FORMAT_ATTR {
        if (log_level_ > LogLevel::DEBUG) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::DEBUG, format, args);
        va_end(args);
    }

    void info(const char* format, ...) LOG_FORMAT_ATTR {
        if (log_level_ > LogLevel::INFO) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::INFO, format, args);
        va_end(args);
    }

    void warn(const char* format, ...) LOG_FORMAT_ATTR {
        if (log_level_ > LogLevel::WARN) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::WARN, format, args);
        va_end(args);
    }

    void error(const char* format, ...) LOG_FORMAT_ATTR {
        va_list args;
        va_start(args, format);
        logv(LogLevel::ERR, format, args);
        va_end(args);
    }
    
    #undef LOG_FORMAT_ATTR

    void logError(const std::string& context, uint64_t address, uint64_t expected, uint64_t actual) {
        // Build the error message first
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), 
            "ERROR: %s at 0x%016llX: expected 0x%016llX, got 0x%016llX",
            context.c_str(), (unsigned long long)address, (unsigned long long)expected, (unsigned long long)actual);
        
        // Format with timestamp/thread/elapsed for log file consistency
        std::string formatted = formatLogLine(LogLevel::ERR, std::string(error_msg));
        
        // File logging is the authoritative record; queue backpressure is
        // summarized on shutdown if individual lines must be dropped.
        pushMessage(LogLevel::ERR, formatted);
        
        // Handle console output with rate limiting (console is best-effort)
        handleConsoleOutput(std::string(error_msg));
    }
    
private:
    void handleConsoleOutput(const std::string& message) {
        if (g_testing_active.load(std::memory_order_relaxed)) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        auto now = std::chrono::high_resolution_clock::now();
        
        auto seconds_since_summary = std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_time_).count();
        if (seconds_since_summary >= 1) {
            if (suppressed_count_ > 0) {
                char buf[128];
                snprintf(buf, sizeof(buf), "ERROR RATE: %u additional errors suppressed (see log file)", suppressed_count_);
                std::lock_guard<std::mutex> console_lock(console_mutex_);
                std::cout << formatLogLine(LogLevel::WARN, buf) << "\n" << std::flush;
                suppressed_count_ = 0;
            }
            error_count_ = 0;
            last_summary_time_ = now;
        }

        if (error_count_ >= error_rate_limit_) {
            suppressed_count_++;
            return;
        }

        error_count_++;
        std::lock_guard<std::mutex> console_lock(console_mutex_);
        std::cout << formatLogLine(LogLevel::ERR, message) << "\n" << std::flush;
    }

    void pushMessage(LogLevel level, const std::string& formatted_message) {
        if (!running_) return;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            constexpr size_t MAX_QUEUE_SIZE = 100000;
            constexpr size_t NONCRITICAL_QUEUE_LIMIT = 90000;
            
            if (log_queue_.size() < MAX_QUEUE_SIZE &&
                (level >= LogLevel::ERR || log_queue_.size() < NONCRITICAL_QUEUE_LIMIT)) {
                log_queue_.push({level, formatted_message});
            } else {
                if (level >= LogLevel::ERR) {
                    dropped_critical_messages_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    dropped_noncritical_messages_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        writer_cv_.notify_one();
    }

    void logv(LogLevel level, const char* format, va_list args) {
        va_list args_copy;
        va_copy(args_copy, args);
        int len = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        if (len < 0) return;

        std::string message;
        message.resize(len + 1); // +1 for null terminator during write
        vsnprintf(&message[0], len + 1, format, args);
        message.resize(len); // Remove null terminator from string
        
        std::string line = formatLogLine(level, message);
        
        // Only print WARN and ERROR to console to prevent spam
        // INFO and DEBUG still go to the log file via pushMessage
        if (level >= LogLevel::WARN) {
            std::lock_guard<std::mutex> console_lock(console_mutex_);
            std::cout << line << "\n";
        }

        pushMessage(level, line);
    }

    void writerThreadFunc() {
        std::vector<std::pair<LogLevel, std::string>> local_batch;
        local_batch.reserve(500); // Process in batches

        while (true) {
             std::unique_lock<std::mutex> lock(queue_mutex_);
              
              // Wait for data or shutdown
              writer_cv_.wait(lock, [this] {
                  return !log_queue_.empty() || !running_;
              });

              if (!running_ && log_queue_.empty()) break;

             // Drain the entire queue into local batch (or up to a reasonable limit)
             // We want to drain fast to unblock producers
             while (!log_queue_.empty() && local_batch.size() < 2000) {
                 local_batch.push_back(std::move(log_queue_.front()));
                 log_queue_.pop();
             }
             
             lock.unlock();

             // Process batch IO without holding lock
            if (!local_batch.empty()) {
                  if (file_handle_) {
                      for (const auto& msg : local_batch) {
                          fprintf(file_handle_, "%s\n", msg.second.c_str());
                          if (msg.first == LogLevel::ERR) {
                              fflush(file_handle_);
                          }
                      }
                      fflush(file_handle_);
                  }
                  local_batch.clear();
              }
        }
        
        // Final flush
        if (file_handle_) {
            fflush(file_handle_);
        }
    }

public:
    double getElapsedSeconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(now - start_time_).count();
    }

    std::string getLogPath() const { return log_filename_; }

private:
    Logger() : running_(false), file_handle_(nullptr), log_filename_(), log_level_(LogLevel::DEBUG),
               error_count_(0), error_rate_limit_(500), suppressed_count_(0) {}
    
    ~Logger() { deinit(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::mutex init_mutex_;
    std::mutex rate_limit_mutex_;
    std::mutex console_mutex_; 
    
    std::mutex queue_mutex_;
    std::condition_variable writer_cv_; // For consumer (blocks when empty)
    std::queue<std::pair<LogLevel, std::string>> log_queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_;

    FILE* file_handle_; // Replaced ofstream
    std::string log_filename_;
    std::atomic<LogLevel> log_level_;
    std::atomic<uint64_t> dropped_critical_messages_{0};
    std::atomic<uint64_t> dropped_noncritical_messages_{0};

    std::chrono::high_resolution_clock::time_point start_time_;
    
    uint32_t error_count_;
    uint32_t error_rate_limit_;
    uint32_t suppressed_count_;
    std::chrono::high_resolution_clock::time_point last_summary_time_;

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        // Use thread-safe localtime variant
        std::tm tm_buf{};
#ifdef _WIN32
        localtime_s(&tm_buf, &time);
#else
        localtime_r(&time, &tm_buf);
#endif

        std::stringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ERR:   return "ERROR";
            default:              return "UNKNOWN";
        }
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
};

} // namespace testsmem4u

#ifdef NDEBUG
    #define LOG_DEBUG(...) ((void)0)
#else
    #define LOG_DEBUG(...) testsmem4u::Logger::get().debug(__VA_ARGS__)
#endif

#define LOG_INFO(...)  testsmem4u::Logger::get().info(__VA_ARGS__)
#define LOG_WARN(...)  testsmem4u::Logger::get().warn(__VA_ARGS__)
#define LOG_ERROR(...) testsmem4u::Logger::get().error(__VA_ARGS__)
#define LOG_ERROR_DETAIL(ctx, addr, exp, act) testsmem4u::Logger::get().logError(ctx, addr, exp, act)
