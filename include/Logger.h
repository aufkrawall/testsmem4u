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
#include <atomic>
#include <queue>
#include <condition_variable>
#include <vector>

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
        std::lock_guard<std::mutex> lock(init_mutex_);

        if (running_) {
            return; // Already initialized
        }

        log_filename_ = filename;
        log_level_ = level;
        
        session_id_ = generateSessionId();
        start_time_ = std::chrono::high_resolution_clock::now();
        error_count_ = 0;
        error_rate_limit_ = 100;
        suppressed_count_ = 0;
        last_error_time_ = std::chrono::high_resolution_clock::now();
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

    bool checkRateLimit() {
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_error_time_).count();

        if (elapsed_ms > 0) {
            uint32_t tokens_to_add = static_cast<uint32_t>(elapsed_ms / 10);
            if (tokens_to_add > 0) {
                if (error_count_ > tokens_to_add) {
                    error_count_ -= tokens_to_add;
                } else {
                    error_count_ = 0;
                }
                last_error_time_ = now;
            }
        }

        if (error_count_ >= error_rate_limit_) {
            return false; 
        }

        error_count_++;
        return true;
    }

    void deinit() {
        std::lock_guard<std::mutex> lock(init_mutex_);
        if (!running_) return;

        running_ = false;
        writer_cv_.notify_one(); 
        queue_cv_.notify_all(); // Wake up any blocked producers so they can exit
        
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        if (file_handle_) {
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
        logv(LogLevel::ERROR, format, args);
        va_end(args);
    }
    
    #undef LOG_FORMAT_ATTR

    void logMemoryAllocation(void* ptr, size_t size, bool locked) {
        debug("MEMORY ALLOC: ptr=0x%016llX size=%zu locked=%d", (unsigned long long)ptr, size, locked);
    }

    void logMemoryFree(void* ptr) {
        debug("MEMORY FREE: ptr=0x%016llX", (unsigned long long)ptr);
    }

    void logMemoryError(const std::string& operation, uint32_t error_code) {
        error("MEMORY ERROR: %s failed with code %u", operation.c_str(), error_code);
    }

    void logTestStart(uint32_t test_num, const std::string& func, uint32_t pattern_mode) {
        info("TEST START: #%02u func=%s pattern_mode=%u", test_num, func.c_str(), pattern_mode);
    }

    void logTestProgress(uint32_t test_num, size_t bytes_tested, size_t total, double elapsed) {
        float percent = (total > 0) ? (100.0f * static_cast<float>(bytes_tested) / static_cast<float>(total)) : 0.0f;
        debug("TEST PROGRESS: #%02u %zu/%zu (%.1f%%) %.3fs", test_num, bytes_tested, total, percent, elapsed);
    }

    void logTestComplete(uint32_t test_num, uint64_t errors, size_t bytes_tested, double duration) {
        if (errors == 0) {
            info("TEST PASS: #%02u %zu bytes in %.3fs", test_num, bytes_tested, duration);
        } else {
            error("TEST FAIL: #%02u %llu errors, %zu bytes in %.3fs", test_num, (unsigned long long)errors, bytes_tested, duration);
        }
    }

    void logThreadStart(uint32_t thread_id) {
        debug("THREAD START: id=%u", thread_id);
    }

    void logThreadComplete(uint32_t thread_id, double duration) {
        debug("THREAD DONE: id=%u completed in %.3fs", thread_id, duration);
    }

    void logError(const std::string& context, uint64_t address, uint64_t expected, uint64_t actual) {
        // Build the error message first
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), 
            "ERROR: %s at 0x%016llX: expected 0x%016llX, got 0x%016llX",
            context.c_str(), (unsigned long long)address, (unsigned long long)expected, (unsigned long long)actual);
        
        // CRITICAL: Always log to file FIRST - this must never be skipped
        // File logging is the authoritative record
        pushMessage(LogLevel::ERROR, std::string(error_msg));
        
        // Handle console output with rate limiting (console is best-effort)
        handleConsoleOutput(std::string(error_msg));
    }
    
    // Separated console output handling for clarity and testability
    void handleConsoleOutput(const std::string& message) {
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        auto now = std::chrono::high_resolution_clock::now();
        
        // Periodic summary of suppressed errors
        auto seconds_since_summary = std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_time_).count();
        if (seconds_since_summary >= 1 && suppressed_count_ > 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "ERROR RATE: %u additional errors suppressed (see log file)", suppressed_count_);
            {
                std::lock_guard<std::mutex> console_lock(console_mutex_);
                std::cout << formatLogLine(LogLevel::WARN, buf) << "\n";
            }
            suppressed_count_ = 0;
            last_summary_time_ = now;
        }

        // Check rate limit for console output only
        if (error_count_ >= error_rate_limit_) {
            suppressed_count_++;
            return;  // Skip console output only
        }

        error_count_++;
        
        // Console output
        std::lock_guard<std::mutex> console_lock(console_mutex_);
        std::cout << formatLogLine(LogLevel::ERROR, message) << "\n";
    }

    void pushMessage(LogLevel level, const std::string& formatted_message) {
        if (!running_) return;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            // Never drop ERROR or higher priority messages - use blocking push
            // For lower priority, use large cap to prevent OOM
            const size_t MAX_QUEUE_SIZE = 100000; // 10x larger for WARN/INFO/DEBUG
            
            if (level >= LogLevel::ERROR) {
                // Critical: Always queue ERROR messages, even if we have to wait
                // This ensures no error data is lost
                log_queue_.push({level, formatted_message});
            } else {
                // Non-critical: Drop if queue is extremely full to prevent OOM
                if (log_queue_.size() < MAX_QUEUE_SIZE) {
                    log_queue_.push({level, formatted_message});
                } else {
                    // Track dropped non-critical messages
                    static std::atomic<uint64_t> dropped_count{0};
                    dropped_count++;
                    // Occasionally log that we're dropping
                    if ((dropped_count.load() % 1000) == 1) {
                        char drop_msg[128];
                        snprintf(drop_msg, sizeof(drop_msg), 
                            "LOGGER: Dropped %llu non-critical messages due to full queue", 
                            (unsigned long long)dropped_count.load());
                        log_queue_.push({LogLevel::WARN, std::string(drop_msg)});
                    }
                }
            }
        }
        queue_cv_.notify_one();
    }

    void logv(LogLevel level, const char* format, va_list args) {
        va_list args_copy;
        va_copy(args_copy, args);
        int len = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        if (len < 0) return;

        // FIXED: Allocate len+1 bytes to accommodate null terminator during vsnprintf
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

        while (running_) {
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
             
             // NOTIFY producers that space is available
             // This wakes up threads blocked in pushMessage
             queue_cv_.notify_all();
             
             lock.unlock();

             // Process batch IO without holding lock
             if (!local_batch.empty()) {
                 if (file_handle_) {
                     bool force_flush = false;
                     for (const auto& msg : local_batch) {
                         fprintf(file_handle_, "%s\n", msg.second.c_str());
                         // Always flush on ERROR to ensure vital data hits disk immediately
                         if (msg.first == LogLevel::ERROR) force_flush = true;
                     }
                     // Regularly flush to ensure no data loss on crash
                     if (force_flush || local_batch.size() > 100) fflush(file_handle_);
                 }
                 local_batch.clear();
             }
        }
        
        // Final flush
        if (file_handle_) {
            fflush(file_handle_);
        }
    }

    std::mutex& getConsoleMutex() { return console_mutex_; }
    std::mutex& getMutex() { return getConsoleMutex(); } 

    double getElapsedSeconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(now - start_time_).count();
    }

    std::string getLogPath() const { return log_filename_; }

private:
    Logger() : running_(false), file_handle_(nullptr), log_filename_(), log_level_(LogLevel::DEBUG),
               session_id_(0), error_count_(0), error_rate_limit_(500), suppressed_count_(0) {}
    
    ~Logger() { deinit(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::mutex init_mutex_;
    std::mutex rate_limit_mutex_;
    std::mutex console_mutex_; 
    
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;  // For producers (blocks when full)
    std::condition_variable writer_cv_; // For consumer (blocks when empty)
    std::queue<std::pair<LogLevel, std::string>> log_queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_;

    FILE* file_handle_; // Replaced ofstream
    std::string log_filename_;
    std::atomic<LogLevel> log_level_;

    uint32_t session_id_;
    std::chrono::high_resolution_clock::time_point start_time_;
    
    uint32_t error_count_;
    uint32_t error_rate_limit_;
    uint32_t suppressed_count_;
    std::chrono::high_resolution_clock::time_point last_error_time_;
    std::chrono::high_resolution_clock::time_point last_summary_time_;

    uint32_t generateSessionId() {
        auto now = std::chrono::high_resolution_clock::now();
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    }

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
};

} // namespace testsmem4u

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

#define LOG_INFO(...)  testsmem4u::Logger::get().info(__VA_ARGS__)
#define LOG_WARN(...)  testsmem4u::Logger::get().warn(__VA_ARGS__)
#define LOG_ERROR(...) testsmem4u::Logger::get().error(__VA_ARGS__)

#define LOG_MEM_ALLOC(ptr, size, locked) testsmem4u::Logger::get().logMemoryAllocation(ptr, size, locked)
#define LOG_MEM_FREE(ptr)                testsmem4u::Logger::get().logMemoryFree(ptr)
#define LOG_MEM_ERROR(op, code)          testsmem4u::Logger::get().logMemoryError(op, code)

#define LOG_TEST_START(num, func, mode)  testsmem4u::Logger::get().logTestStart(num, func, mode)
#define LOG_TEST_DONE(num, errors, bytes, time) testsmem4u::Logger::get().logTestComplete(num, errors, bytes, time)
#define LOG_ERROR_DETAIL(ctx, addr, exp, act) testsmem4u::Logger::get().logError(ctx, addr, exp, act)
