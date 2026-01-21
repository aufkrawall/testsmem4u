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
            if (purge) {
                log_file_.open(filename, std::ios::out | std::ios::trunc);
            } else {
                log_file_.open(filename, std::ios::out | std::ios::app);
            }
        }

        running_ = true;
        writer_thread_ = std::thread(&Logger::writerThreadFunc, this);
    }

    void setErrorRateLimit(uint32_t errors_per_second) {
        // Atomic or simple lock is fine, this is rarely called
        std::lock_guard<std::mutex> lock(init_mutex_);
        error_rate_limit_ = errors_per_second;
    }

    // Checking if we should log based on rate limiting
    // Now internal logic, returns true if we should proceed
    bool checkRateLimit() {
        // We use a separate mutex for rate limiting to reduce contention on the queue mutex
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_error_time_).count();

        // Add tokens based on elapsed time
        if (elapsed_ms > 0) {
            uint32_t tokens_to_add = static_cast<uint32_t>(elapsed_ms / 10); // 1 token per 10ms = 100/sec base refill
            if (tokens_to_add > 0) {
                // If we have "error_count_" representing used tokens, we subtract
                if (error_count_ > tokens_to_add) {
                    error_count_ -= tokens_to_add;
                } else {
                    error_count_ = 0;
                }
                last_error_time_ = now;
            }
        }

        if (error_count_ >= error_rate_limit_) {
            return false; // Rate limit exceeded
        }

        error_count_++;
        return true;
    }

    void deinit() {
        std::lock_guard<std::mutex> lock(init_mutex_);
        if (!running_) return;

        running_ = false;
        queue_cv_.notify_one();
        
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    void setLevel(LogLevel level) {
        log_level_ = level;
    }

    void debug(const char* format, ...) {
        if (log_level_ > LogLevel::DEBUG) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::DEBUG, format, args);
        va_end(args);
    }

    void info(const char* format, ...) {
        if (log_level_ > LogLevel::INFO) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::INFO, format, args);
        va_end(args);
    }

    void warn(const char* format, ...) {
        if (log_level_ > LogLevel::WARN) return;
        va_list args;
        va_start(args, format);
        logv(LogLevel::WARN, format, args);
        va_end(args);
    }

    void error(const char* format, ...) {
        // Always log errors unless rate limited
        va_list args;
        va_start(args, format);
        logv(LogLevel::ERROR, format, args);
        va_end(args);
    }

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
         // Rate limit check specific to memory error floods
        {
            std::lock_guard<std::mutex> lock(rate_limit_mutex_);
            auto now = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_time_).count() >= 1) {
                if (suppressed_count_ > 0) {
                    // We must log this directly or push to queue. Pushing to queue is safer.
                    // But we can't call 'error' easily from here if we want to avoid recursion effectively.
                    // We'll construct the message manually.
                    char buf[128];
                    snprintf(buf, sizeof(buf), "ERROR RATE: %u additional errors suppressed", suppressed_count_);
                    pushMessage(LogLevel::ERROR, std::string(buf));
                }
                suppressed_count_ = 0;
                last_summary_time_ = now;
            }
        }

        if (!checkRateLimit()) {
            std::lock_guard<std::mutex> lock(rate_limit_mutex_);
            suppressed_count_++;
            return;
        }

        error("ERROR: %s at 0x%016llX: expected 0x%016llX, got 0x%016llX",
            context.c_str(), (unsigned long long)address, (unsigned long long)expected, (unsigned long long)actual);
    }
    
    // Legacy support for directly accessing mutex if needed (Monitor thread)
    // The Monitor thread in TestEngine uses this for console locking.
    // For AsyncLogger, we still want to protect the Console output.
    // We can use the init_mutex_ or a dedicated console_mutex_.
    std::mutex& getConsoleMutex() { return console_mutex_; }

    double getElapsedSeconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(now - start_time_).count();
    }

    std::string getLogPath() const { return log_filename_; }
    
    // Compatibility methods for old getters if accessed by external code
    std::mutex& getMutex() { return getConsoleMutex(); } 

private:
    Logger() : running_(false), log_filename_(), log_level_(LogLevel::DEBUG),
               session_id_(0), error_count_(0), error_rate_limit_(100), suppressed_count_(0) {}
    
    ~Logger() { deinit(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Threading members
    std::mutex init_mutex_;
    std::mutex rate_limit_mutex_;
    std::mutex console_mutex_; // Protects std::cout/cerr
    
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::pair<LogLevel, std::string>> log_queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_;

    std::ofstream log_file_;
    std::string log_filename_;
    std::atomic<LogLevel> log_level_;

    // State members
    uint32_t session_id_;
    std::chrono::high_resolution_clock::time_point start_time_;
    
    // Rate limit members
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

    void pushMessage(LogLevel level, const std::string& formatted_message) {
        if (!running_) return;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            // Cap queue size to prevent memory explosion if disk is stuck
            if (log_queue_.size() < 10000) { 
                log_queue_.push({level, formatted_message});
            }
        }
        queue_cv_.notify_one();
    }

    void logv(LogLevel level, const char* format, va_list args) {
        // Do formatting on the caller thread to capture values accurately at the time of call
        char buffer[4096];
        vsnprintf(buffer, sizeof(buffer), format, args);
        
        std::string message(buffer);
        std::string line = formatLogLine(level, message);
        
        // 1. Synchronous Console Output (Fixes interaction with console wizards)
        {
            std::lock_guard<std::mutex> console_lock(console_mutex_);
            std::cout << line << "\n";
        }

        // 2. Asynchronous File Output
        pushMessage(level, line);
    }

    void writerThreadFunc() {
        std::vector<std::pair<LogLevel, std::string>> local_batch;
        local_batch.reserve(100);

        while (running_) {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !log_queue_.empty() || !running_;
            });

            if (!running_ && log_queue_.empty()) break;

            // Swap queue content to local batch to minimize lock time
            while (!log_queue_.empty() && local_batch.size() < 1000) {
                local_batch.push_back(std::move(log_queue_.front()));
                log_queue_.pop();
            }
            lock.unlock();

            // Process batch
            if (!local_batch.empty()) {
                if (log_file_.is_open()) {
                    bool force_flush = false;
                    for (const auto& msg : local_batch) {
                        // Msg.second is already fully formatted
                        log_file_ << msg.second << "\n";
                        if (msg.first == LogLevel::ERROR) force_flush = true;
                    }
                    if (force_flush) log_file_.flush();
                }
                local_batch.clear();
            }
        }
        
        // Final flush
        if (log_file_.is_open()) {
            log_file_.flush();
        }
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
