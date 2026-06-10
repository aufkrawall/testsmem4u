#include "Logger.h"
#include "ConsoleDisplay.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace testsmem4u {

void Logger::init(const std::string& filename, LogLevel level, bool purge) {
    std::lock_guard<std::mutex> lock(init_mutex_);

    if (running_) {
        return; // Already initialized
    }

    log_filename_ = filename;
    log_level_ = level;

    start_time_ = std::chrono::high_resolution_clock::now();
    error_count_ = 0;
    error_rate_limit_.store(100, std::memory_order_relaxed);
    suppressed_count_ = 0;
    dropped_critical_messages_.store(0, std::memory_order_relaxed);
    dropped_noncritical_messages_.store(0, std::memory_order_relaxed);
    last_summary_time_ = std::chrono::high_resolution_clock::now();

    if (!filename.empty()) {
        file_handle_ = fopen(filename.c_str(), purge ? "w" : "a");
        if (!file_handle_) {
            std::cerr << "[-] Failed to open log file: " << filename << std::endl;
        }
    }

    running_ = true;
    writer_thread_ = std::thread(&Logger::writerThreadFunc, this);
}

void Logger::setErrorRateLimit(uint32_t errors_per_second) {
    error_rate_limit_.store(errors_per_second, std::memory_order_relaxed);
}

void Logger::deinit() {
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

void Logger::debug(const char* format, ...) {
    if (log_level_.load(std::memory_order_relaxed) > LogLevel::DEBUG) return;
    va_list args;
    va_start(args, format);
    logv(LogLevel::DEBUG, format, args);
    va_end(args);
}

void Logger::info(const char* format, ...) {
    if (log_level_.load(std::memory_order_relaxed) > LogLevel::INFO) return;
    va_list args;
    va_start(args, format);
    logv(LogLevel::INFO, format, args);
    va_end(args);
}

void Logger::warn(const char* format, ...) {
    if (log_level_.load(std::memory_order_relaxed) > LogLevel::WARN) return;
    va_list args;
    va_start(args, format);
    logv(LogLevel::WARN, format, args);
    va_end(args);
}

void Logger::error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    logv(LogLevel::ERR, format, args);
    va_end(args);
}

void Logger::logError(const std::string& context, uint64_t address, uint64_t expected, uint64_t actual) {
    char error_msg[512];
    snprintf(error_msg, sizeof(error_msg),
        "ERROR: %s at 0x%016llX: expected 0x%016llX, got 0x%016llX",
        context.c_str(), (unsigned long long)address, (unsigned long long)expected, (unsigned long long)actual);

    std::string formatted = formatLogLine(LogLevel::ERR, std::string(error_msg));
    pushMessage(LogLevel::ERR, formatted);
    handleConsoleOutput(std::string(error_msg));
}

// Console output for detected memory errors. Always rate-limited: during an
// error storm on faulty hardware, unthrottled per-error console writes would
// make the run IO-bound. Every error is still counted in the result totals and
// queued for the log file regardless of console suppression. All console
// writes go through ConsoleDisplay so they coordinate with the status line.
void Logger::handleConsoleOutput(const std::string& message) {
    {
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        auto now = std::chrono::high_resolution_clock::now();

        auto seconds_since_summary = std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_time_).count();
        if (seconds_since_summary >= 1) {
            if (suppressed_count_ > 0) {
                char buf[128];
                snprintf(buf, sizeof(buf), "ERROR RATE: %u additional errors suppressed (see log file)", suppressed_count_);
                ConsoleDisplay::get().printLine(formatLogLine(LogLevel::WARN, buf));
                suppressed_count_ = 0;
            }
            error_count_ = 0;
            last_summary_time_ = now;
        }

        if (error_count_ >= error_rate_limit_.load(std::memory_order_relaxed)) {
            suppressed_count_++;
            return;
        }
        error_count_++;
    }

    ConsoleDisplay::get().printError(formatLogLine(LogLevel::ERR, message));
}

void Logger::pushMessage(LogLevel level, const std::string& formatted_message) {
    if (!running_) return;

    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        constexpr size_t MAX_QUEUE_SIZE = 1000000;
        constexpr size_t NONCRITICAL_QUEUE_LIMIT = 900000;

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

void Logger::logv(LogLevel level, const char* format, va_list args) {
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(nullptr, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) return;

    std::string message;
    message.resize(len + 1);
    vsnprintf(&message[0], len + 1, format, args);
    message.resize(len);

    std::string line = formatLogLine(level, message);

    // WARN and infrastructure ERR lines are rare and must be visible; route
    // them through ConsoleDisplay so they do not clobber the status line.
    // (Per-error reporting goes through logError -> handleConsoleOutput,
    // which is rate-limited.)
    if (level >= LogLevel::ERR) {
        ConsoleDisplay::get().printError(line);
    } else if (level >= LogLevel::WARN) {
        ConsoleDisplay::get().printLine(line);
    }

    pushMessage(level, line);
}

void Logger::writerThreadFunc() {
    std::vector<std::pair<LogLevel, std::string>> local_batch;
    local_batch.reserve(500);
    auto last_dropped_report = std::chrono::steady_clock::now();
    uint64_t last_reported_critical = 0;
    uint64_t last_reported_noncritical = 0;

    while (true) {
         std::unique_lock<std::mutex> lock(queue_mutex_);

          auto now = std::chrono::steady_clock::now();
          if (std::chrono::duration_cast<std::chrono::seconds>(now - last_dropped_report).count() >= 30) {
              uint64_t crit = dropped_critical_messages_.load(std::memory_order_relaxed);
              uint64_t noncrit = dropped_noncritical_messages_.load(std::memory_order_relaxed);
              uint64_t new_crit = crit - last_reported_critical;
              uint64_t new_noncrit = noncrit - last_reported_noncritical;
              if (new_crit > 0 || new_noncrit > 0) {
                  if (file_handle_) {
                      auto ts = getTimestamp();
                      auto tid = std::this_thread::get_id();
                      double elapsed = getElapsedSeconds();
                      if (new_crit > 0) {
                          std::string line = std::to_string(new_crit)
                              + " critical messages dropped in last 30s (total: " + std::to_string(crit) + ")";
                          fprintf(file_handle_, "[%s][WARN][T%zu][%.3fs] LOG DROPPED: %s\n",
                                  ts.c_str(), std::hash<std::thread::id>{}(tid),
                                  elapsed, line.c_str());
                      }
                      if (new_noncrit > 0) {
                          std::string line = std::to_string(new_noncrit)
                              + " non-critical messages dropped in last 30s (total: " + std::to_string(noncrit) + ")";
                          fprintf(file_handle_, "[%s][WARN][T%zu][%.3fs] LOG DROPPED: %s\n",
                                  ts.c_str(), std::hash<std::thread::id>{}(tid),
                                  elapsed, line.c_str());
                      }
                      fflush(file_handle_);
                  }
                  last_reported_critical = crit;
                  last_reported_noncritical = noncrit;
              }
              last_dropped_report = now;
          }

          writer_cv_.wait_for(lock, std::chrono::seconds(5), [this] {
              return !log_queue_.empty() || !running_;
          });

          if (!running_ && log_queue_.empty()) break;

         while (!log_queue_.empty() && local_batch.size() < 2000) {
             local_batch.push_back(std::move(log_queue_.front()));
             log_queue_.pop();
         }

         lock.unlock();

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

    if (file_handle_) {
        uint64_t crit = dropped_critical_messages_.load(std::memory_order_relaxed);
        uint64_t noncrit = dropped_noncritical_messages_.load(std::memory_order_relaxed);
        if (crit > 0) {
            fprintf(file_handle_, "[%s][WARN][T%zu][%.3fs] LOG DROPPED: %llu critical messages dropped total (final)\n",
                    getTimestamp().c_str(), std::hash<std::thread::id>{}(std::this_thread::get_id()),
                    getElapsedSeconds(), (unsigned long long)crit);
        }
        if (noncrit > 0) {
            fprintf(file_handle_, "[%s][WARN][T%zu][%.3fs] LOG DROPPED: %llu non-critical messages dropped total (final)\n",
                    getTimestamp().c_str(), std::hash<std::thread::id>{}(std::this_thread::get_id()),
                    getElapsedSeconds(), (unsigned long long)noncrit);
        }
        fflush(file_handle_);
    }
}

std::string Logger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

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

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERR:   return "ERROR";
        default:              return "UNKNOWN";
    }
}

std::string Logger::formatLogLine(LogLevel level, const std::string& message) {
    std::stringstream ss;
    ss << "[" << getTimestamp() << "]";
    ss << "[" << levelToString(level) << "]";
    ss << "[T" << std::this_thread::get_id() << "]";
    ss << "[" << std::fixed << std::setprecision(3) << getElapsedSeconds() << "s]";
    ss << " " << message;
    return ss.str();
}

} // namespace testsmem4u
