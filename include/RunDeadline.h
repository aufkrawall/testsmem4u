#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace testsmem4u {

// Wall-clock time limit for a run. A dedicated thread blocks until the deadline
// or until finish() and calls on_expire exactly once if the deadline came first.
// No polling: workers keep checking their existing stop flag, which on_expire
// sets. finish() is idempotent and joins; the destructor calls it.
class RunDeadline {
public:
    RunDeadline() = default;
    RunDeadline(const RunDeadline&) = delete;
    RunDeadline& operator=(const RunDeadline&) = delete;
    ~RunDeadline() { finish(); }

    // Starts the timer thread (may throw std::system_error like any thread start).
    void start(std::chrono::steady_clock::time_point deadline, std::function<void()> on_expire) {
        thread_ = std::thread([this, deadline, on_expire = std::move(on_expire)]() noexcept {
            std::unique_lock<std::mutex> lock(mutex_);
            if (cv_.wait_until(lock, deadline, [this]() { return finished_; })) return;
            expired_.store(true, std::memory_order_release);
            lock.unlock();
            try {
                on_expire();
            } catch (...) {
                // on_expire only logs and requests a stop; a failed log line must not
                // terminate the process. The expired flag is already set.
            }
        });
    }

    void finish() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            finished_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

    bool expired() const noexcept { return expired_.load(std::memory_order_acquire); }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool finished_ = false;
    std::atomic<bool> expired_{false};
    std::thread thread_; // last: the thread uses the members above
};

} // namespace testsmem4u
