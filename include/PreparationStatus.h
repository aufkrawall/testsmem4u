#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace testsmem4u {

// Owns the preparation display thread even when allocation or rendering throws.
// The one-second timeout only refreshes the UI; completion wakes it immediately.
class PreparationStatus {
public:
    explicit PreparationStatus(std::function<void(uint64_t)> update)
        : worker_([this, update = std::move(update)] {
            try {
                std::unique_lock<std::mutex> lock(mutex_);
                uint64_t seconds = 0;
                while (!done_) {
                    lock.unlock();
                    update(seconds);
                    lock.lock();
                    cv_.wait_for(lock, std::chrono::seconds(1), [this] { return done_; });
                    ++seconds;
                }
            } catch (...) {
                // Read only after join; the callback cannot escape the thread.
                failure_ = std::current_exception();
            }
        }) {}

    ~PreparationStatus() { stopAndJoin(); }
    PreparationStatus(const PreparationStatus&) = delete;
    PreparationStatus& operator=(const PreparationStatus&) = delete;

    void finish() {
        stopAndJoin();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void stopAndJoin() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        cv_.notify_one();
        if (worker_.joinable()) worker_.join();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    bool done_ = false;
    std::exception_ptr failure_;
    std::thread worker_;
};

} // namespace testsmem4u
