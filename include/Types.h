#pragma once

#include <cstdint>
#include <string>
#include <memory>

namespace testsmem4u {

// Test result structure for a single test run segment
struct TestResult {
    uint64_t hard_errors = 0;
    uint64_t soft_errors = 0;
    uint64_t unverified_errors = 0;  // Reserved: errors detected but not re-read verified (currently unused, kept for future error-limiting logic)
    
    uint64_t bytes_tested = 0;
    uint64_t cycles_completed = 0;

    uint64_t total_errors() const { return hard_errors + soft_errors + unverified_errors; }
    uint64_t verified_errors() const { return hard_errors + soft_errors; }

    void merge(const TestResult& other) {
        hard_errors += other.hard_errors;
        soft_errors += other.soft_errors;
        unverified_errors += other.unverified_errors;
        bytes_tested += other.bytes_tested;
        cycles_completed += other.cycles_completed;
    }
};

// Per-test configuration from preset
struct TestConfig {
    uint8_t test_number = 0;
    std::string function;
    uint8_t pattern_mode = 0;
    uint64_t pattern_param0 = 0;
    uint64_t pattern_param1 = 0;
    uint32_t time_percent = 0;
    uint32_t parameter = 0;
    uint32_t block_size_mb = 0;
};

// RAII wrapper for MemoryRegion - ensures proper cleanup on all code paths
class MemoryGuard {
public:
    MemoryGuard() : base_(nullptr), size_(0), is_large_pages_(false), is_locked_(false) {}

    explicit MemoryGuard(uint8_t* base, size_t size, bool large_pages, bool locked)
        : base_(base), size_(size), is_large_pages_(large_pages), is_locked_(locked) {}

    ~MemoryGuard() {
        if (base_) {
            freeInternal(base_, size_, is_large_pages_, is_locked_);
        }
    }

    // Non-copyable
    MemoryGuard(const MemoryGuard&) = delete;
    MemoryGuard& operator=(const MemoryGuard&) = delete;

    // Movable
    MemoryGuard(MemoryGuard&& other) noexcept
        : base_(other.base_), size_(other.size_),
          is_large_pages_(other.is_large_pages_), is_locked_(other.is_locked_) {
        other.base_ = nullptr;
        other.size_ = 0;
        other.is_large_pages_ = false;
        other.is_locked_ = false;
    }

    MemoryGuard& operator=(MemoryGuard&& other) noexcept {
        if (this != &other) {
            if (base_) freeInternal(base_, size_, is_large_pages_, is_locked_);
            base_ = other.base_;
            size_ = other.size_;
            is_large_pages_ = other.is_large_pages_;
            is_locked_ = other.is_locked_;
            other.base_ = nullptr;
            other.size_ = 0;
            other.is_large_pages_ = false;
            other.is_locked_ = false;
        }
        return *this;
    }

    // Self-move assignment safety - do nothing if self-assigned
    MemoryGuard& operator=(MemoryGuard& other) = delete;

    uint8_t* base() const { return base_; }
    size_t size() const { return size_; }
    bool is_large_pages() const { return is_large_pages_; }
    bool is_locked() const { return is_locked_; }
    bool valid() const { return base_ != nullptr; }

    void release() {
        if (base_) {
            freeInternal(base_, size_, is_large_pages_, is_locked_);
            base_ = nullptr;
            size_ = 0;
            is_large_pages_ = false;
            is_locked_ = false;
        }
    }

private:
    uint8_t* base_;
    size_t size_;
    bool is_large_pages_;
    bool is_locked_;

    static void freeInternal(uint8_t* base, size_t size, bool large_pages, bool locked);
};

} // namespace testsmem4u
