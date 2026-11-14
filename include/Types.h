#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>

namespace testsmem4u {

// Data a completed test leaves in its region, so the next test on that memory
// chunk can re-verify it before overwriting it: the data then sat idle for as
// long as other chunks were being tested. Values use global word numbers g:
// UNIFORM p0; XOR p0 ^ g * p1; LINEAR p0 + g * p1; BEAT simd::beat_value with
// even p0, odd p1, salt and step. [offset, offset + bytes) is the region (global
// byte offsets) the description covers.
struct ResidualPattern {
    enum class Kind : uint8_t { NONE, UNIFORM, XOR, LINEAR, BEAT };
    Kind kind = Kind::NONE;
    uint64_t p0 = 0;
    uint64_t p1 = 0;
    uint64_t salt = 0;
    uint64_t step = 0;
    uint64_t offset = 0;
    uint64_t bytes = 0;

    bool valid() const { return kind != Kind::NONE && bytes != 0; }
    bool sameData(const ResidualPattern& other) const {
        return kind == other.kind && p0 == other.p0 && p1 == other.p1 && salt == other.salt && step == other.step;
    }
};

// Test result structure for a single test run segment
struct TestResult {
    uint64_t hard_errors = 0;
    uint64_t soft_errors = 0;
    uint64_t unverified_errors = 0;  // Counted mismatches without re-read classification (bounded sampling or destructive march).

    uint64_t bytes_tested = 0;
    // Set by kernels that completed with a describable final state; merge()
    // deliberately leaves it alone (nested and per-block results differ).
    ResidualPattern residual;

    uint64_t total_errors() const { return hard_errors + soft_errors + unverified_errors; }
    uint64_t verified_errors() const { return hard_errors + soft_errors; }

    void merge(const TestResult& other) {
        hard_errors += other.hard_errors;
        soft_errors += other.soft_errors;
        unverified_errors += other.unverified_errors;
        bytes_tested += other.bytes_tested;
    }
};

// Per-test configuration from preset
struct TestConfig {
    uint8_t test_number = 0;
    bool enabled = true;
    std::string function;
    uint8_t pattern_mode = 0;
    uint64_t pattern_param0 = 0;
    uint64_t pattern_param1 = 0;
    uint32_t time_percent = 0;
    uint32_t parameter = 0;
    uint32_t block_size_mb = 0;
    // SimpleTest "Line Stride": fill order in 64-byte lines. 0/1 write lines in
    // address order; N > 1 writes lines 0, N, 2N, ..., then 1, N+1, ..., so
    // consecutive writes land in different rows (no prefetch, no row hits).
    uint32_t line_stride = 0;
    // Set per invocation by the scheduler from (cycle, loop); not a preset key.
    // 0 writes exactly the configured data. Other values derive new seeds and
    // pattern offsets so repeated passes test new data instead of identical bits.
    uint64_t variation = 0;
};

// RAII wrapper for MemoryRegion - ensures proper cleanup on all code paths
class MemoryGuard {
public:
    MemoryGuard() : base_(nullptr), size_(0), is_large_pages_(false), large_page_bytes_(0), is_locked_(false), locked_offset_(0), locked_bytes_(0), lp_chunk_size_(0) {}

    explicit MemoryGuard(uint8_t* base, size_t size, bool large_pages, size_t large_page_bytes, bool locked,
                         size_t locked_offset = 0, size_t locked_bytes = 0, size_t lp_chunk_size = 0)
        : base_(base), size_(size), is_large_pages_(large_pages), large_page_bytes_(large_page_bytes),
          is_locked_(locked), locked_offset_(locked_offset), locked_bytes_(locked_bytes), lp_chunk_size_(lp_chunk_size) {}

    ~MemoryGuard() {
        if (base_) {
            freeInternal(base_, size_, is_large_pages_, large_page_bytes_, is_locked_, locked_offset_, locked_bytes_, lp_chunk_size_);
        }
    }

    // Non-copyable
    MemoryGuard(const MemoryGuard&) = delete;
    MemoryGuard& operator=(const MemoryGuard&) = delete;

    // Movable
    MemoryGuard(MemoryGuard&& other) noexcept
        : base_(other.base_), size_(other.size_),
          is_large_pages_(other.is_large_pages_), large_page_bytes_(other.large_page_bytes_),
          is_locked_(other.is_locked_), locked_offset_(other.locked_offset_), locked_bytes_(other.locked_bytes_), lp_chunk_size_(other.lp_chunk_size_) {
        other.base_ = nullptr;
        other.size_ = 0;
        other.is_large_pages_ = false;
        other.large_page_bytes_ = 0;
        other.is_locked_ = false;
        other.locked_offset_ = 0;
        other.locked_bytes_ = 0;
        other.lp_chunk_size_ = 0;
    }

    MemoryGuard& operator=(MemoryGuard&& other) noexcept {
        if (this != &other) {
            if (base_) freeInternal(base_, size_, is_large_pages_, large_page_bytes_, is_locked_, locked_offset_, locked_bytes_, lp_chunk_size_);
            base_ = other.base_;
            size_ = other.size_;
            is_large_pages_ = other.is_large_pages_;
            large_page_bytes_ = other.large_page_bytes_;
            is_locked_ = other.is_locked_;
            locked_offset_ = other.locked_offset_;
            locked_bytes_ = other.locked_bytes_;
            lp_chunk_size_ = other.lp_chunk_size_;
            other.base_ = nullptr;
            other.size_ = 0;
            other.is_large_pages_ = false;
            other.large_page_bytes_ = 0;
            other.is_locked_ = false;
            other.locked_offset_ = 0;
            other.locked_bytes_ = 0;
            other.lp_chunk_size_ = 0;
        }
        return *this;
    }

    // Prevent accidental copy-assignment (non-const lvalue ref).
    // Move assignment (MemoryGuard&&) already handles self-assignment via this != &other check.
    MemoryGuard& operator=(MemoryGuard& other) = delete;

    uint8_t* base() const { return base_; }
    size_t size() const { return size_; }
    bool is_large_pages() const { return is_large_pages_; }
    size_t large_page_bytes() const { return large_page_bytes_; }
    bool is_locked() const { return is_locked_; }
    bool valid() const { return base_ != nullptr; }

    void release() {
        if (base_) {
            freeInternal(base_, size_, is_large_pages_, large_page_bytes_, is_locked_, locked_offset_, locked_bytes_, lp_chunk_size_);
            base_ = nullptr;
            size_ = 0;
            is_large_pages_ = false;
            large_page_bytes_ = 0;
            is_locked_ = false;
            locked_offset_ = 0;
            locked_bytes_ = 0;
            lp_chunk_size_ = 0;
        }
    }

private:
    uint8_t* base_;
    size_t size_;
    bool is_large_pages_;
    size_t large_page_bytes_;
    bool is_locked_;
    size_t locked_offset_;
    size_t locked_bytes_;
    size_t lp_chunk_size_;

    static void freeInternal(uint8_t* base, size_t size, bool large_pages, size_t large_page_bytes, bool locked,
                             size_t locked_offset, size_t locked_bytes, size_t lp_chunk_size);
};

} // namespace testsmem4u
