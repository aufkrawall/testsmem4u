#pragma once
#include "TestEngine.h"
#include "Logger.h"
#include <algorithm>
#include <atomic>
#include <chrono>

namespace testsmem4u {

// One RowHammer coverage warning per run; reset by TestEngine::runTests.
extern std::atomic<bool> g_rowhammer_large_page_warning_emitted;

// Account verified blocks once, at the leaf kernel. Nested results are merged
// for the return value only. Error deltas survive cancellation and unwinding.
class VerificationProgress {
public:
    VerificationProgress(TestContext& ctx, TestResult& result, const MemoryRegion& region)
        : ctx_(ctx), result_(result), region_(region) {
        ProgressBinding::setPhase(&ctx, "Fill/prepare");
    }
    ~VerificationProgress() { publish(0); }
    VerificationProgress(const VerificationProgress&) = delete;
    VerificationProgress& operator=(const VerificationProgress&) = delete;

    void addBytes(uint64_t bytes) {
        result_.bytes_tested += bytes;
        publish(bytes);
#ifdef TESTSMEM4U_TESTING
        if (ctx_.phase_hook) ctx_.phase_hook("Verified block", region_);
#endif
    }

    void mergeNested(const TestResult& nested) {
        result_.merge(nested);
        published_.hard_errors += nested.hard_errors;
        published_.soft_errors += nested.soft_errors;
        published_.unverified_errors += nested.unverified_errors;
    }

private:
    void publish(uint64_t bytes) noexcept {
        TestResult delta;
        delta.bytes_tested = bytes;
        delta.hard_errors = result_.hard_errors - published_.hard_errors;
        delta.soft_errors = result_.soft_errors - published_.soft_errors;
        delta.unverified_errors = result_.unverified_errors - published_.unverified_errors;
        ctx_.publishProgress(delta);
        published_ = result_;
    }

    TestContext& ctx_;
    TestResult& result_;
    [[maybe_unused]] const MemoryRegion& region_;
    TestResult published_;
};

// Publishes the outermost kernel's internal repetitions as current-test
// progress for the status line. Nested kernels (retention background tests)
// do not claim the binding and leave the outer kernel's progress untouched.
class RepetitionProgress {
public:
    RepetitionProgress(TestContext& ctx, uint64_t repetitions) noexcept
        : ctx_(ctx), repetitions_(std::max<uint64_t>(1, repetitions)),
          owner_(ProgressBinding::claimRepetitions(&ctx)) {}
    ~RepetitionProgress() {
        if (owner_) ProgressBinding::releaseRepetitions(&ctx_);
    }
    RepetitionProgress(const RepetitionProgress&) = delete;
    RepetitionProgress& operator=(const RepetitionProgress&) = delete;

    void begin(uint64_t repetition) noexcept {
        if (owner_) ProgressBinding::setRepetition(&ctx_, repetition, repetitions_);
    }

private:
    TestContext& ctx_;
    uint64_t repetitions_;
    bool owner_;
};

// Generate expected pattern value for verification
// mode 0: uniform (val = p0)
// mode 1: XOR pattern (val = p0 ^ (index * p1), wrapping is intentional for address testing)
// mode 2: linear pattern (val = p0 + (index * p1), wrapping is intentional for address testing)
// Note: index * p1 multiplication may overflow 64-bit; this is intentional behavior
// for address line testing where we want to see all bit combinations
inline void generatePatternValue(uint64_t index, uint8_t mode, uint64_t p0, uint64_t p1, uint64_t& val) {
    if (mode == 0) val = p0;
    else if (mode == 1) val = p0 ^ (index * p1);
    else if (mode == 2) val = p0 + (index * p1);
    else val = index;
}

inline uint64_t reportAddress(const MemoryRegion& region, const void* ptr) {
    const auto* byte_ptr = static_cast<const uint8_t*>(ptr);
    return static_cast<uint64_t>(region.base_offset_bytes + static_cast<size_t>(byte_ptr - region.base));
}

// Global word number: the index that address-dependent patterns turn into 64-bit
// values. It is uint64_t on every target, so arithmetic on it (e.g. a complement)
// covers all 64 bits even where size_t is 32-bit (linux-x86).
inline uint64_t globalWordStart(const MemoryRegion& region, size_t local_start_idx = 0) {
    return uint64_t{region.base_offset_bytes / sizeof(uint64_t)} + local_start_idx;
}

// RandomAccess Parameter: values up to this limit are passes over the region
// (0 means 1 pass); larger values are an explicit access count per region.
constexpr uint32_t kRandomAccessPassLimit = 100;

inline uint64_t randomAccessIterations(uint32_t parameter, size_t words) {
    if (parameter > kRandomAccessPassLimit) return parameter;
    return static_cast<uint64_t>(words) * std::max(1U, parameter);
}

inline void addUnverifiedOverflow(TestResult& res, size_t total_found, size_t sampled) {
    if (total_found > sampled) {
        res.unverified_errors += static_cast<uint64_t>(total_found - sampled);
    }
}

// Shared mismatch classification: re-reads each sampled mismatch from DRAM via
// safe_read_u64 and logs it as hard (still wrong) or soft/transient (corrected),
// then accounts unsampled mismatches as unverified. Sample offsets in `errors`
// are relative to ptr[base_offset]. expected_at(absolute_offset) must return
// the expected value for ptr[absolute_offset]. Requests a stop after the batch
// when halt_on_error is set and mismatches were found.
template <typename ExpectedFn>
inline void classifyAndLogErrors(const MemoryRegion& region, const uint64_t* ptr,
                                 const std::vector<std::pair<uint64_t, uint64_t>>& errors,
                                 size_t total_found, size_t base_offset, ExpectedFn&& expected_at,
                                 TestResult& res, TestContext& ctx, const char* name, bool halt_on_error) {
    if (total_found == 0) return;

    const std::string hard_name = std::string(name) + " (Hard)";
    const std::string soft_name = std::string(name) + " (Soft)";
    for (const auto& err : errors) {
        const size_t offset = base_offset + static_cast<size_t>(err.first);
        const uint64_t first_observed = err.second;
        const uint64_t expect = expected_at(offset);
        const uint64_t confirmed = simd::safe_read_u64(&ptr[offset]);
        if (confirmed != expect) {
            res.hard_errors++;
            LOG_ERROR_DETAIL(hard_name.c_str(), reportAddress(region, &ptr[offset]), expect, confirmed);
        } else {
            res.soft_errors++;
            LOG_ERROR_DETAIL(soft_name.c_str(), reportAddress(region, &ptr[offset]), expect, first_observed);
        }
    }
    addUnverifiedOverflow(res, total_found, errors.size());
    if (halt_on_error) {
        ctx.requestStop();
    }
}


inline void testPhase(TestContext& ctx, const char* phase, const MemoryRegion& region) {
    ProgressBinding::setPhase(&ctx, phase);
#ifdef TESTSMEM4U_TESTING
    if (ctx.phase_hook) ctx.phase_hook(phase, region);
#else
    (void)region;
#endif
}
} // namespace testsmem4u
