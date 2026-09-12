#pragma once
#include "TestEngine.h"
#include <algorithm>

namespace testsmem4u {
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

inline size_t globalWordStart(const MemoryRegion& region, size_t local_start_idx = 0) {
    return (region.base_offset_bytes / sizeof(uint64_t)) + local_start_idx;
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
#ifdef TESTSMEM4U_TESTING
    if (ctx.phase_hook) ctx.phase_hook(phase, region);
#else
    (void)ctx; (void)phase; (void)region;
#endif
}
} // namespace testsmem4u
