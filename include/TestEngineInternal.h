#pragma once
#include "TestEngine.h"
#include "Logger.h"
#include "MemoryTestKernels.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace testsmem4u {

// One RowHammer coverage warning per run; reset by TestEngine::runTests.
extern std::atomic<bool> g_rowhammer_large_page_warning_emitted;
// RowHammer point-budget INFO lines: true the first time a RowHammer test entry
// (test number, density, block size) runs in this run, so a preset with several
// RowHammer entries logs each budget once. At most kRowHammerBudgetLogLimit
// entries per run; cleared by TestEngine::runTests via resetRowHammerBudgetLog.
constexpr size_t kRowHammerBudgetLogLimit = 16;
bool claimRowHammerBudgetLog(const TestConfig& config);
void resetRowHammerBudgetLog();

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

using simd::mix64;

// XOR mask for one internal repetition of one scheduled pass. It is zero only
// for the first repetition of the first pass, which therefore writes exactly the
// configured pattern; every other (variation, repetition) pair gets new data.
constexpr uint64_t variationMask(uint64_t variation, uint64_t repetition) {
    return variation == 0 && repetition == 0 ? 0 : mix64(variation * 0x9E3779B97F4A7C15ULL + repetition + 1);
}

// Pass variation for loop `loop` of a sequence entry's data pass `pass`
// (EnabledSequence::pass: chunk cycle x occurrences per cycle + occurrence, so
// an entry listed once per cycle has pass == cycle).
constexpr uint64_t passVariation(uint64_t pass, uint64_t loops, uint64_t loop) {
    return pass * loops + loop;
}

// Pseudo-random seeds additionally differ per chunk/sub-block, so no two regions
// hold the same stream. A zero LFSR state never advances, so it is replaced.
constexpr uint64_t regionSeed(uint64_t configured, uint64_t base_offset_bytes, uint64_t variation,
                              uint64_t repetition) {
    const uint64_t seed = (configured ? configured : 0xACE1ACE2DEADBEEFULL) ^
                          variationMask(variation, repetition) ^
                          (base_offset_bytes ? mix64(base_offset_bytes ^ 0x5851F42D4C957F2DULL) : 0);
    return seed ? seed : 0xACE1ACE2DEADBEEFULL;
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

// RandomAccess checks up to this many words per batch, one per disjoint address
// band, each through original/inverted/restored phases.
constexpr size_t kRandomAccessLanes = 16;

// Per-region cap on `RandomAccess mismatch:` debug lines; later mismatching
// batches are only counted in the region summary line.
constexpr uint64_t kRandomAccessMismatchLogLimit = 8;

// RandomAccess stores salt + word * step: an odd step keeps every word's value
// unique (address aliasing stays detectable) while all 64 bits vary. The old
// value, the word number itself, left the upper 32 bits constant everywhere.
constexpr uint64_t kRandomAccessStep = 0x9E3779B97F4A7C15ULL;

constexpr uint64_t randomAccessValue(uint64_t global_word, uint64_t salt) {
    return salt + global_word * kRandomAccessStep;
}

inline uint64_t randomAccessIterations(uint32_t parameter, size_t words) {
    if (parameter > kRandomAccessPassLimit) return parameter;
    return static_cast<uint64_t>(words) * std::max(1U, parameter);
}

// RowHammer hammer points per invocation. Parameter is a density in points per
// GiB of the tested region (0 = 2048, the long-standing 2 per MiB), so RowHammer's
// share of a cycle is the same for every window size and worker count like the
// other size-proportional tests. Until 2026-11-14 Parameter was an absolute count
// per region: 250 points cost ~90 s per chunk even on a 64 MB window, and more
// workers (more, smaller chunks) multiplied the total. At least one point per
// usable stride, at most kRowHammerMaxPoints.
constexpr uint64_t kRowHammerDefaultPointsPerGiB = 2048;
constexpr size_t kRowHammerMaxPoints = 100000;

inline size_t rowHammerPoints(size_t region_bytes, uint32_t points_per_gib, size_t usable_strides) {
    const uint64_t density = points_per_gib ? points_per_gib : kRowHammerDefaultPointsPerGiB;
    // Exact bytes, rounded to the nearest point. Truncating to whole MiB first
    // gave sub-MiB regions (sub-block tails) no points beyond the per-stride
    // floor and cut a 3.6 MiB chunk's budget by 17%. A product that would
    // overflow 64 bits is far above the cap.
    constexpr uint64_t kGiB = uint64_t{1} << 30;
    const uint64_t bytes = static_cast<uint64_t>(region_bytes);
    const uint64_t max_exact_bytes = (std::numeric_limits<uint64_t>::max() - kGiB / 2) / density;
    const uint64_t points = bytes > max_exact_bytes ? kRowHammerMaxPoints : (bytes * density + kGiB / 2) / kGiB;
    const uint64_t floor = std::max<uint64_t>(1, usable_strides);
    return static_cast<size_t>(std::min<uint64_t>(std::max(points, floor), kRowHammerMaxPoints));
}

// Internal repetitions per invocation for the pre-run loop estimate. Parameter
// is a repetition count only for some functions: RefreshStable's is a dwell in
// milliseconds, RowHammer's a density in points per GiB, RandomAccess's above
// kRandomAccessPassLimit an access count, and Walking/LFSRPattern ignore it.
// Counting those as repetitions made the interleaved default preset (three
// RefreshStable entries with Parameter=10000) warn about an excessive run at
// 4 cycles although each cycle is about an hour at 28 GB.
inline uint64_t estimatedRepetitions(const TestConfig& config) {
    const std::string& f = config.function;
    if (f == "Modulo20") return config.parameter ? config.parameter : 3;
    if (f == "RandomAccess") return config.parameter <= kRandomAccessPassLimit ? std::max(1U, config.parameter) : 1;
    if (f == "SimpleTest" || f == "MirrorMove" || f == "MirrorMove128" || f == "BlockMove" ||
        f == "MovingInversion" || f == "MovingInversionLFSR" || f == "MovingInversionWalking") {
        return std::max(1U, config.parameter);
    }
    return 1;
}

// Pre-run estimate of loop invocations times internal repetitions over all
// cycles of the enabled sequence entries (a rough runtime-scale warning above
// kMaxRecommendedLoops).
constexpr uint64_t kMaxRecommendedLoops = 100000;
inline uint64_t estimatedTotalLoops(const Config& config, const std::vector<uint32_t>& seq,
                                    const std::map<uint32_t, TestConfig>& configs) {
    uint64_t total = 0;
    for (uint32_t test_id : seq) {
        const auto it = configs.find(test_id);
        if (it == configs.end() || !it->second.enabled) continue;
        const uint64_t loops =
            std::max<uint64_t>(1, (static_cast<uint64_t>(config.preset.time_percent) * it->second.time_percent) / 100);
        total += loops * estimatedRepetitions(it->second);
    }
    return total * (config.cycles == 0 ? 1 : config.cycles);
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

// SimpleTest "Pattern Mode=3": per-beat complement (simd::BeatPattern). Param0
// is the even word, its complement the odd word, Param1 the address-tag step
// (odd values give every 16-byte unit its own tag; 0 makes the tag constant).
// Passes vary the tag salt, never Param0, so the configured complement
// relations (also between 32-bit halves) hold on every pass.
constexpr uint8_t kPatternModeBeat = 3;

inline simd::BeatPattern simpleBeatPattern(const TestConfig& config, uint64_t repetition) {
    return simd::BeatPattern{config.pattern_param0, ~config.pattern_param0,
                             variationMask(config.variation, repetition), config.pattern_param1};
}

// SimpleTest "Line Stride" fill: whole 64-byte lines (dst is line-aligned) in
// the order 0, s, 2s, ..., then 1, s+1, ..., so consecutive writes land in
// different rows and defeat prefetching; a partial final line comes last.
// value(global_word) gives each word; on x86-64 every word is a non-temporal
// store, so the streaming-fill contract (simd::flush_after_streaming_fill) holds.
template <typename ValueFn>
void fillStridedLines(uint64_t* dst, size_t count, uint64_t word_start, size_t stride, ValueFn&& value) {
    constexpr size_t kWordsPerLine = 8;
    const size_t lines = count / kWordsPerLine;
    [[maybe_unused]] const bool nt = simd::getCapabilities().has_nt_stores;
    auto store = [&](size_t k) {
        const uint64_t word = value(word_start + k);
#if defined(__x86_64__) || defined(_M_X64)
        if (nt) {
            _mm_stream_si64(reinterpret_cast<long long*>(dst + k), static_cast<long long>(word));
            return;
        }
#endif
        dst[k] = word;
    };
    // A stride beyond the block gives one line per phase. Bound the increment
    // too, so a large preset stride cannot wrap size_t on 32-bit targets.
    const size_t line_stride = std::min(stride, lines);
    for (size_t phase = 0; phase < line_stride; ++phase) {
        for (size_t line = phase; line < lines; line += line_stride) {
            for (size_t w = 0; w < kWordsPerLine; ++w) store(line * kWordsPerLine + w);
        }
    }
    for (size_t k = lines * kWordsPerLine; k < count; ++k) store(k);
    simd::sfence();
}

// Verifies base[start .. start+count) against a beat pattern numbered by global
// word and classifies mismatches (hard/soft re-read).
inline size_t verifyBeatAndReport(const MemoryRegion& region, const uint64_t* base, size_t start, size_t count,
                                  const simd::BeatPattern& pattern, TestResult& res, TestContext& ctx,
                                  const char* name, bool halt_on_error) {
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    const uint64_t first_word = globalWordStart(region);
    const size_t found = simd::verify_pattern_beat(base + start, count, pattern, first_word + start, errors);
    classifyAndLogErrors(region, base, errors, found, start,
                         [&](size_t offset) { return simd::beat_value(pattern, first_word + offset); },
                         res, ctx, name, halt_on_error);
    return found;
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
