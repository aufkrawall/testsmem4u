// MirrorMove and MirrorMove128: TestMem5-style mirror moves. Two streams start at
// opposite ends of the memory chunk, read what they find and write it back
// swapped while converging, so every step reads and writes two far-apart rows:
// row conflicts and read/write turnarounds within one thread. Until 2026-11-14
// MirrorMove only inverted the data in place and MirrorMove128 rotated it by one
// word with memmove; neither mirrored anything.
#include "TestEngineInternal.h"
#include <algorithm>

namespace testsmem4u {
namespace {

constexpr size_t kMirrorVerifyBlock = size_t{256} * 1024;
// MirrorMove's step when Param1 is 0. Odd, so every word's value is unique.
constexpr uint64_t kMirrorDefaultStep = 0x9E3779B97F4A7C15ULL;
// MirrorMove128's address-tag step (odd: a distinct tag per 16-byte unit).
constexpr uint64_t kMirror128TagStep = 0xD1B54A32D192ED03ULL;

} // namespace

// Linear data (word g holds base + g * step), then Parameter mirror passes
// (0 = 1). Each pass reverses the chunk word by word and verifies all of it. The
// reversed data is linear again with a negated step, so every pass checks every
// word at a new value. A word read wrongly during a move is written to the
// mirrored position and reported there.
TestResult TestEngine::runMirrorMove(TestContext& ctx, const MemoryRegion& region, const TestConfig& config, bool stop) {
    TestResult res;
    VerificationProgress progress(ctx, res, region);
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    if (!count || ctx.shouldStop()) return res;
    const uint64_t g0 = globalWordStart(region);
    const uint32_t passes = config.parameter ? config.parameter : 1;
    uint64_t base = config.pattern_param0 ^ variationMask(config.variation, 0);
    uint64_t step = config.pattern_param1 ? config.pattern_param1 : kMirrorDefaultStep;
    auto verifyAll = [&](const char* name) {
        for (size_t i = 0; i < count && !ctx.shouldStop(); i += kMirrorVerifyBlock) {
            const size_t n = std::min(kMirrorVerifyBlock, count - i);
            verifyAndReport(region, ptr + i, n, i, 2, base, step, res, ctx, name, stop);
            progress.addBytes(n * sizeof(uint64_t));
        }
    };

    simd::generate_pattern_linear(ptr, count, base, step, true, g0);
    simd::flush_after_streaming_fill(ptr, region.size);
    testPhase(ctx, "Mirror filled", region);
    verifyAll("MirrorMove (Init)");

    RepetitionProgress steps(ctx, passes);
    uint32_t done = 0;
    for (; done < passes && !ctx.shouldStop(); ++done) {
        steps.begin(done);
        testPhase(ctx, "Mirror move", region);
        simd::mirror_reverse_words(ptr, count);
        // The move's loads cached the lines; verification must read DRAM.
        simd::flush_cache_region(ptr, region.size);
        // Word k now holds former word count-1-k.
        base += (2 * g0 + count - 1) * step;
        step = 0 - step;
        testPhase(ctx, "Mirror moved", region);
        verifyAll("MirrorMove (Moved)");
    }
    LOG_DEBUG("MirrorMove: offset=%zu words=%zu passes=%u/%u reversed=%s errors=%llu%s", region.base_offset_bytes, count,
              done, passes, done % 2 ? "yes" : "no", static_cast<unsigned long long>(res.total_errors()),
              ctx.shouldStop() ? " [stopped]" : "");
    return res;
}

// Beat data (simd::BeatPattern: Param0/Param1 are the even/odd words, normally
// complements such as 0x55../0xAA.., plus an address tag per 16-byte unit), then
// Parameter mirror passes (0 = 1) that reverse the order of the 16-byte units,
// each unit kept intact, and verify all of it.
TestResult TestEngine::runMirrorMove128(TestContext& ctx, const MemoryRegion& region, const TestConfig& config,
                                        bool stop) {
    TestResult res;
    VerificationProgress progress(ctx, res, region);
    auto* ptr = reinterpret_cast<uint64_t*>(region.base);
    const size_t count = region.size / sizeof(uint64_t);
    if (!count || ctx.shouldStop()) return res;
    const uint64_t g0 = globalWordStart(region);
    const uint32_t passes = config.parameter ? config.parameter : 1;
    // One salt per pass keeps the configured even/odd relation on new values.
    const simd::BeatPattern original{config.pattern_param0, config.pattern_param1,
                                     variationMask(config.variation, 0), kMirror128TagStep};
    // Units follow global word pairs; a leading odd word and a final odd word
    // stay in place and keep the original values.
    const size_t lead = g0 & 1;
    const size_t units = (count - lead) / 2;
    const size_t moved_end = lead + 2 * units;
    simd::BeatPattern current = original;
    auto verifyRange = [&](size_t begin, size_t end, const simd::BeatPattern& pattern, const char* name) {
        for (size_t i = begin; i < end && !ctx.shouldStop(); i += kMirrorVerifyBlock) {
            const size_t n = std::min(kMirrorVerifyBlock, end - i);
            verifyBeatAndReport(region, ptr, i, n, pattern, res, ctx, name, stop);
            progress.addBytes(n * sizeof(uint64_t));
        }
    };
    auto verifyAll = [&](const char* name) {
        verifyRange(0, lead, original, name);
        verifyRange(lead, moved_end, current, name);
        verifyRange(moved_end, count, original, name);
    };

    simd::generate_pattern_beat(ptr, count, original, g0, true);
    simd::flush_after_streaming_fill(ptr, region.size);
    testPhase(ctx, "Mirror128 filled", region);
    verifyAll("MirrorMove128 (Init)");

    RepetitionProgress steps(ctx, passes);
    uint32_t done = 0;
    for (; done < passes && !ctx.shouldStop(); ++done) {
        steps.begin(done);
        testPhase(ctx, "Mirror128 move", region);
        simd::mirror_reverse_pairs(ptr + lead, 2 * units);
        simd::flush_cache_region(ptr, region.size);
        current = simd::beat_mirrored(current, g0 + lead, units);
        testPhase(ctx, "Mirror128 moved", region);
        verifyAll("MirrorMove128 (Moved)");
    }
    LOG_DEBUG("MirrorMove128: offset=%zu words=%zu units=%zu fixed-words=%zu passes=%u/%u reversed=%s errors=%llu%s",
              region.base_offset_bytes, count, units, count - 2 * units, done, passes, done % 2 ? "yes" : "no",
              static_cast<unsigned long long>(res.total_errors()), ctx.shouldStop() ? " [stopped]" : "");
    return res;
}

} // namespace testsmem4u
