#pragma once

// Per-beat complement pattern (SimpleTest Pattern Mode 3) and mirror moves.

void testBeatPatternKernels() {
    alignas(64) std::array<uint64_t, 80> memory{};
    const simd::BeatPattern pattern{0x55555555AAAAAAAAULL, 0xAAAAAAAA55555555ULL, 0x0123456789ABCDEFULL,
                                    0x9E3779B97F4A7C15ULL};
    for (uint64_t start : {uint64_t{0}, uint64_t{1}, uint64_t{6}, uint64_t{0x10001}}) {
        for (size_t offset : {size_t{0}, size_t{1}, size_t{3}}) {
            for (size_t count : {size_t{0}, size_t{1}, size_t{2}, size_t{5}, size_t{8}, size_t{17}, size_t{64}}) {
                for (bool nt : {true, false}) {
                    memory.fill(0);
                    uint64_t* dst = memory.data() + offset;
                    simd::generate_pattern_beat(dst, count, pattern, start, nt);
                    bool exact = true;
                    for (size_t k = 0; k < count; ++k) exact &= dst[k] == simd::beat_value(pattern, start + k);
                    exact &= memory[offset + count] == 0;
                    std::vector<std::pair<uint64_t, uint64_t>> errors;
                    const size_t clean = simd::verify_pattern_beat(dst, count, pattern, start, errors);
                    expect(exact && clean == 0 && errors.empty(),
                           "Beat generator matches beat_value (start=" + std::to_string(start) + " offset=" +
                               std::to_string(offset) + " count=" + std::to_string(count) + ")");
                    for (size_t bad = 0; bad < count; bad += 3) {
                        dst[bad] ^= uint64_t{1} << (bad % 64);
                        errors.clear();
                        const size_t found = simd::verify_pattern_beat(dst, count, pattern, start, errors);
                        expect(found == 1 && errors.size() == 1 && errors[0].first == bad &&
                                   errors[0].second == (simd::beat_value(pattern, start + bad) ^ (uint64_t{1} << (bad % 64))),
                               "Beat verifier reports the flipped word and its observed value");
                        dst[bad] ^= uint64_t{1} << (bad % 64);
                    }
                }
            }
        }
    }
    // Every 16-byte unit: odd word is the complement of the even word (64-bit
    // beats), and each word's 32-bit halves are complements (DDR5 beats).
    bool beats = true;
    bool halves = true;
    for (uint64_t g = 0; g < 4096; g += 2) {
        const uint64_t even = simd::beat_value(pattern, g);
        const uint64_t odd = simd::beat_value(pattern, g + 1);
        beats &= odd == ~even;
        halves &= static_cast<uint32_t>(even) == static_cast<uint32_t>(~(even >> 32)) &&
                  static_cast<uint32_t>(odd) == static_cast<uint32_t>(~(odd >> 32));
    }
    expect(beats && halves, "Beat pattern keeps 64-bit beat and 32-bit half complements under its address tag");
    std::set<uint64_t> tags;
    for (uint64_t g = 0; g < 8192; g += 2) tags.insert(simd::beat_value(pattern, g));
    expect(tags.size() == 4096, "Every 16-byte unit of a beat pattern holds a distinct value");

    // beat_mirrored describes the data after the 16-byte units are reversed.
    const uint64_t g0 = 0x2000;
    const size_t words = 38;
    simd::generate_pattern_beat(memory.data(), words, pattern, g0, false);
    for (size_t q = 0; q < words / 4; ++q) {
        std::swap(memory[2 * q], memory[words - 2 - 2 * q]);
        std::swap(memory[2 * q + 1], memory[words - 1 - 2 * q]);
    }
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    expect(simd::verify_pattern_beat(memory.data(), words, simd::beat_mirrored(pattern, g0, words / 2), g0, errors) == 0,
           "beat_mirrored predicts reversed 16-byte units");
}

void testSimpleTestBeatMode() {
    alignas(64) std::array<uint64_t, 1024> memory{};
    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(memory.data());
    region.size = memory.size() * sizeof(uint64_t);
    region.base_offset_bytes = 0x40000;
    TestConfig tc;
    tc.function = "SimpleTest";
    tc.pattern_mode = kPatternModeBeat;
    tc.pattern_param0 = 0x55555555AAAAAAAAULL;
    tc.pattern_param1 = 0x9E3779B97F4A7C15ULL;
    tc.parameter = 2;
    TestContext ctx;
    const auto result = TestEngine::runSimpleTest(ctx, region, tc, false);
    const auto last = simpleBeatPattern(tc, 1);
    bool stored = true;
    for (size_t k = 0; k < memory.size(); ++k) stored &= memory[k] == simd::beat_value(last, 0x40000 / 8 + k);
    expect(result.total_errors() == 0 && result.bytes_tested == region.size * 2 && stored,
           "SimpleTest Pattern Mode 3 writes and verifies the beat pattern");
    expect(memory[1] == ~memory[0] && memory[3] == ~memory[2], "SimpleTest Pattern Mode 3 complements every second beat");
    tc.variation = 5;
    const auto varied = simpleBeatPattern(tc, 0);
    expect(varied.even == tc.pattern_param0 && varied.salt != last.salt,
           "Beat passes vary the address tag, not Param0");

    TestContext faulty;
    bool injected = false;
    faulty.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (!injected && std::string(phase) == "Simple filled") {
            reinterpret_cast<uint64_t*>(part.base)[777] ^= 0x10;
            injected = true;
        }
    };
    const auto failed = TestEngine::runSimpleTest(faulty, region, tc, true);
    expect(injected && failed.total_errors() == 1 && faulty.shouldStop(), "SimpleTest Pattern Mode 3 detects a flipped bit");

    const auto path = uniqueTempPath("_beat.cfg");
    for (const auto& [mode, valid] : {std::pair<int, bool>{3, true}, std::pair<int, bool>{4, false}}) {
        {
            std::ofstream file(path);
            file << "Test Sequence=0\n[Test0]\nFunction=SimpleTest\nPattern Mode=" << mode << "\n";
        }
        expect(loadPreset(path).valid == valid, "Preset Pattern Mode " + std::to_string(mode) + " validity");
    }
    cleanupFile(path);
}

void testMirrorKernels() {
    alignas(64) std::array<uint64_t, 1100> memory{};
    for (size_t offset : {size_t{0}, size_t{1}}) {
        for (size_t count : {0, 1, 2, 3, 7, 8, 9, 15, 16, 24, 64, 72, 1024}) {
            for (bool pairs : {false, true}) {
                uint64_t* data = memory.data() + offset;
                std::vector<uint64_t> expected(count);
                for (size_t k = 0; k < count; ++k) data[k] = expected[k] = 0x1000 + k;
                memory[offset + count] = 0xFEED;
                if (pairs) {
                    const size_t units = count / 2;
                    for (size_t u = 0; u < units / 2; ++u) {
                        std::swap(expected[2 * u], expected[2 * (units - 1 - u)]);
                        std::swap(expected[2 * u + 1], expected[2 * (units - 1 - u) + 1]);
                    }
                    simd::mirror_reverse_pairs(data, count);
                } else {
                    std::reverse(expected.begin(), expected.end());
                    simd::mirror_reverse_words(data, count);
                }
                const bool moved = std::equal(expected.begin(), expected.end(), data) && memory[offset + count] == 0xFEED;
                if (pairs) simd::mirror_reverse_pairs(data, count);
                else simd::mirror_reverse_words(data, count);
                bool restored = true;
                for (size_t k = 0; k < count; ++k) restored &= data[k] == 0x1000 + k;
                expect(moved && restored, std::string("Mirror ") + (pairs ? "pairs" : "words") + " count=" +
                                              std::to_string(count) + " offset=" + std::to_string(offset) +
                                              " reverses exactly and twice restores");
            }
        }
    }
}

void testMirrorMovesData() {
    alignas(64) std::array<uint64_t, 2048> memory{};
    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(memory.data());
    region.size = memory.size() * sizeof(uint64_t);
    region.base_offset_bytes = 0x80000;
    const uint64_t g0 = region.base_offset_bytes / 8;
    const size_t count = memory.size();
    TestConfig tc;
    tc.pattern_param0 = 0x5555555555555555ULL;
    tc.pattern_param1 = 0xAAAAAAAAAAAAAAAAULL;
    tc.parameter = 1;
    {
        TestContext ctx;
        tc.function = "MirrorMove";
        const auto result = TestEngine::runMirrorMove(ctx, region, tc, false);
        // One pass leaves the chunk reversed: word 0 holds the former last word.
        expect(result.total_errors() == 0 && result.bytes_tested == region.size * 2 &&
                   memory[0] == tc.pattern_param0 + (g0 + count - 1) * tc.pattern_param1 &&
                   memory[count - 1] == tc.pattern_param0 + g0 * tc.pattern_param1,
               "MirrorMove swaps words between the two ends of the chunk");
        tc.parameter = 2;
        const auto twice = TestEngine::runMirrorMove(ctx, region, tc, false);
        expect(twice.total_errors() == 0 && twice.bytes_tested == region.size * 3 &&
                   memory[0] == tc.pattern_param0 + g0 * tc.pattern_param1,
               "Two MirrorMove passes restore the original order and verify after each move");
        tc.parameter = 1;
    }
    {
        TestContext ctx;
        const auto result = TestEngine::runMirrorMove128(ctx, region, tc, false);
        const simd::BeatPattern original{tc.pattern_param0, tc.pattern_param1, 0, 0xD1B54A32D192ED03ULL};
        expect(result.total_errors() == 0 && memory[0] == simd::beat_value(original, g0 + count - 2) &&
                   memory[1] == simd::beat_value(original, g0 + count - 1) && memory[1] == ~memory[0],
               "MirrorMove128 swaps 16-byte units between the two ends and keeps each unit's beat complement");
    }
    // A word corrupted before a move is carried to the mirrored position.
    for (const char* phase : {"Mirror move", "Mirror128 move"}) {
        TestContext ctx;
        bool injected = false;
        ctx.phase_hook = [&](const char* name, const MemoryRegion&) {
            if (!injected && std::string(name) == phase) {
                memory[0] ^= 4;
                injected = true;
            }
        };
        const bool words = std::string(phase) == "Mirror move";
        const auto result = words ? TestEngine::runMirrorMove(ctx, region, tc, true)
                                  : TestEngine::runMirrorMove128(ctx, region, tc, true);
        const uint64_t landed = words ? memory[count - 1] : memory[count - 2];
        const uint64_t clean = words ? tc.pattern_param0 + g0 * tc.pattern_param1
                                     : simd::beat_value(simd::BeatPattern{tc.pattern_param0, tc.pattern_param1, 0,
                                                                          0xD1B54A32D192ED03ULL}, g0);
        expect(injected && result.total_errors() == 1 && ctx.shouldStop() && landed == (clean ^ 4),
               std::string("Fault before a move travels with the data: ") + phase);
    }
}
