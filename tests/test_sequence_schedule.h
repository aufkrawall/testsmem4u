#pragma once
// Interleaved sequences: repeated test IDs, staggered chunk starts and the
// per-function time breakdown.

void testSequenceOccurrencesNumberPasses() {
    // Sequence 7,3,7,9,7 with entry 3 (the 9) disabled: enabled slots 0,1,2,4.
    const std::vector<uint32_t> ids{7, 3, 7, 9, 7};
    const EnabledSequence sequence({0, 1, 2, 4}, ids, 1, false);
    expect(sequence.occurrences[0] == 3 && sequence.occurrences[1] == 1 && sequence.occurrences[3] == 3 &&
               sequence.occurrence[0] == 0 && sequence.occurrence[2] == 1 && sequence.occurrence[3] == 2,
           "Enabled slots count earlier and total occurrences of their test ID");
    // Chunk cycle 1 (positions 4..7): ID 7 runs passes 3, 4, 5; ID 3 keeps pass == cycle.
    expect(sequence.pass(0, 0) == 0 && sequence.pass(2, 0) == 1 && sequence.pass(3, 0) == 2 &&
               sequence.pass(4, 0) == 3 && sequence.pass(6, 0) == 4 && sequence.pass(7, 0) == 5 &&
               sequence.pass(1, 0) == 0 && sequence.pass(5, 0) == 1,
           "Each occurrence of a repeated ID gets its own data pass; single IDs keep pass == cycle");
    const EnabledSequence plain({0, 1});
    expect(plain.pass(3, 5) == 1 && plain.entry(3, 5) == 1 && plain.offset(5) == 0,
           "Without IDs every slot is a single occurrence and chunks are aligned");
}

void testRepeatedEntriesUseNewData() {
    // An interleaved preset lists one test several times per cycle. Before
    // occurrence-based passes, both occurrences in a cycle used variation
    // (cycle, loop) and rewrote identical data: 2 distinct streams, not 4.
    auto guard = Platform::allocateMemoryRAII(size_t{64} * 1024, false, false, true);
    expect(guard.valid(), "Repeated-entry allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 1;
    config.cycles = 2;
    config.preset.time_percent = 100;
    TestConfig lfsr;
    lfsr.function = "LFSRPattern";
    lfsr.pattern_param0 = 0xACE1ACE2DEADBEEFULL;
    lfsr.time_percent = 1;
    TestConfig simple;
    simple.function = "SimpleTest";
    simple.time_percent = 1;
    std::set<uint64_t> first_words;
    size_t fills = 0;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) != "LFSR filled") return;
        ++fills;
        first_words.insert(*reinterpret_cast<const uint64_t*>(part.base));
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1, 0}, {{0, lfsr}, {1, simple}}, &ctx);
    expect(result.cycles_completed == 2 && result.total_errors() == 0 && fills == 4 && first_words.size() == 4,
           "Two occurrences of one test in each of two cycles write four different streams");
}

void testFunctionTimingSummary() {
    using Clock = SequenceTimings::Clock;
    const Clock::time_point start{};
    auto at = [&](double seconds) {
        return start + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(seconds));
    };
    // Sequence 2,4,2,6,8: test 2 (MirrorMove128) twice, 8 disabled, 6 never ran.
    SequenceTimings timings(5, start);
    timings.record(0, at(5), at(8), uint64_t{1} << 30, true);
    timings.record(1, at(0), at(4), uint64_t{1} << 29, true);
    timings.record(2, at(1), at(2), uint64_t{1} << 30, false);
    std::map<uint32_t, TestConfig> configs;
    configs[2].function = "MirrorMove128";
    configs[4].function = "RandomAccess";
    configs[6].function = "Modulo20";
    configs[8].function = "RowHammer";
    configs[8].enabled = false;
    const auto lines = timings.functionSummary({2, 4, 2, 6, 8}, configs);
    expect(lines.size() == 4 && lines[0].find("Time by function") == 0, "One line per enabled function plus header");
    expect(lines[1].find("MirrorMove128") != std::string::npos && lines[1].find("share= 50.0%") != std::string::npos &&
               lines[1].find("entries=2 runs=1 stopped=1 first=1.0s verified=2.00GiB") != std::string::npos,
           "Repeated entries of a function add up, with the earliest start of any of them");
    expect(lines[2].find("RandomAccess") != std::string::npos && lines[2].find("share= 50.0%") != std::string::npos &&
               lines[3].find("Modulo20") != std::string::npos && lines[3].find("not reached") != std::string::npos,
           "Functions appear in sequence order; unreached ones are named and disabled ones omitted");
}

void testStaggeredSlotsCoverEveryEntry() {
    const std::vector<uint32_t> ids{0, 1, 0, 2};
    const EnabledSequence staggered({0, 1, 2, 3}, ids, 6, true);
    // Offsets c * 4 / 6 for six chunks.
    const std::vector<size_t> expected{0, 0, 1, 2, 2, 3};
    bool offsets = true;
    bool complete = true;
    std::set<std::pair<size_t, uint64_t>> passes; // (chunk, ID 0 pass) must be unique
    bool unique = true;
    for (size_t chunk = 0; chunk < 6; ++chunk) {
        offsets &= staggered.offset(chunk) == expected[chunk];
        for (uint64_t cycle = 0; cycle < 2; ++cycle) {
            std::set<size_t> slots;
            for (uint64_t step = 0; step < 4; ++step) {
                const uint64_t position = cycle * 4 + step;
                slots.insert(staggered.slot(position, chunk));
                if (ids[staggered.entry(position, chunk)] == 0) {
                    unique &= passes.insert({chunk, staggered.pass(position, chunk)}).second;
                }
            }
            complete &= slots.size() == 4;
        }
    }
    expect(offsets, "Staggered chunks start at evenly spread enabled slots");
    expect(complete && staggered.startsCycle(4) && staggered.cycle(7) == 1,
           "Every staggered chunk runs each enabled slot once per chunk cycle");
    // Six chunks x two cycles x two occurrences of ID 0.
    expect(unique && passes.size() == size_t{6} * 4, "Repeated IDs get distinct data passes whatever the starting slot");
}

namespace sequence_schedule {

// Kernel phase labels identify which test a chunk ran first.
std::map<uint8_t*, std::string> firstTestPerChunk(SequenceStart start) {
    std::map<uint8_t*, std::string> first;
    const size_t page = Platform::getNativePageSize();
    auto guard = Platform::allocateMemoryRAII(std::max(size_t{256} * 1024, 8 * page), false, false, true);
    expect(guard.valid(), "Sequence-start allocation");
    if (!guard.valid()) return first;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 2;
    config.cycles = 1;
    config.preset.time_percent = 100;
    config.sequence_start = start;
    std::map<uint32_t, TestConfig> configs;
    configs[0].function = "SimpleTest";
    configs[1].function = "WalkingOnes";
    configs[2].function = "LFSRPattern";
    for (auto& [id, tc] : configs) tc.time_percent = 1;
    std::mutex mutex;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        const std::string name(phase);
        const char* test = name == "Simple fill" ? "SimpleTest" : name == "Walking fill" ? "WalkingOnes"
                         : name == "LFSR filled" ? "LFSRPattern" : nullptr;
        if (!test) return;
        std::lock_guard<std::mutex> lock(mutex);
        first.emplace(part.base, test);
    };
    const auto result = TestEngine::executeSuite(config, region, {0, 1, 2}, configs, &ctx);
    expect(result.cycles_completed == 1 && result.total_errors() == 0 && !result.infrastructure_failure,
           "Sequence-start runs complete one clean cycle");
    return first;
}

} // namespace sequence_schedule

void testStaggeredStartRunsDifferentTests() {
    // Two workers get four chunks. Aligned: every chunk starts with test 0.
    // Staggered: chunk offsets 0, 0, 1, 2 start with all three tests.
    const auto platform = Platform::detectPlatform();
    if (platform.cpu_cores < 2 || Platform::getNativePageSize() == 0) return;
    std::set<std::string> aligned;
    for (const auto& [base, test] : sequence_schedule::firstTestPerChunk(SequenceStart::ALIGNED)) aligned.insert(test);
    std::set<std::string> staggered;
    size_t chunks = 0;
    for (const auto& [base, test] : sequence_schedule::firstTestPerChunk(SequenceStart::STAGGERED)) {
        staggered.insert(test);
        ++chunks;
    }
    expect(aligned == std::set<std::string>{"SimpleTest"}, "Aligned chunks all start with the first entry");
    expect(chunks == 4 && staggered.size() == 3, "Staggered chunks start with different entries");
    Config preset_config;
    preset_config.preset.staggered_start = true;
    Config override_config = preset_config;
    override_config.sequence_start = SequenceStart::ALIGNED;
    expect(staggeredSequenceStart(preset_config) && !staggeredSequenceStart(override_config),
           "The preset's Sequence Start applies unless --sequence-start overrides it");
}

void testStaggeredStartMessageNeedsChunks() {
    // --cores 1 gives one chunk, so staggering changes nothing; the startup line
    // used to claim workers run different tests at the same time anyway.
    const std::vector<uint32_t> ids{0, 1, 2};
    auto contains = [](const std::string& text, const char* part) { return text.find(part) != std::string::npos; };
    const std::string single = describeSequenceStart(EnabledSequence({0, 1, 2}, ids, 1, true), 3, "preset", false);
    const std::string one_entry = describeSequenceStart(EnabledSequence({1}, ids, 4, true), 3, "preset", false);
    const std::string spread =
        describeSequenceStart(EnabledSequence({0, 1, 2}, ids, 4, true), 3, "--sequence-start", true);
    const std::string aligned = describeSequenceStart(EnabledSequence({0, 1, 2}, ids, 4, false), 3, "preset", true);
    expect(contains(single, "no effect with a single memory chunk") && !contains(single, "different tests"),
           "Staggering one chunk is reported as having no effect");
    expect(contains(one_entry, "no effect with one enabled entry"),
           "Staggering a single enabled entry is reported as having no effect");
    expect(contains(spread, "(--sequence-start)") && contains(spread, "last chunk at entry 3 of 3") &&
               contains(spread, "different tests") && contains(spread, "cross-chunk disturbance"),
           "Effective staggering names its source, the last chunk's entry and RowHammer overlap");
    expect(contains(aligned, "aligned") && !contains(aligned, "RowHammer"), "Aligned start has its own line");
}

void testRowHammerPointsFollowDensity() {
    constexpr size_t mib = size_t{1} << 20;
    // Parameter 0 keeps the long-standing default of 2 points per MiB.
    expect(rowHammerPoints(100 * mib, 0, 4) == 200 && rowHammerPoints(1593 * mib, 0, 4) == 3186,
           "Default RowHammer density stays 2 points per MiB");
    // Parameter is points per GiB, so the budget follows the region size: the old
    // absolute count gave a 3.6 MiB chunk of a 64 MB window the same 250 points
    // (about 90 s) as a 1.6 GiB chunk.
    expect(rowHammerPoints(1593 * mib, 160, 4) == 249 && rowHammerPoints(3 * mib, 160, 4) == 4 &&
               rowHammerPoints(1024 * mib, 1000, 4) == 1000,
           "Explicit RowHammer Parameter is a density in points per GiB");
    expect(rowHammerPoints(size_t{512} * 1024, 2048, 3) == 3 && rowHammerPoints(0, 0, 0) == 1,
           "At least one point per usable stride (and never zero)");
    expect(rowHammerPoints(SIZE_MAX / 2, 0xFFFFFFFFU, 4) == kRowHammerMaxPoints &&
               rowHammerPoints(SIZE_MAX, 0xFFFFFFFFU, 4) == kRowHammerMaxPoints,
           "Huge regions and densities are capped without overflow");
    // Exact byte scaling: whole-MiB truncation gave a 512 KiB sub-block tail the
    // per-stride floor (4) instead of 24 points and a 3.6 MiB chunk 29 instead of 35.
    expect(rowHammerPoints(size_t{512} * 1024, 50000, 4) == 24 &&
               rowHammerPoints(3 * mib + size_t{600} * 1024, 10000, 4) == 35,
           "RowHammer points scale with exact bytes, not whole MiB");
}

void testRowHammerBudgetLogPerEntry() {
    // Each RowHammer entry (test number, density, block size) logs its budget
    // once per run; a single run-wide flag hid every entry after the first.
    resetRowHammerBudgetLog();
    TestConfig first;
    first.function = "RowHammer";
    first.test_number = 12;
    first.parameter = 160;
    TestConfig second = first;
    second.test_number = 19;
    second.parameter = 4096;
    second.block_size_mb = 64;
    expect(claimRowHammerBudgetLog(first) && !claimRowHammerBudgetLog(first) && claimRowHammerBudgetLog(second) &&
               !claimRowHammerBudgetLog(second),
           "Every distinct RowHammer entry logs its point budget exactly once");
    for (uint32_t i = 0; i < 2 * kRowHammerBudgetLogLimit; ++i) {
        TestConfig other = first;
        other.parameter = 1000 + i;
        claimRowHammerBudgetLog(other);
    }
    TestConfig late = first;
    late.parameter = 99999;
    expect(!claimRowHammerBudgetLog(late), "RowHammer budget lines are capped per run");
    resetRowHammerBudgetLog();
    expect(claimRowHammerBudgetLog(first), "A new run logs the budget again");
    resetRowHammerBudgetLog();
}

void testLoopEstimateCountsOnlyRepetitions() {
    // RefreshStable's Parameter is a dwell in ms and RowHammer's a density, so
    // the shipped interleaved preset (three 10000 ms RefreshStable entries per
    // cycle) used to warn about an excessive run from 4 cycles on.
    PresetInfo preset = loadPreset("default.cfg");
    expect(preset.valid, "The shipped default.cfg loads (tests run from the project root)");
    Config config;
    config.preset = preset;
    config.cycles = 10;
    const std::vector<uint32_t> seq = parseTestSequence(preset.test_sequence);
    expect(estimatedTotalLoops(config, seq, preset.test_configs) < kMaxRecommendedLoops,
           "Ten cycles of the default preset stay below the excessive-run warning");

    auto entry = [](const char* function, uint32_t parameter) {
        TestConfig test;
        test.function = function;
        test.parameter = parameter;
        return test;
    };
    expect(estimatedRepetitions(entry("RefreshStable", 10000)) == 1 &&
               estimatedRepetitions(entry("RowHammer", 160)) == 1 &&
               estimatedRepetitions(entry("RandomAccess", 1000000)) == 1 &&
               estimatedRepetitions(entry("WalkingOnes", 50)) == 1 &&
               estimatedRepetitions(entry("LFSRPattern", 50)) == 1,
           "Dwell, density, access-count and ignored Parameters are not repetitions");
    expect(estimatedRepetitions(entry("SimpleTest", 32)) == 32 && estimatedRepetitions(entry("SimpleTest", 0)) == 1 &&
               estimatedRepetitions(entry("MirrorMove128", 40)) == 40 &&
               estimatedRepetitions(entry("RandomAccess", 2)) == 2 &&
               estimatedRepetitions(entry("Modulo20", 0)) == 3,
           "Repetition Parameters (and Modulo20's default of 3) still count");

    std::map<uint32_t, TestConfig> heavy{{0, entry("SimpleTest", 60000)}};
    heavy[0].time_percent = 100;
    Config long_run;
    long_run.cycles = 2;
    expect(estimatedTotalLoops(long_run, {0}, heavy) == 120000 &&
               estimatedTotalLoops(long_run, {0}, heavy) > kMaxRecommendedLoops,
           "Genuinely long repetition counts still exceed the warning threshold");
}
