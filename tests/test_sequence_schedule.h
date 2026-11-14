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
