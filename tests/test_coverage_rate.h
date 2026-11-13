#pragma once
// Coverage-per-hour contracts: every logical CPU gets an equal share of the
// window, and repeated passes do not waste time re-testing identical data.

void testCpuTopologyPairsSmtSiblings() {
    // Each SMT sibling must name the core it shares with a primary thread. The
    // Windows fallback numbers cores by logical CPU and so cannot pair them.
    const PlatformInfo info = Platform::detectPlatform();
    const auto targets = Platform::getPreferredCpuTargets(0);
    for (const auto& sibling : targets) {
        if (!sibling.smt_secondary) continue;
        bool paired = false;
        for (const auto& primary : targets) {
            paired |= !primary.smt_secondary && primary.group == sibling.group &&
                      primary.core_index == sibling.core_index;
        }
        expect(paired, "SMT sibling shares its core index with a primary thread");
    }
#ifdef _WIN32
    // Ordinary CPU sets report Allocated=0 (it means reserved for exclusive
    // use); filtering on it once discarded every CPU and forced the fallback.
    expect(std::string(info.cpu_topology_source) == "cpu-sets", "Windows CPU topology comes from CPU sets");
#else
    expect(std::string(info.cpu_topology_source) == "sysfs", "Linux CPU topology comes from sysfs");
#endif
}

void testRegionSchedulerContracts() {
    using Snapshot = RegionScheduler::Snapshot;
    RegionScheduler scheduler(3, 2);
    const auto first = scheduler.claim(0);
    const auto second = scheduler.claim(1);
    expect(first.chunk == 0 && second.chunk == 1 && first.position == 0, "Initial claims take distinct chunks");
    scheduler.complete(0, first.chunk, 1);
    const auto third = scheduler.claim(0);
    expect(third.chunk == 2 && third.position == 0,
           "A free worker takes the least advanced idle chunk, not the one it just finished");
    scheduler.complete(0, third.chunk, 1);
    // Chunks 0 and 2 are idle at position 1; chunk 0 has waited longer.
    const auto fourth = scheduler.claim(0);
    expect(fourth.chunk == 0 && fourth.position == 1, "Ties go to the chunk idle the longest");
    {
        ChunkLease lease(scheduler, 0, fourth.chunk);
    }
    Snapshot snapshot;
    scheduler.snapshot(snapshot);
    expect(snapshot.positions == std::vector<uint64_t>{1, 0, 1} && snapshot.holder[0] == RegionScheduler::kNone &&
           snapshot.holder[1] == 1 && snapshot.serving[0] == RegionScheduler::kNone && snapshot.serving[1] == 1,
           "An abandoned lease returns its chunk without publishing progress");
    expect(scheduler.minimum() == 0, "Completed coverage is the least advanced chunk, including held ones");

    RegionScheduler single(1, 2);
    expect(single.claim(0).chunk == 0 && single.claim(1).chunk == RegionScheduler::kNone,
           "Claims never hand one chunk to two workers");

    // A worker stuck on one chunk cannot make the others drift apart: the free
    // worker alternates between the remaining chunks, least advanced first.
    RegionScheduler balanced(3, 2);
    const auto held = balanced.claim(1);
    uint64_t spread = 0;
    for (int step = 0; step < 12; ++step) {
        const auto claim = balanced.claim(0);
        balanced.complete(0, claim.chunk, claim.position + 1);
        balanced.snapshot(snapshot);
        uint64_t low = UINT64_MAX, high = 0;
        for (size_t chunk = 0; chunk < snapshot.positions.size(); ++chunk) {
            if (chunk == held.chunk) continue;
            low = std::min(low, snapshot.positions[chunk]);
            high = std::max(high, snapshot.positions[chunk]);
        }
        spread = std::max(spread, high - low);
    }
    expect(spread <= 1, "Free chunks stay within one test of each other");
}

namespace coverage_rate {

// Runs one kernel on a fresh page-aligned buffer; returns the final memory image.
std::vector<uint64_t> kernelImage(TestConfig tc, uint64_t variation, size_t offset_bytes, TestResult& result) {
    constexpr size_t words = 2048;
    auto guard = Platform::allocateMemoryRAII(words * sizeof(uint64_t), false, false, true);
    if (!guard.valid()) return {};
    MemoryRegion region{};
    region.base = guard.base();
    region.size = words * sizeof(uint64_t);
    region.base_offset_bytes = offset_bytes;
    TestContext ctx;
    auto time = std::chrono::steady_clock::time_point{};
    ctx.retention_clock = [&]() { time += std::chrono::milliseconds(1); return time; };
    tc.variation = variation;
    result = TestEngine::runTest(ctx, tc.function, region, tc, false);
    const auto* memory = reinterpret_cast<const uint64_t*>(region.base);
    return {memory, memory + words};
}

TestConfig kernel(const char* function, uint8_t mode, uint64_t p0, uint64_t p1, uint32_t parameter) {
    TestConfig tc;
    tc.function = function;
    tc.pattern_mode = mode;
    tc.pattern_param0 = p0;
    tc.pattern_param1 = p1;
    tc.parameter = parameter;
    return tc;
}

} // namespace coverage_rate

void testPassVariationChangesData() {
    using coverage_rate::kernel;
    using coverage_rate::kernelImage;
    expect(variationMask(0, 0) == 0 && variationMask(1, 0) != 0 && variationMask(0, 1) != 0 &&
           variationMask(1, 0) != variationMask(0, 1) && passVariation(0, 5, 0) == 0 &&
           passVariation(1, 5, 0) == 5 && passVariation(1, 5, 4) == 9,
           "Only the first repetition of the first pass keeps the configured data");
    const std::vector<TestConfig> varied{
        kernel("SimpleTest", 1, 0xDEADBEEFCAFEBABEULL, 0x7654321089ABCDEFULL, 0),
        kernel("SimpleTest", 2, 0x12345678, 0x9ABCDEF0, 0),
        kernel("MirrorMove", 0, 0xF0F0F0F0F0F0F0F0ULL, 0x0F0F0F0F0F0F0F0FULL, 1),
        kernel("MirrorMove128", 0, 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL, 1),
        kernel("BlockMove", 0, 0xCCCC3333CCCC3333ULL, 0, 1),
        kernel("MovingInversion", 0, 0xAAAAAAAAAAAAAAAAULL, 0, 2),
        kernel("MovingInversionLFSR", 0, 0xACE1ACE2DEADBEEFULL, 0, 1),
        kernel("LFSRPattern", 0, 0xACE1ACE2DEADBEEFULL, 0, 0),
        kernel("Modulo20", 0, 0xAAAAAAAAAAAAAAAAULL, 0, 1),
        kernel("RefreshStable", 0, ~0ULL, 0, 4),
        kernel("RandomAccess", 0, 0, 0, 1),
    };
    for (const auto& tc : varied) {
        TestResult first, second, again;
        const auto pass0 = kernelImage(tc, 0, 0, first);
        const auto pass1 = kernelImage(tc, 1, 0, second);
        const auto repeat = kernelImage(tc, 1, 0, again);
        expect(!pass0.empty() && first.total_errors() == 0 && second.total_errors() == 0 &&
               again.total_errors() == 0 && first.bytes_tested == second.bytes_tested,
               tc.function + ": varied passes verify clean with unchanged coverage");
        expect(pass0 != pass1, tc.function + ": a later pass writes different data");
        expect(pass1 == repeat, tc.function + ": pass data is reproducible from the variation");
    }

    TestResult result;
    const auto configured = kernelImage(kernel("SimpleTest", 1, 0xDEADBEEFCAFEBABEULL, 0x7654321089ABCDEFULL, 0),
                                        0, 0, result);
    bool exact = !configured.empty();
    for (size_t i = 0; i < configured.size(); ++i) {
        exact &= configured[i] == (0xDEADBEEFCAFEBABEULL ^ (uint64_t{i} * 0x7654321089ABCDEFULL));
    }
    expect(exact, "Pass 0 writes exactly the configured address pattern");
    const auto uniform0 = kernelImage(kernel("SimpleTest", 0, 0xAAAAAAAAAAAAAAAAULL, 0, 0), 0, 0, result);
    const auto uniform1 = kernelImage(kernel("SimpleTest", 0, 0xAAAAAAAAAAAAAAAAULL, 0, 0), 7, 0, result);
    expect(uniform0 == uniform1, "Uniform SimpleTest values are explicit and never varied");
    const auto chunk0 = kernelImage(kernel("LFSRPattern", 0, 0xACE1ACE2DEADBEEFULL, 0, 0), 0, 0, result);
    const auto chunk1 = kernelImage(kernel("LFSRPattern", 0, 0xACE1ACE2DEADBEEFULL, 0, 0), 0, 1 << 20, result);
    expect(chunk0 != chunk1 && result.total_errors() == 0, "Each chunk holds its own pseudo-random stream");
    const auto random = kernelImage(kernel("RandomAccess", 0, 0, 0, 1), 0, 0, result);
    std::set<uint64_t> upper_halves;
    for (uint64_t word : random) upper_halves.insert(word >> 32);
    expect(result.total_errors() == 0 && upper_halves.size() == random.size(),
           "RandomAccess data varies in all 64 bits (upper halves were constant)");
}

void testScheduledPassesUseNewData() {
    // Every loop and cycle of a sequence entry must see new data; before pass
    // variation each repeated invocation rewrote identical bits.
    auto guard = Platform::allocateMemoryRAII(size_t{64} * 1024, false, false, true);
    expect(guard.valid(), "Scheduled variation allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cores = 1;
    config.cycles = 2;
    config.preset.time_percent = 100;
    TestConfig tc;
    tc.function = "LFSRPattern";
    tc.pattern_param0 = 0xACE1ACE2DEADBEEFULL;
    tc.time_percent = 2; // loops = 100% x 2% / 100 = 2
    std::set<uint64_t> first_words;
    size_t fills = 0;
    TestContext ctx;
    ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
        if (std::string(phase) != "LFSR filled") return;
        ++fills;
        first_words.insert(*reinterpret_cast<const uint64_t*>(part.base));
    };
    const auto result = TestEngine::executeSuite(config, region, {0}, {{0, tc}}, &ctx);
    expect(result.cycles_completed == 2 && result.total_errors() == 0 && fills == 4 && first_words.size() == 4,
           "Two loops in each of two cycles write four different pseudo-random streams");
}
