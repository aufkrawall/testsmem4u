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
    // Minimal containers and chroots may lack sysfs topology; detection then
    // legitimately reports affinity-only (every CPU its own core).
    const bool sibling_lists = !targets.empty() &&
        std::ifstream("/sys/devices/system/cpu/cpu" + std::to_string(targets.front().logical_index) +
                      "/topology/thread_siblings_list").good();
    expect(std::string(info.cpu_topology_source) == (sibling_lists ? "sysfs" : "affinity-only"),
           "Linux CPU topology comes from sysfs sibling lists when they are readable");
#endif
}

void testSmtRolesFollowUsableCpus() {
    // Roles depend on which CPUs this process may use, not on the hardware core:
    // with CPU 4 outside the affinity mask, CPU 5 is its core's only thread.
    auto cpu = [](uint16_t group, uint16_t logical, uint16_t core) {
        CpuTarget target;
        target.group = group;
        target.logical_index = logical;
        target.core_index = core;
        return target;
    };
    std::vector<CpuTarget> targets{cpu(0, 1, 0), cpu(0, 0, 0), cpu(0, 2, 2), cpu(0, 3, 2), cpu(0, 5, 4),
                                   cpu(1, 0, 0)};
    cpu_topology::assignSmtRoles(targets);
    auto role = [&](uint16_t group, uint16_t logical) {
        for (const auto& target : targets) {
            if (target.group == group && target.logical_index == logical) {
                return std::string(target.smt ? "smt-" : "solo-") + (target.smt_secondary ? "secondary" : "primary");
            }
        }
        return std::string("missing");
    };
    expect(role(0, 0) == "smt-primary" && role(0, 1) == "smt-secondary" && role(0, 2) == "smt-primary" &&
           role(0, 3) == "smt-secondary", "The lowest usable thread of a core is its primary");
    expect(role(0, 5) == "solo-primary", "A thread whose lower sibling is excluded is a primary, not an SMT sibling");
    expect(role(1, 0) == "solo-primary", "Equal core numbers in different groups are different cores");

    // One core type with SMT siblings and preferred-core scheduling classes (as
    // Windows reports for Ryzen) is still homogeneous.
    std::vector<CpuTarget> homogeneous{cpu(0, 0, 0), cpu(0, 1, 0), cpu(0, 2, 2), cpu(0, 3, 2)};
    for (size_t i = 0; i < homogeneous.size(); ++i) {
        homogeneous[i].scheduling_class = static_cast<uint8_t>(6 - i / 2);
    }
    cpu_topology::assignSmtRoles(homogeneous);
    std::vector<CpuTarget> hybrid{cpu(0, 0, 0), cpu(0, 2, 2)};
    hybrid[0].efficiency_class = 1;
    hybrid[0].raw_performance = 120;
    std::vector<CpuTarget> capacities{cpu(0, 0, 0), cpu(0, 1, 1)};
    capacities[0].raw_performance = 1024;
    capacities[1].raw_performance = 512;
    expect(!cpu_topology::heterogeneousCores(homogeneous) && cpu_topology::heterogeneousCores(hybrid) &&
               cpu_topology::heterogeneousCores(capacities) && !cpu_topology::heterogeneousCores({}),
           "Only different core types (efficiency class, capacity) make a CPU heterogeneous");

    uint32_t narrow = 0;
    uint64_t wide = 0;
    expect(cpu_topology::affinityBit(31, narrow) && narrow == 0x80000000U && !cpu_topology::affinityBit(32, narrow) &&
               cpu_topology::affinityBit(63, wide) && wide == (uint64_t{1} << 63) && !cpu_topology::affinityBit(64, wide),
           "Affinity bits beyond the mask width (32-bit builds) are rejected instead of shifted");
}

void testCpuSetReservationsSelectTargets() {
    // Windows CPU sets: reserved records are skipped while unreserved usable
    // CPUs exist. When the affinity mask allows only reserved CPUs, workers use
    // those with their CPU-set topology instead of a logical-processor fallback
    // that re-added them without core pairing and still counted them skipped.
    auto record = [](uint16_t logical, uint16_t core, bool reserved) {
        cpu_topology::CpuSetRecord result;
        result.target.logical_index = logical;
        result.target.core_index = core;
        result.target.efficiency_class = 1;
        result.reserved = reserved;
        return result;
    };
    const std::vector<cpu_topology::CpuSetRecord> records{record(0, 0, false), record(1, 0, false),
                                                          record(2, 2, true), record(3, 2, true)};
    auto only = [](uint32_t mask) {
        return [mask](uint16_t group, uint32_t logical) {
            return group == 0 && logical < 32 && ((mask >> logical) & 1U) != 0;
        };
    };
    auto logicals = [](const cpu_topology::CpuSetSelection& selection) {
        std::vector<uint32_t> result;
        result.reserve(selection.targets.size());
        for (const auto& target : selection.targets) result.push_back(target.logical_index);
        return result;
    };

    const auto mixed = cpu_topology::selectCpuSetTargets(records, only(0xF));
    expect(logicals(mixed) == std::vector<uint32_t>{0, 1} && mixed.reserved == 2 && !mixed.reserved_only &&
               mixed.affinity_excluded == 0,
           "Reserved CPU sets are skipped while unreserved usable CPUs exist");
    const auto reserved = cpu_topology::selectCpuSetTargets(records, only(0xC));
    expect(logicals(reserved) == std::vector<uint32_t>{2, 3} && reserved.reserved_only && reserved.reserved == 2 &&
               reserved.affinity_excluded == 2 && reserved.targets[0].core_index == 2 &&
               reserved.targets[0].efficiency_class == 1,
           "An affinity mask of only reserved CPUs keeps them, with their CPU-set topology");
    const auto none = cpu_topology::selectCpuSetTargets(records, only(0x30));
    expect(none.targets.empty() && !none.reserved_only && none.affinity_excluded == 2,
           "CPU sets with no usable CPU leave the choice to the logical-processor fallback");
    expect(cpu_topology::selectCpuSetTargets({}, only(0xF)).targets.empty(),
           "Missing CPU-set information yields no targets");
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
    // The abandoned chunk 0 is now worker 0's finished chunk: another idle chunk wins.
    const auto fifth = scheduler.claim(0);
    expect(fifth.chunk == 2, "A worker does not immediately re-claim the chunk it just returned");
    scheduler.abandon(0, fifth.chunk);
    Snapshot snapshot;
    scheduler.snapshot(snapshot);
    expect(snapshot.positions == std::vector<uint64_t>{1, 0, 1} && snapshot.holder[0] == RegionScheduler::kNone &&
           snapshot.holder[1] == 1 && snapshot.serving[0] == RegionScheduler::kNone && snapshot.serving[1] == 1,
           "An abandoned lease returns its chunk without publishing progress");
    expect(scheduler.minimum() == 0, "Completed coverage is the least advanced chunk, including held ones");

    RegionScheduler single(1, 2);
    expect(single.claim(0).chunk == 0 && single.claim(1).chunk == RegionScheduler::kNone,
           "Claims never hand one chunk to two workers");
    single.complete(0, 0, 1);
    expect(single.claim(0).chunk == 0, "A worker re-claims its own chunk when nothing else is idle");

    // Even when its own chunk is the least advanced, a worker leaves it to a peer.
    RegionScheduler lagging(3, 1);
    for (size_t chunk = 0; chunk < 3; ++chunk) {
        const auto claim = lagging.claim(0);
        lagging.complete(0, claim.chunk, claim.chunk == 2 ? 3 : 9);
    }
    expect(lagging.claim(0).chunk == 0, "The just-finished chunk is skipped even if it is the least advanced");

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

void testSlowWorkerCannotStarveAChunk() {
    // Discrete-event model of the real claim policy: one worker 2.5x slower than
    // its peers. Re-claiming the just-finished chunk let that worker keep its own
    // chunk, which then advanced at about half the average rate. No threads or time.
    for (size_t workers : {size_t{2}, size_t{4}, size_t{8}, size_t{16}}) {
        const size_t chunks = workers + 2;
        RegionScheduler scheduler(chunks, workers);
        using Event = std::pair<uint64_t, std::pair<size_t, size_t>>; // finish time, (worker, chunk)
        std::priority_queue<Event, std::vector<Event>, std::greater<Event>> events;
        auto duration = [](size_t worker) { return uint64_t{worker == 1 ? 5U : 2U}; };
        for (size_t worker = 0; worker < workers; ++worker) {
            events.push({duration(worker), {worker, scheduler.claim(worker).chunk}});
        }
        RegionScheduler::Snapshot snapshot;
        constexpr uint64_t items = 2000;
        for (uint64_t done = 0; done < items; ++done) {
            const auto [time, assignment] = events.top();
            events.pop();
            const auto [worker, chunk] = assignment;
            scheduler.snapshot(snapshot);
            scheduler.complete(worker, chunk, snapshot.positions[chunk] + 1);
            events.push({time + duration(worker), {worker, scheduler.claim(worker).chunk}});
        }
        scheduler.snapshot(snapshot);
        const uint64_t low = *std::min_element(snapshot.positions.begin(), snapshot.positions.end());
        const uint64_t high = *std::max_element(snapshot.positions.begin(), snapshot.positions.end());
        expect(low * chunks >= items * 95 / 100 && high - low <= 4,
               "A slow worker cannot leave any chunk behind the others (" + std::to_string(workers) + " workers)");
    }
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
        // Compare each half: RefreshStable's two halves are written by different
        // code (held fill vs active background test), and a whole-buffer check
        // missed an active half that never varied.
        const size_t half = pass0.size() / 2;
        const bool low_varies = !pass0.empty() && !std::equal(pass0.begin(), pass0.begin() + half, pass1.begin());
        const bool high_varies = !pass0.empty() && !std::equal(pass0.begin() + half, pass0.end(), pass1.begin() + half);
        expect(pass1.size() == pass0.size() && low_varies && high_varies,
               tc.function + ": a later pass writes different data in both halves of the region");
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

void testStreamingFillCacheContract() {
    // Post-fill flushes are skipped only where every streaming-fill word is a
    // non-temporal store that evicts cached lines (x86-64 with NT support).
#if defined(__x86_64__) || defined(_M_X64)
    expect(simd::streaming_fill_bypasses_cache() == simd::getCapabilities().has_nt_stores,
           "x86-64 skips post-fill flushes exactly when non-temporal fills are available");
#else
    expect(!simd::streaming_fill_bypasses_cache(), "Builds with cached scalar fills keep the post-fill flush");
#endif
    // Streaming tails are now non-temporal too; they must still write every word.
    alignas(64) std::array<uint64_t, 40> memory{};
    for (size_t count : {size_t{1}, size_t{2}, size_t{3}, size_t{5}, size_t{7}, size_t{9}, size_t{15}, size_t{17},
                         size_t{31}, size_t{33}}) {
        memory.fill(0x5A5A5A5A5A5A5A5AULL);
        simd::generate_pattern_uniform(memory.data(), count, 0x0123456789ABCDEFULL, true);
        simd::flush_after_streaming_fill(memory.data(), count * sizeof(uint64_t));
        bool exact = true;
        for (size_t i = 0; i < memory.size(); ++i) {
            exact &= memory[i] == (i < count ? 0x0123456789ABCDEFULL : 0x5A5A5A5A5A5A5A5AULL);
        }
        expect(exact, "Streaming uniform fills write every word including odd tails, and nothing beyond");
    }
}

void testLfsrWordsAreIndependent() {
    // Raw one-bit-step LFSR states made each word a shifted copy of the previous
    // one (bit j of word i+1 == bit j+1 of word i, except four feedback taps).
    // An unkeyed mix64(state) still produced ~27 exact shifted copies here.
    alignas(64) std::array<uint64_t, 1024> words{};
    simd::fill_lfsr(words.data(), words.size(), 0xACE1ACE2DEADBEEFULL);
    constexpr uint64_t untapped = ~(0xD800000000000000ULL | (1ULL << 63) | (1ULL << 59));
    size_t shifted_copies = 0;
    uint64_t agreeing_bits = 0;
    for (size_t i = 0; i + 1 < words.size(); ++i) {
        const uint64_t predicted = words[i] >> 1;
        shifted_copies += ((words[i + 1] ^ predicted) & untapped) == 0;
        agreeing_bits += static_cast<uint64_t>(__builtin_popcountll(~(words[i + 1] ^ predicted) & untapped));
    }
    const double agreement = static_cast<double>(agreeing_bits) /
                             (static_cast<double>(words.size() - 1) * __builtin_popcountll(untapped));
    expect(shifted_copies == 0 && agreement > 0.48 && agreement < 0.52,
           "LFSR words are not shifted copies of their predecessors (bit agreement near 50%)");
}

void testSequenceTimingSummary() {
    using Clock = SequenceTimings::Clock;
    const Clock::time_point start{};
    auto at = [&](double seconds) {
        return start + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(seconds));
    };
    SequenceTimings timings(4, start);
    timings.record(0, at(0), at(3), uint64_t{1} << 30, true);
    timings.record(0, at(10), at(11), uint64_t{1} << 30, true);
    timings.record(1, at(2), at(8), 0, true);
    timings.record(1, at(9), at(11), uint64_t{1} << 29, false);
    std::map<uint32_t, TestConfig> configs;
    configs[5].function = "SimpleTest";
    configs[7].function = "RowHammer";
    configs[8].function = "Modulo20";
    configs[9].function = "BlockMove";
    configs[9].enabled = false;
    const auto lines = timings.summary({5, 7, 8, 9}, configs, 2, 3, size_t{64} << 20, 12.5);
    expect(lines.size() == 5 && lines[0].find("wall=12.5s workers=2 chunks=3 chunk-MiB=64.0 worker-seconds=12.0") !=
                                    std::string::npos,
           "Time breakdown header records wall time, layout and total worker time");
    expect(lines[1].find("#1  SimpleTest") != std::string::npos && lines[1].find("share= 33.3%") != std::string::npos &&
               lines[1].find("runs=2 avg=2.00s first=0.0s verified=2.00GiB") != std::string::npos,
           "Completed runs report share, average, first start and verified bytes");
    expect(lines[2].find("share= 66.7%") != std::string::npos && lines[2].find("first=2.0s") != std::string::npos &&
               lines[2].find("verified=0.50GiB") != std::string::npos &&
               lines[2].find("stopped=1/2.0s") != std::string::npos,
           "Stopped invocations count toward worker time and verified bytes and are reported separately");
    expect(lines[3].find("Modulo20") != std::string::npos && lines[3].find("not reached") != std::string::npos &&
               lines[4].find("BlockMove") != std::string::npos && lines[4].find("disabled") != std::string::npos,
           "Unreached and disabled entries are named, not omitted");
    const auto first = timings.cycleMilestones(2, at(90));
    expect(first.size() == 2 && first[0].find("Cycle 1 complete on every chunk after 90.0s") == 0 &&
               first[1].find("Cycle 2") == 0 && timings.cycleMilestones(2, at(95)).empty(),
           "Each whole-window cycle completion is logged exactly once");
}
