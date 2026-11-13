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
