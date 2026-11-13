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
