#pragma once

void testRandomAccessContracts() {
    alignas(64) std::array<uint64_t, 1088> memory{};
    constexpr uint64_t sentinel = 0xA53C96E17BD0428FULL;
    // Exercise carries across 32-bit word indices without allocating tens of GiB.
    // The offset is synthetic; it is never a physical or process address.
    const std::array<size_t, 3> offsets{
        0, size_t{0x10000}, std::numeric_limits<size_t>::max() > UINT32_MAX
            ? static_cast<size_t>(uint64_t{0x100000000} * 8 - 64) : size_t{0x80000000}};
    for (size_t offset : offsets) {
        for (size_t count : {0U, 1U, 2U, 7U, 15U, 16U, 17U, 31U, 32U, 33U, 511U, 513U, 1027U}) {
            for (uint32_t parameter : {0U, 1U, 3U, 100U, 101U, 113U}) {
                memory.fill(sentinel);
                MemoryRegion region{};
                // Keep NT-store alignment while guarding both ends of the region.
                region.base = reinterpret_cast<uint8_t*>(memory.data() + 8);
                region.size = count * sizeof(uint64_t);
                region.base_offset_bytes = offset;
                TestContext ctx;
                TestConfig tc;
                tc.parameter = parameter;
                const auto result = TestEngine::runRandomAccess(ctx, region, tc, false);
                const uint64_t accesses = parameter > 100 ? parameter : uint64_t{count} * std::max(1U, parameter);
                expect(result.total_errors() == 0 && !ctx.shouldStop(),
                       "RandomAccess clean phases never invent errors at offset/size/parameter boundaries");
                expect(result.bytes_tested == (count ? 2 * region.size + 3 * accesses * sizeof(uint64_t) : 0),
                       "RandomAccess checks exactly two sweeps and three reads per selected word");
                bool restored = true;
                for (size_t i = 0; i < memory.size(); ++i) {
                    const uint64_t expected = i >= 8 && i - 8 < count ? uint64_t{offset / 8} + i - 8 : sentinel;
                    restored &= memory[i] == expected;
                }
                expect(restored, "RandomAccess restores every word and preserves boundary sentinels");
            }
        }
    }

    // With 17 words, the first fifteen bands contain one word each. Lane 0's
    // post-load hook can therefore corrupt lane 1 before its load, at any phase.
    // Repairing in lane 1's post-load hook models a transient observation exactly,
    // without races, sleeps, or a second implementation of the random generator.
    for (size_t phase = 0; phase < 3; ++phase) {
        for (bool transient : {false, true}) {
            for (bool halt : {false, true}) {
                MemoryRegion region{};
                region.base = reinterpret_cast<uint8_t*>(memory.data());
                region.size = 17 * sizeof(uint64_t);
                region.base_offset_bytes = 0x10000;
                size_t observations = 0;
                bool injected = false;
                bool repaired = false;
                TestContext ctx;
                ctx.phase_hook = [&](const char* name, const MemoryRegion&) {
                    if (std::string(name) != "Random observed") return;
                    const size_t observation = observations++;
                    if (observation == phase * 16) {
                        memory[1] ^= 0x74;
                        injected = true;
                    } else if (transient && observation == phase * 16 + 1) {
                        memory[1] ^= 0x74;
                        repaired = true;
                    }
                };
                TestConfig tc;
                tc.parameter = 101;
                const auto result = TestEngine::runRandomAccess(ctx, region, tc, halt);
                // Persistent restored-phase damage is also seen at the next
                // original read, then repaired by the next inversion/restore.
                const uint64_t expected_errors = !transient && !halt && phase == 2 ? 2 : 1;
                expect(injected && repaired == transient && result.total_errors() == expected_errors &&
                       result.soft_errors == (transient ? 1U : 0U) &&
                       result.hard_errors == (transient ? 0U : expected_errors) &&
                       result.unverified_errors == 0 && ctx.shouldStop() == halt,
                       "RandomAccess classifies first observations in original/inverted/restored phases exactly");
                if (!halt) {
                    bool restored = true;
                    for (size_t i = 0; i < 17; ++i) restored &= memory[i] == region.base_offset_bytes / 8 + i;
                    expect(restored, "RandomAccess continues and restores the region after a reported error");
                }
            }
        }
    }
}
