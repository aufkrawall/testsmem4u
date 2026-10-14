#pragma once

// Word numbers become 64-bit pattern values in every address-dependent test.
// A size_t result would truncate complements and wide arithmetic on 32-bit
// targets for all callers, not only RandomAccess.
static_assert(std::is_same_v<decltype(globalWordStart(std::declval<const MemoryRegion&>())), uint64_t>,
              "globalWordStart must return a 64-bit word number on every target");

// The inverted phase must flip all 64 bits of each selected word on every
// target. On 32-bit builds a size_t complement once left the upper half zero,
// which only a direct memory check catches: expected and stored values agreed.
void testRandomAccessInvertsFullWords() {
    alignas(64) std::array<uint64_t, 17> memory{};
    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(memory.data());
    region.size = memory.size() * sizeof(uint64_t);
    region.base_offset_bytes = 0x10000;
    const uint64_t word_start = region.base_offset_bytes / sizeof(uint64_t);
    // With 17 words the first fifteen lanes own one word each, so lane k reads
    // word k. The first batch's phase-1 loads are observations 16..31.
    size_t observations = 0;
    size_t checked = 0;
    bool full_width = true;
    TestContext ctx;
    ctx.phase_hook = [&](const char* name, const MemoryRegion&) {
        if (std::string(name) != "Random observed") return;
        const size_t observation = observations++;
        if (observation < 16 || observation >= 16 + 15) return;
        const size_t word = observation - 16;
        full_width &= memory[word] == ~(word_start + word);
        ++checked;
    };
    TestConfig tc;
    tc.parameter = 101;
    const auto result = TestEngine::runRandomAccess(ctx, region, tc, false);
    expect(checked == 15 && full_width && result.total_errors() == 0,
           "RandomAccess inverted phase flips all 64 bits of each selected word");
}
