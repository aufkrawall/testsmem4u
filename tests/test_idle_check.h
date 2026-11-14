#pragma once

// Idle-chunk check: tests describe the data they leave behind, and the next
// test on the chunk re-verifies it first.

void testResidualDescriptionsMatchMemory() {
    alignas(64) std::array<uint64_t, 4096> memory{};
    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(memory.data());
    region.size = memory.size() * sizeof(uint64_t);
    region.base_offset_bytes = 0x100000;
    TestConfig tc;
    tc.pattern_param0 = 0x55555555AAAAAAAAULL;
    tc.pattern_param1 = 0x9E3779B97F4A7C15ULL;
    tc.parameter = 1;
    tc.variation = 3;
    using Kind = ResidualPattern::Kind;
    auto check = [&](const std::string& name, TestResult result, Kind kind) {
        TestContext ctx;
        const bool described = result.residual.kind == kind && result.residual.offset == region.base_offset_bytes &&
                               result.residual.bytes == region.size;
        const auto clean = verifyResidual(ctx, region, result.residual, "check", false);
        memory[1234] ^= 0x100;
        const auto dirty = verifyResidual(ctx, region, result.residual, "check", false);
        memory[1234] ^= 0x100;
        expect(described && clean.total_errors() == 0 && clean.bytes_tested == region.size &&
                   dirty.total_errors() == 1,
               name + ": leftover data description matches memory and catches a flipped bit");
    };
    for (uint8_t mode : {uint8_t{0}, uint8_t{1}, uint8_t{2}, kPatternModeBeat}) {
        tc.pattern_mode = mode;
        TestContext ctx;
        const Kind kind = mode == 0 ? Kind::UNIFORM : mode == 1 ? Kind::XOR : mode == 2 ? Kind::LINEAR : Kind::BEAT;
        check("SimpleTest mode " + std::to_string(mode), TestEngine::runSimpleTest(ctx, region, tc, false), kind);
    }
    for (uint32_t passes : {1U, 2U}) {
        tc.parameter = passes;
        TestContext a;
        check("MirrorMove x" + std::to_string(passes), TestEngine::runMirrorMove(a, region, tc, false), Kind::LINEAR);
        TestContext b;
        check("MirrorMove128 x" + std::to_string(passes), TestEngine::runMirrorMove128(b, region, tc, false), Kind::BEAT);
    }
    tc.parameter = 1;
    {
        TestContext ctx;
        check("RandomAccess", TestEngine::runRandomAccess(ctx, region, tc, false), Kind::LINEAR);
        TestContext walking;
        expect(!TestEngine::runWalkingOnes(walking, region, tc, false).residual.valid(),
               "Tests without a described final state leave no idle-check data");
    }
    // Sub-blocks: global-address data describes the whole region, block-relative
    // mirror data does not.
    MemoryRegion big{};
    auto guard = Platform::allocateMemoryRAII(size_t{2} * 1024 * 1024, false, false, true);
    expect(guard.valid(), "Idle-check block allocation");
    if (!guard.valid()) return;
    big.base = guard.base();
    big.size = guard.size();
    tc.block_size_mb = 1;
    tc.function = "SimpleTest";
    tc.pattern_mode = 1;
    TestContext ctx;
    const auto blocks = TestEngine::runRegionWork(ctx, big, tc, false);
    expect(blocks.residual.valid() && blocks.residual.bytes == big.size &&
               verifyResidual(ctx, big, blocks.residual, "check", false).total_errors() == 0,
           "Block-wise SimpleTest leaves data described for the whole chunk");
    tc.function = "MirrorMove";
    expect(!TestEngine::runRegionWork(ctx, big, tc, false).residual.valid(),
           "Block-wise mirror moves leave no whole-chunk description");
    TestContext stopped;
    stopped.phase_hook = [&](const char* phase, const MemoryRegion&) {
        if (std::string(phase) == "Simple verify") stopped.requestStop();
    };
    tc.function = "SimpleTest";
    expect(!TestEngine::runRegionWork(stopped, big, tc, false).residual.valid(),
           "A cancelled test leaves no idle-check data");
}

void testIdleChunkCheckInSuite() {
    auto guard = Platform::allocateMemoryRAII(size_t{1024} * 1024, false, false, true);
    expect(guard.valid(), "Idle-check suite allocation");
    if (!guard.valid()) return;
    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    Config config;
    config.cycles = 2;
    config.preset.time_percent = 100;
    std::map<uint32_t, TestConfig> configs;
    for (uint32_t id : {0U, 1U}) {
        configs[id].function = "SimpleTest";
        configs[id].pattern_mode = static_cast<uint8_t>(id + 1);
        configs[id].pattern_param0 = 0x0123456789ABCDEFULL;
        configs[id].pattern_param1 = 0x9E3779B97F4A7C15ULL;
        configs[id].time_percent = 1;
        configs[id].parameter = 1;
    }
    for (uint32_t cores : {2U, 1U}) {
        config.cores = cores;
        TestContext ctx;
        std::atomic<unsigned> checks{0};
        std::atomic<bool> injected{false};
        ctx.phase_hook = [&](const char* phase, const MemoryRegion& part) {
            if (std::string(phase) != "Idle check") return;
            ++checks;
            // Corrupt one word while the chunk is idle (before the re-read).
            if (!injected.exchange(true)) reinterpret_cast<uint64_t*>(part.base)[17] ^= 0x8000;
        };
        const auto result = TestEngine::executeSuite(config, region, {0, 1}, configs, &ctx);
        if (cores == 2) {
            expect(!result.infrastructure_failure && result.cycles_completed == 2 && checks > 0 &&
                       result.total_errors() == 1,
                   "Idle chunks are re-verified before reuse and corruption while idle is reported");
        } else {
            expect(!result.infrastructure_failure && result.cycles_completed == 2 && checks == 0 &&
                       result.total_errors() == 0,
                   "A single worker re-claiming its own chunk at once skips the idle check");
        }
    }
}
