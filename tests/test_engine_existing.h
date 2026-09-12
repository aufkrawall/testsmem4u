#pragma once
void testMemoryAllocationRoundTrip() {
    constexpr size_t kTestSize = 65536; // 64KB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);

    expect(guard.valid(), "Memory allocation: guard is valid");
    expect(guard.size() >= kTestSize,
           "Memory allocation: allocated size >= requested");

    if (guard.valid()) {
        uint64_t* ptr = reinterpret_cast<uint64_t*>(guard.base());
        size_t count = guard.size() / sizeof(uint64_t);

        // Write known pattern
        constexpr uint64_t kPattern = 0xDEADBEEFCAFEBABEULL;
        for (size_t i = 0; i < count; ++i) ptr[i] = kPattern;

        simd::sfence();

        // Read back and verify
        bool all_match = true;
        for (size_t i = 0; i < count && all_match; ++i) {
            if (ptr[i] != kPattern) all_match = false;
        }
        expect(all_match, "Memory allocation: write/read-back pattern matches");
    }
}

// ---------------------------------------------------------------------------
// Error classification test (verifyAndReport hard vs soft on known-bad buffer)
// ---------------------------------------------------------------------------

void testErrorClassification() {
    // Create a small buffer with known errors
    std::vector<uint64_t> buffer(32, 0xAAAAAAAAAAAAAAAAULL);
    // Deliberately corrupt some elements
    buffer[5] = 0xBBBBBBBBBBBBBBBBULL;  // Will be classified (differs from uniform 0xAA...)
    buffer[12] = 0xCCCCCCCCCCCCCCCCULL; // Same

    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(buffer.data());
    region.size = buffer.size() * sizeof(uint64_t);
    region.base_offset_bytes = 0;
    region.is_large_pages = false;

    TestContext ctx;
    TestResult result{};

    // Verify uniform pattern 0xAA... — buffer[5] and [12] differ
    size_t found = TestEngine::verifyAndReport(
        region, buffer.data(), buffer.size(), 0,
        0, // uniform mode
        0xAAAAAAAAAAAAAAAAULL, 0,
        result, ctx, "ErrorClassification", false, 10);

    expect(found == 2, "Error classification: detects exactly 2 mismatches");
    // With uniform mode, re-read will see the same value (buffer modified before call),
    // so they should be classified as hard errors
    expect(result.hard_errors == 2,
           "Error classification: mismatches classified as hard errors (buffer is modified)");
    expect(result.soft_errors == 0,
           "Error classification: no soft errors from deliberate modifications");
}

void testSimpleEndToEnd() {
    constexpr size_t kTestSize = 4ULL * 1024 * 1024; // 4MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end: memory allocation succeeds");

    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "SimpleTest";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0xDEADBEEFCAFEBABEULL;
    tc.pattern_param1 = 0;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runSimpleTest(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end SimpleTest: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end SimpleTest: no soft errors on clean run");
    expect(res.bytes_tested >= region.size,
           "End-to-end SimpleTest: at least region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end SimpleTest: no infrastructure failure");
}

void testSimpleEndToEndWalkingOnes() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end WalkingOnes: memory allocation succeeds");

    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "WalkingOnes";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0;
    tc.pattern_param1 = 0;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runWalkingOnes(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end WalkingOnes: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end WalkingOnes: no soft errors on clean run");
    expect(res.bytes_tested >= region.size,
           "End-to-end WalkingOnes: at least region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end WalkingOnes: no infrastructure failure");
}

void testEndToEndMirrorMove128() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end MirrorMove128: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "MirrorMove128";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0x5555555555555555ULL;
    tc.pattern_param1 = 0xAAAAAAAAAAAAAAAAULL;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runMirrorMove128(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end MirrorMove128: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end MirrorMove128: no soft errors on clean run");
    expect(res.bytes_tested >= region.size,
           "End-to-end MirrorMove128: at least region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end MirrorMove128: no infrastructure failure");
}

void testEndToEndBlockMove() {
    constexpr size_t kTestSize = 2ULL * 1024 * 1024; // 2MB (needs two halves)
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end BlockMove: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "BlockMove";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0xCCCC3333CCCC3333ULL;
    tc.pattern_param1 = 0;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runBlockMove(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end BlockMove: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end BlockMove: no soft errors on clean run");
    expect(res.bytes_tested >= region.size,
           "End-to-end BlockMove: at least region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end BlockMove: no infrastructure failure");
}

void testEndToEndMovingInversion() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end MovingInversion: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "MovingInversion";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0xAAAAAAAAAAAAAAAAULL;
    tc.pattern_param1 = 0;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runMovingInversion(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end MovingInversion: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end MovingInversion: no soft errors on clean run");
    expect(res.bytes_tested >= region.size * 2,
           "End-to-end MovingInversion: at least 2x region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end MovingInversion: no infrastructure failure");
}

void testEndToEndMovingInversionLFSR() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end MovingInversionLFSR: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "MovingInversionLFSR";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0xACE1ACE2DEADBEEFULL;
    tc.pattern_param1 = 0;
    tc.parameter = 1;

    TestContext ctx;
    TestResult res = TestEngine::runMovingInversionLFSR(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end MovingInversionLFSR: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end MovingInversionLFSR: no soft errors on clean run");
    expect(res.bytes_tested >= region.size * 2,
           "End-to-end MovingInversionLFSR: at least 2x region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end MovingInversionLFSR: no infrastructure failure");
}

void testEndToEndLFSRPattern() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end LFSRPattern: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "LFSRPattern";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0xACE1ACE2DEADBEEFULL;
    tc.pattern_param1 = 0;
    tc.parameter = 0;

    TestContext ctx;
    TestResult res = TestEngine::runLFSRPattern(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end LFSRPattern: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end LFSRPattern: no soft errors on clean run");
    expect(res.bytes_tested >= region.size,
           "End-to-end LFSRPattern: at least region size bytes tested");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end LFSRPattern: no infrastructure failure");
}

void testEndToEndRandomAccess() {
    constexpr size_t kTestSize = 1ULL * 1024 * 1024; // 1MB
    auto guard = Platform::allocateMemoryRAII(kTestSize, false, false, true);
    expect(guard.valid(), "End-to-end RandomAccess: memory allocation succeeds");
    if (!guard.valid()) return;

    MemoryRegion region{};
    region.base = guard.base();
    region.size = guard.size();
    region.base_offset_bytes = 0;
    region.is_large_pages = guard.is_large_pages();
    region.large_page_bytes = guard.large_page_bytes();
    region.is_locked = guard.is_locked();

    TestConfig tc;
    tc.function = "RandomAccess";
    tc.enabled = true;
    tc.pattern_mode = 0;
    tc.pattern_param0 = 0;
    tc.pattern_param1 = 0;
    tc.parameter = 1; // 1 pass

    TestContext ctx;
    TestResult res = TestEngine::runRandomAccess(ctx, region, tc, false);

    expect(res.hard_errors == 0,
           "End-to-end RandomAccess: no hard errors on clean run");
    expect(res.soft_errors == 0,
           "End-to-end RandomAccess: no soft errors on clean run");
    expect(!ctx.hasInfrastructureFailure(),
           "End-to-end RandomAccess: no infrastructure failure");
}
