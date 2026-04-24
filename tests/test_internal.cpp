#include "ConsoleDisplay.h"
#include "TestEngine.h"
#include "simd_ops.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

using namespace testsmem4u;

namespace {

int g_failures = 0;

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        ++g_failures;
    }
}

MemoryRegion makeRegion(std::vector<uint64_t>& buffer, size_t base_word_offset = 0) {
    MemoryRegion region{};
    region.base = reinterpret_cast<uint8_t*>(buffer.data());
    region.size = buffer.size() * sizeof(uint64_t);
    region.base_offset_bytes = base_word_offset * sizeof(uint64_t);
    region.is_large_pages = false;
    region.large_page_bytes = 0;
    region.is_locked = false;
    return region;
}

void testBoundedUniformVerification() {
    std::vector<uint64_t> buffer(64, 0);
    std::vector<std::pair<uint64_t, uint64_t>> errors;

    const size_t found = simd::verify_uniform(buffer.data(), buffer.size(), ~0ULL, errors, 7);
    expect(found == buffer.size(), "verify_uniform counts every mismatch");
    expect(errors.size() == 7, "verify_uniform keeps only the requested number of samples");
}

void testGlobalXorGenerationAndVerification() {
    constexpr size_t start_word = 1024;
    constexpr uint64_t p0 = 0xDEADBEEFCAFEBABEULL;
    constexpr uint64_t p1 = 0x7654321089ABCDEFULL;

    std::vector<uint64_t> buffer(32, 0);
    std::vector<std::pair<uint64_t, uint64_t>> errors;

    simd::generate_pattern_xor(buffer.data(), buffer.size(), p0, p1, false, start_word);
    size_t found = simd::verify_pattern_xor(buffer.data(), buffer.size(), start_word, p0, p1, errors);
    expect(found == 0, "xor pattern verifies with the same global start offset");

    errors.clear();
    found = simd::verify_pattern_xor(buffer.data(), buffer.size(), 0, p0, p1, errors);
    expect(found == buffer.size(), "xor pattern does not accidentally reset to local offset zero");
}

void testVerifyAndReportGlobalOffset() {
    constexpr size_t start_word = 4096;
    constexpr uint64_t p0 = 0x12345678ULL;
    constexpr uint64_t p1 = 0x9ABCDEF0ULL;

    std::vector<uint64_t> buffer(48, 0);
    MemoryRegion region = makeRegion(buffer, start_word);
    TestContext ctx;
    TestResult result{};

    simd::generate_pattern_linear(buffer.data(), buffer.size(), p0, p1, false, start_word);
    const size_t found = TestEngine::verifyAndReport(region, buffer.data(), buffer.size(), 0, 2, p0, p1,
                                                     result, ctx, "InternalGlobalOffset", false);
    expect(found == 0, "verifyAndReport uses global word offsets for address patterns");
    expect(result.total_errors() == 0, "verifyAndReport leaves result clean for valid global pattern");
}

void testVerifyAndReportBoundedOverflow() {
    std::vector<uint64_t> buffer(16, 0);
    MemoryRegion region = makeRegion(buffer);
    TestContext ctx;
    TestResult result{};

    const size_t found = TestEngine::verifyAndReport(region, buffer.data(), buffer.size(), 0, 0, ~0ULL, 0,
                                                     result, ctx, "InternalOverflow", false, 3);
    expect(found == buffer.size(), "verifyAndReport returns exact total mismatch count");
    expect(result.hard_errors == 3, "verifyAndReport classifies retained samples");
    expect(result.soft_errors == 0, "verifyAndReport does not invent soft errors");
    expect(result.unverified_errors == 13, "verifyAndReport records unsampled mismatches as unverified");
}

void testLfsrKnownVectors() {
    uint64_t state = 1;
    state = test_lfsr_next(state);
    expect(state == 0xD800000000000000ULL, "LFSR vector 1");
    state = test_lfsr_next(state);
    expect(state == 0x6C00000000000000ULL, "LFSR vector 2");
    state = test_lfsr_next(state);
    expect(state == 0x3600000000000000ULL, "LFSR vector 3");
}

void testDeliberateLinearBitFlip() {
    constexpr size_t start_word = 17;
    constexpr uint64_t p0 = 0x1000ULL;
    constexpr uint64_t p1 = 3;

    std::vector<uint64_t> buffer(24, 0);
    std::vector<std::pair<uint64_t, uint64_t>> errors;
    simd::generate_pattern_linear(buffer.data(), buffer.size(), p0, p1, false, start_word);
    buffer[9] ^= 1ULL;

    const size_t found = simd::verify_pattern_linear(buffer.data(), buffer.size(), start_word, p0, p1, errors);
    expect(found == 1, "linear verifier detects one deliberate bit flip");
    expect(errors.size() == 1 && errors[0].first == 9, "linear verifier reports the flipped offset");
}

} // namespace

int main() {
    ConsoleDisplay::get().setTestingActive(true);

    testBoundedUniformVerification();
    testGlobalXorGenerationAndVerification();
    testVerifyAndReportGlobalOffset();
    testVerifyAndReportBoundedOverflow();
    testLfsrKnownVectors();
    testDeliberateLinearBitFlip();

    ConsoleDisplay::get().setTestingActive(false);

    if (g_failures != 0) {
        std::cerr << g_failures << " internal test(s) failed.\n";
        return 1;
    }

    std::cout << "All internal tests passed.\n";
    return 0;
}
