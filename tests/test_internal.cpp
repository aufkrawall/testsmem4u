#include "ConsoleDisplay.h"
#include "TestEngine.h"
#include "simd_ops.h"
#include "Utils.h"
#include "ConfigManager.h"
#include "testsmem4u.h"
#include "Platform.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <fstream>
#include <cstdio>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <system_error>

using namespace testsmem4u;

namespace {

int g_failures = 0;

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "[FAIL] " << message << '\n';
        ++g_failures;
    }
}

std::string uniqueTempPath(const std::string& suffix) {
    static uint64_t counter = 0;
    return "testsmem4u_test_" + std::to_string(++counter) + suffix;
}

void cleanupFile(const std::string& path) {
    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Utils tests
// ---------------------------------------------------------------------------

void testUtilsTrim() {
    expect(Utils::trim("") == "", "trim empty string");
    expect(Utils::trim("   ") == "", "trim whitespace-only");
    expect(Utils::trim("  hello  ") == "hello", "trim surrounding spaces");
    expect(Utils::trim("\t\r\nhello\t\r\n") == "hello", "trim various whitespace");
    expect(Utils::trim("hello") == "hello", "trim no-op");
    expect(Utils::trim("  a b  ") == "a b", "trim preserves internal spaces");
}

void testUtilsParseHexStrict() {
    uint64_t val = 0;
    expect(Utils::parseHexStrict("", val) == false, "parseHexStrict rejects empty");
    expect(Utils::parseHexStrict("0x", val) == false, "parseHexStrict rejects bare 0x");
    expect(Utils::parseHexStrict("0x1A", val) && val == 0x1A, "parseHexStrict 0x1A");
    expect(Utils::parseHexStrict("FF", val) && val == 0xFF, "parseHexStrict FF");
    expect(Utils::parseHexStrict("0xDEADBEEF", val) && val == 0xDEADBEEF, "parseHexStrict DEADBEEF");
    expect(Utils::parseHexStrict("0xDEADBEEFCAFEBABE", val) && val == 0xDEADBEEFCAFEBABE, "parseHexStrict 64-bit");
    expect(Utils::parseHexStrict(" 0xABC ", val) && val == 0xABC, "parseHexStrict with spaces");
    expect(Utils::parseHexStrict("0xGGG", val) == false, "parseHexStrict rejects invalid chars");
    expect(Utils::parseHexStrict("-1", val) == false, "parseHexStrict rejects negative");
}

void testUtilsParseUintStrict() {
    uint32_t val = 0;
    expect(Utils::parseUintStrict("", val) == false, "parseUintStrict rejects empty");
    expect(Utils::parseUintStrict("0", val) && val == 0, "parseUintStrict zero");
    expect(Utils::parseUintStrict("123", val) && val == 123, "parseUintStrict 123");
    expect(Utils::parseUintStrict(" 456 ", val) && val == 456, "parseUintStrict with spaces");
    expect(Utils::parseUintStrict("9999999999", val) == false, "parseUintStrict rejects > uint32_max");
    expect(Utils::parseUintStrict("-5", val) == false, "parseUintStrict rejects negative");
    expect(Utils::parseUintStrict("abc", val) == false, "parseUintStrict rejects non-numeric");
    expect(Utils::parseUintStrict("12a", val) == false, "parseUintStrict rejects trailing chars");
    expect(Utils::parseUintStrict("255", val) && val == 255, "parseUintStrict 255");
}

void testUtilsParseKeyValue() {
    std::string key, value;
    expect(Utils::parseKeyValue("", key, value) == false, "parseKeyValue empty");
    expect(Utils::parseKeyValue("=", key, value) == false, "parseKeyValue bare =");
    expect(Utils::parseKeyValue("key=value", key, value) && key == "key" && value == "value",
           "parseKeyValue key=value");
    expect(Utils::parseKeyValue("  abc = 123  ", key, value) && key == "abc" && value == "123",
           "parseKeyValue with spaces");
    expect(Utils::parseKeyValue("=value", key, value) == false, "parseKeyValue no key");
    expect(Utils::parseKeyValue("key=", key, value) && key == "key" && value == "",
           "parseKeyValue empty value");
}

void testParseTestSequenceStrict() {
    std::vector<uint32_t> seq = parseTestSequence("0, 1,2");
    expect(seq.size() == 3 && seq[0] == 0 && seq[1] == 1 && seq[2] == 2,
           "parseTestSequence accepts comma-separated numeric IDs");

    expect(parseTestSequence("1,bad,2").empty(),
           "parseTestSequence rejects mixed invalid tokens");
    expect(parseTestSequence("1,,2").empty(),
           "parseTestSequence rejects empty middle tokens");
    expect(parseTestSequence("1,").empty(),
           "parseTestSequence rejects trailing separators");
}

// ---------------------------------------------------------------------------
// Preset loading tests
// ---------------------------------------------------------------------------

void testPresetLoadValid() {
    std::string path = uniqueTempPath("_valid_preset.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Config Name = Test Preset\n";
        f << "Tests = 2\n";
        f << "Cycles = 3\n";
        f << "Test Sequence = 1,2\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = SimpleTest\n";
        f << "Time (%) = 50\n";
        f << "[Test2]\n";
        f << "Enable = 1\n";
        f << "Function = LFSRPattern\n";
        f << "Time (%) = 50\n";
    }
    PresetInfo preset = loadPreset(path);
    expect(preset.valid, "valid preset loads successfully");
    expect(preset.config_name == "Test Preset", "preset config name");
    expect(preset.tests == 2, "preset tests count");
    expect(preset.cycles == 3, "preset cycles");
    expect(preset.test_configs.size() == 2, "preset has 2 test configs");
    if (preset.test_configs.count(1)) {
        expect(preset.test_configs[1].function == "SimpleTest", "test 1 function");
        expect(preset.test_configs[1].enabled, "test 1 enabled");
    }
    cleanupFile(path);
}

void testPresetLoadMissingFunction() {
    std::string path = uniqueTempPath("_missing_func.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        // No Function= line
    }
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "preset missing Function= is invalid");
    expect(!preset.validation_error.empty(), "preset has validation error message");
    cleanupFile(path);
}

void testPresetLoadUnknownFunction() {
    std::string path = uniqueTempPath("_unknown_func.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = NonExistentTest\n";
    }
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "preset with unknown function is invalid");
    cleanupFile(path);
}

void testPresetLoadAllDisabled() {
    std::string path = uniqueTempPath("_all_disabled.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 0\n";
        f << "Function = SimpleTest\n";
    }
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "preset with all tests disabled is invalid");
    cleanupFile(path);
}

void testPresetLoadBadTestSequenceRef() {
    std::string path = uniqueTempPath("_bad_seq.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 99\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = SimpleTest\n";
    }
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "preset referencing nonexistent test is invalid");
    cleanupFile(path);
}

void testPresetLoadEmptyFile() {
    std::string path = uniqueTempPath("_empty.cfg");
    {
        std::ofstream f(path);
        // Empty file
    }
    // An empty file should produce an invalid preset
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "empty preset file is invalid");
    cleanupFile(path);
}

void testPresetLoadUnsafePath() {
    // Path with null byte should be rejected
    // Use explicit-length construction to embed a null byte in the string
    std::string bad_path("safe_part\0unsafe.cfg", 21);
    PresetInfo preset = loadPreset(bad_path);
    expect(!preset.valid, "preset with null byte path is rejected");
    // Path with ESC byte should be rejected
    std::string esc_path = "test\x1b.cfg";
    preset = loadPreset(esc_path);
    expect(!preset.valid, "preset with ESC byte path is rejected");
    std::string newline_path = "test\n.cfg";
    preset = loadPreset(newline_path);
    expect(!preset.valid, "preset with newline path is rejected");
}

void testPresetLoadAllowsExplicitAbsolutePath() {
    std::string path = uniqueTempPath("_absolute_preset.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = SimpleTest\n";
    }

    std::error_code ec;
    std::filesystem::path absolute = std::filesystem::absolute(path, ec);
    expect(!ec, "absolute preset path can be resolved for test");
    PresetInfo preset = loadPreset(absolute.string());
    expect(preset.valid, "preset loader accepts explicit absolute paths");
    expect(preset.test_configs.size() == 1, "absolute preset path loads test config");
    cleanupFile(path);
}

void testPresetLoadRejectsMalformedSequence() {
    std::string path = uniqueTempPath("_bad_sequence.cfg");
    {
        std::ofstream f(path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1,bad\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = SimpleTest\n";
    }
    PresetInfo preset = loadPreset(path);
    expect(!preset.valid, "preset with mixed invalid Test Sequence is rejected");
    cleanupFile(path);
}

void testPresetLoadRejectsInvalidModeAndEnable() {
    std::string mode_path = uniqueTempPath("_bad_mode.cfg");
    {
        std::ofstream f(mode_path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 1\n";
        f << "Function = SimpleTest\n";
        f << "Pattern Mode = 99\n";
    }
    PresetInfo preset = loadPreset(mode_path);
    expect(!preset.valid, "preset with invalid Pattern Mode is rejected");
    cleanupFile(mode_path);

    std::string enable_path = uniqueTempPath("_bad_enable.cfg");
    {
        std::ofstream f(enable_path);
        f << "[Config]\n";
        f << "Tests = 1\n";
        f << "Test Sequence = 1\n";
        f << "[Test1]\n";
        f << "Enable = 2\n";
        f << "Function = SimpleTest\n";
    }
    preset = loadPreset(enable_path);
    expect(!preset.valid, "preset with invalid Enable value is rejected");
    cleanupFile(enable_path);
}

// ---------------------------------------------------------------------------
// Config save/load round-trip tests
// ---------------------------------------------------------------------------

void testConfigRoundTrip() {
    std::string path = uniqueTempPath("_config.ini");
    
    Config original{};
    original.memory_window_percent = 75;
    original.memory_window_mb = 4096;
    original.cores = 4;
    original.cycles = 10;
    original.use_locked_memory = true;
    original.use_large_pages = false;
    original.halt_on_error = true;
    original.preset_file = "my_preset.cfg";

    bool saved = saveConfig(path, original);
    expect(saved, "config saved successfully");

    Config loaded{};
    bool loaded_ok = loadConfig(path, loaded);
    expect(loaded_ok, "config loaded successfully");
    expect(loaded.memory_window_percent == original.memory_window_percent,
           "config round-trip: memory_window_percent");
    expect(loaded.memory_window_mb == original.memory_window_mb,
           "config round-trip: memory_window_mb");
    expect(loaded.cores == original.cores,
           "config round-trip: cores");
    expect(loaded.cycles == original.cycles,
           "config round-trip: cycles");
    expect(loaded.use_locked_memory == original.use_locked_memory,
           "config round-trip: use_locked_memory");
    expect(loaded.use_large_pages == original.use_large_pages,
           "config round-trip: use_large_pages");
    expect(loaded.halt_on_error == original.halt_on_error,
           "config round-trip: halt_on_error");
    expect(loaded.preset_file == original.preset_file,
           "config round-trip: preset_file");

    cleanupFile(path);
    // Also clean up any .tmp file from atomic write
    cleanupFile(path + ".tmp");
}

void testConfigLoadMissing() {
    Config cfg{};
    bool ok = loadConfig("nonexistent_file_that_does_not_exist.ini", cfg);
    expect(!ok, "loading missing config returns false");
}

void testConfigInvalidLoadDoesNotPartiallyApply() {
    std::string path = uniqueTempPath("_invalid_config.ini");
    {
        std::ofstream f(path);
        f << "[Settings]\n";
        f << "MemoryWindowMB=4096\n";
        f << "Cores=not-a-number\n";
    }

    Config cfg{};
    cfg.memory_window_mb = 128;
    cfg.cores = 2;
    bool ok = loadConfig(path, cfg);
    expect(!ok, "invalid config load returns false");
    expect(cfg.memory_window_mb == 128, "invalid config does not partially apply MemoryWindowMB");
    expect(cfg.cores == 2, "invalid config does not partially apply Cores");
    cleanupFile(path);
    cleanupFile(path + ".tmp");
}

void testConfigRejectsUnsafePath() {
    Config cfg{};
    std::string unsafe_path = "bad\nconfig.ini";
    expect(!loadConfig(unsafe_path, cfg), "config load rejects control-character path");
    expect(!saveConfig(unsafe_path, cfg), "config save rejects control-character path");
}

// ---------------------------------------------------------------------------
// Existing tests from original file follow below
// ---------------------------------------------------------------------------

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

// The verifiers must report the corrupted value they actually loaded, at every
// offset class (SIMD main loop lanes and the scalar tail). This pins the
// register-spill behavior: a mismatch seen by the SIMD compare is recorded from
// the loaded register, never from a second memory read.
void testVerifierObservedValues() {
    constexpr size_t kCount = 67; // odd, not a multiple of 4/8 -> exercises tails
    constexpr uint64_t p0 = 0x0123456789ABCDEFULL;
    constexpr uint64_t p1 = 0x00000000DEADBEEFULL;
    const std::vector<size_t> flip_offsets = {0, 3, 8, 33, 64, 66};

    // verify_uniform
    {
        std::vector<uint64_t> buffer(kCount, p0);
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        for (size_t off : flip_offsets) buffer[off] ^= (1ULL << (off % 64));
        const size_t found = simd::verify_uniform(buffer.data(), buffer.size(), p0, errors);
        expect(found == flip_offsets.size(), "verify_uniform counts all injected flips");
        expect(errors.size() == flip_offsets.size(), "verify_uniform samples all injected flips");
        for (size_t k = 0; k < errors.size() && k < flip_offsets.size(); ++k) {
            expect(errors[k].first == flip_offsets[k], "verify_uniform reports flipped offset");
            expect(errors[k].second == buffer[flip_offsets[k]],
                   "verify_uniform records the observed corrupted value");
        }
    }

    // verify_pattern_linear
    {
        std::vector<uint64_t> buffer(kCount, 0);
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        simd::generate_pattern_linear(buffer.data(), buffer.size(), p0, p1, false, 0);
        for (size_t off : flip_offsets) buffer[off] ^= (1ULL << (off % 64));
        const size_t found = simd::verify_pattern_linear(buffer.data(), buffer.size(), 0, p0, p1, errors);
        expect(found == flip_offsets.size(), "verify_pattern_linear counts all injected flips");
        for (size_t k = 0; k < errors.size() && k < flip_offsets.size(); ++k) {
            expect(errors[k].first == flip_offsets[k], "verify_pattern_linear reports flipped offset");
            expect(errors[k].second == buffer[flip_offsets[k]],
                   "verify_pattern_linear records the observed corrupted value");
        }
    }

    // verify_pattern_xor
    {
        std::vector<uint64_t> buffer(kCount, 0);
        std::vector<std::pair<uint64_t, uint64_t>> errors;
        simd::generate_pattern_xor(buffer.data(), buffer.size(), p0, p1, false, 0);
        for (size_t off : flip_offsets) buffer[off] ^= (1ULL << (off % 64));
        const size_t found = simd::verify_pattern_xor(buffer.data(), buffer.size(), 0, p0, p1, errors);
        expect(found == flip_offsets.size(), "verify_pattern_xor counts all injected flips");
        for (size_t k = 0; k < errors.size() && k < flip_offsets.size(); ++k) {
            expect(errors[k].first == flip_offsets[k], "verify_pattern_xor reports flipped offset");
            expect(errors[k].second == buffer[flip_offsets[k]],
                   "verify_pattern_xor records the observed corrupted value");
        }
    }
}

void testVerifyPatternPair() {
    constexpr uint64_t even_val = 0x5555555555555555ULL;
    constexpr uint64_t odd_val = 0xAAAAAAAAAAAAAAAAULL;
    constexpr size_t kCount = 67; // odd count -> exercises SIMD lanes and scalar tail

    std::vector<uint64_t> buffer(kCount);
    for (size_t i = 0; i < kCount; ++i) {
        buffer[i] = (i & 1) ? odd_val : even_val;
    }

    std::vector<std::pair<uint64_t, uint64_t>> errors;
    size_t found = simd::verify_pattern_pair(buffer.data(), buffer.size(), even_val, odd_val, errors);
    expect(found == 0, "verify_pattern_pair passes a clean alternating pattern");

    // Inject corruption at even and odd offsets across lane positions and tail.
    const std::vector<size_t> flip_offsets = {0, 1, 7, 32, 33, 64, 66};
    for (size_t off : flip_offsets) buffer[off] ^= (1ULL << (off % 64));

    errors.clear();
    found = simd::verify_pattern_pair(buffer.data(), buffer.size(), even_val, odd_val, errors);
    expect(found == flip_offsets.size(), "verify_pattern_pair counts all injected flips");
    expect(errors.size() == flip_offsets.size(), "verify_pattern_pair samples all injected flips");
    for (size_t k = 0; k < errors.size() && k < flip_offsets.size(); ++k) {
        expect(errors[k].first == flip_offsets[k], "verify_pattern_pair reports flipped offset");
        expect(errors[k].second == buffer[flip_offsets[k]],
               "verify_pattern_pair records the observed corrupted value");
    }

    // Bounded sampling still counts every mismatch.
    errors.clear();
    found = simd::verify_pattern_pair(buffer.data(), buffer.size(), even_val, odd_val, errors, 3);
    expect(found == flip_offsets.size(), "verify_pattern_pair counts beyond the sample bound");
    expect(errors.size() == 3, "verify_pattern_pair respects the sample bound");
}

// ---------------------------------------------------------------------------
// Concurrency tests (ThreadBarrier analog using std primitives)
// ---------------------------------------------------------------------------

void testThreadBarrierBasic() {
    constexpr uint32_t kParticipants = 4;
    std::mutex mtx;
    std::condition_variable cv;
    uint32_t arrived = 0;
    uint32_t generation = 0;
    uint32_t barrier_count = 0;

    auto arrive_and_wait = [&]() {
        std::unique_lock<std::mutex> lock(mtx);
        uint32_t gen = generation;
        if (++arrived == kParticipants) {
            arrived = 0;
            ++generation;
            ++barrier_count;
            cv.notify_all();
            return;
        }
        cv.wait(lock, [&]() { return generation != gen; });
    };

    std::vector<std::thread> threads;
    std::atomic<uint32_t> phase_count{0};

    for (uint32_t t = 0; t < kParticipants; ++t) {
        threads.emplace_back([&]() {
            arrive_and_wait();
            phase_count.fetch_add(1, std::memory_order_relaxed);
            arrive_and_wait();
        });
    }

    for (auto& th : threads) th.join();

    expect(barrier_count == 2,
           "ThreadBarrier: barrier released all participants twice");
    expect(phase_count.load(std::memory_order_relaxed) == kParticipants,
           "ThreadBarrier: all threads completed both phases");
}

// ---------------------------------------------------------------------------
// TestContext (standalone) tests
// ---------------------------------------------------------------------------

void testTestContextBasics() {
    TestContext ctx;

    expect(!ctx.shouldStop(), "TestContext: shouldStop returns false initially");
    expect(!ctx.hasInfrastructureFailure(), "TestContext: no infra failure initially");

    ctx.requestStop();
    expect(ctx.shouldStop(), "TestContext: shouldStop returns true after requestStop");

    // Reset by constructing fresh (no un-reset mechanism by design)
    TestContext ctx2;
    ctx2.setActiveTestName("SimpleTest");
    expect(ctx2.getActiveTestName() == "SimpleTest",
           "TestContext: setActiveTestName/getActiveTestName round-trip");
    ctx2.setActiveTestName("LFSRPattern");
    expect(ctx2.getActiveTestName() == "LFSRPattern",
           "TestContext: active test name updates on second set");

    ctx2.setInfrastructureFailure("test error");
    expect(ctx2.hasInfrastructureFailure(),
           "TestContext: hasInfrastructureFailure after set");
    expect(ctx2.shouldStop(),
           "TestContext: requestStop called by setInfrastructureFailure");
    expect(ctx2.getInfrastructureFailureMessage() == "test error",
           "TestContext: infrastructure error message preserved");
}

// ---------------------------------------------------------------------------
// RunResult merge tests
// ---------------------------------------------------------------------------

void testRunResultMerge() {
    TestResult a, b;
    a.hard_errors = 5;
    a.soft_errors = 3;
    a.unverified_errors = 2;
    a.bytes_tested = 1000;

    b.hard_errors = 2;
    b.soft_errors = 7;
    b.unverified_errors = 1;
    b.bytes_tested = 2000;

    a.merge(b);

    expect(a.hard_errors == 7, "RunResult merge: hard_errors = 5+2");
    expect(a.soft_errors == 10, "RunResult merge: soft_errors = 3+7");
    expect(a.unverified_errors == 3, "RunResult merge: unverified_errors = 2+1");
    expect(a.bytes_tested == 3000, "RunResult merge: bytes_tested = 1000+2000");

    // Verify b is unchanged (non-destructive read)
    expect(b.hard_errors == 2, "RunResult merge: source is not modified (hard)");
    expect(b.soft_errors == 7, "RunResult merge: source is not modified (soft)");

    // total_errors() and verified_errors() convenience methods
    expect(a.total_errors() == 7 + 10 + 3, "RunResult: total_errors sum matches");
    expect(a.verified_errors() == 7 + 10, "RunResult: verified_errors = hard + soft");
}

// ---------------------------------------------------------------------------
// Memory allocation round-trip test (small region, no large pages)
// ---------------------------------------------------------------------------

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

} // namespace

int main() {
    ConsoleDisplay::get().setTestingActive(true);

    // Utils tests
    testUtilsTrim();
    testUtilsParseHexStrict();
    testUtilsParseUintStrict();
    testUtilsParseKeyValue();
    testParseTestSequenceStrict();

    // Preset loading tests
    testPresetLoadValid();
    testPresetLoadMissingFunction();
    testPresetLoadUnknownFunction();
    testPresetLoadAllDisabled();
    testPresetLoadBadTestSequenceRef();
    testPresetLoadEmptyFile();
    testPresetLoadUnsafePath();
    testPresetLoadAllowsExplicitAbsolutePath();
    testPresetLoadRejectsMalformedSequence();
    testPresetLoadRejectsInvalidModeAndEnable();

    // Config round-trip tests
    testConfigRoundTrip();
    testConfigLoadMissing();
    testConfigInvalidLoadDoesNotPartiallyApply();
    testConfigRejectsUnsafePath();

    // Existing tests from original file
    testBoundedUniformVerification();
    testGlobalXorGenerationAndVerification();
    testVerifyAndReportGlobalOffset();
    testVerifyAndReportBoundedOverflow();
    testLfsrKnownVectors();
    testDeliberateLinearBitFlip();
    testVerifierObservedValues();
    testVerifyPatternPair();

    // Concurrency and infrastructure tests
    testThreadBarrierBasic();
    testTestContextBasics();
    testRunResultMerge();
    testMemoryAllocationRoundTrip();
    testErrorClassification();

    // End-to-end tests with real memory allocation
    testSimpleEndToEnd();
    testSimpleEndToEndWalkingOnes();
    testEndToEndMirrorMove128();
    testEndToEndBlockMove();
    testEndToEndMovingInversion();
    testEndToEndMovingInversionLFSR();
    testEndToEndLFSRPattern();
    testEndToEndRandomAccess();

    ConsoleDisplay::get().setTestingActive(false);

    if (g_failures != 0) {
        std::cerr << g_failures << " internal test(s) failed.\n";
        return 1;
    }

    std::cout << "All internal tests passed.\n";
    return 0;
}
