// SPDX-License-Identifier: MIT
// Copyright (c) 2026 aufkrawall
//
// Fuzzing harness for testsmem4u preset and config parsers.
// Build with: clang++ -fsanitize=fuzzer,address -O1 -g -std=c++17 -DTESTSMEM4U_FUZZING ...
// Run: ./fuzz_preset corpus/ -max_len=4096

#include "testsmem4u.h"
#include "ConfigManager.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef TESTSMEM4U_FUZZING

static unsigned long currentProcessId() {
#ifdef _WIN32
    return static_cast<unsigned long>(GetCurrentProcessId());
#else
    return static_cast<unsigned long>(getpid());
#endif
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    static std::atomic<uint64_t> counter{0};
    std::error_code ec;
    std::filesystem::path tmp_dir = std::filesystem::temp_directory_path(ec);
    if (ec) tmp_dir = std::filesystem::current_path(ec);
    if (ec) return 0;

    std::filesystem::path tmp_path = tmp_dir / (
        "testsmem4u_fuzz_" + std::to_string(currentProcessId()) + "_" +
        std::to_string(counter.fetch_add(1, std::memory_order_relaxed)) + ".cfg");

    FILE* f = fopen(tmp_path.string().c_str(), "wb");
    if (!f) return 0;
    fwrite(data, 1, size, f);
    fclose(f);

    // Fuzz preset loader
    testsmem4u::PresetInfo preset = testsmem4u::loadPreset(tmp_path.string());
    (void)preset.valid;

    // Fuzz config loader
    testsmem4u::Config config{};
    (void)testsmem4u::loadConfig(tmp_path.string(), config);

    // Cleanup
    std::remove(tmp_path.string().c_str());
    std::remove((tmp_path.string() + ".tmp").c_str());

    return 0;
}

#endif
