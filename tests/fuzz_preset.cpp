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
#include <string>

#ifdef TESTSMEM4U_FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    // Write fuzz input to a temporary file
    char tmp_path[] = "fuzz_preset_XXXXXX.cfg";
    FILE* f = fopen(tmp_path, "wb");
    if (!f) return 0;
    fwrite(data, 1, size, f);
    fclose(f);

    // Fuzz preset loader
    testsmem4u::PresetInfo preset = testsmem4u::loadPreset(tmp_path);
    (void)preset.valid;

    // Fuzz config loader
    testsmem4u::Config config{};
    (void)testsmem4u::loadConfig(tmp_path, config);

    // Cleanup
    std::remove(tmp_path);
    std::remove((std::string(tmp_path) + ".tmp").c_str());

    return 0;
}

#endif
