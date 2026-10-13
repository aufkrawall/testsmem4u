#pragma once

void testUniformMarchSpecialization() {
    alignas(64) std::array<uint64_t, 1056> generic{}, specialized{}, expected{};
    for (size_t count : {0U, 1U, 2U, 3U, 7U, 8U, 15U, 31U, 63U, 511U, 512U, 513U, 1027U}) {
        for (uint64_t pattern : {0ULL, ~0ULL, 0xACE1ACE2DEADBEEFULL}) {
            for (bool march : {false, true}) {
                for (bool reverse : {false, true}) {
                    for (size_t limit : {0U, 3U, 4096U}) {
                        generic.fill(0x1234); specialized.fill(0x1234); expected.fill(pattern);
                        for (size_t i = 0; i < count; ++i) {
                            generic[i + 1] = specialized[i + 1] = pattern ^ (i % 3 == 0 ? 1ULL : 0ULL);
                        }
                        std::vector<std::pair<uint64_t, uint64_t>> old_errors, new_errors;
                        const size_t old_found = simd::verify_words(generic.data() + 1, expected.data(), count,
                                                                    old_errors, march, reverse, limit);
                        const size_t new_found = simd::verify_uniform_words(specialized.data() + 1, pattern, count,
                                                                           new_errors, march, reverse, limit);
                        expect(old_found == new_found && old_errors == new_errors && generic == specialized,
                               "Uniform specialization preserves first observations, direction, tails, sample caps and writes");
                    }
                }
            }
        }
    }
    for (const std::string phase : {"March filled", "March inverted", "March restored"}) {
        TestContext ctx;
        MemoryRegion region{};
        region.base = reinterpret_cast<uint8_t*>(specialized.data()); region.size = 1027 * sizeof(uint64_t);
        bool injected = false;
        ctx.phase_hook = [&](const char* name, const MemoryRegion& part) {
            if (!injected && name == phase) {
                reinterpret_cast<uint64_t*>(part.base)[1026] ^= 1;
                injected = true;
            }
        };
        TestConfig tc; tc.pattern_param0 = 0; tc.parameter = 1;
        const auto result = TestEngine::runMovingInversion(ctx, region, tc, true);
        expect(injected && result.total_errors() == 1 && ctx.shouldStop(),
               "Uniform march specialized path detects injected phase errors: " + phase);
    }
}
