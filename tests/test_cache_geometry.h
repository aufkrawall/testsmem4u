#pragma once

void testCacheFlushGeometry() {
    constexpr uint32_t clflush_bit = uint32_t{1} << 19;
    for (uint32_t bytes : {8U, 16U, 32U, 64U, 128U, 256U, 512U, 1024U}) {
        // Nonzero APIC, logical CPU and brand fields must not affect the stride.
        const uint32_t ebx = 0xABCD00EFU | ((bytes / 8) << 8);
        expect(simd::detail::x86AdvertisedFlushGranule(ebx, clflush_bit) == bytes,
               "Flush granule decodes leaf-1 EBX in eight-byte units independently of unrelated fields");
        // A stride above the real line size would skip lines, so larger
        // advertised granules are capped; smaller ones are honored.
        expect(simd::detail::x86FlushLineSize(ebx, clflush_bit) == std::min<size_t>(bytes, 64),
               "Flush stride honors small granules and never exceeds 64 bytes");
    }
    for (uint32_t ebx : {0U, 0xFFFF00FFU, 0x00000300U, 0x0000FF00U}) {
        expect(simd::detail::x86AdvertisedFlushGranule(ebx, clflush_bit) == 0 &&
                   simd::detail::x86FlushLineSize(ebx, clflush_bit) == 64,
               "Missing or malformed flush granule retains the safe 64-byte fallback");
    }
    expect(simd::detail::x86AdvertisedFlushGranule(0x00001000U, 0) == 0 &&
               simd::detail::x86FlushLineSize(0x00001000U, 0) == 64,
           "Flush granule is unavailable without the CLFSH feature bit");
#if defined(__x86_64__) || defined(__i386__)
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid_count(1, 0, eax, ebx, ecx, edx);
    const simd::SimdCapabilities caps = simd::getCapabilities();
    expect(caps.cache_line_size == simd::detail::x86FlushLineSize(ebx, edx) &&
               caps.flush_granule_advertised == simd::detail::x86AdvertisedFlushGranule(ebx, edx),
           "Native flush loops use the actual CPU's leaf-1 granule");
#endif

    {
        using namespace simd::detail;
        X86CpuFeatures full_v4;
        full_v4.max_leaf = 7;
        full_v4.max_ext_leaf = 0x80000001U;
        full_v4.leaf1_ecx = (uint32_t{1} << 0) | (uint32_t{1} << 9) | (uint32_t{1} << 12) |
                            (uint32_t{1} << 13) | (uint32_t{1} << 19) | (uint32_t{1} << 20) |
                            (uint32_t{1} << 22) | (uint32_t{1} << 23) | (uint32_t{1} << 27) |
                            (uint32_t{1} << 28) | (uint32_t{1} << 29);
        full_v4.leaf7_ebx = (uint32_t{1} << 3) | (uint32_t{1} << 5) | (uint32_t{1} << 8) |
                            (uint32_t{1} << 16) | (uint32_t{1} << 17) | (uint32_t{1} << 28) |
                            (uint32_t{1} << 30) | (uint32_t{1} << 31);
        full_v4.ext1_ecx = (uint32_t{1} << 0) | (uint32_t{1} << 5);
        full_v4.xcr0 = 0xE6ULL;
        expect(supportsX8664V3(full_v4) && supportsX8664V4(full_v4),
               "Full psABI v4 + XCR0 feature set satisfies both x86-64-v3 and x86-64-v4");

        // Knights Landing: AVX512F + AVX512CD only (no DQ, BW, VL).
        X86CpuFeatures knl = full_v4;
        knl.leaf7_ebx &= ~((uint32_t{1} << 17) | (uint32_t{1} << 30) | (uint32_t{1} << 31));
        expect(supportsX8664V3(knl) && !supportsX8664V4(knl),
               "Partial AVX-512 (AVX512F+CD without DQ/BW/VL) satisfies v3 but rejects x86-64-v4");

        // Missing any single v4 bit (e.g. AVX512VL) rejects v4.
        for (unsigned bit : {16U, 17U, 28U, 30U, 31U}) {
            X86CpuFeatures missing_one = full_v4;
            missing_one.leaf7_ebx &= ~(uint32_t{1} << bit);
            expect(!supportsX8664V4(missing_one),
                   "Missing any required AVX-512 v4 feature bit disables x86-64-v4");
        }

        // OS XCR0 with YMM only enables v3 but disables v4.
        X86CpuFeatures no_zmm_os = full_v4;
        no_zmm_os.xcr0 = 0x6ULL;
        expect(supportsX8664V3(no_zmm_os) && !supportsX8664V4(no_zmm_os),
               "OS without ZMM XCR0 state enables x86-64-v3 only");

        // Missing BMI2 or LZCNT or FMA rejects v3 and v4.
        X86CpuFeatures no_bmi2 = full_v4;
        no_bmi2.leaf7_ebx &= ~(uint32_t{1} << 8);
        expect(!supportsX8664V3(no_bmi2) && !supportsX8664V4(no_bmi2),
               "Missing BMI2 rejects x86-64-v3 and x86-64-v4");
        X86CpuFeatures no_lzcnt = full_v4;
        no_lzcnt.ext1_ecx &= ~(uint32_t{1} << 5);
        expect(!supportsX8664V3(no_lzcnt) && !supportsX8664V4(no_lzcnt),
               "Missing LZCNT rejects x86-64-v3 and x86-64-v4");
    }
}
