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
}
