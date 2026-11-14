// Manual probe (not part of the build): does a non-temporal fill leave lines
// that were cached before it cache-resident? testsmem4u skips the whole-region
// flush after streaming fills on x86-64 (simd::streaming_fill_bypasses_cache)
// because such fills evict cached lines. Run this on a new CPU family to check.
//
// Build (pinned llvm-mingw, from the repository root):
//   tools/mingw/llvm-mingw-<version>-ucrt-x86_64/bin/clang++.exe -O2 -std=c++17 -static \
//       tools/probes/nt_fill_cache_probe.cpp -o nt_fill_cache_probe.exe
// Linux: clang++ -O2 -std=c++17 tools/probes/nt_fill_cache_probe.cpp
//
// Expected: every "-> ... NT fill" row matches "flushed" (DRAM latency) and is
// several times slower than "cached". A row near "cached" means NT stores left
// the line cached on this CPU; then streaming_fill_bypasses_cache() must be false.
// It reads an L2-sized block in a shuffled order to defeat prefetchers; times are
// medians of 301 repetitions. Measured 2026-11-13 on a Ryzen 7 5700X (Zen 3):
// cached 1.9 us; flushed and every NT-fill row equal (11.3-13.7 us across runs).
// The flushed row uses CLFLUSHOPT where CPUID reports it, else CLFLUSH (older
// CPUs such as Haswell/Broadwell, which have AVX2 but no CLFLUSHOPT); pass
// --clflush to force CLFLUSH for comparison.
#include <cpuid.h>
#include <immintrin.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <random>
#include <string_view>
#include <vector>

namespace {

constexpr size_t kBlock = 256 * 1024;
constexpr size_t kLines = kBlock / 64;
constexpr int kReps = 301;

std::vector<uint32_t> order;
volatile uint64_t sink;

__attribute__((noinline)) double timedRead(const uint64_t* p) {
    _mm_mfence();
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t s = 0;
    for (uint32_t line : order) s += *reinterpret_cast<const volatile uint64_t*>(p + line * 8);
    _mm_mfence();
    const auto t1 = std::chrono::steady_clock::now();
    sink = s;
    return std::chrono::duration<double, std::micro>(t1 - t0).count();
}

__attribute__((target("clflushopt"))) void flushOpt(uint64_t* p) {
    for (size_t i = 0; i < kBlock / 8; i += 8) _mm_clflushopt(p + i);
    _mm_mfence();
}
void flushLegacy(uint64_t* p) {
    for (size_t i = 0; i < kBlock / 8; i += 8) _mm_clflush(p + i);
    _mm_mfence();
}
// Executing CLFLUSHOPT without CPU support raises #UD (SIGILL).
bool cpuHasClflushopt() {
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    return __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) && (ebx & (1U << 23)) != 0;
}
void (*flush)(uint64_t*) = flushLegacy;
void warm(uint64_t* p) {
    for (int k = 0; k < 3; ++k) timedRead(p);
}
void dirty(uint64_t* p) {
    for (size_t i = 0; i < kBlock / 8; ++i) p[i] = i * 3;
    _mm_mfence();
}
__attribute__((target("avx2"))) void ntAvx2(uint64_t* p, uint64_t v) {
    const __m256i x = _mm256_set1_epi64x(static_cast<long long>(v));
    for (size_t i = 0; i < kBlock / 8; i += 4) _mm256_stream_si256(reinterpret_cast<__m256i*>(p + i), x);
    _mm_sfence();
}
void ntScalar(uint64_t* p, uint64_t v) {
    for (size_t i = 0; i < kBlock / 8; ++i) _mm_stream_si64(reinterpret_cast<long long*>(p + i), static_cast<long long>(v));
    _mm_sfence();
}

} // namespace

int main(int argc, char** argv) {
    const bool force_clflush = argc > 1 && std::string_view(argv[1]) == "--clflush";
    const bool clflushopt = cpuHasClflushopt() && !force_clflush;
    flush = clflushopt ? flushOpt : flushLegacy;
    std::printf("flush instruction: %s%s\n", clflushopt ? "CLFLUSHOPT" : "CLFLUSH",
                force_clflush ? " (forced)" : "");
    // Portable page alignment (Windows UCRT has no aligned_alloc).
    std::vector<uint64_t> storage((kBlock + 4096) / 8);
    auto* p = reinterpret_cast<uint64_t*>((reinterpret_cast<uintptr_t>(storage.data()) + 4095) & ~uintptr_t{4095});
    order.resize(kLines);
    std::iota(order.begin(), order.end(), 0u);
    std::shuffle(order.begin(), order.end(), std::mt19937(42));
    dirty(p);
    struct Case {
        const char* name;
        void (*prepare)(uint64_t*);
    };
    const bool avx2 = __builtin_cpu_supports("avx2");
    const Case cases[] = {
        {"cached (clean, warmed)", [](uint64_t* q) { warm(q); }},
        {"flushed", [](uint64_t* q) { warm(q); flush(q); }},
        {"clean cached -> AVX2 NT fill", [](uint64_t* q) { warm(q); ntAvx2(q, 0x5555); }},
        {"dirty cached -> AVX2 NT fill", [](uint64_t* q) { dirty(q); warm(q); ntAvx2(q, 0xAAAA); }},
        {"dirty cached -> MOVNTI fill", [](uint64_t* q) { dirty(q); warm(q); ntScalar(q, 0x1234); }},
    };
    for (const auto& c : cases) {
        if (!avx2 && std::string_view(c.name).find("AVX2") != std::string_view::npos) continue;
        std::vector<double> t;
        for (int r = 0; r < kReps; ++r) {
            c.prepare(p);
            t.push_back(timedRead(p));
        }
        std::sort(t.begin(), t.end());
        std::printf("%-32s median %7.2f us  p10 %7.2f  p90 %7.2f\n", c.name, t[kReps / 2], t[kReps / 10],
                    t[kReps * 9 / 10]);
    }
    return 0;
}
