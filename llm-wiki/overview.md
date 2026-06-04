# Overview

## Architecture
testsmem4u is a cross-platform RAM testing utility for Windows and Linux.
It supports locked memory, large pages, and dynamic CPU core affinity targeting.
It automatically attempts to relaunch itself using AVX2 (-v3) or AVX-512 (-v4) sibling binaries for performance if present.

## Key Files
- `src/main.cpp`: CLI argument parsing, interactive/non-interactive configuration, and process management.
- `src/TestEngine.cpp`: Test execution orchestration, thread spawning, and verification logic.
- `src/Platform.cpp`: Platform-specific API integration (CPU topology detection, memory locking, memory allocation, privilege escalation).
- `src/simd_ops.cpp`: SSE/AVX/NEON optimized pattern writing and verification loops.
- `src/Logger.cpp`: Async logging implementation (background writer thread, rate-limited console output, queue backpressure).
- `include/Logger.h`: Logger class declaration and LOG_* macros.

## Key Design Decisions
- Process runs at NORMAL priority (not elevated) to avoid semi-freezing Windows.
- Logger split into header (.h) + implementation (.cpp) to reduce compile-time overhead per translation unit.
- `flush_cache_region` caches `getCapabilities()` once per call to avoid repeated function call overhead in hot loops.
- SIMD dispatch uses `#if`/`else`/`#if` chains (not `#elif`) so SSE2 NT-store path is available as runtime fallback in AVX2-compiled builds.
- MovingInversionLFSR Phase 4 uses backward march with pre-computed LFSR seed table for correct address-line coverage.
- Signal handler uses `memory_order_release` for `g_shutdown_initiated` to ensure stop flag visibility to workers.

## Build Tools
- `python build.py --lint`: Runs clang-tidy static analysis (requires `--compile-commands` or generates automatically).
- `python build.py --fuzz`: Builds fuzzing harness for preset/config parsers (requires Linux or MSVC/Clang-cl; libFuzzer unavailable on Windows MinGW).
- `python build.py --tests`: Builds and runs 27 internal tests (Utils, Preset, Config, SIMD, LFSR, Concurrency, E2E).
- `python build.py --run-sanitizers`: Runs ASan + UBSan builds and tests.

## Test Coverage
- 27 internal tests covering: Utils parsing, Preset loading/validation, Config save/load round-trip, SIMD pattern generation/verification, LFSR vectors, Thread barrier, TestContext, MemoryGuard, Error classification, and E2E tests for SimpleTest, WalkingOnes, MirrorMove128, BlockMove, MovingInversion, MovingInversionLFSR, LFSRPattern, RandomAccess.

Last verified: 2026-06-04
Stale risk: Low
