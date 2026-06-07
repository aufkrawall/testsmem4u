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
- `src/PresetLoader.cpp` and `src/ConfigManager.cpp`: preset/config parsing, validation, and fail-closed load/save behavior.
- `src/Logger.cpp`: Async logging implementation (background writer thread, rate-limited console output, queue backpressure).
- `include/Logger.h`: Logger class declaration and LOG_* macros.

## Key Design Decisions
- Process runs at NORMAL priority (not elevated) to avoid semi-freezing Windows
  (`Platform::confirmNormalProcessPriority`, never raises priority).
- Logger split into header (.h) + implementation (.cpp) to reduce compile-time overhead per translation unit.
- `flush_cache_region` caches `getCapabilities()` once per call to avoid repeated function call overhead in hot loops.
- SIMD dispatch uses `#if`/`else`/`#if` chains (not `#elif`) so SSE2 NT-store path is available as runtime fallback in AVX2-compiled builds.
- AVX-512 capability (`caps.has_avx512`) is detected unconditionally (not behind
  `#if __AVX512F__`) so the baseline binary can detect AVX-512 HW and relaunch the
  -v4 sibling; AVX-512 *instruction emission* stays `#if __AVX512F__`-guarded.
- MovingInversionLFSR uses a pre-computed LFSR seed table (built once, invariant of
  repeats) for the Phase 4 backward march address-line coverage.
- Worker stop decisions at `ThreadBarrier` boundaries are latched once by thread 0
  into `epoch_stop` BEFORE the barrier and read by all workers AFTER it, so barrier
  arrival counts stay symmetric under async (Ctrl+C) stop — prevents deadlock.
- Signal handler uses `memory_order_release` for `g_shutdown_initiated` to ensure stop flag visibility to workers.
- Preset/config path validation rejects empty paths and control characters, but allows explicit absolute and parent-relative paths after filesystem canonicalization. Unsafe paths are hex-escaped in diagnostics.
- Config loading parses into a temporary copy and only commits on full success; malformed config files must not leave partially-applied settings behind.
- Preset sequence parsing is strict: malformed, empty, or trailing-comma tokens invalidate the sequence instead of silently dropping bad entries. `Enable` is limited to 0/1 and `Pattern Mode` to 0/1/2.
- On Windows, optimized sibling relaunch waits for the v3/v4 child and returns the child exit code, preserving script-visible failures from the optimized binary.

## Build Toolchain Split (important)
- **x86_64 Windows** targets (`windows-x86_64`, `-v3`, `-v4`) build with **mingw**
  (LLVM MinGW) for CFG+CET hardened static PEs. zig's lld rejects `/CETCOMPAT`.
- **Linux (all arches) + Windows-ARM** build with **zig** (cross-compiler). The mingw
  wrapper always targets `x86_64-w64-mingw32`, so it cannot produce these.
- `compatible_toolchains()` enforces this: each target is built with its correct toolchain.
  Default `python build.py` (or `--toolchain all`) builds the full 10-target matrix
  automatically by partitioning targets into mingw and zig groups.
- Toolchain downloads are pinned with SHA-256 checks and ZIP members are validated before extraction to prevent path traversal. Object files live under toolchain/build-mode-specific directories and rebuild when `build.py` changes.

## Build Tools
- `python build.py --lint`: Runs clang-tidy static analysis (requires `--compile-commands` or generates automatically).
- `python build.py --fuzz`: Builds fuzzing harness for preset/config parsers (requires Linux or MSVC/Clang-cl; libFuzzer unavailable on Windows MinGW). The harness uses unique temporary files, including absolute temp paths.
- `python build.py --tests`: Builds and runs 33 internal tests (Utils, strict sequence parsing, Preset, Config, SIMD, LFSR, Concurrency, E2E).
- `python build.py --run-sanitizers`: Runs ASan + UBSan builds and tests.

## Test Coverage
- 33 internal tests covering: Utils parsing, strict Test Sequence parsing, Preset loading/validation, explicit absolute preset paths, Config save/load round-trip and invalid-load rollback, SIMD pattern generation/verification, LFSR vectors, Thread barrier, TestContext, MemoryGuard, Error classification, and E2E tests for SimpleTest, WalkingOnes, MirrorMove128, BlockMove, MovingInversion, MovingInversionLFSR, LFSRPattern, RandomAccess.

Last verified: 2026-06-07
Stale risk: Low
