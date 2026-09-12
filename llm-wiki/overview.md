# Overview

## Architecture
testsmem4u is a cross-platform RAM testing utility for Windows and Linux.
It supports locked memory, large pages, and dynamic CPU core affinity targeting.
Binary variant selection (baseline / -v3 AVX2 / -v4 AVX-512) is manual — the user
starts the binary matching their CPU; a startup warning points out when a faster
sibling variant would fit (no auto-relaunch, removed 2026-06-10 by user decision).

## Key Files
- `src/main.cpp`: CLI argument parsing, interactive/non-interactive configuration, and process management.
- `src/TestEngine.cpp`: allocation, dispatch, independent worker scheduling, and monitoring.
- `src/TestPatterns.cpp`, `src/TestMarch.cpp`, `src/TestMemoryTraffic.cpp`, `src/TestModulo.cpp`,
  `src/TestRowHammer.cpp`: algorithm units; `src/simd_verify.cpp` owns first-observation march kernels.
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
  `#if __AVX512F__`) so baseline/v3 binaries can warn that the -v4 variant would
  fit the CPU; AVX-512 *instruction emission* stays `#if __AVX512F__`-guarded.
- MovingInversionLFSR uses the inverse LFSR recurrence for backward traversal;
  no seed-table precomputation is needed, and partial blocks are supported.
- Workers keep fixed page-aligned regions but advance independently; minimum completed
  sequence position defines progress and cycle coverage. No per-test barriers.
- RefreshStable tests disjoint active memory during each held-half retention dwell.
- See [memory-testing.md](memory-testing.md) for algorithms, invariants, measurements,
  fault injection, error classification, and validation limits.
- Signal handler uses `memory_order_release` for `g_shutdown_initiated` to ensure stop flag visibility to workers.
- Preset/config path validation rejects empty paths and control characters, but allows explicit absolute and parent-relative paths after filesystem canonicalization. Unsafe paths are hex-escaped in diagnostics.
- Config loading parses into a temporary copy and only commits on full success; malformed config files must not leave partially-applied settings behind.
- Preset sequence parsing is strict: malformed, empty, or trailing-comma tokens invalidate the sequence instead of silently dropping bad entries. `Enable` is limited to 0/1 and `Pattern Mode` to 0/1/2.
- On Windows, the elevation relaunch waits for the elevated child and returns the child exit code, preserving script-visible failures.
- SIMD verifiers record mismatches from the already-loaded vector register
  (spilled to a stack buffer), never from a second memory read — a transient
  flip seen by the SIMD compare is always counted even if the cell reads back
  correct afterwards. Scalar fallbacks read each element exactly once.
- Per-test mismatch classification (DRAM re-read via `safe_read_u64`, hard/soft
  logging, unverified-overflow accounting, halt-on-error) is centralized in
  `classifyAndLogErrors` (TestEngineInternal.h); tests pass an expected-value lambda.
  Destructive march observations use unverified accounting because the cell was intentionally replaced.
- MirrorMove128 verifies its alternating {param0, param1} pattern before a move,
  after an overlapping one-word rotation, and after restoration with bounded SIMD sampling.
- Logger console output is always rate-limited (also during active testing) and
  routed through `ConsoleDisplay::printLine/printError` so it coordinates with
  the status line under a single mutex. The log file never drops ERR lines
  until queue backpressure (counted + reported). Logger initializes before
  config/preset resolution and is closed/reopened around elevation relaunch.
- x86_64 scalar fill fallbacks (linear/xor/increment) use `_mm_stream_si64` NT
  stores when requested, so baseline (SSE2) binaries keep DRAM write stress.

## Build Toolchain Split (important)
- **x86_64 Windows** targets (`windows-x86_64`, `-v3`, `-v4`) build with **mingw**
  (LLVM MinGW) for CFG+CET hardened static PEs. zig's lld rejects `/CETCOMPAT`.
- **Linux (all arches) + Windows-ARM** build with **zig** (cross-compiler). The mingw
  wrapper always targets `x86_64-w64-mingw32`, so it cannot produce these.
- `compatible_toolchains()` enforces this: each target is built with its correct toolchain.
  Default `python build.py` (or `--toolchain all`) builds the full 9-target matrix
  automatically by partitioning targets into mingw and zig groups.
- Toolchain downloads are pinned with SHA-256 checks and ZIP members are validated before extraction to prevent path traversal. Object files live under toolchain/build-mode-specific directories and rebuild when `build.py` changes.

## Build Tools
- `python build.py --lint`: Runs clang-tidy static analysis (requires `--compile-commands` or generates automatically).
- `python build.py --fuzz`: Builds fuzzing harness for preset/config parsers (requires Linux or MSVC/Clang-cl; libFuzzer unavailable on Windows MinGW). The harness uses unique temporary files, including absolute temp paths.
- `python build.py --tests`: Builds and runs the internal tests twice — an SSE2
  baseline runner and an AVX2 (`-v3`) runner so the AVX2 generate/verify paths
  are exercised. `--tests-v4` adds an AVX-512 runner (requires AVX-512 host).
- `python build.py --run-sanitizers`: Runs ASan + UBSan builds and tests (both ISA runners each).

## Test Coverage
- Internal tests covering: Utils parsing, strict Test Sequence parsing, Preset loading/validation, explicit absolute preset paths, Config save/load round-trip and invalid-load rollback, SIMD pattern generation/verification (including recorded-observed-value pinning and verify_pattern_pair), LFSR vectors, independent workers, TestContext, MemoryGuard, Error classification, and E2E tests for SimpleTest, WalkingOnes, MirrorMove128, BlockMove, MovingInversion, MovingInversionLFSR, LFSRPattern, RandomAccess, Modulo20, active retention, and RowHammer.
- Fault hooks test positive error detection, destructive observation retention, partial blocks,
  cancellation and failed workers; virtual time tests retention without sleeping.

Last verified: 2026-09-12
Stale risk: Medium for hardware effectiveness; see the memory-testing page.
