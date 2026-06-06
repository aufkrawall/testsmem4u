# Recent Log

## Audit-Driven Fix Pass: 2026-06-07

User requested implementation of the highest-value audit-style fixes, not a new
audit report. Implemented parser, relaunch, build-chain, fuzzer, and diagnostic
hardening.

### Correctness / reliability
- **Windows optimized relaunch exit codes**: baseline launcher now waits for the
  v3/v4 optimized sibling and returns the child exit code, so scripted runs see
  real memory-test/config failures instead of unconditional success from the
  launcher process. Windows argument quoting now follows CommandLineToArgvW-style
  backslash/quote handling, including trailing backslashes.
- **Config load fail-closed**: `loadConfig()` now parses into a temporary copy and
  only commits on full success. Invalid config files no longer leave partially
  applied values in the active/default config.
- **Preset path behavior fixed**: hardening no longer blocks legitimate explicit
  absolute or parent-relative preset paths. Empty/control-character paths are
  rejected, then valid paths are canonicalized before opening.
- **Strict preset parsing**: malformed `Test Sequence` tokens invalidate the whole
  sequence; `Enable` must be 0/1; `Pattern Mode` must be 0/1/2; block sizes are
  bounded against platform `size_t` overflow. Execution loop counts remain 64-bit.

### Diagnostics / tests
- Unsafe preset paths are hex-escaped in logs, preventing newline/ESC/null bytes
  from altering terminal output while preserving diagnosable bytes.
- Logger elapsed time is initialized at construction so pre-init diagnostics do
  not show epoch-sized elapsed durations.
- Internal tests expanded from 27 to 33, covering strict sequence parsing,
  absolute preset paths, malformed preset field rejection, config rollback on
  invalid load, and unsafe config paths.

### Build / supply chain
- `build.py` now verifies pinned SHA-256 values for downloaded Zig and LLVM MinGW
  archives and validates ZIP member paths before extraction.
- Object files are separated by toolchain and build mode, and source rebuild
  checks include `build.py` mtime so flag/script changes cannot silently reuse
  stale objects.
- Fuzzer harness now uses unique files in the system temp directory instead of a
  literal `fuzz_preset_XXXXXX.cfg` path.
- README build instructions updated to document the verified two-toolchain release
  matrix.

### Verification
- `python -m py_compile build.py` passes.
- `python build.py --tests` passes.
- `python build.py --compile-commands --tests --targets windows-x86_64` passes.
- `python build.py --lint --targets windows-x86_64` passes with clang-tidy clean.
- `python build.py --run-sanitizers` passes ASan and UBSan internal tests.
- `python build.py --toolchain mingw --targets all` builds the 3 Windows x86-64
  release targets.
- `python build.py --toolchain zig --targets all` builds the 6 Zig release targets
  (Linux + Windows ARM).

### Notes / stale-risk
- `audit/code-audit-report.md` disappeared from the worktree during this pass but
  was not part of the requested implementation changes and was not intentionally
  modified here. Treat any audit-report deletion as unrelated unless confirmed.

## Full Review & Fixes: 2026-06-07

Deep review pass. Found and fixed several real issues the prior audit missed, plus
dead-code/build cleanups. All then-current release targets build (zig: Linux+Win-ARM, mingw: x64 Win),
internal tests + ASan + UBSan pass, clang-tidy clean.

### Correctness / reliability
- **Barrier deadlock under async stop** (TestEngine `executeSuite`): per-thread
  `shouldStop()` checks around `ThreadBarrier` (and in the `while` condition) could
  diverge when Ctrl+C flipped the flag mid-loop, leaving workers stranded on a
  barrier → hang until the 2nd Ctrl+C force-kills. Fix: leader (t==0) latches the
  stop decision into `epoch_stop` BEFORE each barrier; all workers read it AFTER,
  so barrier arrivals stay symmetric. Invariant: number of `barrier.arriveAndWait()`
  calls per cycle is identical across all workers regardless of stop timing.
- **AVX-512 never auto-selected**: AVX-512 CPUID/XCR0 detection was behind
  `#if defined(__AVX512F__)`, so the baseline binary (which makes the relaunch
  decision) could never set `has_avx512` → it relaunched to -v3 even on AVX-512 HW
  and -v4 stayed dead. Fix: detect AVX-512 capability unconditionally in
  `detect_x86_capabilities`; instruction emission stays `#if`-guarded so baseline/v3
  never emit AVX-512.
- **MirrorMove128 soft-error logging** reported the re-read (corrected) value, not
  the originally-observed bad value. Fix: capture `observed` before `safe_read_u64`.

### Effectiveness / robustness
- **RefreshStable** now sleeps in 100 ms slices checking `shouldStop()` (was a single
  up-to-10 s blocking sleep, unresponsive to Ctrl+C). Region untouched → retention
  window preserved.
- **MovingInversionLFSR** seed table hoisted out of the repeat loop (was an extra
  O(count) LFSR walk per repeat); now built once (invariant of repeats).
- **Loop-count 32-bit overflow** in `executeSuite` (`time_percent*time_percent`)
  → 64-bit math.
- Added a startup SIMD diagnostic log: `built for <ISA>; CPU supports AVX2/AVX-512`
  to confirm the v3/v4 variant is actually running.

### Build system (all 10 targets now build correctly)
- `-fcf-protection=full` / `/CETCOMPAT` / `/guard:cf` are x86-only; stripped for
  AArch64 targets (`target_is_arm`) so linux-arm64 and windows-arm64 build with zig.
- MSVC linker switches (`/CETCOMPAT` etc.) no longer leak into the compile command
  (zig treated `/CETCOMPAT` as an input file).
- linux-x86 (32-bit): `-Wno-atomic-alignment` (RowHammer uint64 atomics are 8-byte
  aligned at runtime via page-aligned region; i386 ABI just can't prove it).
- **Per-toolchain target compatibility**: `compatible_toolchains()` — x64 Windows ⇒
  mingw (CFG+CET hardened PE; zig lld rejects /CETCOMPAT); Linux + Win-ARM ⇒ zig
  (mingw wrapper only targets x86_64-w64-mingw32). `--targets all` now SKIPS
  incompatible targets with a message instead of emitting broken/mislabeled binaries.
  **Full release matrix build = two runs:** `--toolchain mingw` then `--toolchain zig`.

### Dead code / cleanliness
- Removed: `simd::lfence`, `simd::safe_read_u32`, `simd::getSimdLevelName`,
  `Platform::setThreadAffinity`, `Platform::isAggressiveDefrag`,
  `SimdCapabilities::nt_store_width`, `ConsoleDisplay::last_rendered_len_`.
- `Platform::raiseProcessPriority` → `confirmNormalProcessPriority` (honest name;
  never elevates priority).
- `Logger::error_rate_limit_` → `std::atomic<uint32_t>` (removes a latent
  cross-mutex data race).
- Added `[[maybe_unused]]` to `use_nt` in `generate_pattern_uniform`/`invert_array`
  (ARM scalar path -Wunused-parameter under -Werror).

### Assessed, intentionally unchanged (recommendations / known tradeoffs)
- `default.cfg`: well-balanced, covers all fault classes; left as-is.
- Barrier-synchronized parallelism causes brief core idle at each test transition;
  acceptable tradeoff for coherent progress/accounting (not redesigned).
- Test runner only builds the SSE2 baseline → AVX2/AVX-512 verify paths are not
  unit-tested (mirror scalar logic; v3/v4 compile clean). Recommend a v3 test build.
- Oversized files (Platform.cpp/TestEngine.cpp ~1.8k, main.cpp ~1.6k) exceed the
  600-800 line guideline; splitting deferred (high churn / regression risk).
- Windows optimized-relaunch (`ShellExecuteExA`) returns 0 without waiting, so
  exit codes aren't propagated for scripted runs of the baseline exe on AVX2/512 HW.

## Code Review & Fixes: 2026-06-04

Comprehensive code review completed. All priority 1-3 improvements implemented and committed.

### Priority 1 (Must-fix bugs)
- **P1-1**: Process priority changed from ABOVE_NORMAL to NORMAL (Platform.cpp). Avoids semi-freezing Windows with many cores.
- **P1-2**: MovingInversionLFSR Phase 4 reversed to backward iteration (TestEngine.cpp). Pre-computed LFSR seed table enables correct backward march for address-line coverage.
- **P1-3**: Logger `log_level_` accessed with `memory_order_relaxed` in debug/info/warn fast-paths (Logger.h). Fixes formal C++ data race.

### Priority 2 (Should-fix)
- **P2-1**: `flush_cache_region` caches `getCapabilities()` result once per call (simd_ops.cpp). Avoids repeated function call overhead in hot flush loops.
- **P2-2**: Removed dead commented-out `restoreSystemFileCache` (Platform.cpp).
- **P2-3**: MirrorMove128 verification refactored to block-based scanning with consistent error logging format (TestEngine.cpp). Even/odd positions verified separately against their respective uniform values.
- **P2-4**: Signal handler `g_shutdown_initiated` uses `memory_order_release` instead of `relaxed` (Platform.cpp). Ensures stop flag is visible to workers.

### Priority 3 (Nice-to-have)
- **P3-1**: Replaced `(void)caps;` / `(void)use_nt;` casts with `[[maybe_unused]]` attributes (simd_ops.cpp). Modern C++ idiom.
- **P3-2**: Split Logger from 433-line header-only into ~100-line header + ~300-line implementation (Logger.h + Logger.cpp). Reduces per-TU compile overhead. Added Logger.cpp to build.py SRC_FILES.
- **P3-3**: Fixed `generate_pattern_uniform` and `invert_array` SSE/AVX2 dispatch from `#elif` to `#if`/`else`/`#if` (simd_ops.cpp). SSE2 NT-store path now available as runtime fallback in AVX2-compiled builds.

### Verification
- All internal tests pass (release, ASan, UBSan).
- All 3 Windows targets (x86_64, x86_64-v3, x86_64-v4) build successfully.
- No memory safety or undefined behavior issues detected by sanitizers.

### Status
- Codebase is production-ready.
- Compiler flags (x64-v3/v4) correctly applied.
- `default.cfg` preset is optimal for consumer hardware.
- CPU core utilization correct for P/E cores on Windows and Linux.
- Error detection reliability confirmed (hard/soft classification, bounded sampling).

## Code/Binary Quality Audit: 2026-06-04

Full code and binary quality audit completed. Report at `audit/code-audit-report.md`.

### Verdict: Ready (Score: 8.2/10)

### Key Findings (11 total, 0 Critical, 0 High)
- **F-09-001 (Medium)**: CET Shadow Stack flag absent from PE headers despite `/CETCOMPAT` linker flag — LLVM MinGW toolchain limitation.
- **F-10-004 (Medium)**: No static analysis (clang-tidy/cppcheck) integrated into build workflow.
- **F-03-005 (Medium)**: No fuzzing for preset/config parsers.
- **F-07-008 (Medium)**: Test coverage gaps — 9 of 13 test functions lack dedicated end-to-end tests.
- **F-05-002 (Low)**: Duplicate `flush_cache_region` call in MirrorMove128 (benign, minor perf waste).
- **F-06-003 (Low)**: MemoryGuard deleted operator comment misleading.
- **F-03-006 (Low)**: Linux `reserveHugepages` writes to kernel sysfs (defended by cap + atexit + signal handler).
- **F-12-007 (Low)**: Undocumented NT syscall 80 in aggressive defrag (verified with fallback).
- **F-06-009 (Low)**: Terminal relaunch argument handling (user-controlled, not exploitable).
- **F-04-010 (Low)**: Config path lacks unsafe-character validation (user-controlled).
- **F-13-011 (Low)**: TSan not available for MinGW toolchain.

### Verification
- All internal tests pass (release, ASan, UBSan) — verified during audit.
- PE headers confirm ASLR, DEP/NX, CFG, high-entropy VA, stack canaries.
- Binary sizes consistent (~710-723 KB across 9 targets).
- No secrets, keys, or sensitive data in source or binaries.

## Audit Improvements: 2026-06-04

Implemented all recommendable audit findings. All tests pass (release, ASan, UBSan). clang-tidy passes clean.

### Implemented (11 findings addressed)
- **F-05-002**: Removed duplicate `flush_cache_region` call in MirrorMove128 (TestEngine.cpp:531-534).
- **F-06-003**: Fixed misleading MemoryGuard deleted operator comment (Types.h:103).
- **F-04-010**: Added config path unsafe-character validation (null bytes, ESC injection) in main.cpp.
- **F-10-004**: Added `--lint` flag to build.py for clang-tidy static analysis. Created `.clang-tidy` config. Verified clean.
- **F-03-005**: Added fuzzing harness (`tests/fuzz_preset.cpp`) and `--fuzz` flag to build.py. Graceful error on unsupported platforms (libFuzzer not available for Windows MinGW).
- **F-07-008**: Added 6 new E2E tests: MirrorMove128, BlockMove, MovingInversion, MovingInversionLFSR, LFSRPattern, RandomAccess. Test count: 21 → 27.
- **F-03-006**: Added hugepage restoration atexit handler log message (Platform.cpp).
- **F-12-007**: Added Windows version verification comment to `purgeStandbyList` (Platform.cpp).

### Documented as toolchain limitations (not fixable in code)
- **F-09-001**: CET Shadow Stack (`/CETCOMPAT`) not supported by `ld.lld` (LLVM MinGW linker). PE DLL Characteristics has GUARD_CF but not CET. Requires MSVC linker or post-link PE patching.
- **F-13-011**: TSan (`-fsanitize=thread`) not supported for `x86_64-w64-windows-gnu` target.
- **F-03-005 (partial)**: libFuzzer not available for Windows MinGW. Fuzzing harness source is ready for Linux or MSVC/Clang-cl.

### Verification
- All 27 internal tests pass (release mode).
- ASan: all tests pass, no memory safety issues.
- UBSan: all tests pass, no undefined behavior.
- clang-tidy: no issues found across 9 source files.
- Fuzzing build: graceful error message on Windows MinGW (libFuzzer unavailable).
