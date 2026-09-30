# Changelog

## Unreleased

### New

- **Developer and debug tool discovery:** added non-mutating `tools/discover-debug-tools.ps1` to detect installed Windows SDK debuggers (`cdb`, `windbg`, `dumpchk`, `symchk`), MSVC tools, LLVM utilities, and Sysinternals.
- **Local tool path configuration:** added `tool-paths.example.env` for machine-local toolchain, SDK, and symbol path overrides.
- **Security audit and binary tool inventory:** added `llm-wiki/debug-tools-security-audit.md` and `llm-wiki/debug-tools.md` for native Windows and Linux binary hardening inspection, crash diagnosis, and memory testing verification.
- **Engineering and security guidelines:** added mandatory pre-commit and post-commit secret inspection procedures and changelog maintenance guidelines under `llm-wiki/`.

### Improved

- **Startup diagnostics and regression coverage:** added allocation/prefault and configuration debug messages, deterministic preparation-thread exception tests, and real CLI/build-tool regressions to the normal test command.
- **LFSR streaming throughput:** restored non-temporal streaming stores in `fill_lfsr` (MOVNTI on x86_64) so DRAM write stress is sustained during `LFSRPattern` and `MovingInversionLFSR`.
- **RandomAccess DRAM stress:** added cache flush after initial sweep so random reads target physical DRAM rather than CPU cache; clarified `Parameter` configuration handling (<=100 passes, >100 explicit count) with helper and startup warning.
- **RefreshStable background coverage:** introduced a persistent active-half cursor across dwell windows so short retention dwells reliably sweep the entire active half.

### Fixed

- **Linux unlocked-memory startup:** materialize fresh anonymous pages before residency checks so unlocked runs can complete their first test cycle; residency checks remain enforced.
- **Preparation exception handling:** join the preparation display thread during allocation failures and propagate display failures after joining, preserving normal infrastructure-error reporting.
- **Invalid configuration files:** reject malformed, unreadable, or non-file configurations instead of silently running with defaults; a missing optional file and explicit `--no-config` still allow defaults.
- **Static-analysis verification:** generate absolute compilation-database paths, refresh the database for each lint run, and fail on diagnostics, missing commands, skipped sources, or tool failures. Corrected the project diagnostics exposed by actual analysis.
- **Modulo20 disturbance and verification:** corrected false claim regarding untouched cache lines (due to RFO and writeback); switched disturbance to range fills and verification to SIMD `verify_words` using a 1280-word stride-aligned expected table.
- **RowHammer disturbance isolation:** added `DisturbanceWindow` warning annotations for tests that overlap peer workers' RowHammer execution, avoiding false alarms without forcing idle barrier synchronization.

### Changed

- **Test kernel optimization and cleanup:** removed dead `TestContext` status fields and obsolete barrier tests; hoisted `BlockMove` buffer allocations out of iteration loops; added per-invocation debug summaries.

## 1.6 - 2026-09-12

### New

- **Modulo20 pattern test:** officially registered and enabled in `default.cfg` to stress memory cells and bus lines with modulo-20 disturbance sequences.

### Improved

- **Continuous independent worker scheduling:** eliminated lockstep barrier stragglers; workers advance independently across contiguous page-aligned slices and fast workers continue testing until all regions complete requested cycles, sustaining continuous DRAM load.
- **Retention testing with active background stress:** `RefreshStable` now alternates held and active halves with dual polarity, preserving untouched retention dwell while the active half runs address-sensitive memory passes to keep the memory bus and controller active.
- **March test SIMD acceleration:** forward and backward marches (`WalkingBit`, `MovingInversion`, `MovingInversionWalking`) now read and replace patterns at SIMD granularity and verify restored data.
- **BlockMove and MirrorMove128 stress:** `MirrorMove128` now performs actual data movement; `BlockMove` poisons destinations, uses address-sensitive patterns, copies bidirectionally, and validates unaligned tails.
- **RandomAccess concurrency:** expanded to 16 overlapping disjoint lanes with batched memory fences, checking restorations and final full-region integrity.
- **Console UI readability:** reordered status line so error count and elapsed time precede shortened test names, preventing critical status data from being truncated on narrow terminals.

### Fixed

- **Transient error preservation in LFSR:** eliminated transient-losing `memcmp` and scalar re-reads; LFSR verification computes reverse state directly, removing serial seed-table precomputation.
- **RowHammer aggressor and victim bounds:** checks victims promptly, verifies potential victims before reusing aggressor rows, and enforces explicit point budgets across stride variations.
- **Shutdown race condition:** replaced context-pointer-based shutdown flag with a static-lifetime atomic stop flag, eliminating potential asynchronous teardown lifetime races.

### Changed

- **Modular test engine architecture:** decoupled monolithic `TestEngine.cpp` into dedicated test kernel modules (`TestMarch.cpp`, `TestPatterns.cpp`, `TestMemoryTraffic.cpp`, `TestModulo.cpp`, `TestRowHammer.cpp`).

## 1.5 - 2026-06-10

### Improved

- **SIMD MirrorMove128 verification:** accelerated pattern verification via `simd::verify_pattern_pair` across AVX-512, AVX2, SSE2, and scalar paths, completing checks in a single pass with bounded error sampling.
- **Non-temporal stores in scalar fallbacks:** x86_64 scalar fallbacks for linear, xor, and increment patterns now use `_mm_stream_si64` NT stores to preserve DRAM write pressure on baseline binaries.
- **Dual test runners in build system:** `build.py --tests` builds and runs both baseline (SSE2) and `-v3` (AVX2) test runners automatically, with optional `--tests-v4` for AVX-512 hosts.

### Fixed

- **Transient error retention in SIMD verifiers:** SIMD verifiers now spill vector registers directly to a stack buffer upon mismatch detection, preserving transient bit flips that were previously dropped during scalar re-reads.
- **Console and status line collision:** routed all logger console output through `ConsoleDisplay` under a single mutex, eliminating scrambled progress displays and race conditions between logging and status updates.
- **Early log message loss:** initialized logger before configuration and preset resolution so startup warnings and diagnostics are recorded in the log file.
- **Linux hugepage reservation leak:** fixed SIGABRT signal handler to safely restore kernel hugepage reservation (`nr_hugepages`), preventing leaked allocations on abnormal aborts.
- **Windows elevation exit code propagation:** elevation relaunch now waits for the elevated child process and returns its exit code, enabling accurate status reporting in automated scripts.
- **Console error flood prevention:** applied error rate limiting uniformly across all execution states, preventing I/O stalls during severe memory failure storms.
- **Build race in configuration deployment:** serialized `*.cfg` distribution file copying out of parallel target builds.

### Changed

- **Manual binary variant selection:** removed automatic relaunch to `-v3`/`-v4` binaries to avoid lingering parent console windows; added startup warning hints when the CPU supports a higher SIMD level than the running binary.
- **Error classification deduplication:** consolidated duplicated classification loops across march, walking, and block move tests into unified `classifyAndLogErrors`.

## 1.4 - 2026-06-07

### New

- **Automated multi-target build matrix:** `python build.py` defaults to `--toolchain all`, automatically partitioning and compiling all 10 release targets using MinGW (Windows x86_64 variants) and Zig (Linux x86/x64/ARM and Windows ARM64).
- **Static analysis and fuzzing integration:** added `--lint` supporting `clang-tidy` and added a preset fuzzer harness (`tests/fuzz_preset.cpp`) with `--fuzz`.
- **Comprehensive end-to-end regression tests:** added automated tests for `MirrorMove128`, `BlockMove`, `MovingInversion`, `MovingInversionLFSR`, `LFSRPattern`, `RandomAccess`, `ThreadBarrier`, and config recovery.
- **Aggressive defragmentation control:** added `--aggressive-defrag` flag to gate system-wide memory defragmentation, working set trimming, and file cache flushing behind explicit opt-in.

### Improved

- **Safe configuration parsing:** configuration loader parses into an isolated temporary state and commits only on success, preventing partial configuration corruption on parse errors.
- **Strict preset validation:** validated preset tokens, bounds-checked memory parameters against platform pointer sizes, and rejected unsafe control characters.
- **Process priority management:** ensured normal process priority is retained instead of elevating to above-normal, preventing system responsiveness issues during multi-threaded stress.
- **MovingInversionLFSR efficiency:** hoisted LFSR seed calculation out of iteration repeats, eliminating redundant O(N) precomputation passes.

### Fixed

- **Barrier deadlock on asynchronous termination:** synchronized thread barrier stop signaling by latching stop decisions into epoch markers before barrier arrivals, preventing worker thread deadlocks on Ctrl+C.
- **AVX-512 capability detection:** decoupled AVX-512 CPUID detection from compiler `#if` guards so baseline binaries can accurately detect AVX-512 capable processors.
- **MovingInversionLFSR backward march:** reversed phase 4 iteration order to provide proper backward march address line testing.
- **MirrorMove128 observed value reporting:** fixed soft-error logging to record the originally observed corrupted value rather than the subsequent corrected read.
- **RefreshStable responsive shutdown:** divided retention wait cycles into 100 ms intervals, allowing immediate responsiveness to shutdown requests while preserving retention duration.
- **RowHammer undefined behavior:** replaced volatile writes with non-temporal stores (`_mm_stream_si64`) to prevent compiler optimizations and maximize DRAM row disturbance.
- **Signal handler ordering:** ensured stop flags use release memory ordering to ensure prompt visibility across worker threads.

### Security

- **Compiler and binary hardening:** enabled Control Flow Guard (`/guard:cf`), CET Shadow Stack compatibility flags (`/CETCOMPAT`, `-fcf-protection=full`), ASLR, DEP/NX, and stack canaries across supported targets.
- **Preset path traversal protection:** canonicalized preset paths via `std::filesystem::canonical` and rejected traversal sequences or absolute paths from untrusted contexts.

### Changed

- **Logger header decoupling:** split `Logger` into separate header and implementation files (`Logger.h` / `Logger.cpp`), reducing compilation times across translation units.
