# Recent Log

## 2026-10-14 - RandomAccess false-positive review and 32-bit inversion fix

- Triggered by a user-reported RandomAccess soft error (v1.7, Linux SSE2 baseline,
  mlock'd 4 KiB pages, overclocked RAM). Reviewed fill/sweep/random phases,
  `classifyAndLogErrors`, `safe_read_u64`, SIMD verifiers and worker partitioning:
  no path can invent a mismatch (expected/written formulas match, regions and lane
  bands are disjoint, volatile load cannot be reordered before the same-address
  store, mismatches are recorded from the first load). 1.7's RandomAccess is
  semantically identical to 1.9. Conclusion: the report is very likely genuine.
- Found and fixed a coverage gap: `word_start` was `size_t`, so `~(word_start+idx)`
  on `linux-x86` complemented only 32 bits (upper half zero in both phases). Now
  `uint64_t`. New regression checks memory directly during phase 1.
- Verification: test runner cross-built for `x86-linux-musl` and run in WSL fails
  exactly the new check before the fix and passes all after; native baseline+AVX2
  suites and 20 Python checks (one Linux-only skip) pass.

## 2026-10-14 - Release v1.9

Bumped version string to `1.9` across runtime and changelog:
- Promoted unreleased improvements to `## 1.9 - 2026-10-14` in `CHANGELOG.md`.
- Verified test suite (`python build.py --tests`), static analysis (`--lint`), and runtime sanitizers (`--run-sanitizers`).
- Built all nine release binaries with LLVM MinGW (Windows x86_64 variants with CFG/CET hardening) and Zig (Linux x86/x64/ARM, Windows ARM64).
- Packaged `testsmem4u-1.9-allOS.7z` and published GitHub release `1.9`.

## 2026-10-14 - Reject strict Linux lock failures before prefaulting

- Anonymous allocation now applies THP advice, attempts requested `mlock`, then
  write-prefaults accepted mappings. Strict lock rejection no longer explicitly
  populates a large window first; accepted locked/unlocked/pageable mappings still
  receive private writable pages. HugeTLB allocation remains inherently locked.
- The Linux failure hook checks `mincore` at the lock attempt and requires zero
  resident test pages. This regression failed on the previous production code and
  passes after the fix; accepted pageable fallback is also checked for residency.
  Debug logs identify the pre-prefault lock attempt and skipped prefault on abort.
- Bounded real CLI verification with a child-only zero memlock limit: the 16 MiB
  strict rejection dropped from 4,313 to 213 minor faults and skips prefaulting.
  Locked THP and unlocked 16 MiB runs each complete one cycle with exactly
  16,777,216 bytes verified and zero errors; THP coverage remains full.
- Windows/WSL baseline+AVX2 suites, 20 native Python checks (one Linux-only skip),
  all 11 Linux CLI checks and all five Linux release cross-builds pass. ELF machine
  types and new diagnostic strings were inspected. Strict native static analysis
  passes all production units and the test runner; wiki links/ordering were checked.
  ARM/AVX-512 runtime behavior,
  real THP sysfs writes and system-wide preparation were not exercised.

## 2026-10-13 - Review fixes for the large-page/THP range (4dac99d..0098097)

- THP offer: an expired startup countdown previously reached a blocking `[Y/n]`
  prompt after printing "Starting tests...". `main` now passes `ThpPrompt`
  (AUTOMATION/UNATTENDED/ATTENDED); only an operator who opened the wizard is
  prompted. Answers are trimmed/case-insensitive; `THP setup:` WARN logs became
  INFO because WARN is echoed to the console next to the stream text.
- `hpage_pmd_size` absent now reads as MISSING (legacy global-only) instead of
  READ_ERROR, which made enabled policies fail inspection. Both its readers use
  `memory_pages::parsePageSize`; HugeTLB meminfo parsing is a separate helper.
- RowHammer re-read `/proc/self/smaps` per worker/invocation. Coverage is now
  measured once in `runTests` (`MemoryRegion::page_coverage`, with `total_bytes`
  and `full()`); the regression proves RowHammer no longer queries the OS.
  The allocator's own pre-defrag query remains (second walk at startup only).
- Windows hybrid tail-lock failure freed its chunk with unchecked raw
  `VirtualFree`; it now stays owned by `MappingCleanup`. The new fixture failed
  before the fix. Linux non-strict `mlock` failure is WARN, strict abort ERROR.
- Wizard invalid thread input saved the concrete core count; it now saves
  `Cores=0` (all-core policy) and prints a notice, like empty input.
- Verification per commit: Windows mingw baseline/AVX2 internal suites, 20
  Python regressions (Linux-only one skipped), and zig-built Linux baseline/AVX2
  runners in WSL. Real sysfs THP writes and an interactive Linux countdown were
  not exercised; the prompt-mode decision is covered by stream fixtures.

## 2026-10-13 - Integrate huge-page setup and expand operator documentation

- Linux invokes THP policy setup after final wizard/config resolution and before
  allocation. Disabled effective policy receives an interactive root `[Y/n]`
  recommendation for runtime `madvise`; direct/dry/no-large-page modes never write
  policy. Windows explicitly recommends its privilege offer and explains the
  next-login requirement without requiring a reboot.
- README now details platform setup, elevation/account scope, HugeTLB/THP/native
  allocation, policy inheritance/persistence, coverage, locking and aggressive
  preparation. Removed stale reservation-restoration and missing CLI-report claims.
- New Linux real-CLI regression inherits complete THP disabling only in the child
  process, checks the diagnostic precedes allocation and checks page opt-out skips
  preflight. It fails on the previous binary's missing diagnostic. The native
  policy writer also propagates a real buffered `/dev/full` flush failure.
- Final native/WSL baseline+AVX2 suites and native ASan/UBSan pass. All 19 existing
  Python checks pass; the new Linux-only check is skipped on Windows. Strict native
  analysis passes all units, with changed main/setup/runner rechecked after fixing
  compact enum naming/size and non-throwing test-fixture cleanup. Kernel/THP sysfs
  policies and HugeTLB reservations have not been changed during verification.
- All nine release targets rebuilt after sanitizers; binary signatures/markers,
  sizes and native absence of sanitizer imports were inspected. All 11 Linux CLI
  tests pass, including the new before-allocation/process-disable regression;
  all 20 native Python tests pass with that Linux-only check skipped. Real bounded
  16 MiB runs still obtain full Windows large pages and Linux THP + mlock, verify
  exactly 16,777,216 bytes and complete one cycle with zero errors. Final lifecycle
  checks find no test processes; global/per-size THP policies and pool count are
  unchanged. ARM/AVX-512 runtime behavior and real sysfs writes remain untested.

## 2026-10-13 - Add checked Linux THP setup component

- Added native PMD-size/global policy inspection, inherited process-mode checks,
  and a stream-driven default-Yes runtime `madvise` offer. The component is not
  yet connected to startup; integration and user documentation follow separately.
- Policy/setup fixtures cover modern overrides, legacy controls, consent/EOF,
  non-interactive/unprivileged skips, unsupported policies, write/readback failures
  and changes during confirmation. Native temporary-file fixtures verify exact
  bytes, bounded reads and non-2-MiB control paths without touching real sysfs.
- Windows and WSL baseline/AVX2 internal suites and all 19 Python regressions pass.

## 2026-10-13 - Make wizard defaults and sizing policies comparable

- Both wizards use shared defaults/question order with large pages enabled.
  Input/output streams allow deterministic scripted coverage of the real wizard.
  Main resolves a copy for execution and saves the requested percent/all-core
  policies; explicit values remain explicit. Invalid cycles use three, while
  explicit zero still requests an infinite run.
- Shared window normalization follows preferred native large-page granularity.
  Windows chunk candidates now reach the actual minimum and skip duplicate
  aligned candidates. Worker caps now use native base pages, avoiding invalid
  weighted partition arithmetic when there are more workers than 64-KiB pages.
- Windows/WSL baseline+AVX2 wizard tests and all 19 Python regressions pass.
  All nine release targets, strict native analysis and both native ISA ASan/UBSan
  suites pass, including the final native-page cap correction. Release binaries
  were rebuilt after sanitizers; signatures, sizes and new wizard/preparation
  markers were inspected for all nine, and the native PE has no sanitizer import.
- Real Windows/WSL CLI defaults match policy: 85%/three cycles/locked large-page
  preference; 17 MiB resolves to 16 MiB with large pages and stays 17 MiB when
  disabled. Final 16 MiB allocation checks show full Windows LP and Linux THP +
  mlock, exact bytes/cycle and zero errors. Linux old/fixed/disabled and SIGKILL
  checks still pass with the pool unchanged and no test processes remaining.
  No hardware optimum, full-85%-window coverage or ARM runtime claim is made.

## 2026-10-13 - Preserve Windows LP defaults with bounded preparation

- Native large pages remain the first choice. Chunk fallback uses exact-size
  divisors; incompatible small windows retain their footprint via native pages.
  Owned mapping scopes release partial allocations on exceptions and preserve
  the original size for explicitly permitted pageable fallback after lock failure.
- Aggressive mode tries ordinary full large pages before one system-wide
  preparation/retry; no fixed waits remain. Replaced the incorrect cache-limit
  toggle with the documented cache working-set flush, preserving limit policy.
  Aggregate memory probes no longer imply a broken syscall when concurrent
  allocation masks availability changes; failure/rollback diagnostics are bounded.
- Windows baseline/AVX2 and all 17 Python regressions pass, including new direct,
  exact chunk, hybrid, strict/pageable fallback, small-window and exception cleanup
  fixtures. Cleanup checks record successful free/unmap calls while ownership is
  held, rather than querying addresses that another allocation could reuse.
  Preparation is replaced with a counter; actual global cache flushing
  was deliberately not tested on the active desktop. Strict native analysis
  passes the changed Windows unit in all ISA profiles and the runner. WSL
  baseline/AVX2 fixtures also pass. Removing partial-chunk cleanup in an ignored
  mutation build makes all three owned-chunk regressions fail (exit 1).

## 2026-10-13 - Use process-owned Linux huge pages and measure coverage

- Linux defaults now try compatible existing HugeTLB, then naturally aligned
  THP advice plus write-prefaulting and strict mlock. HugeTLB is non-swappable
  without redundant mlock. Native page sizes drive rounding and worker slices.
- Process-owned THP replaces automatic persistent-pool writes/restoration, fixing
  total-vs-free reservation accounting, concurrent restoration and uncatchable
  kill leaks at their source. Aggressive cache dropping/compaction remains opt-in
  on incomplete coverage, with one synchronous collapse attempt and no sleeps.
- Allocation and RowHammer query smaps coverage. Checked parsing and conservative
  bounds avoid claiming a prefix/full worker slice from aggregate VMA totals;
  unreadable/malformed metadata stays unknown. Details and source anchors are in
  [memory testing](../memory-testing.md#page-allocation-defaults-and-limits).
- New focused portable and Linux syscall-fixture regressions pass in Windows/WSL
  baseline and AVX2 suites, alongside all 17 Python regressions. Linux baseline,
  v3 and v4 release builds pass. Strict native analysis passes all production
  profiles plus the runner after correcting synthetic-test multiplication widths.
- Real 16 MiB comparison: prior Linux binary used locked native pages, fixed
  binary used full THP + mlock, and --no-large-pages used native pages. Each
  completed one cycle with exactly 16,777,216 verified bytes and zero errors.
  SIGKILL after successful aggressive-mode allocation left no process or pool
  change (pool stayed zero; WSL surfaced signal exit as 9). Default Windows used
  full large pages. All checks were bounded; no test processes remain.

## 2026-10-13 - Split native allocation and configuration responsibilities

- Extracted CPU topology, common allocation/cleanup and Windows/Linux allocation
  from Platform.cpp; moved CLI parsing, configuration resolution and the wizard
  out of main.cpp. All affected source units are now below 800 lines.
- This preparatory change retains allocation choices, defaults, pool restoration
  and wizard behavior. Updated the declared build source list and wiki anchors.
- Windows baseline/AVX2 internal suites plus all 17 Python regressions pass;
  Linux baseline/v3/v4 release builds pass with the pinned Zig toolchain.

## 2026-10-13 - Audit large-page defaults and aggressive defrag

- Confirmed large-page preference and strict locking default to enabled on both
  platforms, while `--aggressive-defrag` is opt-in. Windows already tries direct,
  chunked and hybrid large pages; Linux only tries the existing HugeTLB pool by
  default. Automatic pool reservation is tied to aggressive mode.
- Bounded 16 MiB, one-worker/cycle SimpleTest runs with default page switches:
  Windows used full large pages; WSL root with an empty pool used locked standard
  pages. Both verified 16,777,216 bytes with zero errors, exited, and left no test
  processes. Linux pool stayed zero; no aggressive cleanup or pool writes tested.
- Recorded source-verified open Linux findings and OS documentation in
  [memory testing](../memory-testing.md#page-allocation-defaults-and-limits):
  fixed 2 MiB assumptions, redundant mlock-based HugeTLB lock status, total-vs-free
  pool counts, concurrent pool restoration, and absent explicit THP advice/accounting.
  Non-2-MiB and injected-mlock-failure runtime coverage remains unperformed.
- Assessment recommends separating improved allocation from system-wide cleanup
  before changing defaults. This is a recommendation, not a user-approved policy
  change. Runtime code, default behavior and changelog are unchanged.

## 2026-10-13 - Release v1.8

Bumped version string to `1.8` across runtime and changelog:
- Promoted unreleased improvements to `## 1.8 - 2026-10-13` in `CHANGELOG.md`.
- Verified test suite (`python build.py --tests`), static analysis (`--lint`), and runtime sanitizers (`--run-sanitizers`).
- Built all nine release binaries with LLVM MinGW (Windows x86_64 variants with CFG/CET hardening) and Zig (Linux x86/x64/ARM, Windows ARM64).
- Packaged `testsmem4u-1.8-allOS.7z` and published GitHub release `1.8`.

## 2026-10-13 - README Linux swap guidance

- User decision: do not cap default sizing by available memory and do not lower
  worker priority; users are expected to configure swap sensibly. README now
  explains headroom/swap for desktop use with the locked 85% default window.
- Swappiness guidance deliberately only warns against 0: since Linux 5.8 reclaim
  balances anon/file by refault cost (and MGLRU uses refaults), so moderate low
  values differ little from defaults; zram distros use 100-180. Reasoned from
  kernel reclaim design, not measured on a desktop.
- Corrected the stale README claim that Linux never elevates; `main.cpp` relaunches
  through `sudo` unless `--no-elevation` (verified in source).

## 2026-10-13 - Show current-test progress in the status line

- Review follow-up to the reported "stalled" display: long tests (default
  MovingInversion 150 repetitions, roughly 20+ minutes on a 54 GiB desktop run)
  kept the same `T` index, leaving no visible sign of progress within a test.
- Status now reads e.g. `Min C1/3 T4/18 37% | MovingInversion`; `--debug`
  snapshots add `step=x.y%` per listed worker. Details/invariants in
  [memory-testing.md](../memory-testing.md#diagnostics-and-interpretation).
- Verification: native baseline/AVX2 suites pass, including new unit and
  executeSuite checks for loops, march repetitions and retention dwells; a mutation
  permitting nested repetition claims fails two checks. Strict clang-tidy passes.
  A 1 GiB, four-worker AVX2 CLI smoke run showed 0% -> 22% -> 47% -> 70% -> 95%
  during MovingInversion and exited 0 with zero errors.

## 2026-10-13 - Restore Linux hugepage pool on all catchable signals

- Review found `--aggressive-defrag` reservations leaked when the run ended by
  SIGHUP (unhandled) or a second signal (`_exit` skipped the atexit restore).
- Fix: SIGHUP joins the graceful SIGINT/SIGTERM path; the second-signal path calls
  `restoreHugepagesSignalSafe`; the saved count is a lock-free atomic claimed by
  exchange; the atexit handler registers once and logs restore failures.
- Verification (WSL root, 256 MiB, `--aggressive-defrag`, pool 0 -> 130): pre-fix
  binary left 130 pages after HUP, HUP HUP and TERM TERM; fixed binary restored 0
  for INT, INT INT, HUP, HUP HUP and TERM TERM (single HUP prints final results).
  The pool was reset to its original value after each run. No automated test:
  native runners are Windows-hosted and the check needs root plus Linux sysfs.

## 2026-10-13 - Reset SimpleTest fill diagnostics on every repeat

- SimpleTest's constructor-only fill phase left later pattern generation/cache
  flushes labeled `Simple verify`. It now publishes `Simple fill` before each
  internal repeat, retaining the existing verification boundary and byte counts.
- A focused regression fails on the prior code for all three pattern modes. It
  verifies each of three fill transitions happens before a sentinel is overwritten,
  followed by verification and exact live/final totals. No sleeps, clocks or
  per-block logging were added. Sources: `src/TestPatterns.cpp::runSimpleTest`,
  `tests/test_progress_regressions.h::testRepeatedSimplePhases`.
- Native baseline/AVX2 plus all 17 Python regressions pass. Strict clang-tidy
  rechecks the changed production unit in all native ISA profiles and the runner.
  All nine release binaries rebuild and contain the new phase label; signatures
  and sizes are inspected. Native/ISA execution limits remain as recorded below.

## 2026-10-13 - Preserve thread failure recovery under allocation failure

- Review found that the monitor catch block could allocate/throw again before
  recording failure, terminating after already completed verification. A focused
  sustained-allocation-failure regression reproduced exit 86 on the prior code.
- Failure/stop now publish before diagnostics; the first reporter owns a static
  fallback and its detailed message. Monitor cleanup, workers and partial worker
  startup share a non-throwing reporter with one bounded stderr fallback line.
- Permanent tests exercise normal/unknown exceptions and sustained allocation
  failure on monitor and worker threads after actual verification, plus direct
  failure-setting and first-cause retention. Thread-local injection does not alter
  OS memory limits or other threads' allocations. Source anchors and invariants
  are in [memory-testing.md](../memory-testing.md#live-tested-byte-accounting-and-the-apparent-stall-fix).
- Validation: native baseline/AVX2 and all 17 Python regressions, both ISA
  ASan/UBSan suites, full strict clang-tidy plus the updated runner check, and all
  nine release builds pass. Artifact signatures/sizes and the native release PE's
  absence of sanitizer imports are checked. ARM/AVX-512 remain cross-build only.

## 2026-10-13 - Optimize random access and cached disturbance spans

- RandomAccess prepares band starts/sizes once, retaining native remainders and
  exact addresses. Reciprocal remainders and split load/compare arrays were tried
  and rejected after longer comparisons showed no useful throughput gain.
- RandomAccess and RowHammer batch line flushes with one dispatch and MFENCE;
  hammer iterations retain the preceding SFENCE and both aggressor flushes.
- Modulo20 writes nineteen-word cached SIMD spans, excluding every protected word
  even at tails/unaligned starts. Pass flushes and all verified-byte counts remain.
- Added all-offset protected-word sentinels and an actual random transient fault
  hook retaining the originally loaded value after repair. Native baseline/AVX2 and
  all 17 Python regressions pass. Summaries name optimized paths without log storms.
- Default preset, worker/SMT policy, retention dwells, and disturbance budgets are
  unchanged; their hardware optimum is not established by the short measurements.
- Final native baseline/AVX2 plus 17 Python regressions, both ISA ASan/UBSan runs,
  strict clang-tidy and all nine release builds pass. Windows baseline/AVX2 and
  WSL AVX2 complete an 18-entry 64 MiB smoke cycle with zero errors and expected
  diagnostics. Release disassembly confirms direct bulk CLFLUSHOPT loops.
- Final 512 MiB medians show clear one-worker march/LFSR improvements; sixteen
  workers are mostly unchanged, with Modulo20 about 6% higher throughput. Small
  changes are noisy. Method, exact times and hardware limits are in
  [memory-testing.md](../memory-testing.md#2026-10-13-kernel-optimization-check).

## 2026-10-13 - Parallel exact-sequence LFSR generation

- AVX2 fills/expected buffers generate four consecutive states with T^4;
  reverse expected buffers use a 16-entry T^-4 feedback table and forward
  generation. Both return exactly the original scalar boundary state.
- Alignment prefixes/tails retain streaming scalar writes and the fill fence;
  scalar/non-AVX2 targets retain the original recurrence. Added scalar-reference
  tests for all 64 basis seeds, mixed/zero seeds, direction, complement and tails.
- Native baseline/AVX2 and all 17 Python regressions pass, including existing
  partial-reverse, injected-fault, cancellation and live-progress contracts.
- Initial 512 MiB 8/16-worker measurements show mostly bandwidth-limited results;
  no multi-thread speedup or power gain is established by those short samples.
- A one-worker comparison against the pre-task snapshot shows shorter uniform
  march and LFSR times. The harness uses the same pinned release flags, affinity,
  512 MiB region and verified-byte contracts, with a warmup and three samples;
  final combined measurements are recorded below when traffic changes finish.

## 2026-10-13 - Remove cache-flush and uniform-march overhead

- Complete CLFLUSHOPT region/batch loops have one dispatch and a final MFENCE;
  the shipped v1.7 per-line helper calls are removed. Unaligned x86 ranges now
  include both boundary lines. Algorithm flush boundaries remain unchanged.
- Uniform marches use register patterns with dedicated direction/replacement
  paths. Generic-kernel equivalence tests cover unaligned inputs, tails, zero/all-one
  patterns, mismatch observations and capped samples; real phase faults are caught.
- Existing pattern verifiers move to their own translation unit; shared AVX2
  multiplication remains one helper. This keeps SIMD source files below 800 lines.
- Native baseline/AVX2 and all 17 Python regressions pass. Measurements and wider
  validation are recorded as they complete; power/detection gains are unverified.

## 2026-10-13 - Add bounded progress diagnostics and robust status display

- Debug mode adds periodic `Progress:` summaries with aggregate deltas/errors and
  the four least-recently advancing workers' positions, phases, bytes and idle ages.
  Extra workers are counted, phase names capped, and sampling/logging stays in the
  monitor. Workers publish static phase pointers at boundaries; no hot-loop clocks,
  shared byte-counter contention, sleeps or algorithm changes were introduced.
- Narrow status lines prioritize verified bytes, errors and elapsed time. Monitor
  exceptions now log an infrastructure failure and stop/join workers with exact
  collected totals. Virtual time checks diagnostic cadence/caps/ages; a handshake
  reproduces monitor failure after actual verification.
- Windows and WSL Linux baseline/AVX2 suites, all 17 Python regressions,
  ASan/UBSan for both native ISA runners, strict clang-tidy and all nine release
  builds pass. Rebuilt native release binaries after sanitizer runs so `dist/`
  does not retain a sanitizer-dependent baseline application.
- Actual Windows baseline/AVX2 CLI tests show increasing live totals during a
  single 150-repeat march invocation and exactly 30,198,988,800 bytes on completion;
  Linux CLI results also report exact bytes/cycles. All runs are bounded and exited.
- A 300-repeat baseline CLI run additionally exercises the real periodic debug
  snapshot during a march and finishes with exactly 60,397,977,600 bytes, one cycle
  and zero errors. This extends the earlier short smoke only to verify integration.
- README describes totals, diagnostics and existing resource controls. Unknown
  original Linux warning/long-run behavior remains an open reproduction question.

## 2026-10-13 - Fix live progress and final verified-byte results

- Leaf kernels publish completed verification blocks and error deltas to separate
  worker counters. Scoped bindings preserve shared stop/disturbance state; nested
  return-value merges no longer credit work twice. Standalone kernel calls use the
  same accounting through context atomics. Joined totals are folded exactly once.
- Cancellation and exceptions retain completed checks/mismatches; partial cycles
  stay uncredited. Console results and the persistent log now report exact verified
  bytes and completed cycles, with the repeated-read interpretation stated.
- Added deterministic live/peer progress, all-algorithm, configured-sub-block,
  nested retention-error, exception and synthetic 5,000/8,000 GiB regressions.
  The actual CLI regression failed on the prior code's missing total.
- Baseline and AVX2 suites plus all 17 Python regressions pass. See
  [memory-testing.md](../memory-testing.md) for accounting/lifetime invariants.
  The earlier reporting findings below are resolved; the reporter's unobserved
  long-run stall, desktop responsiveness and Linux warning remain unverified.

## 2026-10-13 - Investigate reported tested-byte freeze around 5-8 TB

- Confirmed two unfixed reporting defects: `executeSuite` publishes verified bytes
  only after an entire `runRegionWork` invocation returns, and the final CLI results
  and debug log omit the accumulated tested-byte total. Long internal-repeat tests
  can show a stationary byte total while the clock and memory testing continue.
- Deterministic phase-hook probes with the pinned LLVM MinGW toolchain reproduced
  both baseline/AVX2 paths: 450 verified 64 KiB passes remain invisible live, then
  publish exactly 29,491,200 bytes. Cancellation after 28 passes retains exactly
  1,835,008 bytes internally and credits no completed cycle.
- Synthetic initial totals of 0, 5,000 and 8,000 GiB give identical publication
  behavior and exact arithmetic/formatting. No overflow threshold near the report
  was found; this is not a multi-terabyte endurance run. April v1.3 (`fa89da3`)
  contains the same reporting paths, verified by source inspection only.
- An actual 16 MiB SimpleTest CLI run confirms omitted final byte totals even with
  debug logging. Baseline/AVX2 internal suites and all 16 Python regressions pass;
  they do not test these missing progress/result contracts. All started probes and
  test apps exited; fixtures/binaries/logs remain ignored in `build/`.
- Investigation only: production behavior is unchanged, so no behavioral changelog
  entry or permanent test preserving the defects was added. Follow-up fix/test and
  diagnostic requirements are in [memory-testing.md](../memory-testing.md).
- Original version/configuration, hardware and Linux warning are unavailable.
  Desktop responsiveness, Linux runtime behavior and a permanent computation stall
  remain unverified. Current all-core/85%-of-total-RAM defaults can compete with
  other workloads; normal process priority is confirmed by source inspection.

## 2026-10-13 - Integrate upstream prompt-template updates

- Merged October 2026 baseline updates from `aufkrawall/llm-prompt-templates` into `AGENTS.md`:
  - Rule placement principle: keep always-on rules (gates, precedence, stop conditions) in `AGENTS.md` and detailed reference in `llm-wiki/`.
  - Toolchain/environment substitution guardrail: require declared project toolchain/tools and forbid silent substitution of global or alternate tools.
  - Verification rigor: verify artifact existence and direct output beyond relying only on command exit codes.
  - Reviewable commit workflow: concise title plus short bullet-point body for non-trivial changes; split tasks into small self-contained commits without compiling every intermediate commit.
  - Economical diagnostics: single-line entries, stable prefixes, rate-limited repeats, capped/truncated collections, and verbose logging behind explicit flags.
  - Test apps and computer use: prefer scripted verification, bounded run times with explicit stop conditions, full process lifecycle shutdown, and readiness-gated startup for interdependent processes.
- Updated `CHANGELOG.md` unreleased section with the agent instructions improvements.

## 2026-10-08 - Update README with support and project cross-references

- Added `## Support` section to `README.md` with GitHub Sponsors and Buy Me a Coffee badges.
- Added `## Other projects` section to `README.md` referencing `capture-engine`, `green-curve`, `Shader-Stress`, `obs-indicator`, and GitHub profile repositories.
- Updated `CHANGELOG.md` unreleased section.

## 2026-10-06 - Release v1.7

Bumped version string to `1.7` across runtime and changelog:
- Promoted unreleased improvements to `## 1.7 - 2026-10-06` in `CHANGELOG.md`.
- Verified test suite (`python build.py --tests`), static analysis (`--lint`), and runtime sanitizers (`--run-sanitizers`).
- Built all nine release binaries with LLVM MinGW (Windows x86_64 variants with CFG/CET hardening) and Zig (Linux x86/x64/ARM, Windows ARM64).
- Packaged `testsmem4u-1.7-allOS.7z` and published GitHub release `1.7`.

## 2026-09-30 - Implement runtime, configuration, and analysis review fixes

Resolved all five findings from the review below:

- Linux unlocked mappings receive one volatile write per native page before
  residency checks (`src/Platform.cpp::allocateMemoryRAII`). The RAII guard owns
  the mapping during prefaulting; strict residency checks remain active.
- `include/PreparationStatus.h` stops/joins the display thread on every exit from
  `runTests`, and captures callback exceptions for propagation after joining.
  Completion uses condition-variable notification, rather than a polling delay.
  A test-only allocator callback reproduces the original exception path without
  linker wrappers. Global main also reports startup exceptions with an
  allocation-free stderr fallback when the normal logger is unavailable.
- `loadConfigWithStatus` distinguishes missing from invalid/unreadable files;
  `src/main.cpp::resolveConfiguration` rejects invalid implicit/explicit config.
  Linux libc++ can open a directory and report EOF without `badbit`, so regular
  file validation precedes opening; directories, dangling links, and FIFOs cannot
  silently become defaults or block the parser. The bool load API is retained.
- `tools/build_checks.py` generates absolute database paths/argument arrays and
  fails analysis on warnings/errors, missing commands, skipped files, and tool
  failures, preserving stdout/stderr. `--lint` regenerates its native/test database.
  Standalone database generation preserves explicitly requested cross targets.
- Corrected diagnostics exposed by real analysis: arithmetic widening, loop-bound
  width, pointer null constants, reserved CPUID alias, enum storage, duplicate
  branches, and exception escape from entry points. Naming policy now describes
  existing public/private conventions; bug/performance checks are preserved and
  regression headers are included in analysis.

Regression sources: `tests/test_runtime_regressions.h`, `tests/test_build.py`,
`tests/test_cli.py`, plus fresh-residency assertions in `tests/test_engine_existing.h`.
The normal test command includes real CLI and build-tool coverage. Debug messages
cover allocation choices/results, prefault counts/time, and config load outcomes.

Validation: Windows baseline and AVX2 suites; Linux baseline internal suite under
WSL; real CLI/build-tool regressions; ASan/UBSan for both native ISA runners; all
nine release builds; strict clang-tidy on production/test sources. The original
16 MiB unlocked WSL reproduction now completes one full cycle with zero errors.
AVX-512/ARM validation remains cross-build only. Generated fixtures/logs remain
ignored under `build/review/`; no hardware error-detection improvement is claimed.

## 2026-09-30 - Runtime, configuration, and build-tool review (historical; resolved above)

Reviewed the current scheduler, test kernels, allocation/error paths, configuration
resolution, and lint workflow at `a2cecfa`. Five findings were unfixed at that revision:

- **Linux unlocked startup (P1):** `tryAllocateStandard` creates an untouched
  anonymous mapping, but `executeSuite` calls `checkMemoryResident` before the
  first test writes it. A fresh 16 MiB allocation failed with all 4096 pages
  nonresident and zero test coverage. Reproduction: a one-entry SimpleTest preset,
  `--yes --no-config --no-elevation --no-locked-memory --no-large-pages --memory 16
  --cores 1 --cycles 1`. Reproduced under WSL with a freshly linked baseline Linux
  binary; the equivalent Windows run succeeded. Sources:
  `src/Platform.cpp::tryAllocateStandard` (Linux),
  `src/TestEngine.cpp::executeSuite`.
- **Allocator exception cleanup (P2):** `runTests` starts a preparation thread
  before `allocateMemoryRAII`, but has no scope cleanup to signal/join that thread
  if allocation throws (including allocations made by privilege checks/logging).
  Unwinding destroys a joinable thread and terminates the process before main's
  exception handler can report an infrastructure failure. Reproduced by linking
  the existing baseline test objects with an allocator wrapper that throws;
  `--wrap=_ZN10testsmem4u8Platform18allocateMemoryRAIIEybbb` and a custom terminate
  handler proved termination rather than propagation to the caller. Source:
  `src/TestEngine.cpp::runTests`.
- **Malformed default configuration (P2):** `loadConfig` rejects invalid values
  transactionally, but `resolveConfiguration` falls back to defaults when the
  implicit `config.ini` exists and is invalid. A synthetic config with
  `MemoryWindowMB=16`, `Cores=invalid`, and `Cycles=2` followed by
  `--dry-run --yes --no-elevation --preset <valid-preset>` returned success and
  resolved 85% RAM, every thread, and three cycles. Source:
  `src/main.cpp::resolveConfiguration`.
- **Skipped static analysis (P2):** generated compile databases use
  `directory: "."` and relative file paths. Installed clang-tidy 22.1.6 skips the
  repository sources with "Compile command not found" on stderr and exits zero;
  `run_lint` hides stderr and reports "no issues found". Using absolute directory
  and file paths in an isolated database made analysis run and emit findings.
  Sources: `build.py::write_compile_commands`, `build.py::run_lint`.
- **Lint warning gate (P2):** independently of database lookup, `run_lint` treats
  zero process exit status as clean even when it prints analyzer warnings.
  With a valid isolated database, a synthetic null dereference produced
  `clang-analyzer-core.NullDereference`, yet `run_lint` returned true and printed
  "no issues found". Source: `build.py::run_lint`.

Review-time validation: baseline/SSE2 and AVX2 internal suites passed; Windows x86-64 and Linux
x86-64 baseline/v3/v4 links succeeded. The normal lint command's reported success
is not valid analysis evidence. Earlier "clang-tidy clean" claims are unverified
until the database and result gates are corrected and analysis is rerun. A valid
database currently exposes pre-existing diagnostics; this review did not fix them.
Synthetic reproduction sources and output remain ignored under `build/review/`.
No runtime code changed, so no behavioral changelog entry was added.

## 2026-09-30 - Populate historical releases in CHANGELOG.md

Populated root `CHANGELOG.md` with release entries for v1.6, v1.5, and v1.4, along with current unreleased improvements from the recent workload review pass, following `llm-wiki/changelog-guidelines.md`:
- Documented observable behavior, memory stress characteristics, and SIMD verifier corrections first.
- Formatted entries with concise bold lead-in anchors under standard Keep a Changelog categories (`New`, `Improved`, `Fixed`, `Security`, `Changed`).
- Aligned unreleased items with recent test kernel review fixes and developer tool additions.

## 2026-09-30 - LLM Prompt Templates baseline integration

Integrated missing prompt templates and developer tool guidelines from https://github.com/aufkrawall/llm-prompt-templates:
- Created root `CHANGELOG.md` with Keep a Changelog categories and initial unreleased entries.
- Created `llm-wiki/changelog-guidelines.md` adapting project release conventions and continuous unreleased updates.
- Created `llm-wiki/secret-leak-prevention.md` establishing mandatory pre-commit and post-commit secret checks.
- Created `llm-wiki/debug-tools.md` and `llm-wiki/debug-tools-security-audit.md` covering Windows SDK debuggers, MSVC binary tools, LLVM utilities, Sysinternals (vmmap, procexp), and PE/ELF binary hardening.
- Added non-mutating `tools/discover-debug-tools.ps1` and `tool-paths.example.env` for local developer and debugger tool resolution.
- Updated `AGENTS.md` with secret leak prevention commit gates, changelog rules, diagnostic logging and regression test standards, and Windows tool discovery guidance.
- Updated `.gitignore` to prevent committing local `tool-paths.env` overrides or discovery manifests.

## 2026-09-30 - Review fixes for the v1.6 workload refactor

A high-effort review of 54e3582..cbb33d2 found and fixed:
- LFSR fills (LFSRPattern, MovingInversionLFSR) had regressed to cached scalar
  stores; they now stream via `simd::fill_lfsr` (MOVNTI on x86_64).
- RandomAccess read random cells right after a cached full sweep; the region is now
  flushed first. Its Parameter overload (<=100 passes, >100 explicit count) is now
  a named helper, documented in default.cfg, and warned about at startup.
- Modulo20's claim that protected words are untouched was false at the cache-line
  level (RFO + writeback); comment/cfg/wiki corrected. Disturbance uses range fills
  instead of per-word modulo; verification uses SIMD `verify_words` with a 1280-word
  expected table.
- RefreshStable restarted background work at the active half's first chunk every
  dwell; a persistent cursor now sweeps it fully.
- Independent workers let RowHammer overlap peers' tests. Rejected a lockstep
  barrier (per-cycle idling); added `DisturbanceWindow` WARN annotation instead.
- Removed dead TestContext status fields and an obsolete ThreadBarrier analog test;
  hoisted BlockMove's per-block allocations; added per-invocation debug summaries.

Validation: all nine release targets without warnings; baseline and AVX2 runners;
ASan/UBSan; clang-tidy clean; new regressions for fill_lfsr, RandomAccess parameter
semantics, retention cursor coverage, and DisturbanceWindow overlap rules. Native
AVX2 smoke run (512 MiB unlocked, 8 workers, 7 tests incl. Modulo20/RefreshStable/
RowHammer, 1 cycle): 0 errors in 44 s. Modulo20 took ~4 s per 64 MiB worker region
at default Parameter=3; not benchmarked against the previous implementation.

## 2026-09-12 - Continuous useful RAM testing and verification corrections (v1.6)

The August concurrency audit's claim that static core weights eliminate barrier
stragglers was unsupported. Workers now keep their contiguous page-aligned slices
but advance independently, with minimum completed sequence position defining
whole-region coverage. Fast workers continue actual tests until every region
completes the requested cycles. Partial cycles are not credited; exceptions stop
and join peers. Shutdown uses a static-lifetime atomic, removing the old context
pointer's potential asynchronous teardown lifetime race.

Retention now alternates held/active halves and both polarities, preserving the
configured untouched dwell while the other half runs address-sensitive SimpleTest
passes. No heater or compute-only workload was added. A short 8-worker/512 MiB AVX2
comparison on Ryzen 5700X measured roughly 5% -> 99% worker CPU occupancy in retention;
old 100 ms samples included 0%, while new samples were at least about 91%. This is
process CPU occupancy, not DIMM temperature or measured DRAM bandwidth.

Fixed transient-losing memcmp/re-read LFSR verification, partial backward LFSR block
alignment, misleading separate-pass moving-inversion logic, ignored zero patterns,
and byte-crediting of cancelled work. Marches now read/replace forward and backward
at SIMD granularity and verify restored data; destructive observations count as
unverified errors without an invalid post-overwrite reclassification. LFSR reverse
state removes the serial seed-table precomputation. MirrorMove128 now moves data;
BlockMove uses address-sensitive patterns, poisons destinations, copies both ways,
and checks tails. RandomAccess overlaps 16 disjoint lanes, batches fences, checks
restores and final full-region contents. Modulo20 is registered and in default.cfg.
RowHammer checks victims promptly and checks potential victims before aggressor
reuse, and respects explicit point budgets across stride choices.

The old TestEngine monolith is split by responsibility. New regression coverage
uses deterministic fault hooks, virtual retention time, and a condition-variable
handshake proving worker progress across a peer's blocked test boundary. Existing
E2E tests were split into included headers; build.py tracks those test dependencies.

Validation passed: all nine release targets; baseline/SSE2 and AVX2 unit tests;
ASan and UBSan with both ISA runners; clang-tidy without findings. A 512 MiB locked
RAM smoke run exercised all 18 entries with shortened counts, completed one cycle
on every region in 15.7 seconds, and found zero errors. Its long-name status
truncation exposed a UI issue: error count/time now precede the shortened test name,
with a dedicated regression.

See [memory-testing.md](../memory-testing.md) for current invariants and validation.
Older entries are in [archive-2026-W24.md](archive-2026-W24.md).
