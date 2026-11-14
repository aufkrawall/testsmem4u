# Recent Log

## 2026-11-14 - Review of bb588cd..db63cb2: eight findings checked

An external review listed eight findings; each was checked against code and fixed
where real (commits 9a2fa02..39a3a3c, one per fix). New regression tests were run
with each fix reverted in a scratch mutation build: nine new checks failed, one or
more per mutated fix.

- True, fixed: `runTests` cleared the stop flag, losing a Ctrl+C/close during the
  countdown or wizard (now a latch; returns before allocation). Not true as
  proposed: moving `setFinalResultsPending(false)` before `Logger::deinit` would let
  Windows kill the process before the flush; a post-deinit `LOG_WARN` is dropped
  safely. The exit pause after Ctrl+C is intended.
- True mechanism, different fix: with only reserved CPU sets usable the fallback
  re-added them without topology. The suggested "no fallback" would leave no
  targets (default CPU 0 binds); they are now kept as `cpu-sets-reserved-only`.
- True, fixed: RowHammer whole-MiB truncation (exact bytes now; the review's quoted
  code with a 1,000,000 density clamp did not match the source); budget INFO line
  per RowHammer entry with the real stride range; loop estimate counted dwell ms and
  density (`default.cfg` warned from `--cycles 4`); staggered message with one chunk;
  unused `CpuTarget::weight` removed; Linux topology test assumed sysfs.
- Verification: `python build.py --tests` (baseline/AVX2/x86 + 22 CLI), zig Linux
  x86_64/x86 runners in WSL (also `taskset -c 1,3,5,7` and a mount namespace hiding
  `/sys/devices/system/cpu`), `--run-sanitizers` (ASan/UBSan runners pass; the ASan
  main-binary link failed only because a concurrent CLI check held the exe open),
  `--lint` (one new test warning fixed, re-run clean), per-commit `-fsyntax-only`
  (x86_64 and i686), bounded 16 MiB CLI runs (`--cores 1` staggered no-op line, two
  RowHammer budget lines) and a 12 s `default.cfg --cycles 4` start (estimate 3840).
- Not reproduced on hardware: reserved-only CPU sets (no such host), a real Ctrl+C
  during the countdown (unit-tested at `runTests`).

## 2026-11-14 - Small-window follow-up: RowHammer density, console close

The user's 64 MiB run of the new preset took 5.6 min per cycle and the log had no
time breakdown (window closed). Causes: RowHammer's explicit 250 points per chunk
(~90 s per slice at any size; also scaled with worker count) and a console-close
handler that returned immediately, so Windows killed the process before the summary.
Fixes (bc9b259, f6d4026): Parameter = points per GiB (default unchanged at 2 per
MiB; preset 160), per-stride lines to DEBUG; the close handler now waits for final
results. User re-run: 2.9 min cycle, RefreshStable 90.8% (deliberately time-based,
kept), close event logged and summary present. Suites (Windows 3 runners + CLI),
clang-tidy (two test widening warnings fixed), WSL Linux x86_64 runner pass.

## 2026-11-14 - Detection speed: interleaved default preset, staggered start

User goal: find unstable RAM quickly (28 GB in 2-4 h on the 5700X reference, without
tuning for that CPU only). The user's 64 MiB `default.cfg` run (old layout) projected to
~2 h per cycle at 28 GiB with RandomAccess/RefreshStable/Modulo20/RowHammer first
starting 72-87 min in; TestMem5 anta777 Extreme (local cfg) instead interleaves short
slices and repeats MirrorMove128 8x per cycle. Commits 536710a..HEAD:

- Repeated sequence entries wrote identical data per cycle (pass variation keyed on
  cycle/loop only); now per occurrence (`EnabledSequence::pass`). Regression failed
  before. Single-occurrence presets unchanged.
- `Time by function` run-end lines; startup `Sequence:` composition and
  `Sequence start:` lines; debug `occurrence=k/K`.
- Opt-in staggered start (`Sequence Start=staggered`, `--sequence-start`), default
  aligned. Bounded 128 MiB check: every function first within 0.7 s; RowHammer share
  21.5% -> 34% (hammering slows under concurrent traffic).
- `default.cfg`: 37-entry interleaved sequence, projected ~61 min per cycle at 28 GiB
  (~3.1 h for 3 cycles), longest slice ~2.7 min, every test within ~45 min. Details
  and open questions in [memory-testing](../memory-testing.md#default-preset-layout-interleaved-2026-11-14).
- Verification: `python build.py --tests` (Windows baseline/AVX2/x86 + CLI incl. new
  `--sequence-start` cases), zig Linux x86_64/x86 runners in WSL, `--run-sanitizers`,
  `--lint` (one widening warning in the new test fixed), all nine release targets,
  bounded 128 MiB one-cycle CLI runs (aligned and staggered; RowHammer/RefreshStable
  shortened in a scratch copy). No full-size run (user asked to avoid long tests).
- Open: user's full-size run to confirm the projection; A/B of aligned vs staggered
  on deliberately marginal settings; Test18/RowHammer efficacy.

## 2026-11-14 - Review of the coverage-per-hour commits (97b4e84..196482b)

An external review listed seven findings; all were confirmed against code and, where
possible, reproduced before fixing (commits after 196482b).

- RefreshStable's active half never varied: its background SimpleTest got the pass
  mask pre-XORed into the base and again from `variation`, cancelling it. The
  whole-buffer variation test missed it; now each half is compared (failed before).
- SMT roles came from hardware masks, so under `taskset -c 1,3,5,7` (WSL) every
  usable CPU was an unpaired "sibling" (topology test failed before). Also found:
  Windows 11 let workers bind outside a `start /affinity` mask (old binary ran 16
  workers under mask 0x2 without a bind warning). Windows reports Ryzen preferred
  cores as scheduling classes 0-6, so `heterogeneous` was "yes" even after
  excluding SMT weights; it now compares core types. musl's `_SC_NPROCESSORS_ONLN`
  follows the affinity mask, so Linux affinity-excluded counts read sysfs `online`.
  32-bit `KAFFINITY` shifts are bounded (UB beyond index 31, not reproducible here:
  16-thread host).
- Disabled sequence entries were claimed and released, letting a slow worker
  re-claim its lagging chunk (hook-driven test failed before) and logging 0 s
  completions (42 of them in a 64 MiB 2-cycle run of a `1,0,1` sequence; none now).
- `testIndependentWorkerExecution` window now >= 4 native pages (64 KiB-page
  kernels: one worker, hook deadlock; analysed, not run: no such host).
- Time breakdown dropped stopped invocations' bytes (test failed before).
- NT-fill probe ran CLFLUSHOPT unconditionally; CPUID fallback to CLFLUSH, both
  paths measured equal on Zen 3.
- Changelog topology bullet no longer cites removed region weights. RefreshStable's
  per-chunk dwell share at small worker counts (+100% at `--cores 2`) is real but
  not lost coverage; left for preset rebalancing.
- Verification: `python build.py --tests` (baseline/AVX2/x86 + CLI), zig Linux
  x86_64/x86 runners in WSL with and without `taskset`, all nine release targets,
  bounded 64 MiB CLI runs on Windows (affinity 0x2 and full) and WSL. ARM64 runtime
  and multi-group/>32-CPU Windows hosts untested.
- Open: `CpuTarget::weight` has no consumer (cleanup candidate; removed 2026-11-14 in 965fc09).

## 2026-11-14 - Coverage-per-hour fixes from the detection audit

Verified the 2026-11-13 audit against code and measurements, then implemented the
recommendable items (commits ff30236..HEAD). Dev host: Ryzen 7 5700X, 16 threads,
DDR4, Windows 11; benchmarks used 64 MiB-1 GiB windows, medians, with occasional
background load (noisy to a few percent).

- Audit claims confirmed: identical data every loop/cycle; SMT siblings got half-size
  regions but equal bandwidth (half-size workers finished a 1 GiB SimpleTest run in
  115-146 s while full-size ones exceeded 180 s); NT fill + whole-region flush cost;
  LFSR words were one-bit shifted copies; RandomAccess upper 32 bits constant.
- Found while verifying: Windows CPU-set topology was dead code (`!Allocated` filter
  discarded every ordinary CPU), so core pairing and P/E efficiency classes were never
  used. Fixed (`cpu-sets` source, reserved sets skipped, parked CPUs kept).
- Static per-worker regions replaced by `RegionScheduler` chunks (workers + 2, least
  advanced idle chunk excluding the just-finished one). First version (workers + 1,
  no exclusion) let a slow worker keep its lagging chunk (chunks 40..58 after 40
  cycles); fixed and simulated (`simsched.py`, scratch only). Result: 18 chunks within
  40..43, 40 SimpleTest cycles on 1 GiB in ~8 s instead of ~15 s.
- Pass variation (`TestConfig::variation`, `variationMask`, `regionSeed`), full-width
  RandomAccess values, post-fill flush elision on x86-64 (21.1 vs 19.0 GiB/s), keyed
  one-multiply LFSR output mixing with an SSE2 two-lane path (no loss on SSE2/AVX2
  builds), INFO cycle milestones and run-end `Time breakdown`.
- Rejected: unkeyed `mix64(state)` (shift-commuting, ~3% shifted copies); two-multiply
  mixer on pre-AVX2 builds (7-14% slower); tail-only flushing after cached passes
  (LLC replacement is not LRU); SMT weight tweak (superseded by chunk scheduling).
- Process incident: a commit chained after a gitleaks warning was created with a
  false positive (public golden-ratio constant named `...Key`). The unpushed commit
  was reset and recommitted with the identifier renamed; the session's pre-commit
  script now exits non-zero on any finding.
- Verification: Windows baseline/AVX2/32-bit suites, zig-built Linux baseline/AVX2/
  x86 suites in WSL, all nine release targets build (ARM64 runtime untested), probe
  `tools/probes/nt_fill_cache_probe.cpp` on Zen 3. Bounded CLI runs at 64 MiB-1 GiB.
- Open (rebalanced 2026-11-14, see top entry): default preset rebalancing (shorter cycles, less fixed-pattern share) waited
  for the user's manual full-cycle measurement with the new `Time breakdown`; 512 MiB
  partial data: MirrorMove128 28%, RowHammer 15%, RandomAccess 10%, Walking 10%,
  MirrorMove 9%, MovingInversion 9%, BlockMove 8% of data-proportional time, plus a
  fixed 120 s RefreshStable per chunk per cycle. RowHammer strides (8-64 KiB) likely
  hit open rows in different banks, so few activations: unverified, needs its own
  investigation. P/E-core weights no longer size memory; AMD's manual text on NT-store
  eviction was not retrieved (Zen 3 measured).

## 2026-11-13 - Audit: detection per hour of the default preset (no code changes)

Source review of every kernel plus bounded measurements on the Ryzen 5700X/DDR4 dev
host with the v1.10 AVX2 binary: a partial default cycle (1 GiB, 16 workers, locked
4 KiB pages, `--debug`, stopped after 4.5 min) and a scratch NT-fill/CLFLUSHOPT/verify
microbenchmark. Scratch sources/logs are not in the repository. All items below are
open findings; nothing is implemented. Hardware fault-detection gains are unmeasured.
Status 2026-11-14: verified and largely implemented; see the entry above.

- No detection hole found: first-observation capture, forced rereads, widths and tails
  hold. Baseline `verify_uniform` is scalar and compiles to one load per word
  (standalone `-O3`, without LTO). Release flags contain nothing that weakens checks.
- Identical data every loop and cycle: no kernel receives the loop/cycle index. LFSR
  seed, RandomAccess RNG state and all patterns repeat exactly; only RowHammer varies.
- SMT-secondary weight 50 is wrong for memory-bound work: with equal regions every
  logical CPU gets the same bandwidth share (about 2.3 GiB/s fill, 3.6 GiB/s verify at
  16 threads). Half-size regions therefore finish each test about 2.3x sooner and lap
  the other 67% of the window. Worker 0 (logical CPU 0) was a further 2x outlier.
- Whole-region CLFLUSHOPT after an NT fill adds 31% to fill+verify (per GiB at 16
  threads: fill 0.038 s, flush 0.019 s, verify 0.024 s) with no DRAM traffic. The cost
  is the same after a verify pass and does not scale with threads (about 52 GiB/s
  aggregate at 1 and at 16 threads). Peak here: 26 GiB/s NT fill, 42 GiB/s verify.
- Cycle shape (half-size workers, seconds on 43 MiB regions; RowHammer not reached):
  MirrorMove128 48.8, Walking pair 21.7, RandomAccess 18.6, BlockMove 17.4,
  MirrorMove 16.6, MovingInversion 14.6, five SimpleTests 8.9, MovingInversionWalking
  5.5, MovingInversionLFSR 4.9, Modulo20 3.0, LFSRPattern 1.8; RefreshStable is a
  fixed 120 s. Later tests ran under less contention, so their share is understated.
  Extrapolated to a 27 GiB window, one cycle is roughly 2.5-3 h for full-size regions
  and RandomAccess/RefreshStable/Modulo20/RowHammer first start after about 2 h.
- `lfsrNext` shifts one bit per word, so consecutive words are shifted copies and
  neighbouring data bits carry the same stream one word apart.
- RowHammer strides are 8-64 KiB of virtual address. Unverified claim: same-bank
  adjacent rows are usually 128-512 KiB apart in physical address on dual-channel
  systems, so these strides rarely form a double-sided pair.

## 2026-10-14 - Release v1.10

Bumped version string to `1.10` across runtime and changelog:
- Promoted unreleased improvements to `## 1.10 - 2026-10-14` in `CHANGELOG.md`.
- Verified test suite (`python build.py --tests`), static analysis (`--lint`), and runtime sanitizers (`--run-sanitizers`).
- Built all nine release binaries with LLVM MinGW (Windows x86_64 variants with CFG/CET hardening) and Zig (Linux x86/x64/ARM, Windows ARM64).
- Packaged `testsmem4u-1.10-allOS.7z` and published GitHub release `1.10`.

## 2026-10-14 - Post-1.9 review fixes

- Review of the RandomAccess audit merge found that the 32-bit inversion regression
  could not fail on any automated runner (all were x86_64). `--tests` now adds a
  32-bit `x86` runner (`i686-w64-mingw32` via the pinned llvm-mingw multi-target
  sysroot, run under WOW64; its runtime DLLs come from `i686-w64-mingw32/bin`).
  Reverting `word_start` to `size_t` fails exactly the width check on that runner.
  Enabling it exposed two `%zu`/`SIZE_T` format mismatches in
  `PlatformWindowsMemory.cpp` (`SIZE_T` is `unsigned long` on Win32), now `size_t`.
- x86 flush stride is now capped at 64 bytes (`kMaxFlushStride`): the granule fix
  had dropped the old 16..256 bound and trusted up to 1024, so an over-reported
  granule would skip lines. Startup `Kernels:` debug line now also logs the raw
  advertised granule. Updated fixtures fail on the uncapped implementation.
- `globalWordStart` now returns `uint64_t`, and the generate/verify pattern
  `start_idx` parameters are `uint64_t`, so no caller can repeat the 32-bit
  complement truncation (previously only RandomAccess was widened locally). No
  live defect elsewhere: other callers only add/multiply into 64-bit values.
- `RandomAccess mismatch:` debug lines are capped at 8 per region with a
  `mismatch-batches` total in the summary (a failing DIMM could previously add up
  to three lines per 16 accesses under `--debug`). Verified with a scratch
  (uncommitted) probe: 13 mismatching batches -> 8 detail lines, summary 13. No
  automated test: the test runner has no log-capture API and `Logger` cannot
  restore its level after a DEBUG `init`, so a test would leak state.
- RandomAccess tests use the exported `kRandomAccessLanes`, `kRandomAccessPassLimit`
  and `randomAccessIterations` instead of hard-coded 16/100/formula copies.

## 2026-10-14 - Merge the RandomAccess audit into main

- Integrated the audit regressions, mismatch diagnostics and x86 flush granule fix
  while retaining the independent 32-bit inversion correction and its direct
  memory regression. Changelog/wiki conflicts retain both sets of findings.
- Combined Windows baseline/AVX2 suites, 20 Python checks (one Linux-only skip),
  and WSL Linux x86, x86-64 baseline and AVX2 suites pass. Strict static analysis
  of the merged traffic kernel and test runner passes; wiki links are valid.

## 2026-10-14 - Correct x86 cache-flush geometry after the error audit

- Flush loops now use CPUID.1 EBX[15:8] in eight-byte units with CLFSH validation,
  replacing unreachable AMD detection and wrongly decoded Intel cache-topology
  fields. Existing startup debug logs expose the chosen granule/method. This is a
  coverage/throughput defect; no link to the reported transient error was found.
- Pure decoding and native CPUID regressions pass. An isolated synthetic 32-byte
  CPU fixture fails on the previous 64-byte result and passes after the fix.
- Windows and WSL baseline/AVX2 internal suites pass; all nine pinned-toolchain
  release targets build. Bounded WSL baseline/AVX2 runs alternate RandomAccess and
  address-pattern SimpleTest using 64 MiB, 12 available workers and two complete
  cycles, with locked native pages and locked THP: all four runs find zero errors
  and leave no smoke processes. ARM and AVX-512 runtime behavior remain untested.
- RandomAccess ASan/UBSan baseline/AVX2 checks passed before isolation. The audit
  was developed in a dedicated worktree while another agent owned concurrent main
  edits, including a separate 32-bit inversion-coverage correction.
- Strict native static analysis passes after correcting an implicit-widening
  warning in the new helper; production helper users were rechecked in all three
  compilation-database ISA profiles, plus the baseline test runner. Wiki links and
  semantic scope were checked; no private report paths, logs or captures are tracked.

## 2026-10-14 - Audit RandomAccess false-positive paths

- Reviewed v1.7 and current pattern indices, exclusive worker regions, first-load
  preservation, original/inverted/restored ordering, cache flush/fences and forced
  reread classification. No software false-positive cause was established.
- Added focused clean-boundary and deterministic per-phase transient/persistent
  fault regressions, including large synthetic logical offsets, exact byte totals,
  boundary sentinels and halt/continue behavior. Windows baseline/AVX2 and WSL
  baseline/AVX2 suites pass. Debug-only mismatch summaries identify phase/batch.
- The focused probe passes on v1.7's RandomAccess and SIMD source under the pinned
  Zig 0.14.0 (Clang 19.1.7), baseline and AVX2 release flags. Its only added code is
  the post-load test hook. Deliberately restoring the wrong value produces 446
  assertion failures, establishing that the new coverage detects phase damage.
- Cache-line CPUID decoding was tracked separately (see the correction above),
  rather than treated as an explanation for a transient wrong observation.
  Physical fault attribution remains unproven.

## 2026-10-14 - RandomAccess false-positive review and 32-bit inversion fix

- Triggered by a user-reported RandomAccess soft error (v1.7, Linux SSE2 baseline,
  mlock'd 4 KiB pages, overclocked RAM). Reviewed fill/sweep/random phases,
  `classifyAndLogErrors`, `safe_read_u64`, SIMD verifiers and worker partitioning:
  no false-positive path was identified (expected/written formulas match, regions and lane
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
