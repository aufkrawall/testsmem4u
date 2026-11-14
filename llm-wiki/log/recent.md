# Recent Log

## 2026-11-15 - Follow-up review fixes

Review of the November 13-14 commits confirmed that a very large accepted
`Line Stride` wrapped the ILP32 line index and repeatedly rewrote earlier lines.
`fillStridedLines` now caps both the phase count and line increment at the block's
whole-line count. The existing preset-load DEBUG line states this bound; no
logging runs inside the fill loop.

The extended `testStridedSimpleFill` checks exactly one write per word, values
and boundary sentinels for empty/partial-line blocks and large strides. Before
the fix it failed once on baseline (`SIZE_MAX`) and three times on x86
(`UINT32_MAX-1`, `UINT32_MAX`, `SIZE_MAX`). The underlying preset issue affects
32-bit builds; only the C++ helper accepts a 64-bit `SIZE_MAX` stride.

Verification: `python build.py --tests` passes baseline/AVX2/x86 and the 24-test
Python suite (23 passed, one skipped). Full clang-tidy passes all 30 translation
units with warnings as errors. A bounded one-worker, one-cycle CLI run with a 1 MiB window
and `Line Stride=4294967295` verifies exactly 1,048,576 bytes with zero errors and
the stride-bound DEBUG line. Wiki link/orphan checks pass.

## 2026-11-14 - TestMem5-inspired additions and time-limited runs

The user asked to compare an external TestMem5 anta777 Extreme analysis with
testsmem4u and implement every improvement judged worthwhile, plus wizard inputs like
`27GB4h`. Static checks (MT0.dll disassembly, testsmem4u sources) confirmed the
analysis's testsmem4u claims but refuted "pattern mode 0 = constant" (details in
[memory-testing](../memory-testing.md#testmem5-comparison-static-analysis-2026-11-14)).
Commits 1888202..HEAD, one feature each:

- Time limits: wizard/`--memory` `27GB4h`, `--duration`; `RunDeadline` timer;
  `stop_reason` in results and log. Real 2-3 s runs stop on time.
- Preset OS reserve honored (was parsed and ignored); exact percentage arithmetic
  (a 100% window lost up to 99 bytes and refused RAM minus reserve by 1 MB).
- SimpleTest Pattern Mode 3 (per-beat complement, symmetric 32-bit tag) with
  SSE2/AVX2/AVX-512 kernels. Correction found while writing docs: bus data
  scrambling (default on most platforms) means the physical toggling claim only
  holds with scrambling off; changelog/preset/wiki say so.
- Real mirror moves (converging NT kernels), MirrorMove linear and MirrorMove128
  beat data, Parameter = passes; `invert_array` removed.
- `Line Stride` strided SimpleTest fills (+23% per pass at 256).
- Idle-chunk checks (residual data re-verified on the next claim).
- `default.cfg`: Test19, Test4 strided, MirrorMove128 DDR5-aware words, pass
  counts recalibrated by an old/new A/B (old build from a scratch worktree).
- Verification: `python build.py --tests` (baseline/AVX2/x86 + 24 CLI tests),
  zig Linux x86_64/x86 runners in WSL (built by a scratch script; build.py has no
  Linux runner target), `--run-sanitizers`, clang-tidy (full run found one empty
  catch, fixed; changed units re-linted clean), nine release targets, AVX-512 and
  ARM64 `-fsyntax-only` for the new SIMD files (no AVX-512 host), bounded 1-2 GiB
  runs. Not run: full-size 28 GB cycle; AVX-512 and ARM64 kernels not executed.
- Open: hardware efficacy of all new stresses; DBI/scrambling effect on beat
  patterns; whether Line Stride produces row misses despite controller reordering.

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

Older entries: [October 2026](archive-2026-10.md).
