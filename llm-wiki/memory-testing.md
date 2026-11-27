# Memory testing: workload and coverage

Last verified: 2026-11-21 for the v1.11 audit fixes (RowHammer >24 KiB minimum
chunk / thread-cap / tail-merge and zero-byte completion guard, non-zero exit
codes on interrupted finite/zero-byte runs, Windows `VirtualLock` without
`SeLockMemoryPrivilege`, `QueryWorkingSetEx` residency checks + standard
prefaulting, full psABI `x86-64-v3`/`v4` CPUID gating, Linux cgroup/`RLIMIT_AS`
+ `< 2 GiB` ILP32 sizing, config save/recovery validation, deferred log file open,
EOF-safe privilege prompt, and scoped terminal relaunch); 2026-11-15 for bounded Line Stride traversal (exactly-once word
writes, boundary sentinels and large-stride regressions) and one-CPU regression
portability; 2026-11-14 for the
TestMem5-inspired additions (real mirror moves,
per-beat complement pattern, Line Stride, idle-chunk checks, time limit, preset OS
reserve; Windows baseline/AVX2/x86 + CLI, WSL Linux x86_64/x86, ASan/UBSan,
clang-tidy on changed units, nine release targets, bounded 1-2 GiB runs incl. an
old/new A/B); 2026-11-14 for the review fixes (startup stop latch, reserved-only
Windows CPU sets, exact-byte RowHammer points and per-entry budget lines, run-length
estimate, staggered no-op message; Windows baseline/AVX2/x86 + CLI, WSL Linux
x86_64/x86 incl. `taskset` and hidden CPU sysfs, ASan/UBSan runners, clang-tidy,
bounded 16 MiB runs); 2026-11-14 for the interleaved default preset, per-occurrence pass
data, opt-in staggered starts and per-function time totals (Windows baseline/AVX2/x86,
WSL Linux x86_64/x86 suites, ASan/UBSan, clang-tidy, nine release targets, bounded
128 MiB runs); also 2026-11-14 for dynamic chunk scheduling (enabled entries only), CPU
targets under restricted affinity (Windows `start /affinity`, WSL `taskset`), pass
data variation (including RefreshStable's active half), full-width RandomAccess values, post-fill flush elision, LFSR output
mixing (SSE2/AVX2 lanes) and cycle timing logs (Windows and WSL suites, bounded
64 MiB-1 GiB runs); 2026-10-14 for RandomAccess false-positive contracts, 32-bit full-width
inversion, x86 flush geometry, release cross-builds and Linux lock-before-prefault
ordering; 2026-10-13 for
page-allocation defaults, native kernel contracts, performance and progress/result
reporting; 2026-09-30 for other runtime paths. Stale risk: medium for hardware effectiveness and unobserved
long-run stalls; low for tested native progress/accounting paths.

## Sources and responsibilities

- `src/TestEngine.cpp`: allocation, dispatch, equal page-aligned chunks served
  dynamically by CPU-bound workers, monitoring, termination, exception containment.
- `src/PlatformMemory.cpp::allocateMemoryRAII` and `include/PreparationStatus.h`:
  prefaulting and exception-safe preparation lifetime.
- `include/RegionScheduler.h`: per-chunk completed position in enabled sequence
  entries (`EnabledSequence` maps position + chunk to slot, cycle, original sequence
  index and data pass; `describeSequence` formats the startup composition line), chunk
  claims (least advanced idle chunk first excluding the worker's just-finished chunk,
  ties to the longest idle), `ChunkLease` and the status line's least advanced chunk;
  the minimum defines completed cycles.
- `src/PlatformCpu.cpp` and `include/CpuTopology.h`: usable CPU targets, SMT roles,
  core-type heterogeneity, affinity-mask bits; worker binding.
- `include/TestProgress.h`, `TestContext` and `VerificationProgress` in
  `include/TestEngineInternal.h`: live per-worker totals, scoped binding, and
  leaf-only verified-byte/error publication; joined totals are exact.
- `include/ProgressDiagnostics.h`: monitor-owned progress ages and periodic,
  capped snapshots; `src/ConsoleDisplay.cpp::formatStatus` preserves primary fields
  before coverage/test-name details on narrow terminals.
- `include/InfrastructureFailure.h` and `TestContext`: non-throwing thread-failure
  reporting, first-cause ownership and static message fallback under allocation failure.
- `include/DisturbanceWindow.h`: flags test invocations that overlapped another
  worker's RowHammer so their errors can be annotated.
- `src/TestPatterns.cpp`: SimpleTest (all pattern modes, Line Stride fills),
  walking bits, and the shared public pattern verification/reporting entry point.
- `src/TestMirror.cpp`, `src/simd_mirror.cpp`: MirrorMove/MirrorMove128 and the
  converging mirror kernels (`mirror_reverse_words/pairs`).
- `src/simd_beat.cpp`, `simd::BeatPattern` in `include/simd_ops.h`: per-beat
  complement generate/verify (SimpleTest Pattern Mode 3, MirrorMove128 data).
- `include/IdleChunkCheck.h`, `src/IdleChunkCheck.cpp`, `ResidualPattern` in
  `include/Types.h`: idle-chunk checks (leftover data re-verified on the next claim).
- `include/RunDeadline.h`, `include/InputSpec.h`: run time limit timer and the
- `include/CgroupMemoryLimit.h`, `include/SimdCpuSupport.h`: hierarchical Linux
  cgroup memory limits and full psABI `x86-64-v2`/`v3`/`v4` + XCR0 feature checks.
  shared memory/time input parser (wizard, `--memory`, `--duration`).
- `src/TestMarch.cpp`: LFSR verification and moving-inversion variants.
- `src/simd_verify.cpp`, `include/MemoryTestKernels.h`: first-observation comparison,
  SIMD read/replace in either direction, and forward/inverse LFSR recurrence.
- `src/simd_patterns_verify.cpp`, `include/SimdPatternMath.h`: existing address,
  uniform and pair verifiers, separated from pattern writers to keep files bounded.
- `src/TestMemoryTraffic.cpp`: active retention, batched random access, block moves.
- `src/TestModulo.cpp`: Modulo-20 protected-word coupling test.
- `src/TestRowHammer.cpp`: heuristic multi-stride disturbance test.
- `include/TestEngineInternal.h`: address reporting, mismatch classification,
  bounded sample accounting, and compile-time-only fault injection hooks.
- `tests/test_engine_regressions.h`: fault injection, partial blocks, virtual-time
  retention, actual worker independence, cancellation, and exception regressions.
- `tests/test_runtime_regressions.h`: fresh unlocked residency/run and preparation
  exception regressions, using condition-variable/promise synchronization.
- `src/ConsoleDisplay.cpp`: compact status with error count/time before the variable-length test name.
- `tests/test_sequence_schedule.h`: occurrence numbering, repeated-entry data,
  staggered slot coverage/first tests, per-function time totals.
- `default.cfg`: 20 test definitions (14 functions) in a 39-entry interleaved
  sequence; see "Default preset layout" below.

## Page-allocation defaults and limits

Sources: `include/testsmem4u.h::Config`, `include/RunConfiguration.h::CliOptions`,
`src/PlatformMemory.cpp::allocateMemory`, `src/PlatformWindowsMemory.cpp`,
`src/PlatformLinuxMemory.cpp`, `include/MemoryPages.h`,
`src/TestEngine.cpp::runTests` and `src/TestRowHammer.cpp`.

Both locking and large-page preference default to enabled; saved config and CLI
overrides can disable them. Large-page preference is best effort, while requested
locking is strict. Aggressive preparation remains opt-in.
Both wizards ask the same questions and default to 85% RAM, all cores, three
cycles, locking, large pages and halt-on-error. `ConfigWizard.cpp` returns the
requested policies (`MemoryWindowMB=0`, `Cores=0` for automatic defaults);
`main.cpp` resolves a copy and saves the original request. Explicit MiB/thread
choices remain explicit. Percentage sizing still uses total RAM, preserving
the previous user decision. Invalid cycles fall back to three; explicit zero
retains infinite runs. Shared native-page normalization applies in CLI and wizard
resolution. Windows chunk candidates include the actual API minimum, and native
base pages cap worker counts as well as partition boundaries.

- Windows uses its native page size and `GetLargePageMinimum` for large pages,
  retaining direct/chunked/hybrid allocation and fully locked standard fallback.
  Chunk sizes must divide the requested window exactly; incompatible small
  windows retain their size through native-page fallback. Partial/single mappings
  are owned during preparation, so exceptions release them. Explicit pageable
  fallback retains the original size after VirtualLock failure.
  Aggressive mode first tries ordinary full LP allocation, then permits one cache
  flush/working-set/standby preparation and retry with hybrid fallback. Cache
  flushing uses `SetSystemFileCacheSize(SIZE_T_MAX, SIZE_T_MAX, 0)`, preserving
  limit policy; the old HARD_DISABLE/HARD_ENABLE sequence changed limits and
  could re-enable them at zero. See the
  [documented cache API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setsystemfilecachesize).
  No fixed sleeps remain. Address collisions are checked and rolled back in
  bounded immediate attempts; physical contiguity is per native large page.
- Linux tries an existing default-size HugeTLB pool only when the requested
  window is compatible with the actual `Hugepagesize`. HugeTLB is inherently
  non-swappable: no redundant `mlock` or memlock-limit dependency is imposed.
- Linux fallback mappings are naturally aligned for the native PMD-sized THP
  target and receive `MADV_HUGEPAGE` before attempting requested `mlock` locking.
  Strict lock failures stop before manual write-prefaulting; accepted locked,
  unlocked and explicitly permitted pageable mappings are still write-prefaulted
  before coverage/residency checks. Unsupported advice or unavailable THPs still
  allow valid locked native pages. `--no-large-pages` skips HugeTLB and requests
  `MADV_NOHUGEPAGE`.
- Linux automatic huge-page allocation is now process-owned THP, replacing the
  previous persistent-pool reservation mechanism. No code writes or restores
  `nr_hugepages`, so SIGKILL/OOM and concurrent administrators cannot strand or
  overwrite a task-owned persistent reservation. Explicit preconfigured HugeTLB
  pools remain supported.
- Linux aggressive mode acts only after incomplete THP coverage: optional root
  cache dropping and synchronous compaction, followed by one process-local
  `MADV_COLLAPSE` attempt (Linux 6.1+). Older kernels fall back on unsupported
  advice. No timing sleeps or persistent-pool writes are used.

All native rounding rejects zero/invalid sizes and arithmetic overflow. Linux
keeps incompatible small windows small rather than rounding them up to a 1 GiB
default HugeTLB page. Aligned anonymous mappings retain ownership of the target
address range while trimming excess ends; failure/exception cleanup owns exactly
the remaining mapping. Worker partitioning uses the OS base page size.

`queryLargePageCoverage` reads Linux `/proc/self/smaps` after preparation and once
in `runTests`, which stores the result in `MemoryRegion::page_coverage`; worker and
sub-block slices inherit it unchanged and RowHammer judges `Coverage::full()` of the
whole allocation (a per-invocation smaps walk scaled with window size and workers). It reports THP coverage and page-size targets alongside explicit
large pages. Per-VMA totals cannot locate partial THPs within a worker/sub-block
slice: report conservative lower/upper bounds, and require the lower bound to
cover the whole slice before treating it as fully large. Missing or malformed
metadata is unknown, never presumed full. Numbers are checked, and filenames or
memory contents are not logged. THP coverage is a snapshot and can later change;
large pages do not establish physical row/bank adjacency or RowHammer efficacy.

Regressions: `tests/test_memory_pages.h` checks rounding/overflow, ARM64-sized
normalization, exact/bounded/unknown/malformed smaps totals and fresh native
allocation. Linux-only process-local syscall fixtures exercise non-2-MiB HugeTLB,
redundant-mlock avoidance, incompatible 1 GiB defaults, unavailable huge pages/
advice, strict lock failure plus unmapping, explicit pageable fallback and
no-large-page advice. The lock-failure hook uses `mincore` to require zero resident
test pages at the lock attempt; it failed before moving prefaulting after the lock
decision. An accepted pageable fallback must still be fully resident. These checks
never modify sysctls or impose timing assumptions. Allocation diagnostics report
`before-prefault=yes` at the lock attempt and `prefault-skipped=yes` on strict abort.
`tests/test_config_wizard.h` drives real wizard streams/preset resolution and
checks defaults, saved policies, explicit settings and invalid/infinite cycles;
`tests/test_cli.py` checks real default/override normalization and saved policies.
Windows syscall fixtures additionally check direct success without preparation,
exact 18-MiB chunking, a 6-MiB LP prefix with locked native tail, exception rollback,
strict lock failure, pageable fallback sizing and a small incompatible window.
Fixtures simulate LP API success with releasable native mappings and replace
preparation with a counter; they never change global caches or cache-limit policy.
A hybrid tail-lock failure fixture requires every committed chunk to be released
through the owning `MappingCleanup` (equal hook allocations/releases); a raw
`VirtualFree` on that path previously bypassed the hook and ignored failures.
The same fixture requires exactly one tail-lock failure: attempts retry address
collisions only, so a rejected `VirtualLock` (a working-set quota decision) ends
retries for that chunk size instead of re-allocating the LP prefix twice more.
Cleanup fixtures record successful OS free/unmap calls while ownership is held,
avoiding assumptions that freed virtual addresses remain unused afterwards.
Actual cache flushing was not exercised on the active desktop; its request is
verified against the documented API, while ordinary LP CLI allocation is exercised.

2026-10-13 bounded 16 MiB, one-worker/cycle SimpleTest verification: Windows used
full native large pages; WSL root (empty HugeTLB pool, THP `madvise`) used full THP
plus mlock. Both verified exactly 16,777,216 bytes with zero errors, exited, and
left no test processes; the Linux pool remained zero. The previous Linux binary
used locked native pages on the same pool/policy. This does not establish large
allocation success, throughput gains, ARM runtime behavior or hardware efficacy.

## THP policy setup component

Sources: `include/HugePageSetup.h`, `src/HugePageSetup.cpp`,
`tests/test_huge_page_setup.h`, `src/main.cpp::main`. Linux startup invokes setup
after final wizard/config resolution and before allocation; dry runs return before
elevation/setup. Windows retains its earlier privilege offer and now explicitly
recommends it, explaining that sign-out/sign-in suffices without a reboot.

- Policy inspection parses the bracketed active sysfs value, rejecting unknown,
  duplicate, malformed or oversized input. It resolves the native PMD-size
  `enabled` override/inheritance using `hpage_pmd_size`, then queries inherited
  process THP restrictions with `PR_GET_THP_DISABLE`. Missing per-size controls
  (including a missing `hpage_pmd_size`, which predates them) use the legacy
  global control; `memory_pages::parsePageSize` is the one parser for that file,
  shared with `Platform::getPreferredLargePageSize`; unreadable controls and unknown process modes
  cannot authorize writes. Complete process disabling is never cleared.
- When effective policy is `never`, stream-driven setup recommends `madvise`
  with `[Y/n]` only for an attended (`ThpPrompt::ATTENDED`: the operator opened
  the wizard during the countdown) privileged run with page preference enabled.
  An expired countdown is `UNATTENDED`: it explains how to receive the offer and
  never reads stdin, because that start promised to proceed automatically.
  Answers are trimmed and case-insensitive (`y`/`yes`/empty accept).
  Modern kernels change the PMD-size control only; older kernels change global
  `enabled`. The offer explains the system-wide scope, runtime persistence and
  immediate applicability. It saves no boot configuration or HugeTLB reservation.
- Closed stdin, invalid/negative input, unprivileged and automated runs cannot
  authorize a write. Confirmation rechecks the snapshot; changed policy requires
  a fresh offer unless it already permits the allocation. Successful writes
  require flush/close success and a fresh effective-policy readback. There are no
  restoration writes, retries, cache changes or defrag-policy changes.
- `ThpPolicyAccess` injects synthetic controls for portable deterministic tests.
  `NativeThpPolicyAccess` additionally has ordinary temporary-directory fixtures
  that verify bounded reads, native non-2-MiB paths and exact output bytes.
  A Linux `/dev/full` fixture verifies buffered flush failure propagation.
  Tests never change real sysfs/process policy. Stable `THP setup:` diagnostics
  record parsed modes, decision, control and errno without raw sysfs contents.
  They are INFO/DEBUG (file-only): `LOG_WARN` echoes to the console, which
  duplicated the operator text already written to the setup stream.

Verified against the [kernel THP controls](https://docs.kernel.org/admin-guide/mm/transhuge.html)
and [process-policy API](https://man7.org/linux/man-pages/man2/PR_GET_THP_DISABLE.2const.html),
2026-10-13. Sysfs has no atomic compare-and-set API: an independent policy manager
can change settings after inspection/readback; allocation coverage remains the
final observation of what the test actually obtained.

## Invariants

Workers keep CPU affinity but no fixed memory (changed 2026-11-13). The window is
split into equal native-page-aligned chunks, workers + `kSpareChunks` (2) when the
window has the pages (one chunk for one worker). A chunk is held by exactly one
worker per test invocation, so cache-line ownership and retention isolation hold
within an invocation; data never has to survive between invocations because every
kernel fills its region first. With chunks >= workers, a worker claiming after its
release always finds an idle chunk, so nobody waits.

Claim policy invariant: least advanced idle chunk, but never the worker's
just-finished chunk while another chunk is idle. Rejected (measured/simulated):
workers + 1 chunks with plain least-advanced claims. The releasing worker's own
chunk is usually the most behind (it was held longest), so a slow worker re-claimed
it forever and that chunk advanced at the slow worker's pace: chunks ended at
40..58 in a 1 GiB 40-cycle run, and a discrete-event simulation with one 2.5x
slower worker of 16 gave the worst chunk 42% of the average rate (no better than
static regions). Exclusion with one spare chunk only rotates chunks FIFO and lets
them drift (spread ~17 tests over 3000 items); two spares add a choice and hold the
worst chunk at 98% of average with a spread of about 6. Real run after the fix
(1 GiB, 16 threads, 40 SimpleTest cycles): 18 chunks within 40..43, 7.8-8.2 s
instead of 14.7-15.5 s. Cost: RefreshStable's fixed dwell runs once per chunk, so
its per-cycle worker time is (workers + 2) / workers of the static layout: +12.5% at
16 workers, but +100% at `--cores 2` (4 chunks, 120 s per chunk per cycle with
`default.cfg`, now as three 40 s slices). The dwell is not idle (the active half runs SimpleTest), so this is
a share question for preset rebalancing, not lost coverage; shortening the dwell
would weaken retention. Open, deliberately unchanged 2026-11-14.

Why: static weighted regions were measured (2026-11-13, 5700X, 16 workers) to finish
tests at very different rates. SMT siblings with half-size regions (weight 50)
finished each test about twice as fast as full-size ones, and even with equal
regions OS noise spread per-worker times from 42 s to 82 s. The slowest region
bounded completed cycles and its cells were tested about half as often. With
chunks, a slow CPU just completes fewer invocations. `CpuTarget::weight` lost its
last consumer with chunk scheduling and was removed 2026-11-14.

Worker CPU targets (`src/PlatformCpu.cpp`, `include/CpuTopology.h`, verified
2026-11-14): only CPUs the process can bind to are targets. Linux iterates
`sched_getaffinity`; Windows skips CPU sets reserved for other processes (unless
nothing else is usable, see below), CPUs outside the process affinity mask of its primary group (Windows 11 accepted thread
binds outside a `start /affinity` mask, so the old code silently overrode it), and
logical indices beyond the `KAFFINITY` width (32 in 32-bit builds, where the shift
was undefined). SMT roles are assigned from the targets afterwards
(`assignSmtRoles`): the lowest usable thread of a (group, core_index) core is its
primary, so a thread whose sibling is excluded is not deprioritised. Linux names a
core by its first hardware sibling (core_id repeats per socket); the Windows
fallback by the lowest bit of its core mask. Targets sort primary threads (and
P-cores) first, which matters when `--cores` < usable CPUs. `heterogeneous` means
different core types (efficiency class or cpu_capacity): Windows reports AMD
preferred-core ranking as scheduling classes 0-6 on identical 5700X cores, and the
old SMT-halved weights made weight comparisons always say yes. Linux affinity-excluded
counts come from `/sys/devices/system/cpu/online` (musl's `_SC_NPROCESSORS_ONLN`
counts the affinity mask). Without readable `thread_siblings_list` files (minimal
containers) Linux reports `affinity-only`; the topology test accepts that (verified
in WSL with `/sys/devices/system/cpu` hidden).

Reserved-only Windows CPU sets (`cpu_topology::selectCpuSetTargets`, fixed
2026-11-14): when the affinity mask allows only CPUs reserved for another process,
workers use those reserved CPUs with their CPU-set topology (source
`cpu-sets-reserved-only`, `PlatformInfo::cpu_sets_reserved_only`, WARN at run
start): there is no other CPU to run on. Previously `targets.empty()` triggered the
logical-processor fallback, which re-added the same CPUs without SMT pairing or
efficiency classes while `reserved-skipped` claimed they were skipped. An empty
target list (and thus the fallback) now means CPU sets offered no usable CPU at all;
if detection ever yields no target (`unavailable`), `selectWorkerTargets` pads with
default `CpuTarget{}` entries (CPU 0 bind attempts; open, low risk: single worker
after `cpu_cores` 0 resolves to 1). Not reproducible on the dev host (no reserved sets);
`testCpuSetReservationsSelectTargets` is synthetic.

Staggered start (opt-in, added 2026-11-14; `PresetInfo::staggered_start` from the
`[Main Section]` key `Sequence Start=aligned|staggered`, `Config::sequence_start`
from `--sequence-start`, which wins; `staggeredSequenceStart`). Chunk c begins at
enabled slot `c * N / chunks` (`EnabledSequence::offset`); `slot = (position +
offset) % N`. Positions still count completed invocations, so `cycle()`,
`startsCycle()` (residency check), the claim policy and completed-cycle counting are
unchanged and every chunk runs every slot once per chunk cycle. Status/diagnostics
resolve the entry with the chunk. Default stays aligned (decided 2026-11-14: opt-in
until A/B data on unstable hardware exists). Observed in a bounded 128 MiB run with
shortened fixed-time tests: every function first ran within 0.7 s (aligned: up to
16.5 s), and RowHammer's worker-time share rose from 21.5% to 34% because hammer
iterations slow down under concurrent streaming traffic (fixed point budget, so time
grows). With RowHammer overlapping everything, the cross-chunk disturbance WARN
fires on most errors elsewhere; the startup INFO line says so. With a single chunk
(`--cores 1`; one worker gets one chunk) or a single enabled entry every offset is
0; `describeSequenceStart` then logs that staggering has no effect (fixed
2026-11-14, previously claimed different concurrent tests).

Each chunk executes the configured sequence in order. Completed cycles are the
minimum across chunks. Faster workers continue real tests, including extra cycles,
until every chunk completes the requested count. Disabled sequence entries are not
scheduled: positions count enabled entries only, and logs, status, diagnostics and
timings use the original sequence index. Walking them as zero-time claims (until
2026-11-14) replaced the worker's just-finished chunk on every release, so a slow
worker could re-claim its lagging chunk; they also logged 0 s completions
(`testDisabledEntriesAreNotScheduled` reproduces the re-claim with hooks). An
empty/all-disabled or undefined sequence fails closed.
The displayed test is the least advanced chunk's next test, not a claim that all
chunks run that test. Mid-test cancellation does not publish a completed boundary
(`ChunkLease` returns the chunk unpublished on every exit path).

Pass data variation (added 2026-11-13; sources `include/Types.h::TestConfig::variation`,
`include/TestEngineInternal.h::variationMask/passVariation/regionSeed`, the worker
loop in `src/TestEngine.cpp`): each invocation gets `variation = pass * loops + loop`
with `pass = EnabledSequence::pass = chunk cycle * K + k` for occurrence k of K of
its test ID among enabled slots (changed 2026-11-14: with `cycle` alone, every
occurrence of a repeated ID in a cycle rewrote identical data; IDs listed once keep
`pass == cycle`, so their data is unchanged; `testRepeatedEntriesUseNewData` failed
before). Occurrences are keyed by test ID, not function: distinct IDs with identical
settings are the preset author's choice. Kernels XOR `variationMask(variation, repetition)` into their pattern
or seed; the mask is zero only for (0, 0), so the first repetition of the first pass
writes exactly the configured data and existing contracts hold. Per kernel: SimpleTest
modes 1/2 vary param0 per repetition, mode 3 varies the beat tag salt (keeps the
configured complement relations); MirrorMove varies its linear base and MirrorMove128
its beat salt once per invocation (the mirror passes then move that data); BlockMove adds mask(v, 0) to its existing
per-repetition step; MovingInversion uses value/complement pairs with a new value
per pair (r / 2); LFSRPattern/MovingInversionLFSR use `regionSeed` (configured seed,
variation, repetition and a chunk/sub-block offset salt; zero state replaced);
Modulo20 and RefreshStable vary their base value (both polarities kept). The
retention background test gets the already-varied base with `variation = 0`: also
passing the pass variation made `runSimpleTest` XOR the same mask again and cancel
it, so the active half never changed (fixed 2026-11-14; the variation test now
compares each half of the region separately). Unchanged on purpose: uniform
SimpleTest values, walking bits, MovingInversionWalking, RowHammer (already seeded
from `std::random_device`). RandomAccess uses `randomAccessValue` (below).
Why: before this, every cycle and loop rewrote identical bits (BlockMove's 200 loops,
MovingInversionLFSR's 50 repetitions on one seed, MovingInversion's 75 identical
pairs), so repeated passes re-tested the same cell/value/neighbour combinations.
On controllers that scramble data per address, a fixed software pattern is one
fixed bit pattern per cell; only changing values reach new combinations.
Regressions: `tests/test_coverage_rate.h` checks each varied kernel stays clean,
writes different data for variation 1, reproduces it, keeps pass 0 exact and
uniform SimpleTest fixed, and that a suite run with two loops in two cycles writes
four different LFSR streams. Diagnostics: test-start debug lines log `loops=` and the
first loop's `variation=`; error lines carry expected values.

Because workers are unsynchronised, one chunk's RowHammer can overlap another
chunk's unrelated test. Chunks are native-page-aligned but DRAM rows are larger, so
hammering near a boundary can flip a peer's cells. This is accepted (a lockstep
RowHammer barrier would reintroduce idling at every RowHammer slice: two per cycle in
default.cfg, and with a staggered start some chunk is nearly always hammering).
Instead each invocation runs inside a `DisturbanceWindow`; if it
reports errors and any peer RowHammer was active at its start or started during it,
the worker logs a WARN naming the test and region. Disturbers register
active-then-start and observers snapshot start-then-active, so no overlap is missed.

Windows console close/logoff/shutdown (fixed 2026-11-14; `src/Platform.cpp::
consoleCtrlHandler`, `Platform::setFinalResultsPending`, `src/main.cpp` around
`runTests`): Windows terminates the process when the handler returns, so a closed
window lost the time breakdown and results (seen in the user's 64 MiB log). While
results are pending the handler requests the stop, logs `Console close event`, and
waits (no own timeout; Windows enforces its deadline) on a manual-reset event that
main sets after `Logger::deinit` flushed the file. Set/clear order (reset before
raising the flag, signal before dropping it) keeps a concurrent handler from missing
the signal. Close events never force-quit; a second Ctrl+C/Break still does. Verified
by the user closing a real 64 MiB run's window after one cycle: close line, time
breakdown, coverage and results present. Not automatable in the test runner
(CTRL_CLOSE_EVENT cannot be generated programmatically).

Stop requests latch (fixed 2026-11-14): `runTests` cleared `g_stop_requested` on
entry, so a Ctrl+C or close during the startup countdown, wizard or prompts (handler
registered first in `main`) was discarded after `g_shutdown_initiated` was already
set: the suite ran fully and the next Ctrl+C force-quit without results. The flag
is now never cleared (test-only `TestEngine::clearStopRequestForTesting`);
`runTests` returns before allocating with WARN `Stop requested before testing
started`. `testStopBeforeRunIsKept` fails with the old reset. Reviewed and kept:
`Logger::deinit` runs before `setFinalResultsPending(false)` on purpose (the close
wait must cover the log flush; a handler `LOG_WARN` after deinit is dropped by
`pushMessage`'s `running_` check), and the interactive exit pause after Ctrl+C is
intended (Ctrl+C means stop and save; a second Ctrl+C force-quits).

Shutdown no longer dereferences a stack-context pointer asynchronously: a static
atomic outlives every run. Worker exceptions and partial thread-start failures
request stop and join all successfully started workers. ASan/UBSan do not establish
race freedom; the independent-progress and cancellation tests exercise the actual
worker implementation with deterministic condition-variable handshakes.

Linux unlocked anonymous mappings are materialized with one volatile byte write
per native page before `executeSuite` can check residency. Reading zeroes alone
would not establish private backing. The native mapping scope owns the allocation
during prefaulting/logging, then transfers it to `MemoryGuard`; exceptions release
the owned mapping. This initializes pages once, without
weakening runtime residency checks or guaranteeing against subsequent eviction.
`PreparationStatus` always stops/joins its display worker during unwinding and
rethrows callback failures on `finish()`. Its one-second condition-variable timeout
refreshes the UI only; completion signals wake it immediately.

Retention alternates two cache-line-disjoint halves. Each half receives both
configured polarities and is untouched for at least the configured dwell interval.
The other half runs address-sensitive SimpleTest write/verify passes in bounded
chunks. Roles rotate; no held data is used as background traffic. The deadline is
monotonic, and a current verification chunk may finish after the minimum dwell.
The background chunk cursor persists across a side's dwell windows (and flips the
background polarity per full sweep), so short dwells still cover the whole active
half rather than re-testing its first chunks.
An invocation now has four dwell intervals. Inputs smaller than two cache lines
retain an idle fallback because a separate active region is impossible.

LFSR fills (LFSRPattern and MovingInversionLFSR) stream through `simd::fill_lfsr`
with AVX2 vector stores in v3/v4 and MOVNTI in x86_64 scalar prefixes/tails and
baseline builds (plain stores elsewhere), avoiding RFO reads of stale lines;
a 2026-09-12 regression had used cached scalar stores.
LFSR comparisons retain observed values from the original load, eliminating the
old memcmp-then-re-read transient-loss window. Reverse LFSR generation starts from
the terminal state and walks the inverse recurrence; no count-sized seed-table
prepass exists, and partial backward blocks use their actual indices.

Stored LFSR words are `lfsrOutput(state)`: `p = (state ^ kLfsrOutputSalt) * odd;
p ^ (p >> 32)` (changed 2026-11-13, `include/MemoryTestKernels.h`). The state
recurrence, period, reverse traversal and partial-block handling are unchanged; fill
and expected generation both apply the output function (AVX2 four lanes, SSE2 two
lanes with a T^2 state step, scalar for prefixes/tails and other ISAs). Why: one
Galois step per word made consecutive words shifted copies, so neighbouring data
bits saw the same stream one word apart. Pitfall: mixing the raw state is not
enough, even with the two-multiply `mix64`: odd multiplies and xor-shift-right
commute with a one-bit right shift about half the time each, leaving ~3% exact
shifted copies and neighbour bit correlations up to 0.24. The XOR before mixing
removes both; pairwise (lags 1/2/3/8, within-word) and three-bit correlations are at
noise level. Throughput (1 GiB, 16 threads, LFSR tests, medians of 4 runs with some
background load): raw output 21.0 (SSE2 build) / 20.9 (AVX2) GiB/s; one-multiply
20.7 / 20.9; rejected two-multiply `mix64` 17.8 (scalar) or 19.6 (SSE2 lanes) / 20.8.
The expected-table generation runs serially with verification, so its compute cost
appears directly as lost bandwidth on pre-AVX2 builds.
Regression: `testLfsrWordsAreIndependent` (zero shifted copies, 48-52% agreement);
scalar-reference tests compare SIMD output (all alignments/tails) with `lfsrOutput`.

`src/simd_lfsr.cpp` advances four consecutive states with a closed-form T^4
transform in AVX2 lanes. Cached expected generation shares that exact sequence.
Reverse blocks find their initial state with T^-4 and a 16-entry constexpr
feedback table, then generate forward in ascending memory order; the returned
state remains the reverse block's first state. NT stores retain alignment-safe
scalar prefixes/tails and SFENCE. Scalar-reference tests cover every basis bit,
zero/mixed seeds, unaligned starts, complements and partial blocks. Startup and
LFSR summaries report lane width; no logging is added inside generation loops.

Moving inversions read and replace adjacent SIMD vectors forward, then backward,
then verify the restored data. Whole-pass cache flushes remain. This is vector-grain
march coverage, not a claim to control individual physical DRAM transactions. A
destructive mismatch is recorded as unverified, since rereading after intentionally
overwriting the cell cannot classify the original observation as persistent or
transient. It remains an error and honors halt-on-error. Zero is a valid pattern.

Uniform marches use `verify_uniform_words`: the pattern/complement remain in
registers, with separate read/replace and direction specializations. No expected
table is populated or read for a uniform chunk. The vector-grain traversal,
first loaded mismatch values, sample order/caps and scalar tails match
`verify_words`; `tests/test_performance_regressions.h` compares those contracts
directly and injects faults at all three real uniform-march boundaries.

Post-fill flush elision (2026-11-13; `simd::streaming_fill_bypasses_cache` and
`flush_after_streaming_fill` in `src/simd_ops.cpp`): after a pure streaming fill
(`generate_pattern_*` incl. `generate_pattern_beat`, `fill_lfsr`, Line Stride fills
with use_nt) the whole-region flush is skipped on x86-64 when `has_nt_stores` (SSE4.1
era) is set. Invariant: on that path every word, including odd tails, is a
non-temporal store (the uniform tail became MOVNTI for this; beat and strided fills
use MOVNTI for unaligned/odd words); NT stores evict any
cached copy (Intel SDM Vol. 1 "Caching of Temporal vs. Non-Temporal Data"; older
CPUs such as Pentium M could update a cached line in place, but lack SSE4.1).
Measured with `tools/probes/nt_fill_cache_probe.cpp` on Zen 3: reads after an AVX2
or MOVNTI fill of clean or dirty cached lines take DRAM time, equal to after
CLFLUSHOPT (11.3-13.7 us per 256 KiB) against 1.9 us when cached. AMD's own manual
text was not retrieved; run the probe on new CPU families. The probe uses CLFLUSH
where CPUID lacks CLFLUSHOPT (Haswell/Broadwell, pre-Zen; it used to SIGILL there)
and `--clflush` forces it; both measured equal on Zen 3. Kept flushes: after any
load pass (verify sweeps; mirror moves, whose loads cache lines before the NT
stores and also train prefetchers; idle-chunk checks, since the previous test's last
verify blocks may still be cached), march read/replace, memcpy, Modulo20 disturbance,
RefreshStable before verifying the held half (its 64-byte split is not page-aligned,
so prefetchers on the active half can touch it), RowHammer final sweep, and
everything on ARM64/32-bit x86/non-SSE4.1 CPUs. Rejected: flushing only a
cache-sized tail after cached passes; LLC replacement is not strict LRU, so older
lines can survive a streaming pass. Effect (1 GiB, 16 threads, SimpleTest): 21.1 vs
19.0 GiB/s verified. The startup `Kernels:` debug line reports `post-fill-flush=`.

On x86, CLFLUSHOPT region and address-batch loops run entirely inside a function
compiled for that instruction. Capability dispatch is outside the loop and each
operation ends with MFENCE. This removes per-line calls/VZEROUPPER observed in
the v1.7 ThinLTO binary. Region flushing aligns the start down to cover every
intersecting cache line; a zero-byte range still fences without flushing. This
does not remove algorithm flushes or claim control over physical DRAM ordering.
Per-march summaries identify the selected pattern path; no per-flush logging is added.

BlockMove uses an address-dependent odd-stride pattern. It verifies both copies,
poisons the return destination, copies in both directions, and checks odd tails.
Mirror moves (since 2026-11-14; until then MirrorMove inverted in place and
MirrorMove128 rotated by one word with memmove, so nothing moved between distant
addresses). Two streams start at both ends of the region, load a 64-byte line each,
and store them swapped while converging (`mirror_reverse_words`: word i <-> count-1-i;
`mirror_reverse_pairs`: 16-byte unit i <-> units-1-i, units kept intact). Stores are
non-temporal; SIMD line paths (SSE2/AVX2/AVX-512) need 64-byte alignment and whole
lines, otherwise a scalar MOVNTI/plain-store path runs. The region is flushed after
each pass and fully verified. MirrorMove data is linear (`base + g * step`, Param1 or
the golden step if 0); after a reversal it is linear again with `base += (2 g0 + count
- 1) step`, `step = -step`, so the existing linear verifier checks every pass.
MirrorMove128 data is a beat pattern (Param0/Param1 even/odd words, tag step
0xD1B54A32D192ED03); `simd::beat_mirrored` gives the pattern after reversing units
(salt += (g0 + units - 1) step, step = -step; involution). A leading odd global word
and an odd final word stay in place and are verified against the original pattern.
Parameter = mirror passes. A word misread during a move is written to the mirrored
position, so its error is reported where it landed and re-reads classify it as hard
(the wrong value was stored); `--debug` logs a per-invocation summary.

Per-beat complement pattern (`simd::BeatPattern`, SimpleTest Pattern Mode 3): global
word g holds `(g odd ? odd : even) ^ beat_tag(salt + (g >> 1) * step)`, where
`beat_tag` copies the low 32 bits into both halves. With odd = ~even, consecutive
64-bit words in a 16-byte unit are complements; with even = X:~X (32-bit halves),
each word's halves are complements, and the symmetric tag preserves both relations.
An odd step makes every 16-byte unit's tag unique within 64 GiB. SimpleTest uses
even = Param0, odd = ~Param0, step = Param1, salt = pass variation. Caveat: memory
controllers that scramble bus data (on by default on most current platforms) XOR an
address-keyed stream into what the bus carries, so the physical full toggling only
holds with scrambling off; the pattern is then still a distinct address-tagged one.

Line Stride (SimpleTest, preset key `Line Stride`, `TestConfig::line_stride`):
`fillStridedLines` writes whole 64-byte lines in the order 0, s, 2s, ..., 1, s+1, ...,
then a partial final line; every word is MOVNTI on x86-64. Verification stays
sequential. Both the phase count and line increment use the stride capped at the
block's whole-line count (fixed 2026-11-15). Previously only the phase count was
capped: a large accepted stride such as `UINT32_MAX` wrapped the ILP32 line index
and revisited earlier lines, causing quadratic writes and delaying stop checks.
`tests/test_beat_mirror.h::testStridedSimpleFill` checks exactly one write per word,
values and the boundary sentinel for empty/partial-line blocks and large strides,
including `UINT32_MAX` and `SIZE_MAX`; it fails with the old increment. Preset-load
DEBUG logs state the requested stride and the per-block cap, with no hot-loop
logging. Measured 2026-11-14 (2 GiB, 16 threads, 5700X): stride 256 costs ~23%
more per fill+verify pass than a sequential fill; the controller's write reordering
likely absorbs part of the intended row-miss effect (unmeasured).

Idle-chunk checks (`IdleChunkCheck.cpp`): kernels that complete with known data set
`TestResult::residual` (SimpleTest all modes, MirrorMove, MirrorMove128 without
lead/tail words, RandomAccess); `runRegionWork` keeps it for sub-blocks only when
every block left the same global-address data (so block-wise mirror moves leave
none). The worker records it per chunk before releasing the lease; the next claim
flushes and re-verifies the whole chunk ("Idle check after <test>") before the entry
runs, then forgets it. Skipped when the claiming worker wrote it and completed
nothing since (single worker). Chunk residual state needs no lock: only the lease
holder touches it and the scheduler mutex orders claim/release. Errors note
cross-chunk RowHammer (started since, or running). Run-end INFO line: checks, GiB,
idle min/avg/max, errors, skips; `--debug` logs each check. Cost: one read pass plus
a flush walk per entry (~1% of verified bytes in a 1 GiB default.cfg run).

Regression portability (`tests/test_idle_check.h::testIdleChunkCheckInSuite`,
`tests/test_time_limit.h::testWizardTimeLimit`; fixed 2026-11-15): requested workers
are capped by the usable CPU targets, so requesting two does not guarantee a peer
under one-CPU affinity. The idle test always checks the single-worker skip contract
and runs its multi-worker corruption injection only with two usable CPUs; a single
`[SKIP]` line states the available count otherwise. The wizard time-input fixture
requests one thread so CPU clamping cannot fail an unrelated parsing assertion.

RandomAccess issues up to 16 independent locations in disjoint address bands,
checks the original, inverted, and restored values, and flushes/fences writes as
a batch. Distinct indices prevent outstanding writes from conflicting. Initial
and final full-region sweeps cover unselected cells and collateral corruption; the
region is flushed after the initial sweep so random reads cannot hit its cached tail.
The configured access count remains exact, including the partial last batch.
Parameter 1-100 (0 = 1) is a pass multiplier; >100 is an explicit per-region access
count (`randomAccessIterations`). executeSuite warns about the latter at startup.
Stored values are `randomAccessValue(word, salt) = salt + word * kRandomAccessStep`
(odd golden-ratio step, so every word stays unique and aliasing remains detectable;
`salt = variationMask(variation, 0)`, also XORed into the RNG state so pass 0 keeps
the original access order). Changed 2026-11-13: the word number itself left the
upper 32 bits constant across the window. The fill uses the linear generator and
sweeps use linear verification with the same salt/step; the debug summary logs the
salt. Tests compare memory with `randomAccessValue` and require distinct upper halves.
Expected/written values use a `uint64_t` word start: a `size_t` complement on
32-bit targets left the upper half unflipped (fixed 2026-10-14, covered by
`tests/test_random_access_width.h`, which only fails on 32-bit runners; the default
`--tests` `x86` runner fails it with the old `size_t` word start). Invariant:
`globalWordStart` and the SIMD pattern `start_idx` parameters are `uint64_t` on
every target (a `static_assert` in the width test guards the former);
verifyAndReport's local `start_idx` stays a `size_t` memory index.

RandomAccess prepares band starts/sizes once, retaining the original native
remainder calculation, RNG sequence, addresses and partial-batch counts. Written
addresses use `flush_cache_lines` with one dispatch/fence. Each volatile read's
original observation is retained; a repaired-after-load fault still counts as soft.
Reciprocal remainders and a separate load-then-compare array were tested but
rejected: longer one-/sixteen-worker measurements showed no throughput gain.

False-positive audit (2026-10-14): `tests/test_random_access.h` exercises clean
original/inverted/restored checks with empty, tiny, uneven and partial-batch regions,
Parameter 0/1/3/100/101/113, exact verified-byte counts, range sentinels and synthetic
logical offsets crossing 32-bit word indices on 64-bit builds. Deterministic
post-load hooks inject and optionally repair a mismatch in each of the three
phases, checking hard/soft classification and halt/continue behavior. No timing
assumptions or actual large allocation are required. The initial Windows and WSL
baseline/AVX2 runs pass. An isolated probe also passes against v1.7's RandomAccess
and SIMD implementation with the pinned Zig 0.14.0/Clang 19.1.7 release flags,
adding only the post-load observation hook to its test build. A deliberate wrong
restoration mutation fails the new checks. These checks cannot prove absence of
compiler or hardware faults on other systems. Mismatch-only `RandomAccess mismatch:` debug lines record
region offset, batch access start, phase, active lanes and sample count; only the
first `kRandomAccessMismatchLogLimit` (8) per region are logged (the eighth says
so), and the region summary line reports the total `mismatch-batches`. The tests
derive lane/observation indices from `kRandomAccessLanes` and access counts from
`randomAccessIterations`/`kRandomAccessPassLimit`, so changing either constant
keeps the per-phase injections aimed at the phase they claim. Existing
error lines retain the original wrong value for soft observations.

The v1.7 algorithm also uses disjoint bands, volatile first loads and a completed
flush/fence before each reread/next phase. Its expected original/restored value is
the allocation-relative byte offset divided by eight; the complement is expected
only in the inverted phase. Workers own disjoint native-page slices. Soft means
the first observation mismatched and the forced reread matched; this classification
does not isolate a DIMM cell from CPU/cache/controller instability. Ordinary locked
pages and independent worker progress do not themselves create data mismatches.

Modulo20 holds one word in every 20 at one polarity while repeatedly writing the
other 19 with its complement. Software never reads or writes a protected word during
disturbance, but it shares a cache line with peers: the RFO fetches it and the flush
writes back the fetched value. So this checks disturbance from complement writes in
the same and neighbouring bursts, not an untouched row. Cache flushes separate passes
and final verification checks every word with `simd::verify_words` against a
1280-word (stride- and vector-aligned) expected table. All offsets and both
polarities run, including short tails. This complements the march tests'
cache/buffering sensitivity; see the primary algorithm descriptions at
[MemTest86](https://www.memtest86.com/tech_memtest-algoritm.html) and
[Memtest86+](https://memtest.org/readme).

`src/simd_traffic.cpp::fill_modulo20` writes a short prefix, then fixed nineteen-word
cached SIMD spans following each protected word, and a bounded tail. No masked
store or read/restore of a protected word is used. The existing 2 MiB cancellation
granularity, repeat flushes and verification layout remain. Sentinel regressions
cover all twenty protected offsets and unaligned/partial spans. RandomAccess and
Modulo20 summaries identify their optimized paths without hot-loop logging.

RowHammer checks the selected victim cache line promptly and checks an upcoming
aggressor before overwriting it, so reusing a former victim cannot silently erase
an earlier flip. Final sweeps still cover all other words. The point budget is
shared across available strides rather than silently expanded to one per stride.

Point budget (`include/TestEngineInternal.h::rowHammerPoints`, changed 2026-11-14):
Parameter is a density in points per GiB of the invoked region (0 = 2048 = the
long-standing 2 per MiB), floor one point per usable stride, cap 100000. Exact
bytes, rounded to nearest (`(bytes * density + 2^29) / 2^30`; products that would
overflow 64 bits return the cap). The first version truncated to whole MiB, giving
sub-MiB blocks only the floor and a 3.6 MiB chunk 29 instead of 35 points at 10000. Until then
an explicit Parameter was an absolute count per region; the interleaved preset's 250
cost ~90 s per chunk regardless of size (user's 64 MiB cycle 5.6 min, 2.9 min after
the fix with RefreshStable then 90.8% of worker time) and scaled with worker count
(more, smaller chunks). Old explicit counts now mean per GiB (changelog migration
note). `testRowHammerPointsFollowDensity`; the engine regression expects one point
per stride and polarity on 256 KiB (Parameter 1 gave 2 victims under the old rule).
Logging: one INFO budget line per RowHammer entry, keyed by test number, density
and block size (`claimRowHammerBudgetLog`, at most 16 per run, reset in `runTests`;
a run-wide flag hid every entry after the first), naming the stride range actually
used (regions of 192 KiB or less drop the 64 KiB stride); per-stride `Sweeping
stride` lines and a per-invocation summary (points, elapsed, errors, `[stopped]`)
are DEBUG.

Aggressor writes retain SFENCE, both line flushes and MFENCE each iteration;
`flush_cache_lines` dispatches the two-address flush once. Victim/reuse checks and
point/iteration budgets are unchanged. The software contracts are regression
tested; physical activation rates and fault-detection gains remain unmeasured.

## Default preset layout (interleaved, 2026-11-14)

Update 2026-11-14 (TestMem5-inspired changes): 39 entries; Test19 (beat SimpleTest,
Param0 0x33333333CCCCCCCC, Time 40) twice per cycle; Test4 with Line Stride 256 and
Time 40 (was 50; strided fills ~25% slower); MirrorMove128 words
0x55555555AAAAAAAA/0xAAAAAAAA55555555. Mirror pass counts recalibrated with an
old/new A/B at 2 GiB (Parameter 10 each: MirrorMove 2.11 -> 1.43 s, MirrorMove128
3.45 -> 1.32 s per invocation): MirrorMove 74 (was 50), MirrorMove128 100 (was 40),
keeping slice lengths (MirrorMove128 ~3.2 min at 28 GiB, from 6.9 s per 57 MiB chunk
x 28 in a 1 GiB run). Projection ~64 min per cycle (new entries ~1.2 min, idle checks
~1%); unconfirmed by a full-size run. The text below describes the 37-entry layout.

Sources: `default.cfg`; projection inputs from the user's 64 MiB `default.cfg` run
(old layout, 18 chunks, 16 workers, Ryzen 7 5700X/DDR4) and a bounded 128 MiB run of
the new layout with RowHammer/RefreshStable shortened (scratch only).

Old layout (one block per test per cycle) projected to 28 GiB (per-chunk invocation
averages x 448; RowHammer by points, RefreshStable fixed): ~2.0 h wall per cycle,
~6 h for 3 cycles; MirrorMove128 27 min at a stretch (25%), RowHammer 19 min (18%),
RandomAccess first at 72 min, RefreshStable 83, Modulo20 85, RowHammer 87. At 64 MiB
RefreshStable's fixed 120 s per chunk showed 87% of worker time; at 28 GiB ~2%, so
small-window shares do not represent full-RAM runs.

New layout: 37 entries; MirrorMove128 x6 (Parameter 40), RandomAccess x3 (2 passes),
RefreshStable x3 (Time 1 = 4 x 10 s dwells; same 120 s total), MirrorMove (50),
BlockMove (Time 50), MovingInversion (40), RowHammer (Parameter 160 points per GiB,
~250 per 28 GiB chunk),
MovingInversionLFSR (25), Modulo20 (1), XOR SimpleTest and new Test18 (XOR, 4 MiB
blocks, 32 repetitions per block: TestMem5's small-block construct), LFSRPattern x2
each; Walking pair (Time 1 = one 64-bit sweep each, was 5) and MovingInversionWalking
once. Projected at 28 GiB: ~55 min per chunk cycle, ~61 min wall (unit costs from the
64 MiB run and per-entry averages of the 128 MiB run agree), ~3.1 h for 3 cycles;
longest slice ~2.7 min; first starts: MirrorMove128 0.3 min, RandomAccess 3,
MovingInversion 6, MirrorMove 10.5, RowHammer 13, RefreshStable 14, BlockMove 18,
Modulo20 22, last (MovingInversionWalking) 43.5. Shares: MirrorMove128 ~29%,
RandomAccess ~12%, MirrorMove/BlockMove ~8% each, MovingInversion ~7%, SimpleTests ~7%.

Rationale: a marginal setting fails at a rate that depends on stress type; until the
sensitive type runs, nothing is found. Interleaving minimises the worst-case time to
first exposure; over a full cycle order does not change exposure, weights do.
TestMem5 anta777 Extreme (inspected locally): 31-entry sequence of only SimpleTest
variants (7 of 13 on 4 MB blocks), MirrorMove x5 and MirrorMove128 x8; RefreshStable
defined but not in the sequence; static per-thread blocks ("1680 MB x 14").
Duration scales with RAM size / memory bandwidth (chunk = window / (workers + 2),
per-worker bandwidth ~ total / workers), not with core count. RefreshStable's
fixed dwells (120 s per chunk per cycle) are the one deliberately time-based entry:
~2% at 28 GiB, ~12% at 8 GiB, ~91% at 64 MiB (measured 2026-11-14: 172 s cycle).
Kept: retention exposure needs wall time and the active half is tested throughout;
scaling the dwell with chunk size was considered and not done (would change the
Parameter meaning and weaken small-window retention). Quick small-window runs can
lower Test11's Parameter.

Open/stale-risk: efficacy of real mirror moves, beat patterns, Line Stride and
idle-chunk checks on marginal hardware is unmeasured; no unstable-hardware
time-to-first-error data for any layout or for aligned vs staggered (suggested protocol: deliberately marginal timing/voltage, several
20-30 min runs per variant, compare `Time by function` and first-error times);
RandomAccess/RowHammer per-access cost at 28 GiB may exceed the small-window
extrapolation (TLB reach, row-buffer misses); Test18 and RowHammer efficacy unmeasured;
the user's full-size run has not yet confirmed the projection.

## TestMem5 comparison (static analysis, 2026-11-14)

Local copy of TestMem5 0.13.1 with anta777 presets, inspected with `llvm-objdump`
(never executed). Verified in `bin/MT0.dll` (exports BlockMove, MemManager,
MirrorMove128, MirrorMove, RefreshStable, SimpleTest): no non-temporal stores and no
CLFLUSH, only cached `movaps` plus `prefetchnta`; `rdtsc` only as pass timing (start
and delta / 1000). MirrorMove (loop at 0x401d79) walks one pointer up from the start
and one down from the end, loads 64 bytes at each and stores them swapped with the
16-byte lanes reversed; MirrorMove128 (0x4020d0) swaps 128-byte blocks in order. The
base pattern generator (0x40224c, called by SimpleTest at 0x401a22 before the mode
transform at 0x4022d0) derives a 16-bit value from the 4 KiB page number
(addr >> 12, + addr >> 28, swapped with its complement by address bit 12), rotates it
per 16-bit word, and alternates value/complement in runs of a geometry-derived width
(8 bytes for the shipped `[Global Memory Setup]`): pattern mode 0 is therefore not a
constant. Mode 1 XORs a fixed mask, mode 2 multiplies by the parameters (pmullw).
Not verified (TM5.exe/TM5.dll not disassembled here): a hidden Test0 background
pattern checked around every block, and `Minutes=0` falling back to 90 minutes.
Adopted: real mirror moves, per-beat complement pattern, strided fills, idle-chunk
checks (a cheaper form of the background pattern: verify what the previous test left
instead of writing an extra pattern), time limits, the OS reserve. Not adopted:
cached 4 MiB loops (they can stay in L3 on current CPUs) and removing flushes.

## Diagnostics and interpretation

### x86 cache-flush geometry

Sources: `include/SimdCacheGeometry.h::x86AdvertisedFlushGranule`/`x86FlushLineSize`,
`src/simd_ops.cpp::detect_x86_capabilities`, `flush_cache_region`,
`tests/test_cache_geometry.h`. Verified 2026-10-14.

The advertised granule comes from CPUID leaf 1, EBX bits 15:8, multiplied by
eight when EDX.CLFSH is present. This field describes both CLFLUSH and CLFLUSHOPT
on Intel/AMD; missing, zero or non-power-of-two values keep the existing 64-byte
fallback. Invariant: the flush stride is `min(granule, kMaxFlushStride = 64)`. A
stride at or below the real line size flushes every line (larger lines are just
flushed more than once); a stride above it skips lines and lets verification read
stale cache, so an over-reported granule (e.g. hypervisor CPUID) must never widen
the stride (cap added 2026-10-14; the first granule fix trusted up to 1024 bytes). The old implementation compared the basic maximum leaf with an extended
leaf number (making its AMD branch unreachable), then decoded Intel leaf-4 EAX
instead of EBX with the wrong scale. A wrong stride can skip cache lines or flush
them redundantly, affecting coverage/throughput rather than inventing a mismatch.
The startup `Kernels:` debug line reports `flush-stride`, the raw
`advertised-granule` (0 = absent/invalid) and the flush method; no additional
hot-path logging is needed.

Synthetic fixtures cover 8..1024-byte power-of-two granules (strides capped at 64),
unrelated EBX fields, missing CLFSH and malformed values; native x86 checks compare runtime capabilities
with the actual CPUID leaf. An isolated process-local CPUID fixture advertising
32-byte flush lines detects 64 before the fix and 32 afterwards. This is synthetic
regression evidence, not a claim of reproducing the defect on affected hardware.
The decoding follows the [Intel CPUID specification](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
and [AMD family-17h CPUID reference](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/55803-ppr-family-17h-model-31h-b0-processors.pdf).

### Runtime observations

- Startup logs describe independent scheduling and active retention. Debug logs
  (`--debug`) identify the CPU topology source (`cpu-sets`, `cpu-sets-reserved-only`,
  `logical-processor-fallback`, `sysfs`, `affinity-only`), usable/SMT-sibling/reserved/affinity-excluded
  CPU counts, core-type heterogeneity, chunk layout, how many sequence entries are
  scheduled, each worker's CPU/core/efficiency and scheduling class/SMT role/parked
  state, and per-chunk test starts and elapsed test durations, plus per-invocation summaries from March/LFSRPattern (seed, errors,
  unverified, time), Modulo20 (per polarity), RefreshStable (per dwell: actual dwell,
  active-half base, active chunks, full sweeps, cursor), RandomAccess (access count), and BlockMove
  (per direction). `[stopped]` marks cancelled invocations.
- Preparation debug logs record requested bytes/lock/large-page choices, the
  resulting allocation, and Linux prefault byte/page counts and elapsed time.
- WARN "... while RowHammer ran on another memory chunk" marks errors that may be
  cross-chunk disturbance rather than a failure specific to the named test.
- Final `Coverage` is the number of complete cycles across every memory chunk.
- INFO startup lines (2026-11-14): `Sequence: N enabled entries per cycle, M
  distinct tests; repeated per cycle: <function>(TestID) xK, ...` (capped at 8) and
  `Sequence start: aligned|staggered (source)` (or `... has no effect with ...`).
  Debug test-start lines add `occurrence=k/K`; `variation=` is the first loop's.
- Run-length estimate (`estimatedTotalLoops`, fixed 2026-11-14): DEBUG `Run-length
  estimate: N loop repetitions`, WARN above `kMaxRecommendedLoops` (100000). Only
  repetition Parameters count (`estimatedRepetitions`: SimpleTest, moves, marches;
  RandomAccess pass counts up to 100; Modulo20 default 3); RefreshStable's dwell ms
  and RowHammer's density counted as repetitions made `default.cfg` warn from 4
  cycles on (31275 per cycle; now 960).
- INFO (file, no `--debug`; `include/SequenceTimings.h`, added 2026-11-13): one
  `Cycle N complete on every chunk after Xs` line per whole-window cycle, and a
  run-end `Time breakdown` header (wall, workers, chunks, chunk MiB, total worker
  seconds) plus one line per sequence entry: share of worker time, completed runs,
  average seconds, `first` (seconds after start of its first invocation), verified
  GiB (including bytes of stopped invocations, which count in the run total; they
  were dropped until 2026-11-14), and `stopped=n/s` for invocations cut short, then
  `Time by function` lines (2026-11-14: per function across its entries; share,
  entries, runs, stopped, earliest first start, verified GiB; disabled entries
  omitted, unreached named). Shares include
  faster workers' extra work after the target, so measure composition with several
  cycles. Workers record once per invocation under one mutex; formatting returns
  strings so `testSequenceTimingSummary` checks it without log capture.
- Byte totals count verified reads, including repeated checks and retention's useful
  active tests. They are neither unique memory coverage nor physical bus traffic.
- The status line follows the least advanced chunk (`findSlowestRegion`: lowest
  completed position, then lowest step; the step is the holding worker's, an idle
  chunk counts as 0) and appends that step as a percentage. The monitor takes one
  locked `RegionScheduler::Snapshot` per sample, so position and holder agree. `ProgressBinding` combines worker loop (`beginLoop`), configured
  sub-block (`runRegionWork` -> `beginBlock`) and the outermost kernel's
  `RepetitionProgress` into one per-worker parts-per-million atomic. Nested kernels
  (RefreshStable's background SimpleTest) cannot claim repetitions. Workers reset
  the step before publishing a completed position, so readers never pair a new
  test index with the previous test's step. Units per kernel: SimpleTest/Mirror*/
  BlockMove/MovingInversion(LFSR) repeats, MovingInversionWalking repeats x 64,
  Walking* 64 bits, Modulo20 2 x offsets, RefreshStable sides x polarities,
  RowHammer 2 x points, RandomAccess accesses (updated every 64Ki). LFSRPattern
  advances only by loops. Covered by `tests/test_step_progress.h`; a mutation
  allowing nested claims fails it.
- Live progress includes completed verification blocks from currently running
  invocations. CLI results and the log also include exact final bytes and completed
  cycles, including partial work from cancellation or worker exceptions.
- `--debug` adds one `Progress:` snapshot per ten seconds (subject to UI sampling):
  aggregate verified bytes/delta/errors, worker count, and up to four workers'
  current chunk (`R<n>`, or `R-` between chunks) with that chunk's cycle/test
  position, byte count, phase and idle verified-byte age. The four
  least-recently advancing workers are shown first; omitted workers are counted.
  Phase labels are capped at 32 characters and only static literals are published.
  Idle ages are approximate monitor observations, not hang warnings.
- SimpleTest publishes `Simple fill` before each internal repetition's pattern
  generation/cache flush and then `Simple verify` before checking. The fill label
  must reset each repeat; constructor-only initialization leaves later fills
  mislabeled as verification. `testRepeatedSimplePhases` checks uniform/XOR/linear
  repeats with pre-fill sentinels and exact live/final byte totals.
- Bounded mismatch samples retain exact aggregate counts. Destructive march errors
  are unverified observations; other sampled errors can be classified by rereading.
- Memory-lock allocation contracts are still fail-closed. On Windows the residency
  check (2026-11-27) fails locked chunks on any page outside the working set; for
  unlocked chunks it reads trimmed pages back (Windows trims unlocked pages to the
  standby/modified lists, compression store or page file as routine working-set
  management) and fails only pages that stay non-resident, so unlocked memory is
  best-effort resident between checks. Locked/large-page allocation remains recommended.
  [VirtualLock's contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)
  guarantees residency for successfully locked pages.

## Live tested-byte accounting and the apparent-stall fix

Sources: `include/TestProgress.h`, `include/TestEngine.h::TestContext`,
`include/TestEngineInternal.h::VerificationProgress`, `src/TestEngine.cpp::executeSuite`,
the five algorithm translation units, `src/main.cpp::main` (results section),
and `tests/test_progress_regressions.h` / `tests/test_cli.py`.

The 2026-10-13 investigation confirmed delayed live publication and omitted final
byte totals. Long internal-repeat tests could appear frozen until an entire
`runRegionWork` returned. The same reporting paths exist in April v1.3 (`fa89da3`),
checked by source inspection only. These reporting defects are now fixed.

Accounting invariants:

- Each worker exclusively writes its cache-line-separated `ProgressCounters`
  slot through a scoped thread-local binding keyed to its `TestContext`. Nested
  kernels inherit the same sink; standalone calls update context atomics directly.
  No worker contends on a shared byte counter at every small march/random block.
- `VerificationProgress` credits only completed checks, publishes bytes and error
  deltas, and preserves error deltas on unwinding. Outer march repeats and configured
  sub-blocks merge return values without re-crediting published work. Retention's
  `mergeNested` excludes the background test's already-published errors as well.
- The monitor samples `progressSnapshot()` approximately every 600 ms (200 ms UI
  polling with a 500 ms minimum interval). Live cross-worker snapshots are
  approximate; all atomics are individually safe, and final totals are exact after
  every worker and the monitor join. `finishProgress` then folds slots into the
  context totals and releases them. Never resize/clear slots while readers run.
- Byte totals are verified reads, not writes, unique RAM coverage or bus traffic.
  Fill/flush/disturbance work can legitimately precede the next verified-byte change.
  Completed cycles still require every memory chunk; partial cycles are uncredited.
- Diagnostics are allocated/sampled only with debug mode enabled. Workers publish
  phase labels at algorithm boundaries without locks, clocks or per-block logging.
  Monitor exceptions are logged as infrastructure failures, stop peers, and retain
  completed work through normal joining/folding. Test-only hooks reproduce this.

Thread failure recovery records stop/failure before allocating diagnostic strings
or calling the logger. `beginInfrastructureFailure` claims the first cause and
retains a static fallback label; only the owner stores its detailed message.
`reportInfrastructureFailure` catches failures in both detail storage and logging,
emitting one stderr line with at most 256 detail characters. Monitor work/status
cleanup, worker exceptions and partial worker startup use this protected path.
The direct failure setter accepts `string_view` and cannot throw while storing
details. Fallback pointers must reference static literals; detailed messages and
final results can allocate on the joining/calling thread, where exceptions can be
handled by the caller. This prevents exceptions escaping test threads; it does not
promise successful allocation of every final display under process-wide exhaustion.

`tests/TestAllocationFailure.h` replaces ordinary new/delete in the test runner
only. A thread-local counter enables sustained allocation failure on a selected
monitor/worker; peers and the joining thread keep normal allocation behavior.
`testThreadExceptionCleanup` uses a condition-variable verification handshake,
then exercises standard/unknown exceptions and continued allocation failure on
both thread types. It checks exact collected bytes, joined-slot release and stable
first-cause fallback. The allocation-failure regression terminated with exit 86
before the recovery fix. Sanitizer DLL-backed string allocation can bypass the
runner's replacement allocator, so the direct message-storage regression uses a
test-only storage-boundary hook to force an ordinary allocation there. No sleeps
or low-memory system settings are needed.

Baseline/AVX2 regressions inspect live progress at march phase boundaries (150
internal repetitions), cancel at the tenth forward pass, and throw after a
completed verification/mismatch. Totals remain exact at synthetic starting values
of 0, 5,000 and 8,000 GiB. A condition-variable handshake proves a peer can observe
bytes while the originating worker is still inside its test; no timing assumption
or sleep is needed. All 14 algorithms publish verified-block progress, and nested
retention errors, external/internal repeats and configured sub-blocks are covered.

The actual CLI regression (16 MiB SimpleTest, three internal repetitions) failed
before the fix and now requires exactly 50,331,648 verified bytes and one completed
cycle in console/log output. Baseline/AVX2 suites and all 17 Python regressions pass.
Local fixtures/binaries/logs remain ignored under `build/review/progress-report/`.
Synthetic large counters do not replace a multi-terabyte endurance run.

Final verification on 2026-10-13: Windows and WSL Linux baseline/AVX2 suites,
17 Python regressions, both ASan/UBSan ISA runners and strict clang-tidy pass;
all nine release targets cross-build. AVX-512/ARM remain cross-build only.
Actual Windows baseline/AVX2 CLI runs (64 MiB, one worker, 150 internal march
repetitions) show multiple increasing live totals before the single invocation
returns, then exactly 30,198,988,800 verified bytes and one complete cycle with
zero errors. A Linux baseline CLI run confirms final bytes/cycles too.
An extended 300-repeat baseline CLI run also exercises the real ten-second debug
snapshot during a march and ends with exactly 60,397,977,600 verified bytes.

Limits: the original preset/version, hardware, elapsed stall duration, and Linux
warning are unknown. Actual long-run kernel failure, scheduler starvation, or
memory pressure on the reporter's machine is unverified. Current defaults use all
available CPU targets and 85% of total physical RAM (`src/RunConfiguration.cpp::makeDefaultConfig`
and `src/ConfigWizard.cpp::getSizingBaselineRAM`); process priority remains normal
(`src/Platform.cpp::confirmNormalProcessPriority`). These choices can compete with
other workloads. WSL regressions and a bounded Linux CLI run pass, but desktop
unresponsiveness, a permanent long-run stall and the original unspecified Linux
complaint have not been reproduced or diagnosed.

## Validation and measurements

### 2026-11-21 v1.11 audit fixes (reliability, sizing, and ISA detection)

- `RowHammer` regions at or below `24 KiB` (`TestEngineInternal.h::kMinRowHammerBytes`)
  now fail closed with an infrastructure error instead of returning an empty
  success result (`TestRowHammer.cpp`). When `RowHammer` is enabled in the sequence,
  `TestEngine.cpp` caps effective workers/chunks so every chunk stays above 24 KiB,
  folds sub-threshold `Test Block Size` remainders into the preceding block, and
  refuses to advance scheduler progress (`RegionScheduler`) for any zero-byte test
  entry unless it was intentionally stopped before executing.
- `resolveRunExitCode` (`src/RunConfiguration.cpp`) exits `2` on zero verified bytes
  or interrupted finite runs (`--cycles` or `--duration`) and preserves exit `1` if
  errors were already recorded; Windows double Ctrl+C `TerminateProcess` exits with
  `STATUS_CONTROL_C_EXIT`.
- Windows `tryAllocateVirtualLock` and hybrid large-page tail locking in
  `tryAllocateLargePagesChunked` treat `SetProcessWorkingSetSize` as best-effort
  and no longer gate ordinary `VirtualLock` on `SeLockMemoryPrivilege`;
  `tryAllocateStandard` prefaults native pages and
  `Platform::checkMemoryResident` (`src/PlatformMemory.cpp`) verifies actual working-set
  residency with `QueryWorkingSetEx` (`Valid != 0`) after `VirtualQuery` checks.
  Follow-up 2026-11-27: the check takes the chunk's `is_locked`; unlocked chunks
  re-fault trimmed pages instead of aborting the run (see the residency bullet above).
- `detect_x86_capabilities` (`src/simd_ops.cpp` + `include/SimdCpuSupport.h`) checks
  every psABI v3/v4 CPUID feature and XCR0 state before setting `has_avx2`/`has_avx512`.
- Verification on 2026-11-21: `python build.py --lint` clean across all 30 translation
  units (`WarningsAsErrors`); `python build.py --tests` passed baseline/v3/x86 C++
  runners and 31 Python tests (`27 OK, 4 Linux-only skipped`); `python build.py --run-sanitizers`
  passed ASan and UBSan (baseline, v3, and Python suite); all 9 release targets built
  cleanly; inside WSL, both Zig-built `x86_64-linux-musl` and `x86-linux-musl` C++
  test suites passed (`All internal tests passed.`), 22 Python CLI tests passed
  (`21 OK, 1 Windows-only skipped`), `testsmem4u-linux-x86 --memory 85% --dry-run`
  clamped cleanly to `2044 MB` (rejecting `2048 MB --no-large-pages`), and a 16 MiB
  `testsmem4u-linux-x86` cycle verified `16,777,216` bytes with zero errors.

### 2026-10-13 kernel optimization check

Native baseline/AVX2 suites and all 17 Python regressions pass, including exact
LFSR sequences, uniform/generic equivalence, protected-word sentinels, transient
random observations and live/cancelled progress. ASan/UBSan pass for both native
ISA runners. Strict clang-tidy checks every production source and test runner;
the final random-path simplification was rechecked with the same warning gate.
All nine pinned-toolchain release targets build. Windows baseline/AVX2 and WSL
Linux AVX2 CLI smoke tests cover all 18 entries on 64 MiB with eight workers,
shortened counts/25 ms retention dwells, one full cycle and zero errors. Expected
kernel diagnostics are present. ARM/AVX-512 remain cross-build-only validation.

The native AVX2 release disassembly directly confirms CLFLUSHOPT inside the
region loop without per-line calls/VZEROUPPER, plus MFENCE. ASLR/DEP/CFG flags
remain present; no sanitizer runtime is imported by the delivered release binary.

Compared the pre-task `a905045` snapshot with final kernels on Ryzen 5700X using
the same pinned MinGW release/ThinLTO flags, affinity, 512 MiB allocation and
equal worker slices. Median seconds exclude one warmup and use three samples:

| Kernel | 1 worker before / after | 16 workers before / after |
| --- | --- | --- |
| Uniform march, four repeats | 0.866 / 0.530 | 0.341 / 0.334 |
| LFSR fill + verify | 0.130 / 0.105 | 0.0395 / 0.0401 |
| LFSR march, four repeats | 1.484 / 1.195 | 0.374 / 0.362 |
| Modulo20, one disturbance repeat | 4.449 / 4.479 | 2.198 / 2.075 |

All samples have zero errors and identical per-case verified bytes. Eight-worker
streaming cases mostly change little. Pure region flushing is also essentially
unchanged: removing calls does not remove the hardware's flush cost. Final
16-worker RandomAccess at 1,048,576 accesses per worker is 0.198 s versus 0.198 s
before. A longer 16,777,216-access experiment rejected reciprocal indexing and
separate load/compare arrays after they failed to improve throughput.

These short measurements are software-throughput evidence, with ordinary timing
noise; small percentages do not establish a hardware optimum. (At the time, equal
benchmark slices differed from the then-default weighted SMT regions; runs now use
equal chunks.) No package-power,
DRAM-bus, DIMM-temperature or unstable-memory detection measurements were taken.
Fixtures/logs/snapshots remain ignored under `build/review/performance/`; every
run is bounded. Manual full-capacity testing remains the next hardware check.

Software checks: native baseline/SSE2 and AVX2 regression suites, ASan and UBSan
with both ISA runners, clang-tidy, and all nine release cross-build targets.
AVX-512 and ARM are cross-build coverage only on this Ryzen 5700X host.
A native AVX2 smoke run exercised all 18 entries on 512 MiB of locked standard-page
memory with eight workers and reduced loop/dwell counts: one complete cycle across
every region, zero errors, 15.7 seconds of testing. The subsequent status-only fix
was covered by a regression that ensures long test names cannot hide errors/time.

A short native AVX2 comparison used the prior commit's sources and current sources,
the same compiler/flags, eight workers, and 64 MiB per worker (512 MiB total):

| Case | Before | After | Interpretation |
| --- | --- | --- | --- |
| Retention, 500 ms dwell | 1.117 s, 4.5% worker CPU occupancy | 2.078 s, 99.0% occupancy | Four half-region dwells replace two whole-region dwells; active work verifies 37.5 GiB versus 1 GiB |
| Lowest complete 100 ms retention sample | 0% | 90.7% | No deliberate whole-run idle interval in this short observation |
| Random, 262144 accesses/worker | 0.175 s | 0.076 s | Same access count, plus restored-value checks and complete initial/final sweeps |
| Uniform march, three repeats | 0.198 s, 3 GiB verified | 0.285 s, 4.5 GiB verified | Now includes real read/write transitions and final restoration validation |
| LFSR march, three repeats | 0.220 s, 3 GiB verified | 0.306 s, 4.5 GiB verified | More coverage without the seed-table precomputation |

CPU occupancy is process CPU time divided by wall time and worker count, not total
machine utilization. Short samples have scheduler/accounting noise. Experiments
live only under ignored `build/ram_review/`; generated binaries/logs are not committed.

## Open questions and limits

The 2026-09-30 Linux unlocked startup and preparation-thread defects are fixed;
see [the review/fix log](log/recent.md) for reproduction and validation. Historical
clang-tidy-clean claims remain unverified because the old workflow skipped files
and accepted warnings; current analysis uses the corrected fail-closed gate.

No temperature sensor or unstable-memory experiment was performed. Higher useful
load does not establish a universal optimum or a particular error-detection speedup.
Different DIMMs/controllers, capacities, NUMA placement, SMT, and ISA variants need
hardware-specific measurements. Tiny sub-blocks still exercise a smaller address
span; leave Test Block Size at zero for whole-worker-region testing by default.
Row/bank mapping is unknown: virtual strides and large pages do not prove physical
adjacency or exhaustive RowHammer coverage. OS-owned and firmware-reserved memory
cannot be covered by a user-space allocation. Firmware memory testing remains a
complementary coverage method.
