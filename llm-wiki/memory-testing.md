# Memory testing: workload and coverage

Last verified: 2026-10-13 for page-allocation defaults, native kernel contracts, performance and progress/result reporting; 2026-09-30 for other
runtime paths. Stale risk: medium for hardware effectiveness and unobserved
long-run stalls; low for tested native progress/accounting paths.

## Sources and responsibilities

- `src/TestEngine.cpp`: allocation, dispatch, page-aligned weighted worker regions,
  independent sequence execution, monitoring, termination, exception containment.
- `src/PlatformMemory.cpp::allocateMemoryRAII` and `include/PreparationStatus.h`:
  prefaulting and exception-safe preparation lifetime.
- `include/WorkerProgress.h`: per-worker completed sequence position; the minimum
  defines whole-allocation progress and completed cycles.
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
- `src/TestPatterns.cpp`: SimpleTest, MirrorMove, MirrorMove128, walking bits,
  and the shared public pattern verification/reporting entry point.
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
- `default.cfg`: 18 configured entries covering 14 distinct test functions.

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
  target, receive `MADV_HUGEPAGE` before write-prefaulting, then `mlock` when
  requested. Unsupported advice or unavailable THPs still allow valid locked
  native pages. `--no-large-pages` skips HugeTLB and requests `MADV_NOHUGEPAGE`.
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
no-large-page advice. They never modify sysctls or impose timing assumptions.
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

Workers retain exclusive contiguous regions and CPU affinity. Their test phases
are independent: a faster worker never waits at a test/cycle barrier. Keeping
static regions preserves cache-line ownership and retention isolation; removing
barriers does not require work stealing or tiny shared tiles.

Each worker executes the configured sequence in order. Completed cycles are the
minimum across workers. Faster workers continue real tests, including extra cycles,
until every region completes the requested count. Disabled sequence entries advance
progress without running; an empty/all-disabled or undefined sequence fails closed.
The displayed test is the least advanced region's next test, not a claim that all
workers run that test. Mid-test cancellation does not publish a completed boundary.

Because workers are unsynchronised, one region's RowHammer can overlap another
region's unrelated test. Regions are native-page-aligned but DRAM rows are larger, so
hammering near a boundary can flip a peer's cells. This is accepted (a lockstep
RowHammer barrier would reintroduce per-cycle idling, since RowHammer is last in
default.cfg). Instead each invocation runs inside a `DisturbanceWindow`; if it
reports errors and any peer RowHammer was active at its start or started during it,
the worker logs a WARN naming the test and region. Disturbers register
active-then-start and observers snapshot start-then-active, so no overlap is missed.

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

On x86, CLFLUSHOPT region and address-batch loops run entirely inside a function
compiled for that instruction. Capability dispatch is outside the loop and each
operation ends with MFENCE. This removes per-line calls/VZEROUPPER observed in
the v1.7 ThinLTO binary. Region flushing aligns the start down to cover every
intersecting cache line; a zero-byte range still fences without flushing. This
does not remove algorithm flushes or claim control over physical DRAM ordering.
Per-march summaries identify the selected pattern path; no per-flush logging is added.

BlockMove uses an address-dependent odd-stride pattern. It verifies both copies,
poisons the return destination, copies in both directions, and checks odd tails.
MirrorMove128 verifies initialization, an overlapping one-word rotation, and the
restored alternating pair pattern (including odd-length wrapped tails).

RandomAccess issues up to 16 independent locations in disjoint address bands,
checks the original, inverted, and restored values, and flushes/fences writes as
a batch. Distinct indices prevent outstanding writes from conflicting. Initial
and final full-region sweeps cover unselected cells and collateral corruption; the
region is flushed after the initial sweep so random reads cannot hit its cached tail.
The configured access count remains exact, including the partial last batch.
Parameter 1-100 (0 = 1) is a pass multiplier; >100 is an explicit per-region access
count (`randomAccessIterations`). executeSuite warns about the latter at startup.

RandomAccess prepares band starts/sizes once, retaining the original native
remainder calculation, RNG sequence, addresses and partial-batch counts. Written
addresses use `flush_cache_lines` with one dispatch/fence. Each volatile read's
original observation is retained; a repaired-after-load fault still counts as soft.
Reciprocal remainders and a separate load-then-compare array were tested but
rejected: longer one-/sixteen-worker measurements showed no throughput gain.

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
an earlier flip. Final sweeps still cover all other words. An explicit point budget
is shared across available strides rather than silently expanded to one per stride.

Aggressor writes retain SFENCE, both line flushes and MFENCE each iteration;
`flush_cache_lines` dispatches the two-address flush once. Victim/reuse checks and
point/iteration budgets are unchanged. The software contracts are regression
tested; physical activation rates and fault-detection gains remain unmeasured.

## Diagnostics and interpretation

- Startup logs describe independent scheduling and active retention. Debug logs
  (`--debug`) identify worker region offsets/weights, test starts, and elapsed test
  durations, plus per-invocation summaries from March/LFSRPattern (seed, errors,
  unverified, time), Modulo20 (per polarity), RefreshStable (per dwell: actual dwell,
  active chunks, full sweeps, cursor), RandomAccess (access count), and BlockMove
  (per direction). `[stopped]` marks cancelled invocations.
- Preparation debug logs record requested bytes/lock/large-page choices, the
  resulting allocation, and Linux prefault byte/page counts and elapsed time.
- WARN "... while RowHammer ran on another worker region" marks errors that may be
  cross-region disturbance rather than a failure specific to the named test.
- Final `Coverage` is the number of complete cycles across every worker region.
- Byte totals count verified reads, including repeated checks and retention's useful
  active tests. They are neither unique memory coverage nor physical bus traffic.
- The status line follows the least advanced worker (`findSlowestWorker`: lowest
  completed position, then lowest step) and appends its current-test step as a
  percentage. `ProgressBinding` combines worker loop (`beginLoop`), configured
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
  cycle/test position, byte count, phase and idle verified-byte age. The four
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
- Memory-lock allocation contracts are still fail-closed. On Windows the existing
  residency check proves commitment; unlocked committed memory is not thereby
  proven physically resident. Locked/large-page allocation remains recommended.
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
  Completed cycles still require every worker region; partial cycles are uncredited.
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
noise; small percentages do not establish a hardware optimum. Equal benchmark
slices differ from the default weighted SMT assignments. No package-power,
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
