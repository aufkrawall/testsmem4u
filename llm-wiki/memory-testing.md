# Memory testing: workload and coverage

Last verified: 2026-10-13 for progress/result reporting; 2026-09-30 for other
runtime paths. Stale risk: medium for hardware effectiveness and unobserved
long-run stalls; low for tested native progress/accounting paths.

## Sources and responsibilities

- `src/TestEngine.cpp`: allocation, dispatch, page-aligned weighted worker regions,
  independent sequence execution, monitoring, termination, exception containment.
- `src/Platform.cpp::allocateMemoryRAII` and `include/PreparationStatus.h`:
  prefaulting and exception-safe preparation lifetime.
- `include/WorkerProgress.h`: per-worker completed sequence position; the minimum
  defines whole-allocation progress and completed cycles.
- `include/TestProgress.h`, `TestContext` and `VerificationProgress` in
  `include/TestEngineInternal.h`: live per-worker totals, scoped binding, and
  leaf-only verified-byte/error publication; joined totals are exact.
- `include/ProgressDiagnostics.h`: monitor-owned progress ages and periodic,
  capped snapshots; `src/ConsoleDisplay.cpp::formatStatus` preserves primary fields
  before coverage/test-name details on narrow terminals.
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
region's unrelated test. Regions are 4 KiB-aligned but DRAM rows are larger, so
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
would not establish private backing. `MemoryGuard` owns the allocation during
prefaulting, so later exceptions release it. This initializes pages once, without
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
with MOVNTI on x86_64 (plain stores elsewhere), avoiding RFO reads of stale lines;
a 2026-09-12 regression had used cached scalar stores.
LFSR comparisons retain observed values from the original load, eliminating the
old memcmp-then-re-read transient-loss window. Reverse LFSR generation starts from
the terminal state and walks the inverse recurrence; no count-sized seed-table
prepass exists, and partial backward blocks use their actual indices.

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

RowHammer checks the selected victim cache line promptly and checks an upcoming
aggressor before overwriting it, so reusing a former victim cannot silently erase
an earlier flip. Final sweeps still cover all other words. An explicit point budget
is shared across available strides rather than silently expanded to one per stride.

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
- Live progress includes completed verification blocks from currently running
  invocations. CLI results and the log also include exact final bytes and completed
  cycles, including partial work from cancellation or worker exceptions.
- `--debug` adds one `Progress:` snapshot per ten seconds (subject to UI sampling):
  aggregate verified bytes/delta/errors, worker count, and up to four workers'
  cycle/test position, byte count, phase and idle verified-byte age. The four
  least-recently advancing workers are shown first; omitted workers are counted.
  Phase labels are capped at 32 characters and only static literals are published.
  Idle ages are approximate monitor observations, not hang warnings.
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
available CPU targets and 85% of total physical RAM (`src/main.cpp::makeDefaultConfig`
and `getSizingBaselineRAM`); process priority remains normal
(`src/Platform.cpp::confirmNormalProcessPriority`). These choices can compete with
other workloads. WSL regressions and a bounded Linux CLI run pass, but desktop
unresponsiveness, a permanent long-run stall and the original unspecified Linux
complaint have not been reproduced or diagnosed.

## Validation and measurements

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
