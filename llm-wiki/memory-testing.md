# Memory testing: workload and coverage

Last verified: 2026-09-12. Stale risk: medium for hardware effectiveness;
low for tested software invariants.

## Sources and responsibilities

- `src/TestEngine.cpp`: allocation, dispatch, page-aligned weighted worker regions,
  independent sequence execution, monitoring, termination, exception containment.
- `include/WorkerProgress.h`: per-worker completed sequence position; the minimum
  defines whole-allocation progress and completed cycles.
- `src/TestPatterns.cpp`: SimpleTest, MirrorMove, MirrorMove128, walking bits,
  and the shared public pattern verification/reporting entry point.
- `src/TestMarch.cpp`: LFSR verification and moving-inversion variants.
- `src/simd_verify.cpp`, `include/MemoryTestKernels.h`: first-observation comparison,
  SIMD read/replace in either direction, and forward/inverse LFSR recurrence.
- `src/TestMemoryTraffic.cpp`: active retention, batched random access, block moves.
- `src/TestModulo.cpp`: Modulo-20 protected-word coupling test.
- `src/TestRowHammer.cpp`: heuristic multi-stride disturbance test.
- `include/TestEngineInternal.h`: address reporting, mismatch classification,
  bounded sample accounting, and compile-time-only fault injection hooks.
- `tests/test_engine_regressions.h`: fault injection, partial blocks, virtual-time
  retention, actual worker independence, cancellation, and exception regressions.
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

Shutdown no longer dereferences a stack-context pointer asynchronously: a static
atomic outlives every run. Worker exceptions and partial thread-start failures
request stop and join all successfully started workers. ASan/UBSan do not establish
race freedom; the independent-progress and cancellation tests exercise the actual
worker implementation with deterministic condition-variable handshakes.

Retention alternates two cache-line-disjoint halves. Each half receives both
configured polarities and is untouched for at least the configured dwell interval.
The other half runs address-sensitive SimpleTest write/verify passes in bounded
chunks. Roles rotate; no held data is used as background traffic. The deadline is
monotonic, and a current verification chunk may finish after the minimum dwell.
An invocation now has four dwell intervals. Inputs smaller than two cache lines
retain an idle fallback because a separate active region is impossible.

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

BlockMove uses an address-dependent odd-stride pattern. It verifies both copies,
poisons the return destination, copies in both directions, and checks odd tails.
MirrorMove128 verifies initialization, an overlapping one-word rotation, and the
restored alternating pair pattern (including odd-length wrapped tails).

RandomAccess issues up to 16 independent locations in disjoint address bands,
checks the original, inverted, and restored values, and flushes/fences writes as
a batch. Distinct indices prevent outstanding writes from conflicting. Initial
and final full-region sweeps cover unselected cells and collateral corruption.
The configured access count remains exact, including the partial last batch.

Modulo20 holds one word in every 20 at one polarity while repeatedly writing the
other 19 with its complement. Protected words are not accessed during disturbance;
cache flushes separate passes and final verification checks every word. All offsets
and both polarities run, including short tails. This complements the march tests'
cache/buffering sensitivity; see the primary algorithm descriptions at
[MemTest86](https://www.memtest86.com/tech_memtest-algoritm.html) and
[Memtest86+](https://memtest.org/readme).

RowHammer checks the selected victim cache line promptly and checks an upcoming
aggressor before overwriting it, so reusing a former victim cannot silently erase
an earlier flip. Final sweeps still cover all other words. An explicit point budget
is shared across available strides rather than silently expanded to one per stride.

## Diagnostics and interpretation

- Startup logs describe independent scheduling and active retention. Debug logs
  identify worker region offsets/weights, test starts, and elapsed test durations.
- Final `Coverage` is the number of complete cycles across every worker region.
- Byte totals count verified reads, including repeated checks and retention's useful
  active tests. They are neither unique memory coverage nor physical bus traffic.
- Bounded mismatch samples retain exact aggregate counts. Destructive march errors
  are unverified observations; other sampled errors can be classified by rereading.
- Memory-lock allocation contracts are still fail-closed. On Windows the existing
  residency check proves commitment; unlocked committed memory is not thereby
  proven physically resident. Locked/large-page allocation remains recommended.
  [VirtualLock's contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)
  guarantees residency for successfully locked pages.

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

No temperature sensor or unstable-memory experiment was performed. Higher useful
load does not establish a universal optimum or a particular error-detection speedup.
Different DIMMs/controllers, capacities, NUMA placement, SMT, and ISA variants need
hardware-specific measurements. Tiny sub-blocks still exercise a smaller address
span; leave Test Block Size at zero for whole-worker-region testing by default.
Row/bank mapping is unknown: virtual strides and large pages do not prove physical
adjacency or exhaustive RowHammer coverage. OS-owned and firmware-reserved memory
cannot be covered by a user-space allocation. Firmware memory testing remains a
complementary coverage method.
