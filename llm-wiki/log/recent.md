# Recent Log

## 2026-09-12 - Continuous useful RAM testing and verification corrections

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
