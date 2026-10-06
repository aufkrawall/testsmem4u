# Recent Log

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
