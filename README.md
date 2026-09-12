# testsmem4u

Cross-platform RAM testing tool focused on preset-driven memory stress, locked-memory operation, and operator-friendly CLI execution on Windows and Linux.

## Status

The current release is centered around `default.cfg` as the supported shipped preset.

Recent reliability work in this revision includes:

- Independent workers with fixed, disjoint memory ownership and no per-test barriers.
- Retention under genuine memory load: hold one half untouched while testing the other, then swap roles.
- Forward/backward read-and-invert marches, a final restoration check, and lossless first-observation LFSR verification.
- Address-sensitive bidirectional block copies, overlapping pair-pattern moves, and batched random-access verification.
- A Modulo-20 test for coupling between protected words and repeatedly written neighbours.

- Stricter preset validation so malformed or partially unsupported presets fail closed.
- Bounded mismatch sampling with exact aggregate error counts, so failure storms cannot grow memory without limit.
- Global address-pattern offsets across worker shards and sub-blocks.
- Lightweight internal regression tests for pattern generation, bounded reporting, LFSR vectors, and deliberate bit flips.
- Clearer allocation reporting that distinguishes full large pages from hybrid large-page plus locked-page fallback.
- Informational fallback guidance when the requested test size could not be covered entirely by large pages.
- Infrastructure failures now return a configuration/runtime failure exit code instead of being reported like memory corruption.
- Linux hugepage reservation cleanup is restored on normal process exit as well as successful hugepage runs.

## Features

- Preset-driven test suites via .cfg files.
- One supported bundled preset: `default.cfg`.
- Interactive startup with a configuration wizard.
- Direct, scriptable CLI execution for unattended runs.
- Automatic privilege elevation attempt unless disabled.
- Locked-memory and large-page / hugepage allocation support when the platform allows it.
- Separate `-v3` (AVX2) and `-v4` (AVX-512) binary variants; start the one matching your CPU. The program logs a hint if a faster variant would fit.
- Detailed console progress and a persistent testsmem4u.log file.

## Build

The repository ships with a Python build script with two supported toolchain paths:
LLVM MinGW for hardened Windows x86-64 binaries, and Zig for Linux plus Windows ARM cross-builds.

Build one Windows target:

```powershell
python build.py --toolchain mingw --targets windows-x86_64
```

Build the full configured release matrix:

```powershell
python build.py --toolchain mingw --targets all
python build.py --toolchain zig --targets all
```

Build and run the lightweight internal tests:

```powershell
python build.py --tests
```

Generate `compile_commands.json` for clangd/LSP tooling:

```powershell
python build.py --compile-commands --targets windows-x86_64
```

Artifacts are written to dist.

## Quick Start

Interactive startup with the saved or default configuration:

```powershell
.\dist\testsmem4u-windows-x86_64.exe
```

List bundled presets:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --list-presets
```

Run a preset non-interactively:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --yes --preset default.cfg
```

Inspect the resolved configuration without starting a test run:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --dry-run --preset default.cfg --memory 80% --cycles 3
```

## CLI Summary

The executable now supports the following high-value operator options:

- --help and --version for discovery.
- --list-presets to enumerate available .cfg suites in the current working directory.
- --config FILE to load and save a specific config file.
- --no-config to ignore config files entirely.
- --preset FILE or a positional preset path to select a suite directly.
- --memory VALUE, --cores VALUE, and --cycles VALUE for one-off run overrides.
- --halt-on-error or --no-halt-on-error to control stop behavior.
- --locked-memory or --no-locked-memory to control memory locking.
- --large-pages or --no-large-pages to control large-page preference.
- --show-config and --dry-run for validation and inspection.
- --yes or --non-interactive to suppress prompts and exit pauses.
- --no-elevation to prevent Administrator/root relaunch.

See cli-report.md for the full option reference, mode rules, exit codes, and examples.

## Runtime Behavior

- With no run-specific options, the program loads config.ini from the current working directory if present.
- If launched interactively, it shows a 3-second countdown and opens the wizard if a key is pressed.
- If launched with run-specific CLI overrides, --yes, or non-interactive stdin, it skips prompts and runs in direct CLI mode.
- On Windows, the program can offer to grant SeLockMemoryPrivilege when interactive and elevated.
- On Linux, the program warns when memory-lock or hugepage capability appears limited, but it does not attempt privilege changes automatically.
- Binary variant selection is manual: run the `-v3` (AVX2) or `-v4` (AVX-512) binary that matches your CPU; the baseline binary works everywhere. A startup warning points out when a faster variant would fit your CPU.
- If the run falls back from full large pages to locked standard pages, the console now explains that the test remains valid and how to improve large-page coverage for future runs.

## Files

- config.ini: saved wizard configuration unless --no-config is used.
- testsmem4u.log: runtime log file created in the current working directory.
- *.cfg: preset definitions loaded either from the current working directory or from an explicitly supplied path.

## Exit Codes

- 0: success, informational command success, or dry-run success.
- 1: memory test completed with detected errors.
- 2: CLI, configuration, preset, or runtime infrastructure failure.

## Operational Notes

- The current working directory matters for the default config.ini lookup, log file location, and preset discovery.
- For scheduled tasks, shortcuts, or service-style launchers, prefer explicit --config and --preset paths.
- If large pages are enabled, the effective memory window may be reduced to match large-page granularity.
- Full large-page coverage is beneficial for throughput and RowHammer fidelity, but a fully locked fallback run is still valid for the rest of the suite.

## Coverage and workload

Each worker follows the preset sequence on its own contiguous memory region.
The displayed test/cycle represents the least advanced region; other workers can
already be running later tests. A completed cycle means every region completed the
whole sequence. Faster workers continue genuine tests until all regions finish the
requested cycle count. Stop and infrastructure failures never count incomplete
cycles. Debug logs identify each worker's region, test transitions, and duration.

`RefreshStable` preserves the configured untouched dwell for each half and both
polarities, with write/verify testing on the other half throughout the dwell.
This takes at least four dwell intervals per invocation. It adds no compute-only
heater, artificial spin loop, or unrelated synthetic workload. Tiny inputs smaller
than two cache lines retain an idle fallback because no disjoint region exists.

`MovingInversion*` performs ordered read/write transitions at SIMD-vector granularity,
then flushes and checks the reverse transition and final restored pattern. A mismatch
observed before an intentional overwrite is counted as **Unverified** because it can
no longer be classified by re-reading the original cell. It is still a detected
error, contributes to the error total, and triggers `--halt-on-error`.

The suite reports verified bytes, including repeated checks; this is neither unique
physical coverage nor a hardware DRAM-bandwidth counter. Dwell time, memory latency,
cache flushes, and OS scheduling affect CPU utilization differently. No software
change guarantees maximum DIMM temperature or detection of every instability.
Virtual addresses and large pages do not prove physical DRAM row/bank adjacency;
RowHammer remains a heuristic disturbance test. Firmware-reserved and OS-owned RAM
is outside this user-space tester's allocation.

Implementation details, regression coverage, and local performance measurements are
recorded in [the memory-testing wiki](llm-wiki/memory-testing.md).
