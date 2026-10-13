# testsmem4u

Cross-platform RAM testing tool focused on preset-driven memory stress, locked-memory operation, and operator-friendly CLI execution on Windows and Linux.

## Support

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%23EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/aufkrawall)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-%23FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/aufkrawall)

Support through GitHub Sponsors or Buy Me a Coffee helps with development time, hardware, and tooling. My other
open-source projects would also profit from donations; they are listed in [Other projects](#other-projects) at the
bottom of this page.

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
- Linux automatically requests process-owned transparent huge pages; kernel cleanup also handles forced termination without leaving a program-created HugeTLB reservation.

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
- --aggressive-defrag to permit system-wide cache cleanup and memory compaction after ordinary large-page attempts fail; off by default.
- --show-config and --dry-run for validation and inspection.
- --yes or --non-interactive to suppress prompts and exit pauses.
- --no-elevation to prevent Administrator/root relaunch.

`--help` lists the complete option reference; runtime mode rules and exit codes appear below.

## Runtime Behavior

- With no run-specific options, the program loads config.ini from the current working directory if present.
- If launched interactively, it shows a 3-second countdown and opens the wizard if a key is pressed.
- The wizard asks the same questions on Windows and Linux. Accepting defaults selects 85% of RAM, all cores, three cycles, locked memory, large-page preference and halt-on-error. Saved defaults use `MemoryWindowPercent=85`, `MemoryWindowMB=0` and `Cores=0`, so the next run resolves RAM and core counts for its current system; explicit MiB/thread selections are saved as requested.
- If launched with run-specific CLI overrides, --yes, or non-interactive stdin, it skips prompts and runs in direct CLI mode.
- On Windows, interactive startup recommends and offers to grant a missing `SeLockMemoryPrivilege`. After granting it, sign out and sign back in; a reboot is not required.
- On Linux, the program relaunches itself through `sudo` unless `--no-elevation` is given, so the test window can be locked in RAM. After the wizard, it checks effective THP policy and offers a runtime `madvise` change when the requested huge-page size is disabled. If the countdown expires without opening the wizard, the run starts as promised and only reports a disabled policy instead of waiting for an answer. See [large and huge pages](#large-and-huge-pages) for setup scope and persistence.
- Binary variant selection is manual: run the `-v3` (AVX2) or `-v4` (AVX-512) binary that matches your CPU; the baseline binary works everywhere. A startup warning points out when a faster variant would fit your CPU.
- If the run falls back from full large pages to locked standard pages, the console now explains that the test remains valid and how to improve large-page coverage for future runs.
- Large pages and strict memory locking are preferred by default on both platforms. Windows tries native large pages, chunked/hybrid allocations and fully locked standard fallback. Linux first tries a compatible existing HugeTLB pool, then requests aligned transparent huge pages and locks the mapping. Allocation output reports actual large-page coverage; Linux THP coverage is a snapshot and can change under kernel memory management.
- Linux automatic huge-page allocation does not change the persistent HugeTLB pool. With `--aggressive-defrag`, incomplete THP coverage permits cache dropping, compaction and a process-local collapse attempt; allocations are released by the kernel even after a forced kill. `--no-large-pages` also requests that Linux avoid THP for the test mapping.

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
- Large pages can reduce address-translation overhead and provide physical contiguity within each page. A fully locked fallback run remains valid; large pages do not prove physical DRAM row/bank adjacency or RowHammer effectiveness.

## Large and huge pages

Both platforms prefer large pages and strict memory locking by default. The wizard
defaults to **Yes** for both settings. Page preference is best effort: the allocator
may obtain full coverage, partial coverage or locked native pages. Requested locking
is strict; a failure to lock the test window stops the run instead of silently
testing pageable memory. `--no-large-pages` disables the preference while retaining
locking; `--no-locked-memory` explicitly allows an unlocked fallback.

| Setup or allocation | Windows | Linux |
| --- | --- | --- |
| Initial elevation | Administrator through UAC | Root through `sudo` |
| Setup offer when needed | Grant the account's **Lock Pages in Memory** right, default `[Y/n]` | Set disabled THP policy to **`madvise`**, default `[Y/n]` |
| Scope and persistence | Account right persists across reboots | System-wide policy for the selected THP size; runtime change until reboot or another policy change |
| When setup takes effect | After signing out and signing back in | Before allocation in the same run |
| Reboot required for setup | No | No |
| Automatic persistent huge-page reservation | None | None; preconfigured HugeTLB pools are supported |

### Windows first run

Native Windows large pages require `SeLockMemoryPrivilege`. Administrator elevation
alone does not assign this account right. If it is missing, interactive startup
recommends granting it and offers `[Y/n]`; Enter accepts. The right is assigned to
the account running the elevated process. If UAC uses another account's credentials,
that is the account receiving the right.

After a successful grant, the program exits and asks you to **sign out and sign back
in**, then run it again. Reopening the program in the same login session generally
retains the old login token. A full reboot also creates a new session, but is not
required. Direct/non-interactive runs skip the grant offer.
[Microsoft documents the next-logon requirement](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/lock-pages-in-memory).

The allocator first tries a single native large-page allocation, then contiguous
virtual chunks and a hybrid large-page/locked-native-page allocation, followed by
fully locked native pages if necessary. The page size comes from
`GetLargePageMinimum` rather than an assumed 2 MiB. Each large page is physically
contiguous and nonpageable; the entire test window need not be physically contiguous.
Closing memory-heavy applications or restarting Windows can improve coverage when
memory is fragmented. This optional restart helps allocation success; it is separate
from activating the account right.
[Microsoft large-page support](https://learn.microsoft.com/en-us/windows/win32/memory/large-page-support).

### Linux first run

Linux has two supported huge-page mechanisms:

- **HugeTLB:** explicitly reserved huge pages. The allocator tries the existing
  default-size pool when its page size divides the requested window. These pages
  are inherently non-swappable. The program does not reserve or restore a pool.
- **Transparent huge pages (THP):** the automatic fallback when HugeTLB cannot
  satisfy the request. The allocator aligns the mapping for the native PMD huge-page
  size, requests `MADV_HUGEPAGE`, attempts requested `mlock` locking and then
  write-prefaults accepted mappings. Strict lock failures stop before the program
  explicitly touches the whole window. THP size
  varies with architecture/kernel configuration; 2 MiB is common on x86-64.

After the wizard resolves the final page preference, startup checks the global THP
`enabled` control, the native-size `hugepages-<size>kB/enabled` override where
available, and inherited process THP restrictions. A size-specific policy can
override the global setting, so the global value alone is insufficient.

If effective policy is `never`, an interactive root run whose operator opened the
wizard recommends **`madvise`** and offers `[Y/n]`. This permits huge pages for allocations that explicitly request
them. Modern kernels change only the native PMD-size control. Older kernels with
no size-specific control use the global `enabled` control. The offer explains that
the change also affects other applications and lasts until reboot or another policy
change. It writes no boot configuration, and does not alter THP defrag policy or
reserve a HugeTLB pool. The policy remains active after the test exits; the usual
boot policy is reapplied on reboot. **No reboot, sign-out or application relaunch is required**:
the test allocates its memory after setup and can use the new policy immediately.
[Linux THP policy documentation](https://docs.kernel.org/admin-guide/mm/transhuge.html).

Already suitable policies need no prompt. Direct/non-interactive runs and an
expired startup countdown diagnose a disabled policy without prompting or changing it. An unprivileged interactive run explains how
to relaunch with `sudo`; `--no-large-pages` bypasses THP setup. Missing/unreadable
controls, inherited complete process disabling, declined/invalid input and closed
stdin do not authorize policy changes. Setup rechecks policy after confirmation
and verifies the write by reading it back. Read-only sysfs or policy-manager
interference produces a warning; allocation continues with the existing policy.

Manual HugeTLB reservation can be performed at runtime without a reboot. Large
reservations may fail on fragmented memory; reserving pages at boot is more reliable.
Applying new kernel boot parameters requires a reboot. Reserved HugeTLB pages are
unavailable to ordinary allocations, so pool size should be chosen deliberately.
[Linux HugeTLB documentation](https://docs.kernel.org/admin-guide/mm/hugetlbpage.html).

### Coverage, diagnostics and aggressive preparation

The allocation summary reports **Locked**, **LargePages** and **Method**. Full,
partial and unknown huge-page coverage are distinguished. Linux THP coverage is a
snapshot from the mapping's metadata and can change later. A successful setup
enables allocation policy; actual full coverage still depends on available memory
and fragmentation. `--debug` adds bounded allocation and `THP setup:` diagnostics.

`--aggressive-defrag` remains off by default. On Windows, failed ordinary full
large-page attempts can trigger cache/working-set/standby preparation and one
allocation retry. On Linux, incomplete THP coverage permits cache dropping,
compaction and one process-local collapse attempt on supported kernels. These
operations affect system memory/cache state and can slow other applications while
they refill their caches. Neither platform needs a reboot for these operations.

To receive setup offers, launch interactively without run-specific overrides.
On Linux, press a key during the startup countdown to open the wizard; the THP
offer follows it.
`--yes`, run-specific CLI options and non-interactive stdin skip setup prompts;
`--dry-run` exits before privilege elevation or OS setup.

## Coverage and workload

Each worker follows the preset sequence on its own contiguous memory region.
The displayed test/cycle represents the least advanced region; other workers can
already be running later tests. A completed cycle means every region completed the
whole sequence. Faster workers continue genuine tests until all regions finish the
requested cycle count. Stop and infrastructure failures never count incomplete
cycles. Debug logs identify each worker's region, test transitions, and duration.

The percentage after the test index is how far that least advanced region is
through its current test, including the test's internal repetitions.

The live byte count includes completed verification blocks from tests that are
still running. Final results and `testsmem4u.log` record the exact verified-byte
total and complete-cycle count, including completed checks from a stopped run.
`--debug` adds progress snapshots every ten seconds: aggregate byte deltas and up
to four workers' positions, current-test steps, phases, and time since their byte
counts last advanced.
A fill or disturbance phase can perform useful work before the next verification;
an unchanged verified-byte count alone does not establish that a worker is stuck.

Defaults use all available CPU targets and 85% of total physical RAM. For concurrent
desktop use, select fewer workers with `--cores` and a smaller window with
`--memory` to leave more resources for other applications.

### Linux: swap and swappiness

The test window is locked in RAM and is never swapped, so everything else
(kernel, desktop, applications, file cache) must fit into the remaining ~15%.
To keep the desktop usable during a default-sized run:

- **Leave enough headroom** for the applications you keep open; if the desktop
  becomes sluggish, reduce the window with `--memory`.
- **Have a swap file or partition** so the kernel can move idle application
  memory out of the way instead of only shrinking the file cache.
- **Avoid `vm.swappiness=0`.** It defers swapping until the file cache is nearly
  exhausted. Other values, including distribution defaults, are fine.

Check the current settings with:

```bash
swapon --show
cat /proc/sys/vm/swappiness
```

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
RowHammer remains a heuristic disturbance test. Because workers run independently,
one region's RowHammer can disturb rows shared with a neighbouring region running a
different test; errors found during such an overlap are flagged with a warning in
the log. `RandomAccess` Parameter 1-100 is a pass multiplier, while larger values
are an explicit access count per worker region. Firmware-reserved and OS-owned RAM
is outside this user-space tester's allocation.

Implementation details, regression coverage, and local performance measurements are
recorded in [the memory-testing wiki](llm-wiki/memory-testing.md).

## Other projects

- [capture-engine](https://github.com/aufkrawall/capture-engine) - game capture, recording, overlays, graphics
  overrides, and frame pacing for Windows
- [green-curve](https://github.com/aufkrawall/green-curve) - open-source GPU curve undervolting and overclocking
- [Shader-Stress](https://github.com/aufkrawall/Shader-Stress) - CPU stress test with shader-compilation-like
  workloads
- [obs-indicator](https://github.com/aufkrawall/obs-indicator) - a low-overhead OBS recording-status indicator

More projects are available on [my GitHub profile](https://github.com/aufkrawall?tab=repositories). All of these
projects would also profit from donations - see [Support](#support) at the top of this page.
