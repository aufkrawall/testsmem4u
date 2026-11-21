# Changelog

## Unreleased

### Fixed

- **RowHammer minimum chunk size and zero-byte completion guard:** `RowHammer` on regions of 24 KiB or less now fails closed with an infrastructure error instead of returning an empty result and letting the scheduler credit a completed cycle with zero verified bytes; multi-worker runs on small windows (such as 1 MiB across 48 requested threads) cap worker/chunk counts so every chunk stays above the 24 KiB threshold, `Test Block Size` folds tiny sub-24-KiB RowHammer tails into the preceding block, and the engine refuses to credit any test entry that completes without verifying memory.
- **Interrupted finite and zero-byte runs exit non-zero:** finite runs (`--cycles` or `--duration`) stopped before completion, runs that verify zero bytes, and a second Ctrl+C force-quit on Windows (`STATUS_CONTROL_C_EXIT` instead of `0`) no longer exit with status `0`; detected errors continue to take precedence with exit code `1`.
- **Linux process memory limits in sizing:** percentage sizing and safe-maximum checks on Linux (`getProcessMemoryLimit`, `getSizingBaselineRAM`) now honor cgroup v2 `memory.max` across the hierarchy, cgroup v1 memory limits, and `RLIMIT_AS` instead of sizing only against host RAM.
- **32-bit Linux RAM detection and addressable limit:** `getTotalSystemRAM` and `getAvailableSystemRAM` now multiply `totalram`/`freeram` by `mem_unit` in 64-bit arithmetic instead of wrapping modulo 4 GiB, and 32-bit builds clamp percentage windows and reject explicit windows exceeding the single-region 32-bit mappable ceiling (`< 2 GiB`).
- **Windows ordinary `VirtualLock` without `SeLockMemoryPrivilege`:** `tryAllocateVirtualLock` and the startup privilege prompt no longer reject or gate ordinary `VirtualLock` allocations on `SeLockMemoryPrivilege` (which is only required for `MEM_LARGE_PAGES`), letting Windows decide locking within the process working-set quota.
- **Windows working-set residency verification:** `checkMemoryResident` on Windows now inspects actual page residency with `QueryWorkingSetEx` (after `VirtualQuery` commit/protection checks) instead of accepting nonresident `MEM_COMMIT` pages, and `tryAllocateStandard` prefaults each native page at allocation time so freshly allocated unlocked memory is materialized before pattern tests begin.
- **Config save write/flush verification:** `saveConfig` now checks stream write/flush/close status and flushes OS file buffers/fsync before replacing the target file, deleting the `.tmp` file and preserving any previous valid configuration on failure.
- **Complete config `.tmp` validation in crash recovery:** `recoverOrphanedTempFile` only promotes an orphaned `.tmp` when the target is absent and the temp file passes validation with all settings and its completion marker, discarding truncated temp files instead of turning partial timed saves (`Cycles=0` before `TimeLimitSeconds`) into infinite runs.
- **Previous log preserved on dry runs and startup errors:** startup diagnostics buffer in memory until an actual test run starts (`Logger::attachFile`), so `--dry-run`, invalid configs/presets, and pre-run exits no longer truncate the previous `testsmem4u.log`.
- **Closed stdin does not grant Windows privilege:** the `SeLockMemoryPrivilege` interactive prompt checks `std::getline` stream state and only treats an explicit `y`/`yes` or a live empty Enter press as confirmation, never triggering on EOF.
- **Linux terminal auto-relaunch scoped to bare GUI launches:** terminal emulator relaunch now runs after CLI parsing/early exits and only when launched without arguments, TTYs on stdio, or a stdout pipe, preventing graphical sessions from diverting scripted or invalid CLI invocations into a terminal wrapper.
- **Full `x86-64-v3` and `x86-64-v4` CPUID feature detection:** x86 SIMD capability detection now checks all required psABI v3/v4 CPUID extensions (`BMI1`, `BMI2`, `FMA`, `F16C`, `MOVBE`, `POPCNT`, `LZCNT`, `SSE4.1`/`4.2`, `AVX512F`/`DQ`/`CD`/`BW`/`VL`, and XCR0 state) instead of treating `AVX512F` alone as `v4`-capable or `AVX2` alone as `v3`-capable.

## 1.11 - 2026-11-15

### New

- **Time-limited runs:** the wizard's memory prompt now accepts sizes in MB or GB and an optional time limit right after the size: `50MB`, `27GB`, `50MB30m` (30 minutes) or `27GB4h` (4 hours); `1h30m` and `90s` also work. With a time limit the wizard skips the cycle question and testing runs until the limit expires, then stops and reports the results like a finished run (the current test is cut short; completed cycles are reported as usual). On the command line, `--duration 4h` sets a limit (a bare number means minutes, `none` clears a saved limit) and `--memory` accepts the same `27GB4h` form; without `--cycles` the cycle count is then unlimited, with both the run stops at whichever comes first. The limit counts from the start of testing (after memory allocation), is saved in `config.ini` (`TimeLimitSeconds`), and appears in `--show-config` and in the status line as elapsed/limit. The results and log now state why testing ended (`Stopped by: time limit`, `cycles`, `halt on error`, `stop request` or `infrastructure failure`).
- **Per-beat complement pattern (SimpleTest `Pattern Mode=3`):** every second 64-bit word is the exact complement of the one before, so all data lines of a DDR4 channel flip on every other bus beat (the worst case for crosstalk and simultaneous switching), and with a Param0 whose 32-bit halves are complements (such as `0x55555555AAAAAAAA`) the 32-bit beats of a DDR5 sub-channel flip as well. Unlike a uniform alternating pattern, each 16-byte unit also carries its own address tag (Param1 is the tag step), so misplaced or aliased writes are still detected. Passes change the tag, not Param0, so the complement relations hold on every pass. TestMem5 builds its base pattern this way for every test; previously only MirrorMove128's fixed 0x55/0xAA pair did this here. Most memory controllers scramble data on the bus by default (an address-keyed XOR for signal integrity), so the full toggling applies where scrambling is off; with scrambling it is still an address-tagged pattern with fixed complement relations in software, but the bus sees it scrambled. Pattern Mode 3 has SIMD paths for SSE2, AVX2 and AVX-512 like the other address patterns.
- **Strided SimpleTest writes (`Line Stride`):** a new per-test preset key makes SimpleTest write its pattern in strided order instead of front to back: with `Line Stride=256` it writes 64-byte line 0, 256, 512, ..., then 1, 257, ..., so consecutive writes land in different DRAM rows and the hardware prefetchers get no stream to follow. That turns a streaming fill into a stream of row misses at full write bandwidth (activate/precharge timings under load), which sequential fills and the latency-bound RandomAccess do not provide. Every word is still a non-temporal store and the verification pass stays sequential. All pattern modes work with it; `0` or `1` (default) keeps the sequential fill.
- **Idle memory is checked before it is reused:** when a test on a memory chunk finishes with known data in place (SimpleTest in every pattern mode, MirrorMove, MirrorMove128, RandomAccess), the next test that takes that chunk first re-reads all of it from DRAM and compares. Meanwhile the chunk sat untouched for as long as the other workers needed for their tests (seconds to minutes under full memory load), so this catches cells that lose charge over long holds and writes that land in the wrong place (address decoding faults, disturbance from other chunks), which tests that rewrite their memory right away cannot see. It costs one read pass per test and no extra writes, and is skipped when a single worker takes its own chunk back immediately. Errors are logged as `Idle check after <test>` (with a note when RowHammer ran on another chunk meanwhile) and count like any other error; the log ends with the number of checks, verified GiB, idle times and errors, and `--debug` logs each check. This replaces nothing: RefreshStable's 10-second holds stay. TestMem5 gets a similar effect from its background pattern, which every test checks before overwriting it.
- **Different tests on different cores (opt-in):** `Sequence Start=staggered` in a preset's `[Main Section]`, or `--sequence-start staggered` on the command line, makes each memory chunk start the test sequence at a different, evenly spread entry. Workers then run different tests at the same time, so the memory traffic always mixes streaming, copies, random accesses and retention holds instead of all cores running one test, and every test type is running from the first minutes. Every chunk still runs every entry once per cycle, so coverage and cycle counting are unchanged. The default stays `aligned` (all chunks start at the first entry) until comparisons on unstable hardware show which finds errors faster; RowHammer then overlaps other tests, so their errors are more often tagged as possible cross-chunk disturbance. `--show-config` shows the effective mode and its source, and the log records it at startup together with a one-line summary of the sequence (entries per cycle, distinct tests, tests listed more than once).

### Improved

- **Cycle timing in every log:** `testsmem4u.log` now records when each cycle completed on every memory chunk and ends with a time breakdown per sequence entry: share of worker time, completed runs, average duration, seconds after start until it first ran, verified GiB, and invocations cut short when the run ended, followed by totals per test function (all its sequence entries combined, with the earliest start of any of them). Where a cycle's time goes, and how soon every test type runs, no longer needs `--debug` or log post-processing.
- **New data on every pass:** repeated loops, cycles and internal repetitions no longer rewrite identical bits. Previously every cycle (and every loop of entries such as BlockMove's 200) wrote exactly the same data, so later cycles re-tested the same cell, value and neighbour combinations; for example MovingInversionLFSR's 50 repetitions all used one seed and MovingInversion's 150 alternated one value pair. Each pass now derives fresh seeds or pattern offsets for the address patterns, MirrorMove/MirrorMove128 pairs, BlockMove, MovingInversion, LFSRPattern, MovingInversionLFSR, Modulo20 and RefreshStable, and pseudo-random streams also differ between memory chunks. The first pass still writes exactly the configured patterns, uniform SimpleTest values (all-0, all-1, 0xAA) and walking bits stay fixed, and complement pairs are kept so every cell still holds both states. Pass data is reproducible from the logged cycle and loop; `--debug` test-start lines record the pass variation.
- **Repeated tests in one cycle test new data:** a test listed several times in a cycle's `Test Sequence` (TestMem5-style interleaving, as in anta777's presets) now writes different data at every occurrence. Previously the pass data depended only on cycle and loop, so every occurrence within a cycle rewrote the same bits as the first. Tests listed once per cycle write exactly the data they wrote before. `--debug` test-start lines record the occurrence (for example `occurrence=3/6`).
- **RandomAccess data uses all 64 bits:** each word now stores a unique full-width value instead of its own word number, whose upper 32 bits were the same in every word, so those bits were only ever tested with one value (and its complement). Values and the access order also change on every pass. Debug summaries log the pass's value salt.
- **About 11% more memory traffic per hour on x86-64:** the whole-region cache flush after each streaming (non-temporal) fill is skipped where it cannot matter. Such fills already evict every cached line of the region (documented by Intel and measured on Zen 3), but the flush still walked the whole region with the memory bus idle, adding roughly 30% to each fill-and-verify pass. Flushes after reads, march write-backs, copies and retention dwells are kept, as are all flushes on ARM64, 32-bit x86 and CPUs without non-temporal store support. Measured on a Ryzen 7 5700X: 21.1 instead of 19.0 GiB/s verified. `tools/probes/nt_fill_cache_probe.cpp` checks the assumption on other CPUs, and `--debug` logs whether post-fill flushes are skipped.
- **Better pseudo-random data in LFSR tests:** LFSRPattern and MovingInversionLFSR now store a mixed value of each LFSR state. The raw states advance by a one-bit shift, so every word was a shifted copy of the previous one and neighbouring data bits carried the same bit stream one word apart. The words now have no measurable correlation with each other, at unchanged speed: a new two-lane SSE2 path keeps pre-AVX2 builds as fast as AVX2 builds.
- **Even coverage across the whole test window:** workers no longer own fixed memory regions. The window is split into equal chunks (two more than the number of workers), each chunk runs the test sequence in order, and a worker that finishes a test takes the least advanced idle chunk other than the one it just finished, so a slow worker cannot keep a lagging chunk to itself. Previously, SMT-sibling threads got half-size regions but the same memory bandwidth, so they finished about twice as fast and lapped the others, and OS activity made some workers up to 2x slower than others. The slowest region set the completed-cycle count and was tested about half as often. Now a slow CPU simply runs fewer tests and every part of the window is tested at the same rate: in a 1 GiB, 16-thread check all 18 chunks stayed within 3 tests of each other and 40 cycles finished in about 8 s instead of 15 s. Status, `Coverage` and `--debug` progress refer to chunks; debug logs record the chunk layout and each test's chunk.

### Changed

- **Default preset uses the new stresses:** `default.cfg` adds Test19, a per-beat complement SimpleTest (`Pattern Mode=3`, twice per cycle), writes its linear-address SimpleTest (Test4) in strided order (`Line Stride=256`, Time 40 instead of 50 for the same slice length), and gives MirrorMove128 even/odd words whose 32-bit halves are also complements (`0x55555555AAAAAAAA`/`0xAAAAAAAA55555555`) so DDR5 sub-channel beats flip too. Mirror pass counts were recalibrated for the real mirror moves (MirrorMove128 100 instead of 40, MirrorMove 74 instead of 50) so each slice takes about as long as before: measured 2 GiB A/B runs on a Ryzen 7 5700X put a MirrorMove128 slice at about 3 minutes at 28 GB, as before. One cycle at 28 GB is projected at about 64 instead of 62 minutes (the new entries and the idle-chunk checks); not confirmed by a full-size run.
- **MirrorMove and MirrorMove128 now really mirror memory:** both used to work in place: MirrorMove filled the chunk and inverted every word where it was, MirrorMove128 shifted the whole chunk by one word with `memmove`. Neither moved data between distant addresses, which is what TestMem5's tests of the same name do and what makes them hard on memory timings. Now two streams start at opposite ends of each memory chunk, read what they find and write it back swapped while moving toward each other, so every step reads and writes two far-apart rows (row conflicts and read/write turnarounds within one thread), with non-temporal writes and a cache flush before every check. MirrorMove reverses the chunk word by word on linear address data (Param0 base, Param1 step); MirrorMove128 reverses the order of its 16-byte units on the new per-beat complement data (Param0/Param1 are the even/odd words, kept as complements, with an address tag per unit). `Parameter` is now the number of mirror passes; every pass is verified completely, and a word misread during a move is reported where it landed. `--debug` logs a summary per invocation.
- **Default preset finds instabilities sooner and finishes in about half the time:** `default.cfg` now interleaves short slices of every test (TestMem5 style) instead of running each test once per cycle in one long block. Previously, at 28 GB, MirrorMove128 ran for about 27 minutes at a stretch and RandomAccess, RefreshStable, Modulo20 and RowHammer first started 72-87 minutes into the run; a weakness that only one of those stresses exposes went unnoticed that long. Now MirrorMove128 recurs six times per cycle and RandomAccess and RefreshStable three times, the main stress types run within the first 20 minutes and every test within 45, and no slice takes longer than about 3 minutes. One cycle at 28 GB is projected to take about one hour instead of two (three cycles about 3 instead of 6 hours; projected from measured 64 and 128 MB runs on a Ryzen 7 5700X with DDR4, so check `Time by function` in your log). RowHammer gets two slices of 160 points per GiB instead of 2 points per MiB (18% of the old cycle for a test whose physical effect is unverified), Walking tests one loop each instead of five, and other tests fewer repetitions per slice. A new Test18 adds TestMem5's small-block approach: an XOR-address SimpleTest repeated 32 times on each 4 MB block. Test IDs 0-17 keep their functions.

- **RowHammer `Parameter` is a density:** an explicit RowHammer `Parameter` now means hammer points per GiB of the tested memory chunk instead of an absolute count per chunk, so RowHammer takes the same share of a cycle on every memory size and core count, like the other tests. A fixed count made small windows and many-core CPUs (more, smaller chunks) spend far more time hammering: 250 points cost about 90 s per chunk even on a 64 MB window, making a 64 MB default cycle take 5.6 instead of about 3 minutes. `Parameter=0` keeps the previous default of 2 points per MiB; every invocation still hammers at least one point per stride. Presets that set an explicit count should divide it by the chunk size in GiB. The per-stride `RowHammer: Sweeping stride` lines (hundreds per cycle with the interleaved preset) moved to `--debug`, which also logs a per-invocation summary; the normal log states the point budget once per RowHammer entry.

### Fixed

- **Regression tests with one usable CPU:** the wizard time-limit and idle-chunk tests now work on single-CPU systems and under one-CPU affinity restrictions. The time-input fixture requests one thread; the idle-chunk test always checks the single-worker behavior and explicitly reports when its multi-worker case cannot run.
- **Large line strides on 32-bit builds:** a SimpleTest `Line Stride` larger than the tested block now writes each word once. Very large accepted strides previously wrapped the line index and repeatedly rewrote earlier lines, causing quadratic work and delaying cancellation or time limits until the fill finished. The preset debug line states the block-size bound.
- **Preset OS reserve is honored:** a preset's `Reserved Memory for Windows (Mb)` was read and then ignored; sizing always left a fixed 256 MB untested. It now sets how much RAM stays untested for the operating system (on every platform, at least 256 MB): a percentage window is RAM times the percentage minus that reserve, and an explicit window that would eat into it is refused with an error naming the reserve. `default.cfg` reserves 512 MB, so default 85% runs now test 256 MB less; TestMem5 presets keep their usual 256 MB. `--show-config` shows the reserve and `--debug` logs the sizing inputs. A 100% window could also be refused by 1 MB because the percentage was computed with up to 99 bytes of rounding loss.
- **Ctrl+C during startup now stops the program:** a Ctrl+C or console close during the startup countdown, the configuration wizard or a prompt was forgotten when the test started, so the whole run went ahead and the next Ctrl+C quit at once without writing any results. The stop request is now kept: the program skips memory allocation and testing, prints its (empty) results and logs that the stop came before testing started.
- **RowHammer point budget on small blocks:** RowHammer's point budget now scales with the exact size of the tested block. It was rounded down to whole MiB first, so blocks under 1 MiB (for example the remainder of a chunk split by `Test Block Size`) got only the one-point-per-stride minimum, and small chunks lost up to a sixth of their budget (a 3.6 MiB chunk at `Parameter=10000`: 29 instead of 35 points). Chunks of the usual hundreds of MiB are unaffected. The run log's point-budget line now appears once per RowHammer entry of the preset instead of only for the first, and names the strides actually used (blocks of 192 KiB or less drop the widest).
- **No false "extremely long run" warning for the default preset:** the startup loop estimate counted RefreshStable's dwell time in milliseconds and RowHammer's points per GiB as repetitions, so the default preset warned about an excessive run from `--cycles 4` on although each cycle takes about an hour at 28 GB. Only Parameters that are repetition counts are counted now (RandomAccess up to 100 passes, Modulo20's default of 3); `--debug` logs the estimate.
- **Staggered start with one worker:** with a single memory chunk (`--cores 1`) or a single enabled entry, `Sequence start: staggered` now states that it has no effect instead of claiming that workers run different tests at the same time.
- **Windows CPUs reserved for other processes:** when the process affinity mask allows only CPUs that Windows CPU sets reserve for another process, workers still run there (there is no other CPU), but now keep the CPU-set topology (SMT pairing, efficiency classes) instead of falling back to plain logical-processor numbering, and the log warns about it instead of counting those CPUs as skipped.
- **Closing the console window no longer loses the run's results:** on Windows, closing the window (or logging off or shutting down) during a run ended the process before the time breakdown, coverage and results reached `testsmem4u.log`. The run now stops and writes them first, and the log notes the close event; Windows still ends the process right afterwards. A second Ctrl+C still quits immediately.
- **CPU topology and worker placement:** Windows worker placement now actually uses CPU sets. A wrong filter treated the "allocated" flag (which means reserved for one process's exclusive use, normally off) as required, so every ordinary CPU was discarded and the program always fell back to plain logical-processor numbering: cores were never paired with their SMT siblings and hybrid Intel P/E efficiency classes were ignored. With fewer workers than logical CPUs (`--cores`), workers now take separate physical cores, P-cores first, before SMT siblings.
- **Restricted CPU affinity respected:** a process started with a CPU affinity restriction (for example `start /affinity` on Windows) placed workers on CPUs outside it; it now uses only the allowed CPUs. On Linux (`taskset`, cpusets) and with Windows CPU sets reserved by other processes, a thread whose core sibling was excluded was still treated as an SMT sibling, so it was used last although nothing else ran on its core. 32-bit Windows builds no longer compute undefined affinity masks for logical CPU numbers above 31 on hosts with more than 32 logical CPUs per group; a 32-bit process cannot bind to those CPUs, so they are skipped. `--debug` logs the topology source, usable, SMT-sibling, reserved and affinity-excluded CPU counts, whether core types differ (previously reported "yes" on every SMT CPU), and each worker's core, efficiency and scheduling class, SMT role and parked state.

## 1.10 - 2026-10-14

### Improved

- **32-bit regression coverage:** `python build.py --tests` now also builds and runs a 32-bit x86 Windows test runner, so defects specific to 32-bit builds such as `linux-x86` (for example the RandomAccess inversion fix below) are caught automatically instead of only by manual cross-builds.
- **RandomAccess error diagnosis:** debug logs identify the original, inverted or restored phase and the batch's access offset when a mismatch occurs, for the first 8 mismatching batches per region; the region summary counts the rest, so a failing module cannot flood the debug log. Focused regressions check clean runs at large logical offsets, partial batches, exact coverage, boundary preservation, transient/persistent errors in every phase and halt/continue behavior.

### Fixed

- **RandomAccess on 32-bit Linux:** the inverted phase now flips all 64 bits of each checked word. The `linux-x86` build previously left the upper 32 bits at zero in both phases, so faults in those bits went undetected there. Other targets were unaffected, and no build could report false errors from this.
- **x86 cache-flush stride:** use the CPU's advertised CLFLUSH/CLFLUSHOPT granule instead of incorrectly decoded cache-topology fields, capped at 64 bytes so an over-reported granule (for example from a virtual machine) can never skip cache lines and let verification read cached data instead of RAM. The debug log reports both the advertised granule and the stride used. This was not established as a cause of false-positive errors.

## 1.9 - 2026-10-14

### New

- **Linux first-run huge-page setup:** interactive root runs detect disabled effective THP policy and recommend a default-Yes runtime `madvise` change. The offer explains its system-wide scope and temporary persistence; verified setup takes effect in the same run without a reboot. Direct runs and disabled large-page preference leave policy unchanged.

### Improved

- **Huge-page setup coverage:** added checked Linux THP policy inspection and setup regression coverage for native-size overrides, inherited process restrictions, explicit consent, write/readback failures and concurrent policy changes.
- **Large-page setup guidance:** Windows clearly recommends the required account privilege and explains that signing out and back in is sufficient. The README describes both platforms' setup, page mechanisms, fallbacks, persistence and aggressive preparation.
- **Comparable configuration wizards:** Windows and Linux ask the same questions and default to 85% of RAM, all cores, three cycles, strict locking, large-page preference and halt-on-error. Saved wizard settings retain percentage/all-core policies for the next system instead of freezing resolved RAM/thread counts; explicit selections remain explicit.
- **Linux huge-page defaults:** large-page preference now requests aligned transparent huge pages automatically when an existing HugeTLB pool cannot satisfy the window, while preserving strict memory locking and native-page fallback. Allocation and RowHammer diagnostics report measured huge-page coverage, including conservative bounds for partial worker slices.

### Fixed

- **Linux strict-lock startup:** lock-limit or permission failures are rejected before explicitly populating the entire test window, avoiding unnecessary memory pressure for runs that cannot satisfy strict locking. Accepted locked and pageable mappings still receive write-prefaulting before tests start.
- **Unattended Linux startup no longer waits on the THP offer:** when the startup countdown expires without opening the configuration, a disabled THP policy is reported with instructions instead of blocking indefinitely on a `[Y/n]` prompt. The offer still appears after the operator opens the wizard. Confirmations now accept surrounding whitespace, CRLF input and any letter case, and setup diagnostics no longer appear twice on the console.
- **THP inspection on kernels without `hpage_pmd_size`:** such kernels are treated as global-policy-only, so an already enabled THP policy is no longer reported as "could not determine" on every large-page run. The allocator and THP setup now share one page-size parser, so both select the same huge-page size.
- **Windows hybrid rollback:** when locking a native tail chunk fails during hybrid large-page allocation, that chunk is now released through the same owned cleanup as the others, so release failures are reported instead of silently leaking the chunk. The diagnostic names the lock failure instead of an unavailable address.
- **Linux pageable fallback logging:** an `mlock` failure that continues with explicitly permitted pageable memory is logged as a warning; only strict-lock aborts are errors.
- **Wizard cycles and page granularity:** invalid cycle input falls back to three instead of accidentally selecting an infinite run. Invalid thread input now keeps the portable all-core policy with a notice instead of saving this system's core count. Both platforms normalize windows using their preferred large-page size; Windows chunking reaches its actual native large-page minimum, and worker caps use native base pages on non-4-KiB systems.
- **Windows allocation footprint and recovery:** chunked large-page fallback keeps the requested size instead of rounding small windows up to much larger chunks. Partial allocations are released on exceptions, and an explicitly allowed pageable fallback retains its original size after a lock failure.
- **Windows cache preparation:** aggressive preparation flushes the file-cache working set with the documented API instead of toggling cache limits and potentially leaving hard limits enabled at zero.
- **Native page sizes:** allocation and worker partitioning use the OS base page size; HugeTLB allocation uses its actual default size and does not silently expand a small window to a 1 GiB huge page.
- **HugeTLB lock status:** inherently non-swappable HugeTLB mappings no longer require a redundant successful `mlock()` to satisfy strict locked-memory testing.

### Changed

- **RowHammer coverage check:** RowHammer reuses the large-page coverage measured once after allocation instead of re-reading `/proc/self/smaps` for every worker and invocation, which walked the page tables of the whole test window while other workers were testing. Its warning now reports allocation-wide coverage.
- **Windows aggressive preparation:** ordinary full large-page attempts now run first. Only failure permits one system-wide preparation and retry; allocation no longer relies on fixed sleeps or increasing delays.
- **Linux huge-page preparation:** automatic huge-page provisioning uses process-owned transparent pages instead of changing the persistent HugeTLB pool, preventing reservations from remaining after a kill or overwriting concurrent pool changes. Preconfigured HugeTLB pools remain supported; `--aggressive-defrag` retains optional cache dropping, compaction and one process-local collapse attempt without fixed delays.

## 1.8 - 2026-10-13

### Fixed

- **Unaligned x86 cache flushes:** region flushing covers both boundary cache lines when a range starts or ends inside a line.
- **Live tested-memory progress:** long test invocations now publish verified bytes and observed errors during testing instead of leaving the displayed total unchanged until all internal repetitions finish. Separate worker counters preserve exact totals through nested retention work, configured sub-blocks, cancellation, and worker exceptions.
- **Final test totals:** console results and the persistent log now report the exact verified-byte total and completed cycles, including partial work from a stopped run. The console explains that repeated verification reads contribute to the total.
- **Narrow-terminal progress:** tested-memory totals remain visible alongside errors and elapsed time when cycle details or long test names exceed the terminal width.
- **Progress monitor failures:** exceptions in status rendering or progress diagnostics now stop and join the workers and preserve collected results instead of terminating the process.
- **Failure recovery under memory pressure:** monitor and worker exception handlers record failure and request shutdown before formatting diagnostics. Continued allocation or logging failures use a bounded stderr fallback, allowing threads to join and verified totals to be collected.
- **Linux hugepage pool restoration:** with `--aggressive-defrag`, closing the terminal (SIGHUP), a second Ctrl+C/SIGTERM during shutdown, or SIGTERM followed by another signal no longer leaves the raised system hugepage reservation behind, which could keep most RAM unavailable until reboot. SIGHUP now stops the run gracefully with final results; repeated signals restore the original count before exiting. Restore failures are logged.
- **Repeated fill diagnostics:** SimpleTest publishes its fill phase before every repetition's pattern generation and cache flushing, so normal fill intervals no longer retain the previous verification label.

### Improved

- **Useful memory throughput:** region cache flushes dispatch once instead of calling a helper for every cache line, and uniform moving inversions keep expected patterns in registers. Verification preserves the original observed errors, vector traversal, replacement writes, and byte accounting; no filler load or reduced test coverage was added.
- **LFSR generation:** AVX2-capable variants generate four exact consecutive LFSR states in parallel for streaming fills and expected-data verification. Reverse blocks use an equivalent four-step inverse; seeds, patterns, terminal states and verification coverage are preserved.
- **Random and disturbance throughput:** random access prepares its disjoint address bands once and flushes written addresses with one dispatch/fence. RowHammer uses the same batch-flush path; Modulo20 writes fixed nineteen-word spans while preserving protected words and pass boundaries.
- **Kernel diagnostics:** per-march summaries identify register-pattern uniform marches separately from LFSR table verification.
- **Current-test progress:** the status line now shows how far the least advanced worker is through its current test (for example `T4/18 37%`), so long tests such as MovingInversion's 150 repetitions no longer look stalled while the test index stays unchanged. Progress combines the test's external loops, configured sub-blocks and the kernel's own repetitions, dwells, offsets, hammer points or random-access batches; `--debug` snapshots include each listed worker's step.
- **Long-test diagnostics:** `--debug` records bounded progress snapshots every ten seconds with verified-byte deltas and up to four workers' test positions, phases, and time since their last verified-byte change. Fill, verification, residency, and disturbance phases distinguish normal long work from a possible stall without adding clocks or logging to hot verification blocks.
- **Regression coverage:** added deterministic progress, cancellation, worker/monitor exception, nested accounting, multi-terabyte counter, diagnostic cadence, and narrow-terminal tests across baseline and AVX2 paths.

- **Agent instructions baseline:** merged upstream prompt-template improvements into `AGENTS.md` covering economical diagnostic logging format, test-app and background process lifecycle management, toolchain substitution guardrails, direct artifact/change verification rigor, concise bullet-point commit messages, and small reviewable commits.

### Changed

- **Linux memory headroom guidance:** `README.md` now recommends leaving headroom, having swap and avoiding `vm.swappiness=0` for desktop use alongside the locked default test window, and correctly states that Linux runs relaunch through `sudo` unless `--no-elevation` is given.
- **Support and project references:** added GitHub Sponsors and Buy Me a Coffee donation badges and cross-project links to `README.md`.

## 1.7 - 2026-10-06

### New

- **Developer and debug tool discovery:** added non-mutating `tools/discover-debug-tools.ps1` to detect installed Windows SDK debuggers (`cdb`, `windbg`, `dumpchk`, `symchk`), MSVC tools, LLVM utilities, and Sysinternals.
- **Local tool path configuration:** added `tool-paths.example.env` for machine-local toolchain, SDK, and symbol path overrides.
- **Security audit and binary tool inventory:** added `llm-wiki/debug-tools-security-audit.md` and `llm-wiki/debug-tools.md` for native Windows and Linux binary hardening inspection, crash diagnosis, and memory testing verification.
- **Engineering and security guidelines:** added mandatory pre-commit and post-commit secret inspection procedures and changelog maintenance guidelines under `llm-wiki/`.

### Improved

- **Startup diagnostics and regression coverage:** added allocation/prefault and configuration debug messages, deterministic preparation-thread exception tests, and real CLI/build-tool regressions to the normal test command.
- **LFSR streaming throughput:** restored non-temporal streaming stores in `fill_lfsr` (MOVNTI on x86_64) so DRAM write stress is sustained during `LFSRPattern` and `MovingInversionLFSR`.
- **RandomAccess DRAM stress:** added cache flush after initial sweep so random reads target physical DRAM rather than CPU cache; clarified `Parameter` configuration handling (<=100 passes, >100 explicit count) with helper and startup warning.
- **RefreshStable background coverage:** introduced a persistent active-half cursor across dwell windows so short retention dwells reliably sweep the entire active half.

### Fixed

- **Linux unlocked-memory startup:** materialize fresh anonymous pages before residency checks so unlocked runs can complete their first test cycle; residency checks remain enforced.
- **Preparation exception handling:** join the preparation display thread during allocation failures and propagate display failures after joining, preserving normal infrastructure-error reporting.
- **Invalid configuration files:** reject malformed, unreadable, or non-file configurations instead of silently running with defaults; a missing optional file and explicit `--no-config` still allow defaults.
- **Static-analysis verification:** generate absolute compilation-database paths, refresh the database for each lint run, and fail on diagnostics, missing commands, skipped sources, or tool failures. Corrected the project diagnostics exposed by actual analysis.
- **Modulo20 disturbance and verification:** corrected false claim regarding untouched cache lines (due to RFO and writeback); switched disturbance to range fills and verification to SIMD `verify_words` using a 1280-word stride-aligned expected table.
- **RowHammer disturbance isolation:** added `DisturbanceWindow` warning annotations for tests that overlap peer workers' RowHammer execution, avoiding false alarms without forcing idle barrier synchronization.

### Changed

- **Test kernel optimization and cleanup:** removed dead `TestContext` status fields and obsolete barrier tests; hoisted `BlockMove` buffer allocations out of iteration loops; added per-invocation debug summaries.

## 1.6 - 2026-09-12

### New

- **Modulo20 pattern test:** officially registered and enabled in `default.cfg` to stress memory cells and bus lines with modulo-20 disturbance sequences.

### Improved

- **Continuous independent worker scheduling:** eliminated lockstep barrier stragglers; workers advance independently across contiguous page-aligned slices and fast workers continue testing until all regions complete requested cycles, sustaining continuous DRAM load.
- **Retention testing with active background stress:** `RefreshStable` now alternates held and active halves with dual polarity, preserving untouched retention dwell while the active half runs address-sensitive memory passes to keep the memory bus and controller active.
- **March test SIMD acceleration:** forward and backward marches (`WalkingBit`, `MovingInversion`, `MovingInversionWalking`) now read and replace patterns at SIMD granularity and verify restored data.
- **BlockMove and MirrorMove128 stress:** `MirrorMove128` now performs actual data movement; `BlockMove` poisons destinations, uses address-sensitive patterns, copies bidirectionally, and validates unaligned tails.
- **RandomAccess concurrency:** expanded to 16 overlapping disjoint lanes with batched memory fences, checking restorations and final full-region integrity.
- **Console UI readability:** reordered status line so error count and elapsed time precede shortened test names, preventing critical status data from being truncated on narrow terminals.

### Fixed

- **Transient error preservation in LFSR:** eliminated transient-losing `memcmp` and scalar re-reads; LFSR verification computes reverse state directly, removing serial seed-table precomputation.
- **RowHammer aggressor and victim bounds:** checks victims promptly, verifies potential victims before reusing aggressor rows, and enforces explicit point budgets across stride variations.
- **Shutdown race condition:** replaced context-pointer-based shutdown flag with a static-lifetime atomic stop flag, eliminating potential asynchronous teardown lifetime races.

### Changed

- **Modular test engine architecture:** decoupled monolithic `TestEngine.cpp` into dedicated test kernel modules (`TestMarch.cpp`, `TestPatterns.cpp`, `TestMemoryTraffic.cpp`, `TestModulo.cpp`, `TestRowHammer.cpp`).

## 1.5 - 2026-06-10

### Improved

- **SIMD MirrorMove128 verification:** accelerated pattern verification via `simd::verify_pattern_pair` across AVX-512, AVX2, SSE2, and scalar paths, completing checks in a single pass with bounded error sampling.
- **Non-temporal stores in scalar fallbacks:** x86_64 scalar fallbacks for linear, xor, and increment patterns now use `_mm_stream_si64` NT stores to preserve DRAM write pressure on baseline binaries.
- **Dual test runners in build system:** `build.py --tests` builds and runs both baseline (SSE2) and `-v3` (AVX2) test runners automatically, with optional `--tests-v4` for AVX-512 hosts.

### Fixed

- **Transient error retention in SIMD verifiers:** SIMD verifiers now spill vector registers directly to a stack buffer upon mismatch detection, preserving transient bit flips that were previously dropped during scalar re-reads.
- **Console and status line collision:** routed all logger console output through `ConsoleDisplay` under a single mutex, eliminating scrambled progress displays and race conditions between logging and status updates.
- **Early log message loss:** initialized logger before configuration and preset resolution so startup warnings and diagnostics are recorded in the log file.
- **Linux hugepage reservation leak:** fixed SIGABRT signal handler to safely restore kernel hugepage reservation (`nr_hugepages`), preventing leaked allocations on abnormal aborts.
- **Windows elevation exit code propagation:** elevation relaunch now waits for the elevated child process and returns its exit code, enabling accurate status reporting in automated scripts.
- **Console error flood prevention:** applied error rate limiting uniformly across all execution states, preventing I/O stalls during severe memory failure storms.
- **Build race in configuration deployment:** serialized `*.cfg` distribution file copying out of parallel target builds.

### Changed

- **Manual binary variant selection:** removed automatic relaunch to `-v3`/`-v4` binaries to avoid lingering parent console windows; added startup warning hints when the CPU supports a higher SIMD level than the running binary.
- **Error classification deduplication:** consolidated duplicated classification loops across march, walking, and block move tests into unified `classifyAndLogErrors`.

## 1.4 - 2026-06-07

### New

- **Automated multi-target build matrix:** `python build.py` defaults to `--toolchain all`, automatically partitioning and compiling all 10 release targets using MinGW (Windows x86_64 variants) and Zig (Linux x86/x64/ARM and Windows ARM64).
- **Static analysis and fuzzing integration:** added `--lint` supporting `clang-tidy` and added a preset fuzzer harness (`tests/fuzz_preset.cpp`) with `--fuzz`.
- **Comprehensive end-to-end regression tests:** added automated tests for `MirrorMove128`, `BlockMove`, `MovingInversion`, `MovingInversionLFSR`, `LFSRPattern`, `RandomAccess`, `ThreadBarrier`, and config recovery.
- **Aggressive defragmentation control:** added `--aggressive-defrag` flag to gate system-wide memory defragmentation, working set trimming, and file cache flushing behind explicit opt-in.

### Improved

- **Safe configuration parsing:** configuration loader parses into an isolated temporary state and commits only on success, preventing partial configuration corruption on parse errors.
- **Strict preset validation:** validated preset tokens, bounds-checked memory parameters against platform pointer sizes, and rejected unsafe control characters.
- **Process priority management:** ensured normal process priority is retained instead of elevating to above-normal, preventing system responsiveness issues during multi-threaded stress.
- **MovingInversionLFSR efficiency:** hoisted LFSR seed calculation out of iteration repeats, eliminating redundant O(N) precomputation passes.

### Fixed

- **Barrier deadlock on asynchronous termination:** synchronized thread barrier stop signaling by latching stop decisions into epoch markers before barrier arrivals, preventing worker thread deadlocks on Ctrl+C.
- **AVX-512 capability detection:** decoupled AVX-512 CPUID detection from compiler `#if` guards so baseline binaries can accurately detect AVX-512 capable processors.
- **MovingInversionLFSR backward march:** reversed phase 4 iteration order to provide proper backward march address line testing.
- **MirrorMove128 observed value reporting:** fixed soft-error logging to record the originally observed corrupted value rather than the subsequent corrected read.
- **RefreshStable responsive shutdown:** divided retention wait cycles into 100 ms intervals, allowing immediate responsiveness to shutdown requests while preserving retention duration.
- **RowHammer undefined behavior:** replaced volatile writes with non-temporal stores (`_mm_stream_si64`) to prevent compiler optimizations and maximize DRAM row disturbance.
- **Signal handler ordering:** ensured stop flags use release memory ordering to ensure prompt visibility across worker threads.

### Security

- **Compiler and binary hardening:** enabled Control Flow Guard (`/guard:cf`), CET Shadow Stack compatibility flags (`/CETCOMPAT`, `-fcf-protection=full`), ASLR, DEP/NX, and stack canaries across supported targets.
- **Preset path traversal protection:** canonicalized preset paths via `std::filesystem::canonical` and rejected traversal sequences or absolute paths from untrusted contexts.

### Changed

- **Logger header decoupling:** split `Logger` into separate header and implementation files (`Logger.h` / `Logger.cpp`), reducing compilation times across translation units.
