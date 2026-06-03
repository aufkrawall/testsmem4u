# Recent Log

## Code Review & Fixes: 2026-06-04

Comprehensive code review completed. All priority 1-3 improvements implemented and committed.

### Priority 1 (Must-fix bugs)
- **P1-1**: Process priority changed from ABOVE_NORMAL to NORMAL (Platform.cpp). Avoids semi-freezing Windows with many cores.
- **P1-2**: MovingInversionLFSR Phase 4 reversed to backward iteration (TestEngine.cpp). Pre-computed LFSR seed table enables correct backward march for address-line coverage.
- **P1-3**: Logger `log_level_` accessed with `memory_order_relaxed` in debug/info/warn fast-paths (Logger.h). Fixes formal C++ data race.

### Priority 2 (Should-fix)
- **P2-1**: `flush_cache_region` caches `getCapabilities()` result once per call (simd_ops.cpp). Avoids repeated function call overhead in hot flush loops.
- **P2-2**: Removed dead commented-out `restoreSystemFileCache` (Platform.cpp).
- **P2-3**: MirrorMove128 verification refactored to block-based scanning with consistent error logging format (TestEngine.cpp). Even/odd positions verified separately against their respective uniform values.
- **P2-4**: Signal handler `g_shutdown_initiated` uses `memory_order_release` instead of `relaxed` (Platform.cpp). Ensures stop flag is visible to workers.

### Priority 3 (Nice-to-have)
- **P3-1**: Replaced `(void)caps;` / `(void)use_nt;` casts with `[[maybe_unused]]` attributes (simd_ops.cpp). Modern C++ idiom.
- **P3-2**: Split Logger from 433-line header-only into ~100-line header + ~300-line implementation (Logger.h + Logger.cpp). Reduces per-TU compile overhead. Added Logger.cpp to build.py SRC_FILES.
- **P3-3**: Fixed `generate_pattern_uniform` and `invert_array` SSE/AVX2 dispatch from `#elif` to `#if`/`else`/`#if` (simd_ops.cpp). SSE2 NT-store path now available as runtime fallback in AVX2-compiled builds.

### Verification
- All internal tests pass (release, ASan, UBSan).
- All 3 Windows targets (x86_64, x86_64-v3, x86_64-v4) build successfully.
- No memory safety or undefined behavior issues detected by sanitizers.

### Status
- Codebase is production-ready.
- Compiler flags (x64-v3/v4) correctly applied.
- `default.cfg` preset is optimal for consumer hardware.
- CPU core utilization correct for P/E cores on Windows and Linux.
- Error detection reliability confirmed (hard/soft classification, bounded sampling).
