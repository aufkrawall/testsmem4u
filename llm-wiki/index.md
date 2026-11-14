# LLM Wiki Index

- [Overview](overview.md): architecture (dynamic chunk scheduling since 2026-11-14), toolchain split, build/test entry points, fail-closed configuration and static analysis. Linux strict-lock failure ordering and the 32-bit x86 `--tests` runner verified 2026-10-14; current allocation ownership, shared wizard policies and progress/build checks verified 2026-10-13; earlier runtime fixes 2026-09-30; medium stale risk for historical clean-analysis claims.
- [Memory testing](memory-testing.md): shared wizard policies, Linux THP setup, page-allocation defaults/limits, dynamic chunk scheduling (enabled entries only), worker CPU targets under restricted affinity, pass data variation, post-fill flush elision, LFSR output mixing, cycle timing logs, algorithms, live progress, failure recovery, regression coverage and measurements. Coverage-per-hour changes and their review fixes verified 2026-11-14 (Windows/WSL suites, bounded runs, restricted affinity); preset rebalancing (incl. RefreshStable share at low worker counts) and RowHammer activation effectiveness open. RandomAccess false-positive contracts, 64-bit word numbers and capped mismatch logs, x86 flush granules (stride capped at 64 B), native/WSL smoke checks and release cross-builds verified 2026-10-14; other native baseline+AVX2 contracts, Linux THP/strict-lock fallbacks, Windows preparation, wizard/CLI parity and sanitizers verified 2026-10-13; hardware effectiveness and the original long-run stall remain open.
- [Debug tools](debug-tools.md): local tool inventory, discovery via `tools/discover-debug-tools.ps1`, MSVC and SDK debugger paths. Verified 2026-09-30; low stale risk.
- [Security audit debug tools](debug-tools-security-audit.md): native binary hardening, PE/COFF checks, symbol/dump analysis, and runtime tracing tools. Verified 2026-09-30; low stale risk.
- [Changelog guidelines](changelog-guidelines.md): continuous unreleased changelog updates, bold anchors, Keep a Changelog categories, release note parity. Verified 2026-09-30; low stale risk.
- [Secret leak prevention](secret-leak-prevention.md): mandatory pre-commit and post-commit secret checks, manual fallback, sensitive artifact protection. Verified 2026-09-30; low stale risk.
- [Recent log](log/recent.md): current changes and investigations.
- [Log archive](log/README.md): historical audit and release changes.

The August [concurrency report](../mtreport.md) is historical and superseded where
it assumes lockstep barriers, calibrated weights, or sanitizer-proven race freedom.
