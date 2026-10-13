# LLM Wiki Index

- [Overview](overview.md): architecture, toolchain split, build/test entry points, fail-closed configuration and static analysis. Progress/build checks and Linux hugepage signal restoration (WSL) verified 2026-10-13; earlier runtime fixes 2026-09-30; medium stale risk for historical clean-analysis claims.
- [Memory testing](memory-testing.md): worker scheduling, algorithms, live progress, failure recovery, optimized kernels, regression coverage and measurements. Native baseline+AVX2 contracts, current-test status progress, allocation-failure recovery, sanitizer/static checks and Windows/WSL AVX2 smoke verified 2026-10-13; hardware effectiveness and original long-run stall remain unverified.
- [Debug tools](debug-tools.md): local tool inventory, discovery via `tools/discover-debug-tools.ps1`, MSVC and SDK debugger paths. Verified 2026-09-30; low stale risk.
- [Security audit debug tools](debug-tools-security-audit.md): native binary hardening, PE/COFF checks, symbol/dump analysis, and runtime tracing tools. Verified 2026-09-30; low stale risk.
- [Changelog guidelines](changelog-guidelines.md): continuous unreleased changelog updates, bold anchors, Keep a Changelog categories, release note parity. Verified 2026-09-30; low stale risk.
- [Secret leak prevention](secret-leak-prevention.md): mandatory pre-commit and post-commit secret checks, manual fallback, sensitive artifact protection. Verified 2026-09-30; low stale risk.
- [Recent log](log/recent.md): current changes and investigations.
- [Log archive](log/README.md): historical audit and release changes.

The August [concurrency report](../mtreport.md) is historical and superseded where
it assumes lockstep barriers, calibrated weights, or sanitizer-proven race freedom.
