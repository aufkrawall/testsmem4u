# LLM Wiki Index

- [Overview](overview.md): architecture, toolchain split, build/test entry points, fail-closed configuration and static analysis. Current allocation ownership, shared wizard policies and progress/build checks verified 2026-10-13; earlier runtime fixes 2026-09-30; medium stale risk for historical clean-analysis claims.
- [Memory testing](memory-testing.md): shared wizard policies, page-allocation defaults/limits, worker scheduling, algorithms, live progress, failure recovery, regression coverage and measurements. Native baseline+AVX2 contracts, Linux THP/strict-lock fallbacks, Windows preparation, wizard/CLI parity, sanitizers and all nine release artifacts verified 2026-10-13; hardware effectiveness and the original long-run stall remain open.
- [Debug tools](debug-tools.md): local tool inventory, discovery via `tools/discover-debug-tools.ps1`, MSVC and SDK debugger paths. Verified 2026-09-30; low stale risk.
- [Security audit debug tools](debug-tools-security-audit.md): native binary hardening, PE/COFF checks, symbol/dump analysis, and runtime tracing tools. Verified 2026-09-30; low stale risk.
- [Changelog guidelines](changelog-guidelines.md): continuous unreleased changelog updates, bold anchors, Keep a Changelog categories, release note parity. Verified 2026-09-30; low stale risk.
- [Secret leak prevention](secret-leak-prevention.md): mandatory pre-commit and post-commit secret checks, manual fallback, sensitive artifact protection. Verified 2026-09-30; low stale risk.
- [Recent log](log/recent.md): current changes and investigations.
- [Log archive](log/README.md): historical audit and release changes.

The August [concurrency report](../mtreport.md) is historical and superseded where
it assumes lockstep barriers, calibrated weights, or sanitizer-proven race freedom.
