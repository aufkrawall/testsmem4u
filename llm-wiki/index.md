# LLM Wiki Index

- [Overview](overview.md): architecture, toolchain split, build/test entry points. Verified 2026-09-12; hardware behavior has medium stale risk.
- [Memory testing](memory-testing.md): worker scheduling, algorithms, error accounting, regression coverage, local measurements, and limitations. Verified 2026-09-12; hardware effectiveness remains workload-dependent.
- [Recent log](log/recent.md): current changes and investigations.
- [Log archive](log/README.md): historical audit and release changes.

The August [concurrency report](../mtreport.md) is historical and superseded where
it assumes lockstep barriers, calibrated weights, or sanitizer-proven race freedom.
