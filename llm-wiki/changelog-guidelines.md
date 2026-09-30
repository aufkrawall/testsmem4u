<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 aufkrawall
-->

# Changelog and Release Notes Guidelines

Use this page as the project changelog and release-note maintenance standard for testsmem4u. The root `CHANGELOG.md` tracks user-visible changes and release history. Keep the changelog continuously current during development so release preparation does not depend on reconstructing intent from old commits.

## Purpose

Changelog entries make completed work easy to understand from the user's or operator's point of view. For testsmem4u, focus on observable behavior: memory testing algorithms, error detection and classification, command-line arguments, hardware and SIMD capability detection, platform integration (memory locking, large pages, core affinity), presets, logging, and crash/shutdown behavior.

## Core principles

### 1. Describe the observable issue or capability

- Every entry should identify the user-facing behavior, defect, compatibility issue, operational problem, or capability that changed.
- Do not write purely internal implementation notes without explaining their practical effect.
- Name affected platforms (Windows x86_64, Windows ARM64, Linux x86_64, Linux ARM), binary variants (baseline SSE2, `-v3` AVX2, `-v4` AVX-512), presets, or subsystems when that context materially helps users understand scope.

Prefer:

```markdown
- **LFSR streaming throughput:** restored non-temporal streaming stores in `fill_lfsr` (MOVNTI on x86_64) so DRAM write stress is sustained during LFSRPattern and MovingInversionLFSR.
- **Elevation child exit status:** fixed elevation relaunch on Windows to wait for the child process and return its exact exit code.
- **Memory lock error logging:** added detailed privilege diagnostic when `Lock Pages in Memory` privilege cannot be acquired.
```

Avoid:

```markdown
- **Refactoring:** changed loop in SIMD ops.
- **Process:** fixed elevation helper.
- **Fix:** updated error handling.
```

### 2. Keep entries highly scannable

- Start each bullet with a concise bold anchor: `- **<Anchor>:** <details>` or `- **<Anchor>** <details>`.
- A reader skimming only the bold anchors should understand the notable changes quickly.
- Put the symptom or capability first, then the implementation detail only when it adds useful context.
- Keep one logical change per bullet where practical.

Use standard Keep a Changelog categories:

- `### New`
- `### Improved`
- `### Fixed`
- `### Changed`
- `### Deprecated`
- `### Removed`
- `### Security`

### 3. Create and update the changelog continuously

- When completing changelog-worthy work, update the current `## Unreleased` section before committing.
- Do not defer all changelog writing to release packaging.
- Keep the unreleased section aligned with completed changes since the last published release.
- Changelog-worthy work includes: user-visible fixes, algorithm changes, CLI options, preset parsing rules, error classification corrections, platform compatibility improvements, and meaningful diagnostic/logging improvements.

### 4. Keep release notes aligned with the changelog

- When packaging releases (e.g. `testsmem4u-X.X-allOS.7z`) or publishing GitHub releases, derive release notes directly from the corresponding changelog section rather than maintaining an independent summary.
- Run project build and validation commands (`python build.py --tests`, `--lint`, `--run-sanitizers`) to ensure changes are thoroughly verified before release.

### 5. Frame native capabilities natively

- Describe testsmem4u's own behavior, settings, algorithms, and operating modes directly.
- Avoid unnecessary claims of parity with third-party RAM testing tools.
- Mention third-party software only when relevant to interoperability, compatibility, or verified defect reports.

## Recommended entry structure

```markdown
# Changelog

## Unreleased

### New

- **New capability:** added a user-visible feature and explain the practical effect.

### Improved

- **Algorithm throughput:** improved performance or diagnostics in an observable way.

### Fixed

- **Specific failure:** fixed the concrete bug or crash and identify the affected scope.
```

## Agent workflow

1. Before committing changelog-worthy work, update the `## Unreleased` section in `CHANGELOG.md`.
2. Describe the practical issue, capability, or fix first.
3. Use concise bold anchors (`- **Anchor:** details`).
4. Keep the entry scoped to task-owned changes.
5. Review the changelog together with `git diff` so the description matches the implemented behavior.

## Invariants and guardrails

- Do not claim a fix, supported platform, performance improvement, or security property that was not verified.
- Do not let release notes drift from the changelog when both describe the same release.
- Keep internal implementation details subordinate to the user-visible effect.
