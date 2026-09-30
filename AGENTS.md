<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 aufkrawall
-->

# Agent Instructions

## Critical workflow

- Windows-first project: prefer PowerShell 7.6, Windows-native paths, and installed project tools unless there is a clear reason not to!
- Always git commit after code changes!
- Commit completed code changes with plain git commands only: `git status`, `git add -A`, `git commit -m "<message>"`!
- Do not push to cloud unless explicitly requested, generally just commit locally!
- Every agent-created commit must pass the mandatory pre-commit and post-commit secret-leak checks in `llm-wiki/secret-leak-prevention.md`; never push a commit that has not passed the post-commit check!
- Maintain a root `CHANGELOG.md` using `llm-wiki/changelog-guidelines.md`: record changelog-worthy task-owned changes in the current unreleased section before committing!
- Always consult `llm-wiki/` for code, bug, build, test, config, debugging, or behavior work!
- Keep `llm-wiki/` linted / quality-checked and updated when durable project knowledge changes!
- Always update `llm-wiki/` after code changes!
- Mistrust code, code annotations and llm-wiki! Each of them might be stale or outdated! Come to your own conclusion and act based on that!
- When fixing a bug or implementing a feature, generally always increase or improve debug logging to make bug diagnosis easier!
- The llm-wiki might not get updated after every change, the git commit history might be more up to date!

## Changelog and release notes

- Describe the observable issue, behavior change, compatibility effect, or capability first; keep internal implementation detail secondary.
- Prefer concise bold lead-in anchors (`- **<Anchor>:** <details>`) and standard changelog categories so entries remain highly scannable.
- Keep release notes aligned with the changelog when both describe the same release, and verify changes before packaging.
- Maintain root `CHANGELOG.md` continuously; update the current unreleased section before committing.

## Secret leak prevention

- Treat secret safety as a commit gate, not an optional security-audit task.
- Before committing, inspect staged/untracked task-owned files, the staged patch (`git diff --cached`), and the planned commit message; run repository-provided or available local secret scanning (`gitleaks`, `trufflehog`) when possible.
- After committing, inspect the exact created commit (`git show --format=fuller --stat --patch HEAD`) including patch and metadata, and run commit/history secret scanning when available.
- If scanners are unavailable, perform the documented manual fallback; scanner absence never means the check may be skipped.
- Stop before push on any suspected leak. Remove/redact it, rewrite affected local commits as appropriate, and rotate/revoke real credentials according to project policy.
- Never reproduce full discovered secrets in logs, reports, changelogs, issues, PRs, or commit messages.

## Engineering rules

- Prefer root-cause fixes over workarounds; do not hide, ignore, weaken, or paper over failures!
- Perform thorough thinking about actual root causes of crashes and other issues for proper fixes!
- If the result after thorough thinking is that proper fixes require bigger changes, they generally should be implemented!
- Do not just mitigate fallout, take the hard route of proper and solid root cause fixes!
- Do not use sleeps, wait tables, polling delays, or timing bandaids as crash/race fixes!
- Do not introduce nor accept racy, timing-sensitive, or fragile behavior!
- Keep source files roughly 600-800 lines maximum; split up files when needed!
- Preserve intended features, compatibility guarantees, performance characteristics, and public contracts unless the requested change intentionally alters them!
- Keep behavioral diffs focused; do not mix unrelated formatting, generated churn, cleanup, or opportunistic refactors when they can be separated!
- Treat dumps, logs, media, captures, credentials, private keys, tokens, symbols, and user data as sensitive!
- Do not commit secrets, dumps, logs, captures, private-symbol PDBs, large generated artifacts, user names or private user data!

## Non-negotiable project constraints

- Do not disable features to avoid fixing bugs!

## Tests and diagnostics

Regression coverage and diagnosability are first-class deliverables, not optional polish.

- For every bug fix or behavioral correction, explicitly assess both regression coverage and diagnostics even when existing tests pass. Strongly prefer a focused automated regression test that fails before the fix and passes after it!
- For features, cover the new contract and important edge cases when suitable test infrastructure exists!
- Do not add low-value tests merely to satisfy a blanket rule. If focused automation is genuinely impractical or adds little value, preserve a reproducible verification method and state why automated coverage was omitted.
- Add or improve high-signal debug/diagnostic logging when a recurrence would otherwise be materially harder to diagnose, especially around relevant state transitions, inputs, boundaries, recovery paths, and failures. Keep diagnostics non-secret and low-overhead, and preserve useful debug information when compatible with release policy!
- We are paranoid about having sufficient debug logging!
- If additional regression coverage or diagnostics are deliberately not added for a non-trivial behavioral change, state the reason.
- Do not introduce sleeps or timing assumptions into tests unless timing is the behavior under test and the test remains deterministic!
- Fix pre-existing, as well as newly introduced LSP errors/warnings along the way!

## Windows debugging and binary analysis tools

- When `tools/discover-debug-tools.ps1` and `debug-tool-manifest.json` exist on Windows, use the manifest as machine-specific path evidence instead of duplicating SDK/MSVC discovery logic!
- Verify tool availability before relying on documented paths. Treat hardcoded paths as examples unless the repository declares them mandatory.
- Do not mutate global debugger flags, registry/system settings, binaries, symbols, or persistent environment state unless explicitly requested and justified.
- Inspect relevant dumps, logs, traces, symbols, and produced artifacts when they can establish the reported failure or its root cause.
- Consult `llm-wiki/debug-tools.md` and `llm-wiki/debug-tools-security-audit.md` for complete tool inventories, mitigation checks, and resolution procedures.
- Common installed Windows tools for `.dmp` files, symbol, PE/COFF:

| Tool | Purpose | Installed/default path |
| --- | --- | --- |
| `cdb.exe` | Command-line `.dmp` debugging and stack inspection | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe` |
| `windbg.exe` | Interactive `.dmp` debugging | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe` |

## `llm-wiki/` workflow

- `llm-wiki/` is canonical LLM-maintained derived memory, not the sole source of truth.
- For substantial work, start with `llm-wiki/index.md`, read only relevant topic pages, then read `llm-wiki/log/recent.md` for active/stale-risk areas.
- Read archives only when historical context is needed or explicitly linked.
- For trivial localized edits, skip broad wiki loading unless the area is unfamiliar or stale-risk is likely.
- If `llm-wiki/` is missing during substantial work, create `index.md`, `overview.md`, and `log/recent.md` by inspecting repo structure, build/test entry points, config, docs, and workflows.
- Mistrust wiki claims until verified against code (but mistrust code too!), tests, build scripts, config, or observed behavior.
- Prefer updating existing pages over creating new ones; create new pages only for reusable topics.
- Keep topic pages focused on current best understanding; put chronology, partial investigations, and temporary notes in `llm-wiki/log/recent.md`.
- Mark uncertainty explicitly as open question, stale-risk, or unverified claim.
- Do not dump raw logs or long command output unless it establishes durable knowledge.
- Update the wiki when durable knowledge changes: architecture, behavior, build/test/package/deploy/debug workflows, bugs/root causes, invariants, conventions, rejected approaches, follow-ups, or code style.
- Do not update the wiki for trivial edits with no future-useful context.
- `llm-wiki/debug-tools.md` and `llm-wiki/debug-tools-security-audit.md` contain available debug commands, binary analysis tools, and tool paths.
- `llm-wiki/changelog-guidelines.md` defines changelog and release-note maintenance standards.
- `llm-wiki/secret-leak-prevention.md` defines mandatory pre-commit and post-commit secret safety procedures.
- `llm-wiki/index.md` is a compact routing table with page link, purpose, last verified date, and stale-risk.
- Durable topic pages should include summary, source anchors, invariants, diagnostics/failure modes, open questions/stale-risk, and last verified details.
- `llm-wiki/log/recent.md` is newest-first rolling memory; archive older entries when it gets too long.
- After both wiki updates and code changes, perform a semantic quality check for contradictions, stale claims, duplicates, orphan pages, broken links, missing source anchors, and merge/delete/archive candidates.
