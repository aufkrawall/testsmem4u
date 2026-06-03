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
- Always consult `llm-wiki/` for code, bug, build, test, config, debugging, or behavior work!
- Keep `llm-wiki/` linted / quality-checked and updated when durable project knowledge changes!
- Always update `llm-wiki/` after code changes!
- Mistrust code, code annotations and llm-wiki! Each of them might be stale or outdated! Come to your own conclusion and act based on that!
- When fixing a bug or implementing a feature, generally always increase or improve debug logging to make bug diagnosis easier!
- The llm-wiki might not get upated after every change, the git commit history might be more up to date!

## Engineering rules

- Prefer root-cause fixes over workarounds; do not hide, ignore, weaken, or paper over failures!
- Perform thorough thinking about actual root causes of crashes and other issues for proper fixes!
- If the result after thorough thinking is that proper fixes require bigger changes, they generally should be implemented!
- Do not just mitigate fallout, take the hard route of proper and solid root cause fixes!
- Do not use sleeps, wait tables, polling delays, or timing bandaids as crash/race fixes!
- Do not introduce nor accept racy, timing-sensitive, or fragile behavior!
- Keep source files roughly 600-800 lines maximum; split up files when needed!
- Treat dumps, logs, media, captures, credentials, private keys, tokens, symbols, and user data as sensitive!
- Do not commit secrets, dumps, logs, captures, private-symbol PDBs, large generated artifacts, user names or private user data!

## Non-negotiable project constraints

- Do not disable features to avoid fixing bugs!

## Build, diagnostics, and tests

- Fix pre-existing, as well as newly introduced LSP errors/warnings along they way!

## Debugging and logging

- We are paranoid about having sufficient debug logging!
- Add additional debug logging when it helps diagnose issue root causes, state transitions, failure modes, unexpected runtime conditions, or future regressions!

## Windows debugging and binary analysis tools

- Common installed Windows tools for `.dmp` files, symbol, PE/COFF:

| Tool | Purpose | Installed/default path |
| --- | --- | --- |
| `cdb.exe` | Command-line `.dmp` debugging and stack inspection | `C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe` |
| `windbg.exe` | Interactive `.dmp` debugging | `C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe` |

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
- `llm-wiki/debug-tools.md` contains additional available debug commands and tool paths.
- `llm-wiki/index.md` is a compact routing table with page link, purpose, last verified date, and stale-risk.
- Durable topic pages should include summary, source anchors, invariants, diagnostics/failure modes, open questions/stale-risk, and last verified details.
- `llm-wiki/log/recent.md` is newest-first rolling memory; archive older entries when it gets too long.
- After both wiki updates and code changes, perform a semantic quality check for contradictions, stale claims, duplicates, orphan pages, broken links, missing source anchors, and merge/delete/archive candidates.
