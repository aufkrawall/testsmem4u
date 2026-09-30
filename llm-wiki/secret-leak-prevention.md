<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 aufkrawall
-->

# Secret Leak Prevention

This procedure is part of the normal agent commit workflow in testsmem4u. It applies whenever an agent creates a Git commit, independently of whether a full security audit is being performed.

The goal is to prevent credentials, private keys, tokens, sensitive configuration, private data, local diagnostic artifacts, crash dumps, or memory dumps from entering Git history or commit metadata.

## Sensitive material to protect

Treat at least the following as sensitive:

- Passwords, API keys, bearer tokens, OAuth tokens, personal access tokens, and cloud or CI credentials.
- Private keys, code-signing certificates, private certificate material, and authentication hashes.
- Machine-specific configuration files (such as local `tool-paths.env`, `.env` files, or absolute user path overrides).
- Crash dumps (`.dmp`), core dumps, heap snapshots, ETW captures, network traces, process memory dumps, or test logs containing machine usernames, internal network IPs, or process memory contents.
- Credentials or sensitive tokens embedded in source files, tests, presets, configuration files, changelog entries, or Git commit messages.

Public identifiers, test presets (`default.cfg`), documented placeholders, and synthetic test bit-patterns (e.g. `0xAAAAAAAAAAAAAAAA`, `0xDEADBEEF`) are not secrets, but verify that any new test fixtures remain strictly synthetic and non-sensitive before committing them.

## Mandatory pre-commit check

Before every agent-created commit:

1. Inspect the complete staged-file inventory:
   ```powershell
   git status
   ```
2. Review the exact staged patch, not merely the working-tree diff:
   ```powershell
   git diff --cached
   ```
3. Check for unexpectedly staged local configuration (`tool-paths.env`), dump files (`*.dmp`), log files (`*.log`), compiler temporaries, or sensitive test captures.
4. When a local secret scanner such as `gitleaks` or `trufflehog` is available in PATH, run it against the staged changes:
   ```powershell
   gitleaks protect --staged --verbose
   ```
5. If no automated secret scanner is available, perform a targeted manual review: search the staged diff for credential markers (`secret`, `password`, `token`, `apikey`, `bearer`, `private key`), private paths, and usernames.
6. Review the planned commit message before committing. Do not paste raw tokens, sensitive machine paths, or private data into the commit subject or body.
7. If any suspected secret or sensitive artifact is found, stop immediately. Remove or redact the material before proceeding.

A clean scanner result does not replace manual staged-diff review. Scanners can miss private machine paths, internal URLs, or application memory artifacts.

## Mandatory post-commit check

Immediately after every agent-created commit and before any push:

1. Inspect the exact commit that was created, including full patch and metadata:
   ```powershell
   git show --format=fuller --stat --patch HEAD
   ```
2. Confirm that the commit contains only intended task-owned files and no sensitive artifacts.
3. If an automated secret scanner is available, run it against the newly created commit:
   ```powershell
   gitleaks detect --log-opts="-1 HEAD" --verbose
   ```
4. If automated scanning is unavailable, manually re-check the committed patch and metadata.
5. Do not push or publish any commit that fails this check.

## Remediation when a secret reaches a commit

If a credential or sensitive artifact is committed locally:

- Stop before pushing to any remote repository.
- Remove the sensitive material from the working tree.
- Rewrite or amend the local commit:
  ```powershell
  git reset --soft HEAD~1
  # remove sensitive files, re-stage clean files, and recommit
  ```
- If a real credential was involved, treat it as compromised and rotate/revoke it immediately.
- Never quote the full secret in remediation notes, changelog entries, or commit messages.

## Reporting

When reporting secret-check results:

- State which staged/commit scope was inspected and which scanner or manual fallback was used.
- Distinguish between "automated scanner passed" and "manual inspection completed (scanner unavailable)".
- Report suspected secrets using a redacted fingerprint or location, never the full value.
