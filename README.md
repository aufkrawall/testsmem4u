# testsmem4u

Cross-platform RAM testing tool focused on preset-driven memory stress, locked-memory operation, and operator-friendly CLI execution on Windows and Linux.

## Status

The project is usable, but it is not fully production-ready yet.

This revision improves the operator surface substantially:

- The CLI now has a documented help/version surface.
- Direct-run mode supports validated overrides for memory, cores, cycles, preset, config source, and memory-allocation behavior.
- Non-interactive runs no longer fall through into wizard-only prompts.
- Presets can be listed from the CLI and inspected with a dry run.
- The README and the dedicated CLI report now describe the actual runtime contract.

The remaining production-readiness work is documented in cli-report.md.

## Features

- Preset-driven test suites via .cfg files.
- Interactive startup with a configuration wizard.
- Direct, scriptable CLI execution for unattended runs.
- Automatic privilege elevation attempt unless disabled.
- Locked-memory and large-page / hugepage allocation support when the platform allows it.
- Detailed console progress and a persistent testsmem4u.log file.

## Build

The repository ships with a Python build script that uses Zig as the C++ toolchain.

Build one Windows target:

```powershell
python build.py --targets windows-x86_64
```

Build every configured target:

```powershell
python build.py --targets all
```

Artifacts are written to dist.

## Quick Start

Interactive startup with the saved or default configuration:

```powershell
.\dist\testsmem4u-windows-x86_64.exe
```

List bundled presets:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --list-presets
```

Run a preset non-interactively:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --yes --preset default.cfg
```

Inspect the resolved configuration without starting a test run:

```powershell
.\dist\testsmem4u-windows-x86_64.exe --dry-run --preset default.cfg --memory 80% --cycles 3
```

## CLI Summary

The executable now supports the following high-value operator options:

- --help and --version for discovery.
- --list-presets to enumerate available .cfg suites in the current working directory.
- --config FILE to load and save a specific config file.
- --no-config to ignore config files entirely.
- --preset FILE or a positional preset path to select a suite directly.
- --memory VALUE, --cores VALUE, and --cycles VALUE for one-off run overrides.
- --halt-on-error or --no-halt-on-error to control stop behavior.
- --locked-memory or --no-locked-memory to control memory locking.
- --large-pages or --no-large-pages to control large-page preference.
- --show-config and --dry-run for validation and inspection.
- --yes or --non-interactive to suppress prompts and exit pauses.
- --no-elevation to prevent Administrator/root relaunch.

See cli-report.md for the full option reference, mode rules, exit codes, and examples.

## Runtime Behavior

- With no run-specific options, the program loads config.ini from the current working directory if present.
- If launched interactively, it shows a 3-second countdown and opens the wizard if a key is pressed.
- If launched with run-specific CLI overrides, --yes, or non-interactive stdin, it skips prompts and runs in direct CLI mode.
- On Windows, the program can offer to grant SeLockMemoryPrivilege when interactive and elevated.
- On Linux, the program warns when memory-lock or hugepage capability appears limited, but it does not attempt privilege changes automatically.

## Files

- config.ini: saved wizard configuration unless --no-config is used.
- testsmem4u.log: runtime log file created in the current working directory.
- *.cfg: preset definitions loaded either from the current working directory or from an explicitly supplied path.

## Exit Codes

- 0: success, informational command success, or dry-run success.
- 1: memory test completed with detected errors.
- 2: CLI, configuration, or preset validation failure.

## Operational Notes

- The current working directory matters for the default config.ini lookup, log file location, and preset discovery.
- For scheduled tasks, shortcuts, or service-style launchers, prefer explicit --config and --preset paths.
- If large pages are enabled, the effective memory window may be reduced to match large-page granularity.

