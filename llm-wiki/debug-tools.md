<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 aufkrawall
-->

# Debug and Binary Analysis Tools

This file is the project-local tool inventory for testsmem4u. It documents tools and resolution procedures for crash investigation, memory testing verification, and binary inspection.

## General rules

- Verify that a tool exists and runs before relying on it.
- Prefer repository-pinned or project-local tools when available.
- Prefer discovery (`tools/discover-debug-tools.ps1`, `Get-Command`, `where.exe`, tool manifests) over stale hardcoded paths.
- Treat crash dumps, logs, symbols, and diagnostic output as potentially sensitive.
- Do not mutate binaries, symbols, global debugger flags, registry/system settings, or persistent runtime configuration unless explicitly requested.
- When a preferred tool is unavailable, use a safe equivalent and record the resulting coverage limitation.

## Tool/path resolution

On Windows, `tools/discover-debug-tools.ps1` is the shared non-mutating discovery helper. Run it to inspect local tool availability and generate `debug-tool-manifest.json`:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\discover-debug-tools.ps1 -NoWrite
```

Resolution precedence:

1. Generated `debug-tool-manifest.json` (under `%LOCALAPPDATA%\LLMDebugTools\`)
2. Local, uncommitted `tool-paths.env` (see `tool-paths.example.env`)
3. Project toolchains (e.g. `tools/mingw/` LLVM tools)
4. Shell discovery (`Get-Command`, `where.exe`, `command -v`)
5. Documented standard installation paths
6. System fallbacks

The discovery script is read-only: it does not install packages or modify environment variables.

## Project path overrides

Create a local, uncommitted `tool-paths.env` from `tool-paths.example.env` when overriding tool locations:

```text
PROJECT_ROOT=
BUILD_ROOT=
INSTALL_ROOT=
SYMBOL_ROOT=
LOG_ROOT=
DUMP_ROOT=
CAPTURE_ROOT=
WINDOWS_SDK_DEBUGGERS_X64=
MSVC_TOOLS_X64=
SYSINTERNALS_ROOT=
LLVM_ROOT=
```

## Windows debugging and binary analysis

Windows SDK Debugging Tools live under `Windows Kits\10\Debuggers\<arch>`. On AMD64 systems with the Windows SDK installed, default paths are:
- `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`
- `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe`

Common tools and roles for testsmem4u:

| Tool | Purpose | Typical path / command |
| --- | --- | --- |
| `cdb.exe` | Command-line crash dump and stack inspection | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe` |
| `windbg.exe` | Interactive crash dump and live debugging | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe` |
| `dumpchk.exe` | Dump validation and metadata check | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dumpchk.exe` |
| `symchk.exe` | Symbol validation and symbol-server retrieval | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe` |
| `dumpbin.exe` / `llvm-objdump.exe` | PE/COFF headers, sections, ASLR/DEP/CET mitigation verification | MSVC or MinGW LLVM bin |
| `llvm-strings.exe` / `strings.exe` | Printable string extraction and credential/path inspection | LLVM or Sysinternals |
| `vmmap.exe` | Virtual memory inspection (verify large pages, locked pages, commit size) | Sysinternals |
| `procexp.exe` | Process and thread affinity, core allocation, handle inspection | Sysinternals |
| `procdump.exe` | Automatic crash dump generation during long stress runs | Sysinternals |
| `sigcheck.exe` | File hashes, signatures, and PE metadata | Sysinternals |

### Crash dump inspection example

To inspect a crash dump with symbol resolution:

```powershell
cdb.exe -z "crash.dmp" -y "srv*https://msdl.microsoft.com/download/symbols;build\bin" -c ".ecxr; k; q"
```

### Binary mitigation verification

testsmem4u release binaries on Windows are hardened with ASLR (`/DYNAMICBASE`), High Entropy VA (`/HIGHENTROPYVA`), DEP (`/NXCOMPAT`), and CET (`/CETCOMPAT` on MinGW targets). To verify:

```powershell
dumpbin /headers dist\testsmem4u.exe | Select-String -Pattern "Dynamic base|NX compatible|High entropy|Control Flow|Guard"
```

Or using LLVM tools:

```powershell
llvm-objdump -p dist\testsmem4u.exe
```

## Linux debugging and binary analysis

When testing Linux targets (`linux-x86_64`, `-v3`, `-v4`, `linux-arm64`):

| Tool | Purpose |
| --- | --- |
| `gdb` / `lldb` | Debugging and core dump analysis |
| `readelf` | ELF headers, program headers, dynamic sections, RELRO/NX/PIE |
| `objdump` / `llvm-objdump` | Disassembly and section inspection |
| `checksec` | Security mitigation summary (PIE, stack canary, NX, RELRO) |
| `strace` | Memory allocation and locking syscall tracing (`mmap`, `mlock`, `sched_setaffinity`) |

ELF hardening verification:

```sh
readelf -l ./dist/testsmem4u-linux-x86_64 | grep -E 'GNU_STACK|GNU_RELRO'
```

## Diagnostics and logging in testsmem4u

- testsmem4u includes an asynchronous logger (`src/Logger.cpp`, `include/Logger.h`).
- Console output is rate-limited and synchronized with `ConsoleDisplay`.
- The log file captures all debug and error lines. Log level is configured via CLI or `default.cfg`.
- For diagnosis of test worker behavior, refer to [memory-testing.md](memory-testing.md).
