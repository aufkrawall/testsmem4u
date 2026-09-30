# Changelog

## Unreleased

### New

- **Developer and debug tool discovery:** added non-mutating `tools/discover-debug-tools.ps1` to detect installed Windows SDK debuggers (`cdb`, `windbg`, `dumpchk`, `symchk`), MSVC tools, LLVM utilities, and Sysinternals.
- **Local tool path configuration:** added `tool-paths.example.env` for machine-local toolchain, SDK, and symbol path overrides.
- **Agent guidelines and secret leak prevention:** added mandatory pre-commit and post-commit secret inspection procedures and changelog maintenance guidelines under `llm-wiki/`.
- **Security audit and binary tool inventory:** added `llm-wiki/debug-tools-security-audit.md` and `llm-wiki/debug-tools.md` for native Windows and Linux binary hardening inspection, crash diagnosis, and memory testing verification.
