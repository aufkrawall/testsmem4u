"""Compilation-database generation and fail-closed static-analysis checks."""

import json
import re
import subprocess
from pathlib import Path


def compilation_entry(root: Path, command: list[str], source: Path, output: Path) -> dict:
    return {
        "directory": str(root.resolve()),
        "arguments": command,
        "file": str(source.resolve()),
        "output": str(output.resolve()),
    }


def run_clang_tidy(root: Path, executable: Path, sources: list[Path]) -> bool:
    database = root / "compile_commands.json"
    try:
        entries = json.loads(database.read_text(encoding="utf-8"))
        covered = set()
        for entry in entries:
            directory = Path(entry["directory"])
            if not directory.is_absolute():
                raise ValueError("compile-command directories must be absolute")
            source = Path(entry["file"])
            covered.add((directory / source).resolve())
        missing = [str(source) for source in sources if source.resolve() not in covered]
        if missing:
            raise ValueError("missing compile commands for: " + ", ".join(missing))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"[!] Invalid compilation database: {error}")
        return False

    print(f"[*] Running clang-tidy on {len(sources)} files (warnings are errors)...")
    ok = True
    for source in sources:
        cmd = [str(executable), f"-p={root.resolve()}", "--system-headers=0",
               "--warnings-as-errors=*", str(source.resolve())]
        print(f"  [*] {source.relative_to(root)}")
        try:
            result = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
        except OSError as error:
            print(f"    [!] Could not run clang-tidy: {error}")
            ok = False
            continue
        output = result.stdout + "\n" + result.stderr
        if output.strip():
            print(output.strip())
        # Do not trust a zero exit status if the tool skipped a translation unit
        # or reported findings. Check both streams, including compiler failures.
        failed = result.returncode != 0 or re.search(
            r"\b(?:warning|error):|\bSkipping\b|Compile command not found|Error while processing",
            output, re.IGNORECASE)
        if failed:
            print(f"    [!] Analysis failed for {source.name} (exit {result.returncode})")
            ok = False
    print("[*] clang-tidy: no issues found." if ok else "[!] clang-tidy: analysis failed.")
    return ok
