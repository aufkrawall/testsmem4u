#!/usr/bin/env python3
"""testsmem4u Build Script

Downloads Zig, extracts it, and compiles testsmem4u.
Supports cross-compilation via Zig (Windows x86_64/arm64, Linux x86_64/arm64).
"""

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent
ZIG_VERSION = "0.14.0"
ZIG_URL_WIN_X86_64 = f"https://ziglang.org/download/{ZIG_VERSION}/zig-windows-x86_64-{ZIG_VERSION}.zip"
ZIG_DIR = PROJECT_ROOT / "tools" / "zig"
ZIG_EXE = ZIG_DIR / f"zig-windows-x86_64-{ZIG_VERSION}" / "zig.exe"

INCLUDE_DIR = PROJECT_ROOT / "include"
SRC_FILES = [
    PROJECT_ROOT / "src" / "main.cpp",
    PROJECT_ROOT / "src" / "PresetLoader.cpp",
    PROJECT_ROOT / "src" / "simd_ops.cpp",
    PROJECT_ROOT / "src" / "Platform.cpp",
    PROJECT_ROOT / "src" / "TestEngine.cpp",
    PROJECT_ROOT / "src" / "ConfigManager.cpp",
]


DIST_DIR = PROJECT_ROOT / "dist"

BASE_CXX_FLAGS = [
    "-std=c++17",
    "-O3",
    "-flto",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wshadow",
    "-Wundef",
    "-Werror",
    "-Wno-sign-conversion",
    "-Wno-unused-parameter",
    "-Wl,--gc-sections",
    "-Wl,-O3",
]

HOST_ONLY_FLAGS = [
    "-march=native",
    "-mtune=native",
]

TARGETS = {
    "windows-x86_64": {
        "zig_target": "x86_64-windows-gnu",
        "output": "testsmem4u-windows-x86_64.exe",
        "extra_flags": HOST_ONLY_FLAGS + ["-ladvapi32"],
    },
    "windows-arm64": {
        "zig_target": "aarch64-windows-gnu",
        "output": "testsmem4u-windows-arm64.exe",
        "extra_flags": ["-ladvapi32"],
    },
    "linux-x86": {
        "zig_target": "x86-linux-gnu",
        "output": "testsmem4u-linux-x86",
        "extra_flags": ["-pthread"],
    },
    "linux-x86_64": {
        "zig_target": "x86_64-linux-gnu",
        "output": "testsmem4u-linux-x86_64",
        "extra_flags": ["-pthread"],
    },
    "linux-arm64": {
        "zig_target": "aarch64-linux-gnu",
        "output": "testsmem4u-linux-arm64",
        "extra_flags": ["-pthread"],
    },
}


def download_zig() -> bool:
    if ZIG_EXE.exists():
        print(f"[*] Zig already installed: {ZIG_EXE}")
        return True

    ZIG_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = ZIG_DIR / f"zig-windows-x86_64-{ZIG_VERSION}.zip"

    print(f"[*] Downloading Zig {ZIG_VERSION}...")
    print(f"[*] URL: {ZIG_URL_WIN_X86_64}")

    try:
        urllib.request.urlretrieve(ZIG_URL_WIN_X86_64, zip_path)
        print(f"[*] Downloaded {zip_path.name}")

        print("[*] Extracting...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(ZIG_DIR)

        zip_path.unlink(missing_ok=True)
        return ZIG_EXE.exists()
    except Exception as e:
        print(f"[!] Error downloading Zig: {e}")
        return False


def generate_compile_commands(target_name: str, cmd_base: list, files: list):
    """Generates compile_commands.json for LSP support."""
    # We only generate for the first target built (usually host) to avoid conflicts
    cc_path = PROJECT_ROOT / "compile_commands.json"
    if cc_path.exists():
        return

    print(f"[*] Generating compile_commands.json for {target_name}...")
    
    entries = []
    
    # Zig c++ accepts multiple files at once but compile_commands.json expects one entry per file
    # We need to construct the command as if it was compiling just that file
    
    # Common flags from cmd_base (excluding zig exe and "c++" and the output)
    # cmd_base is [zig_exe, "c++", "-target", ..., flags..., "-I...", "-o..."]
    
    # We want: [zig_exe, "c++", "-target", ..., flags..., "-I...", "-c", file]
    
    base_args = cmd_base[:-len(files)-1] # remove output flag and files
    
    # Filter out -o flag if it was in the base (it is in our case)
    final_args = []
    skip_next = False
    for arg in base_args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-o"):
            if arg == "-o":
                skip_next = True
            continue
        final_args.append(arg)

    for f in files:
        entry = {
            "directory": str(PROJECT_ROOT).replace("\\", "/"),
            "command": " ".join([str(arg).replace("\\", "/") for arg in final_args] + ["-c", str(f).replace("\\", "/")]),
            "file": str(f).replace("\\", "/")
        }
        entries.append(entry)
        
    try:
        with open(cc_path, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to write compile_commands.json: {e}")


def build_target(name: str) -> bool:
    if name not in TARGETS:
        print(f"[!] Unknown target: {name}")
        return False

    if not ZIG_EXE.exists():
        print("[!] Zig not found. Please run download first.")
        return False

    t = TARGETS[name]
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    output_path = DIST_DIR / t["output"]

    flags = list(BASE_CXX_FLAGS)
    flags += t.get("extra_flags", [])

    cmd = [
        str(ZIG_EXE),
        "c++",
        "-target",
        t["zig_target"],
        *flags,
        f"-I{INCLUDE_DIR}",
        f"-o{output_path}",
        *[str(f) for f in SRC_FILES],
    ]

    print(f"[*] Building {name} -> {output_path}")
    print(f"[*] Command: {' '.join(cmd)}")

    # Generate compile_commands.json if this is the Windows target (likely host)
    if "windows" in name:
        generate_compile_commands(name, cmd, SRC_FILES)

    result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Compilation failed:")
        print(result.stderr)
        return False

    if result.stdout.strip():
        print(result.stdout)

    if output_path.exists():
        size = output_path.stat().st_size
        print(f"[*] OK: {size:,} bytes ({size/1024:.1f} KB)")

    # Copy config files to dist
    for cfg in PROJECT_ROOT.glob("*.cfg"):
        shutil.copy2(cfg, DIST_DIR / cfg.name)
        print(f"[*] Copied {cfg.name}")

    return True


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--targets",
        type=str,
        default="all",
        help=f"Comma-separated: {','.join(TARGETS.keys())} or 'all'",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  testsmem4u Build Script")
    print("=" * 60)

    if not download_zig():
        print("[!] Failed to download Zig")
        return 1

    requested = args.targets
    if requested == "all":
        names = list(TARGETS.keys())
    else:
        names = [t.strip() for t in requested.split(",") if t.strip()]

    ok = True
    for n in names:
        ok = build_target(n) and ok

    if ok:
        print("\nBuild complete.")
        print(f"Outputs: {DIST_DIR}")
        return 0

    print("\nBuild failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
