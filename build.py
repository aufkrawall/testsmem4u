#!/usr/bin/env python3
"""testsmem4u Build Script

Downloads Zig, extracts it, and compiles testsmem4u.
Supports cross-compilation via Zig (Windows x86_64/arm64, Linux x86_64/arm64).
Uses parallel compilation for object files.
"""

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import json
import concurrent.futures
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
BUILD_DIR = PROJECT_ROOT / "build"

BASE_CXX_FLAGS = [
    "-std=c++17",
    "-O3",
    "-flto",
    "-Wall",
    "-Wl,--gc-sections",
    "-Wl,-O3",
]

HOST_ONLY_FLAGS = [
    "-mcpu=x86_64_v3",
]

TARGETS = {
    "windows-x86_64": {
        "zig_target": "x86_64-windows-gnu",
        "output": "testsmem4u-windows-x86_64.exe",
        "extra_flags": HOST_ONLY_FLAGS + ["-ladvapi32"],
        "obj_ext": ".obj"
    },
    "windows-arm64": {
        "zig_target": "aarch64-windows-gnu",
        "output": "testsmem4u-windows-arm64.exe",
        "extra_flags": ["-ladvapi32"],
        "obj_ext": ".obj"
    },
    "linux-x86": {
        "zig_target": "x86-linux-gnu",
        "output": "testsmem4u-linux-x86",
        "extra_flags": ["-pthread"],
        "obj_ext": ".o"
    },
    "linux-x86_64": {
        "zig_target": "x86_64-linux-gnu",
        "output": "testsmem4u-linux-x86_64",
        "extra_flags": ["-pthread"],
        "obj_ext": ".o"
    },
    "linux-arm64": {
        "zig_target": "aarch64-linux-gnu",
        "output": "testsmem4u-linux-arm64",
        "extra_flags": ["-pthread"],
        "obj_ext": ".o"
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
    pass


def compile_object(args):
    """Compiles a single source file to an object file."""
    cmd, src_file, obj_file = args
    # Construct command: zig c++ [flags] -c src_file -o obj_file
    full_cmd = cmd + ["-c", str(src_file), "-o", str(obj_file)]
    
    try:
        result = subprocess.run(full_cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            return (False, src_file, result.stderr)
        return (True, src_file, None)
    except Exception as e:
        return (False, src_file, str(e))


def build_target(name: str) -> bool:
    if name not in TARGETS:
        print(f"[!] Unknown target: {name}")
        return False

    if not ZIG_EXE.exists():
        print("[!] Zig not found. Please run download first.")
        return False

    t = TARGETS[name]
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create object directory for this target
    obj_dir = BUILD_DIR / "obj" / name
    obj_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = DIST_DIR / t["output"]

    flags = list(BASE_CXX_FLAGS)
    # Remove link-time flags from compile step if they cause warnings, but -flto is fine
    # Remove -Wl flags for compilation step
    compile_flags = [f for f in flags if not f.startswith("-Wl")]
    
    link_flags = list(flags) # Keep all flags for linking (LTO needs optimization flags)
    link_flags += t.get("extra_flags", [])
    
    # Base compile command
    base_compile_cmd = [
        str(ZIG_EXE),
        "c++",
        "-target",
        t["zig_target"],
        *compile_flags,
        f"-I{INCLUDE_DIR}",
    ]
    
    print(f"[*] Building {name} objects...")
    
    # Prepare jobs
    jobs = []
    obj_files = []
    for src in SRC_FILES:
        obj_file = obj_dir / (src.stem + t["obj_ext"])
        obj_files.append(obj_file)
        
        # Check if rebuild needed (simple mtime check)
        if obj_file.exists() and src.stat().st_mtime < obj_file.stat().st_mtime:
            continue
            
        jobs.append((base_compile_cmd, src, obj_file))

    # Run parallel compilation
    cpu_count = os.cpu_count() or 4
    if jobs:
        print(f"[*] Compiling {len(jobs)} files using {cpu_count} threads...")
        success = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count) as executor:
            results = list(executor.map(compile_object, jobs))
            
            for ok, src, err in results:
                if not ok:
                    print(f"[!] Failed to compile {src.name}:")
                    print(err)
                    success = False
        
        if not success:
            return False
    else:
        print("[*] All objects up to date.")

    # Link step
    print(f"[*] Linking {name} -> {output_path}")
    link_cmd = [
        str(ZIG_EXE),
        "c++",
        "-target",
        t["zig_target"],
        *link_flags,
        *[str(obj) for obj in obj_files],
        f"-o{output_path}",
    ]
    
    result = subprocess.run(link_cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Linking failed:")
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
    print("  testsmem4u Build Script (Multi-threaded)")
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
