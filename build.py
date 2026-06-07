#!/usr/bin/env python3
"""testsmem4u Build Script

Downloads toolchain and compiles testsmem4u.
Supports both Zig (cross-compilation to Windows/Linux/ARM) and
LLVM MinGW (native Windows with CFG/CET/ASan hardening).
Uses parallel compilation for object files.
"""

import argparse
import os
import shutil
import subprocess
import urllib.request
import zipfile
import json
import concurrent.futures
import hashlib
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent

# Zig toolchain (cross-compilation)
ZIG_VERSION = "0.14.0"
ZIG_URL_WIN_X86_64 = (
    f"https://ziglang.org/download/{ZIG_VERSION}/zig-windows-x86_64-{ZIG_VERSION}.zip"
)
ZIG_DIR = PROJECT_ROOT / "tools" / "zig"
ZIG_EXE = ZIG_DIR / f"zig-windows-x86_64-{ZIG_VERSION}" / "zig.exe"
ZIG_SHA256_WIN_X86_64 = "f53e5f9011ba20bbc3e0e6d0a9441b31eb227a97bac0e7d24172f1b8b27b4371"

# LLVM MinGW toolchain (native Windows with CFG/CET/ASan support)
MINGW_VERSION = "20260519"
MINGW_URL_WIN_X86_64 = (
    f"https://github.com/mstorsjo/llvm-mingw/releases/download/{MINGW_VERSION}/llvm-mingw-{MINGW_VERSION}-ucrt-x86_64.zip"
)
MINGW_DIR = PROJECT_ROOT / "tools" / "mingw"
MINGW_CXX = MINGW_DIR / f"llvm-mingw-{MINGW_VERSION}-ucrt-x86_64" / "bin" / "clang++.exe"
MINGW_AR = MINGW_DIR / f"llvm-mingw-{MINGW_VERSION}-ucrt-x86_64" / "bin" / "llvm-ar.exe"
MINGW_SHA256_WIN_X86_64 = "72dbd6e64614e3b3401998992d1bd9c8ace29e74611d71c80309ea71c3fb26f9"

INCLUDE_DIR = PROJECT_ROOT / "include"
SRC_FILES = [
    PROJECT_ROOT / "src" / "main.cpp",
    PROJECT_ROOT / "src" / "PresetLoader.cpp",
    PROJECT_ROOT / "src" / "simd_ops.cpp",
    PROJECT_ROOT / "src" / "Platform.cpp",
    PROJECT_ROOT / "src" / "TestEngine.cpp",
    PROJECT_ROOT / "src" / "ConfigManager.cpp",
    PROJECT_ROOT / "src" / "ConsoleDisplay.cpp",
    PROJECT_ROOT / "src" / "Logger.cpp",
]

TEST_SRC_FILE = PROJECT_ROOT / "tests" / "test_internal.cpp"
FUZZ_SRC_FILE = PROJECT_ROOT / "tests" / "fuzz_preset.cpp"
TEST_SUPPORT_SRC_FILES = [src for src in SRC_FILES if src.name != "main.cpp"]


DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"

BASE_CXX_FLAGS = [
    "-std=c++17",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-rtti",
    "-fno-asynchronous-unwind-tables",
    "-fno-ident",
    "-fno-strict-aliasing",
    "-funroll-loops",
    "-fstack-protector-strong",
]

# Build modes: each mode provides CXX flags and link flags merged with BASE_CXX_FLAGS.
# "release" is the default (preserves all original behavior).
BUILD_MODES = {
    "release": {
        "cxx_flags": ["-O3", "-flto=thin", "-DNDEBUG", "-fcf-protection=full"],
        "link_flags": ["-Wl,--gc-sections", "-Wl,-s"],
        "description": "Optimized release build (default)",
    },
    "debug": {
        "cxx_flags": ["-O0", "-g", "-D_DEBUG"],
        "link_flags": [],
        "description": "Debug build with symbols and assertions",
    },
    "asan": {
        "cxx_flags": ["-O1", "-g", "-fsanitize=address", "-fno-omit-frame-pointer", "-D_DEBUG", "-Wno-unused-command-line-argument"],
        "link_flags": ["-fsanitize=address", "-Wno-unused-command-line-argument"],
        "description": "AddressSanitizer (memory safety)",
    },
    "ubsan": {
        "cxx_flags": ["-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-D_DEBUG", "-Wno-unused-command-line-argument"],
        "link_flags": ["-fsanitize=undefined", "-Wno-unused-command-line-argument"],
        "description": "UndefinedBehaviorSanitizer",
    },
    "tsan": {
        "cxx_flags": ["-O1", "-g", "-fsanitize=thread", "-D_DEBUG", "-Wno-unused-command-line-argument"],
        "link_flags": ["-fsanitize=thread", "-Wno-unused-command-line-argument"],
        "description": "ThreadSanitizer (data race detection)",
    },
}

HOST_V3_FLAGS = [
    "-mcpu=x86_64_v3",
    "-mprefer-vector-width=256",
]
HOST_V3_FLAGS_MINGW = [
    "-march=x86-64-v3",
    "-mprefer-vector-width=256",
]

HOST_V4_FLAGS = [
    "-mcpu=x86_64_v4",
    "-mprefer-vector-width=512",
]
HOST_V4_FLAGS_MINGW = [
    "-march=x86-64-v4",
    "-mprefer-vector-width=512",
]

TARGETS = {
    "windows-x86_64": {
        "zig_target": "x86_64-windows-gnu",
        "output": "testsmem4u-windows-x86_64.exe",
        "extra_flags": ["-ladvapi32", "-Xlinker", "/CETCOMPAT"],
        "extra_flags_mingw": ["-ladvapi32"],
        "obj_ext": ".obj",
    },
    "windows-x86_64-v3": {
        "zig_target": "x86_64-windows-gnu",
        "output": "testsmem4u-windows-x86_64-v3.exe",
        "extra_flags": HOST_V3_FLAGS + ["-ladvapi32", "-Xlinker", "/CETCOMPAT"],
        "extra_flags_mingw": HOST_V3_FLAGS_MINGW + ["-ladvapi32"],
        "obj_ext": ".obj",
    },
    "windows-arm64": {
        "zig_target": "aarch64-windows-gnu",
        "output": "testsmem4u-windows-arm64.exe",
        "extra_flags": ["-ladvapi32", "-Xlinker", "/CETCOMPAT"],
        "obj_ext": ".obj",
    },
    "linux-x86": {
        "zig_target": "x86-linux-musl",
        "output": "testsmem4u-linux-x86",
        # -Wno-atomic-alignment: on 32-bit x86 the uint64 RowHammer atomics have an
        # ABI type-alignment of 4, but the tested region is page-aligned so every
        # element is in fact 8-byte aligned at runtime. The warning is a provably
        # false positive here, so it is suppressed only for this target.
        "extra_flags": ["-pthread", "-msse2", "-Wno-atomic-alignment"],
        "obj_ext": ".o",
    },
    "linux-x86_64": {
        "zig_target": "x86_64-linux-musl",
        "output": "testsmem4u-linux-x86_64",
        "extra_flags": ["-pthread"],
        "obj_ext": ".o",
    },
    "linux-x86_64-v3": {
        "zig_target": "x86_64-linux-musl",
        "output": "testsmem4u-linux-x86_64-v3",
        "extra_flags": ["-pthread"] + HOST_V3_FLAGS,
        "obj_ext": ".o",
    },
    "windows-x86_64-v4": {
        "zig_target": "x86_64-windows-gnu",
        "output": "testsmem4u-windows-x86_64-v4.exe",
        "extra_flags": HOST_V4_FLAGS + ["-ladvapi32", "-Xlinker", "/CETCOMPAT"],
        "extra_flags_mingw": HOST_V4_FLAGS_MINGW + ["-ladvapi32"],
        "obj_ext": ".obj",
    },
    "linux-x86_64-v4": {
        "zig_target": "x86_64-linux-musl",
        "output": "testsmem4u-linux-x86_64-v4",
        "extra_flags": ["-pthread"] + HOST_V4_FLAGS,
        "obj_ext": ".o",
    },
    "linux-arm64": {
        "zig_target": "aarch64-linux-musl",
        "output": "testsmem4u-linux-arm64",
        "extra_flags": ["-pthread"],
        "obj_ext": ".o",
    },
}

COMPANION_TARGETS = {
    "windows-x86_64": ["windows-x86_64-v3", "windows-x86_64-v4"],
    "linux-x86_64": ["linux-x86_64-v3", "linux-x86_64-v4"],
}


def expand_target_names(requested: str) -> list[str]:
    if requested == "all":
        names = list(TARGETS.keys())
    else:
        names = [t.strip() for t in requested.split(",") if t.strip()]

    expanded_names = []
    seen = set()
    for name in names:
        for candidate in [name, *COMPANION_TARGETS.get(name, [])]:
            if candidate not in seen:
                expanded_names.append(candidate)
                seen.add(candidate)
    return expanded_names


def source_needs_rebuild(src: Path, obj_file: Path) -> bool:
    if not obj_file.exists():
        return True

    newest_dependency = src.stat().st_mtime
    newest_dependency = max(newest_dependency, (PROJECT_ROOT / "build.py").stat().st_mtime)
    for header in INCLUDE_DIR.glob("*.h"):
        newest_dependency = max(newest_dependency, header.stat().st_mtime)
    return newest_dependency >= obj_file.stat().st_mtime


_current_build_mode = "release"
_current_toolchain = "zig"

# LLVM MinGW build modes: same flags as Zig but with /guard:cf and /CETCOMPAT
# for Control Flow Guard and CET Shadow Stack enforcement in the PE header.
MINGW_BUILD_MODES = {
    "release": {
        "cxx_flags": ["-O3", "-flto=thin", "-DNDEBUG", "-fcf-protection=full"],
        "link_flags": ["-static", "-Wl,-gc-sections", "-Wl,-s", "-Xlinker", "/guard:cf", "-Xlinker", "/CETCOMPAT"],
        "description": "Optimized release build with CFG + CET hardening (static, standalone)",
    },
    "debug": {
        "cxx_flags": ["-O0", "-g", "-D_DEBUG"],
        "link_flags": [],
        "description": "Debug build with symbols and assertions",
    },
    "asan": {
        "cxx_flags": ["-O1", "-g", "-fsanitize=address", "-fno-omit-frame-pointer", "-D_DEBUG"],
        "link_flags": ["-fsanitize=address"],
        "description": "AddressSanitizer (memory safety) - requires ASan DLL in PATH",
    },
    "ubsan": {
        "cxx_flags": ["-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-D_DEBUG"],
        "link_flags": ["-fsanitize=undefined"],
        "description": "UndefinedBehaviorSanitizer",
    },
}

def get_modes():
    return MINGW_BUILD_MODES if _current_toolchain == "mingw" else BUILD_MODES


def target_is_arm(target: dict) -> bool:
    return target.get("zig_target", "").startswith("aarch64")


def compatible_toolchains(target: dict) -> set:
    """Which toolchains can correctly produce this target.

    - x86_64 Windows: mingw only. It provides the CFG+CET hardened, statically
      linked PE; zig's lld rejects the /CETCOMPAT linker switch.
    - Everything else (all Linux arches and Windows-on-ARM): zig only. The mingw
      wrapper always targets x86_64-w64-mingw32, so it cannot cross-compile to
      Linux or to AArch64 Windows.
    """
    zt = target.get("zig_target", "")
    if zt.startswith("x86_64") and zt.endswith("windows-gnu"):
        return {"mingw"}
    return {"zig"}


def _drop_xlinker_pairs(flags: list[str], drop_values: set) -> list[str]:
    """Remove '-Xlinker <value>' pairs whose value is in drop_values."""
    out = []
    i = 0
    while i < len(flags):
        if flags[i] == "-Xlinker" and i + 1 < len(flags) and flags[i + 1] in drop_values:
            i += 2
            continue
        out.append(flags[i])
        i += 1
    return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive_hash(path: Path, expected_sha256: str, label: str) -> bool:
    actual = sha256_file(path)
    if actual.lower() != expected_sha256.lower():
        print(f"[!] {label} SHA-256 mismatch.")
        print(f"    expected: {expected_sha256}")
        print(f"    actual:   {actual}")
        path.unlink(missing_ok=True)
        return False
    print(f"[*] Verified {label} SHA-256: {actual}")
    return True


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target = (destination / member.filename).resolve()
            if target != root and root not in target.parents:
                raise RuntimeError(f"Refusing to extract unsafe zip member: {member.filename}")
        zf.extractall(destination)

def split_compile_link_flags(target: dict, for_test: bool = False) -> tuple[list[str], list[str]]:
    modes = get_modes()
    mode = modes[_current_build_mode]
    flags = list(BASE_CXX_FLAGS) + list(mode["cxx_flags"])
    target_extra_flags = target.get("extra_flags", [])
    compile_flags = [f for f in flags if not f.startswith("-Wl")]
    compile_flags += [
        f
        for f in target_extra_flags
        # Exclude link-only flags: libraries (-l), linker passthrough (-Wl/-Xlinker),
        # and MSVC-style linker switches (/CETCOMPAT, /guard:cf). These belong only
        # in the link step; leaking them into the compile command makes zig c++
        # treat e.g. "/CETCOMPAT" as an input file ("unrecognized file extension").
        if not f.startswith("-l") and not f.startswith("-Wl")
        and not f.startswith("-Xlinker") and not f.startswith("/")
    ]

    link_flags = list(BASE_CXX_FLAGS) + list(mode["link_flags"]) + list(mode["cxx_flags"])
    link_flags += target_extra_flags
    if for_test:
        # Strip hardening flags from test binaries. This allows the test runner
        # to link without CFG/CET runtime DLL dependencies, but means the test
        # binary does NOT exercise the same hardened control-flow paths as the
        # release binary. Any CFG-table or CET-compatibility regression in the
        # release build would not be caught by the test runner. This trade-off
        # is acceptable because CFG/CET are mature OS-level mitigations and
        # application-side regressions affecting them are extremely rare.
        link_flags = [f for f in link_flags if f not in ("/guard:cf", "/CETCOMPAT", "-Xlinker")]

    if target_is_arm(target):
        # Intel CET (-fcf-protection / /CETCOMPAT) and Control Flow Guard
        # (/guard:cf) are x86-only and rejected by the AArch64 backend/linker.
        # Strip them so ARM targets build; AArch64 has its own (BTI/PAC) schemes.
        x86_only = {"-fcf-protection=full", "/CETCOMPAT", "/guard:cf"}
        compile_flags = [f for f in compile_flags if f not in x86_only]
        link_flags = _drop_xlinker_pairs(link_flags, {"/CETCOMPAT", "/guard:cf"})
        link_flags = [f for f in link_flags if f not in x86_only]
    return compile_flags, link_flags


def download_toolchain() -> bool:
    if _current_toolchain == "zig":
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
            if not verify_archive_hash(zip_path, ZIG_SHA256_WIN_X86_64, "Zig toolchain archive"):
                return False

            print("[*] Extracting...")
            safe_extract_zip(zip_path, ZIG_DIR)

            zip_path.unlink(missing_ok=True)
            return ZIG_EXE.exists()
        except Exception as e:
            print(f"[!] Error downloading Zig: {e}")
            return False
    else:
        # LLVM MinGW
        if MINGW_CXX.exists():
            print(f"[*] LLVM MinGW already installed: {MINGW_CXX}")
            return True

        MINGW_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = MINGW_DIR / f"llvm-mingw-{MINGW_VERSION}-ucrt-x86_64.zip"

        print(f"[*] Downloading LLVM MinGW {MINGW_VERSION}...")
        print(f"[*] URL: {MINGW_URL_WIN_X86_64}")

        try:
            urllib.request.urlretrieve(MINGW_URL_WIN_X86_64, zip_path)
            print(f"[*] Downloaded {zip_path.name} ({zip_path.stat().st_size // 1024 // 1024} MB)")
            if not verify_archive_hash(zip_path, MINGW_SHA256_WIN_X86_64, "LLVM MinGW toolchain archive"):
                return False

            print("[*] Extracting...")
            safe_extract_zip(zip_path, MINGW_DIR)

            zip_path.unlink(missing_ok=True)
            return MINGW_CXX.exists()
        except Exception as e:
            print(f"[!] Error downloading LLVM MinGW: {e}")
            return False


def get_compiler() -> str:
    if _current_toolchain == "mingw":
        return str(MINGW_CXX)
    return str(ZIG_EXE)

def get_cxx_command(target: dict, compile_flags: list[str]) -> list[str]:
    if _current_toolchain == "mingw":
        # Filter flags incompatible with native Clang/LLD or link-only
        incompatible = ("-mcpu=", "-fno-ident", "-fno-asynchronous-unwind-tables", "-l", "-Xlinker")
        filtered = [f for f in compile_flags
                    if not any(f.startswith(p) for p in incompatible)
                    and f not in ("/guard:cf", "/CETCOMPAT")]
        extra = [f for f in target.get("extra_flags_mingw", [])
                 if not f.startswith("-l") and not f.startswith("-Xlinker")]
        return [
            str(MINGW_CXX),
            "--target=x86_64-w64-mingw32",
            *filtered,
            *extra,
            f"-I{INCLUDE_DIR}",
        ]
    return [
        str(ZIG_EXE),
        "c++",
        "-target",
        target["zig_target"],
        *compile_flags,
        f"-I{INCLUDE_DIR}",
    ]

def compile_object(args):
    """Compiles a single source file to an object file."""
    cmd, src_file, obj_file = args
    # Construct command: [compiler] [flags] -c src_file -o obj_file
    full_cmd = cmd + ["-c", str(src_file), "-o", str(obj_file)]

    try:
        result = subprocess.run(
            full_cmd, cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        if result.returncode != 0:
            return (False, src_file, result.stderr)
        # Return warnings from successful compilation too
        return (True, src_file, result.stderr if result.stderr.strip() else None)
    except Exception as e:
        return (False, src_file, str(e))


def build_target(name: str) -> bool:
    if name not in TARGETS:
        print(f"[!] Unknown target: {name}")
        return False

    compiler = get_compiler()
    if not Path(compiler).exists():
        print(f"[!] Compiler not found: {compiler}")
        return False

    t = TARGETS[name]
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # Create object directory for this target and build mode
    obj_dir = BUILD_DIR / "obj" / _current_toolchain / _current_build_mode / name
    obj_dir.mkdir(parents=True, exist_ok=True)

    output_path = DIST_DIR / t["output"]

    compile_flags, link_flags = split_compile_link_flags(t)

    # Base compile command
    base_compile_cmd = get_cxx_command(t, compile_flags)

    print(f"[*] Building {name} objects...")

    # Prepare jobs
    jobs = []
    obj_files = []
    for src in SRC_FILES:
        obj_file = obj_dir / (src.stem + t["obj_ext"])
        obj_files.append(obj_file)

        if not source_needs_rebuild(src, obj_file):
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
                elif err:
                    print(f"[W] Warnings in {src.name}:")
                    print(err)

        if not success:
            return False
    else:
        print("[*] All objects up to date.")

    # Link step
    print(f"[*] Linking {name} -> {output_path}")
    if _current_toolchain == "mingw":
        # Filter linker-incompatible flags
        link_filtered = [f for f in link_flags
                         if f not in ("-fno-ident", "-fno-asynchronous-unwind-tables", "-fno-strict-aliasing")
                         and not f.startswith("-mcpu=")]
        link_cmd = [
            str(MINGW_CXX),
            "--target=x86_64-w64-mingw32",
            *link_filtered,
            *[str(obj) for obj in obj_files],
            f"-o{output_path}",
        ]
    else:
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
    if result.stderr.strip():
        print(f"[W] Linker warnings for {name}:")
        print(result.stderr)

    if output_path.exists():
        size = output_path.stat().st_size
        print(f"[*] OK: {size:,} bytes ({size / 1024:.1f} KB)")

    # Copy config files to dist
    for cfg in PROJECT_ROOT.glob("*.cfg"):
        shutil.copy2(cfg, DIST_DIR / cfg.name)
        print(f"[*] Copied {cfg.name}")

    return True


def build_tests(run_tests: bool = True) -> bool:
    compiler = get_compiler()
    if not Path(compiler).exists():
        print(f"[!] Compiler not found: {compiler}")
        return False

    if not TEST_SRC_FILE.exists():
        print(f"[!] Test source not found: {TEST_SRC_FILE}")
        return False

    target = TARGETS["windows-x86_64"]
    obj_dir = BUILD_DIR / "obj" / _current_toolchain / _current_build_mode / "tests"
    obj_dir.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    compile_flags, link_flags = split_compile_link_flags(target, for_test=True)
    compile_flags = compile_flags + ["-DTESTSMEM4U_TESTING"]

    base_compile_cmd = get_cxx_command(target, compile_flags)

    test_sources = [TEST_SRC_FILE, *TEST_SUPPORT_SRC_FILES]
    obj_files = []
    jobs = []
    for src in test_sources:
        obj_file = obj_dir / (src.stem + target["obj_ext"])
        obj_files.append(obj_file)
        if source_needs_rebuild(src, obj_file):
            jobs.append((base_compile_cmd, src, obj_file))

    cpu_count = os.cpu_count() or 4
    if jobs:
        print(f"[*] Compiling {len(jobs)} test objects using {cpu_count} threads...")
        success = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count) as executor:
            futures = {executor.submit(compile_object, j): j[1] for j in jobs}
            for future in concurrent.futures.as_completed(futures):
                ok, src_file, error = future.result()
                if not ok:
                    print(f"[!] Failed to compile {src_file.name}:")
                    print(error)
                    success = False

        if not success:
            return False

    test_exe = BUILD_DIR / "testsmem4u-tests.exe"
    if _current_toolchain == "mingw":
        link_filtered = [f for f in link_flags
                         if f not in ("-fno-ident", "-fno-asynchronous-unwind-tables", "-fno-strict-aliasing")
                         and not f.startswith("-mcpu=")]
        link_cmd = [
            str(MINGW_CXX),
            "--target=x86_64-w64-mingw32",
            *link_filtered,
            *[str(obj) for obj in obj_files],
            f"-o{test_exe}",
        ]
    else:
        link_cmd = [
            str(ZIG_EXE),
            "c++",
            "-target",
            target["zig_target"],
            *link_flags,
            *[str(obj) for obj in obj_files],
            f"-o{test_exe}",
        ]
    result = subprocess.run(link_cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Test linking failed:")
        print(result.stderr)
        return False
    if result.stderr.strip():
        print(f"[W] Test linker warnings:")
        print(result.stderr)

    if not run_tests:
        return True

    print("[*] Running internal tests...")
    test_env = os.environ.copy()
    if _current_toolchain == "mingw" and MINGW_CXX.exists():
        mingw_bin = str(MINGW_CXX.parent)
        test_env["PATH"] = f"{mingw_bin};{test_env.get('PATH', '')}"
    result = subprocess.run([str(test_exe)], cwd=PROJECT_ROOT, capture_output=True, text=True, env=test_env)
    if result.stdout.strip():
        print(result.stdout)
    if result.stderr.strip():
        print(result.stderr)
    if result.returncode != 0:
        print(f"[!] Internal tests failed with exit code {result.returncode}")
        return False
    return True


def write_compile_commands(names: list[str], include_tests: bool = False) -> bool:
    if not names:
        names = ["windows-x86_64"]

    entries = []
    for name in names:
        if name not in TARGETS:
            print(f"[!] Unknown target for compile_commands.json: {name}")
            return False

        target = TARGETS[name]
        compile_flags, _ = split_compile_link_flags(target)
        obj_dir = BUILD_DIR / "obj" / _current_toolchain / _current_build_mode / name

        for src in SRC_FILES:
            obj_file = obj_dir / (src.stem + target["obj_ext"])
            command = get_cxx_command(target, compile_flags) + [
                "-c",
                str(src),
                "-o",
                str(obj_file),
            ]
            entries.append({
                "directory": ".",
                "command": subprocess.list2cmdline(command),
                "file": str(src.relative_to(PROJECT_ROOT)),
                "output": str(obj_file.relative_to(PROJECT_ROOT)),
            })

    if include_tests:
        target = TARGETS["windows-x86_64"]
        compile_flags, _ = split_compile_link_flags(target)
        compile_flags = compile_flags + ["-DTESTSMEM4U_TESTING"]
        obj_dir = BUILD_DIR / "obj" / _current_toolchain / _current_build_mode / "tests"
        obj_file = obj_dir / (TEST_SRC_FILE.stem + target["obj_ext"])
        command = get_cxx_command(target, compile_flags) + [
            "-c",
            str(TEST_SRC_FILE),
            "-o",
            str(obj_file),
        ]
        entries.append({
            "directory": ".",
            "command": subprocess.list2cmdline(command),
            "file": str(TEST_SRC_FILE.relative_to(PROJECT_ROOT)),
            "output": str(obj_file.relative_to(PROJECT_ROOT)),
        })

    output_path = PROJECT_ROOT / "compile_commands.json"
    output_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    print(f"[*] Wrote {output_path} ({len(entries)} entries)")
    return True


MINGW_CLANG_TIDY = MINGW_DIR / f"llvm-mingw-{MINGW_VERSION}-ucrt-x86_64" / "bin" / "clang-tidy.exe"


def run_lint() -> bool:
    """Run clang-tidy static analysis on all source files."""
    if _current_toolchain != "mingw":
        print("[!] --lint requires the mingw toolchain.")
        return False

    clang_tidy = MINGW_CLANG_TIDY
    if not clang_tidy.exists():
        print(f"[!] clang-tidy not found: {clang_tidy}")
        return False

    compile_commands = PROJECT_ROOT / "compile_commands.json"
    if not compile_commands.exists():
        print("[!] compile_commands.json not found. Run with --compile-commands first.")
        return False

    all_sources = [str(src.relative_to(PROJECT_ROOT)) for src in SRC_FILES]
    all_sources.append(str(TEST_SRC_FILE.relative_to(PROJECT_ROOT)))

    print(f"[*] Running clang-tidy on {len(all_sources)} files...")
    ok = True
    for src in all_sources:
        cmd = [
            str(clang_tidy),
            f"-p={PROJECT_ROOT}",
            "--system-headers=0",
            src,
        ]
        print(f"  [*] {src}")
        result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
        if result.stdout.strip():
            # Filter out notes from non-project headers
            lines = result.stdout.strip().split("\n")
            relevant = [l for l in lines if "warning:" in l or "error:" in l]
            if relevant:
                for line in relevant:
                    print(f"    {line}")
        if result.returncode != 0:
            print(f"    [!] clang-tidy returned {result.returncode}")
            ok = False

    if ok:
        print("[*] clang-tidy: no issues found.")
    else:
        print("[!] clang-tidy: issues found (see above).")
    return ok


def build_fuzz() -> bool:
    """Build and run the fuzzing harness for preset/config parsers."""
    global _current_toolchain, _current_build_mode

    if _current_toolchain != "mingw":
        print("[!] --fuzz requires the mingw toolchain. Switching to mingw.")
        _current_toolchain = "mingw"

    compiler = get_compiler()
    if not Path(compiler).exists():
        print(f"[!] Compiler not found: {compiler}")
        return False

    if not FUZZ_SRC_FILE.exists():
        print(f"[!] Fuzz source not found: {FUZZ_SRC_FILE}")
        return False

    target = TARGETS["windows-x86_64"]
    obj_dir = BUILD_DIR / "obj" / _current_toolchain / "fuzz" / "windows-x86_64"
    obj_dir.mkdir(parents=True, exist_ok=True)

    # Check if libFuzzer is supported for this target
    test_result = subprocess.run(
        [str(compiler), "--target=x86_64-w64-mingw32", "-fsanitize=fuzzer", "-x", "c++", "-c", "-", "-o", "NUL"],
        input="int main(){return 0;}", capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    if test_result.returncode != 0:
        print("[!] -fsanitize=fuzzer is not supported for x86_64-w64-windows-gnu target.")
        print("    LLVM MinGW does not ship a libFuzzer runtime for Windows.")
        print("    To run fuzzing, use a Linux build or a native MSVC/Clang-cl toolchain.")
        print("    The fuzzing harness source (tests/fuzz_preset.cpp) is ready for those platforms.")
        return False

    # Support sources: compile without fuzzer flag (they just need ASan)
    support_cxx_flags = [
        "-std=c++17", "-Wall", "-Wextra",
        "-O1", "-g",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-DTESTSMEM4U_FUZZING",
        "-Wno-unused-command-line-argument",
    ]
    support_compile_cmd = [
        str(compiler),
        "--target=x86_64-w64-mingw32",
        *support_cxx_flags,
        f"-I{INCLUDE_DIR}",
    ]

    # Fuzz source: compile with both fuzzer and ASan
    fuzz_cxx_flags = [
        "-std=c++17", "-Wall", "-Wextra",
        "-O1", "-g",
        "-fsanitize=fuzzer,address",
        "-fno-omit-frame-pointer",
        "-DTESTSMEM4U_FUZZING",
        "-Wno-unused-command-line-argument",
    ]
    fuzz_compile_cmd = [
        str(compiler),
        "--target=x86_64-w64-mingw32",
        *fuzz_cxx_flags,
        f"-I{INCLUDE_DIR}",
    ]

    obj_files = []
    print(f"[*] Compiling fuzz objects...")
    ok = True

    # Compile support sources (no fuzzer)
    for src in TEST_SUPPORT_SRC_FILES:
        obj_file = obj_dir / (src.stem + target["obj_ext"])
        obj_files.append(obj_file)
        cmd = support_compile_cmd + ["-c", str(src), "-o", str(obj_file)]
        result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Failed to compile {src.name}:")
            print(result.stderr)
            ok = False
        elif result.stderr.strip():
            print(f"[W] Warnings in {src.name}:")
            print(result.stderr)

    # Compile fuzz source (with fuzzer)
    fuzz_obj = obj_dir / (FUZZ_SRC_FILE.stem + target["obj_ext"])
    obj_files.append(fuzz_obj)
    cmd = fuzz_compile_cmd + ["-c", str(FUZZ_SRC_FILE), "-o", str(fuzz_obj)]
    result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Failed to compile {FUZZ_SRC_FILE.name}:")
        print(result.stderr)
        ok = False
    elif result.stderr.strip():
        print(f"[W] Warnings in {FUZZ_SRC_FILE.name}:")
        print(result.stderr)

    if not ok:
        return False

    # Link with fuzzer runtime
    fuzz_exe = BUILD_DIR / "testsmem4u-fuzz.exe"
    link_flags = ["-fsanitize=fuzzer,address", "-Wno-unused-command-line-argument"]
    link_cmd = [
        str(compiler),
        "--target=x86_64-w64-mingw32",
        *link_flags,
        *[str(obj) for obj in obj_files],
        f"-o{fuzz_exe}",
    ]

    print("[*] Linking fuzzer...")
    result = subprocess.run(link_cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Fuzz linking failed:")
        print(result.stderr)
        return False
    if result.stderr.strip():
        print(f"[W] Fuzz linker warnings:")
        print(result.stderr)

    if fuzz_exe.exists():
        size = fuzz_exe.stat().st_size
        print(f"[*] OK: {fuzz_exe} ({size:,} bytes)")

    # Run fuzzer with a brief timeout to verify it works
    fuzz_corpus = BUILD_DIR / "fuzz_corpus"
    fuzz_corpus.mkdir(parents=True, exist_ok=True)

    print("[*] Running fuzzer (verification run)...")
    test_env = os.environ.copy()
    mingw_bin = str(MINGW_CXX.parent)
    test_env["PATH"] = f"{mingw_bin};{test_env.get('PATH', '')}"
    result = subprocess.run(
        [str(fuzz_exe), str(fuzz_corpus), "-max_len=4096", "-runs=0", "-timeout=10"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30, env=test_env,
    )
    if result.returncode != 0 and result.returncode != 1:
        print(f"[!] Fuzzer exited with code {result.returncode}")
        if result.stderr.strip():
            print(result.stderr)
        return False

    print("[*] Fuzzer verification passed. Run manually for extended fuzzing:")
    print(f"    {fuzz_exe} {fuzz_corpus} -max_len=4096 -timeout=30")
    return True


def run_sanitizer_builds() -> bool:
    """Build and run tests with ASan and UBSan modes under the MinGW toolchain.
    This exercises the sanitizer build modes that catch memory safety bugs and
    undefined behavior not visible in release builds."""
    global _current_build_mode, _current_toolchain

    original_toolchain = _current_toolchain
    original_build_mode = _current_build_mode
    all_ok = True

    sanitizer_modes = {
        "asan": "AddressSanitizer (memory safety)",
        "ubsan": "UndefinedBehaviorSanitizer",
    }

    for mode_name, mode_desc in sanitizer_modes.items():
        if mode_name not in MINGW_BUILD_MODES:
            print(f"[!] Sanitizer mode '{mode_name}' not available for MinGW. Skipping.")
            continue

        print(f"\n[*] === Sanitizer: {mode_name} ({mode_desc}) ===")
        _current_toolchain = "mingw"
        _current_build_mode = mode_name

        if not download_toolchain():
            print(f"[!] Toolchain download failed for {mode_name} build. Skipping.")
            all_ok = False
            continue

        mode_info = MINGW_BUILD_MODES[mode_name]
        print(f"[*] Build mode: {mode_name} ({mode_info['description']})")

        if mode_name == "asan":
            print("[*] Ensure libclang_rt.asan_dynamic-x86_64.dll from the mingw bin/ directory is in PATH.")

        if not build_tests(run_tests=True):
            print(f"[!] Sanitizer build/tests FAILED for mode: {mode_name}")
            all_ok = False
        else:
            print(f"[*] Sanitizer build/tests PASSED for mode: {mode_name}")

    # Restore original settings
    _current_toolchain = original_toolchain
    _current_build_mode = original_build_mode
    return all_ok


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--targets",
        type=str,
        default="all",
        help=f"Comma-separated: {','.join(TARGETS.keys())} or 'all'",
    )
    parser.add_argument(
        "--tests",
        action="store_true",
        help="Build and run the small internal C++ test runner.",
    )
    parser.add_argument(
        "--no-run-tests",
        action="store_true",
        help="With --tests, compile and link the test runner without executing it.",
    )
    parser.add_argument(
        "--run-sanitizers",
        action="store_true",
        help="Build and run tests with ASan and UBSan modes (MinGW only). Catches memory safety and UB bugs not visible in release builds.",
    )
    parser.add_argument(
        "--compile-commands",
        action="store_true",
        help="Write compile_commands.json for clangd/LSP tooling.",
    )
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Run clang-tidy static analysis on all source files (requires mingw toolchain and compile_commands.json).",
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Build and run the fuzzing harness for preset/config parsers (MinGW only, requires ASan DLL in PATH).",
    )
    parser.add_argument(
        "--toolchain",
        type=str,
        default="all",
        choices=["zig", "mingw", "all"],
        help="Toolchain: mingw (LLVM MinGW, CFG+CET+ASan, static standalone), zig (cross-compiler, musl, for Linux targets), or all (default: run both toolchains to build all targets)",
    )
    parser.add_argument(
        "--build-mode",
        type=str,
        default="release",
        help=f"Build mode: release, debug, asan (mingw only), ubsan",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  testsmem4u Build Script (Multi-threaded)")
    print("=" * 60)

    global _current_build_mode, _current_toolchain

    names = expand_target_names(args.targets)
    if not names:
        print("[!] No build targets requested.")
        return 1

    # When --toolchain all (default), download both toolchains upfront.
    if args.toolchain == "all":
        for tc in ("mingw", "zig"):
            _current_toolchain = tc
            if not download_toolchain():
                print(f"[!] Failed to download toolchain: {tc}")
                return 1
    else:
        _current_toolchain = args.toolchain
        if not download_toolchain():
            print(f"[!] Failed to download toolchain: {args.toolchain}")
            return 1

    # Validate build mode for all active toolchains.
    for tc in (("mingw", "zig") if args.toolchain == "all" else (args.toolchain,)):
        _current_toolchain = tc
        modes = get_modes()
        if args.build_mode not in modes:
            print(f"[!] Build mode '{args.build_mode}' not available for toolchain '{tc}'.")
            print(f"    Available modes: {', '.join(modes.keys())}")
            return 1

    _current_build_mode = args.build_mode
    _current_toolchain = args.toolchain

    if args.compile_commands:
        if not write_compile_commands(names, include_tests=args.tests):
            return 1

    if args.run_sanitizers:
        if args.toolchain not in ("mingw", "all"):
            print("[!] --run-sanitizers requires the mingw toolchain.")
            return 1
        _current_toolchain = "mingw"
        if not run_sanitizer_builds():
            print("[!] One or more sanitizer builds failed.")
            return 1
        print("[*] All sanitizer builds passed.")
        return 0

    if args.lint:
        if not args.compile_commands:
            if not (PROJECT_ROOT / "compile_commands.json").exists():
                print("[*] Generating compile_commands.json for lint...")
                names_for_cc = expand_target_names(args.targets)
                if not write_compile_commands(names_for_cc, include_tests=True):
                    return 1
        return 0 if run_lint() else 1

    if args.fuzz:
        if args.toolchain not in ("mingw", "all"):
            print("[!] --fuzz requires the mingw toolchain.")
            return 1
        _current_toolchain = "mingw"
        return 0 if build_fuzz() else 1

    if args.tests:
        # Tests use the first available toolchain; prefer mingw for native host.
        if args.toolchain == "all":
            _current_toolchain = "mingw"
        return 0 if build_tests(run_tests=not args.no_run_tests) else 1

    # Partition targets by their required toolchain, then build each group with
    # the correct one. This prevents silently emitting mislabeled/broken binaries
    # (e.g. mingw producing an x86_64 PE under a "linux-*" name, or zig failing
    # on /CETCOMPAT for x86_64 Windows).
    if args.toolchain == "all":
        groups: dict[str, list[str]] = {"mingw": [], "zig": []}
        for n in names:
            for tc in compatible_toolchains(TARGETS[n]):
                groups[tc].append(n)
    else:
        groups = {args.toolchain: []}
        for n in names:
            compat = compatible_toolchains(TARGETS[n])
            if args.toolchain in compat:
                groups[args.toolchain].append(n)
            else:
                print(f"[*] Skipping {n}: requires --toolchain {'/'.join(sorted(compat))} "
                      f"(current: {args.toolchain}).")

    overall_ok = True
    for tc, tc_names in groups.items():
        if not tc_names:
            continue
        _current_toolchain = tc
        modes = get_modes()
        mode_info = modes[args.build_mode]
        print(f"\n{'=' * 60}")
        print(f"  Toolchain: {tc}  |  Build mode: {args.build_mode} ({mode_info['description']})")
        print(f"{'=' * 60}")

        if tc == "mingw" and args.build_mode == "asan":
            print("[*] Ensure libclang_rt.asan_dynamic-x86_64.dll from the mingw bin/ directory is in PATH.")

        print(f"[*] Building {len(tc_names)} targets in parallel...")
        ok = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tc_names)) as executor:
            future_to_target = {executor.submit(build_target, n): n for n in tc_names}
            for future in concurrent.futures.as_completed(future_to_target):
                name = future_to_target[future]
                try:
                    if not future.result():
                        print(f"[!] Build failed for target: {name}")
                        ok = False
                except Exception as e:
                    print(f"[!] Exception building target {name}: {e}")
                    ok = False

        if not ok:
            overall_ok = False

    if overall_ok:
        print("\nBuild complete.")
        print(f"Outputs: {DIST_DIR}")
        return 0

    print("\nBuild failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
