# Overview

## Architecture
testsmem4u is a cross-platform RAM testing utility for Windows and Linux.
It supports locked memory, large pages, and dynamic CPU core affinity targeting.
It automatically attempts to relaunch itself using AVX2 (-v3) or AVX-512 (-v4) sibling binaries for performance if present.

## Key Files
- `src/main.cpp`: CLI argument parsing, interactive/non-interactive configuration, and process management.
- `src/TestEngine.cpp`: Test execution orchestration, thread spawning, and verification logic.
- `src/Platform.cpp`: Platform-specific API integration (CPU topology detection, memory locking, memory allocation, privilege escalation).
- `src/simd_ops.cpp`: SSE/AVX/NEON optimized pattern writing and verification loops.
