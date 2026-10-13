"""Run after building the baseline binary; exercises real configuration resolution."""

import os
import ctypes
import subprocess
import tempfile
import unittest
from pathlib import Path


class ConfigCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        name = "testsmem4u-windows-x86_64.exe" if os.name == "nt" else "testsmem4u-linux-x86_64"
        cls.binary = root / "dist" / name
        cls.build_dir = root / "build"
        cls.build_dir.mkdir(exist_ok=True)
        if not cls.binary.exists():
            raise unittest.SkipTest("build the baseline binary before running CLI regressions")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.build_dir)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.preset = self.root / "suite.cfg"
        self.preset.write_text("Test Sequence=0\n[Test0]\nFunction=SimpleTest\nParameter=1\n")
        self.config = self.root / "config.ini"

    def dry_run(self, *extra):
        return subprocess.run([str(self.binary), "--dry-run", "--yes", "--no-elevation",
                               "--preset", str(self.preset), *extra], cwd=self.root,
                              capture_output=True, text=True, timeout=30)

    def test_invalid_implicit_config_fails_without_resolving_defaults(self):
        self.config.write_text("MemoryWindowMB=16\nCores=invalid\n")
        result = self.dry_run()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("invalid or unreadable", result.stdout + result.stderr)
        self.assertNotIn("Dry run complete", result.stdout)

    def test_invalid_explicit_config_is_reported_as_invalid(self):
        self.config.write_text("Cycles=invalid\n")
        result = self.dry_run("--config", str(self.config))
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid or unreadable", result.stdout + result.stderr)

    def test_config_directory_is_rejected_without_resolving_defaults(self):
        self.config.mkdir()
        result = self.dry_run()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("invalid or unreadable", result.stdout + result.stderr)

    def test_no_config_can_explicitly_ignore_invalid_file(self):
        self.config.write_text("Cores=invalid\n")
        result = self.dry_run("--no-config")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_optional_config_still_uses_defaults(self):
        result = self.dry_run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Config source:   defaults", result.stdout)
        self.assertIn("Memory window:   85%", result.stdout)
        self.assertIn("Locked memory:   Yes", result.stdout)
        self.assertIn("Large pages:     Yes", result.stdout)
        self.assertIn("Cycles:          3", result.stdout)

    def test_large_page_window_uses_native_preferred_granularity(self):
        if os.name == "nt":
            query = ctypes.WinDLL("kernel32").GetLargePageMinimum
            query.restype = ctypes.c_size_t
            granularity = query()
        else:
            path = Path("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size")
            granularity = int(path.read_text()) if path.exists() else 0
            if not granularity:
                for line in Path("/proc/meminfo").read_text().splitlines():
                    if line.startswith("Hugepagesize:"):
                        granularity = int(line.split()[1]) * 1024
        expected = 17
        if granularity:
            aligned = (17 * 1024 * 1024 // granularity) * granularity
            if aligned:
                expected = aligned // (1024 * 1024)
        result = self.dry_run("--no-config", "--memory", "17")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Memory window:   {expected} MB", result.stdout)
        result = self.dry_run("--no-config", "--memory", "17", "--no-large-pages")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Memory window:   17 MB", result.stdout)

    def test_saved_percentage_and_all_core_policies_are_resolved(self):
        self.config.write_text("MemoryWindowPercent=85\nMemoryWindowMB=0\nCores=0\nCycles=3\nUseLockedMemory=1\nUseLargePages=1\n")
        result = self.dry_run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Memory window:   85%", result.stdout)
        self.assertIn("Locked memory:   Yes", result.stdout)
        self.assertIn("Large pages:     Yes", result.stdout)

    def test_missing_explicit_config_fails_in_automation(self):
        result = self.dry_run("--config", str(self.config))
        self.assertEqual(result.returncode, 2)
        self.assertIn("Config file not found", result.stdout + result.stderr)

    def test_valid_implicit_config_preserves_requested_values(self):
        self.config.write_text("MemoryWindowMB=16\nCores=1\nCycles=2\nUseLargePages=0\n")
        result = self.dry_run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Memory window:   16 MB", result.stdout)
        self.assertIn("Threads:         1", result.stdout)
        self.assertIn("Cycles:          2", result.stdout)

    def test_completed_run_reports_exact_verified_bytes_and_cycles(self):
        self.preset.write_text("Test Sequence=0\n[Test0]\nFunction=SimpleTest\nParameter=3\n")
        result = subprocess.run([
            str(self.binary), "--yes", "--no-config", "--no-elevation",
            "--no-locked-memory", "--no-large-pages", "--preset", str(self.preset),
            "--memory", "16", "--cores", "1", "--cycles", "1",
        ], cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = result.stdout.split("--- Results ---", 1)[1]
        self.assertIn("50331648 bytes verified", summary)
        self.assertIn("Completed cycles: 1", summary)
        self.assertIn("repeated reads included", summary)
        log = (self.root / "testsmem4u.log").read_text()
        self.assertIn("Results: verified-bytes=50331648 complete-cycles=1", log)


if __name__ == "__main__":
    unittest.main()
