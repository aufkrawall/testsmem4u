"""Run after building the baseline binary; exercises real configuration resolution."""

import os
import ctypes
import signal
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

    @unittest.skipIf(os.name == "nt", "Linux inherited THP process policy")
    def test_inherited_thp_disable_is_diagnosed_before_allocation(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(42, 0, 0, 0, 0) < 0:  # PR_GET_THP_DISABLE
            self.skipTest("kernel does not expose process THP policy")

        def disable_thp_in_child():
            if libc.prctl(41, 1, 0, 0, 0) != 0:  # PR_SET_THP_DISABLE; child only
                raise OSError(ctypes.get_errno(), "could not set child THP policy")

        for extra, expected_warning in (([], True), (["--no-large-pages"], False)):
            with self.subTest(large_pages=expected_warning):
                result = subprocess.run(
                    [str(self.binary), "--yes", "--no-elevation", "--no-config", "--debug",
                     "--memory", "16", "--cores", "1", "--cycles", "1", "--preset", str(self.preset), *extra],
                    cwd=self.root, capture_output=True, text=True, timeout=20,
                    preexec_fn=disable_thp_in_child)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                warning = "THP is disabled for this process by an inherited process policy"
                self.assertEqual(warning in output, expected_warning, output)
                self.assertNotIn("Enable 'madvise' now?", output)
                self.assertIn("Completed cycles: 1", output)
                log = (self.root / "testsmem4u.log").read_text()
                if expected_warning:
                    self.assertLess(output.index(warning), output.index("Starting tests with"), output)
                    self.assertIn("THP setup:", log)
                    self.assertIn("Allocation starting:", log)
                    self.assertLess(log.index("THP setup:"), log.index("Allocation starting:"))
                else:
                    self.assertNotIn("THP setup:", log)

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

    def test_sequence_start_follows_preset_unless_overridden(self):
        result = self.dry_run("--no-config")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sequence start:  aligned (preset)", result.stdout)
        self.preset.write_text("Sequence Start=Staggered\nTest Sequence=0\n[Test0]\nFunction=SimpleTest\n")
        result = self.dry_run("--no-config")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sequence start:  staggered (preset)", result.stdout)
        result = self.dry_run("--no-config", "--sequence-start", "aligned")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sequence start:  aligned (--sequence-start)", result.stdout)

    def test_invalid_sequence_start_is_rejected(self):
        result = self.dry_run("--no-config", "--sequence-start=shuffled")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--sequence-start must be 'aligned' or 'staggered'", result.stdout + result.stderr)
        self.preset.write_text("Sequence Start=random\nTest Sequence=0\n[Test0]\nFunction=SimpleTest\n")
        result = self.dry_run("--no-config")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Sequence Start must be 'aligned' or 'staggered'", result.stdout + result.stderr)

    def test_valid_implicit_config_preserves_requested_values(self):
        self.config.write_text("MemoryWindowMB=16\nCores=1\nCycles=2\nUseLargePages=0\n")
        result = self.dry_run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Memory window:   16 MB", result.stdout)
        self.assertIn("Threads:         1", result.stdout)
        self.assertIn("Cycles:          2", result.stdout)

    def test_time_limit_options(self):
        self.config.write_text("Cycles=3\n")
        result = self.dry_run("--duration", "4h")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Time limit:      4h\n", result.stdout)
        self.assertIn("Cycles:          unlimited (until the time limit)", result.stdout)
        result = self.dry_run("--no-config", "--memory", "16MB2m")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Memory window:   16 MB", result.stdout)
        self.assertIn("Time limit:      2m\n", result.stdout)
        result = self.dry_run("--no-config", "--duration", "90", "--cycles", "2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Time limit:      1h30m (or 2 cycles, whichever is first)", result.stdout)
        self.config.write_text("Cycles=0\nTimeLimitSeconds=600\n")
        result = self.dry_run("--duration", "none")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Time limit:      none", result.stdout)
        for args, message in ((("--duration", "30x"), "Unknown time unit"),
                              (("--memory", "1GB1h", "--duration", "1h"), "more than once"),
                              (("--memory", "2048 30"), "needs a unit")):
            result = self.dry_run("--no-config", *args)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn(message, result.stdout + result.stderr)

    def test_time_limit_stops_real_run(self):
        result = subprocess.run([
            str(self.binary), "--yes", "--no-config", "--no-elevation", "--no-locked-memory",
            "--no-large-pages", "--preset", str(self.preset), "--memory", "16", "--cores", "1",
            "--duration", "2s",
        ], cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Stopped by: time limit", result.stdout)
        log = (self.root / "testsmem4u.log").read_text()
        self.assertIn("Time limit of 2s reached", log)
        self.assertIn("Run end: reason=time limit", log)

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

    def test_rowhammer_1mb_many_cores_verifies_memory(self):
        self.preset.write_text("Test Sequence=0\n[Test0]\nFunction=RowHammer\nParameter=1\n")
        result = subprocess.run([
            str(self.binary), "--yes", "--no-config", "--no-elevation",
            "--no-locked-memory", "--no-large-pages", "--preset", str(self.preset),
            "--memory", "1", "--cores", "48", "--cycles", "1",
        ], cwd=self.root, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Completed cycles: 1", output)
        self.assertNotIn("0 bytes verified", output)
        log = (self.root / "testsmem4u.log").read_text()
        self.assertNotIn("verified-bytes=0", log)

    @unittest.skipIf(os.name == "nt", "POSIX SIGINT interruption check")
    def test_interrupted_finite_run_returns_nonzero_exit_code(self):
        self.preset.write_text("Test Sequence=0\n[Test0]\nFunction=RefreshStable\nParameter=10000\n")
        proc = subprocess.Popen([
            str(self.binary), "--yes", "--no-config", "--no-elevation",
            "--no-locked-memory", "--no-large-pages", "--preset", str(self.preset),
            "--memory", "4", "--cores", "1", "--cycles", "1",
        ], cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            if "Starting tests with" in line:
                break
        proc.send_signal(signal.SIGINT)
        stdout, stderr = proc.communicate(timeout=15)
        output = "".join(lines) + stdout + stderr
        self.assertEqual(proc.returncode, 2, output)
        self.assertIn("Stopped by: stop request", output)


if __name__ == "__main__":
    unittest.main()
