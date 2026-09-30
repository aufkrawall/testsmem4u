"""Regression coverage for compilation databases and the static-analysis gate."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build
from tools.build_checks import compilation_entry, run_clang_tidy


class BuildChecksTests(unittest.TestCase):
    def setUp(self):
        build.BUILD_DIR.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=build.BUILD_DIR)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "sample.cpp"
        self.source.write_text("int sample() { return 0; }\n")
        self.executable = self.root / "clang-tidy.exe"
        entry = compilation_entry(self.root, ["clang++", "-c", str(self.source)],
                                  self.source, self.root / "sample.obj")
        self.database = self.root / "compile_commands.json"
        self.database.write_text(json.dumps([entry]))

    def run_result(self, *, stdout="", stderr="", code=0):
        result = subprocess.CompletedProcess([], code, stdout, stderr)
        with mock.patch("tools.build_checks.subprocess.run", return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                ok = run_clang_tidy(self.root, self.executable, [self.source])
        return ok, output.getvalue(), run

    def test_clean_analysis_is_accepted_and_warnings_are_errors(self):
        ok, _, run = self.run_result()
        self.assertTrue(ok)
        self.assertIn("--warnings-as-errors=*", run.call_args.args[0])

    def test_findings_in_either_stream_fail_even_with_zero_exit(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                ok, output, _ = self.run_result(**{stream: "sample.cpp:1: warning: null dereference"})
                self.assertFalse(ok)
                self.assertIn("null dereference", output)

    def test_skipped_analysis_is_not_success(self):
        ok, output, _ = self.run_result(stderr="Skipping sample.cpp. Compile command not found.")
        self.assertFalse(ok)
        self.assertIn("Compile command not found", output)

    def test_tool_failure_is_not_success(self):
        ok, _, _ = self.run_result(code=1)
        self.assertFalse(ok)

    def test_invalid_and_incomplete_databases_fail_before_launch(self):
        for entries in ([{"directory": ".", "file": str(self.source)}], [], None):
            with self.subTest(entries=entries):
                self.database.write_text(json.dumps(entries))
                ok, _, run = self.run_result()
                self.assertFalse(ok)
                run.assert_not_called()

    def test_generated_database_has_absolute_paths_and_testing_define(self):
        test_source = self.root / "test_internal.cpp"
        with mock.patch.multiple(build, PROJECT_ROOT=self.root, BUILD_DIR=self.root / "build",
                                 SRC_FILES=[self.source], TEST_SRC_FILE=test_source,
                                 _current_toolchain="mingw"):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(build.write_compile_commands(["windows-x86_64"], include_tests=True))
        entries = json.loads(self.database.read_text())
        self.assertEqual(len(entries), 2)
        for entry in entries:
            for field in ("directory", "file", "output"):
                self.assertTrue(Path(entry[field]).is_absolute())
            self.assertIn("arguments", entry)
        self.assertIn("-DTESTSMEM4U_TESTING", entries[1]["arguments"])

    def test_lint_regenerates_database_and_selects_native_targets(self):
        with mock.patch("sys.argv", ["build.py", "--lint"]), \
                mock.patch.object(build, "download_toolchain", return_value=True), \
                mock.patch.object(build, "write_compile_commands", return_value=True) as write, \
                mock.patch.object(build, "run_lint", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(build.main(), 0)
        self.assertTrue(write.call_args.kwargs["include_tests"])
        self.assertEqual(set(write.call_args.args[0]),
                         {"windows-x86_64", "windows-x86_64-v3", "windows-x86_64-v4"})

    def test_cross_target_database_uses_zig_when_native_targets_are_absent(self):
        selected = []
        def record(names, include_tests):
            selected.append((names, include_tests, build._current_toolchain))
            return True
        with mock.patch("sys.argv", ["build.py", "--targets", "linux-x86", "--compile-commands"]), \
                mock.patch.object(build, "download_toolchain", return_value=True), \
                mock.patch.object(build, "write_compile_commands", side_effect=record), \
                mock.patch.object(build, "build_target", return_value=True), \
                mock.patch.object(build, "copy_configs_to_dist"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(build.main(), 0)
        self.assertEqual(selected, [(["linux-x86"], False, "zig")])

    @unittest.skipUnless(build.MINGW_CLANG_TIDY.exists(), "installed clang-tidy is required")
    def test_real_analyzer_null_dereference_fails_gate(self):
        (self.root / ".clang-tidy").write_text("Checks: '-*,clang-analyzer-core.NullDereference'\n")
        self.source.write_text("int sample() { int* value = nullptr; return *value; }\n")
        entry = compilation_entry(self.root, [str(build.MINGW_CXX), "-std=c++17", "-c", str(self.source)],
                                  self.source, self.root / "sample.obj")
        self.database.write_text(json.dumps([entry]))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertFalse(run_clang_tidy(self.root, build.MINGW_CLANG_TIDY, [self.source]))
        self.assertIn("clang-analyzer-core.NullDereference", output.getvalue())


if __name__ == "__main__":
    unittest.main()
