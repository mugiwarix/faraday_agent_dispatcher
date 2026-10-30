"""Synthetic subprocess tests: no scanners, network targets, or persistent files."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from faraday_agent_dispatcher.utils import scanner_process
from faraday_agent_dispatcher.utils.scanner_process import ScannerProcessError, run_scanner


class ScannerProcessTests(unittest.TestCase):
    def setUp(self):
        self.real_popen = subprocess.Popen
        self.processes = []
        self.options = []

    def tearDown(self):
        # Defensive cleanup also applies when an assertion fails.
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def start(self, *args, **kwargs):
        self.options.append(kwargs)
        process = self.real_popen(*args, **kwargs)
        self.processes.append(process)
        return process

    def run_python(self, source, *args, **kwargs):
        with patch.object(scanner_process.subprocess, "Popen", side_effect=self.start):
            return run_scanner([sys.executable, "-c", source, *args], **kwargs)

    def assert_cleaned(self):
        self.assertTrue(self.processes)
        for process in self.processes:
            self.assertIsNotNone(process.poll())
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    self.assertTrue(stream.closed)

    def test_nonzero_exit_returns_bytes_and_stdin_is_devnull(self):
        result = self.run_python(
            "import os; assert os.read(0, 1) == b''; "
            "os.write(1, b'\\xffstdout'); os.write(2, b'\\xfestderr'); raise SystemExit(7)"
        )
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"\xffstdout")
        self.assertEqual(result.stderr, b"\xfestderr")
        self.assertFalse(self.options[0]["shell"])
        self.assertTrue(self.options[0]["close_fds"])
        self.assertIsNone(self.options[0].get("preexec_fn"))
        self.assert_cleaned()

    def test_environment_and_argv_pass_without_shell_expansion(self):
        argument = "$(not-a-command); *"
        result = self.run_python(
            "import os, sys; print(os.environ['SCANNER_TEST']); print(sys.argv[1])",
            argument, env={"SCANNER_TEST": "value"},
        )
        self.assertEqual(result.stdout, ("value\n" + argument + "\n").encode())

    @unittest.skipUnless(os.name == "posix", "POSIX process groups")
    def test_inherits_executor_process_group_and_session(self):
        result = self.run_python(
            "import json, os; print(json.dumps([os.getpgrp(), os.getsid(0)]))"
        )
        self.assertEqual(json.loads(result.stdout), [os.getpgrp(), os.getsid(0)])
        self.assertFalse(self.options[0].get("start_new_session", False))
        self.assertNotIn("process_group", self.options[0])

    def test_inclusive_output_caps_and_empty_zero_caps(self):
        result = self.run_python(
            "import os; os.write(1, b'12345678'); os.write(2, b'1234')",
            max_stdout_bytes=8, max_stderr_bytes=4,
        )
        self.assertEqual((result.stdout, result.stderr), (b"12345678", b"1234"))
        result = self.run_python("pass", max_stdout_bytes=0, max_stderr_bytes=0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_output_floods_fail_safely_and_reap_child(self):
        for fd, name in ((1, "stdout"), (2, "stderr")):
            with self.subTest(stream=name):
                start = time.monotonic()
                with self.assertRaisesRegex(ScannerProcessError, "Scanner " + name + " limit exceeded"):
                    self.run_python(
                        "import os; payload = b'SECRET' * 1000\n"
                        "while True: os.write({}, payload)".format(fd),
                        max_stdout_bytes=1024, max_stderr_bytes=1024, timeout=5,
                    )
                self.assertLess(time.monotonic() - start, 5)
                self.assert_cleaned()

    def test_simultaneous_streams_drain_without_deadlock(self):
        result = self.run_python(
            "import os\n"
            "for _ in range(128):\n"
            " os.write(1, b'o' * 1024)\n"
            " os.write(2, b'e' * 1024)\n",
            max_stdout_bytes=131072, max_stderr_bytes=131072, timeout=5,
        )
        self.assertEqual(result.stdout, b"o" * 131072)
        self.assertEqual(result.stderr, b"e" * 131072)

    def test_discard_output_ignores_stream_caps(self):
        result = self.run_python(
            "import os\n"
            "for _ in range(256):\n"
            " os.write(1, b'o' * 4096)\n"
            " os.write(2, b'e' * 4096)\n",
            capture_output=False, max_stdout_bytes=None, max_stderr_bytes=None,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.stdout)
        self.assertIsNone(result.stderr)
        self.assertEqual(self.options[0]["stdout"], subprocess.DEVNULL)
        self.assertEqual(self.options[0]["stderr"], subprocess.DEVNULL)
        self.assert_cleaned()

    def test_timeout_reaps_running_child_with_or_without_pipes(self):
        cases = (
            (True, "import time; time.sleep(10)"),
            (False, "import time; time.sleep(10)"),
            (True, "import os, time; os.close(1); os.close(2); time.sleep(10)"),
        )
        for capture, source in cases:
            with self.subTest(capture=capture, source=source):
                start = time.monotonic()
                with self.assertRaisesRegex(ScannerProcessError, "Scanner timed out"):
                    self.run_python(source, timeout=0.3, capture_output=capture)
                self.assertLess(time.monotonic() - start, 3)
                self.assert_cleaned()

    @unittest.skipUnless(os.name == "posix", "POSIX pipes")
    def test_exited_leader_with_pipe_still_open_obeys_timeout(self):
        # Keep a writer open exactly as an inherited descendant pipe would be,
        # without leaving an orphan process for the host's init to reap.
        read_fd, write_fd = os.pipe()
        with os.fdopen(write_fd, "wb", buffering=0) as writer:
            with os.fdopen(read_fd, "rb", buffering=0) as reader:
                def start_with_held_pipe(*args, **kwargs):
                    kwargs["stdout"] = writer
                    process = self.start(*args, **kwargs)
                    process.stdout = reader
                    return process

                start = time.monotonic()
                with patch.object(scanner_process.subprocess, "Popen", side_effect=start_with_held_pipe):
                    with self.assertRaisesRegex(ScannerProcessError, "Scanner timed out"):
                        run_scanner([sys.executable, "-c", "pass"], timeout=0.5)
                self.assertLess(time.monotonic() - start, 3)
                self.assertEqual(self.processes[0].returncode, 0)
                self.assert_cleaned()

    @unittest.skipUnless(sys.platform == "linux", "Linux child resource limit")
    def test_file_size_limit_applies_only_in_child(self):
        import resource

        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = 1024 if before[1] == resource.RLIM_INFINITY else min(1024, before[1])
        result = self.run_python(
            "import json, resource; print(json.dumps(resource.getrlimit(resource.RLIMIT_FSIZE)))",
            max_file_bytes=1024,
        )
        self.assertEqual(json.loads(result.stdout), [limit, limit])
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.bin"
            result = self.run_python(
                "import os, sys\n"
                "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT, 0o600)\n"
                "while True: os.write(fd, b'x' * 8192)\n",
                str(path), max_file_bytes=1024, capture_output=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertLessEqual(path.stat().st_size, limit)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before)
        self.assert_cleaned()

    def test_invalid_options_rejected_before_spawn(self):
        invalid = [
            {"timeout": value} for value in (0, -1, None, True, float("nan"), float("inf"), 10 ** 1000)
        ] + [
            {"max_stdout_bytes": -1}, {"max_stderr_bytes": None},
            {"max_stdout_bytes": True}, {"capture_output": 1},
            {"max_file_bytes": -1}, {"max_file_bytes": True},
        ]
        with patch.object(scanner_process.subprocess, "Popen") as popen:
            for options in invalid:
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        run_scanner([sys.executable, "-c", "pass"], **options)
            for argv in ("echo hello", [], None):
                with self.subTest(argv=argv):
                    with self.assertRaises(ValueError):
                        run_scanner(argv)
            popen.assert_not_called()

    def test_start_failure_does_not_expose_command(self):
        with self.assertRaises(ScannerProcessError) as caught:
            run_scanner(["/nonexistent/SCANNER_SECRET", "SECRET_ARGUMENT"])
        self.assertEqual(str(caught.exception), "Scanner could not start")
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
