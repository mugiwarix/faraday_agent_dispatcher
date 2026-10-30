"""Bounded synchronous scanner execution, preserving the executor's process group."""

import math
import os
import selectors
import subprocess
import sys
import time


class ScannerProcessError(RuntimeError):
    """Safe execution failure: messages never contain argv, environment, or output."""


def _file_limit(max_file_bytes):
    if max_file_bytes is None:
        return None
    if sys.platform != "linux":
        raise ValueError("Scanner file limits require Linux")
    if type(max_file_bytes) is not int or not 0 <= max_file_bytes <= sys.maxsize:
        raise ValueError("Invalid scanner file limit")
    import resource

    def apply_limit():
        # Runs only in the scanner child. Never change the executor's limits.
        _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = max_file_bytes if hard == resource.RLIM_INFINITY else min(max_file_bytes, hard)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    return apply_limit


def _reap(process):
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # An uninterruptible child must not turn a bounded call into an endless
        # wait. The enclosing executor runner remains responsible for its group.
        pass


def run_scanner(
    argv, *, env=None, timeout=90, max_stdout_bytes=262144,
    max_stderr_bytes=2048, max_file_bytes=None, capture_output=True,
):
    """Run an argv list/tuple without a shell; return a CompletedProcess.

    stdout/stderr are bytes, or None with capture_output=False (both streams go
    to DEVNULL and their byte caps are ignored). Nonzero exits are returned, not
    raised. Captured streams have independent inclusive byte caps. Timeout is a
    positive finite number covering execution AND pipe draining, including pipes
    held open by descendants after the scanner leader exits.

    Invalid options raise ValueError; start/I/O failures, output overflow, and
    timeouts raise ScannerProcessError without exposing scanner data. stdin is
    DEVNULL. max_file_bytes optionally sets Linux RLIMIT_FSIZE in the child only;
    this caps EACH regular file, not aggregate disk use. File-limit failures are
    reflected in the scanner's exit status (a scanner may handle EFBIG itself).

    No new process group or session is created. Local failures kill/reap the
    direct child and close all pipes; the outer runner MUST kill the executor's
    process group to clean up descendants. This preserves PORCO group cleanup.
    As with subprocess.Popen, process creation itself cannot be interrupted by
    this timeout. The optional file limit uses Linux preexec_fn and is intended
    for the dedicated scanner executor, not a multithreaded application process.
    """
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("Scanner argv must be a nonempty list or tuple")
    if type(timeout) not in (int, float) or timeout <= 0:
        raise ValueError("Invalid scanner timeout")
    try:
        valid_timeout = math.isfinite(timeout)
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        raise ValueError("Invalid scanner timeout")
    if type(capture_output) is not bool:
        raise ValueError("Invalid scanner capture option")
    if capture_output:
        for limit in (max_stdout_bytes, max_stderr_bytes):
            if type(limit) is not int or limit < 0:
                raise ValueError("Invalid scanner output limit")
    preexec_fn = _file_limit(max_file_bytes)
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            argv, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            shell=False, close_fds=True, bufsize=0, preexec_fn=preexec_fn,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        raise ScannerProcessError("Scanner could not start") from None

    stdout = bytearray()
    stderr = bytearray()
    try:
        if capture_output:
            with selectors.DefaultSelector() as selector:
                for stream, buffer, limit, name in (
                    (process.stdout, stdout, max_stdout_bytes, "stdout"),
                    (process.stderr, stderr, max_stderr_bytes, "stderr"),
                ):
                    selector.register(stream, selectors.EVENT_READ, (buffer, limit, name))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ScannerProcessError("Scanner timed out")
                    for key, _events in selector.select(remaining):
                        buffer, limit, name = key.data
                        chunk = os.read(key.fd, min(65536, limit - len(buffer) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        elif len(buffer) + len(chunk) > limit:
                            raise ScannerProcessError("Scanner {} limit exceeded".format(name))
                        else:
                            buffer.extend(chunk)
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ScannerProcessError("Scanner timed out") from None
        return subprocess.CompletedProcess(
            argv, process.returncode,
            bytes(stdout) if capture_output else None,
            bytes(stderr) if capture_output else None,
        )
    except OSError:
        raise ScannerProcessError("Scanner I/O failed") from None
    finally:
        _reap(process)
