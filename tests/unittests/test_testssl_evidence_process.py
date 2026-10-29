"""Local sleeping Python stubs only; never run scanners or use the network."""

import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress

import psutil
import pytest


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group cleanup")


@pytest.fixture
def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    try:
        yield
    finally:
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0


@pytest.fixture
def sleeping_stub(tmp_path):
    path = tmp_path / "sleep.py"
    path.write_text("""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
Path(sys.argv[1]).write_text(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp(), 'child': child.pid}))
time.sleep(60)
""", encoding="utf-8")
    return path, tmp_path / "pids.json"


def metadata(path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.01)
    pytest.fail("Sleeping stub did not start")


def processes(data):
    return [psutil.Process(data[key]) for key in ("pid", "child")]


def dead(process):
    with suppress(psutil.NoSuchProcess):
        return not process.is_running() or process.status() == psutil.STATUS_ZOMBIE
    return True


def cleanup(outer, descendants):
    with suppress(ProcessLookupError):
        os.killpg(outer.pid, signal.SIGKILL)
    outer.wait(timeout=5)
    for process in descendants:
        with suppress(psutil.NoSuchProcess):
            process.kill()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for process in descendants:
            with suppress(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        if all(not process.is_running() for process in descendants):
            return
        time.sleep(0.01)
    pytest.fail("Stub processes were not reaped")


def test_runner_outer_kill_reaches_scanner_and_descendant(subreaper, sleeping_stub):
    script, pidfile = sleeping_stub
    code = """
import sys
from faraday_agent_dispatcher.static.executors.official.testssl import _run_evidence
_run_evidence([sys.executable, sys.argv[1], sys.argv[2]], env={}, timeout=30)
"""
    descendants = []
    with subprocess.Popen([sys.executable, "-c", code, str(script), str(pidfile)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={}, start_new_session=True) as outer:
        try:
            data = metadata(pidfile)
            descendants = processes(data)
            assert data["pgid"] == outer.pid
            assert os.getpgid(data["child"]) == outer.pid
            os.killpg(outer.pid, signal.SIGKILL)
            outer.wait(timeout=5)
            psutil.wait_procs(descendants, timeout=3)
            assert all(dead(process) for process in descendants)
        finally:
            cleanup(outer, descendants)


@pytest.mark.parametrize("mode", ["timeout", "interrupt"])
def test_inner_abort_kills_subtree_not_callers_group(subreaper, sleeping_stub, mode):
    script, pidfile = sleeping_stub
    code = """
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from faraday_agent_dispatcher.static.executors.official.testssl import _run_evidence
sibling = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
Path(sys.argv[2] + '.sibling').write_text(str(sibling.pid))
timer = threading.Timer(1, lambda: os.kill(os.getpid(), signal.SIGINT)) if sys.argv[3] == 'interrupt' else None
try:
    if timer:
        timer.start()
    try:
        _run_evidence([sys.executable, sys.argv[1], sys.argv[2]], env={}, timeout=10 if timer else 1)
        result = 'unexpected success'
    except subprocess.TimeoutExpired:
        result = 'timeout'
    except KeyboardInterrupt:
        result = 'interrupt'
    print(json.dumps({'result': result, 'sibling_alive': sibling.poll() is None}), flush=True)
finally:
    if timer:
        timer.cancel()
        timer.join()
    sibling.kill()
    sibling.wait()
"""
    descendants = []
    with subprocess.Popen([sys.executable, "-c", code, str(script), str(pidfile), mode],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, start_new_session=True) as outer:
        try:
            data = metadata(pidfile)
            descendants = processes(data) + [psutil.Process(int(pidfile.with_suffix('.json.sibling').read_text()))]
            stdout, stderr = outer.communicate(timeout=10)
            assert outer.returncode == 0, stderr.decode(errors="replace")
            assert json.loads(stdout) == {"result": mode, "sibling_alive": True}
            assert all(dead(process) for process in descendants)
        finally:
            cleanup(outer, descendants)
