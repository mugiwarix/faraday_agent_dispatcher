import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from faraday_plugins.plugins.repo.testssl.plugin import TestsslPlugin as EvidencePlugin


TESTSSL = importlib.import_module("faraday_agent_dispatcher.static.executors.official.testssl")
PREFIX = "EXECUTOR_CONFIG_TESTSSL_"


@pytest.fixture(autouse=True)
def environment():
    with patch.dict(os.environ, {
        "TESTSSL_PATH": sys.executable,
        PREFIX + "EVIDENCE": "true",
        PREFIX + "TARGET": '["10.0.0.1"]',
        PREFIX + "PORTS": '["443"]',
        PREFIX + "VULN": '["sslv2_sslv3"]',
    }, clear=True):
        yield


def record(finding_id="SSLv2", text="not offered", severity="OK", **kwargs):
    return {"id": finding_id, "ip": "10.0.0.1/10.0.0.1", "port": "443",
            "severity": severity, "finding": text, **kwargs}


def scanner(monkeypatch, payload=None, returncode=0):
    calls = []
    if payload is None:
        payload = json.dumps([record("service", "HTTP", "INFO"), record(), record("SSLv3"),
                              record("TLS1_2", "offered"), record("engine_problem", "retry", "WARN")]).encode()

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        Path(cmd[cmd.index("--jsonfile") + 1]).write_bytes(payload)
        return returncode

    monkeypatch.setattr(TESTSSL, "_run_evidence", run)
    return calls


def invoke(capsys, code):
    with pytest.raises(SystemExit) as exc:
        TESTSSL.main()
    assert exc.value.code == code
    output = capsys.readouterr()
    assert len(output.err.encode()) <= 2048
    if code:
        assert output.out == ""
    else:
        assert output.out.endswith("\n") and len(output.out.splitlines()) == 1
        assert len(output.out.encode()) <= 32768
    return output


def test_evidence_stdout_exact_report_without_classification(monkeypatch, capsys):
    raw = "  not offered\r\n\t✓  "
    entries = [record(text=raw), record("service", "HTTP", "INFO"), record("unexpected", "failure", "ERROR")]
    calls = scanner(monkeypatch, json.dumps(entries).encode())
    for name in ["get_common_parameters", "build_vulnerabilities", "filter_severity", "resolve_checks"]:
        monkeypatch.setattr(TESTSSL, name, lambda *a: pytest.fail("Normal-mode classification called"))
    monkeypatch.setenv("AGENT_CONFIG_IGNORE_INFO", "true")
    report = json.loads(invoke(capsys, 0).out)
    assert set(report) == {"hosts", "command"}
    host = report["hosts"][0]
    assert host["ip"] == "10.0.0.1"
    service = host["services"][0]
    assert service["port"] == 443 and service["protocol"] == "tcp"
    evidence = service["vulnerabilities"]
    assert [item["name"] for item in evidence] == ["SSLv2", "service", "unexpected"]
    assert evidence[0]["desc"] == raw and evidence[0]["data"] == "OK"
    assert report["command"]["tool"] == "testssl.sh"
    cmd, options = calls[0]
    assert cmd[-1] == "10.0.0.1:443" and cmd.count("-p") == 1
    for flag, value in [("--nodns", "none"), ("--color", "0"), ("--warnings", "off"),
                        ("--connect-timeout", "5"), ("--openssl-timeout", "10")]:
        assert cmd[cmd.index(flag) + 1] == value
    assert options["timeout"] == 900
    assert not {"--phone-out", "--starttls", "--proxy"} & set(cmd)


def test_child_environment_exact_allowlist(monkeypatch, capsys):
    allowed = {key: "permitted" for key in TESTSSL.EVIDENCE_ENV}
    for key, value in {**allowed, "HTTP_PROXY": "secret", "https_proxy": "secret", "ALL_PROXY": "secret",
                       "LD_PRELOAD": "secret", "LD_LIBRARY_PATH": "secret", "DYLD_INSERT_LIBRARIES": "secret",
                       "PYTHONPATH": "secret", "PYTHONHOME": "secret", "BASH_ENV": "secret", "ENV": "secret",
                       "OPENSSL_CONF": "secret", "PHONE_OUT": "true", "EXECUTOR_CONFIG_SECRET": "secret"}.items():
        monkeypatch.setenv(key, value)
    calls = scanner(monkeypatch)
    invoke(capsys, 0)
    assert calls[0][1]["env"] == {**allowed, "PHONE_OUT": "false"}


def test_problem_records_survive_negative_weak_cipher_evidence(monkeypatch, capsys):
    monkeypatch.setenv(PREFIX + "VULN", '["weak_ciphers"]')
    entries = [record(finding_id) for finding_id in ["cipherlist_LOW", "cipherlist_OBSOLETED", "cipherlist_EXPORT"]]
    entries += [record("unrelated", "retry", "WARN"), record("scanTime", "check skipped", "INFO")]
    scanner(monkeypatch, json.dumps(entries).encode())
    report = json.loads(invoke(capsys, 0).out)
    evidence = report["hosts"][0]["services"][0]["vulnerabilities"]
    assert [item["name"] for item in evidence] == [entry["id"] for entry in entries]
    assert evidence[-2]["data"] == "WARN" and evidence[-1]["desc"] == "check skipped"


def test_plugin_banners_suppressed(monkeypatch, capsys):
    module = importlib.import_module("faraday_plugins.plugins.repo.testssl.plugin")
    original = module.createPlugin

    def noisy(*args, **kwargs):
        print("Faraday banner")
        print("Faraday stderr banner" * 1000, file=sys.stderr)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "createPlugin", noisy)
    scanner(monkeypatch)
    assert invoke(capsys, 0).err == ""


@pytest.mark.parametrize("target", [
    "example.com", "https://10.0.0.1", "10.0.0.1:443", "010.0.0.1", "10.0.0.1 ", "0.0.0.0",
    "0.1.2.3", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "--help", None, True, 123,
])
def test_invalid_target_fails_before_launch(monkeypatch, capsys, target):
    monkeypatch.setenv(PREFIX + "TARGET", json.dumps([target]))
    monkeypatch.setattr(TESTSSL, "_run_evidence", lambda *a, **kw: pytest.fail("Scanner launched"))
    invoke(capsys, 1)


@pytest.mark.parametrize("name,value", [
    ("TARGET", "[]"), ("TARGET", '["10.0.0.1","10.0.0.2"]'), ("TARGET", '["10.0.0.1",null]'),
    ("TARGET", '["10.0.0.1",""]'), ("TARGET", '["10.0.0.1"'), ("TARGET", "[" * 1500 + "]" * 1500),
    ("PORTS", "[]"), ("PORTS", "0"), ("PORTS", "65536"), ("PORTS", "0443"), ("PORTS", "443.0"),
    ("PORTS", "443,8443"), ("PORTS", "[true]"), ("PORTS", "[443.0]"), ("PORTS", "-1"),
    ("VULN", "[]"), ("VULN", '["all"]'), ("VULN", '["SSLv2"]'), ("VULN", '["SSLv2 Protocol"]'),
    ("VULN", '["sslv2","unknown"]'), ("VULN", '["CVE-2016-2183"]'), ("VULN", '["94437"]'),
    ("VULN", '["sslv2",""]'), ("VULN", '[null]'), ("VULN", "[true]"), ("VULN", "[1]"),
    ("VULN", '["sslv2", " sslv3"]'), ("VULN", "x" * 4097),
    ("STARTTLS", "smtp"), ("EXTRA_ARGS", "--proxy attacker"), ("EXTRA_ARGS", "--phone-out"),
    ("EXTRA_ARGS", "--ip=10.0.0.2"), ("ISSUE", '["sslv2"]'), ("EXCLUDE_VULN", '["sslv3"]'),
    ("PHONE_OUT", "true"), ("PHONE_OUT", "typo"), ("SNEAKY", "true"), ("IDS_FRIENDLY", "true"),
    ("INCLUDE_INFO", "true"), ("PROXY", "http://proxy"), ("NODNS", "min"),
    ("CONNECT_TIMEOUT", "6"), ("OPENSSL_TIMEOUT", "11"), ("TIMEOUT", "901"),
    ("TIMEOUT", "0"), ("TIMEOUT", "-1"), ("TIMEOUT", "nan"), ("TIMEOUT", "[1]"),
    ("EVIDENCE", "typo"), ("EVIDENCE", '["true"]'),
])
def test_unsafe_or_ambiguous_parameters_fail_closed(monkeypatch, capsys, name, value):
    monkeypatch.setenv(PREFIX + name, value)
    monkeypatch.setattr(TESTSSL, "_run_evidence", lambda *a, **kw: pytest.fail("Scanner launched"))
    invoke(capsys, 1)


@pytest.mark.parametrize("name", ["TESTSSL_PATH", "OPENSSL_PATH"])
@pytest.mark.parametrize("value", ["relative", "/nonexistent/binary", "/tmp"])
def test_binary_path_validation(monkeypatch, capsys, name, value):
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(TESTSSL, "_run_evidence", lambda *a, **kw: pytest.fail("Scanner launched"))
    invoke(capsys, 1)


def test_nonexecutable_binary_fails(monkeypatch, capsys, tmp_path):
    path = tmp_path / "scanner"
    path.write_text("not executable")
    monkeypatch.setenv("TESTSSL_PATH", str(path))
    monkeypatch.setattr(TESTSSL, "_run_evidence", lambda *a, **kw: pytest.fail("Scanner launched"))
    invoke(capsys, 1)


def test_exact_checks_optional_openssl_and_bounded_timeouts(monkeypatch, capsys):
    monkeypatch.setenv("OPENSSL_PATH", sys.executable)
    monkeypatch.setenv(PREFIX + "VULN", '["heartbleed","sslv2","sslv2_sslv3","sweet32"]')
    monkeypatch.setenv(PREFIX + "PORTS", "[443]")
    monkeypatch.setenv(PREFIX + "CONNECT_TIMEOUT", "3")
    monkeypatch.setenv(PREFIX + "OPENSSL_TIMEOUT", "7")
    monkeypatch.setenv(PREFIX + "TIMEOUT", "30")
    calls = scanner(monkeypatch)
    invoke(capsys, 0)
    cmd, options = calls[0]
    assert cmd[cmd.index("--openssl") + 1] == sys.executable
    assert {"-p", "-s", "-H", "-W"} <= set(cmd) and cmd.count("-p") == 1
    assert cmd[cmd.index("--connect-timeout") + 1] == "3"
    assert cmd[cmd.index("--openssl-timeout") + 1] == "7" and options["timeout"] == 30
    assert "OPENSSL_PATH" not in options["env"]


def test_loopback_is_valid_generic_direct_scan(monkeypatch, capsys):
    monkeypatch.setenv(PREFIX + "TARGET", '["127.0.0.1"]')
    calls = scanner(monkeypatch, json.dumps([record(ip="127.0.0.1/127.0.0.1")]).encode())
    report = json.loads(invoke(capsys, 0).out)
    assert report["hosts"][0]["ip"] == "127.0.0.1" and calls[0][0][-1] == "127.0.0.1:443"


@pytest.mark.parametrize("returncode", [1, 2, 3, -9])
def test_nonzero_scanner_exit_never_parses_partial(monkeypatch, capsys, returncode):
    scanner(monkeypatch, returncode=returncode)
    monkeypatch.setattr(EvidencePlugin, "processReport", lambda *a: pytest.fail("Partial report parsed"))
    invoke(capsys, 1)


def test_outer_timeout_and_os_errors_fail_without_output(monkeypatch, capsys):
    for error in [subprocess.TimeoutExpired("scanner", 1), OSError("x" * 10000), KeyboardInterrupt()]:
        with patch.object(TESTSSL, "_run_evidence", side_effect=error):
            invoke(capsys, 1)


@pytest.mark.parametrize("payload", [
    b"", b"[{", b"[] trailing", b"\xff", b'[{"id":"SSLv2","id":"SSLv3"}]',
    b'[{"x":NaN}]', b'[{"x":1e999}]', json.dumps([record(ip="10.0.0.2")]).encode(),
    json.dumps([record(port="8443")]).encode(),
])
def test_malformed_evidence_has_no_stdout(monkeypatch, capsys, payload):
    scanner(monkeypatch, payload)
    invoke(capsys, 1)


@pytest.mark.parametrize("payload", [
    b" " * 262145,
    json.dumps([record()] * 65).encode(),
    json.dumps([record("ignored")] * 2049).encode(),
    json.dumps([record(text="x" * 8193)]).encode(),
    json.dumps([record(text="é" * 1000)] * 20).encode(),
])
def test_resource_limits_exit_three_never_truncate(monkeypatch, capsys, payload):
    scanner(monkeypatch, payload)
    invoke(capsys, 3)


def test_symlink_scanner_output_rejected(monkeypatch, capsys):
    def run(cmd, **kwargs):
        path = Path(cmd[cmd.index("--jsonfile") + 1])
        other = path.with_name("other.json")
        other.write_text(json.dumps([record()]))
        path.symlink_to(other)
        return 0

    monkeypatch.setattr(TESTSSL, "_run_evidence", run)
    invoke(capsys, 1)


def test_stderr_read_is_bounded_and_scanner_keeps_callers_group(monkeypatch):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"warning")
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stderr:
        proc = MagicMock(stderr=stderr)
        popen = MagicMock()
        popen.return_value.__enter__.return_value = proc
        stop = MagicMock()
        monkeypatch.setattr(TESTSSL.subprocess, "Popen", popen)
        monkeypatch.setattr(TESTSSL, "_stop_evidence", stop)
        with patch.object(TESTSSL.os, "read", wraps=os.read) as read:
            with pytest.raises(ValueError, match="Scanner wrote stderr"):
                TESTSSL._run_evidence(["scanner"], env={}, timeout=1)
        read.assert_called_once_with(read_fd, 2048)
        stop.assert_called_once_with(proc)
        popen.assert_called_once_with(["scanner"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={})


@pytest.mark.parametrize("size", [1, 2048, 1048576])
def test_stderr_only_warning_fails_closed_even_with_valid_json(monkeypatch, capsys, tmp_path, size):
    script = tmp_path / "scanner"
    script.write_text(f"#!{sys.executable}\n" + "\n".join([
        "import json, os, sys",
        f"data = {json.dumps([record()])!r}",
        "with open(sys.argv[sys.argv.index('--jsonfile') + 1], 'w') as output: output.write(data)",
        f"os.write(2, b'W' * {size})",
    ]), encoding="utf-8")
    script.chmod(0o700)
    monkeypatch.setenv("TESTSSL_PATH", str(script))
    output = invoke(capsys, 1)
    assert "Scanner wrote stderr" in output.err
    assert "W" * 10 not in output.err


def test_scanner_stdout_is_discarded(monkeypatch, capsys, tmp_path):
    script = tmp_path / "scanner"
    script.write_text(f"#!{sys.executable}\n" + "\n".join([
        "import os, sys",
        "with open(sys.argv[sys.argv.index('--jsonfile') + 1], 'w') as output: output.write('[]')",
        "os.write(1, b'banner' * 100000)",
    ]), encoding="utf-8")
    script.chmod(0o700)
    monkeypatch.setenv("TESTSSL_PATH", str(script))
    assert json.loads(invoke(capsys, 0).out)["hosts"][0]["services"][0]["vulnerabilities"] == []


def test_manifest_keeps_existing_interface():
    root = Path(TESTSSL.__file__).parents[2]
    manifest = json.loads((root / "manifests" / "testssl-1.0.0.json").read_text())
    assert manifest["arguments"]["TESTSSL_EVIDENCE"] == {"mandatory": False, "type": "boolean", "base": "boolean"}
    for name in ["TARGET", "PORTS", "VULN"]:
        assert manifest["arguments"]["TESTSSL_" + name]["type"] == "list"
    assert manifest["environment_variables"] == ["TESTSSL_PATH", "OPENSSL_PATH"]


@pytest.mark.parametrize("enabled", [None, "false"])
def test_normal_mode_not_routed_to_evidence(monkeypatch, capsys, enabled):
    if enabled is None:
        monkeypatch.delenv(PREFIX + "EVIDENCE")
    else:
        monkeypatch.setenv(PREFIX + "EVIDENCE", enabled)
    monkeypatch.setenv(PREFIX + "VULN", '["sslv2"]')
    monkeypatch.setattr(TESTSSL, "evidence_main", lambda: pytest.fail("Evidence mode called"))
    monkeypatch.setattr(TESTSSL, "scan", lambda *a: ([record("SSLv2", "offered", "CRITICAL")], {}))
    TESTSSL.main()
    report = json.loads(capsys.readouterr().out)
    evidence = report["hosts"][0]["services"][0]["vulnerabilities"]
    assert evidence[0]["name"] == "SSL Version 2 and 3 Protocol Detection"
    assert evidence[0]["severity"] == "critical"
