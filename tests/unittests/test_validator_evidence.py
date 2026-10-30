"""Synthetic validator evidence and command-shape tests; no scanner or connection.

Covered here: the Nmap script-output parser, the testssl.sh record adapter, and the
execution hooks a dispatcher's runner consumes. Scanner coverage itself is exercised
against local TLS services during development, never from the suite.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from faraday_agent_dispatcher.utils.executor_profiles import (
    SUPPORTED_HANDLERS, ProfileError, build_command, get_profile,
)
from faraday_agent_dispatcher.static.executors.official import nmap, testssl

TARGET = "192.0.2.10"
PORT = 443
TESTSSL_BINARY = "/trusted/testssl.sh"

NMAP_DESCRIPTION = "  TLSv1.0:\n    ciphers:\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n"


def nmap_task(profile, description=NMAP_DESCRIPTION, port=PORT, target=TARGET):
    claims = profile.claims("vulnerability-1", profile.candidate_fields("TLS Version 1.0 Protocol Detection"))
    return {"id": "ab" * 16, "executor_id": profile.executor_id, "profile_id": profile.id, "target": target,
            "port": port, "claims": claims, "arguments": profile.arguments(target, port, claims)}, {
        "state": "COMPLETED",
        "stdout": json.dumps({"hosts": [{"ip": target, "services": [{
            "port": port, "protocol": "tcp", "status": "open",
            "vulnerabilities": [{"name": nmap.SCRIPT_NAME, "desc": description}]}]}]}),
    }


def scanner_record(finding_id="TLS1", *, severity="HIGH", finding="offered", target=TARGET, port=PORT):
    return {"id": finding_id, "severity": severity, "finding": finding, "ip": target, "port": port}


def evidence(records, check_ids=("tls1_0",), target=TARGET, port=PORT):
    profile = get_profile("testssl-3.2.4-ssl-tls")
    return {
        "format": testssl.EVIDENCE_FORMAT, "profile_id": profile.id, "tool_version": profile.metadata["tool_version"],
        "target": target, "port": port, "check_ids": list(check_ids), "records": records,
    }


class NmapEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.profile = get_profile("nmap-tls-protocols")

    def test_protocol_sections_requires_nested_negotiated_cipher_rows(self):
        self.assertEqual(nmap.protocol_sections(NMAP_DESCRIPTION), {"TLSv1.0"})
        self.assertEqual(nmap.protocol_sections(NMAP_DESCRIPTION + NMAP_DESCRIPTION), set())
        self.assertEqual(nmap.protocol_sections("  TLSv1.0:\n    ciphers:\n"), set())
        self.assertEqual(nmap.protocol_sections(None), set())

    def test_positive_protocol_evidence_and_non_reproduction_never_infer_false_positive(self):
        task, result = nmap_task(self.profile)
        self.assertEqual(self.profile.evaluate(task, result),
                         ({"TLSv1.0": "REPRODUCED"}, "NOT_REPRODUCED", "PROTOCOL_NOT_OBSERVED"))
        self.assertEqual(self.profile.evaluate(task, result), nmap.evaluate_task(task, result))

    def test_untrusted_or_ambiguous_output_stays_inconclusive(self):
        task, result = nmap_task(self.profile)
        for mutation, reason in (
            (lambda report: report["hosts"][0].__setitem__("ip", "192.0.2.11"), "TARGET_MISMATCH"),
            (lambda report: report["hosts"][0]["services"][0].__setitem__("port", 8443), "SERVICE_MISMATCH"),
            (lambda report: report["hosts"][0]["services"][0].__setitem__("protocol", "udp"), "SERVICE_MISMATCH"),
            (lambda report: report["hosts"][0].__setitem__("services", []), "AMBIGUOUS_OR_MISSING_SERVICE"),
            (lambda report: report["hosts"][0]["services"][0].__setitem__("status", "filtered"), "SERVICE_NOT_OPEN"),
            (lambda report: report["hosts"][0]["services"][0].__setitem__("status", []), "INVALID_SERVICE_OUTPUT"),
            (lambda report: report["hosts"][0]["services"][0].__setitem__("vulnerabilities", []), "MISSING_OR_AMBIGUOUS_SCRIPT"),
            (lambda report: report["hosts"][0]["services"][0]["vulnerabilities"][0].__setitem__("desc", "nothing"),
             "NO_PROTOCOL_CIPHER_EVIDENCE"),
        ):
            report = json.loads(result["stdout"])
            mutation(report)
            with self.subTest(reason=reason):
                self.assertEqual(self.profile.evaluate(task, {**result, "stdout": json.dumps(report)})[2], reason)
        self.assertEqual(self.profile.evaluate(task, {"state": "ERROR", "stdout": ""})[1], "INCONCLUSIVE")
        self.assertEqual(self.profile.evaluate(task, {"state": "COMPLETED", "stdout": ""})[2], "NO_STRUCTURED_OUTPUT")
        self.assertEqual(self.profile.evaluate(task, {"state": "COMPLETED", "stdout": "not json"})[2], "INVALID_FARADAY_OUTPUT")

    def test_evidence_size_bound_is_enforced_per_line(self):
        task, _result = nmap_task(self.profile)
        oversized = {"state": "COMPLETED", "stdout": "{" + '"a":1,' * 9000 + '"a":1}'}
        self.assertEqual(self.profile.evaluate(task, oversized)[2], "INVALID_FARADAY_OUTPUT")


class TestsslEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.profile = get_profile("testssl-3.2.4-ssl-tls")

    def test_exact_name_and_cve_mapping_and_allowlisted_flags(self):
        self.assertEqual(testssl.check_ids_for_vulnerability("TLS Version 1.0 Deprecated Protocol"), ("tls1_0",))
        self.assertEqual(testssl.check_ids_for_vulnerability("unrelated issue", ["CVE-2014-0160"]), ("heartbleed",))
        self.assertEqual(testssl.check_ids_for_vulnerability("unrelated", ["CVE-1999-0001"]), ())
        self.assertEqual(testssl.flags_for_checks(["tls1_0", "weak_ciphers"]), ("-p", "-s"))
        with self.assertRaisesRegex(ValueError, "Unsupported testssl check"):
            testssl.flags_for_checks(["--jsonfile"])
        with self.assertRaisesRegex(ValueError, "At least one"):
            testssl.flags_for_checks([])

    def test_vendor_catalog_alias_shares_the_weak_signature_evidence_rule(self):
        for name in (
            "SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)",
            "  ssl certificate signed using weak hashing algorithm (known ca)",
        ):
            self.assertEqual(testssl.check_ids_for_vulnerability(name), ("cert_weak_hash",))
        self.assertEqual(testssl.check_ids_for_vulnerability("SSL Certificate Signed Using Weak Hashing"), ())
        self.assertEqual(testssl.flags_for_checks(["cert_weak_hash"]), ("-S",))

        task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["cert_weak_hash"]}}
        weak = {"state": "COMPLETED", "stdout": json.dumps(evidence(
            [scanner_record("cert_signatureAlgorithm", severity="MEDIUM", finding="SHA1 with RSA")],
            ("cert_weak_hash",),
        ))}
        observed, _, _ = testssl.evaluate_records(task, weak)
        self.assertEqual(observed, {"cert_weak_hash": "REPRODUCED"})
        for finding, severity, expected in (("SHA256 with RSA", "OK", "NOT_REPRODUCED"), ("SHA224 with RSA", "INFO", None)):
            clean = {"state": "COMPLETED", "stdout": json.dumps(evidence(
                [scanner_record("cert_signatureAlgorithm", severity=severity, finding=finding)],
                ("cert_weak_hash",),
            ))}
            observed, fallback, _reason = testssl.evaluate_records(task, clean)
            self.assertEqual(observed, {} if expected is None else {"cert_weak_hash": expected})
            self.assertEqual(fallback, "INCONCLUSIVE")

    def test_command_disables_dns_and_phone_home_and_uses_literal_scope(self):
        argv = testssl.build_argv(TESTSSL_BINARY, TARGET, PORT, ["tls1_0"], "/tmp/evidence.json")
        self.assertIn("--nodns", argv)
        self.assertEqual(argv[argv.index("--nodns") + 1], "none")
        self.assertNotIn("--phone-out", argv)
        self.assertIn(f"{TARGET}:{PORT}", argv)
        self.assertIn("--jsonfile", argv)
        self.assertNotIn("--target", argv)

    def test_scanner_json_uses_upstream_finding_schema_and_binds_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scanner.json"
            upstream_record = scanner_record()
            upstream_record["ip"] = f"{TARGET}/{TARGET}"
            path.write_text(json.dumps([upstream_record]), encoding="utf-8")
            parsed = testssl.load_scanner_json(path, TARGET, PORT, ["tls1_0"])
            self.assertEqual(parsed["records"], [{
                "id": "TLS1", "severity": "HIGH", "finding": "offered", "ip": TARGET, "port": PORT,
            }])
            path.write_text(json.dumps([scanner_record()]), encoding="utf-8")
            self.assertEqual(testssl.load_scanner_json(path, TARGET, PORT, ["tls1_0"])["records"][0]["ip"], TARGET)
            upstream_record["ip"] = f"{TARGET}/192.0.2.11"
            path.write_text(json.dumps([upstream_record]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "endpoint mismatch"):
                testssl.load_scanner_json(path, TARGET, PORT, ["tls1_0"])
            path.write_text(json.dumps([{"id": "TLS1", "severity": "HIGH", "vulnerability": "offered",
                                         "ip": TARGET, "port": PORT}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "finding text"):
                testssl.load_scanner_json(path, TARGET, PORT, ["tls1_0"])

    def test_positive_evidence_negative_check_and_incomplete_output(self):
        task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["tls1_0"]}}
        observed, fallback, _reason = testssl.evaluate_records(
            task, {"state": "COMPLETED", "stdout": json.dumps(evidence([scanner_record()]))}
        )
        self.assertEqual((observed, fallback), ({"tls1_0": "REPRODUCED"}, "INCONCLUSIVE"))

        clean = {"state": "COMPLETED", "stdout": json.dumps(evidence([scanner_record(severity="OK", finding="not offered")]))}
        self.assertEqual(testssl.evaluate_records(task, clean)[0], {"tls1_0": "NOT_REPRODUCED"})
        self.assertEqual(testssl.evaluate_records(task, {"state": "ERROR", "stdout": ""}),
                         ({}, "INCONCLUSIVE", "TASK_NOT_COMPLETED"))

        mismatched = {"state": "COMPLETED", "stdout": json.dumps(evidence([scanner_record(finding_id="TLS1_1")]))}
        self.assertEqual(testssl.evaluate_records(task, mismatched),
                         ({}, "INCONCLUSIVE", "NO_COMPLETE_CHECK_EVIDENCE"))

    def test_absence_based_checks_use_direct_evidence_only(self):
        hsts_task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["hsts"]}}
        observed, _, _ = testssl.evaluate_records(hsts_task, {"state": "COMPLETED", "stdout": json.dumps(evidence([
            scanner_record("service", severity="OK", finding="HTTP"),
            scanner_record("HSTS", severity="OK", finding="not offered (HTTP)"),
        ], ("hsts",)))})
        self.assertEqual(observed, {"hsts": "REPRODUCED"})

        kem_task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["post_quantum_kex"]}}
        for finding, expected in (("-", {"post_quantum_kex": "REPRODUCED"}),
                                  ("X25519MLKEM768", {"post_quantum_kex": "NOT_REPRODUCED"})):
            observed, _, _ = testssl.evaluate_records(kem_task, {"state": "COMPLETED", "stdout": json.dumps(
                evidence([scanner_record("FS_KEMs", severity="OK", finding=finding)], ("post_quantum_kex",)))})
            with self.subTest(finding=finding):
                self.assertEqual(observed, expected)

    def test_evidence_envelope_must_match_the_issued_task(self):
        task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["tls1_0"]}}
        for mutation in (
            lambda payload: payload.__setitem__("format", "other.v1"),
            lambda payload: payload.__setitem__("target", "192.0.2.11"),
            lambda payload: payload.__setitem__("port", 8443),
            lambda payload: payload.__setitem__("check_ids", ["heartbleed"]),
            lambda payload: payload["records"].append({"id": "TLS1"}),
        ):
            payload = evidence([scanner_record()])
            mutation(payload)
            with self.subTest(payload=sorted(payload)):
                self.assertEqual(testssl.evaluate_records(task, {"state": "COMPLETED", "stdout": json.dumps(payload)})[2],
                                 "INVALID_TESTSSL_EVIDENCE")
        record_mismatch = evidence([scanner_record(target="192.0.2.11")])
        self.assertEqual(testssl.evaluate_records(task, {"state": "COMPLETED", "stdout": json.dumps(record_mismatch)})[2],
                         "TESTSSL_TARGET_MISMATCH")

    def test_strict_json_rejects_duplicates_nonfinite_and_oversized_payload(self):
        from faraday_agent_dispatcher.utils.executor_profiles import strict_json

        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'{"a":1e400}', b"x" * (32768 + 1), b""):
            with self.subTest(payload=payload[:24]), self.assertRaises(ValueError):
                strict_json(payload)


class ApprovedExecutorTests(unittest.TestCase):
    def test_malformed_records_and_scalar_fields_are_inconclusive(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = testssl_task(profile)
        malformed = [None, [], 1, "record", [scanner_record()]]
        for field in ("id", "finding", "severity", "ip", "port"):
            for value in (None, [], {}, True, 1.5):
                malformed.append({**scanner_record(), field: value})
        for item in malformed:
            with self.subTest(item=item):
                result = {"state": "COMPLETED", "stdout": json.dumps(evidence([item]))}
                self.assertEqual(profile.evaluate(task, result)[1], "INCONCLUSIVE")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "scanner.json")
            for item in malformed:
                path.write_text(json.dumps([item]), encoding="utf-8")
                with self.subTest(raw=item), self.assertRaises(ProfileError):
                    testssl.load_scanner_json(path, TARGET, PORT, ["tls1_0"])

    def test_renegotiation_dos_never_proves_mitm(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ["renegotiation"]}}
        for finding_id in ("secure_client_renego", "client_renegotiation", "insecure_renego"):
            result = {"state": "COMPLETED", "stdout": json.dumps(evidence([
                scanner_record(finding_id, severity="HIGH", finding="VULNERABLE (DoS)")], ["renegotiation"]))}
            self.assertEqual(profile.evaluate(task, result)[0], {})
        result = {"state": "COMPLETED", "stdout": json.dumps(evidence([
            scanner_record("secure_renego", severity="CRITICAL", finding="VULNERABLE")], ["renegotiation"]))}
        self.assertEqual(profile.evaluate(task, result)[0], {"renegotiation": "REPRODUCED"})

    def test_approved_executor_privacy_faraday_roundtrip_and_temp_cleanup(self):
        from faraday_plugins.plugins.repo.faraday_json.plugin import FaradayJsonPlugin

        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = testssl_task(profile)
        output_paths = []

        def run(argv, **kwargs):
            self.assertEqual(argv[-1], f"{TARGET}:{PORT}")
            self.assertEqual(argv[argv.index("--nodns") + 1], "none")
            for forbidden in ("--phone-out", "--starttls", "--sni", "--openssl", "--custom=1"):
                self.assertNotIn(forbidden, argv)
            self.assertEqual(kwargs["env"]["PHONE_OUT"], "false")
            self.assertFalse(kwargs["capture_output"])
            self.assertEqual(kwargs["max_file_bytes"], testssl.MAX_SCANNER_JSON_BYTES)
            self.assertNotIn("BASH_ENV", kwargs["env"])
            self.assertNotIn("OPENSSL", kwargs["env"])
            path = Path(argv[argv.index("--jsonfile") + 1])
            output_paths.append(path)
            path.write_text(json.dumps([scanner_record(), scanner_record("service", severity="OK", finding="HTTP")]), encoding="utf-8")
            return SimpleNamespace(returncode=0, stderr=None)

        with patch.dict(os.environ, {"TESTSSL_PATH": sys.executable}):
            command = build_command(profile, task)
        hostile = {"EXECUTOR_CONFIG_TESTSSL_EXTRA_ARGS": "--custom=1", "EXECUTOR_CONFIG_TESTSSL_STARTTLS": "smtp",
                   "EXECUTOR_CONFIG_TESTSSL_TARGET": "other.example:8443", "PHONE_OUT": "true",
                   "OPENSSL": "/untrusted", "BASH_ENV": "/untrusted"}
        with patch.dict(os.environ, {**hostile, **command.environment}), patch(
                "faraday_agent_dispatcher.utils.scanner_process.run_scanner", side_effect=run):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                testssl.main()
        report = json.loads(stdout.getvalue())
        self.assertEqual(set(report), {"hosts", "command", "validation_evidence"})
        self.assertEqual(profile.evaluate(task, {"state": "COMPLETED", "stdout": stdout.getvalue()})[0], {"tls1_0": "REPRODUCED"})
        self.assertEqual(len(report["hosts"][0]["services"][0]["vulnerabilities"]), 1)
        parser = FaradayJsonPlugin()
        parser.parseOutputString(stdout.getvalue())
        self.assertTrue(json.loads(parser.get_json())["hosts"])
        self.assertTrue(output_paths)
        self.assertTrue(all(not path.exists() for path in output_paths))

    def test_approved_executor_failure_never_emits_success(self):
        from faraday_agent_dispatcher.utils.scanner_process import ScannerProcessError

        profile = get_profile("testssl-3.2.4-ssl-tls")
        with patch.dict(os.environ, {"TESTSSL_PATH": sys.executable}):
            command = build_command(profile, testssl_task(profile))
        for failure in (OSError("cannot start"), testssl.subprocess.TimeoutExpired("testssl.sh", 900),
                        ScannerProcessError("Scanner stdout limit exceeded")):
            with patch.dict(os.environ, command.environment), patch(
                    "faraday_agent_dispatcher.utils.scanner_process.run_scanner", side_effect=failure):
                stdout = io.StringIO()
                with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
                    testssl.main()
                self.assertEqual(raised.exception.code, 1)
                self.assertEqual(stdout.getvalue(), "")

    def test_duplicate_failed_and_conflicting_records_fail_affected_check_closed(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        cases = [
            (["tls1_0"], [scanner_record(), scanner_record(severity="ERROR", finding="analysis failed")]),
            (["tls1_0"], [scanner_record(), scanner_record()]),
            (["post_quantum_kex"], [scanner_record("FS_KEMs", severity="OK", finding="-"),
                                    scanner_record("FS_ciphers", severity="OK", finding="X25519MLKEM768")]),
            (["weak_ciphers"], [scanner_record("cipherlist_LOW", severity="HIGH", finding="offered"),
                               scanner_record("cipherlist_EXPORT", severity="ERROR", finding="analysis failed")]),
        ]
        for ids, records in cases:
            task = {"target": TARGET, "port": PORT, "arguments": {"CHECK_IDS": ids}}
            result = {"state": "COMPLETED", "stdout": json.dumps(evidence(records, ids))}
            with self.subTest(ids=ids, records=records):
                self.assertNotIn("REPRODUCED", profile.evaluate(task, result)[0].values())

    def test_nmap_failed_scan_never_parses_valid_looking_xml(self):
        xml = b'<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>'
        environment = {"FAD_VALIDATION_MODE": "1", "EXECUTOR_CONFIG_TARGET": json.dumps([TARGET])}
        with patch.dict(os.environ, environment), patch(
                "faraday_agent_dispatcher.utils.scanner_process.run_scanner",
                return_value=SimpleNamespace(returncode=1, stdout=xml, stderr=b"failed")), patch(
                "faraday_plugins.plugins.repo.nmap.plugin.NmapPlugin") as plugin:
            with redirect_stdout(io.StringIO()) as stdout, self.assertRaises(SystemExit) as raised:
                nmap.main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(stdout.getvalue(), "")
            plugin.assert_not_called()

    def test_custom_testssl_profile_binding_is_resolved_before_scan(self):
        from faraday_agent_dispatcher.utils import executor_profiles as registry
        from tests.unittests.test_validator_profiles import executor_manifest, manifest

        data = manifest("testssl-3.2.4-ssl-tls")
        data["id"] = "third-testssl-profile"
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "testssl.json").write_text(json.dumps(executor_manifest(data)), encoding="utf-8")
            profile = registry.load_profiles(directory)[data["id"]]
        task = testssl_task(profile)
        with patch.dict(registry._PROFILES, {profile.id: profile}), patch.dict(os.environ, {"TESTSSL_PATH": sys.executable}):
            command = build_command(profile, task)

            def run(argv, **kwargs):
                Path(argv[argv.index("--jsonfile") + 1]).write_text(json.dumps([scanner_record()]), encoding="utf-8")
                return SimpleNamespace(returncode=0, stderr=None)

            with patch.dict(os.environ, command.environment), patch(
                    "faraday_agent_dispatcher.utils.scanner_process.run_scanner", side_effect=run):
                with redirect_stdout(io.StringIO()) as stdout:
                    testssl.main()
            self.assertEqual(json.loads(stdout.getvalue())["validation_evidence"]["profile_id"], profile.id)
            self.assertEqual(profile.evaluate(task, {"state": "COMPLETED", "stdout": stdout.getvalue()})[0], {"tls1_0": "REPRODUCED"})

    def test_analysis_error_does_not_prove_fixed_severity_check(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = testssl_task(profile)
        for severity in ("WARN", "ERROR", "INFO", "SPECIAL"):
            result = {"state": "COMPLETED", "stdout": json.dumps(evidence([scanner_record(severity=severity)]))}
            self.assertEqual(profile.evaluate(task, result)[0], {})


def testssl_task(profile):
    claims = profile.claims("vulnerability-1", {"check_ids": ["tls1_0"]})
    return {"id": "cd" * 16, "profile_id": profile.id, "executor_id": profile.executor_id,
            "target": TARGET, "port": PORT, "arguments": profile.arguments(TARGET, PORT, claims), "claims": claims}


class RuntimeHookTests(unittest.TestCase):
    def test_supported_handlers_are_the_registered_profile_handlers(self):
        self.assertEqual(sorted(SUPPORTED_HANDLERS), sorted({p.handler_id for p in
                            [get_profile("nmap-tls-protocols"), get_profile("testssl-3.2.4-ssl-tls")]}))

    def test_nmap_command_is_the_packaged_official_executor(self):
        profile = get_profile("nmap-tls-protocols")
        task, _result = nmap_task(profile)
        command = build_command(profile, task)
        self.assertEqual(command.handler_id, "nmap_tls")
        self.assertEqual(command.argv, (sys.executable, nmap.nmap_executor_script()))
        self.assertTrue(command.argv[1].endswith("static/executors/official/nmap.py"))
        self.assertEqual(command.environment, {"NMAP_UNPRIVILEGED": "1", "FAD_VALIDATION_MODE": "1"})

    def test_testssl_command_runs_official_executor_with_compact_binding(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = testssl_task(profile)
        task["claims"] = [{"vulnerability_id": str(index), "check_id": "tls1_0"} for index in range(10000)]
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory, "testssl.sh")
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o700)
            with patch.dict(os.environ, {"TESTSSL_PATH": str(binary)}):
                command = build_command(profile, task)
            self.assertEqual(command.argv, (sys.executable, str(Path(testssl.__file__).resolve())))
            self.assertEqual(command.environment["TESTSSL_PATH"], str(binary))
            self.assertEqual(command.environment["PHONE_OUT"], "false")
            self.assertEqual(command.environment["FAD_VALIDATION_MODE"], "1")
            binding = command.environment["FAD_VALIDATION_TASK"]
            self.assertLess(len(binding), 1024)
            self.assertEqual(json.loads(binding), {"profile_id": profile.id, "target": TARGET,
                                                 "port": PORT, "check_ids": ["tls1_0"]})

    def test_missing_pinned_binary_and_unknown_handler_fail_closed(self):
        profile = get_profile("testssl-3.2.4-ssl-tls")
        task = testssl_task(profile)
        for missing in ("", "testssl.sh", "/does/not/exist", "/tmp"):
            with self.subTest(missing=missing), patch.dict(os.environ, {"TESTSSL_PATH": missing}), self.assertRaises(ProfileError):
                build_command(profile, task)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ProfileError):
            build_command(profile, task)
        with self.assertRaises(ProfileError):
            build_command(SimpleNamespace(handler_id="arbitrary"), task)

    def test_command_rejects_task_tampering_before_execution(self):
        profile = get_profile("nmap-tls-protocols")
        task, _ = nmap_task(profile)
        task["arguments"]["TARGET"] = ["192.0.2.99"]
        with self.assertRaises(ProfileError):
            build_command(profile, task)


if __name__ == "__main__":
    unittest.main()
