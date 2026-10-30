"""Unit tests for the testssl executor.

Only the pure logic is covered: the scan itself is exercised against a local
TLS server during development, never from the test suite.
"""

import importlib
import json
import os
from types import SimpleNamespace
from unittest.mock import patch


def _executor():
    return importlib.import_module("faraday_agent_dispatcher.static.executors.official.testssl")


TESTSSL = _executor()


def agent_config(**kwargs):
    settings = {"ignore_info": False, "min_severity": "", "max_severity": "", "resolve_hostname": False}
    settings.update(kwargs)
    return SimpleNamespace(**settings)


def finding(finding_id, text, severity="OK", ip="10.0.0.1/10.0.0.1", port="443"):
    return {"id": finding_id, "ip": ip, "port": port, "severity": severity, "finding": text}


def scan_entries(extra=None):
    """Minimal but realistic testssl.sh record set for one HTTPS endpoint."""
    entries = [
        finding("service", "HTTP"),
        finding("SSLv2", "not offered"),
        finding("SSLv3", "not offered"),
        finding("TLS1", "offered (deprecated)"),
        finding("TLS1_1", "offered (deprecated)"),
        finding("TLS1_2", "offered (OK)"),
        finding("cipherlist_NULL", "not offered"),
        finding("cipherlist_aNULL", "not offered"),
        finding("cipherlist_LOW", "not offered"),
        finding("cipherlist_OBSOLETED", "not offered"),
        finding("SWEET32", "not vulnerable", "OK"),
        finding("LUCKY13", "not vulnerable", "OK"),
        finding("BEAST", "not vulnerable", "OK"),
        finding("heartbleed", "not vulnerable", "OK"),
        finding("CCS", "not vulnerable", "OK"),
        finding("secure_renego", "OK (service does not support renegotiation)", "OK"),
        finding("fallback_SCSV", "NOT supported as extension - possibly vulnerable against SCSV", "OK"),
        finding("HSTS", "not offered (HTTP)", "OK"),
        finding("cert_commonName", "weak.example.com"),
        finding("cert_subjectAltName", "DNS:weak.example.com"),
        finding("cert_signatureAlgorithm", "SHA256 with RSA", "OK"),
        finding("cert_keySize", "RSA 2048 bits", "OK"),
        finding("cert_expirationStatus", "no", "OK"),
        finding("cert_trust", "Ok (subject weak.example.com)"),
        finding("cert_chain_of_trust", "passed."),
        finding("FS", "yes (OK), among 10 (n/a)", "OK"),
        finding("FS_ciphers", "ECDHE-RSA-AES256-GCM-SHA384", "OK"),
        finding("FS_KEMs", "X25519MLKEM768", "OK"),
    ]
    return entries + list(extra or [])


def vuln_names(vulns):
    return [vuln["name"] for vuln in vulns]


def build(entries, keys, **options):
    opts = {"include_info": False}
    opts.update(options)
    return TESTSSL.build_vulnerabilities(entries, keys, opts)


# --------------------------------------------------------------------------
# VULN selection
# --------------------------------------------------------------------------


def test_resolve_checks_accepts_catalog_issue_names():
    keys, unknown = TESTSSL.resolve_checks(["SSL/TLS Multiple Issues:", "Weak Cryptography"])
    assert unknown == []
    assert {"sslv2", "sslv3", "heartbleed", "cert_weak_hash", "logjam"} <= set(keys)
    # the weak-crypto issue contributes the post-quantum check, nothing else
    assert "post_quantum_kex" in keys and "hsts" not in keys


def test_resolve_checks_accepts_keys_cves_and_plugin_ids():
    keys, unknown = TESTSSL.resolve_checks(["post_quantum_kex", "CVE-2016-2183", "94437", "nessus-31705"])
    assert unknown == []
    assert set(keys) == {"post_quantum_kex", "sweet32", "anon_ciphers"}


def test_resolve_checks_reports_unknown_tokens_only():
    keys, unknown = TESTSSL.resolve_checks(["heartbleed", "definitely-not-a-check"])
    assert keys == ["heartbleed"]
    assert unknown == ["definitely-not-a-check"]


def test_resolve_checks_group_aliases_and_exclusion():
    keys, _ = TESTSSL.resolve_checks(["certificate"])
    assert "cert_expired" in keys and "heartbleed" not in keys
    keep, _ = TESTSSL.resolve_checks(["all"])
    drop, _ = TESTSSL.resolve_checks(["sslv3"])
    assert set(drop) < set(keep)


def test_resolve_checks_matches_vulnerability_name():
    keys, unknown = TESTSSL.resolve_checks(["SSL RC4 Cipher Suites Supported (Bar Mitzvah)"])
    assert keys == ["rc4"] and unknown == []


# --------------------------------------------------------------------------
# Target expansion and command building
# --------------------------------------------------------------------------


def test_target_uris_expand_ports_only_when_missing():
    assert TESTSSL.target_uris(["10.0.0.1"], [443, 8443], True, "") == ["10.0.0.1:443", "10.0.0.1:8443"]
    assert TESTSSL.target_uris(["10.0.0.1:993"], [443], True, "") == ["10.0.0.1:993"]
    assert TESTSSL.target_uris(["https://a.example.com:8443/"], [443], True, "") == ["https://a.example.com:8443"]


def test_target_uris_keep_default_port_for_starttls():
    assert TESTSSL.target_uris(["mail.example.com"], [443], False, "smtp") == ["mail.example.com"]
    assert TESTSSL.target_uris(["mail.example.com"], [587], True, "smtp") == ["mail.example.com:587"]


def test_scan_flags_are_unioned_in_tool_order():
    flags = TESTSSL.scan_flags(["sslv3", "post_quantum_kex", "heartbleed"])
    assert flags == ["-p", "-f", "-H"]  # broad category tests first, then single tests


def test_build_command_carries_uri_last_and_json_file():
    cmd = TESTSSL.build_command(
        "10.0.0.1:443",
        "/tmp/out.json",
        ["sslv3"],
        {
            "binary": "testssl.sh",
            "openssl": None,
            "starttls": "smtp",
            "nodns": "none",
            "connect_timeout": 7,
            "openssl_timeout": 9,
            "sneaky": True,
            "ids_friendly": False,
            "phone_out": False,
            "extra_args": ["--custom=1"],
        },
    )
    assert cmd[0] == "testssl.sh"
    assert cmd[-1] == "10.0.0.1:443"
    assert cmd[-4:-2] == ["--jsonfile", "/tmp/out.json"] and cmd[-2] == "--overwrite"
    assert ["--starttls", "smtp"] == cmd[cmd.index("--starttls") : cmd.index("--starttls") + 2]
    assert "--sneaky" in cmd and "--custom=1" in cmd
    assert "--nodns" in cmd and cmd[cmd.index("--nodns") + 1] == "none"
    assert "--warnings" in cmd and "off" in cmd


def test_nodns_defaults_to_forward_only_and_rejects_unknown_modes():
    with patch.object(TESTSSL.arg_helpers, "single", return_value=None):
        assert TESTSSL._nodns() == "min"
    with patch.object(TESTSSL.arg_helpers, "single", return_value="none"):
        assert TESTSSL._nodns() == "none"
    with patch.object(TESTSSL.arg_helpers, "single", return_value="all"):
        assert TESTSSL._nodns() == "min"


# --------------------------------------------------------------------------
# testssl.sh JSON parsing
# --------------------------------------------------------------------------


def test_parse_findings_reads_flat_json():
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "scan.json")
        with open(path, "w") as handle:
            json.dump(scan_entries(), handle)
        entries = TESTSSL.parse_findings(path)
    assert len(entries) == len(scan_entries())


def test_parse_findings_survives_a_truncated_file():
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "scan.json")
        with open(path, "w") as handle:
            handle.write(json.dumps(scan_entries())[:400] + '{"id": "cert_keySize", "severity": "OK"')
        entries = TESTSSL.parse_findings(path)
    assert entries and all(entry["id"] for entry in entries)


def test_parse_findings_missing_file_is_not_fatal():
    assert TESTSSL.parse_findings("/nonexistent/scan.json") == []


# --------------------------------------------------------------------------
# Finding selection
# --------------------------------------------------------------------------


def test_clean_endpoint_reports_only_the_deprecated_protocols():
    keys, _ = TESTSSL.resolve_checks(["SSL/TLS Multiple Issues:"])
    vulns = build(scan_entries(), keys)
    assert vuln_names(vulns) == [
        "TLS Version 1.0 Deprecated Protocol",
        "TLS Version 1.1 Deprecated Protocol",
        "TLS_FALLBACK_SCSV Downgrade Protection Not Supported",
    ]
    assert [vuln["severity"] for vuln in vulns] == ["medium", "medium", "info"]
    assert vulns[0]["refs"] == ["RFC 8996"]


def test_reported_protocols_only_when_actually_offered():
    entries = scan_entries([finding("SSLv3", "offered", "CRITICAL")])
    vulns = build(entries, ["sslv3"])
    assert vuln_names(vulns) == ["SSL Version 2 and 3 Protocol Detection"]
    assert vulns[0]["severity"] == "critical"
    assert "NESSUS-20007" in vulns[0]["refs"]


def test_negative_findings_are_never_reported():
    keys = ["heartbleed", "ccs_injection", "sweet32", "beast", "cbc_ciphers", "rc4", "weak_dh"]
    assert build(scan_entries(), keys) == []


def test_analysis_errors_do_not_inherit_pinned_severities():
    entries = [finding("TLS1", "offered (analysis failed)", "ERROR"),
               finding("FS_KEMs", "could not test", "WARN")]
    assert build(entries, ["tls1_0", "post_quantum_kex"]) == []


def test_client_renegotiation_dos_is_not_mitm_injection():
    entries = [finding("secure_client_renego", "VULNERABLE (DoS)", "HIGH")]
    assert build(entries, ["renegotiation"]) == []
    entries.append(finding("secure_renego", "VULNERABLE", "CRITICAL"))
    assert len(build(entries, ["renegotiation"])) == 1


def test_positive_attack_findings_use_pinned_severities():
    entries = scan_entries(
        [
            finding("heartbleed", "vulnerable, VULNERABLE (DoS!)", "CRITICAL"),
            finding("CCS", "vulnerable, VULNERABLE (inject)", "HIGH"),
            finding("SWEET32", "vulnerable, VULNERABLE", "HIGH"),
            finding("RC4", "vulnerable, VULNERABLE", "HIGH"),
        ]
    )
    vulns = {vuln["name"]: vuln for vuln in build(entries, ["heartbleed", "ccs_injection", "sweet32", "rc4"])}
    assert vulns["OpenSSL Heartbeat Information Disclosure (Heartbleed)"]["severity"] == "critical"
    assert vulns["SSL 64-bit Block Size Cipher Suites Supported (SWEET32)"]["severity"] == "high"
    assert vulns["SSL RC4 Cipher Suites Supported (Bar Mitzvah)"]["severity"] == "high"
    assert "CVE-2014-0160" in vulns["OpenSSL Heartbeat Information Disclosure (Heartbleed)"]["cve"]


def test_self_signed_certificate_is_reported_once():
    entries = scan_entries(
        [
            finding("cert_chain_of_trust", "failed (self signed).", "CRITICAL"),
            finding("cert_trust", "certificate does not match supplied URI", "HIGH"),
        ]
    )
    names = vuln_names(build(entries, ["cert_self_signed", "cert_untrusted", "cert_cn_mismatch"]))
    assert names == ["SSL Self-Signed Certificate", "SSL Certificate 'commonName' Mismatch"]


def test_untrusted_chain_is_reported_when_it_is_not_self_signed():
    entries = scan_entries([finding("cert_chain_of_trust", "incomplete certificate chain", "HIGH")])
    vulns = build(entries, ["cert_self_signed", "cert_untrusted"])
    assert vuln_names(vulns) == ["SSL Certificate Cannot Be Trusted"]
    assert vulns[0]["severity"] == "medium"


def test_expired_and_weak_certificate_findings():
    entries = scan_entries(
        [
            finding("cert_expirationStatus", "expired 30 days ago", "CRITICAL"),
            finding("cert_signatureAlgorithm", "SHA1 with RSA", "MEDIUM"),
            finding("cert_keySize", "RSA 1024 bits (exponent is 65537)", "MEDIUM"),
            finding("cert_subjectAltName", "No SAN, browsers are complaining", "HIGH"),
            finding("cert_commonName", "no CN field in subject", "MEDIUM"),
        ]
    )
    vulns = {vuln["name"]: vuln for vuln in build(entries, ["cert_expired", "cert_weak_hash", "cert_weak_key"])}
    assert set(vulns) == {
        "SSL Certificate Expiry",
        "SSL Certificate Signed Using Weak Hashing Algorithm",
        "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits",
    }
    assert vulns["SSL Certificate Expiry"]["severity"] == "critical"
    assert vulns["SSL Certificate Signed Using Weak Hashing Algorithm"]["severity"] == "high"
    assert "NESSUS-15901" in vulns["SSL Certificate Expiry"]["refs"]
    assert "NESSUS-35291" in vulns["SSL Certificate Signed Using Weak Hashing Algorithm"]["refs"]
    # A sane certificate must not raise the SHA-1/short-key findings.
    assert build(scan_entries(), ["cert_expired", "cert_weak_hash", "cert_weak_key"]) == []


def test_missing_certificate_fields():
    entries = scan_entries(
        [
            finding("cert_commonName", "no CN field in subject", "MEDIUM"),
            finding("cert_subjectAltName", "No SAN, browsers are complaining", "HIGH"),
        ]
    )
    keys = ["cert_no_subject", "cert_no_san"]
    assert vuln_names(build(entries, keys)) == [
        "SSL Certificate with no Common Name",
        "SSL Certificate without subjectAltName",
    ]
    assert build(scan_entries(), keys) == []


def test_hsts_is_only_reported_for_http_services():
    entries = scan_entries()
    assert vuln_names(build(entries, ["hsts"])) == ["HSTS Missing From HTTPS Server"]
    # A non-HTTP endpoint (e.g. SMTP STARTTLS) cannot serve HSTS.
    smtp = [entry for entry in entries if entry["id"] != "service"] + [finding("service", "SMTP")]
    assert build(smtp, ["hsts"]) == []


def test_post_quantum_check_is_reported_when_no_kem_is_offered():
    without_kem = [entry for entry in scan_entries() if entry["id"] != "FS_KEMs"] + [finding("FS_KEMs", "-", "OK")]
    vulns = build(without_kem, ["post_quantum_kex"])
    assert vuln_names(vulns) == ["Remote Services Not Using Post-Quantum Ciphers"]
    assert vulns[0]["severity"] == "info"
    assert "NESSUS-277650" in vulns[0]["refs"]
    assert build(scan_entries(), ["post_quantum_kex"]) == []


def test_info_vulnerabilities_are_opt_in():
    entries = scan_entries()
    assert build(entries, ["sslv2"]) == []
    names = vuln_names(build(entries, ["sslv2"], include_info=True))
    assert "SSL/TLS Versions Supported" in names
    assert "SSL Certificate Information" in names


# --------------------------------------------------------------------------
# Faraday output shape
# --------------------------------------------------------------------------


def test_host_service_and_vulnerability_shape():
    entries = scan_entries([finding("SSLv3", "offered", "CRITICAL")])
    vulns = build(entries, ["sslv3", "cert_expired"])
    host = TESTSSL.build_host("web.example.com:443", entries, vulns, agent_config(), 443)
    assert host["ip"] == "10.0.0.1"
    assert host["hostnames"] == ["web.example.com"]
    service = host["services"][0]
    assert set(service) == {"name", "port", "protocol", "vulnerabilities"}
    assert service["name"] == "https" and service["port"] == 443
    for vuln in vulns:
        assert set(vuln) >= {"name", "desc", "severity", "type", "data", "external_id", "refs", "cve", "resolution"}
        assert "tool" not in vuln and "output" not in vuln
        assert vuln["data"] and vuln["desc"] and vuln["resolution"]
    assert json.dumps({"hosts": [host], "command": {}})


def test_ip_target_keeps_no_hostname_and_starttls_service_name():
    entries = [entry for entry in scan_entries() if entry["id"] != "service"] + [finding("service", "SMTP")]
    host = TESTSSL.build_host("10.0.0.1:587", entries, [], agent_config(), 443)
    assert host["hostnames"] == []
    assert host["services"][0] == {"name": "smtp", "port": 587, "protocol": "tcp", "vulnerabilities": []}


def test_resolve_ip_falls_back_to_the_target_when_the_tool_gives_nothing():
    entries = [finding("cert_trust", "Ok", ip="/")]
    assert TESTSSL.resolve_ip("10.9.9.9:443", entries, agent_config()) == "10.9.9.9"
    assert TESTSSL.resolve_ip("web.example.com:443", [], agent_config()) == "web.example.com"
    assert TESTSSL.resolve_ip("web.example.com:443", [], agent_config(resolve_hostname=True)) == "web.example.com"


def test_severity_window_from_the_agent_config():
    entries = scan_entries([finding("SSLv3", "offered", "CRITICAL")])
    vulns = build(entries, ["sslv3", "tls1_0"]) + build(entries, [], include_info=True)[:1]
    assert len(vulns) == 3
    assert TESTSSL.filter_severity(vulns, agent_config(ignore_info=True)) == vulns[:2]
    kept = TESTSSL.filter_severity(vulns, agent_config(min_severity="critical"))
    assert [vuln["name"] for vuln in kept] == ["SSL Version 2 and 3 Protocol Detection"]
    kept = TESTSSL.filter_severity(vulns, agent_config(max_severity="low"))
    assert [vuln["severity"] for vuln in kept] == ["info"]


def test_faraday_command_metadata():
    command = TESTSSL.faraday_command(["testssl.sh", "10.0.0.1"], "10.0.0.1", 0)
    assert command["tool"] == "testssl.sh"
    assert command["params"] == "target=10.0.0.1"
    assert command["import_source"] == "report"
    assert command["duration"] >= 0
