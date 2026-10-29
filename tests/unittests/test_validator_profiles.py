"""Approved validator profiles: manifest trust boundary and matching behaviour.

Synthetic data only. No scanner is executed and no target is contacted.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from faraday_agent_dispatcher.validators import (
    MANIFEST_DIRECTORY, ProfileError, get_profile, load_profiles, profiles,
)
from faraday_agent_dispatcher.validators.rules import EVIDENCE_RULES
from faraday_agent_dispatcher.validators.testssl import CHECKS

NMAP_PROFILE_ID = "nmap-tls-protocols"
TESTSSL_PROFILE_ID = "testssl-3.2.4-ssl-tls"
TARGET = "192.0.2.10"


def manifest(profile_id=NMAP_PROFILE_ID):
    return json.loads((MANIFEST_DIRECTORY / f"{profile_id}.json").read_text(encoding="utf-8"))


def task_for(profile, name="TLS Version 1.0 Deprecated Protocol", cves=()):
    claims = profile.claims("vulnerability-1", profile.candidate_fields(name, cves))
    return {"id": "ab" * 16, "executor_id": profile.executor_id, "profile_id": profile.id,
            "target": TARGET, "port": 443, "claims": claims,
            "arguments": profile.arguments(TARGET, 443, claims)}


class ProfileLoaderTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "profile.json").write_text(json.dumps(data), encoding="utf-8")
            return load_profiles(directory)

    def test_shipped_profiles_are_sorted_and_metadata_excludes_executable_fields(self):
        loaded = profiles()
        self.assertEqual(list(loaded), sorted(loaded))
        self.assertEqual(list(loaded), [NMAP_PROFILE_ID, TESTSSL_PROFILE_ID])
        loaded.clear()
        self.assertEqual(len(profiles()), 2)
        for profile in profiles().values():
            self.assertEqual(set(profile.metadata), {
                "id", "executor_id", "title", "description", "tool_version", "arguments", "target",
                "options", "verdicts", "automatic_statuses",
            })
            self.assertEqual(profile.platforms, ("linux/amd64", "linux/arm64"))
            self.assertNotIn("handler", profile.metadata)
            self.assertNotIn("runtime", profile.metadata)

    def test_unknown_profiles_fail_closed(self):
        for value in ("unknown", "../nmap", "", [], None, 1):
            with self.subTest(value=value), self.assertRaises(ProfileError):
                get_profile(value)

    def test_malformed_or_executable_manifests_fail_closed(self):
        mutations = [
            ("manifest_version", True), ("handler", "os.system"), ("executor_id", "other"),
            ("id", "../profile"), ("platforms", ["windows/amd64"]), ("platforms", []),
            ("checks", {}), ("checks", {"TLSv1.9": manifest()["checks"]["TLSv1.0"]}),
            ("arguments", {"TARGET": "$(whoami)"}), ("runtime", {"command": "sh"}),
            ("verdicts", ["FALSE_POSITIVE"]), ("limits", {"max_tasks": True, "max_vulnerabilities": 10000}),
        ]
        for key, value in mutations:
            data = manifest()
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load(data)
        for data in ([], {}, {**manifest(), "import": "os"}):
            with self.subTest(data=type(data)), self.assertRaises(ValueError):
                self.load(data)
        for field, value in (("address_family", "ipv6"), ("transport", "udp"), ("hostnames", True), ("sni", True)):
            data = manifest()
            data["target"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(data)
        for field in ("ids", "require", "exclude", "unavailable"):
            data = manifest(TESTSSL_PROFILE_ID)
            data["checks"]["tls1_0"][field] = ["untrusted evidence"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(data)

    def test_strict_bounded_json_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "profile.json")
            with self.assertRaises(ValueError):
                load_profiles(directory)
            for raw in (b'[]', b'{"id":"x","id":"y"}', b'{"id":NaN}', b'\xff', b'[' * 2000,
                        b'x' * (128 * 1024 + 1)):
                path.write_bytes(raw)
                with self.subTest(raw=raw[:25]), self.assertRaises(ValueError):
                    load_profiles(directory)
            path.write_text(json.dumps(manifest()), encoding="utf-8")
            duplicate = Path(directory, "duplicate.json")
            duplicate.write_bytes(path.read_bytes())
            with self.assertRaisesRegex(ValueError, "Duplicate profile id"):
                load_profiles(directory)
            duplicate.unlink()
            duplicate.symlink_to(path)
            with self.assertRaises(ValueError):
                load_profiles(directory)

    def test_privacy_runtime_and_flags_cannot_be_weakened(self):
        for change in ("phone", "dns", "extra_flag", "check_flag", "environment"):
            data = manifest(TESTSSL_PROFILE_ID)
            if change == "phone":
                data["runtime"]["environment"]["PHONE_OUT"] = "true"
            elif change == "dns":
                data["runtime"]["fixed_flags"].remove("--nodns")
            elif change == "extra_flag":
                data["runtime"]["fixed_flags"].append("--phone-out")
            elif change == "check_flag":
                data["checks"]["tls1_0"]["flags"] = ["--phone-out"]
            else:
                data["runtime"]["environment"]["PYTHONPATH"] = "/untrusted"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load(data)

    def test_extra_manifest_cannot_widen_target_policy(self):
        third = manifest()
        third.update(id="third-tls-profile", title="Third bounded profile")
        third["checks"]["TLSv1.0"].update(name="Third exact check", aliases=[])
        third["target"]["ports_per_task"] = 8
        with self.assertRaisesRegex(ValueError, "Unsupported profile target policy"):
            self.load(third)


class ProfileBehaviourTests(unittest.TestCase):
    def test_all_historical_nmap_exact_aliases_and_no_cve_matching(self):
        profile = get_profile(NMAP_PROFILE_ID)
        for version in ("1.0", "1.1"):
            for name in (
                f"TLS Version {version} Protocol Detection", f"TLS Version {version} Protocol Deprecated",
                f"TLS Version {version} Deprecated Protocol", f"TLS {version} Deprecated Protocol",
                f"TLS {version} Protocol Detection", f"TLS {version} Protocol Deprecated",
                f"TLS {version} Supported", f"TLS {version} Enabled", f"TLSv{version} Enabled", f"TLSv{version} is enabled",
            ):
                with self.subTest(name=name):
                    self.assertEqual(profile.match("  " + name.swapcase() + "  "), (f"TLSv{version}",))
                    self.assertEqual(profile.candidate_fields(name), {"protocol": f"TLSv{version}"})
        self.assertEqual(profile.match("unrelated", ["CVE-2014-0160"]), ())
        self.assertEqual(profile.candidate_fields("TLS Version 1.0 Protocol"), {})

    def test_testssl_names_alias_cves_and_trusted_unavailability(self):
        profile = get_profile(TESTSSL_PROFILE_ID)
        self.assertEqual(profile.match("  SSL CERTIFICATE SIGNED USING WEAK HASHING ALGORITHM (KNOWN CA) "), ("cert_weak_hash",))
        self.assertEqual(profile.match("unrelated", " cve-2014-0160 "), ("heartbleed",))
        self.assertEqual(profile.match("SSL Certificate Cannot Be Trusted"), ())
        self.assertEqual(profile.match("SSL Certificate 'commonName' Mismatch"), ())
        self.assertEqual(profile.match("OpenSSL Heartbeat Information Disclosure"), ())
        self.assertEqual(profile.match("unrelated", ["CVE-2014-0160-extra"]), ())
        self.assertEqual(profile.candidate_fields("SSL Self-Signed Certificate"), {"check_ids": ["cert_self_signed"]})
        self.assertNotIn("cert_untrusted", profile.criteria)
        self.assertNotIn("cert_cn_mismatch", profile.criteria)
        for key, rule in EVIDENCE_RULES.items():
            self.assertFalse({"name", "aliases", "cves", "flags"}.intersection(rule))
            if key in CHECKS:
                self.assertEqual(CHECKS[key]["ids"], rule["ids"])

    def test_arguments_are_manifest_owned_and_tampering_is_rejected(self):
        profile = get_profile(NMAP_PROFILE_ID)
        self.assertEqual(profile.arguments(TARGET, 443, []), {
            "TARGET": [TARGET], "PORT_LIST": ["443"], "SCRIPT_CMD": "ssl-enum-ciphers",
            "OPTION_PN": True, "SCRIPT_TIMEOUT": 30, "HOST_TIMEOUT": 60,
        })
        profile = get_profile(TESTSSL_PROFILE_ID)
        task = task_for(profile)
        task["claims"].extend(profile.claims("vulnerability-2", {"check_ids": ["heartbleed", "tls1_0"]}))
        task["arguments"] = profile.arguments(TARGET, 443, task["claims"])
        self.assertEqual(task["arguments"], {"CHECK_IDS": ["heartbleed", "tls1_0"]})
        self.assertIs(profile.validate_task(task), task)
        for ids in (["tls1_0"], ["heartbleed", "tls1_0", "weak_ciphers"], ["tls1_0", "heartbleed"],
                    ["heartbleed", "tls1_0", "tls1_0"], [True], ["unknown"], ("heartbleed", "tls1_0")):
            bad = copy.deepcopy(task)
            bad["arguments"]["CHECK_IDS"] = ids
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                profile.validate_task(bad)
        for field, value in (("check_id", "unknown"), ("check_id", "cert_untrusted"), ("vulnerability_id", True)):
            bad = copy.deepcopy(task)
            bad["claims"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                profile.validate_task(bad)
        task["claims"].append(task["claims"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate claim"):
            profile.validate_task(task)

    def test_task_target_and_port_stay_literal_single_ipv4_tcp(self):
        profile = get_profile(NMAP_PROFILE_ID)
        for target, port in (
            ("example.com", 443), ("192.0.2.10 ", 443), ("0.0.0.0", 443),
            ("127.0.0.1", 443), ("169.254.1.1", 443), ("224.0.0.1", 443), ("192.0.2.10", 0),
            ("192.0.2.10", 65536), ("192.0.2.10", "443"), ("2001:db8::1", 443),
        ):
            task = task_for(profile)
            task["target"], task["port"] = target, port
            task["arguments"] = {**task["arguments"], "TARGET": [target], "PORT_LIST": [str(port)]}
            with self.subTest(target=target, port=port), self.assertRaises(ValueError):
                profile.validate_task(task)

    def test_claim_count_bound_and_profile_identity_are_enforced(self):
        profile = get_profile(TESTSSL_PROFILE_ID)
        self.assertEqual(profile.limits["max_vulnerabilities"], 10000)
        task = task_for(profile)
        task["claims"] = []
        with self.assertRaisesRegex(ValueError, "Invalid claim count"):
            profile.validate_task(task)
        for field, value in (("profile_id", "other-profile"), ("executor_id", "nmap")):
            bad = {**task_for(profile), field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Unsupported executor profile"):
                profile.validate_task(bad)


if __name__ == "__main__":
    unittest.main()
