# -*- coding: utf-8 -*-

# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

"""Pinned testssl.sh profile: manifest metadata plus trusted Python evidence.

No scanner, network, or application imports. The manifest supplies declarative
metadata; upstream evidence IDs, patterns, and availability gates stay trusted
Python so a shipped data file can never widen what counts as a finding.
"""

import json
import re

from .limits import ProfileError, strict_json
from .registry import profile_for_handler
from .rules import EVIDENCE_RULES

EVIDENCE_FORMAT = "porco.testssl-evidence.v1"
MAX_SCANNER_JSON_BYTES = 262144
_ACTIONABLE = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_SAFE_KEMS = re.compile(r"ML-?KEM|P256MLKEM|X25519MLKEM|X448MLKEM", re.IGNORECASE)


def _profile(profile=None):
    return profile_for_handler("testssl") if profile is None else profile


def check_ids_for_vulnerability(name, cves=(), *, profile=None):
    """Exact-name/CVE matching only; no category, description, or fuzzy matching."""
    return _profile(profile).match(name, cves)


def flags_for_checks(check_ids, *, profile=None):
    return _profile(profile).flags_for_checks(check_ids)


def task_arguments(target, port, check_ids, *, profile=None):
    return _profile(profile).arguments(target, port, [{"check_id": key} for key in check_ids])


def build_argv(binary, target, port, check_ids, output_path, *, profile=None):
    profile = _profile(profile)
    flags = profile.flags_for_checks(check_ids)
    return [
        binary, *profile.runtime["fixed_flags"], *flags,
        "--jsonfile", str(output_path), "--overwrite", f"{target}:{port}",
    ]


def _reported_target_matches(value, target):
    # testssl.sh 3.2.4 JSON writes `NODE/NODEIP`; for literal IPv4 scope both
    # components must remain the approved address. Some compatible outputs use
    # the bare address, which is equally unambiguous.
    return type(value) is str and value in (target, f"{target}/{target}")


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError("Duplicate JSON key")
        result[key] = value
    return result


def load_scanner_json(path, target, port, check_ids, *, profile=None):
    """Strictly read bounded flat testssl output and keep only approved check IDs."""
    import os
    import stat

    profile = _profile(profile)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SCANNER_JSON_BYTES:
            raise ProfileError("Invalid testssl output file")
        raw = stream.read(MAX_SCANNER_JSON_BYTES + 1)
    if not raw or len(raw) > MAX_SCANNER_JSON_BYTES:
        raise ProfileError("Invalid testssl output size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ProfileError("Invalid JSON constant")))
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise ProfileError("Invalid testssl JSON") from exc
    if type(data) is not list or len(data) > 2048:
        raise ProfileError("Invalid testssl JSON records")
    profile.flags_for_checks(check_ids)
    wanted_ids = {finding_id for key in check_ids for finding_id in EVIDENCE_RULES[key]["ids"]}
    records = []
    for item in data:
        if type(item) is not dict:
            raise ProfileError("Invalid testssl vulnerability")
        finding_id = item.get("id")
        if finding_id not in wanted_ids and finding_id != "service":
            continue
        finding = item.get("finding")
        severity = item.get("severity")
        if type(finding) is not str or len(finding.encode("utf-8")) > 8192:
            raise ProfileError("Invalid testssl finding text")
        if type(severity) is not str or len(severity) > 32:
            raise ProfileError("Invalid testssl severity")
        if not _reported_target_matches(item.get("ip"), target) or str(item.get("port")) != str(port):
            raise ProfileError("testssl output endpoint mismatch")
        records.append({"id": finding_id, "severity": severity.upper(), "finding": finding,
                        "ip": target, "port": port})
    return {"format": EVIDENCE_FORMAT, "profile_id": profile.id, "tool_version": profile.metadata["tool_version"],
            "target": target, "port": port, "check_ids": sorted(set(check_ids)), "records": records}


def positive_record(check_id, record):
    """Return true only for direct, check-specific positive evidence."""
    check = EVIDENCE_RULES[check_id]
    text = record["finding"]
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in check["exclude"]):
        return False
    if check_id == "cert_weak_key":
        match = re.search(r"\bRSA\s+(\d{2,5})\s*bits\b", text, re.IGNORECASE)
        return bool(match and int(match.group(1)) < 2048 and record["severity"] in _ACTIONABLE)
    if check.get("absence"):
        if _SAFE_KEMS.search(text) or record["severity"] not in _ACTIONABLE | {"OK"}:
            return False
        if check_id == "post_quantum_kex" and record["id"] == "FS_KEMs" and text.strip() == "-":
            return True
        return bool(re.search(r"none|no |not offered|not supported|unavailable", text, re.IGNORECASE))
    if check_id == "hsts":
        return bool(
            record["severity"] in _ACTIONABLE | {"OK"}
            and re.search(r"\bhttps?\b", record.get("service", ""), re.IGNORECASE)
            and any(re.search(pattern, text, re.IGNORECASE) for pattern in check["require"])
        )
    if check_id == "tls_fallback":
        return bool(re.search(r"not supported", text, re.IGNORECASE))
    if check.get("require") and not any(re.search(pattern, text, re.IGNORECASE) for pattern in check["require"]):
        return False
    if check.get("http") and not re.search(r"\bhttps?\b", record.get("service", ""), re.IGNORECASE):
        return False
    return record["severity"] in _ACTIONABLE


def evaluate_records(task, result, *, profile=None):
    """Map complete, strictly-bound scanner records to positive/non-positive outcomes."""
    profile = _profile(profile)
    if result["state"] != "COMPLETED":
        return {}, "INCONCLUSIVE", "TASK_NOT_COMPLETED"
    try:
        evidence = strict_json(result["stdout"].encode("utf-8"))
        if (type(evidence) is not dict or set(evidence) != {"format", "profile_id", "tool_version", "target", "port", "check_ids", "records"}
                or evidence["format"] != EVIDENCE_FORMAT or evidence["profile_id"] != profile.id
                or evidence["tool_version"] != profile.metadata["tool_version"] or evidence["target"] != task["target"]
                or evidence["port"] != task["port"] or evidence["check_ids"] != task["arguments"]["CHECK_IDS"]
                or type(evidence["records"]) is not list):
            return {}, "INCONCLUSIVE", "INVALID_TESTSSL_EVIDENCE"
        records_by_id = {}
        service_text = " ".join(item["finding"] for item in evidence["records"] if item.get("id") == "service")
        for item in evidence["records"]:
            if type(item) is not dict or set(item) != {"id", "severity", "finding", "ip", "port"}:
                return {}, "INCONCLUSIVE", "INVALID_TESTSSL_EVIDENCE"
            if item["ip"] != task["target"] or item["port"] != task["port"]:
                return {}, "INCONCLUSIVE", "TESTSSL_TARGET_MISMATCH"
            records_by_id.setdefault(item["id"], []).append({**item, "service": service_text})
        observed = {}
        for check_id in task["arguments"]["CHECK_IDS"]:
            check = EVIDENCE_RULES[check_id]
            matching = [record for finding_id in check["ids"] for record in records_by_id.get(finding_id, ())]
            if any(positive_record(check_id, record) for record in matching):
                observed[check_id] = "REPRODUCED"
            elif matching and all(record["severity"] == "OK" for record in matching):
                # A complete explicit OK is current non-reproduction only. It never
                # proves the imported historical vulnerability false or changes status.
                observed[check_id] = "NOT_REPRODUCED"
        return observed, "INCONCLUSIVE", "NO_COMPLETE_CHECK_EVIDENCE"
    except (KeyError, TypeError, ValueError, RecursionError):
        return {}, "INCONCLUSIVE", "INVALID_TESTSSL_EVIDENCE"


def _load_checks():
    """Compatibility view: metadata comes from JSON, evidence rules stay Python."""
    profile = _profile()
    return {
        key: {**{field: tuple(value) if type(value) is list else value
                 for field, value in metadata.items()}, **EVIDENCE_RULES[key]}
        for key, metadata in profile.checks.items()
    }


def _load_indexes(checks):
    names, cves = {}, {}
    for check_id, check in checks.items():
        for title in (check["name"], *check.get("aliases", ())):
            names.setdefault(title.casefold(), []).append(check_id)
        for cve in check["cves"]:
            cves.setdefault(cve.casefold(), []).append(check_id)
    return names, cves


CHECKS = _load_checks()
NAME_INDEX, CVE_INDEX = _load_indexes(CHECKS)
PROFILE_ID = _profile().id
TOOL_VERSION = _profile().metadata["tool_version"]
