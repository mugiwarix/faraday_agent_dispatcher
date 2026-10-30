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

"""Approved validation profiles for the bundled official executors.

A profile binds one approved executor to a fixed target policy and a closed set
of evidence criteria. Manifests contain literal arguments, not templates or code,
and only the handlers below can turn a manifest into an executed command, so a new
manifest can never introduce an arbitrary command, flag set, or target selection.

This module is shared by whoever dispatches a validator job. It loads package
metadata and official executor helpers, with no scanner execution or network I/O.
"""

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .profile_limits import (
    MAX_IDENTIFIER_BYTES, ProfileError, canonical_bytes, checked_text, integer, keys,
    require, same_value, strict_json, strings, text,
)
from faraday_agent_dispatcher.static.executors.official import nmap, testssl

MANIFEST_DIRECTORY = Path(__file__).resolve().parent.parent / "static" / "manifests"
_MAX_MANIFEST_BYTES = 128 * 1024
# Handler -> executor, claim field, candidate field. No dynamic imports or paths.
_HANDLERS = {"nmap_tls": ("nmap", "protocol", "protocol"), "testssl": ("testssl", "check_id", "check_ids")}
# -U remains in historical profile ordering, but no approved check selects it.
_TESTSSL_FLAGS = frozenset(flag for check in testssl.CHECKS.values() for flag in check["flags"]) | {"-U"}
_PUBLIC_KEYS = {"id", "executor_id", "title", "description", "verdicts", "automatic_statuses", "arguments", "target"}
_MANIFEST_KEYS = _PUBLIC_KEYS | {
    "manifest_version", "handler", "success_reason", "rejection_reason", "platforms",
    "limits", "checks", "runtime", "characteristics",
}
_TARGET_POLICY = {
    "address_family": "ipv4", "transport": "tcp", "ports_per_task": 1,
    "min_port": 1, "max_port": 65535, "hostnames": False, "sni": False,
}


def _text(value):
    """Manifest strings stay non-empty, bounded, and free of control characters."""
    return text(value, nonempty=True) and printable(value)


def printable(value):
    return all(ord(char) >= 32 and ord(char) != 127 for char in value)


def _validate_manifest(data):
    require(type(data) is dict and set(data) - {"tool_version"} == _MANIFEST_KEYS)
    require(type(data["manifest_version"]) is int and data["manifest_version"] == 1)
    require(all(_text(data[key]) for key in ("id", "executor_id", "handler", "title", "description", "success_reason", "rejection_reason")))
    require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9.]+)*", data["id"]) is not None)
    require(data["handler"] in _HANDLERS and data["executor_id"] == _HANDLERS[data["handler"]][0], "Unsupported profile handler")
    require("tool_version" not in data or _text(data["tool_version"]))
    require(data["verdicts"] == ["REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"] and data["automatic_statuses"] == ["TRUE_POSITIVE"])
    require(strings(data["platforms"]) and bool(data["platforms"]) and set(data["platforms"]) <= {"linux/amd64", "linux/arm64"})
    # Global safety baseline cannot be weakened by a new manifest.
    require(same_value(data["target"], _TARGET_POLICY), "Unsupported profile target policy")
    limits = data["limits"]
    require(type(limits) is dict and set(limits) == {"max_tasks", "max_vulnerabilities"})
    require(all(type(limits[key]) is int and 1 <= limits[key] <= cap
                for key, cap in (("max_tasks", 1024), ("max_vulnerabilities", 10000))))
    require(type(data["characteristics"]) is dict and all(
        _text(key) and (type(value) in (bool, int) or _text(value)) for key, value in data["characteristics"].items()))
    runtime, arguments = data["runtime"], data["arguments"]
    require(type(runtime) is dict and set(runtime) == {"environment", "fixed_flags", "flag_order"})
    require(strings(runtime["flag_order"]) and type(arguments) is dict)
    nmap = data["handler"] == "nmap_tls"
    if nmap:
        require(set(arguments) == {"TARGET", "PORT_LIST", "SCRIPT_CMD", "OPTION_PN", "SCRIPT_TIMEOUT", "HOST_TIMEOUT"})
        require(arguments["TARGET"] == [] and arguments["PORT_LIST"] == []
                and arguments["SCRIPT_CMD"] == "ssl-enum-ciphers" and arguments["OPTION_PN"] is True)
        require(all(type(arguments[key]) is int and 1 <= arguments[key] <= 60 for key in ("SCRIPT_TIMEOUT", "HOST_TIMEOUT")))
        require(same_value(runtime, {"environment": {"NMAP_UNPRIVILEGED": "1"}, "fixed_flags": [], "flag_order": []}), "Unsafe Nmap runtime policy")
    else:
        require(same_value(arguments, {"CHECK_IDS": []}))
        # Neither omission nor later flag overrides may enable DNS/phone-home.
        require(runtime["environment"] == {"PHONE_OUT": "false"} and runtime["fixed_flags"] == [
            "--quiet", "--color", "0", "--warnings", "off", "--nodns", "none",
            "--connect-timeout", "5", "--openssl-timeout", "10",
        ] and set(runtime["flag_order"]) <= _TESTSSL_FLAGS and data.get("tool_version") == "3.2.4", "Unsafe testssl runtime policy")
    require(type(data["checks"]) is dict and bool(data["checks"]))
    for criterion, check in data["checks"].items():
        require(bool(re.fullmatch(r"TLSv1\.[01]", criterion)) if nmap else criterion in testssl.validation_check_ids(), "Unsupported profile evidence criterion")
        require(type(check) is dict and set(check) == {"name", "aliases", "cves", "flags"})
        require(_text(check["name"]) and all(strings(check[key]) for key in ("aliases", "cves", "flags")))
        require(all(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve) for cve in check["cves"]))
        require(not check["cves"] and not check["flags"] if nmap else
                set(check["flags"]) == set(testssl.validation_check(criterion)["flags"]))


@dataclass(frozen=True)
class Profile:
    id: str
    executor_id: str
    claim_field: str
    candidate_field: str
    success_reason: str
    rejection_reason: str
    metadata: dict
    platforms: tuple
    handler_id: str
    _data: dict = field(repr=False)
    _names: dict = field(default_factory=dict, init=False, repr=False)
    _cves: dict = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        for key, check in self._data["checks"].items():
            if self._supported(key):
                for name in (check["name"], *check["aliases"]):
                    self._names.setdefault(name.casefold(), set()).add(key)
                for cve in check["cves"]:
                    self._cves.setdefault(cve.casefold(), set()).add(key)

    @property
    def runtime(self):
        return copy.deepcopy(self._data["runtime"])

    @property
    def limits(self):
        return dict(self._data["limits"])

    @property
    def checks(self):
        return copy.deepcopy(self._data["checks"])

    @property
    def criteria(self):
        return tuple(sorted(key for key in self._data["checks"] if self._supported(key)))

    def _supported(self, criterion):
        return (criterion in self._data["checks"] and (self.claim_field == "protocol"
                or testssl.validation_available(criterion)))

    def match(self, name, cves=()):
        selected = set(self._names.get(str(name or "").strip().casefold(), ()))
        for cve in cves if isinstance(cves, (list, tuple, set)) else (cves,):
            selected.update(self._cves.get(str(cve).strip().casefold(), ()))
        return tuple(sorted(selected))

    def candidate_fields(self, name, cves=()):
        selected = self.match(name, cves)
        return {} if not selected else {self.candidate_field: selected[0] if self.claim_field == "protocol" else list(selected)}

    def claims(self, vulnerability_id, candidate):
        selected = candidate.get(self.candidate_field)
        selected = [selected] if self.claim_field == "protocol" else selected
        require(type(selected) in (list, tuple) and bool(selected)
                and all(type(key) is str and self._supported(key) for key in selected)
                and len(set(selected)) == len(selected), "Unsupported profile candidate")
        return [{"vulnerability_id": vulnerability_id, self.claim_field: key} for key in selected]

    def arguments(self, target, port, claims):
        arguments = copy.deepcopy(self._data["arguments"])
        if self.claim_field == "protocol":
            arguments.update(TARGET=[target], PORT_LIST=[str(port)])
        else:
            arguments["CHECK_IDS"] = sorted({claim["check_id"] for claim in claims})
        return arguments

    def validate_task(self, task):
        from .profile_limits import literal_target

        require(task["profile_id"] == self.id and task["executor_id"] == self.executor_id, "Unsupported executor profile")
        literal_target(task["target"])
        integer(task["port"], 1, 65535, "port")
        claims = task["claims"]
        require(type(claims) is list and 1 <= len(claims) <= self.limits["max_vulnerabilities"], "Invalid claim count")
        seen = set()
        for claim in claims:
            keys(claim, {"vulnerability_id", self.claim_field}, "claim")
            checked_text(claim["vulnerability_id"], MAX_IDENTIFIER_BYTES, "vulnerability id", nonempty=True)
            criterion = claim[self.claim_field]
            require(type(criterion) is str and self._supported(criterion), "Invalid profile claim")
            identity = (claim["vulnerability_id"], criterion)
            require(identity not in seen, "Duplicate claim")
            seen.add(identity)
        require(same_value(task["arguments"], self.arguments(task["target"], task["port"], claims)), "Invalid profile arguments")
        return task

    def flags_for_checks(self, check_ids):
        require(type(check_ids) in (list, tuple) and bool(check_ids), "At least one testssl check is required")
        require(all(type(key) is str and self._supported(key) for key in check_ids), "Unsupported testssl check")
        wanted = {flag for key in check_ids for flag in self._data["checks"][key]["flags"]}
        order = self._data["runtime"]["flag_order"]
        return tuple(flag for flag in order if flag in wanted) + tuple(sorted(wanted - set(order)))

    def evaluate(self, task, result):
        if self.handler_id == "nmap_tls":
            return nmap.evaluate_task(task, result)
        return testssl.evaluate_records(task, result, profile=self)


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate profile manifest key")
        result[key] = value
    return result


def load_profiles(directory=MANIFEST_DIRECTORY):
    """Load validation_profiles lists inside official executor manifests.

    Directory is package-owned, never task input. Other executor metadata is
    ignored; only the closed handler set can produce an approved invocation.
    """
    loaded = {}
    try:
        paths = sorted(Path(directory).glob("*.json"))
        require(1 <= len(paths) <= 1024, "Invalid executor manifest count")
        for path in paths:
            require(not path.is_symlink() and path.is_file() and path.stat().st_size <= _MAX_MANIFEST_BYTES)
            with path.open("rb") as stream:
                raw = stream.read(_MAX_MANIFEST_BYTES + 1)
            require(0 < len(raw) <= _MAX_MANIFEST_BYTES)
            manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_pairs,
                                  parse_constant=lambda _value: (_ for _ in ()).throw(ProfileError("Invalid profile JSON constant")))
            require(type(manifest) is dict, "Invalid executor manifest")
            entries = manifest.get("validation_profiles", [])
            require(type(entries) is list and len(entries) <= 128, "Invalid validation profiles")
            for data in entries:
                _validate_manifest(data)
                require(manifest.get("name") == data["executor_id"], "Profile executor mismatch")
                require(data["id"] not in loaded, "Duplicate profile id")
                require(len(loaded) < 128, "Invalid profile manifest count")
                executor, claim, candidate = _HANDLERS[data["handler"]]
                metadata = copy.deepcopy({key: data[key] for key in _PUBLIC_KEYS})
                metadata.update(tool_version=data.get("tool_version", ""), options=copy.deepcopy({
                    "characteristics": data["characteristics"], "checks": data["checks"],
                }))
                loaded[data["id"]] = Profile(data["id"], executor, claim, candidate, data["success_reason"],
                                             data["rejection_reason"], metadata, tuple(data["platforms"]), data["handler"], data)
        require(bool(loaded), "No validation profiles")
    except (OSError, UnicodeError, TypeError, RecursionError, OverflowError) as exc:
        raise ProfileError("Invalid profile manifest") from exc
    return dict(sorted(loaded.items()))


_PROFILES = load_profiles(MANIFEST_DIRECTORY)


def profiles():
    return dict(_PROFILES)


def get_profile(profile_id):
    require(type(profile_id) is str and profile_id in _PROFILES, "Unsupported executor profile")
    return _PROFILES[profile_id]


def profile_for_handler(handler_id):
    """Handlers source their IDs and settings from the registry, never constants."""
    for profile in _PROFILES.values():
        if profile.handler_id == handler_id:
            return profile
    raise ProfileError("Unsupported profile handler")


SUPPORTED_HANDLERS = tuple(_HANDLERS)


@dataclass(frozen=True)
class Command:
    """Official executor invocation; stdout contains all validation evidence."""

    handler_id: str
    argv: tuple
    environment: dict = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "environment", dict(self.environment))


def build_command(profile, task, *, work_dir=None):
    """Preflight one task without I/O to targets; paths come only from the image.

    Runner supplies a sanitized task environment and merges command.environment.
    work_dir remains part of the runner API; evidence files are executor-private.
    """
    require(profile.handler_id in SUPPORTED_HANDLERS, "Unsupported executor profile")
    require(get_profile(profile.id) is profile, "Unsupported executor profile")
    profile.validate_task(task)
    if profile.handler_id == "nmap_tls":
        return Command(profile.handler_id, nmap.executor_argv(),
                       {**profile.runtime["environment"], "FAD_VALIDATION_MODE": "1"})
    return Command(profile.handler_id, testssl.executor_argv(), testssl.validation_environment(profile, task))
