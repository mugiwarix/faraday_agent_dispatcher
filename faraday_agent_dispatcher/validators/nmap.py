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

"""Approved Nmap profile: official dispatcher executor plus strict evidence rules.

The command is the packaged official Nmap executor driven only by the
``EXECUTOR_CONFIG_*`` values a validated profile produced. Evidence is untrusted
scanner output: it can confirm a protocol, never disprove a stored finding.
"""

import re

from .limits import strict_json

SCRIPT_NAME = "ssl-enum-ciphers"


def nmap_executor_script():
    """Absolute path of the packaged official executor, or raise."""
    from pathlib import Path

    script = Path(__file__).resolve().parent.parent / "static" / "executors" / "official" / "nmap.py"
    if not script.is_file():
        raise FileNotFoundError(str(script))
    return str(script)


def executor_argv():
    import sys

    return [sys.executable, nmap_executor_script()]


def protocol_sections(description):
    """Recognize Nmap's indented protocol -> ciphers -> negotiated cipher rows."""
    if not isinstance(description, str):
        return set()
    protocols, seen = set(), set()
    current, ciphers = None, False
    for line in description.splitlines():
        header = re.fullmatch(r"  (TLSv1\.[0-3]|SSLv[23]):[ \t]*", line)
        if header:
            current, ciphers = header[1], False
            if current in seen:
                return set()
            seen.add(current)
        elif line == "    ciphers:" and current:
            ciphers = True
        elif ciphers and current and re.fullmatch(
            r"      (?:TLS|SSL)_[A-Z0-9_]+(?: \([^()\r\n]+\))? - [A-F]", line,
        ):
            protocols.add(current)
        elif line.strip() and len(line) - len(line.lstrip(" ")) < 6:
            ciphers = False
            if len(line) - len(line.lstrip(" ")) <= 2:
                current = None
    return protocols


# Historical name kept for callers that treat this parser as private API.
_protocol_sections = protocol_sections


def evaluate_task(task, result):
    """Untrusted offline evidence is not runner attestation; never produces FP."""
    if result["state"] != "COMPLETED":
        return {}, "INCONCLUSIVE", "TASK_NOT_COMPLETED"
    try:
        lines = [line for line in result["stdout"].splitlines() if line.strip()]
        if not lines:
            return {}, "INCONCLUSIVE", "NO_STRUCTURED_OUTPUT"
        services = []
        for line in lines:
            report = strict_json(line.encode("utf-8"))
            if not isinstance(report, dict) or not isinstance(report.get("hosts"), list):
                return {}, "INCONCLUSIVE", "INVALID_FARADAY_OUTPUT"
            for host in report["hosts"]:
                if not isinstance(host, dict) or host.get("ip") != task["target"]:
                    return {}, "INCONCLUSIVE", "TARGET_MISMATCH"
                host_services = host.get("services")
                if not isinstance(host_services, list):
                    return {}, "INCONCLUSIVE", "INVALID_SERVICE_OUTPUT"
                for service in host_services:
                    if (not isinstance(service, dict) or type(service.get("port")) is not int
                            or service["port"] != task["port"] or service.get("protocol") != "tcp"):
                        return {}, "INCONCLUSIVE", "SERVICE_MISMATCH"
                    services.append(service)
        if len(services) != 1:
            return {}, "INCONCLUSIVE", "AMBIGUOUS_OR_MISSING_SERVICE"
        service = services[0]
        if service.get("status") != "open":
            return {}, "NOT_REPRODUCED", "SERVICE_NOT_OPEN"
        vulnerabilities = service.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or any(not isinstance(item, dict) for item in vulnerabilities):
            return {}, "INCONCLUSIVE", "INVALID_SCRIPT_OUTPUT"
        scripts = [item for item in vulnerabilities if item.get("name") == SCRIPT_NAME]
        if len(scripts) != 1:
            return {}, "INCONCLUSIVE", "MISSING_OR_AMBIGUOUS_SCRIPT"
        protocols = protocol_sections(scripts[0].get("desc"))
        if not protocols:
            return {}, "INCONCLUSIVE", "NO_PROTOCOL_CIPHER_EVIDENCE"
        return {protocol: "REPRODUCED" for protocol in protocols}, "NOT_REPRODUCED", "PROTOCOL_NOT_OBSERVED"
    except (ValueError, TypeError, RecursionError):
        return {}, "INCONCLUSIVE", "INVALID_FARADAY_OUTPUT"
