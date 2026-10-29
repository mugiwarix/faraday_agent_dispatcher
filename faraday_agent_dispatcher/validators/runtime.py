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

"""Execution hooks a dispatcher supplies to its runner, per approved profile.

A runner owns lifecycle only: authorization prompt, platform/expiry checks,
sanitized environment, bounded process group, interruption, and checkpoints. This
module owns what to run and how to read it back, following the same executor
structure as the official Faraday executors: a package-owned script driven by
``EXECUTOR_CONFIG_*`` values, or a pinned scanner binary driven by allowlisted
flags. Callers never obtain a command, flag, or import that a manifest did not
approve, and nothing here launches a process.
"""

from dataclasses import dataclass
from pathlib import Path

from . import nmap, testssl
from .limits import ProfileError

# Closed set; a dispatcher must refuse anything else rather than guess a runtime.
SUPPORTED_HANDLERS = ("nmap_tls", "testssl")
# Only the image/runner supplies the scanner path, so this package stays
# independent of any particular container or package manager.
TESTSSL_BINARY_ARGUMENT = "testssl_path"


@dataclass(frozen=True)
class Command:
    """One bounded invocation: argv plus where the scanner leaves structured output."""

    handler_id: str
    argv: tuple
    evidence_path: str = None
    environment: dict = None

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(str(argument) for argument in self.argv))
        object.__setattr__(self, "environment", dict(self.environment or ()))


def runtime_environment(profile):
    """Profile-owned environment additions; the runner keeps the base sandbox."""
    return dict(profile.runtime["environment"])


def build_command(profile, task, *, work_dir, testssl_path=None):
    """Build the only permitted invocation for one validated task."""
    if profile.handler_id == "nmap_tls":
        return Command(profile.handler_id, nmap.executor_argv(), environment=runtime_environment(profile))
    if profile.handler_id == "testssl":
        if type(testssl_path) is not str or not testssl_path:
            raise ProfileError("Pinned testssl.sh binary is unavailable to this runtime")
        evidence_path = str(Path(work_dir) / f"testssl-{task['id']}.json")
        argv = testssl.build_argv(
            testssl_path, task["target"], task["port"], task["arguments"]["CHECK_IDS"], evidence_path,
            profile=profile,
        )
        return Command(profile.handler_id, argv, evidence_path=evidence_path, environment=runtime_environment(profile))
    raise ProfileError("Unsupported executor profile")


def collect_evidence(profile, task, command):
    """Normalize scanner output into the canonical evidence record, or return None.

    ``None`` means the scanner's own stdout is the evidence, which is the case for
    the official Faraday executor that prints plugin JSON.
    """
    if command.evidence_path is None:
        return None
    if profile.handler_id != "testssl":
        raise ProfileError("Unsupported executor profile")
    from .limits import canonical_bytes

    return canonical_bytes(testssl.load_scanner_json(
        command.evidence_path, task["target"], task["port"], task["arguments"]["CHECK_IDS"], profile=profile,
    ))
