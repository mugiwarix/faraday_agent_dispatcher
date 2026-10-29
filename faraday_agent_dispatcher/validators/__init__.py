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

"""Validator profiles owned by the Faraday dispatcher.

Each profile binds one approved executor to a fixed target policy, a closed set of
evidence criteria, and the exact command that may run. Dispatching applications may
reuse these profiles and these execution hooks; they must not maintain a parallel
copy of scanner knowledge. Nothing in this package launches a process, resolves a
hostname, reads a database, or imports an application.
"""

from .limits import ProfileError, canonical_bytes, strict_json
from .registry import (
    MANIFEST_DIRECTORY, Profile, get_profile, load_profiles, profile_for_handler, profiles,
)
from .rules import EVIDENCE_RULES
from .runtime import SUPPORTED_HANDLERS, Command, build_command, collect_evidence, runtime_environment

__all__ = [
    "Command", "EVIDENCE_RULES", "MANIFEST_DIRECTORY", "Profile", "ProfileError",
    "SUPPORTED_HANDLERS", "build_command", "canonical_bytes", "collect_evidence",
    "get_profile", "load_profiles", "profile_for_handler", "profiles",
    "runtime_environment", "strict_json",
]
