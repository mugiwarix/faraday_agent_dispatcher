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

"""Bounded input guards for validator profiles and scanner evidence.

Validator support must never import the application that dispatches it, so these
primitives are deliberately self-contained. They guard profile manifests, task
bindings, and untrusted scanner output only; the dispatching application keeps its
own plan/result envelope checks.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re

MAX_TEXT_BYTES = 4096
MAX_IDENTIFIER_BYTES = 1024
MAX_EVIDENCE_BYTES = 32768
MAX_PORT = 65535

_HEX_RE = re.compile(r"[0-9a-f]+")


class ProfileError(ValueError):
    """Safe profile-facing failure; never includes scanner output."""


def require(condition, message="Invalid validator profile"):
    if not condition:
        raise ProfileError(message)


def text(value, limit=MAX_TEXT_BYTES, name="value", nonempty=False):
    if type(value) is not str:
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        return False
    return bool(size <= limit) and (not nonempty or bool(value.strip()))


def printable_text(value, limit=MAX_TEXT_BYTES):
    """Manifest text stays single-line, printable, and bounded."""
    if not text(value, limit):
        return False
    return bool(value.strip()) and all(ord(char) >= 32 and ord(char) != 127 for char in value)


def strings(value):
    return type(value) is list and all(printable_text(item) for item in value) and len(set(value)) == len(value)


def checked_text(value, limit, name, nonempty=False):
    if not text(value, limit, name, nonempty=nonempty):
        raise ProfileError(f"Invalid {name}")


def integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProfileError(f"Invalid {name}")


def keys(value, expected, name):
    if type(value) is not dict or set(value) != expected:
        raise ProfileError(f"Invalid {name} fields")


def hex_string(value, length, name):
    if type(value) is not str or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ProfileError(f"Invalid {name}")


def same_value(actual, expected):
    """Equality alone accepts bool/int and int/float argument tampering."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(same_value(actual[key], value) for key, value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(same_value(a, b) for a, b in zip(actual, expected))
    return actual == expected


def literal_target(target):
    """Approved validator scope: canonical IPv4 unicast, including private networks.

    Hostnames are never resolved here: a profile task is an address plus one TCP
    port, so no code path in this package can widen a job to a name or a range.
    """
    if type(target) is not str or len(target) > 15:
        raise ProfileError("Invalid target")
    try:
        address = ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError:
        raise ProfileError("Invalid target") from None
    if (
        str(address) != target or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_unspecified or address.is_reserved
        or address.packed[0] == 0
    ):
        raise ProfileError("Invalid target")
    return target


def strict_json(payload, limit=MAX_EVIDENCE_BYTES):
    """Parse bounded evidence JSON without duplicate keys or non-finite numbers."""
    if type(payload) is not bytes or not payload or len(payload) > limit:
        raise ProfileError("Invalid evidence size")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProfileError("Duplicate JSON key")
            result[key] = value
        return result

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ProfileError("Non-finite JSON number")
        return parsed

    try:
        return json.loads(
            payload.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ProfileError("Non-finite JSON number")),
            parse_float=finite_float,
        )
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise ProfileError("Invalid evidence JSON") from exc


def canonical_bytes(value):
    """Canonical compact JSON, matching the plan/result encoding."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ProfileError("Invalid JSON value") from exc
