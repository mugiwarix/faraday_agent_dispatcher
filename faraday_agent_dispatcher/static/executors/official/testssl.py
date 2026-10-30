#!/usr/bin/env python3
"""TestSSL executor: SSL/TLS checks for the Faraday/Porco issue catalog.

Wraps ``testssl.sh`` (https://testssl.sh). One scan is run per target with the
test flags needed by the selected checks, and the actionable findings are turned
into Faraday vulnerabilities whose names track the Nessus findings the issue
catalog expects (``SSL/TLS Multiple Issues``, ``Weak Cryptography``, ...).

The scan is scoped by ``TESTSSL_VULN``: a list (or comma separated string) of
issue names, check names, CVE ids or Nessus plugin ids. The available names are
the keys of ``CHECKS`` below; an empty value means "run every SSL/TLS check".
The manifest ships the argument documentation; the equivalent agent config is:

    [testssl]
    repo_executor = testssl.py
    max_size = 262144

    [testssl_varenvs]
    TESTSSL_PATH = /usr/local/bin/testssl.sh

    [testssl_params]
    TESTSSL_TARGET: 10.0.0.5:44330
    TESTSSL_PORTS: 443, 8443
    TESTSSL_VULN: SSL/TLS Multiple Issues, heartbleed, 94437
    TESTSSL_NODNS: min

Requires ``testssl.sh`` (and ``openssl``) on the dispatcher host; nothing else is
executed. Everything the tool prints goes to stderr, only the Faraday JSON line
is written to stdout.
"""

import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from faraday_agent_dispatcher.utils import arg_helpers
from faraday_agent_dispatcher.utils.agent_configuration import get_common_parameters

TOOL = "testssl.sh"
EXECUTOR = "testssl"

# Issues of the Porco catalog this executor feeds. Names must match issues.yaml.
ISSUE_SSL_TLS = "SSL/TLS Multiple Issues"
ISSUE_WEAK_CRYPTO = "Weak Cryptography"
ISSUE_SERVER_CONFIG = "Insecure Server Configuration"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Only these testssl.sh severities describe something worth reporting. INFO/OK/
# WARN/PROMPT/SPECIAL/ERROR are tool chatter or analysis problems.
TESTSSL_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

VALID_STARTTLS = frozenset(
    [
        "ftp",
        "smtp",
        "lmtp",
        "pop3",
        "imap",
        "xmpp",
        "xmpp-server",
        "telnet",
        "ldap",
        "nntp",
        "sieve",
        "postgres",
        "mysql",
    ]
)

# testssl.sh finding ids that are bookkeeping, not evidence.
IGNORED_IDS = frozenset(["engine_problem", "scanTime"])

# Every check declares: the Faraday vulnerability name, the testssl.sh finding ids
# that prove it, the test flags that produce those ids, and how to report it.
#   require  : at least one regex must match the finding text
#   exclude  : no regex may match the finding text
#   severity : fixed severity. Without it only actionable testssl.sh severities
#              (LOW..CRITICAL) are reported, using the tool's own rating.
#   mode     : "absent" reports the finding when the safe pattern is *missing*
#   http     : only meaningful for services testssl.sh saw answering HTTP
CHECKS = {
    # -- deprecated protocols -------------------------------------------------
    "sslv2": {
        "name": "SSL Version 2 and 3 Protocol Detection",
        "ids": ["SSLv2"],
        "flags": ["-p"],
        "require": [r"(?<!not )\boffered\b"],
        "severity": "critical",
        "nessus": [20007, 132634],
        "tags": ["protocol"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable SSLv2 on the service.",
    },
    "sslv3": {
        "name": "SSL Version 2 and 3 Protocol Detection",
        "ids": ["SSLv3"],
        "flags": ["-p"],
        "require": [r"(?<!not )\boffered\b"],
        "severity": "critical",
        "nessus": [20007],
        "tags": ["protocol"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable SSLv3 on the service.",
    },
    "tls1_0": {
        "name": "TLS Version 1.0 Deprecated Protocol",
        "ids": ["TLS1"],
        "flags": ["-p"],
        "severity": "medium",
        "require": [r"(?<!not )\boffered\b"],
        "refs": ["RFC 8996"],
        "tags": ["protocol"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable TLS 1.0 and require TLS 1.2 or higher.",
    },
    "tls1_1": {
        "name": "TLS Version 1.1 Deprecated Protocol",
        "ids": ["TLS1_1"],
        "flags": ["-p"],
        "severity": "medium",
        "require": [r"(?<!not )\boffered\b"],
        "refs": ["RFC 8996"],
        "nessus": [157288],
        "tags": ["protocol"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable TLS 1.1 and require TLS 1.2 or higher.",
    },
    # -- weak cipher suites ---------------------------------------------------
    "anon_ciphers": {
        "name": "SSL Anonymous Cipher Suites Supported",
        "ids": ["cipherlist_aNULL", "cipherlist_NULL"],
        "flags": ["-s"],
        "severity": "high",
        "require": [r"(?<!not )\boffered\b"],
        "nessus": [31705],
        "tags": ["cipher"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Remove anonymous and unauthenticated cipher suites from the server configuration.",
    },
    "weak_ciphers": {
        "name": "SSL Weak Cipher Suites Supported",
        "ids": ["cipherlist_LOW", "cipherlist_OBSOLETED", "cipherlist_EXPORT"],
        "flags": ["-s"],
        "severity": "medium",
        "require": [r"(?<!not )\boffered\b"],
        "nessus": [26928],
        "tags": ["cipher"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Restrict the cipher list to modern, forward-secret AEAD suites.",
    },
    "sweet32": {
        "name": "SSL 64-bit Block Size Cipher Suites Supported (SWEET32)",
        "ids": ["SWEET32", "cipherlist_3DES_IDEA"],
        "flags": ["-W", "-s"],
        "severity": "high",
        "require": [r"vulnerab|(?<!not )\boffered\b"],
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2016-2183", "CVE-2016-6329"],
        "nessus": [94437, 42873],
        "tags": ["cipher", "attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable 64-bit block ciphers (3DES, IDEA, RC2) and prefer AES-GCM suites.",
    },
    "rc4": {
        "name": "SSL RC4 Cipher Suites Supported (Bar Mitzvah)",
        "ids": ["RC4"],
        "flags": ["-4"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2013-2566", "CVE-2015-2808"],
        "nessus": [65821],
        "tags": ["cipher", "attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable every RC4 cipher suite.",
    },
    "cbc_ciphers": {
        "name": "SSL Cipher Block Chaining Cipher Suites Supported",
        "ids": ["LUCKY13"],
        "flags": ["-L"],
        "severity": "medium",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2013-0169", "CVE-2014-3568"],
        "nessus": [70544],
        "tags": ["cipher", "attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Prefer AEAD (AES-GCM/ChaCha20-Poly1305) suites over CBC-MAC suites.",
    },
    "weak_dh": {
        "name": "SSL Server Accepts Weak Diffie-Hellman Keys",
        "ids": ["LOGJAM-common_primes"],
        "flags": ["-J"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "nessus": [53360, 83875],
        "tags": ["cipher"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Use 2048-bit or larger DH groups (RFC 5114 group 14 or newer) or ECDHE only.",
    },
    # -- named attacks --------------------------------------------------------
    "heartbleed": {
        "name": "OpenSSL Heartbeat Information Disclosure (Heartbleed)",
        "ids": ["heartbleed"],
        "flags": ["-H"],
        "severity": "critical",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2014-0160"],
        "nessus": [73412],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Upgrade OpenSSL and restart every service linked against it.",
    },
    "ccs_injection": {
        "name": "OpenSSL ChangeCipherSpec Injection",
        "ids": ["CCS"],
        "flags": ["-I"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2014-0224"],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Patch OpenSSL to 1.0.1h or later and restart the service.",
    },
    "ticketbleed": {
        "name": "F5 BIG-IP Session Ticket Memory Disclosure (Ticketbleed)",
        "ids": ["ticketbleed"],
        "flags": ["-T"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "refs": ["https://ticketbleed.com"],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Patch the BIG-IP/Traffic Manager and rotate the ssl profile session-ticket keys.",
    },
    "robot": {
        "name": "Return of Bleichenbacher's Oracle Threat (ROBOT)",
        "ids": ["ROBOT"],
        "flags": ["--robot"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "refs": ["https://robotattack.org"],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable RSA key-exchange ciphers and patch the TLS stack.",
    },
    "renegotiation": {
        "name": "SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection",
        # secure_client_renego is CVE-2011-1473 DoS, not MiTM injection.
        "ids": ["secure_renego"],
        "flags": ["-R"],
        "severity": "medium",
        "require": [r"vulnerab|not supported|insecure|^accepted"],
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2009-3555"],
        "nessus": [42880],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Support TLS renegotiation indication (RFC 5746) or disable renegotiation.",
    },
    "crime": {
        "name": "SSL Compression Methods Supported (CRIME)",
        "ids": ["CRIME_TLS"],
        "flags": ["-C"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2012-4929"],
        "nessus": [62563],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable TLS-level compression.",
    },
    "breach": {
        "name": "HTTP Compression Over TLS Vulnerability (BREACH)",
        "ids": ["BREACH"],
        "flags": ["-B"],
        "severity": "medium",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2013-3587"],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable HTTP compression or mitigate per-request tokenization.",
    },
    "poodle": {
        "name": "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
        "ids": ["POODLE_SSL"],
        "flags": ["-O"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2014-3566"],
        "nessus": [78479],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable SSLv3 on the service.",
    },
    "tls_fallback": {
        "name": "TLS_FALLBACK_SCSV Downgrade Protection Not Supported",
        "ids": ["fallback_SCSV"],
        "flags": ["-Z"],
        "require": [r"not supported"],
        "severity": "info",
        "refs": ["RFC 7507"],
        "tags": ["protocol"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Upgrade the TLS stack so it honours TLS_FALLBACK_SCSV.",
    },
    "freak": {
        "name": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
        "ids": ["FREAK"],
        "flags": ["-F"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2015-0204"],
        "nessus": [81606],
        "tags": ["attack", "cipher"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Remove EXPORT cipher suites and patch the TLS stack.",
    },
    "logjam": {
        "name": "SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)",
        "ids": ["LOGJAM"],
        "flags": ["-J"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2015-4000"],
        "nessus": [83738],
        "tags": ["attack", "cipher"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Remove EXPORT ciphers and stop using export-grade or < 2048-bit DH parameters.",
    },
    "drown": {
        "name": "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)",
        "ids": ["DROWN"],
        "flags": ["-D"],
        "severity": "high",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2016-0800"],
        "nessus": [89058],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Disable SSLv2 everywhere, including every host reusing this private key.",
    },
    "beast": {
        "name": (
            "SSL/TLS Protocol Initialization Vector Implementation Information " "Disclosure Vulnerability (BEAST)"
        ),
        "ids": ["BEAST", "BEAST_CBC_TLS1", "BEAST_CBC_SSL3"],
        "flags": ["-A"],
        "severity": "medium",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2011-3389"],
        "nessus": [58751],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Prefer TLS 1.1+ and AEAD ciphers; disable CBC suites for legacy protocols.",
    },
    "winshock": {
        "name": "Microsoft Windows Schannel Remote Code Execution Vulnerability (WinShock)",
        "ids": ["winshock"],
        "flags": ["--winshock"],
        "severity": "critical",
        "exclude": [r"not vulnerable"],
        "cve": ["CVE-2014-6321"],
        "refs": ["MS14-066"],
        "tags": ["attack"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Apply the MS14-066 security update.",
    },
    # -- certificate ----------------------------------------------------------
    "cert_expired": {
        "name": "SSL Certificate Expiry",
        "ids": ["cert_expirationStatus", "cert_notAfter"],
        "flags": ["-S"],
        "require": [r"expired|expires <"],
        "nessus": [15901],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Replace the certificate before it expires.",
    },
    "cert_self_signed": {
        "name": "SSL Self-Signed Certificate",
        "ids": ["cert_chain_of_trust"],
        "flags": ["-S"],
        "severity": "high",
        "require": [r"self[- ]signed"],
        "nessus": [57582],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Serve a certificate issued by a CA the clients trust, with the full chain.",
    },
    "cert_untrusted": {
        "name": "SSL Certificate Cannot Be Trusted",
        "ids": ["cert_chain_of_trust", "cert_trust"],
        "flags": ["-S"],
        "severity": "medium",
        "require": [r"failed|can'?t be verified|cannot be verified|incomplete"],
        "exclude": [r"self[- ]signed|does not match"],
        "nessus": [51192],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Install the missing intermediate certificates or reissue the leaf certificate.",
    },
    "cert_cn_mismatch": {
        "name": "SSL Certificate 'commonName' Mismatch",
        "ids": ["cert_trust"],
        "flags": ["-S"],
        "severity": "medium",
        "require": [r"does not match|wrong host"],
        "nessus": [45410, 45411],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Issue the certificate for the hostname the clients actually use (SAN/CN).",
    },
    "cert_no_subject": {
        "name": "SSL Certificate with no Common Name",
        "ids": ["cert_commonName"],
        "flags": ["-S"],
        "require": [r"no cn|no subject|not set|subject empty|empty subject|field in subject"],
        "severity": "medium",
        "nessus": [159544, 159545],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Reissue the certificate with a proper subject and subjectAltName.",
    },
    "cert_no_san": {
        "name": "SSL Certificate without subjectAltName",
        "ids": ["cert_subjectAltName"],
        "flags": ["-S"],
        "require": [r"no san"],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Reissue the certificate with a subjectAltName covering every served name.",
    },
    "cert_weak_hash": {
        "name": "SSL Certificate Signed Using Weak Hashing Algorithm",
        "ids": ["cert_signatureAlgorithm"],
        "flags": ["-S"],
        "severity": "high",
        "require": [r"\bMD[245]\b|SHA-?1\b"],
        "nessus": [35291, 95631, 86067],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Reissue the certificate signed with SHA-256 or better.",
    },
    "cert_weak_key": {
        "name": "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits",
        "ids": ["cert_keySize"],
        "flags": ["-S"],
        "require": [r"\b\d{2,4}\s*bits\b"],
        "nessus": [69551, 60108],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Rekey the certificate with a 2048-bit RSA key or an EC key.",
    },
    "cert_chain_unsorted": {
        "name": "SSL Certificate Chain Not Sorted",
        "ids": ["certs_list_ordering_problem"],
        "flags": ["-S"],
        "severity": "low",
        "require": [r"^yes"],
        "nessus": [56471],
        "tags": ["certificate"],
        "issue": ISSUE_SSL_TLS,
        "resolution": "Send the chain ordered leaf-first without the trust-anchor root.",
    },
    # -- transport hardening --------------------------------------------------
    "hsts": {
        # Inverse logic on purpose: for HSTS the testssl.sh finding "not offered"
        # is the problem, so the check names its own severity.
        "name": "HSTS Missing From HTTPS Server",
        "ids": ["HSTS"],
        "flags": ["-h"],
        "require": [r"not offered"],
        "severity": "low",
        "http": True,
        "nessus": [42823, 84502, 142960],
        "tags": ["protocol"],
        "issue": ISSUE_SERVER_CONFIG,
        "resolution": "Serve Strict-Transport-Security with a max-age of at least six months.",
    },
    "post_quantum_kex": {
        "name": "Remote Services Not Using Post-Quantum Ciphers",
        "ids": ["FS_KEMs", "FS_ciphers"],
        "flags": ["-f"],
        "require": [r"ML-?KEM|P256MLKEM|X25519MLKEM|X448MLKEM"],
        "mode": "absent",
        "severity": "info",
        "nessus": [277650, 277654],
        "tags": ["cipher"],
        "issue": ISSUE_WEAK_CRYPTO,
        "resolution": (
            "Enable a hybrid post-quantum key exchange (e.g. X25519MLKEM768) so recorded "
            "traffic cannot be decrypted later (harvest-now-decrypt-later)."
        ),
    },
}

# Informational findings, only reported when TESTSSL_INCLUDE_INFO is on.
INFO_CHECKS = {
    "SSL/TLS Versions Supported": ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"],
    "SSL Cipher Suites Supported": [
        "cipherlist_NULL",
        "cipherlist_aNULL",
        "cipherlist_EXPORT",
        "cipherlist_LOW",
        "cipherlist_3DES_IDEA",
        "cipherlist_OBSOLETED",
        "cipherlist_STRONG_NOFS",
        "cipherlist_STRONG_FS",
    ],
    "Perfect Forward Secrecy Supported": ["FS", "FS_ciphers", "FS_KEMs"],
    "SSL Certificate Information": [
        "cert_commonName",
        "cert_subjectAltName",
        "cert_issuer",
        "cert_signatureAlgorithm",
        "cert_keySize",
        "cert_notAfter",
    ],
    "SSL/TLS Overall Grade": ["overall_grade", "grade_cap_reason_1", "grade_cap_reason_2"],
}

# Group tokens accepted by the VULN argument.
GROUP_ALIASES = {
    "all": None,  # None -> every check
    "everything": None,
    "ssl": None,
    "ssl/tls": None,
    "tls": None,
    "cert": "certificate",
    "certificate": "certificate",
    "certificates": "certificate",
    "cipher": "cipher",
    "ciphers": "cipher",
    "ciphersuite": "cipher",
    "ciphersuites": "cipher",
    "protocol": "protocol",
    "protocols": "protocol",
    "attack": "attack",
    "attacks": "attack",
    "vuln": "attack",
    "vulns": "attack",
    "vulnerability": "attack",
    "vulnerabilities": "attack",
}


def _normalize(token):
    """Canonical form of a VULN token: trimmed punctuation, spaces, case, underscores."""
    text = str(token).strip().strip(":;,. ").lower()
    return re.sub(r"\s+", " ", text).replace("_", "-")


NAME_INDEX = {}
KEY_INDEX = {}
NESSUS_INDEX = {}
CVE_INDEX = {}
ISSUE_INDEX = {}
for _key, _check in CHECKS.items():
    KEY_INDEX[_normalize(_key)] = _key
    NAME_INDEX.setdefault(_normalize(_check["name"]), []).append(_key)
    for _plugin_id in _check.get("nessus", []):
        NESSUS_INDEX.setdefault(str(_plugin_id), []).append(_key)
    for _cve in _check.get("cve", []):
        CVE_INDEX.setdefault(_normalize(_cve), []).append(_key)
    ISSUE_INDEX.setdefault(_normalize(_check.get("issue", "")), []).append(_key)

PORT_RE = re.compile(r":(\d+)(?:/\d+)?$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TRUE_VALUES = frozenset(["true", "1", "yes", "on", "y"])
PLACEHOLDER_IPS = frozenset(["", "-", "/", "n/a", "none"])


def log(msg):
    print(f"{datetime.now(timezone.utc)} - TestSSL: {msg}", file=sys.stderr, flush=True)


def _bool(name, default=False):
    """Read a boolean per-scan argument, tolerating the usual truthy spellings."""
    raw = arg_helpers.single(f"EXECUTOR_CONFIG_TESTSSL_{name}")
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in TRUE_VALUES


def _tokens(name):
    """Per-scan list argument as tokens: JSON array, CSV or a single value."""
    tokens = []
    for value in arg_helpers.items(f"EXECUTOR_CONFIG_TESTSSL_{name}"):
        tokens.extend(part.strip() for part in str(value).split(","))
    return [token for token in tokens if token]


def _int(name, default):
    raw = arg_helpers.single(f"EXECUTOR_CONFIG_TESTSSL_{name}")
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _nodns():
    mode = (arg_helpers.single("EXECUTOR_CONFIG_TESTSSL_NODNS") or "min").strip().lower()
    if mode not in {"min", "none"}:
        log(f"TESTSSL_NODNS '{mode}' is invalid; using min")
        return "min"
    return mode


def resolve_checks(tokens):
    """Map VULN/EXCLUDE_VULN tokens onto CHECKS keys.

    Accepts check keys, Faraday vulnerability names, issue names of the Porco
    catalog, CVE ids, Nessus plugin ids and group aliases (all/cert/cipher/
    protocol/attack). Returns
    ``(keys, unknown)``; an empty ``keys`` means "every check".
    """
    keys = []
    unknown = []
    for token in tokens:
        text = _normalize(token)
        if not text:
            continue
        hits = _lookup(text)
        if hits:
            _add(keys, hits)
        else:
            unknown.append(str(token))
    return keys, unknown


def _lookup(text):
    """CHECKS keys a single normalized VULN token refers to, or ``None``."""
    if text in KEY_INDEX:
        return [KEY_INDEX[text]]
    if text in GROUP_ALIASES:
        tag = GROUP_ALIASES[text]
        return _all_keys() if tag is None else _tagged_keys(tag)
    if re.fullmatch(r"(?:nessus[-:]?)?\d+", text):
        return NESSUS_INDEX.get(re.sub(r"\D", "", text))
    if text.startswith("cve-"):
        return CVE_INDEX.get(text)
    if text in NAME_INDEX:
        return NAME_INDEX[text]
    if text in ISSUE_INDEX:
        return ISSUE_INDEX[text]
    hits = [key for key in CHECKS if text in _normalize(key) or text in _check_name(key)]
    return hits or None


def _add(keys, found):
    for key in found:
        if key not in keys:
            keys.append(key)


def _all_keys():
    return list(CHECKS.keys())


def _tagged_keys(tag):
    return [key for key, check in CHECKS.items() if tag in check.get("tags", [])]


def _check_name(key):
    return _normalize(CHECKS[key]["name"])


def target_uris(targets, ports, ports_given, starttls):
    """Expand targets into the URIs testssl.sh is called with.

    A target that already carries a port is used as-is; otherwise one URI per
    configured port is produced. STARTTLS targets keep the protocol default port
    unless ports were given explicitly.
    """
    uris = []
    for token in targets:
        target = str(token).strip().rstrip("/")
        if not target:
            continue
        if _explicit_port(target) is not None:
            uris.append(target)
            continue
        if starttls and not ports_given:
            uris.append(target)
            continue
        for port in ports:
            uris.append(f"{target}:{port}")
    return uris


def _explicit_port(uri):
    host = uri.split("//", 1)[1] if "//" in uri else uri
    match = PORT_RE.search(host.split("/")[0])
    return int(match.group(1)) if match else None


def scan_flags(check_keys):
    """Union of the test flags the selected checks need, in testssl.sh order."""
    wanted = set()
    for key in check_keys:
        wanted.update(CHECKS[key]["flags"])
    order = ["-p", "-s", "-f", "-S", "-h", "-U"]
    flags = [flag for flag in order if flag in wanted]
    flags += [flag for flag in sorted(wanted) if flag not in flags]
    return flags


def build_command(uri, json_path, check_keys, options):
    cmd = [
        options["binary"],
        "--quiet",
        "--color",
        "0",
        "--warnings",
        "off",
        "--connect-timeout",
        str(options["connect_timeout"]),
        "--openssl-timeout",
        str(options["openssl_timeout"]),
        "--nodns",
        options["nodns"],
    ]
    if options["openssl"]:
        cmd += ["--openssl", options["openssl"]]
    if options["starttls"]:
        cmd += ["--starttls", options["starttls"]]
    if options["sneaky"]:
        cmd.append("--sneaky")
    if options["ids_friendly"]:
        cmd.append("--ids-friendly")
    if options["phone_out"]:
        cmd.append("--phone-out")
    cmd += scan_flags(check_keys)
    if options["extra_args"]:
        cmd += options["extra_args"]
    cmd += ["--jsonfile", json_path, "--overwrite", uri]
    return cmd


def parse_findings(json_path):
    """Return the finding records of a testssl.sh flat JSON file."""
    try:
        with open(json_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read().strip()
    except OSError as exc:
        log(f"cannot read {json_path}: {exc}")
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = _salvage_objects(text)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict) and type(entry.get("id")) is str and entry["id"]]


def _salvage_objects(text):
    """Recover one record per line after testssl.sh interrupted a write.

    Truncated files (timeouts, killed scans) leave dangling objects behind; keep
    every complete ``{...}`` block instead of losing the whole scan.
    """
    entries = []
    for chunk in re.findall(r"\{[^{}]*\}", text, re.DOTALL):
        try:
            entries.append(json.loads(chunk))
        except json.JSONDecodeError:
            continue
    return entries


def _matches(patterns, finding):
    return any(re.search(pattern, finding, re.IGNORECASE) for pattern in patterns or [])


def _reportable(check, severity, finding):
    """Whether one finding record proves ``check``."""
    if severity not in set(TESTSSL_SEVERITY) | {"OK"}:
        return False
    if _matches(check.get("exclude"), finding):
        return False
    if check.get("require") and not _matches(check["require"], finding):
        return False
    if check.get("severity"):
        # The check names its own severity, so testssl.sh may rate it OK.
        return True
    return severity in TESTSSL_SEVERITY


def _highest(matched):
    best = "info"
    for _, _, severity in matched:
        candidate = TESTSSL_SEVERITY.get(severity)
        if candidate and SEVERITY_ORDER[candidate] > SEVERITY_ORDER[best]:
            best = candidate
    return best


def build_vulnerabilities(entries, check_keys, options):
    """Turn finding records into the Faraday vulnerability dicts of one scan."""
    by_id = {}
    for entry in entries:
        by_id.setdefault(entry["id"], []).append(entry)

    service = " ".join(str(e.get("finding") or "") for e in by_id.get("service", []))
    http_service = bool(re.search(r"\bhttps?\b", service, re.IGNORECASE))

    vulns = []
    for key in check_keys:
        check = CHECKS[key]
        if check.get("http") and not http_service:
            log(f"{key}: skipped, service answered '{service.strip() or 'unknown'}'")
            continue
        records = [
            (entry["id"], str(entry.get("finding") or ""), str(entry.get("severity") or "").upper())
            for finding_id in check["ids"]
            for entry in by_id.get(finding_id, [])
        ]
        if check.get("mode") == "absent":
            # The finding is that nothing in the scan proves the safe pattern.
            if (not records or any(severity not in set(TESTSSL_SEVERITY) | {"OK"} for _, _, severity in records)
                    or _matches(check.get("require"), " ".join(text for _, text, _ in records))):
                continue
            matched, severity_value = records, check["severity"]
        else:
            matched = [record for record in records if _reportable(check, record[2], record[1])]
            if not matched:
                continue
            severity_value = check.get("severity") or _highest(matched)
        vulns.append(build_vulnerability(key, check, matched, severity_value))

    if options["include_info"]:
        vulns += build_info_vulnerabilities(by_id)
    return vulns


def build_vulnerability(key, check, matched, severity):
    findings = "\n".join(f"* {finding_id}: {finding}" for finding_id, finding, _ in matched)
    refs = [f"NESSUS-{plugin_id}" for plugin_id in check.get("nessus", [])]
    refs += check.get("refs", [])
    return {
        "name": check["name"],
        "desc": (
            f"testssl.sh finding ({check['issue']}):\n"
            f"{findings}\n\n"
            "Proof of the finding is the testssl.sh output quoted above."
        ),
        "severity": severity,
        "type": "Vulnerability",
        "external_id": f"{EXECUTOR}:{key}",
        "refs": refs,
        "cve": check.get("cve", []),
        "data": findings,
        "resolution": check.get("resolution", ""),
    }


def build_info_vulnerabilities(by_id):
    vulns = []
    for name, finding_ids in INFO_CHECKS.items():
        lines = [
            f"* {entry['id']}: {entry.get('finding', '')}"
            for finding_id in finding_ids
            for entry in by_id.get(finding_id, [])
        ]
        if not lines:
            continue
        vulns.append(
            {
                "name": name,
                "desc": "testssl.sh survey:\n" + "\n".join(lines),
                "severity": "info",
                "type": "Vulnerability",
                "external_id": f"{EXECUTOR}:{name.lower().replace(' ', '-')}",
                "refs": [],
                "cve": [],
                "data": "\n".join(lines),
                "resolution": "",
            }
        )
    return vulns


def scan(uri, check_keys, options):
    """Run one testssl.sh scan, returning ``(entries, command)``.

    ``command`` is always returned so Faraday records the attempt even when the
    scan produced nothing.
    """
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="testssl-") as tmpdir:
        json_path = os.path.join(tmpdir, "scan.json")
        cmd = build_command(uri, json_path, check_keys, options)
        log(f"scanning {uri}: {' '.join(cmd)}")
        returncode = None
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=options["timeout"],
            )
            returncode = proc.returncode
            if proc.stderr:
                for line in proc.stderr.strip().splitlines():
                    log(f"testssl.sh: {line}")
        except subprocess.TimeoutExpired:
            log(f"{uri}: testssl.sh timed out after {options['timeout']}s")
        except OSError as exc:
            log(f"cannot run {options['binary']}: {exc}. Install testssl.sh or set TESTSSL_PATH.")
            return [], faraday_command(cmd, uri, started)
        # testssl.sh exits non-zero on unreachable targets and on warnings; the
        # JSON file is the only reliable verdict, so the code is not checked here.
        entries = [entry for entry in parse_findings(json_path) if entry["id"] not in IGNORED_IDS]
        if not entries:
            log(f"{uri}: no findings parsed (exit code {returncode})")
        return entries, faraday_command(cmd, uri, started)


def faraday_command(cmd, uri, started):
    return {
        "tool": TOOL,
        "command": " ".join(cmd),
        "params": f"target={uri}",
        "user": os.environ.get("USER", ""),
        "hostname": socket.gethostname(),
        "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
        "duration": int((time.time() - started) * 1000),
        "import_source": "report",
    }


def resolve_ip(target, entries, agent_config):
    """Best available address for the host record."""
    for entry in entries:
        candidate = str(entry.get("ip") or "").split("/")[0].strip()
        if candidate.lower() in PLACEHOLDER_IPS:
            continue
        if IPV4_RE.match(candidate) or re.match(r"^[\w.:-]+$", candidate):
            return candidate
    host = _target_host(target)
    if IPV4_RE.match(host):
        return host
    if agent_config.resolve_hostname:
        try:
            return socket.gethostbyname(host)
        except (OSError, UnicodeError):
            log(f"{host}: could not be resolved, using it as-is")
    return host


def service_name(entries, port):
    """Faraday service name for the tested port."""
    found = " ".join(str(entry.get("finding") or "") for entry in entries if entry.get("id") == "service")
    text = found.strip().lower()
    if re.search(r"\bhttps?\b", text):
        return "https"
    if port in (443, 8443, 4443):
        return "https"
    if text and text not in ("-", "unknown", "vulnerability found", "no protocols available"):
        return text.split()[0]
    return "ssl"


def _target_host(target):
    """Host part of a target: no scheme, no port, no path."""
    host = target.split("//", 1)[1] if "//" in target else target
    host = host.split("/")[0]
    if host.startswith("[") and "]" in host:  # bracketed IPv6 literal
        return host[: host.index("]") + 1]
    match = PORT_RE.search(host)
    if match:
        host = host[: match.start()]
    return host


def build_host(target, entries, vulns, agent_config, default_port=443):
    port = _explicit_port(target)
    if port is None:
        for entry in entries:
            match = re.search(r"\d+", str(entry.get("port") or ""))
            if match:
                port = int(match.group())
                break
    if port is None:
        port = default_port
    name = _target_host(target)
    service = service_name(entries, port)
    host = {
        "ip": resolve_ip(target, entries, agent_config),
        "description": f"{TOOL} SSL/TLS assessment of {name}:{port} ({service})",
        "hostnames": [name] if name and not IPV4_RE.match(name) else [],
        "services": [{"name": service, "port": port, "protocol": "tcp", "vulnerabilities": vulns}],
    }
    return host


def filter_severity(vulns, agent_config):
    """Apply the agent-wide severity window to the produced vulnerabilities."""
    kept = []
    for vuln in vulns:
        severity = vuln["severity"]
        if severity not in SEVERITY_ORDER:
            severity = "unclassified"
        elif agent_config.ignore_info and severity == "info":
            continue
        floor = agent_config.min_severity
        if floor in SEVERITY_ORDER and severity in SEVERITY_ORDER:
            if SEVERITY_ORDER[severity] < SEVERITY_ORDER[floor]:
                continue
        ceiling = agent_config.max_severity
        if ceiling in SEVERITY_ORDER and severity in SEVERITY_ORDER:
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[ceiling]:
                continue
        kept.append(vuln)
    return kept


def get_options():
    starttls = (arg_helpers.single("EXECUTOR_CONFIG_TESTSSL_STARTTLS") or "").strip().lower()
    if starttls and starttls not in VALID_STARTTLS:
        log(f"TESTSSL_STARTTLS '{starttls}' is not one of {', '.join(sorted(VALID_STARTTLS))}; ignored")
        starttls = ""
    ports = []
    for port in _tokens("PORTS"):
        try:
            ports.append(int(str(port).strip()))
        except ValueError:
            log(f"TESTSSL_PORTS: '{port}' is not a port, ignored")
    return {
        "binary": os.environ.get("TESTSSL_PATH", "testssl.sh"),
        "openssl": os.environ.get("OPENSSL_PATH") or None,
        "ports": ports,
        "ports_given": bool(ports),
        "starttls": starttls,
        "nodns": _nodns(),
        "connect_timeout": _int("CONNECT_TIMEOUT", 10),
        "openssl_timeout": _int("OPENSSL_TIMEOUT", 15),
        "timeout": _int("TIMEOUT", 900),
        "sneaky": _bool("SNEAKY"),
        "ids_friendly": _bool("IDS_FRIENDLY"),
        "phone_out": _bool("PHONE_OUT"),
        "include_info": _bool("INCLUDE_INFO"),
        "extra_args": shlex.split(arg_helpers.single("EXECUTOR_CONFIG_TESTSSL_EXTRA_ARGS") or ""),
    }


def main():
    agent_config = get_common_parameters()
    targets = _tokens("TARGET")
    if not targets:
        log("TESTSSL_TARGET is required (host, host:port, URL or URL:port)")
        sys.exit(1)

    options = get_options()
    if not options["ports"]:
        options["ports"] = [443]

    tokens = _tokens("VULN") + _tokens("ISSUE")
    excluded = _tokens("EXCLUDE_VULN")
    check_keys, unknown = resolve_checks(tokens)
    for token in unknown:
        log(f"TESTSSL_VULN: '{token}' is not a known check, issue, CVE or Nessus plugin id; ignored")
    if tokens and not check_keys:
        log("TESTSSL_VULN matched nothing, nothing to scan")
        sys.exit(1)
    if not check_keys:
        check_keys = _all_keys()
    drop, _ = resolve_checks(excluded)
    for key in drop:
        if key in check_keys:
            check_keys.remove(key)

    log(
        f"{len(targets)} target(s), {len(check_keys)} check(s): "
        f"{','.join(sorted(check_keys))} | flags: {' '.join(scan_flags(check_keys)) or '-'}"
    )

    scanned = 0
    reported = 0
    for uri in target_uris(targets, options["ports"], options["ports_given"], options["starttls"]):
        entries, command = scan(uri, check_keys, options)
        vulns = filter_severity(build_vulnerabilities(entries, check_keys, options), agent_config)
        hosts = []
        if vulns:
            hosts = [build_host(uri, entries, vulns, agent_config, options["ports"][0])]
        else:
            log(f"{uri}: no finding above the severity threshold")
        print(json.dumps({"hosts": hosts, "command": command}), flush=True)
        scanned += 1
        reported += len(vulns)

    log(f"{scanned} scan(s) finished, {reported} vulnerability(ies) reported")


if __name__ == "__main__":
    main()
