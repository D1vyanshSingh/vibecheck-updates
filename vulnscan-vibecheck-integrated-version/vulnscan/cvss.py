"""CVSS 3.1 base scores for findings, derived from a vector.

Severity words are not enough for a client, an insurer or a ticketing system,
but a bare number is not either: a score means nothing without the vector it
came from. This module therefore keeps the *vector* as the source of truth and
computes the base score from it, using the FIRST CVSS 3.1 base formula. The
band the computed score falls into is the band the report shows, so a rule can
never quietly claim "high" while carrying a 5.3 vector.

Three sources of vector, in order of preference:

``nvd``
    The advisory database carries NVD's own CVSS 3.x vector for a CVE; that
    score is not ours to invent.
``rule``
    A curated vector in :data:`CURATED_VECTORS`, written from the rule's own
    impact text (what the attacker gains, what interaction it needs).
``baseline``
    Fallback for a rule with no curated vector: the band-level baseline vector.
    It is a floor for triage, not a claim about a specific attack path, and
    the report labels it as such.
"""

from __future__ import annotations

import math

CVSS_VERSION = "3.1"
PREFIX = "CVSS:3.1/"

# Order matters: first band whose floor the score clears wins.
BANDS: tuple[tuple[str, float], ...] = (
    ("critical", 9.0),
    ("high", 7.0),
    ("medium", 4.0),
    ("low", 0.1),
    ("informational", 0.0),
)

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
       "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Band baselines: each vector scores inside its own band (checked by tests).
BAND_VECTORS: dict[str, str] = {
    "critical": PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",        # 9.8
    "high": PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",            # 7.5
    "medium": PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",          # 5.3
    "low": PREFIX + "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",             # 3.1
    "informational": PREFIX + "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",   # 0.0
}

# Reusable vectors, named by what they describe rather than by score.
_UNPRIVILEGED_RCE = BAND_VECTORS["critical"]
_REMOTE_WRITE = PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"         # 9.1
_REMOTE_READ = PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"          # 7.5
_AUTH_SERVICE_EXPOSED = PREFIX + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 8.1
_MITM_ACTIVE = PREFIX + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"          # 7.4
_DISCLOSURE = PREFIX + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"           # 5.9
_CONFIG_IMPACT = PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"        # 5.3
_COOKIE_THEFT = PREFIX + "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"         # 5.3
_CONFIG_LOW = PREFIX + "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"           # 3.1
_FINGERPRINT = PREFIX + "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"          # 3.1
_OBSERVATION = PREFIX + "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"          # 0.0

# Rule -> vector, written from the rule's impact text. Every entry is checked
# against the severity the rule emits (tests/test_cvss.py), so the score and
# the band cannot drift apart.
CURATED_VECTORS: dict[str, str] = {
    # Network exposure of authentication-bearing services: an attacker who can
    # reach the port gets a real protocol with real impact, but must still get
    # past authentication, hence AC:H rather than the 9.8 of an open API.
    "VS-EXP-TELNET": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-TELNET-ALT": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-RDP": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-SMB": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-VNC": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-DOCKER-TLS": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-KUBELET": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-ETCD": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-WINRM": _AUTH_SERVICE_EXPOSED,
    "VS-EXP-MONGODB": _AUTH_SERVICE_EXPOSED,
    "VS-HTTP-ADMIN-OPEN": _AUTH_SERVICE_EXPOSED,
    # Unauthenticated management APIs: full read/write, no interaction.
    "VS-EXP-REDIS-NOAUTH": _UNPRIVILEGED_RCE,
    "VS-EXP-DOCKER": _UNPRIVILEGED_RCE,
    "VS-HTTP-DOCKER-VERSION": _UNPRIVILEGED_RCE,
    "VS-EXP-MEMCACHED-NOAUTH": _REMOTE_WRITE,
    "VS-HTTP-ES-OPEN": _REMOTE_WRITE,
    # Authenticated databases / consoles reachable from the network.
    "VS-EXP-MYSQL": _CONFIG_IMPACT,
    "VS-EXP-POSTGRES": _CONFIG_IMPACT,
    "VS-EXP-MSSQL": _CONFIG_IMPACT,
    "VS-EXP-ORACLE": _CONFIG_IMPACT,
    "VS-EXP-RABBITMQ": _CONFIG_IMPACT,
    "VS-EXP-KIBANA": _CONFIG_IMPACT,
    "VS-EXP-NFS": _CONFIG_IMPACT,
    "VS-EXP-RSYNC": _CONFIG_IMPACT,
    "VS-EXP-REDIS-AUTH": _CONFIG_IMPACT,
    "VS-EXP-REDIS": _CONFIG_IMPACT,
    "VS-EXP-MEMCACHED": _CONFIG_IMPACT,
    "VS-HTTP-ES-EXPOSED": _CONFIG_IMPACT,
    "VS-HTTP-DIR-LISTING": _CONFIG_IMPACT,
    "VS-HTTP-STACKTRACE": _CONFIG_IMPACT,
    "VS-HTTP-HSTS": _CONFIG_IMPACT,
    "VS-HTTP-CSP": _CONFIG_IMPACT,
    # Metrics / admin endpoints with no credentials but narrow content.
    "VS-EXP-PROMETHEUS": _FINGERPRINT,
    "VS-EXP-ADMIN": _FINGERPRINT,
    # Public API discovery endpoint: an inventory aid, not a weakness itself.
    "VS-EXP-K8S-API": _OBSERVATION,
    # Anonymous read access to files.
    "VS-FTP-ANON": _REMOTE_READ,
    # Cleartext or weak transport.
    "VS-FTP-CLEARTEXT": _FINGERPRINT,
    "VS-TLS-EXPIRED": _MITM_ACTIVE,
    "VS-TLS-NOT-YET-VALID": _DISCLOSURE,
    "VS-TLS-EXPIRING": _CONFIG_IMPACT,
    "VS-TLS-SELF-SIGNED": _FINGERPRINT,
    "VS-TLS-HOSTNAME": _DISCLOSURE,
    "VS-TLS-WEAK-CIPHER": _MITM_ACTIVE,
    "VS-TLS-LEGACY": _DISCLOSURE,
    # Information disclosure and browser-configuration issues.
    "VS-HTTP-SERVER-VERSION": _FINGERPRINT,
    "VS-HTTP-POWERED-BY": _FINGERPRINT,
    "VS-HTTP-COOKIE-NO-SECURE": _COOKIE_THEFT,
    "VS-HTTP-COOKIE-NO-HTTPONLY": _CONFIG_LOW,
    "VS-HTTP-XFO": _CONFIG_LOW,
    "VS-HTTP-XCTO": _CONFIG_LOW,
    "VS-HTTP-CLEARTEXT": _OBSERVATION,
    "VS-HTTP-REFPOL": _OBSERVATION,
    # Fingerprinted CVEs with a published severity.
    "VS-CVE-2011-2523": _UNPRIVILEGED_RCE,
    "VS-CVE-2021-41773": _UNPRIVILEGED_RCE,
    "VS-CVE-2021-42013": _UNPRIVILEGED_RCE,
    "VS-CVE-2024-6387": _DISCLOSURE,
    "VS-EOL-SOFTWARE": _CONFIG_IMPACT,
}


class VectorError(ValueError):
    """A CVSS vector string that cannot be scored."""


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest 1-decimal number >= value."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def _parse(vector: str) -> dict[str, str]:
    text = (vector or "").strip()
    if text.upper().startswith("CVSS:3."):
        text = text.split("/", 1)[1] if "/" in text else ""
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        if not part:
            continue
        key, _, value = part.partition(":")
        if key and value:
            metrics[key.upper()] = value.upper()
    return metrics


def score_from_vector(vector: str) -> float:
    """CVSS 3.1 base score for a vector string; 0.0 when Impact is zero."""
    metrics = _parse(vector)
    missing = [k for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
               if k not in metrics]
    if missing:
        raise VectorError(f"vector missing {', '.join(missing)}: {vector!r}")
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            raise VectorError(f"unsupported scope {scope!r}")
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
        iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = (8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
                          * _PR[scope][metrics["PR"]] * _UI[metrics["UI"]])
    except KeyError as exc:
        raise VectorError(f"unsupported metric value in {vector!r}: {exc}") from None
    if impact <= 0:
        return 0.0
    if scope == "U":
        return round(_roundup(min(impact + exploitability, 10)), 1)
    return round(_roundup(min(1.08 * (impact + exploitability), 10)), 1)


def band_for(score: float) -> str:
    """The severity band a CVSS score belongs to (same thresholds as checks)."""
    for band, floor in BANDS:
        if score >= floor:
            return band
    return "informational"


def vector_source(finding) -> tuple[str, str]:
    """(vector, source) for a finding; source is nvd, rule or baseline."""
    explicit = (getattr(finding, "cvss_vector", "") or "").strip()
    if explicit.upper().startswith("CVSS:3."):
        return explicit, "nvd"
    curated = CURATED_VECTORS.get(finding.rule_id)
    if curated:
        return curated, "rule"
    return BAND_VECTORS.get(finding.severity, BAND_VECTORS["medium"]), "baseline"


def describe(finding) -> dict:
    """CVSS block for one finding: score, vector, version, band and source."""
    vector, source = vector_source(finding)
    score = score_from_vector(vector)
    band = band_for(score)
    # A vector that scores outside the finding's declared band is a bug in the
    # rule, not something to paper over at render time: the tests pin every
    # curated vector to the severity its rule emits.
    return {
        "score": score,
        "vector": vector,
        "version": ("3.0" if vector.upper().startswith("CVSS:3.0") else "3.1"),
        "band": band,
        "source": source,
    }
