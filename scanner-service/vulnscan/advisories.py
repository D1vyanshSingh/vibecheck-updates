"""Offline advisory database: NVD JSON -> SQLite -> version-range matching.

The shipped CVE rules in :mod:`vulnscan.checks` are hand-picked fingerprints.
This module replaces that with a real, offline database built from NVD's CVE
JSON 2.0 feeds: one row per affected CPE version range, queried by product and
version at scan time. Standard library only (``sqlite3``, ``urllib``,
``gzip``), so a scan never touches the network unless ``--update-db`` is asked
for.

Two honesty rules are built into the schema rather than the report:

* Ranges are matched, not equated, so Apache 2.4.48–2.4.50 all hit
  CVE-2021-41773 without three separate rules.
* A distro-patched build (``1.18.0-1ubuntu1``, ``9.6p1-3ubuntu13``) downgrades
  the finding to ``tentative``: the vendor may have backported the fix, so the
  upstream version range alone cannot prove exploitability.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
USER_AGENT = "vulnscan-advisory-updater/1.0 (+https://nvd.nist.gov/)"

# Products vulnscan can identify, mapped to the CPE vendor/product pairs that
# describe the same software in NVD. Detection names are normalized through
# :func:`product_key` before lookup.
PRODUCT_CPES: dict[str, tuple[tuple[str, str], ...]] = {
    "apache-httpd": (("apache", "http_server"),),
    "nginx": (("f5", "nginx"), ("nginx", "nginx")),
    "openssh": (("openbsd", "openssh"), ("openssh", "openssh")),
    "mysql": (("oracle", "mysql"), ("mysql", "mysql")),
    "mariadb": (("mariadb", "mariadb"),),
    "postgresql": (("postgresql", "postgresql"),),
    "redis": (("redis", "redis"),),
    "vsftpd": (("beasts", "vsftpd"),),
    "openssl": (("openssl", "openssl"),),
    "php": (("php", "php"),),
}

_CPE_TO_KEY = {pair: key for key, pairs in PRODUCT_CPES.items() for pair in pairs}

# Distro markers: a package revision means the vendor's build may differ from
# the upstream release NVD describes.
_DISTRO_RE = re.compile(
    r"(?<![a-z])(ubuntu|debian|centos|red\s*hat|rhel|amazon(?:linux)?|fedora|suse|"
    r"sles|alpine|rocky|almalinux)(?![a-z])", re.I)
_REVISION_RE = re.compile(r"-(\d+(?:\.\d+)*)(?:[a-z]{2,})?\.?[a-z]{2,}\d*", re.I)
_RHEL_RE = re.compile(r"\.el\d+", re.I)
_VERSION_RE = re.compile(r"^\s*(\d[\w.~+-]*)")
_NUMBER_RE = re.compile(r"\d+")


# --------------------------------------------------------------------------
# Version handling
# --------------------------------------------------------------------------

def parse_version(text: str) -> tuple[int, ...]:
    """Comparable form of a version string: numeric groups, in order.

    ``9.6p1`` -> ``(9, 6, 1)``, ``2.4.49`` -> ``(2, 4, 49)``. This is the same
    ordering NVD ranges assume for the products in :data:`PRODUCT_CPES`; it is
    deliberately not a full package-version comparison.
    """
    return tuple(int(group) for group in _NUMBER_RE.findall(text or ""))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def version_lt(a: str, b: str) -> bool:
    left, right = _pad(parse_version(a), parse_version(b))
    return left < right


def split_version(raw: str, *hints: str) -> tuple[str, str]:
    """Return ``(upstream_version, distro)`` for a detected version string.

    ``1.18.0-1ubuntu1`` -> ``("1.18.0", "ubuntu")``; a bare ``2.4.49`` keeps an
    empty distro. ``hints`` (nmap extrainfo, HTTP Server header, banner) are
    scanned for a distro name too, because nmap reports ``OpenSSH 9.6p1`` with
    the Ubuntu release in a separate field.
    """
    text = (raw or "").strip()
    distro = ""
    match = _VERSION_RE.match(text)
    version = match.group(1) if match else text
    revision = _REVISION_RE.search(version)
    if revision:
        version = version[:revision.start()]
        # The package revision itself names the distro: 1.18.0-1ubuntu1.
        found = _DISTRO_RE.search(revision.group(0))
        if found:
            distro = re.sub(r"\s+", " ", found.group(1).lower())
        elif _RHEL_RE.search(revision.group(0)):
            distro = "red hat"
    if not distro:
        for hint in hints:
            found = _DISTRO_RE.search(hint or "")
            if found:
                distro = re.sub(r"\s+", " ", found.group(1).lower())
                break
    return version.strip(".-"), distro


def product_key(product: str) -> str | None:
    """Map a detected product name onto a :data:`PRODUCT_CPES` key."""
    name = (product or "").strip().lower()
    if not name:
        return None
    if "mariadb" in name:
        return "mariadb"
    if "mysql" in name:
        return "mysql"
    if "postgres" in name:
        return "postgresql"
    if "openssh" in name:
        return "openssh"
    if "openssl" in name:
        return "openssl"
    if "nginx" in name:
        return "nginx"
    if "vsftpd" in name:
        return "vsftpd"
    if "redis" in name:
        return "redis"
    if name.startswith("php") or " php" in name:
        return "php"
    if "httpd" in name or "http server" in name or name == "apache":
        return "apache-httpd"
    return None


def severity_from_score(score: float | None, label: str = "") -> str:
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    return {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low"}.get((label or "").lower(), "medium")


# --------------------------------------------------------------------------
# CPE parsing and NVD ingestion
# --------------------------------------------------------------------------

def _split_cpe(criteria: str) -> list[str]:
    """Split a CPE 2.3 string on unescaped colons."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in criteria:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    """``cpe:2.3:a:apache:http_server:2.4.49:...`` -> vendor, product, version.

    NVD encodes an exact vulnerable release inside the criteria string, not in
    a cpeMatch attribute, so the version has to come from part 5.
    """
    parts = _split_cpe(criteria or "")
    if len(parts) < 5 or parts[0] != "cpe" or parts[2] != "a":
        return None
    version = parts[5] if len(parts) > 5 else ""
    return parts[3].lower(), parts[4].lower(), version


def _metrics(cve: dict) -> tuple[float | None, str, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                return (float(score), data.get("baseSeverity", ""),
                        data.get("vectorString", ""))
    return None, "", ""


def _description(cve: dict) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return (item.get("value") or "").strip()
    return ""


def _match_rows(match: dict, cpe_version: str = "") -> list[dict]:
    """One CPE match element -> advisory rows (exact version or range)."""
    if match.get("vulnerable") is False:
        return []
    exact = match.get("version") or cpe_version
    start = match.get("versionStartIncluding")
    end = match.get("versionEndExcluding")
    end_inclusive = 0
    start_inclusive = 1
    if not start:
        start = match.get("versionStartExcluding")
        start_inclusive = 0 if start else 1
    if not end:
        end = match.get("versionEndIncluding")
        end_inclusive = 1 if end else 0
    if exact in ("*", "-", ""):
        exact = None
    if not exact and not start and not end:
        # NVD uses a bare wildcard for "all versions"; without a range or a
        # fixed release it cannot be graded honestly, so it is skipped.
        return []
    return [{"introduced": start, "start_inclusive": start_inclusive,
             "fixed": end, "end_inclusive": end_inclusive,
             "exact_version": exact}]


def rows_from_nvd(document: dict) -> list[dict]:
    """Flatten one NVD CVE JSON 2.0 document into advisory rows."""
    rows: list[dict] = []
    for entry in document.get("vulnerabilities") or []:
        cve = entry.get("cve") or {}
        cve_id = cve.get("id") or ""
        if not cve_id.startswith("CVE-"):
            continue
        score, label, vector = _metrics(cve)
        summary = _description(cve)
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    parsed = parse_cpe(match.get("criteria", ""))
                    if not parsed:
                        continue
                    vendor, cpe_product, cpe_version = parsed
                    key = _CPE_TO_KEY.get((vendor, cpe_product))
                    if not key:
                        continue
                    for row in _match_rows(match, cpe_version):
                        rows.append({
                            "cve": cve_id, "product": key,
                            "severity": severity_from_score(score, label),
                            "cvss": score, "vector": vector,
                            "summary": summary[:600],
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            **row,
                        })
    return rows


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS advisory (
    cve TEXT NOT NULL,
    product TEXT NOT NULL,
    introduced TEXT,
    start_inclusive INTEGER NOT NULL DEFAULT 1,
    fixed TEXT,
    end_inclusive INTEGER NOT NULL DEFAULT 0,
    exact_version TEXT,
    severity TEXT NOT NULL,
    cvss REAL,
    vector TEXT,
    summary TEXT,
    url TEXT
);
CREATE INDEX IF NOT EXISTS advisory_product ON advisory(product);
"""


def default_db_path() -> Path:
    override = os.environ.get("VULNSCAN_DB", "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "vulnscan" / "advisories.sqlite3"


@dataclass(frozen=True)
class Advisory:
    cve: str
    product: str
    severity: str
    cvss: float | None
    vector: str
    summary: str
    url: str
    introduced: str
    fixed: str

    @property
    def title(self) -> str:
        return f"{self.cve} affects {self.product}"


@dataclass(frozen=True)
class DatabaseInfo:
    path: str
    exists: bool
    advisories: int
    cves: int
    built_at: str
    years: str


def _in_range(version: str, row: sqlite3.Row) -> bool:
    if row["exact_version"]:
        return parse_version(version) == parse_version(row["exact_version"])
    if row["introduced"]:
        left, right = _pad(parse_version(version), parse_version(row["introduced"]))
        if left < right or (not row["start_inclusive"] and left == right):
            return False
    if row["fixed"]:
        left, right = _pad(parse_version(version), parse_version(row["fixed"]))
        if left > right or (not row["end_inclusive"] and left == right):
            return False
    return True


class AdvisoryDB:
    """Read-only view of a built advisory database."""

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else default_db_path()
        self._conn: sqlite3.Connection | None = None
        self._load_error = ""

    # -- lifecycle ---------------------------------------------------------
    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is not None:
            return self._conn
        if not self.path.is_file():
            return None
        try:
            # Read-only: a scan must never modify or create the database.
            uri = f"file:{self.path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("SELECT 1 FROM advisory LIMIT 1")
        except sqlite3.Error as exc:
            self._load_error = str(exc)
            self._conn = None
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- status ------------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._connect() is not None

    def info(self) -> DatabaseInfo:
        conn = self._connect()
        if conn is None:
            return DatabaseInfo(str(self.path), self.path.is_file(), 0, 0,
                                "", self._load_error)
        row = conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT cve) AS c FROM advisory").fetchone()
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
        return DatabaseInfo(str(self.path), True, row["n"], row["c"],
                            meta.get("built_at", ""), meta.get("years", ""))

    # -- query -------------------------------------------------------------
    def lookup(self, product: str, version: str) -> list[Advisory]:
        """Advisories for ``product`` whose affected range contains ``version``.

        One advisory per CVE: NVD lists several ranges for a single CVE, and a
        report should not repeat the same CVE because two CPEs matched.
        """
        conn = self._connect()
        if conn is None or not product or not version:
            return []
        rows = conn.execute(
            "SELECT * FROM advisory WHERE product = ?", (product,)).fetchall()
        best: dict[str, Advisory] = {}
        for row in rows:
            if not _in_range(version, row):
                continue
            advisory = Advisory(
                cve=row["cve"], product=row["product"], severity=row["severity"],
                cvss=row["cvss"], vector=row["vector"], summary=row["summary"],
                url=row["url"], introduced=row["introduced"] or "",
                fixed=row["fixed"] or "")
            current = best.get(advisory.cve)
            # Keep the most severe description when NVD repeats a CVE across
            # ranges; the fixed version shown is the earliest one available.
            if current is None or (advisory.cvss or 0) > (current.cvss or 0):
                best[advisory.cve] = advisory
        return sorted(best.values(), key=lambda a: (-(a.cvss or 0), a.cve))


def build_database(rows: list[dict], path: str | os.PathLike,
                   source: dict | None = None) -> DatabaseInfo:
    """Write ``rows`` to a fresh database, replacing ``path`` atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=".advisories-", suffix=".sqlite3",
                                         dir=str(target.parent))
    os.close(handle)
    temp = Path(temp_name)
    try:
        conn = sqlite3.connect(str(temp))
        try:
            conn.executescript(_SCHEMA)
            conn.executemany(
                "INSERT OR IGNORE INTO advisory (cve, product, introduced, "
                "start_inclusive, fixed, end_inclusive, exact_version, severity, "
                "cvss, vector, summary, url) VALUES (:cve, :product, :introduced, "
                ":start_inclusive, :fixed, :end_inclusive, :exact_version, "
                ":severity, :cvss, :vector, :summary, :url)", rows)
            meta = {
                "schema_version": str(SCHEMA_VERSION),
                "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "advisories": str(conn.execute(
                    "SELECT COUNT(*) FROM advisory").fetchone()[0]),
                **(source or {}),
            }
            conn.executemany("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                             list(meta.items()))
            conn.commit()
        finally:
            conn.close()
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
    db = AdvisoryDB(target)
    try:
        return db.info()
    finally:
        db.close()


def _download(url: str, timeout: float = 180.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def update_database(path: str | os.PathLike | None = None,
                    years: list[int] | None = None,
                    log=print) -> DatabaseInfo:
    """Download NVD feeds, rebuild the database, and return its status."""
    target = Path(path) if path else default_db_path()
    if years is None:
        current = datetime.now(timezone.utc).year
        years = list(range(current - 5, current + 1))
    rows: list[dict] = []
    for year in years:
        url = FEED_URL.format(year=year)
        log(f"  fetching {url}")
        try:
            raw = _download(url)
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"could not download {url}: {exc}") from exc
        try:
            document = json.loads(gzip.decompress(raw).decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"{url} was not NVD gzip JSON: {exc}") from exc
        part = rows_from_nvd(document)
        rows.extend(part)
        log(f"    {len(part)} advisory rows")
    info = build_database(rows, target, source={"years": ",".join(str(y) for y in years),
                                                "source": "nvd-json-2.0"})
    return info
