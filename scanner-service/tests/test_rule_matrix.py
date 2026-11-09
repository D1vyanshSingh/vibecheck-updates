"""Positive and negative case for every rule the scanner ships.

Each rule is exercised twice: a fixture that plants the weakness must produce
the finding at the severity and confidence the rule documents, and a nearby
fixture without it must not produce that finding at all. That second half is
the point — a rule that fires on everything is worse than a missing rule.

The case count is pinned to the rule registry: a new rule without a case fails
``test_every_rule_has_a_case`` before it can reach a report.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from vulnscan import checks
from vulnscan.checks import Finding
from vulnscan.scanner import PortService


# --- fixtures -------------------------------------------------------------

def svc(port: int, service: str = "", *, banner: str = "", http: dict | None = None,
        tls: dict | None = None, product: str = "", version: str = "",
        identity_source: str = "banner", app: dict | None = None,
        extrainfo: str = "") -> PortService:
    out = PortService(host="target.example", ip="127.0.0.1", port=port,
                      state="open", service=service, banner=banner, http=http,
                      tls=tls, product=product, version=version,
                      identity_source=identity_source, extrainfo=extrainfo)
    if app:
        out.app = app
    return out


SAFE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def web(**overrides) -> dict:
    base = {
        "scheme": "https", "path": "/", "status": 200, "reason": "OK",
        "headers": dict(SAFE_HEADERS), "server": "nginx", "powered_by": "",
        "title": "Example", "body_preview": "hello", "body_length": 5,
    }
    base.update(overrides)
    return base


def tls_cert(**overrides) -> dict:
    cert = {"subject": "CN=target.example", "issuer": "CN=Example CA",
            "not_before": "2025-01-01", "not_after": "2027-01-01",
            "days_remaining": 365, "expired": False, "self_signed": False,
            "hostname_matches": True, "san": ["target.example"]}
    cert.update(overrides)
    return cert


def healthy_tls(**overrides) -> dict:
    base = {"ok": True, "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256,
            "cert": tls_cert()}
    base.update(overrides)
    return base


FAMILY_SERVICE = {
    "telnet": "telnet", "rdp": "ms-wbt-server", "smb": "microsoft-ds",
    "vnc": "vnc", "docker": "docker", "kubelet": "kubelet", "etcd": "etcd",
    "mysql": "mysql", "postgres": "postgresql", "mssql": "ms-sql-s",
    "oracle": "oracle", "winrm": "winrm", "rabbitmq": "rabbitmq",
    "kibana": "kibana", "nfs": "nfs", "rsync": "rsync",
    "kubernetes": "kubernetes", "prometheus": "prometheus", "http": "http",
}


@dataclass
class Case:
    rule_id: str
    severity: str
    confidence: str
    positive: PortService
    negative: PortService
    legacy: dict | None = None
    ftp: tuple[str, str] | None = None      # (positive reply, negative reply)
    key: str = ""
    note: str = ""

    @property
    def slug(self) -> str:
        return self.key or f"{self.rule_id}-{self.positive.port}"


CASES: list[Case] = []


def add(case: Case) -> None:
    CASES.append(case)


# 21 port-keyed exposure rules. Positive: the port, strongly identified as the
# expected protocol, with nothing that would prove more than the protocol.
# Negative: the same port speaking a protocol the rule must not claim.
EXPOSURE = [
    (23, "VS-EXP-TELNET", "high"),
    (2323, "VS-EXP-TELNET-ALT", "high"),
    (3389, "VS-EXP-RDP", "high"),
    (445, "VS-EXP-SMB", "high"),
    (5900, "VS-EXP-VNC", "high"),
    (5901, "VS-EXP-VNC", "high"),
    (2376, "VS-EXP-DOCKER-TLS", "high"),
    (10250, "VS-EXP-KUBELET", "high"),
    (2379, "VS-EXP-ETCD", "high"),
    (3306, "VS-EXP-MYSQL", "medium"),
    (5432, "VS-EXP-POSTGRES", "medium"),
    (1433, "VS-EXP-MSSQL", "medium"),
    (1521, "VS-EXP-ORACLE", "medium"),
    (5985, "VS-EXP-WINRM", "high"),
    (15672, "VS-EXP-RABBITMQ", "medium"),
    (5601, "VS-EXP-KIBANA", "medium"),
    (2049, "VS-EXP-NFS", "medium"),
    (873, "VS-EXP-RSYNC", "medium"),
    (6443, "VS-EXP-K8S-API", "informational"),
    (9090, "VS-EXP-PROMETHEUS", "low"),
    (9201, "VS-EXP-ADMIN", "low"),
]
for port, rule_id, severity in EXPOSURE:
    family = sorted(checks.EXPECTED_FAMILIES[port])[0]
    add(Case(rule_id, severity, "firm",
             svc(port, FAMILY_SERVICE[family],
                 banner="service banner", identity_source="banner"),
             svc(port, "ssh", banner="SSH-2.0-OpenSSH_9.6p1",
                 identity_source="banner"),
             key=f"{rule_id}-{port}",
             note=f"port {port} speaking {family} vs. ssh"))


# Protocol-proof service rules.
add(Case("VS-EXP-REDIS-NOAUTH", "critical", "certain",
         svc(6379, "redis", banner="# Server\r\nredis_version:6.0.9"),
         svc(6379, "redis", banner="-NOAUTH Authentication required."),
         note="INFO answered vs. AUTH enforced"))
add(Case("VS-EXP-REDIS-AUTH", "medium", "firm",
         svc(6379, "redis", banner="-NOAUTH Authentication required."),
         svc(6379, "redis", banner="# Server\r\nredis_version:6.0.9"),
         note="auth enforced vs. open"))
add(Case("VS-EXP-REDIS", "medium", "tentative",
         svc(6379, "", identity_source="port"),
         svc(6379, "redis", banner="# Server\r\nredis_version:6.0.9"),
         note="unidentified listener vs. proven Redis"))
add(Case("VS-EXP-MEMCACHED-NOAUTH", "critical", "certain",
         svc(11211, "memcached", banner="STAT pid 4242\r\nSTAT version 1.6.9"),
         svc(11211, "memcached"),
         note="stats answered vs. nothing"))
add(Case("VS-EXP-MEMCACHED", "medium", "firm",
         svc(11211, "memcached"),
         svc(11211, "memcached", banner="STAT pid 4242\r\nSTAT version 1.6.9"),
         note="generic memcached listener vs. proven no-auth"))
add(Case("VS-EXP-DOCKER", "critical", "firm",
         svc(2375, "docker", product="Docker", banner="Docker API"),
         svc(2375, "ssh", banner="SSH-2.0-OpenSSH_9.6p1"),
         note="Docker API vs. ssh squatting the port"))
add(Case("VS-EXP-MONGODB", "high", "firm",
         svc(27017, "mongodb", banner="MongoDB handshake"),
         svc(27017, "http", http=web(scheme="http")),
         note="mongo wire vs. HTTP"))

# FTP: the check opens a session, so the fixture is the server's reply.
add(Case("VS-FTP-ANON", "high", "certain",
         svc(21, "ftp", banner="220 (vsFTPD 2.3.4)"),
         svc(21, "ftp", banner="220 (vsFTPD 2.3.4)"),
         ftp=("331 Password required.\r\n230 Login successful.\r\n",
              "331 Password required.\r\n530 Login incorrect.\r\n"),
         note="anonymous 230 vs. rejected login"))
add(Case("VS-FTP-CLEARTEXT", "low", "certain",
         svc(21, "ftp", banner="220 (vsFTPD 2.3.4)"),
         svc(21, "http", http=web(scheme="http")),
         ftp=("530 Login incorrect.\r\n", "530 Login incorrect.\r\n"),
         note="plain FTP vs. an HTTP service on 21"))

# TLS certificate and protocol rules.
TLS_CASES = [
    ("VS-TLS-EXPIRED", "high", "certain",
     tls_cert(expired=True, days_remaining=-3), None,
     "expired certificate"),
    ("VS-TLS-NOT-YET-VALID", "medium", "certain",
     tls_cert(not_yet_valid=True), None, "notBefore in the future"),
    ("VS-TLS-EXPIRING", "medium", "certain",
     tls_cert(days_remaining=5), None, "expires within 14 days"),
    ("VS-TLS-SELF-SIGNED", "low", "certain",
     tls_cert(self_signed=True), None, "issuer == subject"),
    ("VS-TLS-HOSTNAME", "medium", "firm",
     tls_cert(hostname_matches=False, san=["other.example"]), None,
     "SAN does not cover the host"),
    ("VS-TLS-WEAK-CIPHER", "high", "certain",
     None, {"cipher": "RC4-SHA", "cipher_bits": 128}, "RC4 negotiated"),
]
for rule_id, severity, confidence, cert, tls_overrides, note in TLS_CASES:
    positive = healthy_tls()
    negative = healthy_tls()
    if cert is not None:
        positive["cert"] = cert
    else:
        positive.update(tls_overrides or {})
    add(Case(rule_id, severity, confidence,
             svc(8443, "https", tls=positive),
             svc(8443, "https", tls=negative),
             note=note))
add(Case("VS-TLS-LEGACY", "medium", "firm",
         svc(8443, "https", tls=healthy_tls()),
         svc(8443, "https", tls=healthy_tls()),
         legacy={"TLS 1.0": True, "TLS 1.1": False},
         note="TLS 1.0 accepted"))
CASES[-1].negative = svc(8443, "https", tls=healthy_tls())
CASES[-1].legacy = {"TLS 1.0": True, "TLS 1.1": False}
# The negative needs legacy off, which the runner below supplies per case.
CASES[-1].negative.tls = healthy_tls()

# HTTP security-header rules.
HEADER_CASES = [
    ("VS-HTTP-HSTS", "medium", "strict-transport-security"),
    ("VS-HTTP-CSP", "medium", "content-security-policy"),
    ("VS-HTTP-XFO", "low", "x-frame-options"),
    ("VS-HTTP-XCTO", "low", "x-content-type-options"),
    ("VS-HTTP-REFPOL", "informational", "referrer-policy"),
]
for rule_id, severity, header in HEADER_CASES:
    missing = dict(SAFE_HEADERS)
    missing.pop(header)
    if header == "x-frame-options":
        # frame-ancestors in a CSP substitutes for X-Frame-Options, so the
        # positive case has to drop that too or the rule correctly stays quiet.
        missing["content-security-policy"] = "default-src 'self'"
    add(Case(rule_id, severity, "certain",
             svc(8443, "https", http=web(headers=missing), tls=healthy_tls(),
                 identity_source="http"),
             svc(8443, "https", http=web(), tls=healthy_tls(),
                 identity_source="http"),
             note=f"missing {header} vs. present"))

# HTTP configuration and admin-surface rules.
add(Case("VS-HTTP-SERVER-VERSION", "low", "certain",
         svc(8443, "https", http=web(server="nginx/1.18.0"),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https", http=web(server="nginx"), tls=healthy_tls(),
             identity_source="http"), note="versioned vs. bare Server header"))
add(Case("VS-HTTP-POWERED-BY", "low", "certain",
         svc(8443, "https", http=web(powered_by="PHP/7.4.3"),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https", http=web(), tls=healthy_tls(),
             identity_source="http"), note="X-Powered-By present vs. absent"))
add(Case("VS-HTTP-DIR-LISTING", "medium", "certain",
         svc(8443, "https", http=web(body_preview="<h1>Index of /backup</h1>"),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https", http=web(), tls=healthy_tls(),
             identity_source="http"), note="autoindex vs. normal page"))
add(Case("VS-HTTP-STACKTRACE", "medium", "certain",
         svc(8443, "https",
             http=web(body_preview="Traceback (most recent call last): ..."),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https", http=web(), tls=healthy_tls(),
             identity_source="http"), note="traceback vs. generic error"))
add(Case("VS-HTTP-COOKIE-NO-SECURE", "medium", "firm",
         svc(8443, "https",
             http=web(headers=dict(SAFE_HEADERS, **{"set-cookie": "sid=1; HttpOnly"})),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https",
             http=web(headers=dict(SAFE_HEADERS,
                                   **{"set-cookie": "sid=1; Secure; HttpOnly"})),
             tls=healthy_tls(), identity_source="http"),
         note="cookie without Secure vs. with"))
add(Case("VS-HTTP-COOKIE-NO-HTTPONLY", "low", "firm",
         svc(8443, "https",
             http=web(headers=dict(SAFE_HEADERS, **{"set-cookie": "sid=1; Secure"})),
             tls=healthy_tls(), identity_source="http"),
         svc(8443, "https",
             http=web(headers=dict(SAFE_HEADERS,
                                   **{"set-cookie": "sid=1; Secure; HttpOnly"})),
             tls=healthy_tls(), identity_source="http"),
         note="cookie without HttpOnly vs. with"))
add(Case("VS-HTTP-CLEARTEXT", "informational", "certain",
         svc(8080, "http", http=web(scheme="http", path="/"),
             identity_source="http"),
         svc(8080, "https", http=web(), tls=healthy_tls(),
             identity_source="http"), note="HTTP only vs. HTTPS"))
add(Case("VS-HTTP-ES-OPEN", "critical", "certain",
         svc(9200, "http", http=web(scheme="http",
                                    body_preview='{"cluster_name":"lab"}'),
             identity_source="http"),
         svc(9200, "http", http=web(scheme="http", status=401,
                                    body_preview=""),
             identity_source="http"), note="open cluster vs. 401"))
add(Case("VS-HTTP-ES-EXPOSED", "medium", "firm",
         svc(9200, "http", http=web(scheme="http", status=401),
             identity_source="http"),
         svc(9200, "http", http=web(scheme="http",
                                    body_preview='{"cluster_name":"lab"}'),
             identity_source="http"), note="401 vs. open cluster"))
add(Case("VS-HTTP-DOCKER-VERSION", "critical", "certain",
         svc(2375, "docker",
             http=web(scheme="http", body_preview='{"ApiVersion":"1.41"}'),
             identity_source="http"),
         svc(2375, "docker", http=web(scheme="http", body_preview="hello"),
             identity_source="http"), note="Docker API body vs. generic page"))
add(Case("VS-HTTP-ADMIN-OPEN", "high", "firm",
         svc(5601, "http", http=web(scheme="http"), identity_source="http"),
         svc(5601, "http", http=web(scheme="http", status=401),
             identity_source="http"), note="200 vs. 401"))

# Version fingerprints and end-of-life software.
add(Case("VS-CVE-2011-2523", "critical", "certain",
         svc(21, "ftp", product="vsftpd", version="2.3.4"),
         svc(21, "ftp", product="vsftpd", version="2.3.5"),
         note="2.3.4 vs. 2.3.5"))
add(Case("VS-CVE-2021-41773", "critical", "firm",
         svc(8080, "http", product="Apache httpd", version="2.4.49"),
         svc(8080, "http", product="Apache httpd", version="2.4.51"),
         note="2.4.49 vs. 2.4.51"))
add(Case("VS-CVE-2021-42013", "critical", "firm",
         svc(8080, "http", product="Apache httpd", version="2.4.50"),
         svc(8080, "http", product="Apache httpd", version="2.4.51"),
         note="2.4.50 vs. 2.4.51"))
add(Case("VS-CVE-2024-6387", "medium", "tentative",
         svc(22, "ssh", product="OpenSSH", version="9.6p1"),
         svc(22, "ssh", product="OpenSSH", version="9.8p1"),
         note="portable 9.6p1 vs. fixed 9.8p1"))
add(Case("VS-EOL-SOFTWARE", "medium", "firm",
         svc(8443, "https", product="nginx", version="1.14.0"),
         svc(8443, "https", product="nginx", version="1.26.0"),
         note="EOL nginx vs. maintained branch"))


# --- execution ------------------------------------------------------------

def _legacy_for(case: Case, positive: bool) -> dict | None:
    if case.rule_id != "VS-TLS-LEGACY":
        return case.legacy
    return {"TLS 1.0": True} if positive else {"TLS 1.0": False}


def _sync_findings(case: Case, positive: bool) -> list[Finding]:
    target = case.positive if positive else case.negative
    legacy = _legacy_for(case, positive)
    return (checks.check_exposure(target) + checks.check_http(target)
            + checks.check_fingerprints(target) + checks.check_tls(target, legacy))


async def _ftp_findings(case: Case, positive: bool) -> list[Finding]:
    target = case.positive if positive else case.negative
    reply = case.ftp[0 if positive else 1]

    async def fake_send(*_args, **_kwargs):
        return reply

    with patch.object(checks, "send_recv", fake_send):
        return await checks.check_ftp_anonymous([target], 0.1)


class RuleMatrixTests(unittest.IsolatedAsyncioTestCase):
    def _assert_positive(self, case: Case, findings: list[Finding]) -> None:
        matches = [f for f in findings if f.rule_id == case.rule_id]
        self.assertEqual(1, len(matches),
                         f"{case.rule_id} did not fire for its planted fixture")
        finding = matches[0]
        self.assertEqual(case.severity, finding.severity)
        self.assertEqual(case.confidence, finding.confidence)

    def _assert_negative(self, case: Case, findings: list[Finding]) -> None:
        self.assertNotIn(case.rule_id, {f.rule_id for f in findings},
                         f"{case.rule_id} fired without its weakness planted")


def _make_test(case: Case, positive: bool):
    suffix = "positive" if positive else "negative"
    if case.ftp:
        async def test(self):
            findings = await _ftp_findings(case, positive)
            (self._assert_positive if positive else self._assert_negative)(
                case, findings)
    else:
        def test(self):
            findings = _sync_findings(case, positive)
            (self._assert_positive if positive else self._assert_negative)(
                case, findings)
    test.__name__ = f"test_{case.slug.lower().replace('-', '_')}_{suffix}"
    test.__doc__ = f"{case.rule_id} {suffix}: {case.note}"
    return test


for _case in CASES:
    setattr(RuleMatrixTests, f"test_{_case.slug.lower().replace('-', '_')}_positive",
            _make_test(_case, True))
    setattr(RuleMatrixTests, f"test_{_case.slug.lower().replace('-', '_')}_negative",
            _make_test(_case, False))


# --- coverage -------------------------------------------------------------

CHECKS_SOURCE = Path(checks.__file__).read_text(encoding="utf-8")


def literal_rule_ids() -> set[str]:
    ids = set(re.findall(r'rule_id="([^"]+)"', CHECKS_SOURCE))
    ids.update(entry[0] for entry in checks.EXPOSURE_RULES.values())
    ids.update(entry[1] for entry in checks.SECURITY_HEADERS)
    return ids


class CoverageTests(unittest.TestCase):
    def test_every_rule_has_two_cases(self):
        self.assertEqual(58, len(CASES), "58 rule instances → 116 cases")
        self.assertEqual(116, len(CASES) * 2)

    def test_matrix_covers_every_rule_id(self):
        covered = {case.rule_id for case in CASES}
        self.assertEqual(literal_rule_ids(), covered)

    def test_every_rule_has_a_positive_and_a_negative_method(self):
        for case in CASES:
            slug = case.slug.lower().replace("-", "_")
            with self.subTest(rule=case.slug):
                self.assertTrue(hasattr(RuleMatrixTests, f"test_{slug}_positive"))
                self.assertTrue(hasattr(RuleMatrixTests, f"test_{slug}_negative"))

    def test_case_severities_match_the_rules(self):
        # The matrix is the contract: changing a rule's severity without
        # updating its case should fail here, not silently weaken the test.
        for case in CASES:
            if case.rule_id.startswith("VS-CVE-") or case.rule_id == "VS-EOL-SOFTWARE":
                continue
            if case.rule_id.startswith("VS-EXP-") and case.rule_id not in {
                    "VS-EXP-REDIS-NOAUTH", "VS-EXP-REDIS-AUTH", "VS-EXP-REDIS",
                    "VS-EXP-MEMCACHED-NOAUTH", "VS-EXP-MEMCACHED",
                    "VS-EXP-DOCKER", "VS-EXP-MONGODB"}:
                rule = next(r for r in checks.EXPOSURE_RULES.values()
                            if r[0] == case.rule_id)
                with self.subTest(rule=case.slug):
                    self.assertEqual(rule[2], case.severity)
            elif case.rule_id.startswith("VS-HTTP-"):
                headers = {entry[1]: entry[3] for entry in checks.SECURITY_HEADERS}
                if case.rule_id in headers:
                    with self.subTest(rule=case.rule_id):
                        self.assertEqual(headers[case.rule_id], case.severity)


if __name__ == "__main__":
    unittest.main()
