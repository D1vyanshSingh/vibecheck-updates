"""Vulnerability checks: exposure, TLS, HTTP config, and version fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import advisories
from .scanner import (PORT_SERVICES, UNIDENTIFIED_SERVICE_NAMES, PortService,
                      http_fetch, send_recv)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

CITATION = "https://cwe.mitre.org/data/definitions/{n}.html"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    evidence: str
    remediation: str
    asset: dict
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    status: str = "open"
    id: str = ""
    # CVSS vector from the advisory source (NVD), when one exists. Rules
    # without one get a curated or band-baseline vector in the report.
    cvss_vector: str = ""

    @property
    def sort_key(self) -> int:
        return SEVERITY_ORDER.index(self.severity) if self.severity in SEVERITY_ORDER else 99


def _asset(svc: PortService, path: str = "") -> dict:
    asset = {
        "host": svc.host,
        "ip": svc.ip,
        "port": svc.port,
        "protocol": "tcp",
        "service": svc.service or "",
    }
    if path:
        scheme = "https" if (svc.tls or {}).get("ok") else "http"
        asset["url"] = f"{scheme}://{svc.host}:{svc.port}{path}"
    return asset


def _ref(*urls: str) -> list[str]:
    return list(urls)


def _cwe(*numbers: int) -> list[str]:
    return [f"CWE-{n}" for n in numbers]


# --------------------------------------------------------------------------
# Service identity: port numbers locate, protocols decide
# --------------------------------------------------------------------------

SERVICE_FAMILIES: dict[str, str] = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet",
    "smtp": "smtp", "submission": "smtp", "smtps": "smtp",
    "domain": "dns", "pop3": "pop3", "pop3s": "pop3",
    "imap": "imap", "imaps": "imap", "ldap": "ldap", "ldaps": "ldap",
    "http": "http", "https": "http", "http-proxy": "http",
    "http-alt": "http", "ssl/http": "http",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "smb": "smb",
    "ms-wbt-server": "rdp", "ms-wbt": "rdp", "rdp": "rdp",
    "vnc": "vnc",
    "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgres", "postgres": "postgres",
    "ms-sql-s": "mssql", "ms-sql": "mssql",
    "oracle": "oracle", "oracle-tns": "oracle",
    "mongodb": "mongo", "mongod": "mongo",
    "redis": "redis", "memcached": "memcached",
    "elasticsearch": "elastic",
    "docker": "docker", "docker-tls": "docker",
    "rsync": "rsync", "nfs": "nfs", "nfs_acl": "nfs",
    "wsman": "winrm", "winrm": "winrm",
    "rabbitmq": "rabbitmq", "kibana": "kibana",
    "prometheus": "prometheus", "kubernetes": "kubernetes",
    "etcd": "etcd", "kubelet": "kubelet",
    "ftp/smtp": "ftp-smtp",
}

# Identity sources that reflect something the service said or nmap probed.
STRONG_IDENTITY_SOURCES = {"nmap", "http", "banner"}
# nmap's own guess is only a claim when it version-probed the port (conf >= 8).
STRONG_NMAP_CONFIDENCE = 8
# Families that all ride HTTP: a Docker API and an HTTP response are not a
# disagreement, they are the same protocol seen two ways.
HTTP_RIDING_FAMILIES = {"http", "tls", "docker", "kubelet", "kibana", "rabbitmq",
                        "elastic", "prometheus", "kubernetes", "etcd", "winrm"}

# A port only decides which rules are worth running. The finding fires only
# when the identified protocol is in the rule's accepted families.
EXPECTED_FAMILIES: dict[int, frozenset[str]] = {
    23: frozenset({"telnet"}),
    2323: frozenset({"telnet"}),
    3389: frozenset({"rdp"}),
    445: frozenset({"smb"}),
    5900: frozenset({"vnc"}),
    5901: frozenset({"vnc"}),
    2376: frozenset({"docker", "http", "tls"}),
    10250: frozenset({"kubelet", "http"}),
    2379: frozenset({"etcd", "http"}),
    3306: frozenset({"mysql"}),
    5432: frozenset({"postgres"}),
    1433: frozenset({"mssql"}),
    1521: frozenset({"oracle"}),
    5985: frozenset({"winrm", "http"}),
    15672: frozenset({"rabbitmq", "http"}),
    5601: frozenset({"kibana", "http"}),
    2049: frozenset({"nfs"}),
    873: frozenset({"rsync"}),
    6443: frozenset({"kubernetes", "http", "tls"}),
    9090: frozenset({"prometheus", "http"}),
    9201: frozenset({"http"}),
}


def normalize_service(name: str) -> str:
    return (name or "").strip().lower().rstrip("?")


def service_family(svc: PortService) -> str:
    """Protocol family from the identity, then from transport-level facts."""
    family = SERVICE_FAMILIES.get(normalize_service(svc.service))
    if family:
        return family
    if svc.http is not None:
        return "http"
    if (svc.tls or {}).get("ok"):
        return "tls"
    return "unknown"


def identity_is_strong(svc: PortService) -> bool:
    return (svc.identity_source or "") in STRONG_IDENTITY_SOURCES


def _claim_is_strong(claim: dict) -> bool:
    """A claim counts only when the source actually proved something."""
    source = claim.get("source")
    if source == "nmap":
        try:
            if int(claim.get("confidence") or 0) < STRONG_NMAP_CONFIDENCE:
                return False
        except (TypeError, ValueError):
            return False
        # "tcpwrapped" carries a high conf value and no protocol: nmap is
        # saying it could not identify the port, so it cannot be a strong claim.
        return normalize_service(claim.get("service")) not in UNIDENTIFIED_SERVICE_NAMES
    return source in STRONG_IDENTITY_SOURCES


def _claim_family(claim: dict) -> str:
    family = SERVICE_FAMILIES.get(normalize_service(claim.get("service", "")))
    if not family:
        return ""
    return "http" if family in HTTP_RIDING_FAMILIES else family


def claims_conflict(claims: list[dict] | None) -> list[dict]:
    """Strong claims that disagree about the protocol, ignoring HTTP-riding ones."""
    strong = [claim for claim in (claims or []) if _claim_is_strong(claim)]
    if len(strong) < 2:
        return []
    families = {_claim_family(c) for c in strong}
    families.discard("")
    return strong if len(families) > 1 else []


def identity_conflicts(svc: PortService) -> list[dict]:
    """Strong identification claims on this service that disagree."""
    return claims_conflict(svc.identity_claims)


def _exposure_confidence(svc: PortService,
                         expected: frozenset[str]) -> str | None:
    """firm when the protocol matches, tentative when unidentified, None if contradicted."""
    if identity_conflicts(svc):
        return "tentative"
    if identity_is_strong(svc):
        return "firm" if service_family(svc) in expected else None
    return "tentative"


def _exposure_evidence(svc: PortService, expected: frozenset[str],
                       confidence: str) -> str:
    base = _banner_evidence(svc)
    if confidence != "tentative":
        return base
    wanted = " or ".join(sorted(expected)) or "the expected protocol"
    note = (f"{base} Nothing on the wire confirmed {wanted}; this is a "
            f"port-based lead, not a proven exposure.")
    conflicts = identity_conflicts(svc)
    if conflicts:
        claims = "; ".join(f"{c['source']}={(c.get('service') or '?')}"
                           for c in conflicts)
        note += f" Conflicting identifications: {claims}."
    return note


# --------------------------------------------------------------------------
# NSE script evidence: a script can prove what the port only suggested
# --------------------------------------------------------------------------

# Ports whose identity a curated script can confirm, plus the marker that
# shows the script got a real answer rather than an error or a timeout.
SERVICE_PROOF_SCRIPTS: dict[int, tuple[str, re.Pattern]] = {
    22: ("ssh-auth-methods",
         re.compile(r"supported authentication methods", re.I)),
    445: ("smb-os-discovery", re.compile(r"^\s*OS\s*:", re.M)),
    3389: ("rdp-ntlm-info",
           re.compile(r"(Product_Version|Target_Name|NetBIOS_Computer_Name)\s*:", re.I)),
}
DOCKER_SCRIPT = "docker-version"


def script_text(svc: PortService, *script_ids: str) -> str:
    """Output of the given NSE scripts for this service, or '' when none ran."""
    scripts = svc.scripts or {}
    return "\n".join((scripts.get(sid) or "").strip()
                     for sid in script_ids if (scripts.get(sid) or "").strip())


def _script_evidence(svc: PortService, *script_ids: str) -> str:
    """Formatted script output to append to a finding's evidence."""
    text = script_text(svc, *script_ids)
    if not text:
        return ""
    return f"\n\nnmap {'/'.join(script_ids)}:\n{text[:400]}"


def _service_proof(svc: PortService) -> str:
    """Script output that proves this port really runs the expected service."""
    entry = SERVICE_PROOF_SCRIPTS.get(svc.port)
    if not entry:
        return ""
    script_id, marker = entry
    text = script_text(svc, script_id)
    return text if text and marker.search(text) else ""


# App-layer probes that can prove an exposure rule's port claim. The probe
# itself is made by the scanner (scanner.APP_PROBES) and stored on
# ``PortService.app``; a 200 with the product's markers is protocol-level
# proof, 401/403 proves the product exists but requires authentication.
APP_PROOF_PORTS: dict[int, str] = {
    2375: "docker",
    2376: "docker",
    2379: "etcd",
    5601: "kibana",
    6443: "kubernetes",
    9090: "prometheus",
    10250: "kubelet",
    15672: "rabbitmq",
}


def _app_confidence(svc: PortService) -> tuple[str, str]:
    """(confidence, evidence) from the read-only app probe, or ("", "")."""
    name = APP_PROOF_PORTS.get(svc.port)
    probe = (svc.app or {}).get(name or "") or {}
    if not probe:
        return "", ""
    status = probe.get("status")
    evidence = (f"\n\nRead-only probe {probe.get('scheme', 'http')}://{svc.host}:"
                f"{svc.port}{probe.get('path', '/')} → {status}; response: "
                f"{probe.get('body', '')[:300]!r}")
    if status == 200 and probe.get("confirmed"):
        return "certain", evidence
    if status == 200 or status in (401, 403):
        # The endpoint answered, but without the product's markers (or with an
        # auth challenge): the service exists, anonymous access does not follow.
        return "firm", evidence
    return "", evidence


# --------------------------------------------------------------------------
# 1. Exposed-service checks (port/banner based)
# --------------------------------------------------------------------------

# rule_id, title, severity, cwe, description, impact, remediation
EXPOSURE_RULES: dict[int, tuple] = {
    23: ("VS-EXP-TELNET", "Telnet service exposed", "high", _cwe(319, 284),
         "A Telnet service is reachable on this host. Telnet transmits credentials "
         "and session data, including passwords, in cleartext.",
         "Anyone able to reach this port can capture credentials with a passive "
         "sniffer and may gain interactive shell access to the system.",
         "Disable Telnet and use SSH instead. If Telnet must stay, restrict it to a "
         "management network with firewall rules."),
    2323: ("VS-EXP-TELNET-ALT", "Telnet service exposed on alternate port", "high",
           _cwe(319, 284),
           "A Telnet service is reachable on a non-standard port. Telnet transmits "
           "credentials and session data in cleartext.",
           "Cleartext credentials can be captured by anyone on the network path, and "
           "an interactive shell may be available to remote attackers.",
           "Remove the service or replace it with SSH; restrict management ports to "
           "a trusted network."),
    3389: ("VS-EXP-RDP", "Remote Desktop (RDP) exposed to the network", "high",
           _cwe(284, 20),
           "The Microsoft Remote Desktop service is reachable from the scan source. "
           "Exposed RDP is a frequent target of brute-force attacks and credential "
           "stuffing, and was the primary vector for wormable flaws such as BlueKeep.",
           "Compromise of a workstation or server via guessed or reused credentials, "
           "leading to full user-session control and potential domain impact.",
           "Restrict RDP to a VPN or management network with firewall rules, enforce "
           "NLA, and disable direct internet exposure."),
    445: ("VS-EXP-SMB", "SMB file sharing exposed to the network", "high",
          _cwe(284, 319),
          "SMB (port 445) is reachable from the scan source. Exposed SMB exposes file "
          "shares to brute-force and exploitation attempts, and SMBv1 in particular "
          "is vulnerable to wormable flaws such as EternalBlue (CVE-2017-0144).",
          "Unauthorized access to shared files and directories, credential relay "
          "attacks, or remote code execution when SMBv1 is enabled.",
          "Block ports 445/139 at the perimeter, require VPN access for file sharing, "
          "and disable SMBv1."),
    5900: ("VS-EXP-VNC", "VNC service exposed to the network", "high",
           _cwe(319, 284),
           "A VNC service is reachable from the scan source. VNC streams the remote "
           "desktop in cleartext unless tunneled, and many deployments run without "
           "authentication or with passwords that are trivial to guess.",
           "A remote attacker can observe or take over the desktop session, gaining "
           "the same access as the logged-in user.",
           "Expose VNC only over an SSH or TLS tunnel, require strong passwords, and "
           "firewall the port to trusted hosts."),
    5901: ("VS-EXP-VNC", "VNC service exposed to the network", "high",
           _cwe(319, 284),
           "A VNC service is reachable from the scan source. VNC streams the remote "
           "desktop in cleartext unless tunneled, and many deployments run without "
           "authentication or with passwords that are trivial to guess.",
           "A remote attacker can observe or take over the desktop session.",
           "Expose VNC only over an SSH or TLS tunnel, require strong passwords, and "
           "firewall the port to trusted hosts."),
    2376: ("VS-EXP-DOCKER-TLS", "Docker daemon API exposed with TLS", "high",
           _cwe(306, 284),
           "The Docker daemon API is reachable over the network with TLS enabled. "
           "Anyone who can authenticate to it controls containers on this host.",
           "Full control of containers and images, container escape potential, and "
           "host-level compromise via privileged containers or mounted host paths.",
           "Restrict the Docker socket to localhost or a trusted management network "
           "and use client-certificate authentication."),
    10250: ("VS-EXP-KUBELET", "Kubelet API exposed to the network", "high",
            _cwe(306, 284),
            "The Kubernetes kubelet API (10250) is reachable from the scan source. "
            "Unauthenticated kubelet APIs allow listing and exec-ing into pods.",
            "Container takeover, secret theft from pod environments, and lateral "
            "movement inside the cluster.",
            "Enable kubelet authentication (--anonymous-auth=false) and restrict "
            "10250 to cluster-internal traffic."),
    2379: ("VS-EXP-ETCD", "etcd API exposed to the network", "high",
           _cwe(306, 284),
           "The etcd key-value store used by Kubernetes is reachable from the scan "
           "source. Unauthenticated etcd holds all cluster state including secrets.",
           "Read and write access to every secret in the cluster, enabling full "
           "cluster takeover.",
           "Bind etcd to localhost, require client certificates, and firewall the "
           "port."),
    3306: ("VS-EXP-MYSQL", "MySQL server exposed to the network", "medium",
           _cwe(284),
           "The MySQL listener is reachable from the scan source, so the database "
           "accepts connection attempts from hosts outside its own network.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Bind MySQL to localhost or restrict port 3306 to application servers with "
           "firewall rules."),
    5432: ("VS-EXP-POSTGRES", "PostgreSQL server exposed to the network", "medium",
           _cwe(284),
           "The PostgreSQL listener is reachable from the scan source, so the "
           "database accepts connection attempts from outside its own network.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Bind PostgreSQL to localhost or restrict port 5432 to application servers "
           "with firewall rules."),
    1433: ("VS-EXP-MSSQL", "MS SQL Server exposed to the network", "medium",
           _cwe(284),
           "The MS SQL Server listener is reachable from the scan source.",
           "Database credentials become subject to brute-force and known server "
           "exploits from any reachable host.",
           "Restrict port 1433 to trusted application servers and disable remote "
           "sa logins."),
    1521: ("VS-EXP-ORACLE", "Oracle TNS listener exposed to the network", "medium",
           _cwe(284),
           "The Oracle TNS listener is reachable from the scan source.",
           "Database credentials become subject to brute-force and listener exploits "
           "from any reachable host.",
           "Restrict port 1521 to trusted networks and enable Valid Node Checking."),
    5985: ("VS-EXP-WINRM", "WinRM service exposed over cleartext HTTP", "high",
           _cwe(319, 284),
           "Windows Remote Management (HTTP) is reachable from the scan source. "
           "WinRM over HTTP sends credentials and shell traffic unencrypted.",
           "Credential theft and remote shell access to the Windows host.",
           "Require WinRM over HTTPS (5986) with Kerberos, and firewall port 5985."),
    15672: ("VS-EXP-RABBITMQ", "RabbitMQ management console exposed", "medium",
            _cwe(284, 200),
            "The RabbitMQ management interface is reachable from the scan source. "
            "Internet-facing management consoles are routinely brute-forced.",
            "Exposure of message queues, credentials and routing topology, plus the "
            "ability to publish or consume messages.",
            "Bind the management plugin to localhost or restrict it to an admin "
            "network with strong credentials."),
    5601: ("VS-EXP-KIBANA", "Kibana dashboard exposed to the network", "medium",
           _cwe(284, 200),
           "Kibana is reachable from the scan source. Without authentication it "
           "discovers and visualizes the contents of the Elasticsearch index.",
           "Exposure of indexed data such as logs, user records or business data.",
           "Place Kibana behind authentication and restrict it to an internal "
           "network."),
    2049: ("VS-EXP-NFS", "NFS file sharing exposed to the network", "medium",
           _cwe(284),
           "The NFS service is reachable from the scan source.",
           "Unauthorized mounts and reads of exported filesystems, subject to "
           "client-side export and uid-mapping weaknesses.",
           "Restrict exports with squash options and firewall port 2049 to trusted "
           "hosts."),
    873: ("VS-EXP-RSYNC", "rsync daemon exposed to the network", "medium",
          _cwe(284, 319),
          "The rsync daemon is reachable from the scan source and often allows "
          "anonymous reads of configured modules.",
          "Read (and sometimes write) access to synced directories and disclosure of "
          "sensitive files.",
          "Disable the rsync daemon where unused, require auth, and firewall the "
          "port."),
    6443: ("VS-EXP-K8S-API", "Kubernetes API server exposed", "informational",
           _cwe(284),
           "The Kubernetes API server is reachable from the scan source. Exposure is "
           "expected for managed clusters, but unauthenticated endpoints should be "
           "audited.",
           "Anonymous or stolen-credential access to cluster resources if RBAC "
           "misconfigures anonymous-auth endpoints.",
           "Verify anonymous-auth is disabled and API access is gated by network "
           "policy."),
    9090: ("VS-EXP-PROMETHEUS", "Prometheus metrics endpoint exposed", "low",
           _cwe(200),
           "A Prometheus metrics endpoint is reachable from the scan source. Metrics "
           "often include hostnames, process lists and internal service names.",
           "Internal topology and host details become visible to an attacker "
           "scanning from outside.",
           "Restrict metrics endpoints to an internal monitoring network or require "
           "authentication."),
    9201: ("VS-EXP-ADMIN", "Administrative service on a public interface", "low",
           _cwe(284),
           "A service commonly used for administration is reachable from the scan "
           "source.",
           "Administrative interfaces facing untrusted networks are prime brute-force "
           "and exploit targets.",
           "Move administrative services behind a VPN or management network."),
}


def check_exposure(svc: PortService) -> list[Finding]:
    findings: list[Finding] = []
    rule = EXPOSURE_RULES.get(svc.port)
    if rule:
        rule_id, title, severity, cwe, desc, impact, fix = rule
        expected = EXPECTED_FAMILIES.get(svc.port, frozenset())
        confidence = _exposure_confidence(svc, expected)
        proof = _service_proof(svc)
        if confidence == "tentative" and proof:
            # A curated script queried the service and got a real answer: that
            # is identification, not a port-table guess.
            confidence = "firm"
        app_confidence, app_evidence = _app_confidence(svc)
        if app_confidence == "certain":
            confidence = "certain"
        elif app_confidence and confidence in (None, "tentative"):
            confidence = "firm"
        if confidence:
            evidence = _exposure_evidence(svc, expected, confidence)
            if proof:
                evidence += _script_evidence(
                    svc, SERVICE_PROOF_SCRIPTS[svc.port][0])
            if app_confidence:
                evidence += app_evidence
            findings.append(Finding(
                rule_id=rule_id, title=title, severity=severity,
                confidence=confidence,
                description=desc, impact=impact,
                evidence=evidence,
                remediation=fix, asset=_asset(svc),
                cwe=cwe, references=_ref(CITATION.format(n=cwe[0].split("-")[1]))))

    # Evidence-driven services are keyed by protocol, not by port number, so a
    # Redis on 6380 is still found and a web server on 6379 is not called Redis.
    findings.extend(_check_redis(svc))
    findings.extend(_check_special_service(svc))
    return findings


def _is_textual(text: str) -> bool:
    """True when a banner is readable text rather than protocol bytes."""
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text) >= 0.85


def _banner_evidence(svc: PortService) -> str:
    if svc.banner:
        identity = f"Port {svc.port}/tcp is open and identified as " \
                   f"{svc.service or 'unknown service'}"
        if _is_textual(svc.banner):
            return f"{identity}. Banner: {svc.banner[:300]!r}"
        # Binary handshakes (MongoDB, MySQL, PostgreSQL) belong in the JSON,
        # not as escaped control bytes on a client's finding card.
        return f"{identity}, from its protocol handshake."
    return f"Port {svc.port}/tcp is open and identified as " \
           f"{svc.service or PORT_SERVICES.get(svc.port, 'a service')}."


def _check_redis(svc: PortService) -> list[Finding]:
    family = service_family(svc)
    if family not in ("redis", "unknown"):
        return []                      # an identified non-Redis service
    banner = svc.banner or ""
    if "redis_version" in banner:
        return [Finding(
            rule_id="VS-EXP-REDIS-NOAUTH",
            title="Redis exposed without authentication",
            severity="critical", confidence="certain",
            description="The INFO command returned server details without requiring "
                        "authentication, confirming that this Redis instance accepts "
                        "commands from unauthenticated clients.",
            impact="Full read and write access to cached data, session tokens and "
                   "job queues. Crafted payloads can lead to remote code execution "
                   "via CONFIG SET and module loading.",
            evidence=f"INFO server response (no AUTH required): {banner[:300]!r}",
            remediation="Set 'requirepass' (or ACL users), bind Redis to trusted "
                        "interfaces only, and firewall port 6379.",
            asset=_asset(svc), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306),
                            "https://redis.io/docs/latest/operate/oss_and_stack/"
                            "management/security/"))]
    if "NOAUTH" in banner or "authentication required" in banner.lower():
        return [Finding(
            rule_id="VS-EXP-REDIS-AUTH",
            title="Redis reachable from the network",
            severity="medium", confidence="firm",
            description="A Redis instance is reachable from the scan source and "
                        "requires authentication (the INFO command was rejected).",
            impact="The instance is exposed to password-guessing attacks; weak or "
                   "default passwords would give access to cached data and queues.",
            evidence=f"INFO server response: {banner[:300]!r}",
            remediation="Bind Redis to localhost or a private network and firewall "
                        "port 6379 even when authentication is enabled.",
            asset=_asset(svc), cwe=_cwe(284),
            references=_ref(CITATION.format(n=284)))]
    if family == "redis" or svc.port == 6379:
        return [Finding(
            rule_id="VS-EXP-REDIS", title="Redis reachable from the network",
            severity="medium", confidence="tentative",
            description="A listener on this port is reachable and looks like Redis, "
                        "but the banner did not reveal whether authentication is "
                        "required.",
            impact="If authentication is absent or weak, cached data and session "
                   "tokens are readable and writable by remote clients.",
            evidence=_banner_evidence(svc),
            remediation="Set 'requirepass', bind to trusted interfaces, and firewall "
                        "port 6379.",
            asset=_asset(svc), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306)))]
    return []


def _check_special_service(svc: PortService) -> list[Finding]:
    """Checks whose result depends on what the service actually answered.

    The port decides which checks are worth running; the protocol family
    decides whether a finding is allowed to fire.
    """
    banner = svc.banner or ""
    family = service_family(svc)
    http = svc.http or {}
    body = (http.get("body_preview") or "").lower()
    product = (svc.product or "").lower()

    def contradicted(*families: str) -> bool:
        return identity_is_strong(svc) and family not in families

    if (svc.port == 11211 or family == "memcached") and not contradicted("memcached"):
        if "STAT " in banner:
            return [Finding(
                rule_id="VS-EXP-MEMCACHED-NOAUTH",
                title="Memcached exposed without authentication",
                severity="critical", confidence="certain",
                description="The memcached stats command returned server statistics "
                            "without authentication, confirming unauthenticated access.",
                impact="Read/write access to cached objects (sessions, tokens), plus "
                       "historical use of memcached for UDP amplification DDoS.",
                evidence=f"stats response: {banner[:300]!r}",
                remediation="Disable UDP listeners (-U 0), bind to localhost, set "
                            "'-A' access control, and firewall port 11211.",
                asset=_asset(svc), cwe=_cwe(306),
                references=_ref(CITATION.format(n=306)))]
        return [Finding(
            rule_id="VS-EXP-MEMCACHED", title="Memcached reachable from the network",
            severity="medium",
            confidence=("firm" if family == "memcached" and identity_is_strong(svc)
                        else "tentative"),
            description="A memcached listener is reachable from the scan source.",
            impact="Cached sessions or tokens may be readable, and UDP exposure can "
                   "abuse the service for amplification attacks.",
            evidence=_banner_evidence(svc),
            remediation="Bind memcached to localhost, disable UDP, and firewall the "
                        "port.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]

    if (svc.port == 2375 or family == "docker") and not contradicted("docker", "http"):
        docker_script = _script_evidence(svc, DOCKER_SCRIPT)
        docker_probe = (svc.app or {}).get("docker") or {}
        probe_proves = (docker_probe.get("status") == 200
                        and docker_probe.get("confirmed"))
        is_docker = ("docker" in product or "docker" in body
                     or "apiversion" in body or bool(docker_script)
                     or probe_proves)
        if probe_proves or docker_script:
            confidence = "certain"
        elif is_docker:
            confidence = "firm"
        else:
            confidence = "tentative"
        probe_evidence = (
            f"\n\nRead-only probe GET /version → {docker_probe.get('status')}; "
            f"response: {docker_probe.get('body', '')[:300]!r}"
            if docker_probe else "")
        return [Finding(
            rule_id="VS-EXP-DOCKER", title="Docker daemon API exposed without TLS",
            severity="critical", confidence=confidence,
            description=("The Docker daemon API is reachable over plain HTTP. Anyone "
                         "who can reach it fully controls the Docker daemon on this host."
                         if is_docker else
                         "Port 2375 answers HTTP without TLS. That is the Docker "
                         "daemon's default API port, but the response did not carry "
                         "Docker markers, so the daemon itself is unconfirmed."),
            impact="Remote code execution: an attacker can start a privileged "
                   "container, mount the host filesystem, and take over the machine.",
            evidence=((f"{_banner_evidence(svc)} Body: {body[:200]!r}"
                       if is_docker else
                       f"{_banner_evidence(svc)} No Docker API markers in the "
                       f"response.") + docker_script + probe_evidence),
            remediation="Disable the plain-HTTP Docker socket (-H fd:// without "
                        "tcp:// binding), require TLS on 2376, and firewall the port.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]

    if (svc.port == 27017 or family == "mongo") and not contradicted("mongo"):
        mongo = (svc.app or {}).get("mongo") or {}
        confidence = ("firm" if family == "mongo" and identity_is_strong(svc)
                      else "tentative")
        description = ("A MongoDB listener is reachable from the scan source. "
                       "Unauthenticated MongoDB instances are scanned and exploited "
                       "within minutes of being exposed.")
        evidence = _banner_evidence(svc)
        version = f" (server {mongo['version']})" if mongo.get("version") else ""
        if mongo.get("open"):
            confidence = "certain"
            description = ("The MongoDB handshake answered a read-only "
                           f"listDatabases command without authentication{version}, "
                           "so the database accepts unauthenticated clients.")
            evidence += (f"\n\nlistDatabases reply (no credentials sent): "
                         f"{mongo.get('body', '')[:300]!r}")
        elif mongo.get("auth_required"):
            confidence = "firm"
            description = ("A MongoDB server is reachable from the scan source and "
                           f"answers the handshake{version}, but it rejects "
                           "unauthenticated commands (authorization is enabled).")
            evidence += (f"\n\nHandshake/listDatabases reply: "
                         f"{mongo.get('body', '')[:300]!r}")
        return [Finding(
            rule_id="VS-EXP-MONGODB", title="MongoDB exposed to the network",
            severity="high", confidence=confidence,
            description=description,
            impact="Read and write access to the entire database when authorization "
                   "is absent; historically the most common cause of large cloud "
                   "data leaks.",
            evidence=evidence,
            remediation="Enable authorization (security.authorization: enabled), bind "
                        "to trusted interfaces, and firewall port 27017.",
            asset=_asset(svc), cwe=_cwe(306), references=_ref(CITATION.format(n=306)))]
    if svc.port == 21:
        return []  # covered by the anonymous-FTP check
    return []


async def check_ftp_anonymous(services: list[PortService], timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.state != "open":
            continue
        family = service_family(svc)
        banner = (svc.banner or "").lower()
        looks_ftp = (family == "ftp"
                     or "vsftpd" in banner or "multicraft" in banner
                     or (family == "unknown" and not identity_is_strong(svc)
                         and svc.port in (21, 2121)))
        if not looks_ftp:
            continue              # never send FTP logins to an identified non-FTP service
        response = await send_recv(
            svc.ip, svc.port, b"USER anonymous\r\nPASS guest@vulnscan.local\r\n",
            timeout)
        if re.search(r"\b230\b", response):
            findings.append(Finding(
                rule_id="VS-FTP-ANON",
                title="Anonymous FTP login allowed", severity="high",
                confidence="certain",
                description="The FTP server accepted an anonymous login, letting any "
                            "unauthenticated client list and transfer files.",
                impact="Unauthorized read (and on misconfigured sites, write) access "
                       "to every file in the public tree, including backups or "
                       "credentials left there.",
                evidence=f"USER anonymous → server replied: {response[:300]!r}",
                remediation="Set 'anon_enable=NO' in the FTP configuration, or "
                            "restrict anonymous accounts to a read-only empty jail.",
                asset=_asset(svc), cwe=_cwe(22, 306),
                references=_ref(CITATION.format(n=306))))
        if family == "ftp" or svc.port == 21:
            findings.append(Finding(
                rule_id="VS-FTP-CLEARTEXT",
                title="FTP credentials sent in cleartext", severity="low",
                confidence=("certain" if identity_is_strong(svc) else "tentative"),
                description="The FTP service exchanges usernames and "
                            "passwords without encryption (no TLS observed).",
                impact="Credentials can be captured by anyone able to observe "
                       "traffic on the network path.",
                evidence=f"Port {svc.port} open. Banner: {svc.banner[:200]!r}",
                remediation="Require FTPS (explicit TLS) or replace FTP with SFTP.",
                asset=_asset(svc), cwe=_cwe(319),
                references=_ref(CITATION.format(n=319))))
    return findings


# --------------------------------------------------------------------------
# 2. TLS certificate and protocol checks
# --------------------------------------------------------------------------

def check_tls(svc: PortService, legacy_versions: dict | None = None) -> list[Finding]:
    tls = svc.tls or {}
    if not tls.get("ok"):
        return []
    findings: list[Finding] = []
    cert = tls.get("cert") or {}

    if cert.get("expired"):
        findings.append(Finding(
            rule_id="VS-TLS-EXPIRED", title="TLS certificate has expired",
            severity="high", confidence="certain",
            description="The presented certificate is past its notAfter date, so "
                        "clients reject the connection as untrusted.",
            impact="Users see a security warning, and automated clients fail; an "
                   "expired cert on an HTTPS endpoint often signals an abandoned or "
                   "unmonitored system.",
            evidence=f"Subject {cert.get('subject')!r}, issuer {cert.get('issuer')!r}, "
                     f"expired {cert.get('not_after')!r}.",
            remediation="Renew the certificate and automate renewal before expiry.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))
    elif cert.get("not_yet_valid"):
        findings.append(Finding(
            rule_id="VS-TLS-NOT-YET-VALID", title="TLS certificate is not yet valid",
            severity="medium", confidence="certain",
            description="The certificate's notBefore date is in the future, usually "
                        "caused by clock skew or a misconfigured deployment.",
            impact="Clients reject the connection until the clock or certificate is "
                   "corrected.",
            evidence=f"Valid from {cert.get('not_before')!r}.",
            remediation="Check host clock sync (NTP) and redeploy the certificate.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))
    else:
        days = cert.get("days_remaining")
        if isinstance(days, int) and days < 14:
            findings.append(Finding(
                rule_id="VS-TLS-EXPIRING", title="TLS certificate expires soon",
                severity="medium", confidence="certain",
                description=f"The certificate expires in {days} day(s); "
                            "once expired, clients will refuse the connection.",
                impact="Service outage for TLS clients once the certificate lapses.",
                evidence=f"notAfter {cert.get('not_after')!r} ({days} days remaining).",
                remediation="Renew the certificate now and automate renewal.",
                asset=_asset(svc), cwe=_cwe(295),
                references=_ref(CITATION.format(n=295))))

    if cert.get("self_signed"):
        findings.append(Finding(
            rule_id="VS-TLS-SELF-SIGNED", title="Self-signed TLS certificate",
            severity="low", confidence="certain",
            description="The certificate is signed by its own subject rather than a "
                        "trusted certificate authority, so clients cannot establish "
                        "trust in the server's identity.",
            impact="Browsers warn users, training them to click through warnings; "
                   "man-in-the-middle attacks become indistinguishable from the "
                   "legitimate certificate.",
            evidence=f"Subject {cert.get('subject')!r} == issuer {cert.get('issuer')!r}.",
            remediation="Issue the certificate from a trusted CA (Let's Encrypt is "
                        "free) or add the internal CA to trusted stores.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))

    if cert.get("hostname_matches") is False:
        findings.append(Finding(
            rule_id="VS-TLS-HOSTNAME", title="Certificate does not match the hostname",
            severity="medium", confidence="firm",
            description="None of the certificate's subject alternative names cover "
                        "the scanned host, so clients fail hostname verification.",
            impact="TLS clients reject the connection; if users bypass the warning, "
                   "the connection may be a spoof.",
            evidence=f"Scanned host {svc.host!r}; SANs {cert.get('san')!r}.",
            remediation="Reissue the certificate including this host in the SAN list.",
            asset=_asset(svc), cwe=_cwe(295),
            references=_ref(CITATION.format(n=295))))

    cipher = (tls.get("cipher") or "").upper()
    if any(token in cipher for token in ("NULL", "EXPORT", "RC4", "DES-CBC3", "Anon")):
        findings.append(Finding(
            rule_id="VS-TLS-WEAK-CIPHER", title="Weak TLS cipher negotiated",
            severity="high", confidence="certain",
            description="The handshake selected a cipher suite with broken or "
                        "obsolete encryption.",
            impact="Session traffic can be decrypted or tampered with offline.",
            evidence=f"Negotiated cipher: {tls.get('cipher')!r} "
                     f"({tls.get('cipher_bits')} bits), {tls.get('version')}.",
            remediation="Disable export, NULL, RC4 and 3DES cipher suites; prefer "
                        "AEAD suites (AES-GCM, ChaCha20-Poly1305).",
            asset=_asset(svc), cwe=_cwe(327),
            references=_ref(CITATION.format(n=327))))

    if legacy_versions:
        legacy = [name for name, supported in legacy_versions.items() if supported]
        if legacy:
            findings.append(Finding(
                rule_id="VS-TLS-LEGACY",
                title=f"Legacy TLS versions accepted ({', '.join(legacy)})",
                severity="medium", confidence="firm",
                description="The server completes handshakes with outdated TLS "
                            "versions, which are subject to downgrade and padding "
                            "oracle style attacks (BEAST, POODLE).",
                impact="Downgrade attacks and weak-cipher exploitation against "
                       "legacy protocol versions.",
                evidence=f"Handshake succeeded with: {', '.join(legacy)}; "
                         f"current version: {tls.get('version')}.",
                remediation="Set the minimum protocol version to TLS 1.2 "
                            "(ideally TLS 1.3) and disable TLS 1.0/1.1.",
                asset=_asset(svc), cwe=_cwe(326),
                references=_ref(CITATION.format(n=326))))

    # nmap's ssl-cert ran the same handshake independently; where we already
    # report a certificate problem, quote its findings as corroboration.
    cert_script = _script_evidence(svc, "ssl-cert")
    if cert_script:
        for finding in findings:
            if finding.rule_id.startswith(("VS-TLS-EXPIRED", "VS-TLS-SELF-SIGNED",
                                           "VS-TLS-HOSTNAME", "VS-TLS-EXPIRING",
                                           "VS-TLS-WEAK-CIPHER")):
                finding.evidence += cert_script

    return findings


# --------------------------------------------------------------------------
# 3. HTTP configuration checks
# --------------------------------------------------------------------------

SECURITY_HEADERS = [
    ("strict-transport-security", "VS-HTTP-HSTS", "missing HTTP Strict "
     "Transport Security (HSTS) header", "medium", _cwe(319),
     "The HTTPS response does not set Strict-Transport-Security, so browsers will "
     "still honour plain-HTTP requests to this host.",
     "An attacker can strip the connection down to HTTP and capture credentials or "
     "session cookies (SSL stripping).",
     "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all "
     "HTTPS responses."),
    ("content-security-policy", "VS-HTTP-CSP", "missing Content-Security-Policy "
     "header", "medium", _cwe(693),
     "The response has no Content-Security-Policy, leaving cross-site scripting "
     "defences to browser defaults.",
     "Injected scripts execute freely, turning any XSS into full account takeover.",
     "Define a CSP that restricts script sources and disallows inline script; start "
     "with report-only mode and tighten."),
    ("x-frame-options", "VS-HTTP-XFO", "missing X-Frame-Options / frame-ancestors "
     "protection", "low", _cwe(1021),
     "The response can be framed by third-party pages because neither X-Frame-Options "
     "nor a frame-ancestors CSP directive is set.",
     "Clickjacking: attackers overlay the page to trick users into clicking controls "
     "they cannot see.",
     "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a "
     "'frame-ancestors' CSP directive."),
    ("x-content-type-options", "VS-HTTP-XCTO", "missing X-Content-Type-Options "
     "header", "low", _cwe(693),
     "The response omits X-Content-Type-Options: nosniff, so browsers may guess the "
     "content type of responses.",
     "MIME-sniffing attacks can turn an uploaded file or text response into active "
     "script in the page's origin.",
     "Send 'X-Content-Type-Options: nosniff' on every response."),
    ("referrer-policy", "VS-HTTP-REFPOL", "missing Referrer-Policy header",
     "informational", _cwe(200),
     "Without Referrer-Policy, full URLs (including query strings and session "
     "tokens) leak to third-party sites through the Referer header.",
     "Disclosure of URLs, tokens or identifiers to external origins.",
     "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
]

HEADER_RULE_BY_KEY = {entry[1]: entry for entry in SECURITY_HEADERS}


def check_http(svc: PortService) -> list[Finding]:
    http = svc.http
    if not http or http.get("status", 0) == 0:
        return []
    findings: list[Finding] = []
    headers = http.get("headers", {}) or {}
    is_https = http.get("scheme") == "https"
    is_admin_path = svc.port in (2375, 2376, 5601, 9200, 15672, 9090, 8500)

    for key, rule_id, title, severity, cwe, desc, impact, fix in SECURITY_HEADERS:
        if key in headers:
            continue
        if key == "strict-transport-security" and not is_https:
            continue
        if key == "x-frame-options" and "frame-ancestors" in headers.get(
                "content-security-policy", "").lower():
            continue
        findings.append(Finding(
            rule_id=rule_id, title=f"Web service on port {svc.port} is {title}",
            severity=severity, confidence="certain",
            description=desc, impact=impact,
            evidence=f"GET {http.get('path', '/')} {http.get('scheme')}://{svc.host}:"
                     f"{svc.port} returned {http.get('status')} without a "
                     f"{key!r} header. Response headers: "
                     f"{', '.join(sorted(headers))}.",
            remediation=fix, asset=_asset(svc, http.get("path", "/")),
            cwe=cwe, references=_ref(CITATION.format(n=cwe[0].split("-")[1]))))

    server = http.get("server", "")
    if re.search(r"/\d+[\d.]*", server):
        findings.append(Finding(
            rule_id="VS-HTTP-SERVER-VERSION",
            title=f"Server version disclosed in HTTP header ({server})",
            severity="low", confidence="certain",
            description="The Server header reveals the exact web server software and "
                        "version, removing the guessing an attacker would otherwise "
                        "do when matching CVEs.",
            impact="Targeted exploitation of version-specific vulnerabilities.",
            evidence=f"Server: {server!r}",
            remediation="Suppress version information (e.g. 'server_tokens off;' in "
                        "nginx, 'ServerTokens Prod' in Apache).",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(200),
            references=_ref(CITATION.format(n=200))))

    powered = http.get("powered_by", "")
    if powered:
        findings.append(Finding(
            rule_id="VS-HTTP-POWERED-BY",
            title=f"Framework version disclosed (X-Powered-By: {powered})",
            severity="low", confidence="certain",
            description="An X-Powered-By header discloses the application stack to "
                        "any unauthenticated client.",
            impact="Easier targeted exploitation using stack-specific exploits.",
            evidence=f"X-Powered-By: {powered!r}",
            remediation="Remove the X-Powered-By header in the framework or "
                        "web-server configuration.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(200),
            references=_ref(CITATION.format(n=200))))

    body = http.get("body_preview", "") or ""
    if re.search(r"(?i)index of\s*/", body) or "Parent Directory" in body:
        findings.append(Finding(
            rule_id="VS-HTTP-DIR-LISTING", title="Directory listing enabled",
            severity="medium", confidence="certain",
            description="The web server returns an automatic directory index, "
                        "revealing every file in the folder.",
            impact="Disclosure of files never meant to be linked — backups, config "
                   "dumps, source archives — which are trivial to download.",
            evidence=f"GET {http.get('path', '/')} returned {http.get('status')} "
                     f"with an autoindex page; title {http.get('title')!r}.",
            remediation="Disable autoindex/directory listing and serve an explicit "
                        "index file or 404.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(548),
            references=_ref(CITATION.format(n=548))))

    if re.search(r"(?i)(traceback \(most recent call last\)|java\.lang\.\w+Exception|"
                 r"System\.\w+Exception|Stack trace:)", body):
        findings.append(Finding(
            rule_id="VS-HTTP-STACKTRACE", title="Verbose error page leaks stack trace",
            severity="medium", confidence="certain",
            description="The application returned a raw exception stack trace to an "
                        "unauthenticated request.",
            impact="Discloses internal paths, framework versions and query structure "
                   "that directly aid injection and path-traversal attacks.",
            evidence=f"Response body contains a stack trace; snippet: "
                     f"{body[:300]!r}",
            remediation="Return generic error pages in production and log details "
                        "server-side only.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(209),
            references=_ref(CITATION.format(n=209))))

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies = set_cookie
        if "secure" not in cookies.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-COOKIE-NO-SECURE",
                title="Cookie set without the Secure attribute", severity="medium",
                confidence="firm",
                description="A cookie is issued without the Secure flag, so browsers "
                            "send it over plain-HTTP connections.",
                impact="Session cookies can be stolen by an attacker on the network "
                       "path (credential/session hijacking).",
                evidence=f"Set-Cookie: {cookies[:300]!r}",
                remediation="Add the Secure attribute to all cookies issued over "
                            "HTTPS.",
                asset=_asset(svc, http.get("path", "/")), cwe=_cwe(614),
                references=_ref(CITATION.format(n=614))))
        if "httponly" not in cookies.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-COOKIE-NO-HTTPONLY",
                title="Cookie set without the HttpOnly attribute", severity="low",
                confidence="firm",
                description="A cookie lacks the HttpOnly flag, so page scripts can "
                            "read it.",
                impact="Any cross-site scripting bug becomes a direct session-theft "
                       "bug.",
                evidence=f"Set-Cookie: {cookies[:300]!r}",
                remediation="Add the HttpOnly attribute to session cookies.",
                asset=_asset(svc, http.get("path", "/")), cwe=_cwe(1004),
                references=_ref(CITATION.format(n=1004))))

    if not is_https and svc.port not in (2375, 2376) and not is_admin_path:
        findings.append(Finding(
            rule_id="VS-HTTP-CLEARTEXT",
            title=f"Web service on port {svc.port} served over plaintext HTTP",
            severity="informational", confidence="certain",
            description="The service answers plain HTTP with no TLS listener "
                        "observed, so all request and response traffic crosses the "
                        "network unencrypted.",
            impact="Credentials, cookies and page content are readable and modifiable "
                   "by anyone on the path.",
            evidence=f"HTTP GET {http.get('scheme')}://{svc.host}:{svc.port}"
                     f"{http.get('path', '/')} → {http.get('status')} "
                     f"{http.get('reason', '')} (no TLS).",
            remediation="Terminate TLS in front of the service and redirect HTTP to "
                        "HTTPS.",
            asset=_asset(svc, http.get("path", "/")), cwe=_cwe(319),
            references=_ref(CITATION.format(n=319))))

    findings.extend(_check_admin_exposure(svc, http))
    return findings


def _check_admin_exposure(svc: PortService, http: dict) -> list[Finding]:
    """Management consoles and framework fingerprints visible over HTTP."""
    findings: list[Finding] = []
    body = http.get("body_preview", "") or ""
    title = (http.get("title") or "").lower()

    if svc.port == 9200:
        if http.get("status") == 200 and "cluster" in body.lower():
            findings.append(Finding(
                rule_id="VS-HTTP-ES-OPEN",
                title="Elasticsearch cluster accessible without authentication",
                severity="critical", confidence="certain",
                description="The Elasticsearch root endpoint answered successfully "
                            "without credentials, so the cluster is open to anyone "
                            "who can reach it.",
                impact="Full read of indexed data (often logs or personal records) "
                       "and write access via the update and delete APIs.",
                evidence=f"GET http://{svc.host}:9200/ → {http.get('status')}; "
                         f"body: {body[:300]!r}",
                remediation="Enable X-Pack security or place Elasticsearch behind an "
                            "authenticated reverse proxy; bind to localhost.",
                asset=_asset(svc, "/"), cwe=_cwe(306),
                references=_ref(CITATION.format(n=306))))
        elif http.get("status") in (401, 403):
            findings.append(Finding(
                rule_id="VS-HTTP-ES-EXPOSED",
                title="Elasticsearch reachable from the network", severity="medium",
                confidence="firm",
                description="Elasticsearch responds to unauthenticated requests with "
                            "401/403 — authentication is on, but the port is exposed.",
                impact="Subject to brute-force and known vulnerability scans; index "
                       "data is at risk if credentials are weak.",
                evidence=f"GET http://{svc.host}:9200/ → {http.get('status')}.",
                remediation="Restrict port 9200 to trusted networks.",
                asset=_asset(svc, "/"), cwe=_cwe(284),
                references=_ref(CITATION.format(n=284))))

    docker_markers = ("docker" in body.lower()
                      or "apiversion" in body.lower()
                      or "docker" in (http.get("server") or "").lower())
    if svc.port in (2375, 2376) and http.get("status") == 200 and docker_markers:
        findings.append(Finding(
            rule_id="VS-HTTP-DOCKER-VERSION",
            title="Docker daemon API responds over HTTP", severity="critical",
            confidence="certain",
            description="The Docker engine API answered an unauthenticated request "
                        "on this port.",
            impact="Remote code execution: containers, images and volumes are fully "
                   "controllable by anyone who can reach the API.",
            evidence=f"GET {http.get('scheme')}://{svc.host}:{svc.port}/version → "
                     f"{http.get('status')}; body: {body[:300]!r}",
            remediation="Remove the tcp:// Docker socket binding; keep the API on a "
                        "UNIX socket with TLS client auth if remote access is needed.",
            asset=_asset(svc, "/"), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306))))

    if svc.port in (5601, 15672, 9090, 8500, 8983, 5985) and http.get("status") == 200:
        findings.append(Finding(
            rule_id="VS-HTTP-ADMIN-OPEN",
            title=f"Administrative web console responding without authentication "
                  f"({svc.service or svc.port})",
            severity="high", confidence="firm",
            description="A management console returned HTTP 200 to an "
                        "unauthenticated request from the scan source.",
            impact="Exposure of operational data and, depending on the product, "
                   "control over the underlying system.",
            evidence=f"GET {http.get('scheme')}://{svc.host}:{svc.port}/ → "
                     f"{http.get('status')}; title {http.get('title')!r}.",
            remediation="Put the console behind authentication and restrict it to an "
                        "administrative network.",
            asset=_asset(svc, "/"), cwe=_cwe(306),
            references=_ref(CITATION.format(n=306))))
    return findings


# --------------------------------------------------------------------------
# 4. Version fingerprints → known CVEs and end-of-life software
# --------------------------------------------------------------------------

def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:4])


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    size = max(len(a), len(b))
    return a + (0,) * (size - len(a)), b + (0,) * (size - len(b))


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return _pad(a, b)[0] < _pad(a, b)[1]


def _le(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return _pad(a, b)[0] <= _pad(a, b)[1]


_ADVISORY_IMPACT = {
    "critical": "Likely unauthenticated remote compromise of the service if the "
                "affected code path is reachable.",
    "high": "Serious loss of confidentiality, integrity or availability of the "
            "service when the flaw is triggered.",
    "medium": "Limited impact, usually requiring specific conditions, a "
              "configuration choice, or prior access.",
    "low": "Minimal direct impact; typically a stepping stone or a hardening "
           "issue.",
}


def _affected_range(advisory: "advisories.Advisory") -> str:
    if advisory.introduced and advisory.fixed:
        return f"versions >= {advisory.introduced} and < {advisory.fixed}"
    if advisory.introduced:
        return f"versions >= {advisory.introduced}"
    if advisory.fixed:
        return f"versions before {advisory.fixed}"
    return "the affected release"


def _advisory_findings(svc: PortService, db, skip_cves: set[str]) -> list[Finding]:
    """Version-range matches from the offline advisory database."""
    if db is None or not db.available or not svc.version:
        return []
    key = advisories.product_key(svc.product or "")
    if not key:
        return []
    version, distro = advisories.split_version(
        svc.version, svc.extrainfo or "", (svc.http or {}).get("server", ""),
        svc.banner or "")
    if not advisories.parse_version(version):
        return []

    findings: list[Finding] = []
    for advisory in db.lookup(key, version):
        if advisory.cve in skip_cves:
            continue
        # Upstream version in range = firm. A distro package revision may carry
        # a backported fix, so the same match is only tentative there.
        confidence = "tentative" if distro else "firm"
        description = advisory.summary or (
            f"{advisory.cve} lists {svc.product} {version} as affected.")
        evidence = (f"Detected {svc.product} {version} on "
                    f"{svc.host}:{svc.port}; {advisory.cve} covers "
                    f"{_affected_range(advisory)}.")
        if distro:
            description += (f" This build carries a {distro} package revision, "
                            "and distributors frequently backport security fixes "
                            "without changing the upstream version — verify the "
                            "package changelog before treating this as "
                            "exploitable.")
            evidence += (f" Package revision detected ({distro}); backport status "
                         "unknown.")
        findings.append(Finding(
            rule_id=f"VS-{advisory.cve}",
            title=f"{advisory.cve}: {svc.product} {version} affected",
            severity=advisory.severity, confidence=confidence,
            description=description,
            impact=_ADVISORY_IMPACT.get(advisory.severity, _ADVISORY_IMPACT["medium"]),
            evidence=evidence,
            remediation=(f"Upgrade beyond the affected range: {advisory.fixed} or "
                         "later (confirm the distro package first)."
                         if advisory.fixed else
                         f"Apply the vendor fix or documented mitigation for "
                         f"{advisory.cve}."),
            asset=_asset(svc), cve=[advisory.cve],
            references=_ref(advisory.url),
            cvss_vector=advisory.vector or ""))
    return findings


def check_fingerprints(svc: PortService,
                       advisory_db: "advisories.AdvisoryDB | None" = None
                       ) -> list[Finding]:
    """Match detected product/version against known flaws.

    The hand-written rules below are curated fingerprints that carry rich
    context; the advisory database adds real version ranges on top. Both feed
    one list, de-duplicated by CVE, so a matched CVE never appears twice.
    """
    product = (svc.product or "").lower()
    version = svc.version
    if not product or not version:
        return []
    ver = _version_tuple(version)
    findings: list[Finding] = []

    if "vsftpd" in product and ver == (2, 3, 4):
        findings.append(Finding(
            rule_id="VS-CVE-2011-2523",
            title="vsftpd 2.3.4 backdoor (CVE-2011-2523)", severity="critical",
            confidence="certain",
            description="The banner identifies vsftpd 2.3.4, the release shipped "
                        "with a deliberate backdoor that opens a shell on a "
                        "non-standard port when the username contains ':)' .",
            impact="Trivial remote code execution as the FTP server user.",
            evidence=f"Banner: {svc.banner[:300]!r}",
            remediation="Reinstall a current vsftpd release immediately and audit "
                        "the host for signs of compromise.",
            asset=_asset(svc), cwe=_cwe(912), cve=["CVE-2011-2523"],
            references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2011-2523")))

    if "apache" in product:
        if ver == (2, 4, 49):
            findings.append(Finding(
                rule_id="VS-CVE-2021-41773",
                title="Apache 2.4.49 path traversal and RCE (CVE-2021-41773)",
                severity="critical", confidence="firm",
                description="Apache HTTP Server 2.4.49 contains a path traversal "
                            "flaw in its normalisation code that, with CGI scripts "
                            "enabled, allows arbitrary command execution.",
                impact="Unauthenticated remote code execution as the web-server user.",
                evidence=f"Server banner reports Apache/{version}; "
                         f"product fingerprint from {svc.http.get('server')!r}"
                         if svc.http else f"Version {version} detected.",
                remediation="Upgrade to Apache 2.4.51 or later immediately.",
                asset=_asset(svc), cwe=_cwe(22), cve=["CVE-2021-41773"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2021-41773")))
        elif ver == (2, 4, 50):
            findings.append(Finding(
                rule_id="VS-CVE-2021-42013",
                title="Apache 2.4.50 path traversal and RCE (CVE-2021-42013)",
                severity="critical", confidence="firm",
                description="Apache HTTP Server 2.4.50 is an incomplete fix for "
                            "CVE-2021-41773 and remains vulnerable to path "
                            "traversal and code execution.",
                impact="Unauthenticated remote code execution as the web-server user.",
                evidence=f"Server: {svc.http.get('server')!r}" if svc.http
                         else f"Version {version} detected.",
                remediation="Upgrade to Apache 2.4.51 or later immediately.",
                asset=_asset(svc), cwe=_cwe(22), cve=["CVE-2021-42013"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2021-42013")))

    if "openssh" in product:
        # CVE-2024-6387 (regreSSHion): portable OpenSSH 8.5p1 – 9.7p1.
        portable = re.search(r"p\d+", version) is not None
        if portable and (8, 5) <= ver <= (9, 7):
            findings.append(Finding(
                rule_id="VS-CVE-2024-6387",
                title="OpenSSH affected by regreSSHion (CVE-2024-6387)",
                severity="medium", confidence="tentative",
                description=f"OpenSSH {version} falls in the range affected by "
                            "regreSSHion, a signal-handler race condition in the "
                            "SSH-2.0 handshake. Exploitation is hard but the flaw "
                            "is unauthenticated.",
                impact="In the worst case, unauthenticated remote code execution as "
                       "root; practical exploitation requires many connections and "
                       "is timing dependent.",
                evidence=f"SSH banner: {svc.banner[:200]!r}",
                remediation="Upgrade to OpenSSH 9.8p1 or later, or set "
                            "LoginGraceTime to 0 as a mitigation.",
                asset=_asset(svc), cwe=_cwe(362), cve=["CVE-2024-6387"],
                references=_ref("https://nvd.nist.gov/vuln/detail/CVE-2024-6387")))

    # End-of-life / unsupported version notices.
    eol = None
    if "apache" in product and _lt(ver, (2, 4, 0)):
        eol = ("Apache HTTP Server 2.2.x", "2.2 reached end of life in 2017")
    elif product == "php" and _lt(ver, (8, 0, 0)):
        eol = (f"PHP {version}", "PHP 7.x and older are end of life")
    elif "mysql" in product and _lt(ver, (8, 0, 0)):
        eol = (f"MySQL {version}", "MySQL 5.7 and older are end of life")
    elif "nginx" in product and _lt(ver, (1, 24, 0)):
        eol = (f"nginx {version}", "this release is far behind the maintained branch")
    if eol:
        findings.append(Finding(
            rule_id="VS-EOL-SOFTWARE",
            title=f"End-of-life software detected: {eol[0]}",
            severity="medium", confidence="firm",
            description=f"{eol[1]}; it no longer receives security patches, so every "
                        "newly disclosed vulnerability stays permanently exploitable.",
            impact="Accumulating unpatched CVEs with no vendor fix available.",
            evidence=f"Detected {svc.product} {version} on port {svc.port}.",
            remediation="Upgrade to a currently supported release of this software.",
            asset=_asset(svc), cwe=_cwe(1104),
            references=_ref("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")))

    seen = {cve for finding in findings for cve in finding.cve}
    findings.extend(_advisory_findings(svc, advisory_db, seen))
    return findings


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

async def run_checks(services: list[PortService], timeout: float,
                     check_legacy_tls: bool = False,
                     advisory_db: "advisories.AdvisoryDB | None" = None
                     ) -> list[Finding]:
    """Run every check against the collected services, newest evidence first."""
    from .scanner import supports_tls_version  # local import avoids cycles

    findings: list[Finding] = []
    for svc in services:
        findings.extend(check_exposure(svc))
        findings.extend(check_http(svc))
        findings.extend(check_fingerprints(svc, advisory_db))

    findings.extend(await check_ftp_anonymous(services, timeout))

    for svc in services:
        if not (svc.tls or {}).get("ok"):
            continue
        legacy: dict | None = None
        if check_legacy_tls:
            legacy = {
                "TLS 1.0": await supports_tls_version(
                    svc.ip, svc.port, _tls_version("TLSv1"), timeout),
                "TLS 1.1": await supports_tls_version(
                    svc.ip, svc.port, _tls_version("TLSv1_1"), timeout),
            }
        findings.extend(check_tls(svc, legacy))

    # Stable IDs ordered by severity, then by host/port for determinism.
    findings.sort(key=lambda f: (f.sort_key, f.asset.get("host", ""),
                                 f.asset.get("port", 0), f.rule_id))
    for index, finding in enumerate(findings, start=1):
        finding.id = f"VS-{index:04d}"
    return findings


def _tls_version(name: str):
    import ssl
    return getattr(ssl.TLSVersion, name)
