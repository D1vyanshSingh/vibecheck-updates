"""Async TCP connect scan with banner grabbing, TLS and HTTP probing."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import struct
import tempfile
import time
import os
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 2.5
MAX_BANNER = 4096
MAX_HTTP_BODY = 65536

# Ports that need a purpose-built payload to make the service talk.
PROBES: dict[int, bytes] = {
    25: b"EHLO vulnscan.local\r\n",
    587: b"EHLO vulnscan.local\r\n",
    6379: b"INFO server\r\n",     # redis: reveals version + auth state
    11211: b"stats\r\n",          # memcached
    2181: b"ruok\r\n",            # zookeeper
}

# App-layer verification: one read-only GET per port, aimed at an endpoint that
# only the expected product answers. A 200 proves anonymous access; a 401/403
# proves the product is there with authentication on. No credentials are ever
# sent, and nothing is written.
APP_PROBES: dict[int, tuple[str, str]] = {
    2375: ("docker", "/version"),
    2376: ("docker", "/version"),
    2379: ("etcd", "/health"),
    5601: ("kibana", "/api/status"),
    6443: ("kubernetes", "/version"),
    9090: ("prometheus", "/api/v1/targets"),
    9200: ("elasticsearch", "/_cluster/health"),
    10250: ("kubelet", "/pods"),
    15672: ("rabbitmq", "/api/overview"),
}

# App names (as stored on PortService.app) that confirm the port's product.
APP_HTTPISH = {"", "http", "https", "http-alt", "ssl/http", "unknown"}
MONGO_PORTS = {27017, 27018}

# Services that will never answer HTTP; skip the HTTP probe for them.
NON_HTTP_PORTS = {
    21, 22, 23, 25, 53, 110, 119, 135, 139, 143, 445, 512, 513, 514,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 6443, 11211,
    27017,
}

# Ports where an HTTP response is expected and worth trying first.
HTTP_PORTS = {
    80, 81, 591, 593, 2080, 2480, 3000, 4567, 5000, 5104, 5800, 6080,
    8000, 8008, 8080, 8081, 8083, 8088, 8090, 8180, 8280, 8888, 9000,
    9080, 9090, 9443, 16080, 18090, 28080,
}

# Protocols whose server speaks first. Every other port is treated as
# client-first: the scan sends its probe (or an HTTP request) straight away
# instead of waiting for a greeting that never comes.
SERVER_FIRST_PORTS = {
    21, 22, 23, 25, 110, 143, 465, 587, 636, 873, 993, 995, 3306, 5900, 5901,
}

# Ports where TLS is the transport: a plaintext probe would only earn an alert,
# so the handshake is the first thing sent. All of these complete in one
# connection, and the HTTP ones reuse it for the request that follows.
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 5671, 6443, 8443, 8883, 9443}
TLS_HTTP_PORTS = {443, 2376, 6443, 8443, 9443}

# X.224 connection request (the classic RDP negotiation, no credentials).
RDP_NEGOTIATION = bytes.fromhex("030000130ee000000000000100080003000000")

# Well-known port → service name (used when the banner is inconclusive).
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http", 3128: "squid",
    3306: "mysql", 3389: "ms-wbt", 4443: "https", 5000: "http",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5985: "winrm",
    6379: "redis", 6443: "https", 7001: "http", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8088: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "http", 9300: "elasticsearch",
    9418: "git", 11211: "memcached", 15672: "http", 27017: "mongodb",
    50000: "db2",
}

# Banner/product/version fingerprints.
# product and (optional) version in the software string: "OpenSSH_9.6p1"
_SSH_RE = re.compile(r"SSH-[\d.]+-([A-Za-z0-9.]+)(?:_([0-9][^\s]*))?",
                     re.IGNORECASE)
_FTP_RE = re.compile(r"\((vsFTPD|Pure-FTPd|ProFTPD|wu-ftpd)[ /]([0-9][\w.]+)", re.IGNORECASE)
_SMTP_RE = re.compile(r"^(?:\d{3}[ -].*?\s)?([A-Za-z][\w.-]*)\s([0-9][\w.]+)", re.IGNORECASE)
_MYSQL_RE = re.compile(r"^([\d]+(?:\.[\d]+){1,3})[-\w.]*")
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class PortService:
    """Result of probing one host:port."""
    host: str
    ip: str
    port: int
    state: str = "closed"            # open | closed | filtered
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    probe: str = ""                  # what we sent, if anything
    tls: dict | None = None
    http: dict | None = None
    scanned_at: str = ""
    # Engine-supplied identification (nmap) and protocol facts.
    proto: str = "tcp"
    source: str = "native"          # native | nmap
    cpe: list[str] = field(default_factory=list)
    nmap_conf: int = 0               # nmap identification confidence, 0-10
    extrainfo: str = ""
    os_matches: list[dict] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    rtt_ms: int | None = None
    identity_source: str = "port"     # port | banner | http | nmap
    identity_claims: list[dict] = field(default_factory=list)
    # Set when the port is open but told us nothing: something accepted the
    # connection and then went silent or reset it (nmap calls this
    # "tcpwrapped"). These are identification gaps, not clean results.
    identification_error: str = ""
    # Read-only app-layer verification results, keyed by product
    # (docker, etcd, kubelet, kibana, rabbitmq, prometheus, elasticsearch,
    # kubernetes, mongo). See APP_PROBES and probe_mongo.
    app: dict[str, dict] = field(default_factory=dict)

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def http_service_name(self) -> str:
        return "https" if (self.tls or {}).get("ok") else "http"


def guess_service(port: int) -> str:
    return PORT_SERVICES.get(port, "")


# Names that say "no identification happened" rather than naming a protocol.
# nmap emits "tcpwrapped" when the port accepted TCP and then stopped talking.
UNIDENTIFIED_SERVICE_NAMES = frozenset({"", "unknown", "tcpwrapped"})


def _decode_der_cert(der: bytes) -> dict:
    """Decode a DER certificate into Python's dict form (no verification)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(pem)
        return ssl._ssl._test_decode_cert(path) or {}
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _name_map(name_part) -> dict[str, str]:
    """Flatten a certificate name tuple into a key/value map.

    The nesting depth differs between Python versions and decode paths
    (e.g. ((('commonName', 'host'),),) vs (('commonName', 'host'),)),
    so flatten recursively and keep the last value per key.
    """
    out: dict[str, str] = {}

    def walk(nodes) -> None:
        for item in nodes or ():
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                out[item[0]] = item[1]
            elif isinstance(item, tuple):
                walk(item)

    walk(name_part)
    return out


def summarize_cert(cert: dict, host: str) -> dict:
    """Turn a decoded certificate into the fields the report needs."""
    subject = tuple(cert.get("subject") or ())
    issuer = tuple(cert.get("issuer") or ())
    subject_map = _name_map(subject)
    issuer_map = _name_map(issuer)
    sans = [v for kind, v in (cert.get("subjectAltName") or ()) if kind == "DNS"]
    info: dict = {
        "subject": subject_map.get("commonName") or str(subject_map) or "",
        "issuer": issuer_map.get("commonName") or str(issuer_map) or "",
        "self_signed": subject_map == issuer_map or subject == issuer,
        "san": sans[:25],
        "not_before": cert.get("notBefore") or "",
        "not_after": cert.get("notAfter") or "",
    }
    now = time.time()
    try:
        end = ssl.cert_time_to_seconds(info["not_after"])
        start = ssl.cert_time_to_seconds(info["not_before"])
        info["days_remaining"] = int((end - now) // 86400)
        info["expired"] = now > end
        info["not_yet_valid"] = now < start
    except (ValueError, TypeError):
        info["days_remaining"] = None
        info["expired"] = False
        info["not_yet_valid"] = False
    info["hostname_matches"] = _hostname_matches(host, sans)
    return info


def _hostname_matches(host: str, sans: list[str]) -> bool | None:
    """Best-effort hostname check against SANs; None when undecidable."""
    if host.replace(".", "").isdigit():
        return None  # IP verification needs iPAddress SANs we did not parse
    if not sans:
        return None
    host = host.lower().rstrip(".")
    for san in sans:
        san = san.lower().rstrip(".")
        if san == host:
            return True
        if san.startswith("*.") and host.endswith(san[1:]) and host.count(".") == san.count("."):
            return True
    return False


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_details(writer, host: str) -> dict:
    """Protocol, cipher and certificate of an established TLS connection."""
    try:
        sslobj = writer.get_extra_info("ssl_object")
        cipher = sslobj.cipher()
        info: dict = {
            "ok": True,
            "version": sslobj.version() or "",
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
        }
        der = sslobj.getpeercert(binary_form=True)
        if der:
            info["cert"] = summarize_cert(_decode_der_cert(der), host)
        return info
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def tls_session(host: str, port: int, timeout: float, *,
                      want_http: bool = False) -> tuple[dict, dict | None, bytes]:
    """One TLS connection: handshake, optional HTTPS GET and greeting.

    Returns ``(tls_info, http, inner_greeting)``. Certificate, cipher and the
    HTTP response used to come from two separate connections; both now share
    this socket, so a TLS port costs one connection instead of three.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_tls_context(),
                                    server_hostname=host), timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}, None, b""
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}, None, b""
    try:
        info = _tls_details(writer, host)
        if not info.get("ok"):
            return info, None, b""
        if want_http:
            http, raw = await _http_exchange(reader, writer, host, port,
                                            "https", "/", timeout)
            return info, http, raw
        greeting = await _read_first_bytes(reader, timeout)
        return info, None, greeting
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def probe_tls(host: str, port: int, timeout: float) -> dict:
    """Attempt a TLS handshake; returns protocol and certificate details."""
    info, _http, _greeting = await tls_session(host, port, timeout)
    return info


async def supports_tls_version(host: str, port: int, version: ssl.TLSVersion,
                               timeout: float) -> bool:
    """True when the service completes a handshake pinned to one TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError, AttributeError):
        return False
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), min(timeout, 2.0))
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def grab_banner(host: str, port: int, timeout: float) -> tuple[str, str]:
    """Read the service's opening line. Returns (banner, what_was_sent)."""
    probe = PROBES.get(port)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return "", "connect-timeout"
    except Exception as exc:
        return "", f"connect-failed ({type(exc).__name__})"
    try:
        if probe:
            writer.write(probe)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(MAX_BANNER), timeout)
        text = data.decode("latin-1", "replace").strip()
        return text[:1024], probe.decode("latin-1", "replace").strip() if probe else ""
    except asyncio.TimeoutError:
        return "", probe.decode("latin-1", "replace").strip() if probe else ""
    except Exception as exc:
        return "", f"read-failed ({type(exc).__name__})"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def send_recv(host: str, port: int, payload: bytes, timeout: float,
                    rounds: int = 1) -> str:
    """Send payloads and return the concatenated response text (for checks)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return ""
    chunks: list[str] = []
    try:
        for _ in range(max(1, rounds)):
            writer.write(payload)
            await writer.drain()
            await asyncio.sleep(0.3)      # let multi-line replies fully arrive
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(MAX_BANNER), 0.6)
                    if not data:
                        break
                    chunks.append(data.decode("latin-1", "replace"))
            except asyncio.TimeoutError:
                pass
            break
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return "".join(chunks)[:2048]


def _http_request_bytes(host: str, port: int, scheme: str,
                        path: str = "/") -> bytes:
    host_hdr = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if scheme == "https" else 80
    authority = host_hdr if port == default_port else f"{host_hdr}:{port}"
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "User-Agent: vulnscan/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")


def _parse_http(raw: bytes, scheme: str, path: str) -> dict | None:
    """Parse a response already read from the socket."""
    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        return None
    try:
        parts = lines[0].decode("latin-1", "replace").split()
        status = int(parts[1]) if len(parts) > 1 else 0
        reason = parts[2] if len(parts) > 2 else ""
    except (ValueError, IndexError):
        status, reason = 0, ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        key_s = key.decode("latin-1", "replace").strip().lower()
        value_s = value.decode("latin-1", "replace").strip()
        headers[key_s] = f"{headers[key_s]}, {value_s}" if key_s in headers else value_s
    title = ""
    match = _TITLE_RE.search(body)
    if match:
        title = match.group(1).decode("utf-8", "replace").strip()[:200]
    return {
        "scheme": scheme,
        "path": path,
        "status": status,
        "reason": reason,
        "headers": headers,
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "title": title,
        "location": headers.get("location", ""),
        "content_type": headers.get("content-type", ""),
        "body_preview": body[:4000].decode("utf-8", "replace"),
        "body_length": len(body),
    }


async def _http_exchange(reader: asyncio.StreamReader, writer,
                         host: str, port: int, scheme: str, path: str,
                         timeout: float) -> tuple[dict | None, bytes]:
    """Send one GET over an existing connection; returns (parsed, raw)."""
    try:
        writer.write(_http_request_bytes(host, port, scheme, path))
        await writer.drain()
        raw = await _read_response(reader, timeout)
    except Exception:
        return None, b""
    return _parse_http(raw, scheme, path), raw


async def http_fetch(host: str, port: int, scheme: str, timeout: float,
                     path: str = "/") -> dict | None:
    """Issue a single HTTP GET and parse status, headers, title and a snippet."""
    ctx = _tls_context() if scheme == "https" else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ctx,
                server_hostname=host if ctx is not None else None), timeout)
    except Exception:
        return None
    try:
        http, _raw = await _http_exchange(reader, writer, host, port, scheme,
                                         path, timeout)
        return http
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _read_response(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """Read until the server closes, we time out, or we hit the size cap."""
    buffer = bytearray()
    deadline = time.monotonic() + timeout
    while len(buffer) < MAX_HTTP_BODY:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(8192, MAX_HTTP_BODY - len(buffer))), remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
        # Headers complete → short grace period for the body only.
        if b"\r\n\r\n" in buffer and deadline - time.monotonic() > timeout / 2:
            deadline = min(deadline, time.monotonic() + max(0.4, timeout / 2))
    return bytes(buffer)


def _extract_product(service: str, banner: str, http: dict | None) -> tuple[str, str]:
    """Pull (product, version) out of a banner or HTTP headers."""
    # FTP server fingerprints — match wherever they appear in the banner.
    match = _FTP_RE.search(banner)
    if match:
        return match.group(1), match.group(2)
    if not banner:
        if http and http.get("server"):
            server = http["server"]
            return _split_server(server)
        return "", ""
    if service == "ssh":
        match = _SSH_RE.search(banner)
        if match:
            return match.group(1), match.group(2) or ""
    if service == "ftp":
        match = _FTP_RE.search(banner)
        if match:
            return match.group(1), match.group(2)
    if service in ("smtp", "submission", "smtps"):
        first = banner.splitlines()[0] if banner else ""
        match = _SMTP_RE.match(first)
        if match and match.group(1).lower() not in {"220"}:
            return match.group(1), match.group(2)
        m2 = re.search(r"\b(Postfix|Exim|sendmail|Exchange)\b[ /]?([\d.]+)?", first, re.IGNORECASE)
        if m2:
            return m2.group(1), m2.group(2) or ""
    if service == "mysql":
        # Handshake: 3-byte length, sequence, protocol 0x0a, then the
        # NUL-terminated server version ("5.7.31-log").
        raw = banner.encode("latin-1", "ignore")
        if len(raw) > 5 and raw[4] == 0x0A:
            end = raw.find(b"\x00", 5)
            if end > 5:
                return "MySQL", raw[5:end].decode("latin-1", "replace")
        match = _MYSQL_RE.match(banner)
        if match and "mysql" in banner.lower():
            return "MySQL", match.group(1)
    if service == "redis" and "redis_version" in banner:
        match = re.search(r"redis_version:([\d.]+)", banner)
        if match:
            return "Redis", match.group(1)
    if service == "memcached" and "STAT version" in banner:
        match = re.search(r"STAT version ([\w.]+)", banner)
        if match:
            return "Memcached", match.group(1)
    if http and http.get("server"):
        return _split_server(http["server"])
    if banner.startswith("HTTP/"):
        return "", ""
    return "", ""


def _split_server(server: str) -> tuple[str, str]:
    """'nginx/1.18.0 (Ubuntu)' → ('nginx', '1.18.0')."""
    server = server.strip()
    match = re.match(r"([A-Za-z0-9._+-]+)[/ ]([0-9][\w.]*)", server)
    if match:
        return match.group(1), match.group(2)
    return server.split()[0] if server.split() else "", ""


async def _finish_evidence(svc: PortService, timeout: float) -> PortService:
    """App-layer probes, Mongo handshake and product extraction."""
    await probe_app_layer(svc, timeout)
    if (svc.port in MONGO_PORTS and not (svc.tls or {}).get("ok")
            and (not svc.service or "mongo" in svc.service.lower())):
        mongo = await probe_mongo(svc.ip, svc.port, timeout)
        if mongo:
            svc.app["mongo"] = mongo
    svc.product, svc.version = _extract_product(svc.service, svc.banner, svc.http)
    mongo = svc.app.get("mongo") or {}
    if mongo.get("version") and not svc.version:
        svc.product, svc.version = "MongoDB", mongo["version"]
    return svc


async def _plain_identify(svc: PortService, reader, writer,
                          timeout: float) -> None:
    """Identify a plaintext service on the connection already open.

    One connection carries every step: the greeting (when the server speaks
    first), the protocol probe (when it waits), and the HTTP fallback. The
    old flow opened three or four sockets per port and made a TLS handshake
    attempt even at SSH.
    """
    port = svc.port
    data = b""
    if (port in SERVER_FIRST_PORTS
            or (port not in PORT_SERVICES and port not in HTTP_PORTS)):
        data = await _read_first_bytes(reader, timeout)
    service = classify_first_bytes(data)
    sent = ""

    if not service:
        payload = active_probe(port)
        if payload:
            try:
                writer.write(payload)
                await writer.drain()
                reply = await _read_first_bytes(reader, timeout)
            except Exception:
                reply = b""
            if reply:
                data += reply
                sent = payload.decode("latin-1", "replace").strip()
                service = classify_first_bytes(data)

    if not service:
        http, raw = await _http_exchange(reader, writer, svc.ip, port, "http",
                                         "/", timeout)
        data += raw
        if raw:
            service = classify_first_bytes(raw)
        if http is not None and service in ("", "http"):
            svc.http = http
            svc.service = "http"
            svc.identity_source = "http"
            _record_identity(svc, "http", "http")
            return

    if service == "tls":
        # Plaintext earned a TLS alert: the caller retries with a handshake.
        return
    if service == "ftp/smtp":
        service = PORT_SERVICES.get(port, "ftp/smtp")
    if not service:
        return
    svc.service = service
    svc.identity_source = "banner"
    svc.banner = data.decode("latin-1", "replace").strip()[:1024]
    svc.probe = sent
    _record_identity(svc, "banner", service)


async def _tls_port_handshake(svc: PortService, timeout: float) -> dict:
    """Handshake on a TLS port, using the same socket for HTTPS.

    Returns the TLS info (``ok`` is False when the port is not TLS after all,
    so the caller can fall back to a plaintext probe).
    """
    tls, http, raw = await tls_session(
        svc.ip, svc.port, timeout, want_http=svc.port in TLS_HTTP_PORTS)
    if not tls.get("ok"):
        return tls
    svc.tls = tls
    svc.http = http
    if http is not None:
        svc.service = "https"
        svc.identity_source = "http"
        _record_identity(svc, "http", "https")
        return tls
    service = classify_first_bytes(raw)
    if service and service not in ("tls", "http"):
        svc.service = service
        svc.identity_source = "banner"
        svc.banner = raw.decode("latin-1", "replace").strip()[:1024]
        _record_identity(svc, "banner", service)
    else:
        # A handshake proves TLS, not which application rides on it.
        svc.service = PORT_SERVICES.get(svc.port, "https")
        svc.identity_source = "port"
    return tls


async def probe_port(host: str, ip: str, port: int, timeout: float) -> PortService:
    """Full probe of one host:port over as few connections as possible."""
    svc = PortService(host=host, ip=ip, port=port,
                      scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if port in TLS_PORTS:
        tls = await _tls_port_handshake(svc, timeout)
        if tls.get("ok"):
            svc.state = "open"
            return await _finish_evidence(svc, timeout)
        error = str(tls.get("error") or "").lower()
        # A refused/timed-out connection is answered here; no second attempt.
        if "refused" in error:
            svc.state = "closed"
            return svc
        if "timeout" in error:
            svc.state = "filtered"
            return svc

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        svc.state = "filtered"
        return svc
    except (ConnectionRefusedError, OSError):
        svc.state = "closed"
        return svc
    svc.state = "open"
    try:
        await _plain_identify(svc, reader, writer, timeout)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
        # Accepted, then dropped: the listener exists but revealed nothing.
        # Recorded as an identification gap -- reporting it as a silent clean
        # port is what makes a scanner look empty when it is merely blind.
        svc.identification_error = _describe_identification_error(exc)
        svc.service = ""
        svc.identity_source = ""
        return svc
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not svc.service and svc.http is None:
        # Nothing plaintext answered; a TLS listener on an unusual port only
        # reveals itself in the handshake.
        tls, http, raw = await tls_session(ip, port, timeout, want_http=True)
        if tls.get("ok"):
            svc.tls = tls
            svc.http = http
            if http is not None:
                svc.service = "https"
                svc.identity_source = "http"
                _record_identity(svc, "http", "https")
            else:
                service = classify_first_bytes(raw)
                if service and service not in ("tls", "http"):
                    svc.service = service
                    svc.identity_source = "banner"
                    svc.banner = raw.decode("latin-1", "replace").strip()[:1024]
                    _record_identity(svc, "banner", service)

    if not svc.service and svc.http is None:
        svc.service = guess_service(port)
        svc.identity_source = "port" if svc.service else ""

    return await _finish_evidence(svc, timeout)


_SIGNATURES = (
    ("ssh-", "ssh"),
    ("rfb 00", "vnc"),
    ("redis_version", "redis"),
    ("-err unknown command", "redis"),
    ("stat pid", "memcached"),
    ("stat version", "memcached"),
    ("220 (vsftpd", "ftp"),
    ("220 (proftpd", "ftp"),
    ("220 (pure-ftpd", "ftp"),
    ("220 ", "ftp/smtp"),
    ("+ok", "pop3"),
    ("* ok", "imap"),
    ("amqp", "rabbitmq"),
    ("mysql_native_password", "mysql"),
    ("password authentication failed", "postgresql"),
    ("\xffsmb", "smb"),
    ("http/", "http"),
)

# "220" alone does not distinguish FTP from SMTP, so it never overrides a
# port-based guess (it may still name an otherwise unidentified service).
_AMBIGUOUS_SIGNATURES = {"ftp/smtp"}


def _describe_identification_error(exc: BaseException) -> str:
    """Plain-language reason a connected port could not be identified."""
    if isinstance(exc, ConnectionResetError):
        return "connection reset during identification"
    if isinstance(exc, ConnectionAbortedError):
        return "connection aborted during identification"
    return "connection closed during identification"


def _banner_signature(banner: str) -> str:
    """Best-effort protocol signature from the opening bytes of a service."""
    lowered = (banner or "").lower()
    if not lowered:
        return ""
    for token, name in _SIGNATURES:
        if token in lowered:
            return name
    return ""


def _record_identity(svc: PortService, source: str,
                     service: str | None = None) -> None:
    """Keep every identification claim so conflicts can be reported."""
    claim = {"source": source, "service": service or svc.service,
             "product": svc.product, "version": svc.version}
    if svc.identity_claims:
        last = svc.identity_claims[-1]
        if (last.get("service") == claim["service"]
                and last.get("product") == claim["product"]):
            return
    svc.identity_claims.append(claim)


# --------------------------------------------------------------------------
# First-bytes protocol classification (native engine)
# --------------------------------------------------------------------------

# Checked against the lowercased opening bytes, most specific marker first.
# A match here is a protocol fact, not a port guess: it is what the service
# actually sent.
_FIRST_BYTES_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"ssh-", "ssh"),
    (b"http/", "http"),
    (b"\x16\x03", "tls"),
    (b"\x15\x03", "tls"),          # alert: a TLS listener that got plaintext
    (b"rfb 00", "vnc"),
    (b"\xffsmb", "smb"),
    (b"\xfesmb", "smb"),
    (b"\x03\x00\x00", "rdp"),        # TPKT / X.224
    (b"\xff\xfb", "telnet"),
    (b"\xff\xfd", "telnet"),
    (b"amqp", "rabbitmq"),
    (b"imok", "zookeeper"),
    (b"+ok", "pop3"),
    (b"* ok", "imap"),
    (b"-noauth", "redis"),
    (b"-err", "redis"),
    (b"# server", "redis"),
    (b"redis_version", "redis"),
    (b"stat ", "memcached"),
    (b"220 (vsftpd", "ftp"),
    (b"220 (proftpd", "ftp"),
    (b"220 (pure-ftpd", "ftp"),
    (b"esmtp", "smtp"),
    (b"@rsyncd", "rsync"),
)

GREETING_WAIT = 0.35


def _is_mysql_handshake(data: bytes) -> bool:
    """MySQL: 3-byte packet length, sequence 0, protocol version 10."""
    return (len(data) >= 5 and data[3] == 0
            and int.from_bytes(data[:3], "little") > 0
            and data[4] == 0x0A)


def _is_postgres_message(data: bytes) -> bool:
    """PostgreSQL: a message type byte followed by a big-endian length."""
    if len(data) < 9 or data[1:4] != b"\x00\x00\x00":
        return False
    return data[0:1] in (b"R", b"E", b"S", b"N") and data[4] < 0x80


def _is_mongo_message(data: bytes) -> bool:
    """MongoDB wire message: sane length + OP_REPLY/OP_MSG opcode."""
    if len(data) < 16:
        return False
    length = int.from_bytes(data[:4], "little")
    opcode = int.from_bytes(data[12:16], "little")
    return 16 <= length <= 64 * 1024 * 1024 and opcode in (1, 2013)


def classify_first_bytes(data: bytes) -> str:
    """Protocol family from the first bytes a service sent, or ``""``.

    This is what the native engine identifies on: no port table involved, only
    what went over the wire. A bare ``220`` greeting returns ``ftp/smtp`` —
    real evidence of the family, but not of which of the two it is.
    """
    if not data:
        return ""
    lowered = data[:512].lower()
    for marker, name in _FIRST_BYTES_MARKERS:
        if marker in lowered:
            return name
    if _is_mysql_handshake(data):
        return "mysql"
    if _is_postgres_message(data):
        return "postgresql"
    if _is_mongo_message(data):
        return "mongodb"
    if lowered.startswith(b"220"):
        return "ftp/smtp"
    if b"login:" in lowered:
        return "telnet"
    return ""


async def _read_first_bytes(reader: asyncio.StreamReader, timeout: float,
                            limit: int = MAX_BANNER) -> bytes:
    """Short, bounded read of whatever a service says without being asked."""
    deadline = time.monotonic() + min(max(timeout, 0.15), GREETING_WAIT + 0.15)
    buffer = bytearray()
    while len(buffer) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(limit - len(buffer)),
                                           remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
        if classify_first_bytes(bytes(buffer)):
            break
    return bytes(buffer)


# Markers that a 200 response really came from the expected product rather
# than from a generic web app squatting on the port. 401/403 needs no marker:
# an authentication challenge on a product-specific path is evidence enough.
APP_MARKERS: dict[str, tuple[str, ...]] = {
    "docker": ("docker", "apiversion"),
    "etcd": ("health",),
    "kibana": ("status", "version"),
    "kubernetes": ("gitversion", "major"),
    "prometheus": ("activetargets", "success"),
    "elasticsearch": ("cluster_name", "status"),
    "kubelet": ("items", "podlist", "apiVersion"),
    "rabbitmq": ("rabbitmq_version", "management_version"),
}


def _probe_matches_product(name: str, result: dict) -> bool:
    body = (result.get("body_preview") or "").lower()
    if result.get("status") in (401, 403):
        return True
    return any(marker.lower() in body for marker in APP_MARKERS.get(name, ()))


async def probe_app_layer(svc: PortService, timeout: float) -> None:
    """One read-only GET against a product-specific endpoint, never auth'd.

    The result lands on ``svc.app`` and lets a check upgrade a port-based
    guess to protocol-level proof (a 200) or at least confirm the product is
    there with authentication on (401/403). A non-HTTP service is left alone:
    shouting an HTTP request at SSH produces noise on the target and nothing
    useful here.
    """
    entry = APP_PROBES.get(svc.port)
    if not entry:
        return
    name, path = entry
    service = (svc.service or "").lower()
    if (svc.http is None and not (svc.banner or "").startswith("HTTP/")
            and service not in APP_HTTPISH and name not in service):
        return
    scheme = "https" if (svc.tls or {}).get("ok") else "http"
    result = await http_fetch(svc.ip, svc.port, scheme, timeout, path=path)
    if result is None and scheme == "http" and svc.http is None:
        # Some consoles only speak TLS; try once before giving up.
        alternate = await http_fetch(svc.ip, svc.port, "https", timeout, path=path)
        if alternate is not None:
            scheme, result = "https", alternate
    if result is None:
        return
    status = result.get("status") or 0
    if status not in (200, 401, 403, 404):
        return
    svc.app[name] = {
        "name": name,
        "path": path,
        "scheme": scheme,
        "status": status,
        "server": result.get("server", ""),
        "body": (result.get("body_preview") or "")[:600],
        "confirmed": _probe_matches_product(name, result),
    }


def _bson_int_command(name: str) -> bytes:
    """Minimal BSON document ``{name: 1}`` for a MongoDB command query."""
    body = (b"\x10" + name.encode("ascii") + b"\x00"
            + struct.pack("<i", 1) + b"\x00")
    return struct.pack("<i", len(body) + 4) + body


def _mongo_query(command: bytes) -> bytes:
    """OP_QUERY against admin.$cmd — the handshake every MongoDB accepts."""
    payload = (struct.pack("<i", 0) + b"admin.$cmd\x00"
               + struct.pack("<ii", 0, -1) + command)
    return struct.pack("<iiii", 16 + len(payload), 1, 0, 2004) + payload


def active_probe(port: int) -> bytes:
    """The bytes that make a waiting service answer, or b'' if none is known.

    Every probe is read-only: an INFO/stats query, a hello, a protocol
    negotiation. Nothing here authenticates or changes state.
    """
    if port in PROBES:
        return PROBES[port]
    if port in MONGO_PORTS:
        return _mongo_query(_bson_int_command("isMaster"))
    if port == 3389:
        return RDP_NEGOTIATION
    return b""


async def _mongo_reply(reader: asyncio.StreamReader, timeout: float) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout)
    length = struct.unpack("<i", header)[0]
    if length < 16 or length > 65536:
        return b""
    # Keep the length prefix: the parser needs the full message header.
    return header + await asyncio.wait_for(
        reader.readexactly(length - 4), timeout)


def _cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("latin-1", "replace"), end + 1


def _parse_bson(data: bytes, offset: int = 0) -> tuple[dict, int]:
    """Parse the top level of a BSON document, skipping unknown types."""
    if len(data) < offset + 4:
        return {}, len(data)
    length = struct.unpack_from("<i", data, offset)[0]
    end = offset + length
    if length < 5 or end > len(data):
        return {}, len(data)
    fields: dict = {}
    pos = offset + 4
    try:
        while pos < end - 1:
            kind = data[pos]
            pos += 1
            name, pos = _cstring(data, pos)
            if kind == 0x01:
                fields[name] = struct.unpack_from("<d", data, pos)[0]
                pos += 8
            elif kind == 0x02:
                size = struct.unpack_from("<i", data, pos)[0]
                pos += 4
                fields[name] = data[pos:pos + size - 1].decode("latin-1", "replace")
                pos += size
            elif kind in (0x03, 0x04):
                nested, pos = _parse_bson(data, pos)
                if kind == 0x04:
                    fields[name] = [nested[key] for key in
                                    sorted(nested, key=lambda k: int(k)
                                           if k.isdigit() else 0)]
                else:
                    fields[name] = nested
            elif kind == 0x05:
                size = struct.unpack_from("<i", data, pos)[0]
                pos += 5 + size
            elif kind == 0x07:
                pos += 12
            elif kind == 0x08:
                fields[name] = bool(data[pos])
                pos += 1
            elif kind == 0x09 or kind == 0x11 or kind == 0x12:
                fields[name] = struct.unpack_from("<q", data, pos)[0]
                pos += 8
            elif kind == 0x0A:
                fields[name] = None
            elif kind == 0x0B:
                _, pos = _cstring(data, pos)
                _, pos = _cstring(data, pos)
            elif kind == 0x10:
                fields[name] = struct.unpack_from("<i", data, pos)[0]
                pos += 4
            elif kind == 0x13:
                pos += 16
            elif kind in (0x7F, 0xFF):
                pass
            else:
                break
    except (struct.error, IndexError, ValueError):
        return fields, end
    return fields, end


def _mongo_document(message: bytes) -> dict:
    """Top-level BSON document of an OP_REPLY or OP_MSG message."""
    if len(message) < 20:
        return {}
    opcode = struct.unpack_from("<i", message, 12)[0]
    offset = 36 if opcode == 1 else 21 if opcode == 2013 else -1
    if offset < 0 or offset >= len(message):
        return {}
    return _parse_bson(message, offset)[0]


async def probe_mongo(host: str, port: int, timeout: float) -> dict | None:
    """Read-only MongoDB handshake + listDatabases (no credentials sent).

    ``listDatabases`` is metadata-only: when it answers without authentication
    the database is open to anyone who can reach the port. When the reply
    carries ``requires authentication`` / ``Unauthorized`` the server is
    exposed but protected, which is a different (and lower) claim.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
    except Exception:
        return None
    hello = b""
    listing = b""
    try:
        writer.write(_mongo_query(_bson_int_command("isMaster")))
        await writer.drain()
        hello = await _mongo_reply(reader, timeout)
        writer.write(_mongo_query(_bson_int_command("listDatabases")))
        await writer.drain()
        listing = await _mongo_reply(reader, timeout)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    if not hello and not listing:
        return None
    hello_doc = _mongo_document(hello)
    listing_doc = _mongo_document(listing)
    version = str(hello_doc.get("version") or listing_doc.get("version") or "")
    errmsg = str(listing_doc.get("errmsg") or "").lower()
    auth_required = (listing_doc.get("code") in (13, 18)
                     or "requires authentication" in errmsg
                     or "not authorized" in errmsg)
    databases = listing_doc.get("databases")
    open_access = (isinstance(databases, list)
                   and listing_doc.get("ok") in (1, 1.0, True))
    preview: dict = {"version": version, "ok": listing_doc.get("ok")}
    if isinstance(databases, list):
        preview["databases"] = [entry.get("name") for entry in databases[:10]
                                if isinstance(entry, dict)]
    if listing_doc.get("errmsg"):
        preview["errmsg"] = str(listing_doc["errmsg"])[:200]
    return {
        "name": "mongo",
        "path": "admin.$cmd listDatabases",
        "scheme": "mongodb",
        "status": 200 if open_access else (401 if auth_required else 0),
        "version": version,
        "auth_required": auth_required,
        "open": open_access,
        "body": json.dumps(preview)[:600],
        "confirmed": bool(listing_doc),
    }


async def collect_evidence(svc: PortService, timeout: float,
                           guess_names: bool = True) -> PortService:
    """Probe TLS, banner and HTTP for an already-open service.

    The native engine calls this after its own connect check. The nmap engine
    calls it on the ports nmap reported open, so both engines hand the checks
    the same evidence. With ``guess_names=False`` the identification nmap
    supplied (service/product/version) is kept and only gaps are filled.
    """
    ip, port = svc.ip, svc.port
    svc.tls = await probe_tls(ip, port, timeout)
    tls_ok = bool(svc.tls.get("ok"))

    if not tls_ok:
        svc.banner, svc.probe = await grab_banner(ip, port, timeout)
    else:
        svc.probe = svc.tls.get("version", "")

    scheme = "https" if tls_ok else "http"
    # HTTP is tried on web-ish ports, on anything that already answered HTTP,
    # and as a last resort on a port that said nothing at all -- that is what
    # lets a web server squatting on, say, 5900 be identified instead of being
    # reported as VNC from the port number alone.
    wants_http = (port in HTTP_PORTS
                  or svc.banner.startswith("HTTP/")
                  or (svc.service or "").startswith("http")
                  or not svc.banner)
    if wants_http:
        svc.http = await http_fetch(ip, port, scheme, timeout)
        if svc.http is None and not tls_ok and port in HTTP_PORTS:
            # Plain failed on a web-ish port — try TLS before giving up.
            alt = await probe_tls(ip, port, timeout)
            if alt.get("ok"):
                svc.tls = alt
                tls_ok = True
                svc.http = await http_fetch(ip, port, "https", timeout)

    await probe_app_layer(svc, timeout)
    if (svc.port in MONGO_PORTS and not tls_ok
            and (not svc.service or "mongo" in svc.service.lower())):
        mongo = await probe_mongo(ip, port, timeout)
        if mongo:
            svc.app["mongo"] = mongo

    native_claim: tuple[str, str] | None = None
    if svc.identification_error:
        # A port that answered TCP and then went silent is not a port-table
        # guess away from being "identified": say unidentified rather than
        # name it from the port number alone.
        svc.service = ""
        svc.identity_source = ""
    elif guess_names:
        svc.service = guess_service(port) or svc.service
        if svc.service:
            svc.identity_source = "port"
    if svc.http is not None:
        native_claim = ("http", "https" if tls_ok else "http")
    if svc.http and (guess_names or not svc.service):
        svc.service = "https" if tls_ok else svc.http_service_name()
        svc.identity_source = "http"

    signature = _banner_signature(svc.banner)
    if signature:
        if guess_names and svc.identity_source == "port":
            if signature == svc.service:
                svc.identity_source = "banner"      # the wire proved the guess
            elif signature not in _AMBIGUOUS_SIGNATURES:
                svc.service = signature
                svc.identity_source = "banner"
        elif not svc.service:
            svc.service = signature
            svc.identity_source = "banner"
        native_claim = ("banner", svc.service or signature)

    product, version = _extract_product(svc.service, svc.banner, svc.http)
    if guess_names:
        svc.product, svc.version = product, version
    else:
        svc.product = svc.product or product
        svc.version = svc.version or version

    mongo = svc.app.get("mongo") or {}
    if mongo.get("version") and not svc.version:
        svc.product, svc.version = "MongoDB", mongo["version"]

    # If a later probe did get a protocol answer, the earlier silence is no
    # longer the whole story and the identification gap is closed.
    if svc.service and svc.identity_source in ("http", "banner", "nmap"):
        svc.identification_error = ""

    if native_claim and native_claim[1]:
        _record_identity(svc, *native_claim)
    return svc


async def run_scan(hosts: list[str], ports: list[int], timeout: float = DEFAULT_TIMEOUT,
                   concurrency: int = 256,
                   progress=None) -> list[PortService]:
    """Scan every host × port with a bounded concurrency budget."""
    ip_cache: dict[str, str] = {}
    for host in hosts:
        if host in ip_cache:
            continue
        try:
            ip_cache[host] = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except OSError:
            ip_cache[host] = host
    total = len(hosts) * len(ports)
    semaphore = asyncio.Semaphore(concurrency)
    done = 0

    async def _one(host: str, port: int) -> PortService:
        nonlocal done
        async with semaphore:
            result = await probe_port(host, ip_cache[host], port, timeout)
        done += 1
        if progress and (done % 25 == 0 or done == total):
            progress(done, total, result)
        return result

    tasks = [_one(host, port) for host in hosts for port in ports]
    results = await asyncio.gather(*tasks)
    open_services = [r for r in results if r.state == "open"]
    open_services.sort(key=lambda r: (r.host, r.port))
    return open_services
