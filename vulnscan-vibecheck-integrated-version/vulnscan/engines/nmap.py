"""nmap detection engine.

nmap is an *optional external dependency*: it is discovered on ``PATH`` (or via
``VULNSCAN_NMAP``) and invoked as a subprocess. It is never bundled or vendored,
because its licence forbids redistribution inside proprietary products and the
project's value is the report it produces around someone else's detector.

The engine runs ``nmap -sV`` for identification only, parses the XML into the
shared ``PortService`` model, and then collects the same TLS/banner/HTTP
evidence the native engine collects, so the checks downstream see one shape.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..scanner import (DEFAULT_TIMEOUT, UNIDENTIFIED_SERVICE_NAMES, PortService,
                       collect_evidence)
from .errors import EngineError, EngineUnavailable

NAME = "nmap"

# Curated read-only NSE scripts. The first group is tagged ``safe`` in nmap's
# own script.db; the extended group is read-only too but tagged ``intrusive``
# (many requests, or a handshake a fragile service may log or drop), so it is
# never on by default. Nothing here can write, brute-force or exploit.
SAFE_SCRIPTS = (
    "ssl-cert", "http-title", "http-headers", "smb-os-discovery",
    "rdp-ntlm-info", "docker-version", "snmp-info",
)
EXTENDED_SCRIPTS = SAFE_SCRIPTS + (
    "ssl-enum-ciphers", "ssh-auth-methods", "http-enum",
)
NSE_PROFILES: dict[str, tuple[str, ...]] = {
    "off": (),
    "safe": SAFE_SCRIPTS,
    "extended": EXTENDED_SCRIPTS,
}
SCRIPT_TIMEOUT_S = 30

# Standard install locations when the binary is not on PATH.
_COMMON_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/usr/sbin/nmap",
    "/opt/homebrew/bin/nmap",
    "/opt/local/bin/nmap",
]

_VERSION_CACHE: dict[str, str] = {}


class NmapError(EngineError):
    """nmap failed, emitted unparseable output, or produced nothing usable."""


def find_nmap() -> str | None:
    """Return an executable nmap path, or None when nmap is unavailable."""
    override = os.environ.get("VULNSCAN_NMAP", "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
        return shutil.which(override)
    found = shutil.which("nmap")
    if found:
        return found
    for path in _COMMON_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def nmap_version(path: str) -> str:
    """Version string reported by ``nmap --version`` (cached per path)."""
    if path in _VERSION_CACHE:
        return _VERSION_CACHE[path]
    version = ""
    try:
        proc = subprocess.run([path, "--version"], capture_output=True,
                              text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None:
        match = re.search(r"Nmap version (\S+)", proc.stdout or "")
        if match:
            version = match.group(1)
    _VERSION_CACHE[path] = version
    return version


def port_args(ports: list[int]) -> list[str]:
    """Compact ``-p`` arguments for a port list (``-p-`` for the full range)."""
    unique = sorted({int(p) for p in ports})
    if not unique:
        raise ValueError("no ports to scan")
    if unique[0] == 1 and unique[-1] == 65535 and len(unique) == 65535:
        return ["-p-"]
    parts: list[str] = []
    start = prev = unique[0]
    for port in unique[1:]:
        if port == prev + 1:
            prev = port
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = port
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ["-p", ",".join(parts)]


def build_argv(nmap_path: str, hosts: list[str], ports: list[int], *,
               scripts: list[str] | None = None,
               host_timeout_s: int = 300,
               service_detection: bool = True,
               version_intensity: int | None = None) -> list[str]:
    """Build the nmap command line. No shell, no user-controlled flags."""
    argv = [nmap_path]
    if service_detection:
        argv.append("-sV")
        if version_intensity is not None:
            argv += ["--version-intensity", str(int(version_intensity))]
    argv += [
        "-Pn",                      # treat targets as up; ICMP is often filtered
        "-n",                       # no reverse DNS: host names come from targets
        "-T4",
        "--max-retries", "2",
        "--host-timeout", f"{host_timeout_s}s",
    ]
    if scripts:
        argv += ["--script", ",".join(scripts),
                 "--script-timeout", f"{SCRIPT_TIMEOUT_S}s"]
    argv += ["-oX", "-"]
    argv += port_args(ports)
    argv += list(hosts)
    return argv


def _invoke(argv: list[str], timeout_s: float | None) -> str:
    """Run nmap and return its XML, or raise NmapError with a useful message."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout_s)
    except FileNotFoundError as exc:
        raise EngineUnavailable(f"nmap was not found at {argv[0]!r}") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap did not finish within {timeout_s:.0f}s") from exc
    except OSError as exc:
        raise NmapError(f"could not run nmap: {exc}") from exc
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = lines[-1] if lines else f"exit status {proc.returncode}"
        raise NmapError(f"nmap failed (exit {proc.returncode}): {detail}")
    if "<nmaprun" not in (proc.stdout or ""):
        raise NmapError("nmap produced no XML output")
    return proc.stdout


def _target_names(targets: list[str]) -> dict[str, str]:
    """Map resolved IPs back to the host names the user asked for."""
    names: dict[str, str] = {}
    for target in targets:
        try:
            for info in socket.getaddrinfo(target, None, socket.AF_INET):
                names.setdefault(info[4][0], target)
        except OSError:
            continue
    return names


def _script_output(script: ET.Element) -> str:
    """Usable output of one NSE script; failures and empty runs are dropped."""
    text = (script.get("output", "") or "").strip()
    if not text or "Script execution failed" in text or text.startswith("ERROR:"):
        return ""
    return text


def _os_matches(host_el: ET.Element) -> list[dict]:
    matches: list[dict] = []
    for match in host_el.findall("os/osmatch"):
        entry = {"name": match.get("name", ""),
                 "accuracy": int(match.get("accuracy", "0") or 0)}
        osclass = match.find("osclass")
        if osclass is not None:
            family = osclass.get("osfamily", "")
            if family:
                entry["family"] = family
        matches.append(entry)
    return matches


def parse_xml(xml_text: str,
              targets: list[str] | None = None) -> tuple[list[PortService], dict]:
    """Parse nmap XML into PortService objects plus scan metadata."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"could not parse nmap XML: {exc}") from exc

    names = _target_names(targets or [])
    services: list[PortService] = []
    hosts_up = hosts_down = 0
    skipped: dict[str, int] = {}
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            hosts_down += 1
            continue
        hosts_up += 1

        addr = ""
        for address in host_el.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6"):
                addr = address.get("addr", "")
                break
        if not addr:
            continue

        hostname_el = host_el.find("hostnames/hostname")
        ptr = hostname_el.get("name", "") if hostname_el is not None else ""
        label = names.get(addr) or ptr or addr

        os_matches = _os_matches(host_el)
        times = host_el.find("times")
        rtt_ms: int | None = None
        if times is not None and times.get("srtt"):
            try:
                rtt_ms = max(1, int(int(times.get("srtt")) / 1000))
            except ValueError:
                rtt_ms = None

        host_scripts = {script.get("id", ""): _script_output(script)
                        for script in host_el.findall("hostscript/script")
                        if _script_output(script)}

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else "") or "unknown"
            if state != "open":
                skipped[state] = skipped.get(state, 0) + 1
                continue
            try:
                port = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            service_el = port_el.find("service")
            attrs = service_el.attrib if service_el is not None else {}
            try:
                confidence = int(attrs.get("conf", "0") or 0)
            except ValueError:
                confidence = 0
            service_name = attrs.get("name", "")
            if attrs.get("tunnel") == "ssl" and service_name == "http":
                service_name = "https"      # nmap reports "ssl/http"

            script_output = dict(host_scripts)
            for script in port_el.findall("script"):
                text = _script_output(script)
                if text:
                    script_output[script.get("id", "")] = text

            # "tcpwrapped" and "unknown" are nmap saying it could not read a
            # protocol, not names for a service. Keeping them as the service
            # would present a blind port as an identified one.
            identified = (service_name.strip().lower().rstrip("?")
                          not in UNIDENTIFIED_SERVICE_NAMES)
            identification_error = "" if identified else (
                f"nmap reported {service_name or 'no service name'} — the port "
                "answered TCP but sent no readable protocol")

            svc = PortService(
                host=label,
                ip=addr,
                port=port,
                state="open",
                service=service_name if identified else "",
                identification_error=identification_error,
                product=attrs.get("product", ""),
                version=attrs.get("version", ""),
                proto=port_el.get("protocol", "tcp"),
                source=NAME,
                nmap_conf=confidence,
                extrainfo=attrs.get("extrainfo", ""),
                os_matches=list(os_matches),
                scripts=script_output,
                rtt_ms=rtt_ms,
                scanned_at=scanned_at,
                identity_source=("nmap" if confidence >= 8 and identified
                                 else "" if identification_error else "port"),
                identity_claims=[{
                    "source": "nmap",
                    "service": service_name,
                    "product": attrs.get("product", ""),
                    "version": attrs.get("version", ""),
                    "confidence": confidence,
                }],
            )
            if service_el is not None:
                svc.cpe = [cpe.text.strip() for cpe in service_el.findall("cpe")
                           if cpe.text and cpe.text.strip()]
            services.append(svc)

    services.sort(key=lambda s: (s.ip, s.port))
    meta = {
        "engine": NAME,
        "version": root.get("version", ""),
        "hosts_up": hosts_up,
        "hosts_down": hosts_down,
        "open_ports": len(services),
        "skipped_ports": skipped,
    }
    return services, meta


def identity_is_weak(svc: PortService) -> bool:
    """True when nmap's name is a port-table guess rather than a probe result."""
    name = (svc.service or "").strip().lower()
    if svc.nmap_conf < 8 or not name or name == "unknown" or name.endswith("?"):
        return True
    return False


def _is_privileged() -> bool:
    try:
        return os.geteuid() == 0        # type: ignore[attr-defined]
    except AttributeError:              # Windows
        return False


async def _enrich(services: list[PortService], timeout: float,
                  concurrency: int) -> None:
    """Collect native TLS/banner/HTTP evidence for nmap's open ports."""
    limit = max(1, min(32, concurrency))
    semaphore = asyncio.Semaphore(limit)

    async def one(svc: PortService) -> None:
        if svc.proto != "tcp":
            return
        # A low-confidence nmap name (table guess, "unknown", "foo?") must not
        # override what the service actually said on the wire. In that case let
        # the native evidence pass name it; otherwise keep nmap's identification.
        weak = identity_is_weak(svc)
        async with semaphore:
            await collect_evidence(svc, timeout, guess_names=weak)

    await asyncio.gather(*(one(svc) for svc in services))


async def run(hosts: list[str], ports: list[int], *, timeout: float = DEFAULT_TIMEOUT,
              concurrency: int = 256, progress=None,
              scripts: list[str] | None = None,
              host_timeout_s: int = 300,
              process_timeout_s: float = 1800.0,
              enrich: bool = True,
              version_intensity: int | None = None) -> tuple[list[PortService], dict]:
    """Identify open services with nmap; returns (services, metadata)."""
    path = find_nmap()
    if not path:
        raise EngineUnavailable(
            "nmap is not installed or not on PATH; install it or use "
            "--engine native")

    argv = build_argv(path, hosts, ports, scripts=scripts,
                      host_timeout_s=host_timeout_s,
                      version_intensity=version_intensity)
    started = time.monotonic()
    xml_text = await asyncio.to_thread(_invoke, argv, process_timeout_s)
    services, meta = parse_xml(xml_text, targets=hosts)
    meta["_raw_xml"] = xml_text
    if enrich:
        await _enrich(services, timeout, concurrency)
    meta.update({
        "engine": NAME,
        "version": meta.get("version") or nmap_version(path),
        "scripts": list(scripts or ()),
        "argv": argv,
        "privileged": _is_privileged(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "open_ports": len(services),
        "host_timeout_seconds": host_timeout_s,
        "process_timeout_seconds": process_timeout_s,
    })
    return services, meta
