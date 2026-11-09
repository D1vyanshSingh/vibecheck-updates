"""SSRF guard for website assessments.

A user may only assess a URL they control. That makes the URL attacker-supplied
input to a server-side fetch, so every hop is checked before it is requested:

* scheme must be http or https, and no credentials may appear in the URL;
* the hostname is resolved and *every* returned address must be globally
  routable — loopback, private, link-local, multicast, reserved and the cloud
  metadata address are refused;
* redirects are not followed automatically; each Location is re-guarded.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 3


class URLGuardError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class GuardedURL:
    original: str
    normalized: str
    host: str
    port: int
    scheme: str
    addresses: tuple[str, ...]

    def replaces(self, other: "GuardedURL") -> bool:
        return (self.host, self.port) != (other.host, other.port)


def _normalize(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        raise URLGuardError("A URL is required.")
    if len(candidate) > MAX_URL_LENGTH:
        raise URLGuardError("URL is too long.")
    if "://" not in candidate:
        candidate = "https://" + candidate

    parts = urlsplit(candidate)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLGuardError("Only http and https URLs can be assessed.")
    if not parts.hostname:
        raise URLGuardError("That URL has no hostname.")
    if parts.username or parts.password:
        raise URLGuardError("URLs with embedded credentials are refused.")

    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise URLGuardError("That URL has an invalid port.") from exc

    if host in BLOCKED_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
        raise URLGuardError("That host is not eligible for assessment.")

    path = parts.path or "/"
    normalized = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))
    return normalized, host, port, parts.scheme.lower()


def _addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        ipaddress.ip_address(host)
        return (host,)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise URLGuardError("That hostname did not resolve.") from exc

    found: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in found:
            found.append(address)
    if not found:
        raise URLGuardError("That hostname did not resolve.")
    return tuple(found)


def _reject_private(address: str, *, allow_private: bool = False) -> None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise URLGuardError("That host did not resolve to an IP address.") from exc

    # Cloud metadata and link-local ranges are never eligible, not even in the
    # explicitly opted-in private mode used for local test targets.
    if ip.is_link_local or ip.is_multicast or ip.is_reserved:
        raise URLGuardError("That address is inside a private or reserved range.")
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("169.254.0.0/16"):
        raise URLGuardError("Cloud metadata endpoints are refused.")
    if allow_private:
        return
    if ip.is_loopback or ip.is_private:
        raise URLGuardError("That address is inside a private or reserved range.")
    if ip.is_unspecified:
        raise URLGuardError("That address is not routable.")
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("169.254.0.0/16"):
        raise URLGuardError("Cloud metadata endpoints are refused.")
    if not ip.is_global:
        raise URLGuardError("That address is not globally routable.")


def guard_url(url: str) -> GuardedURL:
    from app.config import settings

    normalized, host, port, scheme = _normalize(url)
    addresses = _addresses(host, port)
    allow_private = settings.allow_private_assessment_hosts
    for address in addresses:
        _reject_private(address, allow_private=allow_private)
    return GuardedURL(
        original=url,
        normalized=normalized,
        host=host,
        port=port,
        scheme=scheme,
        addresses=addresses,
    )
