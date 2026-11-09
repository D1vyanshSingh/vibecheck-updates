"""Authorized website assessment.

Read-only: GET requests against the URL the customer supplied, with redirects
re-checked hop by hop, a byte ceiling and no body execution. Findings are
evidence-linked header and transport observations, not exploit claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from app.assessment.urlguard import MAX_REDIRECTS, URLGuardError, guard_url
from app.scanners.types import Finding

MAX_BYTES = 512 * 1024
TIMEOUT_SECONDS = 15.0
USER_AGENT = "VibeCheck-Assessment/1.0 (+https://vibecheck.dev)"


@dataclass
class WebAssessment:
    requested_url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    redirects: list[str] = field(default_factory=list)
    body_bytes: int = 0
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "headers": self.headers,
            "redirects": self.redirects,
            "body_bytes": self.body_bytes,
            "error": self.error,
            "limitations": self.limitations,
        }


def _header(headers: httpx.Headers, name: str) -> str:
    return (headers.get(name) or "").strip()


def _finding(rule: str, title: str, severity: str, description: str, remediation: str, url: str) -> Finding:
    return Finding(
        scanner="web_headers",
        rule_id=rule,
        title=title,
        severity=severity,
        category="configuration",
        confidence="high",
        description=description,
        file_path=url,
        remediation=remediation,
        evidence=f"URL: {url}",
        metadata={"scanner_version": "builtin", "surface": "http"},
    ).normalize()


def evaluate(url: str, status: int, headers: httpx.Headers, scheme: str) -> list[Finding]:
    """Pure header/transport checks, kept separate so they are testable."""
    findings: list[Finding] = []
    hsts = _header(headers, "strict-transport-security")
    csp = _header(headers, "content-security-policy")
    frame = _header(headers, "x-frame-options")
    ctype = _header(headers, "content-type")
    server = _header(headers, "server")
    powered = _header(headers, "x-powered-by")

    if scheme == "http":
        findings.append(
            _finding(
                "VC-WEB-NO-TLS",
                "Site is served over plain HTTP",
                "high",
                "The assessed URL responded over HTTP, so credentials, session cookies and "
                "page content can be read or modified in transit.",
                "Redirect all HTTP traffic to HTTPS and enable HSTS once the redirect is stable.",
                url,
            )
        )
    elif not hsts:
        findings.append(
            _finding(
                "VC-WEB-NO-HSTS",
                "Missing Strict-Transport-Security",
                "medium",
                "HTTPS is used but the response does not ask browsers to keep using it, "
                "so a downgrade on the first request remains possible.",
                "Send Strict-Transport-Security with a max-age of at least 15552000 and includeSubDomains where valid.",
                url,
            )
        )

    if not csp:
        findings.append(
            _finding(
                "VC-WEB-NO-CSP",
                "Missing Content-Security-Policy",
                "medium",
                "Without a policy, injected markup can load scripts from any origin. "
                "This raises the impact of any injection flaw but is not itself proof of one.",
                "Ship a restrictive Content-Security-Policy; start in report-only mode and tighten iteratively.",
                url,
            )
        )

    if not frame and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "VC-WEB-NO-FRAME-POLICY",
                "No clickjacking protection declared",
                "low",
                "Neither X-Frame-Options nor CSP frame-ancestors is present, so the page "
                "may be embedded by another site.",
                "Set CSP frame-ancestors 'none' (or X-Frame-Options: DENY) unless embedding is intentional.",
                url,
            )
        )

    if server or powered:
        findings.append(
            _finding(
                "VC-WEB-BANNER",
                "Server software is advertised",
                "info",
                "Response headers disclose the server or framework version, which helps "
                "an attacker pick known-vulnerable payloads.",
                "Remove or genericise the Server and X-Powered-By headers at the edge.",
                url,
            )
        )

    if "text/html" in ctype.lower() and not csp:
        pass  # already reported as missing CSP

    if status >= 500:
        findings.append(
            _finding(
                "VC-WEB-SERVER-ERROR",
                "Assessed page returned a server error",
                "low",
                "The page returned a 5xx response. Error pages often leak stack traces or "
                "framework internals, so review what this response body contains.",
                "Return a generic error page in production and log details server-side.",
                url,
            )
        )

    return findings


def assess_url(url: str) -> WebAssessment:
    """Fetch the URL once, following at most three pre-validated redirects."""
    assessment = WebAssessment(requested_url=url)
    current = url

    try:
        guarded = guard_url(current)
    except URLGuardError as exc:
        assessment.error = exc.message
        return assessment

    with httpx.Client(
        timeout=TIMEOUT_SECONDS,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                with client.stream("GET", guarded.normalized) as response:
                    if response.is_redirect:
                        location = response.headers.get("location", "")
                        if not location:
                            assessment.error = "Redirect had no Location header."
                            return assessment
                        target = urljoin(guarded.normalized, location)
                        assessment.redirects.append(target)
                        try:
                            guarded = guard_url(target)
                        except URLGuardError as exc:
                            assessment.error = f"Redirect refused: {exc.message}"
                            return assessment
                        current = target
                        continue

                    body = b""
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) >= MAX_BYTES:
                            assessment.limitations.append(
                                f"Response body truncated at {MAX_BYTES} bytes; only headers were evaluated."
                            )
                            break

                    assessment.status_code = response.status_code
                    assessment.final_url = str(response.url)
                    assessment.headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "content-type",
                            "content-security-policy",
                            "strict-transport-security",
                            "x-frame-options",
                            "server",
                            "x-powered-by",
                            "referrer-policy",
                            "permissions-policy",
                            "set-cookie",
                        }
                    }
                    assessment.body_bytes = len(body)
                    assessment.findings = evaluate(
                        str(response.url),
                        response.status_code,
                        response.headers,
                        urlparse_scheme(str(response.url)),
                    )
                    assessment.limitations.append(
                        "Header and transport observations only. No authentication, fuzzing, "
                        "injection testing or business-logic review was performed."
                    )
                    if "set-cookie" in response.headers:
                        assessment.limitations.append(
                            "Cookie attributes were not scored in this version; review them manually."
                        )
                    return assessment
            except httpx.HTTPError as exc:
                assessment.error = f"Request failed: {type(exc).__name__}"
                return assessment

    assessment.error = "Too many redirects."
    return assessment


def urlparse_scheme(url: str) -> str:
    return url.split(":", 1)[0].lower() if ":" in url else "https"
