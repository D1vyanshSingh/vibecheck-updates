"""VibeCheck scan service.

Runs the bundled vulnscan engine behind an HTTP endpoint so the deployed site
can scan without a Python process on the web host. Only the standard library is
used: the engine is dependency-free already, and the request handling here is
small enough that a framework would only add build weight.

Endpoints
    GET  /health
        -> {"status": "ok", "engine": "vulnscan 0.1.0"}

    POST /scan   {"host": "example.com", "port": 443, "label": "..."}
        -> {"status": "ok", "report": {...}, "html": "<!DOCTYPE html>..."}

Every request must carry ``x-scan-secret`` matching the ``SCAN_SECRET``
environment variable; the endpoint runs on a public URL, and without it anyone
could drive scans from this host.

The HTML report is returned inline rather than stored: serverless instances
share no disk, and the caller already holds the report it was rendered from.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tempfile
import traceback
from contextlib import redirect_stdout
from pathlib import Path
from wsgiref.simple_server import make_server

from vulnscan import __version__
from vulnscan.cli import main as cli_main

MAX_BODY = 8 * 1024
MAX_HOST = 253

# A host that starts with "-" would be read as a flag by the CLI, and
# whitespace/control characters have no business in one.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]+$")


class RequestError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _json(start_response, status: int, payload: dict, headers=None):
    body = json.dumps(payload).encode("utf-8")
    all_headers = [("Content-Type", "application/json; charset=utf-8"),
                   ("Content-Length", str(len(body))),
                   ("Cache-Control", "no-store")]
    all_headers.extend(headers or [])
    start_response(f"{status} {_REASONS.get(status, '')}".strip(), all_headers)
    return [body]


_REASONS = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
            404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error",
            503: "Service Unavailable"}


def _authorised(environ) -> bool:
    secret = os.environ.get("SCAN_SECRET", "")
    if not secret:
        raise RequestError(503, "SCAN_SECRET is not configured on the scanner.")
    return environ.get("HTTP_X_SCAN_SECRET", "") == secret


def _read_json(environ) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise RequestError(400, "Invalid Content-Length.") from None
    if length <= 0:
        raise RequestError(400, "Expected a JSON body.")
    if length > MAX_BODY:
        raise RequestError(400, "Request body is too large.")
    raw = environ["wsgi.input"].read(length)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise RequestError(400, "Body is not valid JSON.") from None
    if not isinstance(payload, dict):
        raise RequestError(400, "Body must be a JSON object.")
    return payload


def _scan(host: str, port: int, label: str) -> tuple[dict, str]:
    """Run one URL scan and return the report plus its branded HTML."""
    ports = ",".join(str(p) for p in dict.fromkeys([port, 80, 443, 8080, 8443]))
    workdir = tempfile.mkdtemp(prefix="vibecheck-scan-")
    html_path = os.path.join(workdir, "report.html")
    json_path = os.path.join(workdir, "report.json")

    argv = [
        host,
        "-p", ports,
        "-r", label,
        "--engine", "native",
        "-o", workdir,
        "--html", html_path,
        "--json", json_path,
        "--no-pdf",      # no browser on this host; the caller offers print
        "--no-color",
        "-q",
    ]

    try:
        # The CLI reports progress on stdout; keep it out of any response.
        with redirect_stdout(io.StringIO()):
            cli_main(argv)

        if not os.path.exists(json_path):
            raise RequestError(500, "The scanner produced no report.")

        report = json.loads(Path(json_path).read_text(encoding="utf-8"))
        html = Path(html_path).read_text(encoding="utf-8") if os.path.exists(html_path) else ""
        return report, html
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def application(environ, start_response):
    """WSGI entrypoint. Vercel loads this as the Python service app."""
    path = environ.get("PATH_INFO", "/") or "/"
    method = environ.get("REQUEST_METHOD", "GET").upper()

    try:
        if path == "/health":
            if method not in ("GET", "HEAD"):
                raise RequestError(405, "Use GET.")
            return _json(start_response, 200, {
                "status": "ok",
                "engine": f"vulnscan {__version__}",
            })

        if path != "/scan":
            raise RequestError(404, "Unknown path. Use POST /scan or GET /health.")
        if method != "POST":
            raise RequestError(405, "Use POST.")
        if not _authorised(environ):
            raise RequestError(401, "Invalid scan secret.")

        payload = _read_json(environ)
        raw_host = str(payload.get("host") or "").strip().lower()
        if not raw_host:
            raise RequestError(400, "Missing host.")
        if len(raw_host) > MAX_HOST or not _HOST_RE.match(raw_host) or raw_host.startswith("-"):
            raise RequestError(400, "That host is not a valid scan target.")

        try:
            port = int(payload.get("port") or 0)
        except (TypeError, ValueError):
            raise RequestError(400, "Port must be a number.") from None
        if not 1 <= port <= 65535:
            raise RequestError(400, "Port must be between 1 and 65535.")

        label = str(payload.get("label") or f"URL scan — {raw_host}")[:120]

        report, html = _scan(raw_host, port, label)
        return _json(start_response, 200, {
            "status": "ok",
            "report": report,
            "html": html,
        })
    except RequestError as err:
        return _json(start_response, err.status, {"status": "error", "message": err.message})
    except Exception:                                   # noqa: BLE001 - boundary
        traceback.print_exc()
        return _json(start_response, 500, {
            "status": "error",
            "message": "The scan failed inside the scanner service.",
        })


if __name__ == "__main__":
    # Local run: SCAN_SECRET=devsecret python3 main.py
    port = int(os.environ.get("PORT", "8020"))
    print(f"scan service on http://localhost:{port}")
    with make_server("127.0.0.1", port, application) as server:
        server.serve_forever()
