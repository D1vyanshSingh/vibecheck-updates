"""Local test rig: fake services with deliberate vulnerabilities for scanner tests.

Run:  python3 tests/fake_services.py   (serve until Ctrl+C)
One service per protocol family, each with the weakness vulnscan is meant to
report (and nothing that would make a false positive look true):

  21/2121  FTP       anonymous login, vsftpd 2.3.4 banner, cleartext
  2375     Docker    unauthenticated /version API over plain HTTP
  2379     etcd      unauthenticated /health and /version
  5601     Kibana    unauthenticated /api/status dashboard
  6379     Redis     no authentication (INFO answers)
  8080     HTTP      directory listing, stack trace, no security headers
  8443     HTTPS     self-signed certificate
  9090     Prometheus unauthenticated /api/v1/targets
  9200     Elasticsearch open cluster (health + index list)
  10250    kubelet   anonymous /pods listing
  11211    memcached no authentication (stats answers)
  15672    RabbitMQ  management API without a login
  27017    MongoDB   handshake + listDatabases without authentication
"""

import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(ROOT, "out")


def raw_server(port: int, handler) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(16)

    def accept_loop() -> None:
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    print(f"  fake service on {port}")


def redis_handler(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"# Server\r\nredis_version:7.2.4\r\n"
                         b"redis_mode:standalone\r\nresponse:2\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def memcached_handler(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"STAT pid 4242\r\nSTAT version 1.6.9\r\nSTAT curr_items 1\r\nEND\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def ftp_handler(conn: socket.socket) -> None:
    try:
        conn.sendall(b"220 (vsFTPD 2.3.4)\r\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            replies = b""
            for line in data.decode("latin-1", "replace").split("\r\n"):
                line = line.strip().upper()
                if not line:
                    continue
                if line.startswith("USER"):
                    replies += b"331 Please specify the password.\r\n"
                elif line.startswith("PASS"):
                    replies += b"230 Login successful.\r\n"
                else:
                    replies += b"200 command ok\r\n"
            if replies:
                conn.sendall(replies)
    except OSError:
        pass
    finally:
        conn.close()


_HTTP_BODY = (b"<html><head><title>Test Application Home</title></head>"
              b"<body><h1>placeholder</h1></body></html>")


def http_payload() -> bytes:
    header = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
              f"Content-Length: {len(_HTTP_BODY)}\r\nServer: TestWeb/1.2\r\n"
              "Connection: close\r\n\r\n").encode("latin-1")
    return header + _HTTP_BODY


def plain_http_handler(conn: socket.socket) -> None:
    try:
        conn.recv(8192)
        conn.sendall(http_payload())
    except OSError:
        pass
    finally:
        conn.close()


def make_https_handler(cert_dir: str, port: int = 8443) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(cert_dir, "selfsigned.pem"),
                        os.path.join(cert_dir, "selfsigned.key"))

    def handler(conn: socket.socket) -> None:
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(8192)
                tls_conn.sendall(http_payload())
        except OSError:
            pass

    raw_server(port, handler)


_STATUS_REASONS = {200: "OK", 401: "Unauthorized", 403: "Forbidden",
                   404: "Not Found"}


def make_json_http_server(port: int, routes: dict, server: str) -> None:
    """Serve fixed routes from a dict: path -> (status, body, extra_headers)."""

    def handler(conn: socket.socket) -> None:
        try:
            request = conn.recv(8192).decode("latin-1", "replace")
            parts = request.split(" ")
            path = (parts[1] if len(parts) > 1 else "/").split("?")[0]
            status, body, extra = routes.get(path, (404, {"error": "not found"}, {}))
            if isinstance(body, (dict, list)):
                payload = json.dumps(body).encode("utf-8")
                content_type = "application/json"
            else:
                payload = body
                content_type = "text/html; charset=utf-8"
            headers = {"Content-Type": content_type, "Server": server,
                       "Content-Length": str(len(payload)),
                       "Connection": "close"}
            headers.update(extra)
            head = (f"HTTP/1.1 {status} {_STATUS_REASONS.get(status, 'OK')}\r\n"
                    + "".join(f"{key}: {value}\r\n" for key, value in headers.items())
                    + "\r\n").encode("latin-1")
            conn.sendall(head + payload)
        except OSError:
            pass
        finally:
            conn.close()

    raw_server(port, handler)


# --- MongoDB wire fixture -------------------------------------------------

def _bson_element(name: str, value) -> bytes:
    if isinstance(value, bool):
        return b"\x08" + name.encode() + b"\x00" + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return b"\x10" + name.encode() + b"\x00" + struct.pack("<i", value)
    if isinstance(value, list):
        inner = b"".join(_bson_element(str(i), item)
                         for i, item in enumerate(value))
        doc = struct.pack("<i", len(inner) + 5) + inner + b"\x00"
        return b"\x04" + name.encode() + b"\x00" + doc
    if isinstance(value, dict):
        inner = b"".join(_bson_element(key, item)
                         for key, item in value.items())
        doc = struct.pack("<i", len(inner) + 5) + inner + b"\x00"
        return b"\x03" + name.encode() + b"\x00" + doc
    return (b"\x02" + name.encode() + b"\x00"
            + struct.pack("<i", len(str(value).encode()) + 1)
            + str(value).encode() + b"\x00")



def bson_document(fields: dict) -> bytes:
    body = b"".join(_bson_element(name, value) for name, value in fields.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def mongo_reply(document: bytes, request_id: int = 1) -> bytes:
    # OP_REPLY: flags, cursorID (int64), startingFrom, numberReturned, document.
    body = struct.pack("<iqii", 0, 0, 0, 1) + document
    return struct.pack("<iiii", 16 + len(body), request_id, 1, 1) + body


def _read_mongo_request(conn: socket.socket) -> bytes:
    header = conn.recv(4)
    if len(header) < 4:
        return b""
    length = struct.unpack("<i", header)[0]
    return conn.recv(max(1, length - 4))


def mongo_handler(conn: socket.socket) -> None:
    """Handshake + listDatabases, both answered without authentication."""
    try:
        if not _read_mongo_request(conn):
            return
        conn.sendall(mongo_reply(bson_document({
            "version": "4.4.6", "maxWireVersion": 9, "ok": 1})))
        command = _read_mongo_request(conn)
        if "listDatabases" in command.decode("latin-1", "replace"):
            conn.sendall(mongo_reply(bson_document({
                "databases": [{"name": "admin"}, {"name": "lab"}],
                "totalSize": 4096, "ok": 1})))
    except OSError:
        pass
    finally:
        conn.close()


def start_http_subprocess(port: int) -> None:
    handler = http.server.SimpleHTTPRequestHandler
    try:
        allow_reuse = socketserver.TCPServer.allow_reuse_address
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
        socketserver.TCPServer.allow_reuse_address = allow_reuse
    except OSError as exc:
        print(f"  port {port} already in use ({exc}); skipping it")
        return
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"  http.server on {port}")


def main() -> int:
    os.makedirs(CERT_DIR, exist_ok=True)
    pem = os.path.join(CERT_DIR, "selfsigned.pem")
    key = os.path.join(CERT_DIR, "selfsigned.key")
    if not (os.path.exists(pem) and os.path.exists(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "3650", "-subj", "/CN=testapp.local",
             "-keyout", key, "-out", pem],
            check=True, capture_output=True)
        print("  generated self-signed certificate")

    for port, handler_fn in ((6379, redis_handler), (11211, memcached_handler),
                             (8443, None)):
        try:
            if handler_fn is None:
                make_https_handler(CERT_DIR, port)
            else:
                raw_server(port, handler_fn)
        except OSError as exc:
            print(f"  port {port} unavailable ({exc}); skipping it")
    # Windows reserves some low ports (PermissionError) → fall back to 2121.
    for ftp_port in (21, 2121):
        try:
            raw_server(ftp_port, ftp_handler)
            break
        except PermissionError:
            print(f"  port {ftp_port} reserved by Windows, trying next")
    start_http_subprocess(8080)
    fixtures = (
        (2375, {"/": (200, {"message": "page not found"}, {}),
                "/version": (200, {"Version": "20.10.6", "ApiVersion": "1.41",
                                   "Os": "linux"}, {})},
         "Docker/20.10.6 (linux)"),
        (2379, {"/health": (200, {"health": "true"}, {}),
                "/version": (200, {"etcdserver": "3.5.5"}, {})}, "etcd/3.5.5"),
        (5601, {"/api/status": (200, {"status": {"overall": {"level":
                                                           "available"}},
                                      "version": {"number": "7.17.1"}}, {}),
                "/": (200, b"<html><title>Kibana</title></html>", {})},
         "Kibana/7.17.1"),
        (9090, {"/api/v1/targets": (200, {"status": "success",
                                          "data": {"activeTargets": []}}, {})},
         "Prometheus/2.40.1"),
        (9200, {"/": (200, {"cluster_name": "lab-es", "version": "7.17.1"}, {}),
                "/_cluster/health": (200, {"cluster_name": "lab-es",
                                            "status": "green"}, {})},
         "Elastic/7.17.1"),
        (10250, {"/healthz": (200, b"ok", {}),
                 "/pods": (200, {"kind": "PodList", "apiVersion": "v1",
                                 "items": []}, {})}, "kubelet/1.26.1"),
        (15672, {"/api/overview": (200, {"management_version": "3.9.11",
                                         "rabbitmq_version": "3.9.11"}, {}),
                 "/": (200, b"<html><title>RabbitMQ</title></html>", {})},
         "RabbitMQ/3.9.11"),
    )
    for fixture_port, routes, server in fixtures:
        try:
            make_json_http_server(fixture_port, routes, server)
        except OSError as exc:
            print(f"  port {fixture_port} unavailable ({exc}); skipping it")
    try:
        raw_server(27017, mongo_handler)
    except OSError as exc:
        print(f"  port 27017 unavailable ({exc}); skipping it")

    print("test services running — Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
