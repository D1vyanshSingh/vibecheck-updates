"""First-bytes protocol identification and the one-connection native probe.

The native engine must identify a service from what it sent, not from the port
number, and must do it over one connection per port. These tests stand up
services that speak each protocol on an *unassigned* port, so nothing but the
wire can name them, and count how many TCP connections a probe used.
"""

from __future__ import annotations

import asyncio
import struct
import unittest
from unittest import mock

from vulnscan import checks, scanner
from vulnscan.scanner import classify_first_bytes, probe_port


def bson_doc() -> bytes:
    """Tiny valid BSON document: {"ok": 1.0}."""
    inner = b"\x01ok\x00" + struct.pack("<d", 1.0)
    return struct.pack("<i", len(inner) + 5) + inner + b"\x00"


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.18.0\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 47\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><head><title>Wire Test</title></head></html>"
)
REDIS_INFO = b"# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\n"
MYSQL_HANDSHAKE = (struct.pack("<i", 74)[:3] + b"\x00\x0a5.7.31-log\x00"
                   + b"\x92\x10\x00\x00abCdEfGh\x00")


class ClassifierTests(unittest.TestCase):
    def test_server_first_greetings(self):
        cases = {
            b"SSH-2.0-OpenSSH_9.6p1\r\n": "ssh",
            b"220 (vsFTPD 2.3.4)\r\n": "ftp",
            b"220 mail.example ESMTP Postfix\r\n": "smtp",
            b"+OK POP3 server ready\r\n": "pop3",
            b"* OK [CAPABILITY IMAP4rev1] ready\r\n": "imap",
            b"RFB 003.008\n": "vnc",
            b"@RSYNCD: 31.0\n": "rsync",
            b"\xff\xfd\x18Welcome\r\nlogin: ": "telnet",
        }
        for data, expected in cases.items():
            with self.subTest(data=data):
                self.assertEqual(expected, classify_first_bytes(data))

    def test_bare_220_is_only_a_family(self):
        self.assertEqual("ftp/smtp", classify_first_bytes(b"220 ready\r\n"))

    def test_protocol_replies(self):
        cases = {
            b"# Server\r\nredis_version:4.0.14\r\n": "redis",
            b"-NOAUTH Authentication required.\r\n": "redis",
            b"STAT pid 4242\r\nSTAT version 1.6.9\r\n": "memcached",
            b"imok": "zookeeper",
            b"HTTP/1.1 404 Not Found\r\n\r\n": "http",
            b"AMQP\x00\x00\x09\x01": "rabbitmq",
        }
        for data, expected in cases.items():
            with self.subTest(data=data):
                self.assertEqual(expected, classify_first_bytes(data))

    def test_binary_handshakes(self):
        mysql = struct.pack("<i", 74)[:3] + b"\x00\x0a" + b"5.7.31-log\x00"
        self.assertEqual("mysql", classify_first_bytes(mysql))
        self.assertEqual("postgresql", classify_first_bytes(
            b"E\x00\x00\x00\x1dSFATAL\x00C0A000\x00"))
        reply = struct.pack("<iiii", 16 + len(bson_doc()), 1, 1, 1) + bson_doc()
        self.assertEqual("mongodb", classify_first_bytes(reply))
        self.assertEqual("rdp", classify_first_bytes(
            bytes.fromhex("030000130ed000001234000200080000000000")))
        self.assertEqual("smb", classify_first_bytes(b"\xffSMB\x72\x00"))

    def test_tls_records_and_alerts(self):
        self.assertEqual("tls", classify_first_bytes(b"\x16\x03\x01\x00\x7d"))
        # A TLS listener answering a plaintext request with an alert.
        self.assertEqual("tls", classify_first_bytes(b"\x15\x03\x01\x00\x02\x02\x28"))

    def test_unknown_and_empty(self):
        self.assertEqual("", classify_first_bytes(b""))
        self.assertEqual("", classify_first_bytes(b"\x00\x01\x02\x03junk"))
        # HTTP bodies are never mistaken for a banner: the status line comes
        # first, so a page that mentions "login:" is still HTTP.
        self.assertEqual("http", classify_first_bytes(
            b"HTTP/1.1 200 OK\r\n\r\n<html>login:</html>"))


class Wire:
    """A one-shot TCP service that counts how often it was connected to."""

    def __init__(self, handler):
        self.handler = handler
        self.connections = 0
        self.server = None
        self.port = 0

    async def start(self):
        async def accept(reader, writer):
            self.connections += 1
            try:
                await self.handler(reader, writer)
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        self.server = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


async def ssh_handler(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-2ubuntu2\r\n")
    await writer.drain()
    await reader.read(1024)


async def http_handler(reader, writer):
    await reader.read(4096)
    writer.write(HTTP_RESPONSE)
    await writer.drain()


async def redis_handler(reader, writer):
    request = await reader.read(4096)
    if b"INFO" in request.upper():
        writer.write(REDIS_INFO)
    else:
        writer.write(b"-ERR unknown command\r\n")
    await writer.drain()


async def mysql_handler(reader, writer):
    writer.write(MYSQL_HANDSHAKE)
    await writer.drain()
    await reader.read(512)


async def mongo_handler(reader, writer):
    header = await reader.readexactly(4)
    length = struct.unpack("<i", header)[0]
    await reader.readexactly(max(0, length - 4))
    body = bson_doc()
    writer.write(struct.pack("<iiii", 16 + len(body), 1, 1, 1) + body)
    await writer.drain()


class NativeProbeTests(unittest.IsolatedAsyncioTestCase):
    async def probe(self, handler, timeout: float = 0.6):
        wire = await Wire(handler).start()
        self.addAsyncCleanup(wire.close)
        svc = await probe_port("127.0.0.1", "127.0.0.1", wire.port, timeout)
        return svc, wire

    async def test_ssh_is_identified_from_its_banner_in_one_connection(self):
        svc, wire = await self.probe(ssh_handler)
        self.assertEqual("ssh", svc.service)
        self.assertEqual("banner", svc.identity_source)
        self.assertIn("OpenSSH_9.6p1", svc.banner)
        self.assertEqual(("OpenSSH", "9.6p1"), (svc.product, svc.version))
        self.assertEqual(1, wire.connections)

    async def test_http_is_identified_and_parsed_in_one_connection(self):
        svc, wire = await self.probe(http_handler)
        self.assertEqual("http", svc.service)
        self.assertEqual("http", svc.identity_source)
        self.assertEqual(200, svc.http["status"])
        self.assertEqual("Wire Test", svc.http["title"])
        self.assertEqual(("nginx", "1.18.0"), (svc.product, svc.version))
        self.assertEqual(1, wire.connections)

    async def test_a_waiting_service_is_asked_on_the_same_connection(self):
        # Redis never speaks first: the INFO probe goes out on the socket that
        # is already open instead of opening a second one for a banner.
        wire = await Wire(redis_handler).start()
        self.addAsyncCleanup(wire.close)
        with mock.patch.dict(scanner.PROBES, {wire.port: b"INFO server\r\n"}):
            svc = await probe_port("127.0.0.1", "127.0.0.1", wire.port, 0.6)
        self.assertEqual("redis", svc.service)
        self.assertEqual("banner", svc.identity_source)
        self.assertIn("redis_version:6.2.6", svc.banner)
        self.assertEqual(1, wire.connections)

    async def test_mysql_handshake_gives_product_and_version(self):
        svc, wire = await self.probe(mysql_handler)
        self.assertEqual("mysql", svc.service)
        self.assertEqual(("MySQL", "5.7.31-log"), (svc.product, svc.version))
        self.assertEqual(1, wire.connections)

    async def test_mongo_handshake_is_recognised_without_a_port_hint(self):
        wire = await Wire(mongo_handler).start()
        self.addAsyncCleanup(wire.close)
        with mock.patch.object(scanner, "MONGO_PORTS", {wire.port}), \
                mock.patch.object(scanner, "probe_mongo",
                                  new=_no_mongo):
            svc = await probe_port("127.0.0.1", "127.0.0.1", wire.port, 0.6)
        self.assertEqual("mongodb", svc.service)
        self.assertEqual("banner", svc.identity_source)
        self.assertEqual(1, wire.connections)

    async def test_https_on_an_unusual_port_costs_two_connections(self):
        # Plaintext gets a TLS alert, and only then is a handshake attempted;
        # the old flow handshook first on every port and still paid for the
        # HTTP probe on another connection.
        alert = b"\x15\x03\x01\x00\x02\x02\x28"

        async def tls_only(reader, writer):
            await reader.read(4096)
            writer.write(alert)
            await writer.drain()

        svc, wire = await self.probe(tls_only)
        self.assertEqual(2, wire.connections)
        self.assertEqual("open", svc.state)
        # No TLS listener behind that alert, so no service was claimed.
        self.assertEqual("", svc.service)

    async def test_port_table_guess_is_marked_as_one(self):
        async def silent(reader, writer):
            await reader.read(4096)

        wire = await Wire(silent).start()
        self.addAsyncCleanup(wire.close)
        with mock.patch.dict(scanner.PORT_SERVICES, {wire.port: "vnc"}):
            svc = await probe_port("127.0.0.1", "127.0.0.1", wire.port, 0.4)
        self.assertEqual("vnc", svc.service)
        self.assertEqual("port", svc.identity_source)

    async def test_http_on_a_vnc_port_is_http_not_vnc(self):
        # The roadmap's acceptance case, now decided by the wire rather than a
        # fixture that set identity_source by hand.
        async def slow_http(reader, writer):
            await asyncio.sleep(0.5)      # let the greeting wait expire
            await reader.read(4096)
            writer.write(HTTP_RESPONSE)
            await writer.drain()

        wire = await Wire(slow_http).start()
        self.addAsyncCleanup(wire.close)
        with mock.patch.dict(scanner.PORT_SERVICES, {wire.port: "vnc"}):
            svc = await probe_port("127.0.0.1", "127.0.0.1", wire.port, 1.2)
        self.assertEqual("http", svc.service)
        findings = checks.check_exposure(svc)
        self.assertNotIn("VS-EXP-VNC", {f.rule_id for f in findings})

    async def test_closed_port_is_closed_without_extra_attempts(self):
        wire = await Wire(ssh_handler).start()
        port = wire.port
        await wire.close()
        svc = await probe_port("127.0.0.1", "127.0.0.1", port, 0.4)
        self.assertEqual("closed", svc.state)


class EvidenceRenderingTests(unittest.TestCase):
    """Binary handshakes prove identity but do not belong on a finding card."""

    def test_binary_handshake_is_summarised(self):
        svc = scanner.PortService(
            host="target.example", ip="127.0.0.1", port=27017, state="open",
            service="mongodb", identity_source="banner",
            banner="\x93\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00")
        finding = next(f for f in checks.check_exposure(svc)
                       if f.rule_id == "VS-EXP-MONGODB")
        self.assertIn("protocol handshake", finding.evidence)
        self.assertNotIn("\\x00", finding.evidence)

    def test_text_banner_is_still_quoted(self):
        svc = scanner.PortService(
            host="target.example", ip="127.0.0.1", port=2323, state="open",
            service="telnet", identity_source="banner",
            banner="Welcome to the appliance\r\n\r\nlogin: ")
        finding = next(f for f in checks.check_exposure(svc)
                       if f.rule_id == "VS-EXP-TELNET-ALT")
        self.assertIn("Banner:", finding.evidence)
        self.assertIn("login:", finding.evidence)


async def _no_mongo(*_args, **_kwargs):
    return None


if __name__ == "__main__":
    unittest.main()
