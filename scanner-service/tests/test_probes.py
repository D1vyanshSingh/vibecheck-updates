"""App-layer probe tests: one read-only request, no authentication attempts.

The probes are what turn "a port is open" into "this product answered". They
must (a) hit the product-specific path, (b) require the product's own markers
for a 200 to count, (c) keep an authentication challenge as weaker evidence,
and (d) never speak HTTP to a service identified as something else.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import unittest
from unittest.mock import patch

from vulnscan import checks, scanner
from vulnscan.scanner import PortService, probe_app_layer, probe_mongo


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


def bson(fields: dict) -> bytes:
    body = b"".join(_bson_element(name, value) for name, value in fields.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def mongo_reply(document: bytes) -> bytes:
    body = struct.pack("<iqii", 0, 0, 0, 1) + document
    return struct.pack("<iiii", 16 + len(body), 1, 1, 1) + body


async def _read_mongo_request(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = struct.unpack("<i", header)[0]
    return await reader.readexactly(max(0, length - 4))


def http_response(status: int, body: bytes, headers: dict | None = None) -> bytes:
    extra = headers or {}
    head = (f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\n"
            f"Server: Test/1.0\r\nConnection: close\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in extra.items())
            + "\r\n").encode("latin-1")
    return head + body


class AppProbeTests(unittest.IsolatedAsyncioTestCase):
    async def serve(self, payload: bytes, requests: list[str] | None = None):
        async def handler(reader, writer):
            request = (await reader.read(4096)).decode("latin-1", "replace")
            if requests is not None:
                requests.append(request)
            writer.write(payload)
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, OSError):
                pass

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self.addAsyncCleanup(self._stop, server)
        return port

    async def _stop(self, server) -> None:
        server.close()
        await server.wait_closed()

    def service(self, port: int, **kwargs) -> PortService:
        return PortService(host="127.0.0.1", ip="127.0.0.1", port=port,
                           state="open", **kwargs)

    async def test_a_marker_matching_200_is_stored_as_confirmed(self):
        requests: list[str] = []
        port = await self.serve(
            http_response(200, b'{"kind":"PodList","apiVersion":"v1","items":[]}'),
            requests)
        svc = self.service(port, service="http")
        with patch.dict(scanner.APP_PROBES, {port: ("kubelet", "/pods")}):
            await probe_app_layer(svc, 2.0)
        probe = svc.app["kubelet"]
        self.assertEqual(200, probe["status"])
        self.assertTrue(probe["confirmed"])
        self.assertEqual("/pods", probe["path"])
        self.assertIn("GET /pods", requests[0])

    async def test_a_200_without_markers_is_not_proof(self):
        port = await self.serve(http_response(200, b"<html>hello</html>"))
        svc = self.service(port, service="http")
        with patch.dict(scanner.APP_PROBES, {port: ("prometheus", "/api/v1/targets")}):
            await probe_app_layer(svc, 2.0)
        self.assertEqual(200, svc.app["prometheus"]["status"])
        self.assertFalse(svc.app["prometheus"]["confirmed"])

    async def test_an_auth_challenge_is_kept_but_not_confirmed(self):
        port = await self.serve(http_response(401, b"unauthorized"))
        svc = self.service(port, service="http")
        with patch.dict(scanner.APP_PROBES, {port: ("rabbitmq", "/api/overview")}):
            await probe_app_layer(svc, 2.0)
        probe = svc.app["rabbitmq"]
        self.assertEqual(401, probe["status"])
        self.assertTrue(probe["confirmed"])

    async def test_an_unrelated_service_is_never_sent_http(self):
        requests: list[str] = []
        port = await self.serve(http_response(200, b"{}"), requests)
        svc = self.service(port, service="ssh", identity_source="banner",
                           banner="SSH-2.0-OpenSSH_9.6p1")
        with patch.dict(scanner.APP_PROBES, {port: ("kubelet", "/pods")}):
            await probe_app_layer(svc, 2.0)
        self.assertEqual({}, svc.app)
        self.assertEqual([], requests)

    async def test_an_unreachable_probe_does_not_fabricate_a_result(self):
        probe = PortService(host="127.0.0.1", ip="127.0.0.1", port=1,
                            state="open", service="http")
        with patch.dict(scanner.APP_PROBES, {1: ("kubelet", "/pods")}):
            await probe_app_layer(probe, 0.3)
        self.assertEqual({}, probe.app)


class MongoProbeTests(unittest.IsolatedAsyncioTestCase):
    async def serve(self, replies: list[bytes]):
        queue = list(replies)

        async def handler(reader, writer):
            try:
                for reply in queue:
                    await _read_mongo_request(reader)
                    writer.write(reply)
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionResetError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self.addAsyncCleanup(self._stop, server)
        return port

    async def _stop(self, server) -> None:
        server.close()
        await server.wait_closed()

    async def test_open_database_is_proven_by_a_read_only_command(self):
        port = await self.serve([
            mongo_reply(bson({"version": "4.4.6", "ok": 1})),
            mongo_reply(bson({"databases": [{"name": "admin"},
                                             {"name": "lab"}], "ok": 1})),
        ])
        result = await probe_mongo("127.0.0.1", port, 2.0)
        self.assertTrue(result["open"])
        self.assertFalse(result["auth_required"])
        self.assertEqual(200, result["status"])
        self.assertEqual("4.4.6", result["version"])

    async def test_auth_required_is_reported_as_exposure_without_access(self):
        port = await self.serve([
            mongo_reply(bson({"version": "5.0.9", "ok": 1})),
            mongo_reply(bson({"ok": 0, "code": 13,
                              "errmsg": "command listDatabases requires "
                                        "authentication"})),
        ])
        result = await probe_mongo("127.0.0.1", port, 2.0)
        self.assertFalse(result["open"])
        self.assertTrue(result["auth_required"])
        self.assertEqual(401, result["status"])

    async def test_no_listener_returns_none(self):
        self.assertIsNone(await probe_mongo("127.0.0.1", 1, 0.3))


class CheckUpgradeTests(unittest.TestCase):
    def service(self, port: int, **kwargs) -> PortService:
        return PortService(host="h", ip="127.0.0.1", port=port, state="open",
                           identity_source="banner", **kwargs)

    def test_app_probe_upgrades_a_port_guess_to_certain(self):
        svc = self.service(10250, service="kubelet")
        svc.app["kubelet"] = {"name": "kubelet", "path": "/pods",
                              "scheme": "http", "status": 200,
                              "body": '{"kind":"PodList"}', "confirmed": True}
        found = [f for f in checks.check_exposure(svc) if f.rule_id == "VS-EXP-KUBELET"]
        self.assertEqual(1, len(found))
        self.assertEqual("certain", found[0].confidence)
        self.assertIn("/pods", found[0].evidence)

    def test_auth_challenge_upgrades_a_guess_only_to_firm(self):
        svc = self.service(15672, service="http")
        svc.app["rabbitmq"] = {"name": "rabbitmq", "path": "/api/overview",
                               "scheme": "http", "status": 401,
                               "body": "", "confirmed": True}
        found = [f for f in checks.check_exposure(svc)
                 if f.rule_id == "VS-EXP-RABBITMQ"]
        self.assertEqual("firm", found[0].confidence)

    def test_a_200_without_markers_does_not_upgrade(self):
        svc = self.service(9090, service="http")
        svc.app["prometheus"] = {"name": "prometheus", "path": "/api/v1/targets",
                                 "scheme": "http", "status": 200,
                                 "body": "<html>hello</html>", "confirmed": False}
        found = [f for f in checks.check_exposure(svc)
                 if f.rule_id == "VS-EXP-PROMETHEUS"]
        self.assertNotEqual("certain", found[0].confidence)

    def test_open_mongo_is_certain_and_protected_mongo_is_firm(self):
        open_svc = self.service(27017, service="mongodb")
        open_svc.app["mongo"] = {"name": "mongo", "status": 200, "open": True,
                                 "auth_required": False, "version": "4.4.6",
                                 "body": '{"databases":[]}'}
        open_find = checks._check_special_service(open_svc)[0]
        self.assertEqual("VS-EXP-MONGODB", open_find.rule_id)
        self.assertEqual("certain", open_find.confidence)

        locked = self.service(27017, service="mongodb")
        locked.app["mongo"] = {"name": "mongo", "status": 401, "open": False,
                               "auth_required": True, "version": "5.0.9",
                               "body": "requires authentication"}
        locked_find = checks._check_special_service(locked)[0]
        self.assertEqual("firm", locked_find.confidence)
        self.assertIn("authorization is enabled", locked_find.description)


if __name__ == "__main__":
    unittest.main()
