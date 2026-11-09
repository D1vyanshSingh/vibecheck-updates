"""Identification gaps: ports that answer TCP and then reveal nothing.

A port that accepts a connection and resets, or that nmap calls
``tcpwrapped``, is a blind spot -- not a clean result. These tests pin the
three places that has to surface: the native probe (which must not crash), the
nmap parser (which must not invent a service name), and the report (which must
say so instead of printing an empty findings list).
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest

from vulnscan import checks
from vulnscan.engines import nmap as nmap_engine
from vulnscan.report import build_report, render_html
from vulnscan.scanner import PortService, collect_evidence, probe_port

TCPWRAPPED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1793777412" version="7.992"
         xmloutputversion="1.05">
<host starttime="1793777412" endtime="1793777415">
  <status state="up" reason="user-set"/>
  <address addr="192.0.2.50" addrtype="ipv4"/>
  <hostnames><hostname name="tarpit.example" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="tcpwrapped" method="table" conf="8"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="nginx" version="1.18.0" method="probed" conf="10"/>
    </port>
  </ports>
</host>
</nmaprun>
"""


class ResettingListener:
    """TCP listener that accepts and immediately sends RST."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self) -> "ResettingListener":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self.sock.close()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            # Hold the connection briefly so the client is inside its
            # identification read (not still connecting) when the RST lands.
            time.sleep(0.05)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            b"\x01\x00\x00\x00\x00\x00\x00\x00")
            conn.close()


class NativeResetTests(unittest.TestCase):
    def test_a_resetting_port_is_an_identification_gap_not_a_crash(self):
        with ResettingListener() as listener:
            svc = asyncio.run(probe_port("localhost", "127.0.0.1",
                                         listener.port, 1.5))
        self.assertEqual("open", svc.state)
        self.assertEqual("", svc.service)
        self.assertEqual("", svc.identity_source)
        self.assertIn("reset", svc.identification_error)

    def test_evidence_collection_does_not_name_it_from_the_port_table(self):
        with ResettingListener() as listener:
            svc = PortService(host="localhost", ip="127.0.0.1",
                              port=listener.port, state="open",
                              identification_error="connection reset during identification")
            asyncio.run(collect_evidence(svc, 1.0, guess_names=True))
        self.assertEqual("", svc.service)
        self.assertEqual("", svc.identity_source)
        self.assertFalse(checks.identity_is_strong(svc))


class NmapTcpwrappedTests(unittest.TestCase):
    def setUp(self):
        services, _meta = nmap_engine.parse_xml(TCPWRAPPED_XML,
                                                ["tarpit.example"])
        self.by_port = {svc.port: svc for svc in services}

    def test_tcpwrapped_is_recorded_as_unidentified(self):
        svc = self.by_port[22]
        self.assertEqual("", svc.service)
        self.assertEqual("", svc.identity_source)
        self.assertIn("tcpwrapped", svc.identification_error)

    def test_tcpwrapped_claim_is_not_strong_even_at_conf_8(self):
        claim = self.by_port[22].identity_claims[0]
        self.assertEqual(8, claim["confidence"])
        self.assertFalse(checks._claim_is_strong(claim))

    def test_a_real_identification_beside_it_is_untouched(self):
        svc = self.by_port[443]
        self.assertEqual("https", svc.service)
        self.assertEqual("nmap", svc.identity_source)
        self.assertEqual("", svc.identification_error)


class ReportUnidentifiedTests(unittest.TestCase):
    def setUp(self):
        blind = PortService(
            host="tarpit.example", ip="192.0.2.50", port=22, state="open",
            service="", identity_source="", nmap_conf=8, source="nmap",
            identification_error="nmap reported tcpwrapped — the port answered "
                                 "TCP but sent no readable protocol")
        web = PortService(host="tarpit.example", ip="192.0.2.50", port=443,
                          state="open", service="https", product="nginx",
                          version="1.18.0", identity_source="nmap", source="nmap")
        self.report = build_report(
            targets=["tarpit.example"], ports=[22, 443],
            services=[blind, web], findings=[],
            started_at="2026-11-05T10:00:00Z", duration_s=3.0,
            options={"timeout": 5.0, "concurrency": 32},
            scan_meta={"engine": "nmap", "version": "7.992"},
            advisory_meta={"available": False})

    def test_coverage_lists_the_port_and_the_reason(self):
        unidentified = self.report["coverage"]["unidentified"]
        self.assertEqual(1, len(unidentified))
        self.assertEqual(22, unidentified[0]["port"])
        self.assertIn("tcpwrapped", unidentified[0]["reason"])

    def test_json_service_carries_the_identification_error(self):
        blind = [s for s in self.report["services"] if s["port"] == 22][0]
        self.assertIn("tcpwrapped", blind["identification_error"])
        self.assertNotIn("identity_source", blind)

    def test_an_identified_service_beside_it_is_still_reported(self):
        # A blind port must not stop the identified one from being reported.
        web = [s for s in self.report["services"] if s["port"] == 443][0]
        self.assertEqual("https", web["service"])
        self.assertNotIn("identification_error", web)

    def test_html_names_the_gap_instead_of_the_port_table(self):
        page = render_html(self.report)
        self.assertIn("Unidentified", page)
        self.assertIn("tcpwrapped", page)
        self.assertIn("not identified", page)


if __name__ == "__main__":
    unittest.main()
