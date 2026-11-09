"""Tests for the nmap detection engine and engine selection.

No nmap installation is required: XML parsing is tested against a captured
fixture, and the subprocess path is tested against a fake executable through
the VULNSCAN_NMAP override.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vulnscan.cli import main
from vulnscan.engines import (EngineUnavailable, nmap as nmap_engine, nse_scripts,
                              resolve)
from vulnscan.engines.errors import EngineError
from vulnscan.scanner import PortService, collect_evidence

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1793777412" version="7.992" xmloutputversion="1.05">
<host starttime="1793777412" endtime="1793777415">
  <status state="up" reason="user-set"/>
  <address addr="192.0.2.10" addrtype="ipv4"/>
  <hostnames><hostname name="web.example" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu 22.04"
               ostype="Linux" method="probed" conf="10">
        <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
      </service>
      <script id="ssh-auth-methods" output="publickey"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="closed" reason="reset"/>
      <service name="http" method="table" conf="3"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 - 5.15" accuracy="98">
      <osclass type="general purpose" osfamily="Linux"/>
    </osmatch>
  </os>
  <times srtt="1500" rttvar="100" to="100000"/>
</host>
<host>
  <status state="down" reason="no-response"/>
  <address addr="192.0.2.11" addrtype="ipv4"/>
</host>
<runstats><finished time="1793777415" elapsed="3.10" exit="success"/>
<hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""

# A localhost-only scan result used by the CLI sidecar test: the port is
# closed, so evidence collection fails fast instead of timing out.
LOCAL_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.992">
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="59998"><state state="open"/>
<service name="unknown" method="table" conf="3"/></port></ports></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


class NseProfileTests(unittest.TestCase):
    def test_safe_profile_runs_only_scripts_nmap_tags_safe(self):
        safe = nse_scripts("safe")
        self.assertIn("docker-version", safe)
        for intrusive in ("ssh-auth-methods", "ssl-enum-ciphers", "http-enum"):
            self.assertNotIn(intrusive, safe)

    def test_extended_profile_adds_the_read_only_intrusive_scripts(self):
        extended = nse_scripts("extended")
        for name in ("ssh-auth-methods", "ssl-enum-ciphers", "http-enum"):
            self.assertIn(name, extended)
        # Extended is a superset: the safe set never disappears.
        self.assertTrue(set(nse_scripts("safe")) <= set(extended))

    def test_off_runs_nothing_and_unknown_profiles_are_rejected(self):
        self.assertEqual([], nse_scripts("off"))
        with self.assertRaises(EngineError):
            nse_scripts("vuln")

    def test_argv_carries_script_flags_only_when_requested(self):
        argv = nmap_engine.build_argv("nmap", ["127.0.0.1"], [22],
                                      scripts=["ssl-cert", "http-title"])
        self.assertEqual("ssl-cert,http-title", argv[argv.index("--script") + 1])
        self.assertEqual(f"{nmap_engine.SCRIPT_TIMEOUT_S}s",
                         argv[argv.index("--script-timeout") + 1])
        bare = nmap_engine.build_argv("nmap", ["127.0.0.1"], [22])
        self.assertNotIn("--script", bare)


class NmapXmlTests(unittest.TestCase):
    def setUp(self):
        self.services, self.meta = nmap_engine.parse_xml(NMAP_XML)

    def test_only_open_ports_become_services(self):
        self.assertEqual([22, 8080], [s.port for s in self.services])

    def test_captures_identity_cpe_and_confidence(self):
        ssh = self.services[0]
        self.assertEqual("ssh", ssh.service)
        self.assertEqual("OpenSSH", ssh.product)
        self.assertEqual("9.6p1", ssh.version)
        self.assertEqual("Ubuntu 22.04", ssh.extrainfo)
        self.assertEqual(["cpe:/a:openbsd:openssh:9.6p1"], ssh.cpe)
        self.assertEqual(10, ssh.nmap_conf)
        self.assertEqual("nmap", ssh.source)
        self.assertEqual("tcp", ssh.proto)
        self.assertEqual({"ssh-auth-methods": "publickey"}, ssh.scripts)

    def test_failed_script_output_is_dropped_rather_than_reported(self):
        xml = NMAP_XML.replace(
            'output="publickey"',
            'output="ERROR: Script execution failed (use -d to debug)"')
        services, _ = nmap_engine.parse_xml(xml)
        self.assertEqual({}, services[0].scripts)

    def test_captures_address_hostname_os_and_rtt(self):
        ssh = self.services[0]
        self.assertEqual("web.example", ssh.host)
        self.assertEqual("192.0.2.10", ssh.ip)
        self.assertEqual(1, ssh.rtt_ms)
        self.assertEqual("Linux 5.4 - 5.15", ssh.os_matches[0]["name"])
        self.assertEqual(98, ssh.os_matches[0]["accuracy"])
        self.assertEqual("Linux", ssh.os_matches[0]["family"])

    def test_down_hosts_and_closed_ports_are_excluded(self):
        self.assertEqual(1, self.meta["hosts_up"])
        self.assertEqual(1, self.meta["hosts_down"])
        self.assertEqual({"closed": 1}, self.meta["skipped_ports"])
        self.assertTrue(all(s.ip == "192.0.2.10" for s in self.services))

    def test_target_name_wins_over_ptr(self):
        services, _ = nmap_engine.parse_xml(NMAP_XML, targets=["127.0.0.1"])
        # 127.0.0.1 does not resolve to 192.0.2.10, so the PTR name is used.
        self.assertEqual("web.example", services[0].host)
        services, _ = nmap_engine.parse_xml(NMAP_XML, targets=["192.0.2.10"])
        self.assertEqual("192.0.2.10", services[0].host)

    def test_invalid_xml_raises(self):
        with self.assertRaises(EngineError):
            nmap_engine.parse_xml("<nmaprun><host>")

    def test_ssl_tunnel_is_named_https(self):
        xml = ("<nmaprun version='7.992'><host><status state='up'/>"
               "<address addr='192.0.2.12' addrtype='ipv4'/><ports>"
               "<port protocol='tcp' portid='8443'><state state='open'/>"
               "<service name='http' tunnel='ssl' product='Apache httpd' "
               "version='2.2.34' conf='10'/></port>"
               "</ports></host></nmaprun>")
        services, _ = nmap_engine.parse_xml(xml)
        self.assertEqual("https", services[0].service)


class IdentityWeaknessTests(unittest.TestCase):
    def _svc(self, name: str, conf: int) -> PortService:
        return PortService(host="h", ip="127.0.0.1", port=1,
                           service=name, nmap_conf=conf, source="nmap")

    def test_probed_identity_is_strong(self):
        self.assertFalse(nmap_engine.identity_is_weak(self._svc("ssh", 10)))

    def test_port_table_guess_is_weak(self):
        self.assertTrue(nmap_engine.identity_is_weak(self._svc("esmagent", 3)))

    def test_uncertain_names_are_weak(self):
        self.assertTrue(nmap_engine.identity_is_weak(self._svc("mongod?", 10)))
        self.assertTrue(nmap_engine.identity_is_weak(self._svc("unknown", 10)))
        self.assertTrue(nmap_engine.identity_is_weak(self._svc("", 10)))


class PortArgTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(["-p", "22"], nmap_engine.port_args([22]))

    def test_ranges_and_individual_ports(self):
        self.assertEqual(["-p", "21-23,80,8000-8002"],
                         nmap_engine.port_args([23, 22, 21, 80, 8002, 8000, 8001]))

    def test_full_range_uses_dash(self):
        self.assertEqual(["-p-"], nmap_engine.port_args(list(range(1, 65536))))

    def test_empty_port_list_is_rejected(self):
        with self.assertRaises(ValueError):
            nmap_engine.port_args([])


class BuildArgvTests(unittest.TestCase):
    def test_command_identifies_and_streams_xml(self):
        argv = nmap_engine.build_argv("nmap", ["192.0.2.10"], [22, 80])
        self.assertEqual("nmap", argv[0])
        self.assertIn("-sV", argv)
        self.assertIn("-Pn", argv)
        self.assertIn("-oX", argv)
        self.assertEqual("-", argv[argv.index("-oX") + 1])
        self.assertEqual(["192.0.2.10"], argv[-1:])
        self.assertIn("22,80", argv)

    def test_scripts_are_opt_in(self):
        plain = nmap_engine.build_argv("nmap", ["h"], [22])
        self.assertNotIn("--script", plain)
        with_scripts = nmap_engine.build_argv("nmap", ["h"], [22],
                                              scripts=["ssl-cert", "http-title"])
        self.assertEqual(["ssl-cert,http-title"],
                         with_scripts[with_scripts.index("--script") + 1:][:1])

    def test_version_intensity_is_opt_in(self):
        self.assertNotIn("--version-intensity",
                         nmap_engine.build_argv("nmap", ["h"], [22]))
        argv = nmap_engine.build_argv("nmap", ["h"], [22], version_intensity=4)
        self.assertEqual("4", argv[argv.index("--version-intensity") + 1])


class ResolveTests(unittest.TestCase):
    def test_auto_prefers_nmap(self):
        with mock.patch.object(nmap_engine, "find_nmap", return_value="/usr/bin/nmap"):
            self.assertEqual(("nmap", None), resolve("auto"))

    def test_auto_falls_back_with_a_reason(self):
        with mock.patch.object(nmap_engine, "find_nmap", return_value=None):
            name, reason = resolve("auto")
        self.assertEqual("native", name)
        self.assertIn("nmap", reason)

    def test_explicit_nmap_is_strict(self):
        with mock.patch.object(nmap_engine, "find_nmap", return_value=None):
            with self.assertRaises(EngineUnavailable):
                resolve("nmap")

    def test_native_never_looks_for_nmap(self):
        with mock.patch.object(nmap_engine, "find_nmap",
                               side_effect=AssertionError("should not be called")):
            self.assertEqual(("native", None), resolve("native"))

    def test_unknown_engine_is_rejected(self):
        with self.assertRaises(EngineError):
            resolve("masscan")


@unittest.skipIf(os.name != "posix", "fake executable needs a POSIX shell")
class FakeNmapTests(unittest.TestCase):
    def _fake_nmap(self, body: str, exit_code: int = 0) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        handle.write("#!/bin/sh\n")
        handle.write(f"cat <<'XML'\n{NMAP_XML}\nXML\n" if body == "xml" else body + "\n")
        handle.write(f"exit {exit_code}\n")
        handle.close()
        path = Path(handle.name)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.addCleanup(path.unlink)
        return path

    def test_run_uses_override_and_returns_services(self):
        fake = self._fake_nmap("xml")
        with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": str(fake)}):
            services, meta = asyncio.run(
                nmap_engine.run(["192.0.2.10"], [22, 8080], enrich=False,
                                scripts=["ssl-cert"]))
        self.assertEqual([22, 8080], [s.port for s in services])
        self.assertEqual("nmap", meta["engine"])
        self.assertEqual(["ssl-cert"], meta["scripts"])
        self.assertEqual(str(fake), meta["argv"][0])
        self.assertIn("--host-timeout", meta["argv"])
        self.assertIn("--script", meta["argv"])

    def test_run_raises_on_failure_with_stderr_detail(self):
        fake = self._fake_nmap("echo 'nmap: permission denied' >&2", exit_code=1)
        with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": str(fake)}):
            with self.assertRaises(EngineError) as ctx:
                asyncio.run(nmap_engine.run(["127.0.0.1"], [22], enrich=False))
        self.assertIn("permission denied", str(ctx.exception))

    def test_run_raises_on_empty_output(self):
        fake = self._fake_nmap("echo 'not xml'")
        with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": str(fake)}):
            with self.assertRaises(EngineError):
                asyncio.run(nmap_engine.run(["127.0.0.1"], [22], enrich=False))

    def test_missing_binary_is_unavailable(self):
        with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": "/nonexistent/nmap"}):
            with mock.patch("shutil.which", return_value=None):
                self.assertIsNone(nmap_engine.find_nmap())
                with self.assertRaises(EngineUnavailable):
                    resolve("nmap")

    def test_cli_writes_the_raw_xml_beside_the_json(self):
        fake = Path(tempfile.mkdtemp()) / "fake-nmap"
        fake.write_text("#!/bin/sh\ncat <<'XML'\n" + LOCAL_XML + "\nXML\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        with tempfile.TemporaryDirectory() as out:
            json_path = os.path.join(out, "report.json")
            with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": str(fake)}):
                code = main(["127.0.0.1", "-p", "59998", "--engine", "nmap",
                             "--json", json_path, "--no-html", "--no-pdf", "-q"])
            self.assertEqual(0, code)
            sidecar = os.path.join(out, "report.nmap.xml")
            self.assertTrue(os.path.exists(sidecar))
            with open(sidecar, encoding="utf-8") as handle:
                self.assertIn("<nmaprun", handle.read())
            with open(json_path, encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertEqual(sidecar, report["metadata"]["scan"]["raw_xml"])
            self.assertNotIn("_raw_xml", report["metadata"]["scan"])

    def test_cli_keeps_the_xml_when_json_is_disabled(self):
        fake = Path(tempfile.mkdtemp()) / "fake-nmap"
        fake.write_text("#!/bin/sh\ncat <<'XML'\n" + LOCAL_XML + "\nXML\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        with tempfile.TemporaryDirectory() as out:
            html_path = os.path.join(out, "report.html")
            with mock.patch.dict(os.environ, {"VULNSCAN_NMAP": str(fake)}):
                code = main(["127.0.0.1", "-p", "59998", "--engine", "nmap",
                             "--no-json", "--html", html_path, "--no-pdf", "-q"])
            self.assertEqual(0, code)
            self.assertTrue(os.path.exists(os.path.join(out, "report.nmap.xml")))


class CliEngineTests(unittest.TestCase):
    def test_explicit_nmap_without_nmap_exits_2(self):
        with mock.patch.object(nmap_engine, "find_nmap", return_value=None):
            code = main(["127.0.0.1", "-p", "22", "--engine", "nmap",
                         "--no-html", "--no-json", "--no-pdf", "-q"])
        self.assertEqual(2, code)


class EvidencePreservationTests(unittest.TestCase):
    def test_nmap_identity_survives_native_evidence_collection(self):
        svc = PortService(host="127.0.0.1", ip="127.0.0.1", port=59999,
                          state="open", service="ssh", product="OpenSSH",
                          version="9.6p1", source="nmap", nmap_conf=10)
        asyncio.run(collect_evidence(svc, timeout=0.2, guess_names=False))
        self.assertEqual("ssh", svc.service)
        self.assertEqual("OpenSSH", svc.product)
        self.assertEqual("9.6p1", svc.version)


if __name__ == "__main__":
    unittest.main()
