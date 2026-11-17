"""Cross-platform parser checks: feed real sample outputs, no network needed. Run: python3 -m unittest discover -s tests"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402  (loads config.example.json, binds nothing)

MACOS_ARP = "? (192.168.30.1) at ec:75:c:be:11:a4 on en0\n? (192.168.30.55) at 78:55:36:5:66:29 on en0\n"
IP_NEIGH = "192.168.30.1 dev eth0 lladdr ec:75:0c:be:11:a4 REACHABLE\n192.168.30.9 dev eth0  FAILED\n"
LINUX_ARP = "192.168.30.1 ether ec:75:0c:be:11:a4 eth0\n192.168.30.2 ether 78:55:36:05:66:29 eth0\n"
WIN_ARP = (
    "Interfejs: 192.168.30.5 --- 0x5\n"
    "  adres internetowy        adres fizyczny       typ\n"
    "  192.168.30.1             ec-75-0c-be-11-a4     dynamiczny\n"
    "  192.168.30.55            78-55-36-05-66-29     statyczny\n"
)
PING_MAC = "64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.3 ms\n"
PING_WIN = ("Odpowiedz z 1.1.1.1: liczba bajtow=32 czas=12ms TTL=57\n")
PING_WIN_SHORT = "Reply from 1.1.1.1: bytes=32 time<1ms TTL=57\n"


class Parsers(unittest.TestCase):
    def test_arp_all_platforms(self):
        cases = [
            (MACOS_ARP, {"192.168.30.1": "ec:75:0c:be:11:a4", "192.168.30.55": "78:55:36:05:66:29"}),
            (IP_NEIGH, {"192.168.30.1": "ec:75:0c:be:11:a4"}),
            (LINUX_ARP, {"192.168.30.1": "ec:75:0c:be:11:a4", "192.168.30.2": "78:55:36:05:66:29"}),
            (WIN_ARP, {"192.168.30.1": "ec:75:0c:be:11:a4", "192.168.30.55": "78:55:36:05:66:29"}),
        ]
        for sample, expected in cases:
            got = server._parse_arp(sample)
            for ip, mac in expected.items():
                self.assertEqual(got.get(ip), mac, sample)

    def test_arp_normalizes_dashes_and_case(self):
        got = server._parse_arp(WIN_ARP)
        self.assertTrue(all(m == m.lower() and "-" not in m for m in got.values()))

    def test_ping_variants(self):
        self.assertEqual(server._parse_ping(PING_MAC), 12.3)
        self.assertEqual(server._parse_ping(PING_WIN), 12.0)
        self.assertEqual(server._parse_ping(PING_WIN_SHORT), 0.4)
        self.assertIsNone(server._parse_ping("Request timed out."))

    def test_ping_cmd_per_os(self):
        self.assertEqual(server._ping_cmd("1.1.1.1", 700)[:2], ["ping", "-n"]) if sys.platform == "win32" else None
        if sys.platform == "darwin":
            self.assertEqual(server._ping_cmd("1.1.1.1", 700), ["ping", "-c1", "-W", "700", "1.1.1.1"])
        if sys.platform.startswith("linux"):
            self.assertEqual(server._ping_cmd("1.1.1.1", 700), ["ping", "-c1", "-W", "1", "1.1.1.1"])

    def test_config_example_consistent(self):
        cfg = json.loads((Path(server.__file__).parent / "config.example.json").read_text(encoding="utf-8"))
        ids = set(cfg["device_ids"]) | {s["id"] for s in cfg["tcp_services"]}
        for rule in cfg["link_rtts"]:
            self.assertIn(rule["device"], ids | set(cfg["ping_targets"]))
        for dev in cfg["always_up"] + list(cfg["smoothed_devices"]):
            self.assertIn(dev, ids)

    def test_history_roundtrip(self):
        server.DATA = lambda name: os.path.join(server.STATE_DIR, "test_" + name)  # noqa
        try:
            os.makedirs(server.STATE_DIR, exist_ok=True)
            server.append_history(1000, {"a": 1})
            rows = server.read_history()
            self.assertEqual(rows[-1]["d"], {"a": 1})
        finally:
            for f in ("test_history.jsonl",):
                p = os.path.join(server.STATE_DIR, f)
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
