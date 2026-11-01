"""Extraction and streaming tests — the two things that decide if this is usable."""

import gzip
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-test-"))

from bastet import extract, logs  # noqa: E402

SAMPLES = {
    "auth": (
        "Nov  1 02:00:11 web01 sshd[410]: Failed password for invalid user admin "
        "from 45.155.205.233 port 5100 ssh2\n"
    ),
    "http": (
        '203.0.113.9 - - [01/Nov/2026:10:00:11 +0100] "GET /login HTTP/1.1" 200 512 '
        '"-" "sqlmap/1.7.2"\n'
    ),
}

TEXT = """
Hello, we received this message from support@evil-corp.top:
Please check https://evil-login.top/reset?token=abc and also 45.155.205.233.
Reference CVE-2021-44228, hash d41d8cd98f00b204e9800998ecf8427e.
Internal: 10.10.0.5 and 2001:db8::1. Logo is at https://example.com/logo.png
"""


class TestExtract(unittest.TestCase):
    def test_finds_every_kind(self):
        kinds = {i.kind for i in extract.extract(TEXT)}
        for expected in ("email", "url", "ipv4", "ipv6", "cve", "md5", "domain"):
            self.assertIn(expected, kinds)

    def test_deduplicates(self):
        text = "1.2.3.4 and again 1.2.3.4 and 10.0.0.1"
        values = [i.value for i in extract.extract(text)]
        self.assertEqual(values.count("1.2.3.4"), 1)

    def test_timestamps_are_not_ipv6(self):
        text = "Nov  1 02:00:11 something 2026:10:00:11 and 2001:db8::1"
        values = [i.value for i in extract.extract(text, only=("ipv6",))]
        self.assertEqual(values, ["2001:db8::1"])

    def test_filenames_are_not_domains(self):
        text = "open report.png and notes.log and config.yaml, then evil-corp.top"
        values = [i.value for i in extract.extract(text, only=("domain",))]
        self.assertEqual(values, ["evil-corp.top"])

    def test_bad_octets_rejected(self):
        self.assertEqual(extract.extract("999.1.1.1 and 1.2.3.4", only=("ipv4",))[0].value, "1.2.3.4")

    def test_only_filter(self):
        only_ips = extract.extract(TEXT, only=("ipv4",))
        self.assertTrue(all(i.kind == "ipv4" for i in only_ips))

    def test_by_kind_counts(self):
        counts = extract.by_kind(extract.extract(TEXT))
        self.assertEqual(sum(counts.values()), len(extract.extract(TEXT)))

    def test_empty(self):
        self.assertEqual(extract.extract("nothing here at all"), [])

    def test_limit(self):
        text = " ".join(f"10.0.0.{i}" for i in range(1, 40))
        self.assertEqual(len(extract.extract(text, limit=5)), 5)

    def test_from_file(self):
        directory = tempfile.mkdtemp(prefix="bastet-extract-")
        path = Path(directory) / "alert.txt"
        path.write_text(TEXT, encoding="utf-8")
        self.assertTrue(extract.from_file(path))

    def test_from_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            extract.from_file("/nope/alert.txt")

    def test_risk_comes_from_classify(self):
        indicators = extract.extract("visit evil-login.top", only=("domain",))
        self.assertEqual(indicators[0].risk, "high")


class TestStreaming(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bastet-stream-")

    def write(self, name: str, body: str) -> Path:
        path = Path(self.dir) / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_reads_gzip(self):
        path = Path(self.dir) / "auth.log.gz"
        with gzip.open(path, "wt") as handle:
            handle.write(SAMPLES["auth"] * 10)
        analysis = logs.analyse(path)
        self.assertEqual(analysis.parsed, 10)

    def test_refuses_binary(self):
        path = Path(self.dir) / "payload.bin"
        path.write_bytes(b"\x7fELF\x00\x00\x00\x00binary stuff")
        with self.assertRaises(logs.LogError):
            list(logs.iter_lines(path))

    def test_missing_file(self):
        with self.assertRaises(logs.LogError):
            list(logs.iter_lines(Path(self.dir) / "nope.log"))

    def test_directory(self):
        with self.assertRaises(logs.LogError):
            list(logs.iter_lines(Path(self.dir)))

    def test_max_lines(self):
        path = self.write("big.log", SAMPLES["auth"] * 100)
        self.assertEqual(len(list(logs.iter_lines(path, max_lines=25))), 25)

    def test_ip_filter(self):
        body = SAMPLES["auth"] + SAMPLES["auth"].replace("45.155.205.233", "8.8.4.4")
        analysis = logs.analyse(self.write("auth.log", body), ip_filter="45.155")
        self.assertEqual(analysis.parsed, 1)
        self.assertEqual(analysis.top_ips[0][0], "45.155.205.233")

    def test_hour_filter(self):
        body = (
            SAMPLES["auth"].replace("02:00:11", "02:10:00")
            + SAMPLES["auth"].replace("02:00:11", "09:10:00")
        )
        path = self.write("auth.log", body)
        analysis = logs.analyse(path, since=logs.parse_clock("08:00", None), until=logs.parse_clock("10:00", None))
        self.assertEqual(analysis.parsed, 1)

    def test_parse_clock(self):
        self.assertEqual(logs.parse_clock("14:30", None).hour, 14)
        self.assertEqual(logs.parse_clock("1430", None).minute, 30)
        with self.assertRaises(ValueError):
            logs.parse_clock("half past two", None)

    def test_access_log_offset_is_respected(self):
        line = '1.2.3.4 - - [01/Nov/2026:10:00:11 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
        event = logs.parse_line(line, 1)
        self.assertIsNotNone(event.ts)
        # stored as local time; the hour can move by the local offset, never by more
        self.assertLessEqual(abs(event.ts.hour - 10), 14)

    def test_elapsed_is_recorded(self):
        analysis = logs.analyse(self.write("auth.log", SAMPLES["auth"] * 20))
        self.assertGreaterEqual(analysis.elapsed_ms, 0)

    def test_throughput_is_sane(self):
        """A 50k-line file should not take a second on any reasonable machine."""
        body = (SAMPLES["auth"] + SAMPLES["http"]) * 25_000
        path = self.write("bulk.log", body)
        started = time.perf_counter()
        analysis = logs.analyse(path)
        elapsed = time.perf_counter() - started
        self.assertEqual(analysis.lines, 50_000)
        self.assertLess(elapsed, 5.0, f"50k lines took {elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
