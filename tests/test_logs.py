"""Log triage tests against the example files — real shapes, not invented ones."""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-test-"))

from bastet import logs  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

AUTH = """\
Nov  1 02:00:11 web01 sshd[410]: Failed password for invalid user admin from 45.155.205.233 port 5100 ssh2
Nov  1 02:01:11 web01 sshd[411]: Failed password for invalid user admin from 45.155.205.233 port 5101 ssh2
Nov  1 02:02:11 web01 sshd[412]: Failed password for invalid user admin from 45.155.205.233 port 5102 ssh2
Nov  1 02:03:11 web01 sshd[413]: Failed password for invalid user admin from 45.155.205.233 port 5103 ssh2
Nov  1 02:04:11 web01 sshd[414]: Failed password for invalid user admin from 45.155.205.233 port 5104 ssh2
Nov  1 02:05:11 web01 sshd[415]: Failed password for root from 45.155.205.233 port 5105 ssh2
Nov  1 02:06:31 web01 sshd[4231]: Accepted password for deploy from 45.155.205.233 port 5241 ssh2
Nov  1 09:00:12 web01 sshd[440]: Failed password for nox from 10.10.10.20 port 41000 ssh2
Nov  1 09:01:12 web01 sshd[441]: Failed password for nox from 10.10.10.20 port 41001 ssh2
Nov  1 09:08:44 web01 sshd[449]: Accepted publickey for nox from 10.10.10.20 port 41077 ssh2
"""

HTTP = """\
45.155.205.233 - - [01/Nov/2026:03:12:06 +0100] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.7.2"
45.155.205.233 - - [01/Nov/2026:03:12:07 +0100] "GET /wp-login.php HTTP/1.1" 404 162 "-" "sqlmap/1.7.2"
198.51.100.7 - - [01/Nov/2026:04:00:00 +0100] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
"""


class TestParsing(unittest.TestCase):
    def test_ssh_failure(self):
        event = logs.parse_line(AUTH.splitlines()[0], 1)
        self.assertEqual(event.kind, "ssh-fail")
        self.assertEqual(event.ip, "45.155.205.233")
        self.assertEqual(event.user, "admin")

    def test_ssh_success(self):
        event = logs.parse_line("Nov  1 02:06:31 web01 sshd[4231]: Accepted password for deploy from 45.1.1.1 port 22 ssh2", 1)
        self.assertEqual(event.kind, "ssh-ok")
        self.assertEqual(event.user, "deploy")

    def test_invalid_user(self):
        event = logs.parse_line("Nov  1 10:00:03 web01 sshd[4502]: Invalid user git from 185.220.101.44 port 61002 ssh2", 1)
        self.assertEqual(event.kind, "ssh-invalid")

    def test_http_line(self):
        event = logs.parse_line(HTTP.splitlines()[0], 1)
        self.assertEqual(event.kind, "http")
        self.assertEqual(event.path, "/.env")
        self.assertEqual(event.status, 404)
        self.assertIn("sqlmap", event.ua)

    def test_ts_parsed(self):
        event = logs.parse_line(AUTH.splitlines()[0], 1)
        self.assertIsNotNone(event.ts)
        self.assertEqual(event.ts.hour, 2)

    def test_garbage_is_kept_as_other(self):
        event = logs.parse_line("something unrelated happened", 1)
        self.assertEqual(event.kind, "other")

    def test_blank_and_comment(self):
        self.assertIsNone(logs.parse_line("", 1))
        self.assertIsNone(logs.parse_line("# comment", 2))

    def test_detect_format(self):
        self.assertEqual(logs.detect_format(AUTH.splitlines()), "auth")
        self.assertEqual(logs.detect_format(HTTP.splitlines()), "http")


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bastet-logs-")

    def write(self, name: str, body: str) -> Path:
        path = Path(self.dir) / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_brute_force_detected(self):
        analysis = logs.analyse(self.write("auth.log", AUTH))
        kinds = {f.kind for f in analysis.findings}
        self.assertIn("brute-force", kinds)
        brute = next(f for f in analysis.findings if f.kind == "brute-force")
        self.assertGreaterEqual(brute.count, 5)

    def test_success_after_failure_is_critical(self):
        analysis = logs.analyse(self.write("auth.log", AUTH))
        critical = [f for f in analysis.findings if f.severity == "critical"]
        self.assertTrue(critical)
        self.assertEqual(critical[0].kind, "success-after-failure")
        self.assertEqual(critical[0].subject, "45.155.205.233")
        self.assertEqual(analysis.worst, "critical")

    def test_scanner_paths(self):
        analysis = logs.analyse(self.write("access.log", HTTP))
        kinds = {f.kind for f in analysis.findings}
        self.assertIn("scanner-paths", kinds)
        self.assertIn("suspicious-user-agent", kinds)

    def test_no_findings_on_boring_log(self):
        boring = '198.51.100.7 - - [01/Nov/2026:04:00:00 +0100] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        analysis = logs.analyse(self.write("quiet.log", boring))
        self.assertEqual(analysis.findings, [])
        self.assertEqual(analysis.worst, "info")

    def test_counts_and_tops(self):
        analysis = logs.analyse(self.write("auth.log", AUTH))
        self.assertEqual(analysis.failed_by_ip["45.155.205.233"], 6)
        self.assertEqual(analysis.ok_by_ip["45.155.205.233"], 1)
        self.assertEqual(analysis.top_ips[0][0], "45.155.205.233")

    def test_hourly_histogram(self):
        analysis = logs.analyse(self.write("auth.log", AUTH))
        self.assertEqual(sum(analysis.hourly), analysis.parsed)
        self.assertEqual(analysis.hourly[2], 7)

    def test_json_shape(self):
        import json

        analysis = logs.analyse(self.write("auth.log", AUTH))
        payload = analysis.to_dict()
        json.dumps(payload)
        self.assertEqual(payload["format"], "auth")
        self.assertTrue(payload["findings"])
        self.assertIn("hourly", payload)

    def test_example_files_exist_and_parse(self):
        if not (EXAMPLES / "auth.log").exists():
            self.skipTest("examples not present")
        analysis = logs.analyse(EXAMPLES / "auth.log")
        self.assertGreater(analysis.parsed, 10)
        self.assertIn("brute-force", {f.kind for f in analysis.findings})


if __name__ == "__main__":
    unittest.main()
