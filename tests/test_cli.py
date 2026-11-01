"""CLI smoke tests: every subcommand has to run and exit with something sane."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-cli-"))

from rich.console import Console  # noqa: E402

from bastet import cli  # noqa: E402


def run(*args: str) -> tuple[int, str]:
    """Rich writes through its own Console, so redirect_stdout alone sees nothing."""
    from bastet import ui

    captured = io.StringIO()
    original = ui.console
    ui.console = Console(file=captured, width=100, highlight=False, legacy_windows=False)
    plain = io.StringIO()
    try:
        with redirect_stdout(plain):
            code = cli.main(list(args))
    finally:
        ui.console = original
    return code, captured.getvalue() + plain.getvalue()


class TestSmoke(unittest.TestCase):
    def test_dashboard(self):
        code, output = run()
        self.assertEqual(code, 0)
        self.assertIn("BASTET", output.upper())

    def test_cat(self):
        code, output = run("cat")
        self.assertEqual(code, 0)
        self.assertIn("BASTET", output.upper())

    def test_ioc_json(self):
        code, output = run("ioc", "--json", "8.8.8.8", "evil.top")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload[0]["kind"], "ipv4")
        self.assertEqual(payload[1]["risk"], "high")

    def test_ioc_table(self):
        code, output = run("ioc", "45.155.205.233")
        self.assertEqual(code, 0)
        self.assertIn("IPV4", output.upper())

    def test_decode_json(self):
        code, output = run("decode", "--json", "aGVsbG8gd29ybGQ=")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload[-1]["value"], "hello world")

    def test_encode(self):
        code, output = run("encode", "hi", "--as", "hex")
        self.assertEqual(code, 0)
        self.assertIn("6869", output)

    def test_encode_unknown(self):
        # argparse rejects it at parse time, which is the same exit code 2
        with self.assertRaises(SystemExit) as ctx:
            run("encode", "hi", "--as", "nope")
        self.assertEqual(ctx.exception.code, 2)

    def test_hash_text(self):
        code, output = run("hash", "--json", "abc")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(len(payload["sha256"]), 64)

    def test_hash_identify(self):
        code, output = run("hash", "--identify", "a" * 40, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["kind"], "sha1")

    def test_hash_missing_file(self):
        code, _ = run("hash", "--file", "/nonexistent/file")
        self.assertEqual(code, 2)

    def test_ip_json(self):
        code, output = run("ip", "--json", "10.0.0.0/24")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["usable_hosts"], 254)

    def test_ip_contains(self):
        code, _ = run("ip", "10.0.0.0/24", "--contains", "10.0.0.5")
        self.assertEqual(code, 0)
        code, _ = run("ip", "10.0.0.0/24", "--contains", "10.9.9.9")
        self.assertEqual(code, 4)

    def test_ip_bad(self):
        code, _ = run("ip", "nonsense")
        self.assertEqual(code, 2)

    def test_port_json(self):
        code, output = run("port", "--json", "445")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)[0]["risk"], "high")

    def test_port_unknown(self):
        code, _ = run("port", "zzz-not-a-service")
        self.assertEqual(code, 2)

    def test_attack_list(self):
        code, output = run("attack")
        self.assertEqual(code, 0)
        self.assertIn("T1059", output)

    def test_attack_exact(self):
        code, output = run("attack", "T1110")
        self.assertEqual(code, 0)
        self.assertIn("Brute Force", output)

    def test_attack_unknown(self):
        code, _ = run("attack", "zzzz-no-such-technique")
        self.assertEqual(code, 2)

    def test_logs_json(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "auth.log")
        if not os.path.exists(path):
            self.skipTest("example log missing")
        code, output = run("logs", path, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertTrue(payload["findings"])

    def test_logs_fail_on(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "auth.log")
        if not os.path.exists(path):
            self.skipTest("example log missing")
        code, _ = run("logs", path, "--fail-on", "critical")
        self.assertEqual(code, 4)

    def test_logs_missing_file(self):
        code, _ = run("logs", "/nope/auth.log")
        self.assertEqual(code, 2)

    def test_case_lifecycle(self):
        code, output = run("case", "new", "--title", "smoke test", "--severity", "low")
        self.assertEqual(code, 0)
        case_id = [line for line in output.split() if line.startswith("IR-")][0]
        self.assertEqual(run("case", "add", case_id, "a thing happened")[0], 0)
        code, output = run("case", "show", case_id)
        self.assertEqual(code, 0)
        self.assertIn("a thing happened", output)
        self.assertEqual(run("case", "status", case_id, "closed")[0], 0)
        code, output = run("case", "export", case_id)
        self.assertEqual(code, 0)
        self.assertIn("## Timeline", output)

    def test_case_unknown(self):
        self.assertEqual(run("case", "show", "IR-1999-0001")[0], 2)
        self.assertEqual(run("case", "add", "IR-1999-0001", "x")[0], 2)

    def test_triage_list(self):
        code, output = run("triage", "--list")
        self.assertEqual(code, 0)
        self.assertIn("phishing", output)

    def test_triage_render(self):
        code, output = run("triage", "phishing")
        self.assertEqual(code, 0)
        self.assertIn("- [ ]", output)

    def test_triage_unknown(self):
        self.assertEqual(run("triage", "nothing-here")[0], 2)

    def test_doctor(self):
        code, output = run("doctor")
        self.assertEqual(code, 0)
        self.assertIn("rich", output)


if __name__ == "__main__":
    unittest.main()
