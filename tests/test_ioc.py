"""Indicator triage tests — the part that has to be right at 03:00."""

import os
import tempfile
import unittest

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-test-"))

from bastet import ioc  # noqa: E402


class TestClassify(unittest.TestCase):
    def test_ipv4(self):
        indicator = ioc.classify("8.8.8.8")
        self.assertEqual(indicator.kind, "ipv4")
        self.assertEqual(indicator.risk, "medium")

    def test_private_ip_is_low_risk(self):
        indicator = ioc.classify("10.10.10.5")
        self.assertEqual(indicator.risk, "low")
        self.assertIn("private", indicator.notes[0])

    def test_loopback(self):
        self.assertIn("loopback", ioc.classify("127.0.0.1").notes[0])

    def test_ipv6(self):
        self.assertEqual(ioc.classify("2001:4860:4860::8888").kind, "ipv6")

    def test_domains(self):
        self.assertEqual(ioc.classify("example.com").kind, "domain")
        self.assertEqual(ioc.classify("a.b.c.example.co.uk").kind, "domain")

    def test_punycode_is_high(self):
        indicator = ioc.classify("xn--80ak6aa92e.com")
        self.assertEqual(indicator.risk, "high")
        self.assertIn("punycode", " ".join(indicator.notes).lower())

    def test_suspicious_tld(self):
        indicator = ioc.classify("login-secure.top")
        self.assertEqual(indicator.risk, "high")

    def test_url_with_credentials_is_high(self):
        indicator = ioc.classify("http://user:pw@10.0.0.5/x")
        self.assertEqual(indicator.risk, "high")
        self.assertIn("credentials in the URL", " ".join(indicator.notes))

    def test_url_host_tld_matches_domain_verdict(self):
        """The same host must not read HIGH as a domain and LOW as a URL."""
        url = ioc.classify("https://evil-login.top/reset")
        domain = ioc.classify("evil-login.top")
        self.assertEqual(url.risk, domain.risk)
        self.assertEqual(url.risk, "high")

    def test_url_scheme(self):
        self.assertEqual(ioc.classify("https://example.com/path?q=1").kind, "url")

    def test_hashes(self):
        self.assertEqual(ioc.classify("d41d8cd98f00b204e9800998ecf8427e").kind, "md5")
        self.assertEqual(ioc.classify("a" * 40).kind, "sha1")
        self.assertEqual(ioc.classify("a" * 64).kind, "sha256")
        self.assertEqual(ioc.classify("a" * 128).kind, "sha512")

    def test_known_hash_is_named(self):
        indicator = ioc.classify("d41d8cd98f00b204e9800998ecf8427e")
        self.assertIn("empty file", indicator.notes[0])

    def test_all_same_character_is_flagged(self):
        indicator = ioc.classify("a" * 32)
        self.assertIn("placeholder", " ".join(indicator.notes))

    def test_email(self):
        self.assertEqual(ioc.classify("someone@example.com").kind, "email")

    def test_cve(self):
        indicator = ioc.classify("CVE-2021-44228")
        self.assertEqual(indicator.kind, "cve")
        self.assertIn("nvd", indicator.links)

    def test_unknown(self):
        self.assertEqual(ioc.classify("hello world").kind, "unknown")
        self.assertEqual(ioc.classify("").kind, "empty")

    def test_links_only_for_public(self):
        self.assertIn("virustotal", ioc.classify("8.8.8.8").links)
        self.assertNotIn("virustotal", ioc.classify("10.0.0.1").links)


class TestDefang(unittest.TestCase):
    def test_roundtrip(self):
        value = "https://evil-login.top/path?a=1"
        self.assertEqual(ioc.refang(ioc.defang(value)), value)

    def test_defang_ip(self):
        self.assertEqual(ioc.defang("45.155.205.233"), "45[.]155[.]205[.]233")

    def test_defang_scheme(self):
        self.assertTrue(ioc.defang("http://x.com").startswith("hxxp"))

    def test_hashes_are_not_defanged(self):
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        self.assertEqual(ioc.defang(digest), digest)

    def test_refang_brackets(self):
        self.assertEqual(ioc.refang("evil[.]top"), "evil.top")

    def test_classify_after_defang(self):
        self.assertEqual(ioc.classify("evil[.]top").kind, "domain")


class TestRisk(unittest.TestCase):
    def test_worst_of_many(self):
        items = ioc.triage(["10.0.0.1", "evil.top", "8.8.8.8"])
        self.assertEqual(ioc.worst_risk(items), "high")

    def test_empty_list(self):
        self.assertEqual(ioc.worst_risk([]), "info")

    def test_to_dict(self):
        payload = ioc.classify("evil.top").to_dict()
        self.assertEqual(payload["kind"], "domain")
        self.assertEqual(payload["defanged"], "evil[.]top")


if __name__ == "__main__":
    unittest.main()
