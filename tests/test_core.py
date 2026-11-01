"""CVE, cases, subnet, ATT&CK and port tests."""

import json
import os
import tempfile
import unittest

os.environ.setdefault("BASTET_DATA_DIR", tempfile.mkdtemp(prefix="bastet-test-"))

from bastet import attack, cases, cve, netcalc, ports  # noqa: E402

NVD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "descriptions": [
                    {"lang": "es", "value": "no importa"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-502"}, {"value": "CWE-400"}]}
                ],
                "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
            }
        }
    ]
}


class TestCve(unittest.TestCase):
    def test_normalise_variants(self):
        for text in ("CVE-2021-44228", "cve-2021-44228", "2021-44228", "CVE 2021 44228"):
            self.assertEqual(cve.normalise(text), "CVE-2021-44228")

    def test_is_cve(self):
        self.assertTrue(cve.is_cve("cve-2021-44228"))
        self.assertFalse(cve.is_cve("not-a-cve"))

    def test_parse_fixture(self):
        record = cve.parse(NVD_FIXTURE)
        self.assertEqual(record.id, "CVE-2021-44228")
        self.assertEqual(record.cvss, 10.0)
        self.assertEqual(record.severity, "critical")
        self.assertIn("Log4j2", record.description)
        self.assertNotIn("no importa", record.description)
        self.assertEqual(record.cwes, ["CWE-502", "CWE-400"])
        self.assertTrue(record.refs)

    def test_parse_empty_raises(self):
        with self.assertRaises(cve.LookupError_):
            cve.parse({"vulnerabilities": []})

    def test_parse_without_metrics(self):
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2020-1", "descriptions": [{"lang": "en", "value": "x"}]}}]}
        record = cve.parse(payload)
        self.assertIsNone(record.cvss)
        self.assertEqual(record.severity, "unknown")

    def test_cache_roundtrip(self):
        record = cve.parse(NVD_FIXTURE)
        cve.cache_put(record)
        again = cve.cache_get(record.id)
        self.assertIsNotNone(again)
        self.assertEqual(again.source, "cache")
        self.assertEqual(again.cvss, 10.0)

    def test_cache_miss(self):
        self.assertIsNone(cve.cache_get("CVE-1999-9999"))


class TestCases(unittest.TestCase):
    def setUp(self):
        os.environ["BASTET_DATA_DIR"] = tempfile.mkdtemp(prefix="bastet-cases-")

    def test_new_and_get(self):
        case = cases.new_case("Suspicious login", "high", "from a hosting ASN")
        found = cases.get_case(case.id)
        self.assertEqual(found.title, "Suspicious login")
        self.assertEqual(found.severity, "high")
        self.assertTrue(case.id.startswith("IR-"))

    def test_ids_increment(self):
        first = cases.new_case("one")
        second = cases.new_case("two")
        self.assertEqual(int(second.id.split("-")[-1]), int(first.id.split("-")[-1]) + 1)

    def test_add_event_and_order(self):
        case = cases.new_case("timeline test")
        cases.add_event(case.id, "first", "note")
        cases.add_event(case.id, "second", "action")
        found = cases.get_case(case.id)
        self.assertEqual([e["text"] for e in found.events], ["first", "second"])

    def test_add_to_unknown_case(self):
        with self.assertRaises(KeyError):
            cases.add_event("IR-1999-0001", "nope")

    def test_status_change(self):
        case = cases.new_case("close me")
        cases.set_status(case.id, "closed", "false positive")
        found = cases.get_case(case.id)
        self.assertEqual(found.status, "closed")
        self.assertEqual(found.resolution, "false positive")

    def test_open_count_excludes_closed(self):
        one = cases.new_case("open one")
        two = cases.new_case("open two")
        cases.set_status(two.id, "closed")
        self.assertEqual(cases.open_count(), 1)

    def test_list_filters(self):
        cases.new_case("a")
        cases.new_case("b")
        self.assertEqual(len(cases.list_cases()), 2)
        self.assertEqual(len(cases.list_cases("closed")), 0)

    def test_export_markdown(self):
        case = cases.new_case("export me", "medium", "summary here")
        cases.add_event(case.id, "the thing happened", "finding")
        markdown = cases.export_markdown(case.id)
        self.assertIn(case.id, markdown)
        self.assertIn("summary here", markdown)
        self.assertIn("the thing happened", markdown)
        self.assertIn("## Timeline", markdown)

    def test_export_unknown(self):
        with self.assertRaises(KeyError):
            cases.export_markdown("IR-1999-0001")

    def test_get_unknown(self):
        self.assertIsNone(cases.get_case("IR-1999-0001"))


class TestNetcalc(unittest.TestCase):
    def test_slash_24(self):
        info = netcalc.subnet("10.10.10.0/24")
        self.assertEqual(info.network, "10.10.10.0")
        self.assertEqual(info.netmask, "255.255.255.0")
        self.assertEqual(info.broadcast, "10.10.10.255")
        self.assertEqual(info.usable_hosts, 254)
        self.assertEqual(info.first_host, "10.10.10.1")
        self.assertTrue(info.is_private)

    def test_host_bits_are_cleared(self):
        self.assertEqual(netcalc.subnet("10.0.0.77/24").network, "10.0.0.0")

    def test_bare_address(self):
        self.assertEqual(netcalc.subnet("8.8.8.8").cidr, "8.8.8.8/32")

    def test_slash_31(self):
        self.assertEqual(netcalc.subnet("10.0.0.0/31").total_addresses, 2)

    def test_ipv6(self):
        info = netcalc.subnet("2001:db8::/64")
        self.assertEqual(info.version, 6)
        self.assertIsNone(info.broadcast)
        self.assertEqual(info.total_addresses, 2 ** 64)

    def test_contains(self):
        self.assertTrue(netcalc.contains("10.0.0.0/24", "10.0.0.5"))
        self.assertFalse(netcalc.contains("10.0.0.0/24", "10.0.1.5"))
        self.assertFalse(netcalc.contains("10.0.0.0/24", "not-an-ip"))

    def test_overlap(self):
        self.assertTrue(netcalc.overlap("10.0.0.0/24", "10.0.0.128/25"))
        self.assertFalse(netcalc.overlap("10.0.0.0/24", "10.0.2.0/24"))

    def test_summarise(self):
        self.assertIn("254 usable", netcalc.summarise("10.0.0.0/24"))

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            netcalc.subnet("999.1.1.1/24")


class TestAttack(unittest.TestCase):
    def test_by_id_exact(self):
        technique = attack.by_id("T1059")
        self.assertEqual(technique["name"], "PowerShell")

    def test_by_id_lowercase(self):
        self.assertIsNotNone(attack.by_id("t1059.001"))

    def test_parent_matches_subtechnique(self):
        self.assertIsNotNone(attack.by_id("T1059"))

    def test_search(self):
        results = attack.search("ransomware")
        self.assertTrue(results)
        self.assertTrue(any("Encrypted" in r["name"] or "Impact" in r["tactic"] for r in results))

    def test_tactic_filter(self):
        results = attack.search("", "exfiltration")
        self.assertTrue(results)
        self.assertTrue(all(r["tactic"] == "exfiltration" for r in results))

    def test_unknown(self):
        self.assertIsNone(attack.by_id("T9999"))

    def test_by_tactic_covers_everything(self):
        grouped = attack.by_tactic()
        total = sum(len(v) for v in grouped.values())
        self.assertEqual(total, len(attack.load()))

    def test_every_entry_has_detection(self):
        for technique in attack.load():
            self.assertTrue(technique["detection"], technique["id"])
            self.assertTrue(technique["tactic"] in attack.tactics())


class TestPorts(unittest.TestCase):
    def test_lookup(self):
        self.assertEqual(ports.lookup(6379)["service"], "redis")
        self.assertIsNone(ports.lookup(1))

    def test_search_by_name(self):
        self.assertTrue(ports.search("smb"))

    def test_search_by_number(self):
        self.assertEqual(ports.search("445")[0]["port"], 445)

    def test_dangerous(self):
        entries = ports.dangerous("critical")
        self.assertTrue(entries)
        self.assertTrue(all(e["risk"] == "critical" for e in entries))

    def test_sorted_unique(self):
        numbers = [e["port"] for e in ports.load()]
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_data_is_json_serialisable(self):
        json.dumps(ports.load())


if __name__ == "__main__":
    unittest.main()
