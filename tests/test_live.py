"""Живые проверки против реальных регистратур. Запускаются только при LIVE_TESTS=1:

    LIVE_TESTS=1 python3 -m unittest tests.test_live -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checker  # noqa: E402

FREE = "zzq-surely-free-domain-98765"


@unittest.skipUnless(os.environ.get("LIVE_TESTS") == "1", "живые тесты выключены (LIVE_TESTS=1)")
class LiveTests(unittest.TestCase):
    def check(self, domain):
        r = checker.check_domain(domain, use_cache=False)
        self.assertIsNone(r["error"], f"{domain}: {r}")
        return r

    def test_tci_whois(self):
        self.assertFalse(self.check("nic.ru")["free"])
        self.assertTrue(self.check(f"{FREE}.ru")["free"])
        self.assertFalse(self.check("nic.su")["free"])
        self.assertFalse(self.check("яндекс.рф")["free"])
        self.assertTrue(self.check(f"{FREE}.рф")["free"])

    def test_rdap_gtlds(self):
        for tld in ("com", "org", "info", "app", "xyz", "online"):
            self.assertFalse(self.check(f"nic.{tld}")["free"], tld)
            self.assertTrue(self.check(f"{FREE}.{tld}")["free"], tld)

    def test_whois_cctlds(self):
        for tld in ("by", "kz", "de", "io"):
            self.assertFalse(self.check(f"nic.{tld}")["free"], tld)
            self.assertTrue(self.check(f"{FREE}.{tld}")["free"], tld)

    def test_iana_discovery_for_unlisted_tld(self):
        # .lu нет ни в таблице whois, ни (возможно) в RDAP-снимке — сервер должен найтись через IANA
        r = checker.check_domain(f"{FREE}.lu", use_cache=False)
        self.assertIn(r["error"], (None, checker.ERR_UNPARSED, checker.ERR_UNSUPPORTED))
        if r["error"] is None:
            self.assertTrue(r["free"])


if __name__ == "__main__":
    unittest.main()
