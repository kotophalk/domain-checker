"""Тесты ядра (checker.py). Сеть не нужна; живые проверки — в test_live.py."""

import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checker  # noqa: E402
from checker import (  # noqa: E402
    ERR_INVALID, ERR_QUOTA, ERR_SUBDOMAIN, ERR_TIMEOUT, ERR_UNPARSED, ERR_UNSUPPORTED, ERR_UPSTREAM,
    InvalidDomain, UpstreamError, classify_whois, normalize_domain,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "whois")


class NormalizeTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(normalize_domain("Example.RU"), ("example.ru", "example.ru"))

    def test_strips_scheme_path_port_www_dot(self):
        self.assertEqual(normalize_domain(" https://WWW.Yandex.ru:443/path?q=1#x ")[0], "yandex.ru")
        self.assertEqual(normalize_domain("yandex.ru.")[0], "yandex.ru")
        self.assertEqual(normalize_domain("user@yandex.ru")[0], "yandex.ru")

    def test_www_alone_is_a_domain(self):
        # www.ru — домен второго уровня, а не префикс
        self.assertEqual(normalize_domain("www.ru")[0], "www.ru")

    def test_idn(self):
        ascii_, display = normalize_domain("Пример.РФ")
        self.assertEqual(ascii_, "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(display, "пример.рф")
        self.assertEqual(normalize_domain("xn--e1afmkfd.xn--p1ai"), ("xn--e1afmkfd.xn--p1ai", "пример.рф"))

    def test_second_level_suffixes(self):
        self.assertEqual(normalize_domain("example.co.uk")[0], "example.co.uk")
        self.assertEqual(normalize_domain("example.com.ua")[0], "example.com.ua")

    def test_subdomains_rejected(self):
        for s in ("www2.yandex.ru", "a.b.example.com", "example.spb.ru", "a.example.co.uk"):
            with self.assertRaises(InvalidDomain, msg=s) as cm:
                normalize_domain(s)
            self.assertEqual(str(cm.exception), ERR_SUBDOMAIN)

    def test_invalid(self):
        for s in ("", "   ", "abcd", "-hfoo.com", "foo-.ru", "exa mple.ru", "127.0.0.1", "ex_ample.ru",
                  "a" * 64 + ".ru", "example.r", "example.123", "http://", ".ru", "ru.", "пример.р ф"):
            with self.assertRaises(InvalidDomain, msg=repr(s)) as cm:
                normalize_domain(s)
            self.assertEqual(str(cm.exception), ERR_INVALID, msg=repr(s))

    def test_too_long(self):
        with self.assertRaises(InvalidDomain):
            normalize_domain(".".join(["a" * 60] * 5) + ".ru")


class ClassifyWhoisFixturesTests(unittest.TestCase):
    """Каждый записанный ответ регистратуры должен классифицироваться правильно."""

    # whois у этих зон отключён/пуст — ответ обязан быть «нераспознано», а не «свободен»
    EXPECTED_UNKNOWN = {("es", "free"), ("shop", "free")}

    def test_fixtures(self):
        self.assertTrue(os.path.isdir(FIXTURES), FIXTURES)
        checked = 0
        for tld in sorted(os.listdir(FIXTURES)):
            for kind in ("free", "taken"):
                path = os.path.join(FIXTURES, tld, kind + ".txt")
                if not os.path.exists(path):
                    continue
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                want = "unknown" if (tld, kind) in self.EXPECTED_UNKNOWN else kind
                with self.subTest(tld=tld, kind=kind):
                    self.assertEqual(classify_whois(text), want)
                checked += 1
        self.assertGreater(checked, 100)

    def test_no_quota_false_positives_in_fixtures(self):
        for tld in sorted(os.listdir(FIXTURES)):
            for kind in ("free", "taken"):
                path = os.path.join(FIXTURES, tld, kind + ".txt")
                if not os.path.exists(path):
                    continue
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                for rx in checker._QUOTA_RE:
                    self.assertIsNone(rx.search(text), f"{tld}/{kind}: {rx.pattern}")


class ClassifyWhoisSyntheticTests(unittest.TestCase):
    def test_quota_and_errors_never_free(self):
        for s in ("Error: rate limit exceeded", "% Query rate limit exceeded. Try again later.",
                  "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS", "Your IP address has been blocked",
                  "Access denied", "% Too many requests", "Requests of this client are not permitted"):
            self.assertEqual(classify_whois(s), "quota", s)
        for s in ("", "   \n", "Error: connection refused", "Some garbage\nno idea", "error"):
            self.assertEqual(classify_whois(s), "unknown", repr(s))

    def test_free_wins_over_domain_line(self):
        # DENIC/EURid и др. печатают «Domain: x» и для свободных доменов
        self.assertEqual(classify_whois("Domain: foo.de\nStatus: free\n"), "free")
        self.assertEqual(classify_whois("Domain:\tfoo.eu\nStatus:\tAVAILABLE\n"), "free")

    def test_taken_variants(self):
        self.assertEqual(classify_whois("domain:        NIC.RU\nstate:         REGISTERED\n"), "taken")
        self.assertEqual(classify_whois("   Domain Name: NIC.COM\n"), "taken")
        self.assertEqual(classify_whois("domain.............: nic.fi\nstatus.............: Registered\n"), "taken")
        self.assertEqual(classify_whois("** Domain Name: google.tr\n"), "taken")
        self.assertEqual(classify_whois("Domain GOOGLE.KG (ACTIVE)\n"), "taken")


class _FakeHTTPResponse(io.BytesIO):
    def __init__(self, status, body=b"", url="http://x"):
        super().__init__(body)
        self.status = status
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _http_error(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b"{}"))


class RdapTests(unittest.TestCase):
    def setUp(self):
        checker._cache.clear()
        self.p_gate = mock.patch.object(checker._gate, "wait", lambda *a, **k: None)
        self.p_gate.start()

    def tearDown(self):
        self.p_gate.stop()

    def _run(self, side_effect):
        with mock.patch("checker.urllib.request.urlopen", side_effect=side_effect):
            return checker._rdap_lookup("example.com", ["https://rdap.example/"])

    def test_404_is_free(self):
        self.assertFalse(self._run([_http_error(404)]))

    def test_200_domain_is_taken(self):
        body = json.dumps({"objectClassName": "domain", "ldhName": "EXAMPLE.COM"}).encode()
        self.assertTrue(self._run([_FakeHTTPResponse(200, body)]))

    def test_200_with_error_404_body_is_free(self):
        body = json.dumps({"errorCode": 404, "title": "Not Found"}).encode()
        self.assertFalse(self._run([_FakeHTTPResponse(200, body)]))

    def test_200_garbage_is_error(self):
        with self.assertRaises(UpstreamError) as cm:
            self._run([_FakeHTTPResponse(200, b"<html>captive portal</html>")])
        self.assertEqual(str(cm.exception), ERR_UNPARSED)

    def test_429_is_quota(self):
        with self.assertRaises(UpstreamError) as cm:
            self._run([_http_error(429)])
        self.assertEqual(str(cm.exception), ERR_QUOTA)

    def test_5xx_is_upstream_error(self):
        with self.assertRaises(UpstreamError) as cm:
            self._run([_http_error(503)])
        self.assertEqual(str(cm.exception), ERR_UPSTREAM)

    def test_timeout_retries_then_error(self):
        import socket
        with self.assertRaises(UpstreamError) as cm:
            self._run([socket.timeout(), socket.timeout()])
        self.assertEqual(str(cm.exception), ERR_TIMEOUT)

    def test_transient_then_ok(self):
        self.assertFalse(self._run([urllib.error.URLError("boom"), _http_error(404)]))


class CheckDomainFlowTests(unittest.TestCase):
    """Сквозная логика check_domain с подменёнными источниками."""

    def setUp(self):
        checker._cache.clear()

    def test_invalid_input_returns_error_result(self):
        r = checker.check_domain("abcd")
        self.assertEqual(r, {"domain": "abcd", "ascii": None, "free": False, "error": ERR_INVALID, "source": None})

    def test_rdap_preferred_then_whois_fallback(self):
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=["https://rdap.example/"]), \
             mock.patch("checker._rdap_lookup", side_effect=UpstreamError(ERR_UPSTREAM)), \
             mock.patch("checker.whois_server_for", return_value="whois.example"), \
             mock.patch("checker._whois_lookup", return_value=False) as wl:
            r = checker.check_domain("example.com")
        self.assertTrue(r["free"])
        self.assertEqual(r["source"], "whois")
        wl.assert_called_once_with("example.com", "whois.example")

    def test_rdap_error_without_whois_surfaces_rdap_error(self):
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=["https://rdap.example/"]), \
             mock.patch("checker._rdap_lookup", side_effect=UpstreamError(ERR_QUOTA)), \
             mock.patch("checker.whois_server_for", return_value=None):
            r = checker.check_domain("example.com")
        self.assertEqual((r["free"], r["error"], r["source"]), (False, ERR_QUOTA, None))

    def test_unsupported_zone(self):
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=[]), \
             mock.patch("checker.whois_server_for", return_value=None):
            r = checker.check_domain("foo.zzzznotatld")
        self.assertEqual((r["free"], r["error"]), (False, ERR_UNSUPPORTED))

    def test_unparsed_whois_is_error_not_free(self):
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=[]), \
             mock.patch("checker.whois_server_for", return_value="whois.example"), \
             mock.patch("checker.whois_raw", return_value="Error: something odd\n"):
            r = checker.check_domain("example.ru")
        self.assertEqual((r["free"], r["error"], r["source"]), (False, ERR_UNPARSED, None))

    def test_cache_hits_only_successful_results(self):
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=["https://rdap.example/"]), \
             mock.patch("checker._rdap_lookup", return_value=False) as rl:
            checker.check_domain("cached.com")
            checker.check_domain("CACHED.com")
        self.assertEqual(rl.call_count, 1)
        with mock.patch.object(checker.rdap_bootstrap, "urls_for", return_value=["https://rdap.example/"]), \
             mock.patch("checker._rdap_lookup", side_effect=UpstreamError(ERR_TIMEOUT)) as rl, \
             mock.patch("checker.whois_server_for", return_value=None):
            self.assertEqual(checker.check_domain("err.com")["error"], ERR_TIMEOUT)
            checker.check_domain("err.com")
        self.assertEqual(rl.call_count, 2)


class HostGateTests(unittest.TestCase):
    def test_spacing(self):
        g = checker.HostGate()
        sleeps = []
        with mock.patch("checker.time.sleep", side_effect=lambda s: sleeps.append(s)), \
             mock.patch("checker.time.monotonic", return_value=100.0):
            g.wait("h", 0.5)
            g.wait("h", 0.5)
            g.wait("h", 0.5)
            g.wait("other", 0.5)
        self.assertEqual([round(s, 3) for s in sleeps], [0.5, 1.0])


class TTLCacheTests(unittest.TestCase):
    def test_ttl_and_eviction(self):
        c = checker.TTLCache(ttl=10, maxsize=2)
        with mock.patch("checker.time.monotonic", return_value=0.0):
            c.set("a", {"v": 1}); c.set("b", {"v": 2}); c.set("c", {"v": 3})
            self.assertIsNone(c.get("a"))
            self.assertEqual(c.get("c"), {"v": 3})
        with mock.patch("checker.time.monotonic", return_value=11.0):
            self.assertIsNone(c.get("c"))

    def test_disabled(self):
        c = checker.TTLCache(ttl=0, maxsize=10)
        c.set("a", {"v": 1})
        self.assertIsNone(c.get("a"))


if __name__ == "__main__":
    unittest.main()
