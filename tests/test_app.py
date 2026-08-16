"""HTTP-контракт app.py: поднимаем сервер на свободном порту, проверку доменов подменяем."""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402


def fake_check(raw):
    d = raw.strip().lower()
    if "." not in d:
        return {"domain": raw, "ascii": None, "free": False, "error": "Некорректный домен", "source": None}
    return {"domain": d, "ascii": d, "free": d.startswith("free-"), "error": None, "source": "fake"}


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.check_domain = fake_check
        app.Config.MAX_DOMAINS = 3
        app.rate_limiter = app.RateLimiter(per_minute=6, burst=6)
        cls.server = app.make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path, method="GET", headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, headers=headers or {})
        # r.headers — email.message.Message: доступ к заголовкам без учёта регистра
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def get_json(self, path, **kw):
        status, headers, body = self.get(path, **kw)
        return status, headers, (json.loads(body) if body else None)


class ApiCheckTests(ServerTestCase):
    def setUp(self):
        app.rate_limiter = app.RateLimiter(per_minute=6, burst=6)

    def test_ok_preserves_order_and_shape(self):
        status, _, data = self.get_json("/api/check?domains=free-a.ru,%20taken.ru%20,abcd")
        self.assertEqual(status, 200)
        self.assertEqual([d["domain"] for d in data], ["free-a.ru", "taken.ru", "abcd"])
        self.assertEqual([d["free"] for d in data], [True, False, False])
        self.assertEqual(data[2]["error"], "Некорректный домен")
        for d in data:
            self.assertEqual(set(d), {"domain", "ascii", "free", "error", "source"})

    def test_raw_utf8_and_percent_encoded_idn(self):
        # curl шлёт кириллицу сырыми байтами, браузер — через encodeURIComponent; оба должны работать
        import socket
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall("GET /api/check?domains=пример.рф HTTP/1.0\r\nHost: x\r\n\r\n".encode("utf-8"))
            raw = b""
            while chunk := s.recv(65536):
                raw += chunk
        body = json.loads(raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
        self.assertEqual(body[0]["domain"], "пример.рф")
        status, _, data = self.get_json("/api/check?domains=%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84")
        self.assertEqual((status, data[0]["domain"]), (200, "пример.рф"))

    def test_dedup_and_separators(self):
        status, _, data = self.get_json("/api/check?domains=a.ru%0Ab.ru;A.RU,,b.ru")
        self.assertEqual(status, 200)
        self.assertEqual([d["domain"] for d in data], ["a.ru", "b.ru"])

    def test_missing_param_400_json(self):
        status, headers, data = self.get_json("/api/check")
        self.assertEqual(status, 400)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertIn("error", data)

    def test_too_many_400(self):
        status, _, data = self.get_json("/api/check?domains=a.ru,b.ru,c.ru,d.ru")
        self.assertEqual(status, 400)
        self.assertEqual(data["max_domains"], 3)

    def test_rate_limit_429(self):
        self.assertEqual(self.get_json("/api/check?domains=a.ru,b.ru,c.ru")[0], 200)
        self.assertEqual(self.get_json("/api/check?domains=d.ru,e.ru,f.ru")[0], 200)
        status, headers, data = self.get_json("/api/check?domains=g.ru")
        self.assertEqual(status, 429)
        self.assertTrue(int(headers["Retry-After"]) >= 1)
        self.assertEqual(data["retry_after"], int(headers["Retry-After"]))

    def test_trust_proxy_uses_xff(self):
        app.Config.TRUST_PROXY = True
        try:
            for i in range(3):
                s, _, _ = self.get_json("/api/check?domains=a.ru,b.ru", headers={"X-Forwarded-For": f"10.0.0.{i}, 1.2.3.4"})
                self.assertEqual(s, 200)
        finally:
            app.Config.TRUST_PROXY = False


class MiscRoutesTests(ServerTestCase):
    def test_healthz(self):
        status, _, data = self.get_json("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")
        self.assertGreater(data["rdap_zones"], 1000)

    def test_limits(self):
        status, _, data = self.get_json("/api/limits")
        self.assertEqual((status, data["max_domains"]), (200, 3))

    def test_tlds(self):
        status, _, data = self.get_json("/api/tlds")
        self.assertEqual(status, 200)
        for t in ("ru", "su", "xn--p1ai", "com", "app", "by", "kz"):
            self.assertIn(t, data["tlds"])
        self.assertNotIn("es", data["tlds"])

    def test_unknown_api_404_json(self):
        status, _, data = self.get_json("/api/nope")
        self.assertEqual((status, "error" in data), (404, True))

    def test_static_index(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"domainsInput", body)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.get("/static/index.html")[0], 200)

    def test_head_static_has_no_body(self):
        status, headers, body = self.get("/", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)

    def test_no_source_or_traversal(self):
        for p in ("/app.py", "/checker.py", "/static/../app.py", "/static/../../etc/passwd", "/tests/test_app.py", "/data/rdap_dns.json"):
            self.assertEqual(self.get(p)[0], 404, p)

    def test_cors_off_by_default(self):
        _, headers, _ = self.get("/api/limits", headers={"Origin": "https://example.org"})
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_cors_when_enabled(self):
        app.Config.CORS_ALLOW_ORIGIN = "https://a.example, https://b.example"
        try:
            _, headers, _ = self.get("/api/limits", headers={"Origin": "https://b.example"})
            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://b.example")
            _, headers, _ = self.get("/api/limits", headers={"Origin": "https://evil.example"})
            self.assertNotIn("Access-Control-Allow-Origin", headers)
            status, headers, _ = self.get("/api/check", method="OPTIONS", headers={"Origin": "https://a.example"})
            self.assertEqual(status, 204)
            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://a.example")
        finally:
            app.Config.CORS_ALLOW_ORIGIN = ""


class SplitDomainsTests(unittest.TestCase):
    def test_split(self):
        self.assertEqual(app.split_domains(" a.ru,\nB.ru;a.RU,, ,c.ru "), ["a.ru", "B.ru", "c.ru"])
        self.assertEqual(app.split_domains(""), [])


class RateLimiterTests(unittest.TestCase):
    def test_bucket(self):
        rl = app.RateLimiter(per_minute=60, burst=10)
        self.assertEqual(rl.take("ip", 10), 0.0)
        wait = rl.take("ip", 1)
        self.assertGreater(wait, 0)
        self.assertLessEqual(wait, 1.01)
        self.assertEqual(rl.take("other", 1), 0.0)

    def test_disabled(self):
        rl = app.RateLimiter(per_minute=0, burst=0)
        self.assertEqual(rl.take("ip", 1000), 0.0)


if __name__ == "__main__":
    unittest.main()
