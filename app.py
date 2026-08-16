"""HTTP-сервер проверки доменов: API + статика. Только стандартная библиотека.

Запуск: ``python3 app.py`` (каталог запуска не важен — статика берётся рядом со скриптом).
Настройки — переменными окружения, см. ``Config`` ниже и README.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import checker

log = logging.getLogger("app")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = _env_int("PORT", 8080)
    MAX_DOMAINS = _env_int("MAX_DOMAINS", 20)               # доменов в одном запросе
    RATE_LIMIT_PER_MIN = _env_int("RATE_LIMIT_PER_MIN", 60)   # проверок домена в минуту на IP (0 — выключить)
    RATE_LIMIT_BURST = _env_int("RATE_LIMIT_BURST", 60)       # размер «ведра»
    CHECK_WORKERS = _env_int("CHECK_WORKERS", 16)             # одновременных проверок доменов на весь сервер
    TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"   # брать IP из X-Forwarded-For
    CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "")  # "" — без CORS; "*" или список через запятую
    RDAP_BOOTSTRAP_REFRESH = os.environ.get("RDAP_BOOTSTRAP_REFRESH", "1") == "1"
    REQUEST_TIMEOUT = _env_int("REQUEST_TIMEOUT", 60)         # таймаут сокета клиента, сек


# ---------------------------------------------------------------------------
# Лимит на IP: token bucket
# ---------------------------------------------------------------------------

class RateLimiter:
    """Ведро токенов на ключ (IP). ``take(key, n)`` → 0, если разрешено, иначе секунд до разрешения."""

    def __init__(self, per_minute: int, burst: int) -> None:
        self.rate = per_minute / 60.0
        self.burst = float(max(burst, 1))
        self._buckets: dict[str, tuple[float, float]] = {}   # key -> (tokens, last_ts)
        self._lock = threading.Lock()
        self.enabled = per_minute > 0

    def take(self, key: str, n: int = 1) -> float:
        if not self.enabled:
            return 0.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= n:
                self._buckets[key] = (tokens - n, now)
                wait = 0.0
            else:
                self._buckets[key] = (tokens, now)
                wait = (n - tokens) / self.rate if self.rate > 0 else 60.0
            if len(self._buckets) > 20000:
                stale = now - 3600
                for k in [k for k, (_, ts) in self._buckets.items() if ts < stale]:
                    del self._buckets[k]
        return wait


rate_limiter = RateLimiter(Config.RATE_LIMIT_PER_MIN, Config.RATE_LIMIT_BURST)
_pool = ThreadPoolExecutor(max_workers=max(1, Config.CHECK_WORKERS), thread_name_prefix="check")

# Заменяемая точка входа в проверку (тесты подменяют, чтобы не ходить в сеть).
check_domain = checker.check_domain


def split_domains(raw: str) -> list[str]:
    """Разбить строку по запятым/переводам строк, убрать пустые и дубли, сохранив порядок."""
    seen: set[str] = set()
    out: list[str] = []
    for part in raw.replace("\n", ",").replace(";", ",").split(","):
        p = part.strip()
        if not p:
            continue
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def check_many(domains: list[str]) -> list[dict]:
    """Проверить список параллельно, сохранив порядок."""
    if len(domains) <= 1:
        return [check_domain(d) for d in domains]
    return list(_pool.map(check_domain, domains, timeout=Config.REQUEST_TIMEOUT))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class DomainCheckerHandler(SimpleHTTPRequestHandler):
    server_version = "DomainChecker/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = Config.REQUEST_TIMEOUT

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    # --- утилиты -----------------------------------------------------------

    def client_ip(self) -> str:
        headers = getattr(self, "headers", None)
        if Config.TRUST_PROXY and headers is not None:
            xff = headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
            real = headers.get("X-Real-IP")
            if real:
                return real.strip()
        return self.client_address[0]

    def _cors_headers(self) -> None:
        allow = Config.CORS_ALLOW_ORIGIN
        if not allow:
            return
        origin = self.headers.get("Origin", "")
        if allow == "*":
            self.send_header("Access-Control-Allow-Origin", "*")
        elif origin and origin in [o.strip() for o in allow.split(",")]:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        else:
            return
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")

    def send_json(self, status: int, payload, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        for k, v in (extra_headers or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802 — имя из базового класса
        log.info("%s %s", self.client_ip(), fmt % args)

    def list_directory(self, path):  # листинг каталогов запрещён
        self.send_error(HTTPStatus.NOT_FOUND)
        return None

    # --- маршрутизация -----------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self, head: bool) -> None:
        # http.server декодирует строку запроса как latin-1; сырые UTF-8-байты
        # в URL (curl без percent-encoding, «пример.рф») иначе превращаются в кракозябры.
        try:
            self.path = self.path.encode("latin-1").decode("utf-8")
        except UnicodeError:
            pass
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/api/check":
            return self.api_check(parse_qs(parts.query))
        if path == "/api/limits":
            return self.send_json(200, {"max_domains": Config.MAX_DOMAINS,
                                        "rate_limit_per_min": Config.RATE_LIMIT_PER_MIN})
        if path == "/api/tlds":
            return self.send_json(200, {"tlds": checker.supported_tlds()},
                                  {"Cache-Control": "public, max-age=3600"})
        if path == "/healthz":
            return self.send_json(200, {"status": "ok", "rdap_zones": len(checker.rdap_bootstrap),
                                        "rdap_publication": checker.rdap_bootstrap.publication})
        if path.startswith("/api/"):
            return self.send_json(404, {"error": "Неизвестный метод API"})
        # статика: только / и /static/<файл> (каталог static/ рядом со скриптом)
        if path == "/":
            self.path = "/index.html"
        elif path.startswith("/static/"):
            self.path = path[len("/static"):]
        else:
            return self.send_error(HTTPStatus.NOT_FOUND)
        return super().do_HEAD() if head else super().do_GET()

    def do_GET(self) -> None:  # noqa: N802
        return self._dispatch(head=False)

    def do_HEAD(self) -> None:  # noqa: N802
        return self._dispatch(head=True)

    # --- API ---------------------------------------------------------------

    def api_check(self, query: dict) -> None:
        raw = ",".join(query.get("domains", []))
        domains = split_domains(raw)
        if not domains:
            return self.send_json(400, {"error": "Не переданы домены (параметр domains)"})
        if len(domains) > Config.MAX_DOMAINS:
            return self.send_json(400, {"error": f"Не более {Config.MAX_DOMAINS} доменов за один запрос",
                                        "max_domains": Config.MAX_DOMAINS})
        wait = rate_limiter.take(self.client_ip(), len(domains))
        if wait > 0:
            retry = max(1, int(wait + 0.999))
            return self.send_json(429, {"error": "Слишком много запросов, попробуйте позже",
                                        "retry_after": retry}, {"Retry-After": retry})
        try:
            results = check_many(domains)
        except Exception as e:  # таймаут пула и т.п. — отдаём ошибку, а не падаем
            log.exception("check_many failed: %s", e)
            return self.send_json(503, {"error": "Сервис временно перегружен, попробуйте позже"})
        return self.send_json(200, results)


def make_server(host: str = Config.HOST, port: int = Config.PORT) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), DomainCheckerHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    if Config.RDAP_BOOTSTRAP_REFRESH:
        checker.start_bootstrap_refresher()
    server = make_server()
    log.info("Domain Checker слушает http://%s:%d/ (лимит %d доменов/запрос, %d проверок/мин на IP)",
             Config.HOST, Config.PORT, Config.MAX_DOMAINS, Config.RATE_LIMIT_PER_MIN)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
