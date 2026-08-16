"""Проверка доступности доменов: нормализация, RDAP, whois (порт 43), лимитеры, кэш.

Только стандартная библиотека. Точка входа — ``check_domain(raw) -> dict``:

    {"domain": "пример.рф", "ascii": "xn--e1afmkfd.xn--p1ai",
     "free": True | False, "error": None | "…по-русски…", "source": "rdap" | "whois" | None}

Логика ответа трёхзначная и честная: «свободен» — только когда регистратура явно
это сказала (RDAP 404 или распознанный whois-паттерн). Всё остальное — «занят»
(распознан) или ошибка с пояснением. Нераспознанный ответ никогда не считается
«свободен».

Порядок источников для зоны: RDAP (bootstrap IANA) → whois из таблицы ниже →
whois-сервер, найденный через whois.iana.org → «Неподдерживаемая зона».
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

log = logging.getLogger("checker")

# ---------------------------------------------------------------------------
# Настройки (переопределяются переменными окружения)
# ---------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


WHOIS_TIMEOUT = _env_float("WHOIS_TIMEOUT", 10.0)
RDAP_TIMEOUT = _env_float("RDAP_TIMEOUT", 10.0)
WHOIS_MIN_INTERVAL = _env_float("WHOIS_MIN_INTERVAL", 0.5)   # пауза между запросами к одному whois-хосту
RDAP_MIN_INTERVAL = _env_float("RDAP_MIN_INTERVAL", 0.1)     # то же для RDAP-хостов
UPSTREAM_CONCURRENCY = _env_int("UPSTREAM_CONCURRENCY", 8)   # одновременных запросов наружу всего
CACHE_TTL = _env_float("CACHE_TTL", 60.0)                    # кэш результатов, сек (0 — выключить)
CACHE_MAX = _env_int("CACHE_MAX", 10000)
IANA_TTL = 24 * 3600
USER_AGENT = os.environ.get("USER_AGENT", "domain-checker/1.0 (+https://github.com/kotophalk/domain-checker)")
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_BOOTSTRAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rdap_dns.json")
MAX_RESPONSE_BYTES = 256 * 1024

# ---------------------------------------------------------------------------
# Сообщения об ошибках (пользовательские, по-русски)
# ---------------------------------------------------------------------------

ERR_INVALID = "Некорректный домен"
ERR_SUBDOMAIN = "Укажите домен без поддоменов (например, example.ru)"
ERR_UNSUPPORTED = "Неподдерживаемая зона"
ERR_TIMEOUT = "Сервер регистратуры не отвечает"
ERR_QUOTA = "Регистратура временно ограничила запросы, попробуйте позже"
ERR_UNPARSED = "Не удалось разобрать ответ регистратуры"
ERR_UPSTREAM = "Сервис регистратуры временно недоступен"


class InvalidDomain(ValueError):
    """Строка не является доменом второго уровня; ``str(e)`` — сообщение для пользователя."""


# ---------------------------------------------------------------------------
# Нормализация и валидация
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{2,59})$")

# Публичные суффиксы второго уровня, под которыми регистрируют домены «третьего» уровня.
# Домен вида name.<suffix> считается доменом второго уровня и проверяется у регистратуры TLD.
SECOND_LEVEL_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk ltd.uk plc.uk net.uk
    com.ua net.ua org.ua in.ua kiev.ua kyiv.ua
    com.tr net.tr org.tr gen.tr
    com.pl net.pl org.pl biz.pl info.pl
    com.br net.br org.br
    co.jp ne.jp or.jp
    com.au net.au org.au
    co.nz net.nz org.nz
    com.mx org.mx
    co.il org.il
    com.cn net.cn org.cn
    co.za org.za
    com.kz org.kz
    com.by
    com.ge org.ge
    com.md
    com.uz co.uz
    com.kg org.kg
    """.split()
)


def normalize_domain(raw: str) -> tuple[str, str]:
    """Возвращает ``(ascii, display)`` или бросает ``InvalidDomain``.

    Принимает мусор в духе «https://WWW.Пример.РФ/путь?x=1», отрезает схему, путь,
    порт, ведущий www. и завершающую точку; кириллицу переводит в punycode.
    """
    s = (raw or "").strip().lower()
    s = _SCHEME_RE.sub("", s)
    s = re.split(r"[/?#\\]", s, 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = re.sub(r":\d{1,5}$", "", s)
    s = s.strip(" \t.")
    if s.startswith("www.") and s.count(".") >= 2:
        s = s[4:]
    if not s or "." not in s or " " in s:
        raise InvalidDomain(ERR_INVALID)
    try:
        ascii_domain = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidDomain(ERR_INVALID)
    if len(ascii_domain) > 253:
        raise InvalidDomain(ERR_INVALID)
    labels = ascii_domain.split(".")
    if any(not _LABEL_RE.match(lbl) for lbl in labels):
        raise InvalidDomain(ERR_INVALID)
    if not _TLD_RE.match(labels[-1]):
        raise InvalidDomain(ERR_INVALID)
    if len(labels) > 2 and not (len(labels) == 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES):
        raise InvalidDomain(ERR_SUBDOMAIN)
    try:
        display = ascii_domain.encode("ascii").decode("idna")
    except UnicodeError:
        display = ascii_domain
    return ascii_domain, display


# ---------------------------------------------------------------------------
# Лимитеры в сторону регистратур
# ---------------------------------------------------------------------------

class HostGate:
    """Минимальный интервал между запросами к одному хосту (общий для всех потоков)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_allowed: dict[str, float] = {}

    def wait(self, host: str, min_interval: float) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_allowed.get(host, 0.0))
            self._next_allowed[host] = slot + min_interval
            if len(self._next_allowed) > 5000:  # не даём словарю расти бесконечно
                cutoff = now - 60
                for h in [h for h, t in self._next_allowed.items() if t < cutoff]:
                    del self._next_allowed[h]
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


_gate = HostGate()
_upstream_sem = threading.BoundedSemaphore(max(1, UPSTREAM_CONCURRENCY))


# ---------------------------------------------------------------------------
# Кэш результатов (короткий, чтобы повторные клики не били по регистратурам)
# ---------------------------------------------------------------------------

class TTLCache:
    def __init__(self, ttl: float, maxsize: int) -> None:
        self.ttl = ttl
        self.maxsize = maxsize
        self._d: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str):
        if self.ttl <= 0:
            return None
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            exp, val = item
            if exp < time.monotonic():
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return val

    def set(self, key: str, val: dict) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            self._d[key] = (time.monotonic() + self.ttl, val)
            self._d.move_to_end(key)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


_cache = TTLCache(CACHE_TTL, CACHE_MAX)


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------

class RdapBootstrap:
    """TLD → список базовых URL RDAP. Снимок из data/, опционально обновляется с IANA."""

    def __init__(self) -> None:
        self._index: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self.publication = None
        self.load_file(RDAP_BOOTSTRAP_FILE)

    def _ingest(self, data: dict) -> None:
        idx: dict[str, list[str]] = {}
        for tlds, urls in data.get("services", []):
            urls = [u for u in urls if isinstance(u, str) and u.startswith(("https://", "http://"))]
            urls.sort(key=lambda u: not u.startswith("https://"))  # https раньше http
            for t in tlds:
                idx[t.lower()] = urls
        with self._lock:
            self._index = idx
            self.publication = data.get("publication")

    def load_file(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._ingest(json.load(f))
            return True
        except (OSError, ValueError) as e:
            log.warning("RDAP bootstrap: не удалось прочитать %s: %s", path, e)
            return False

    def refresh_from_iana(self, timeout: float = 20.0) -> bool:
        try:
            req = urllib.request.Request(RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read(4 * 1024 * 1024).decode("utf-8"))
            if not data.get("services"):
                return False
            self._ingest(data)
            log.info("RDAP bootstrap обновлён с IANA (publication=%s, зон=%d)", self.publication, len(self._index))
            return True
        except Exception as e:  # сеть/JSON — не критично, остаёмся на снимке
            log.warning("RDAP bootstrap: обновление с IANA не удалось: %s", e)
            return False

    def urls_for(self, tld: str) -> list[str]:
        with self._lock:
            return list(self._index.get(tld.lower(), ()))

    def __len__(self) -> int:
        return len(self._index)


rdap_bootstrap = RdapBootstrap()


class UpstreamError(Exception):
    """Ошибка обращения к регистратуре; ``str(e)`` — сообщение для пользователя."""


def _rdap_lookup(ascii_domain: str, base_urls: list[str]) -> bool:
    """True — занят, False — свободен. Бросает UpstreamError, если ответа нет."""
    last_err: Exception | None = None
    for base in base_urls:
        url = f"{base.rstrip('/')}/domain/{ascii_domain}"
        host = urllib.parse.urlsplit(url).hostname or base
        for attempt in (1, 2):
            _gate.wait(host, RDAP_MIN_INTERVAL)
            req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                                       "User-Agent": USER_AGENT})
            try:
                with _upstream_sem:
                    with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
                        status = resp.status
                        body = resp.read(MAX_RESPONSE_BYTES)
                if status == 200:
                    try:
                        obj = json.loads(body.decode("utf-8", "replace"))
                    except ValueError:
                        raise UpstreamError(ERR_UNPARSED)
                    if isinstance(obj, dict) and obj.get("errorCode") == 404:
                        return False
                    if isinstance(obj, dict) and (obj.get("objectClassName") == "domain" or obj.get("ldhName")):
                        return True
                    raise UpstreamError(ERR_UNPARSED)
                raise UpstreamError(ERR_UNPARSED)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return False
                if e.code == 429:
                    raise UpstreamError(ERR_QUOTA)
                if e.code in (400, 422):
                    # регистратура не приняла имя (обычно IDN-правила зоны) — это не «свободен»
                    raise UpstreamError(ERR_UNPARSED)
                last_err = UpstreamError(ERR_UPSTREAM)
                log.info("RDAP %s -> HTTP %s", url, e.code)
                break  # другой базовый URL, если есть
            except (socket.timeout, TimeoutError):
                last_err = UpstreamError(ERR_TIMEOUT)
                log.info("RDAP %s -> timeout (попытка %d)", url, attempt)
            except (urllib.error.URLError, ConnectionError, OSError, ValueError) as e:
                last_err = UpstreamError(ERR_UPSTREAM)
                log.info("RDAP %s -> %s: %s (попытка %d)", url, type(e).__name__, e, attempt)
    raise last_err or UpstreamError(ERR_UPSTREAM)


# ---------------------------------------------------------------------------
# WHOIS (порт 43)
# ---------------------------------------------------------------------------

# Верифицированная таблица TLD → whois-сервер (ответы записаны в tests/fixtures/whois/).
WHOIS_SERVERS: dict[str, str] = {
    "ru": "whois.tcinet.ru", "su": "whois.tcinet.ru", "xn--p1ai": "whois.tcinet.ru",
    "moscow": "whois.nic.moscow", "xn--80adxhks": "whois.nic.xn--80adxhks",
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "cc": "ccwhois.verisign-grs.com", "name": "whois.nic.name",
    "org": "whois.publicinterestregistry.org",
    "io": "whois.nic.io", "me": "whois.nic.me", "ai": "whois.nic.ai",
    "biz": "whois.nic.biz", "club": "whois.nic.club", "tv": "whois.nic.tv", "vip": "whois.nic.vip",
    "online": "whois.nic.online", "site": "whois.nic.site", "store": "whois.nic.store",
    "tech": "whois.nic.tech", "space": "whois.nic.space", "website": "whois.nic.website",
    "fun": "whois.nic.fun", "xyz": "whois.nic.xyz", "top": "whois.nic.top",
    "ws": "whois.website.ws", "blog": "whois.nic.blog",
    "ua": "whois.ua", "by": "whois.cctld.by", "kz": "whois.nic.kz", "uz": "whois.cctld.uz",
    "am": "whois.amnic.net", "ge": "whois.nic.ge", "md": "whois.nic.md", "kg": "whois.kg",
    "de": "whois.denic.de", "eu": "whois.eu", "pl": "whois.dns.pl", "lv": "whois.nic.lv",
    "lt": "whois.domreg.lt", "ee": "whois.tld.ee", "fi": "whois.fi", "se": "whois.iis.se",
    "no": "whois.norid.no", "dk": "whois.punktum.dk", "cz": "whois.nic.cz", "sk": "whois.sk-nic.sk",
    "it": "whois.nic.it", "fr": "whois.nic.fr", "nl": "whois.domain-registry.nl", "ch": "whois.nic.ch",
    "tr": "whois.trabis.gov.tr", "be": "whois.dns.be", "at": "whois.nic.at",
}

# Зоны, где whois по 43 порту не отвечает или пуст без белого списка IP (например, .es).
WHOIS_BLACKLIST_TLDS = frozenset({"es"})

# Порядок проверки: QUOTA → FREE → TAKEN → нераспознано (ошибка).
# Все паттерны — по строкам (re.M), регистр не важен.
_QUOTA_PATTERNS = [
    r"^\s*%*\s*(?:error:?\s*)?(?:query\s+)?rate\s*limit(?:s)?\s+exceeded",
    r"^\s*%*\s*(?:error:?\s*)?(?:lookup\s+)?quota\s+exceeded",
    r"^\s*%*\s*(?:error:?\s*)?too\s+many\s+(?:requests|queries)",
    r"^\s*%*\s*whois\s+limit\s+exceeded",
    r"^\s*%*\s*(?:error:?\s*)?(?:you\s+have\s+)?exceeded\s+(?:the\s+)?(?:maximum|allowed|query)",
    r"^\s*%*\s*(?:error:?\s*)?maximum\s+(?:query|request)\s+rate",
    r"^\s*%*\s*(?:error:?\s*)?(?:your\s+)?(?:ip(?:\s+address)?|access|connection|client|host)\s+(?:has\s+been\s+|is\s+|was\s+)?(?:blocked|blacklisted|banned|denied)\b",
    r"^\s*%*\s*access\s+denied",
    r"^\s*%*\s*requests\s+of\s+this\s+client\s+are\s+not\s+permitted",
    r"^\s*%*\s*excessive\s+querying",
    r"^\s*%*\s*ratelimit\s+exceeded",
]
_FREE_PATTERNS = [
    r"^No entries found for the selected source",                    # TCI (.ru/.su/.рф), Punktum (.dk)
    r"^%+\s*No entries found\b",                                     # .ua, .cz
    r"^No entries found\b",                                          # .md
    r"^%*\s*No match for\b",                                         # Verisign, .name, .ge, .br
    r"^%*\s*No match\s*$",                                           # .am, .no
    r"^%+\s*nothing found",                                          # .at
    r"^%+\s*NOT FOUND",                                              # .fr
    r"^\s*NOT FOUND\s*$",
    r"^\s*Domain not found\.?\s*$",                                  # Identity Digital, .ee, .fi, .sk, .moscow
    r"^No Data Found\s*$",                                           # GoDaddy Registry (.biz/.club/.tv/.vip)
    r"^Not found:\s",                                                # .blog
    r"^Status:\s*(?:free|available)\s*$",                            # .de, .lv, .eu, .be, .it, .lt
    r"is available for registration",                                # Radix (.online/.site/…), .kg
    r"^The queried object does not exist",                           # .xyz, .top, .ws
    r"^object does not exist",                                       # .by
    r"^We do not have an entry in our database matching your query", # .ch
    r"^No information available about domain name",                  # .pl
    r"^\S+ is free\s*$",                                             # .nl
    r"^\*\*\* Nothing found",                                        # .kz
    r'^domain "[^"]+" not found\.',                                  # .se
    r"^No match found for\b",                                        # .tr
    r'^Sorry, but domain: "[^"]+", not found in database',           # .uz
    r"^Data not found\.",                                            # .kg
    r"^No Object Found\b",
    r"^%*\s*No such domain\b",                                       # .lu
    r"^Domain Status:\s*No Object Found",
    r"^%ERROR:101: no entries found",                                # .cz
]
_TAKEN_PATTERNS = [
    r"^[\s*]*Domain\s+Name\s*[.:]",                                  # Verisign, .kz, .by, .nl, .md, .no, .tr («** Domain Name:»)
    r"^\s*domain[\s.]*:\s*\S",                                       # TCI, .ua, .at, .cz, .se, .de, .dk, .eu, .fi («domain....: x»)
    r"^\s*Domain name:\s*$",                                         # .ch (имя на следующей строке)
    r"^\s*Domain\s+\S+\s+\((?:ACTIVE|REGISTERED|OK|EXPIRED|SUSPENDED|HOLD)",  # .kg
    r"^Domain Information\s*$",                                      # .no
    r"^\s*state:\s*(?:REGISTERED|active)\b",                         # TCI, .se
]
_QUOTA_RE = [re.compile(p, re.I | re.M) for p in _QUOTA_PATTERNS]
_FREE_RE = [re.compile(p, re.I | re.M) for p in _FREE_PATTERNS]
_TAKEN_RE = [re.compile(p, re.I | re.M) for p in _TAKEN_PATTERNS]


def classify_whois(text: str) -> str:
    """'free' | 'taken' | 'quota' | 'unknown' — по сырому тексту ответа whois."""
    if not text or not text.strip():
        return "unknown"
    for rx in _QUOTA_RE:
        if rx.search(text):
            return "quota"
    for rx in _FREE_RE:
        if rx.search(text):
            return "free"
    for rx in _TAKEN_RE:
        if rx.search(text):
            return "taken"
    return "unknown"


def whois_raw(server: str, query: str, timeout: float = WHOIS_TIMEOUT) -> str:
    """Один запрос по протоколу whois (RFC 3912). Бросает OSError/socket.timeout."""
    _gate.wait(server, WHOIS_MIN_INTERVAL)
    with _upstream_sem:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall(query.encode("ascii", "strict") + b"\r\n")
            chunks: list[bytes] = []
            total = 0
            while True:
                b = s.recv(8192)
                if not b:
                    break
                chunks.append(b)
                total += len(b)
                if total >= MAX_RESPONSE_BYTES:
                    break
    return b"".join(chunks).decode("utf-8", "replace")


class IanaWhoisIndex:
    """TLD → whois-сервер из whois.iana.org, с кэшем (в т.ч. отрицательным)."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._lock = threading.Lock()

    def server_for(self, tld: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(tld)
            if hit and hit[0] > now:
                return hit[1]
        server: str | None = None
        try:
            txt = whois_raw("whois.iana.org", tld)
            m = re.search(r"^whois:\s*(\S+)\s*$", txt, re.M)
            server = m.group(1).lower() if m else None
        except OSError as e:
            log.info("IANA whois для .%s: %s", tld, e)
            return None  # не кэшируем сетевые ошибки
        with self._lock:
            self._cache[tld] = (now + IANA_TTL, server)
        return server


iana_whois = IanaWhoisIndex()


def whois_server_for(tld: str) -> str | None:
    if tld in WHOIS_BLACKLIST_TLDS:
        return None
    return WHOIS_SERVERS.get(tld) or iana_whois.server_for(tld)


def _whois_lookup(ascii_domain: str, server: str) -> bool:
    try:
        text = whois_raw(server, ascii_domain)
    except (socket.timeout, TimeoutError):
        raise UpstreamError(ERR_TIMEOUT)
    except OSError as e:
        log.info("whois %s @ %s: %s", ascii_domain, server, e)
        raise UpstreamError(ERR_UPSTREAM)
    verdict = classify_whois(text)
    if verdict == "free":
        return False
    if verdict == "taken":
        return True
    if verdict == "quota":
        raise UpstreamError(ERR_QUOTA)
    log.warning("whois %s @ %s: нераспознанный ответ (%d байт): %r", ascii_domain, server, len(text), text[:200])
    raise UpstreamError(ERR_UNPARSED)


# ---------------------------------------------------------------------------
# Публичный API модуля
# ---------------------------------------------------------------------------

def _result(display: str, ascii_domain: str | None, free: bool, error: str | None, source: str | None) -> dict:
    return {"domain": display, "ascii": ascii_domain, "free": free, "error": error, "source": source}


def check_domain(raw: str, use_cache: bool = True) -> dict:
    """Проверить один домен. Никогда не бросает исключений."""
    try:
        ascii_domain, display = normalize_domain(raw)
    except InvalidDomain as e:
        return _result((raw or "").strip()[:253], None, False, str(e), None)

    if use_cache:
        cached = _cache.get(ascii_domain)
        if cached is not None:
            return dict(cached)

    tld = ascii_domain.rsplit(".", 1)[1]
    res: dict | None = None
    errors: list[str] = []

    rdap_urls = rdap_bootstrap.urls_for(tld)
    if rdap_urls:
        try:
            res = _result(display, ascii_domain, not _rdap_lookup(ascii_domain, rdap_urls), None, "rdap")
        except UpstreamError as e:
            errors.append(str(e))

    if res is None:
        server = whois_server_for(tld)
        if server:
            try:
                res = _result(display, ascii_domain, not _whois_lookup(ascii_domain, server), None, "whois")
            except UpstreamError as e:
                errors.append(str(e))

    if res is None:
        res = _result(display, ascii_domain, False, errors[0] if errors else ERR_UNSUPPORTED, None)

    if use_cache and res["error"] is None:
        _cache.set(ascii_domain, res)
    return dict(res)


def supported_tlds() -> list[str]:
    """Зоны, для которых источник известен без обращения к IANA (RDAP-снимок + таблица whois)."""
    with rdap_bootstrap._lock:
        s = set(rdap_bootstrap._index)
    s.update(WHOIS_SERVERS)
    s.difference_update(WHOIS_BLACKLIST_TLDS)
    return sorted(s)


def start_bootstrap_refresher(interval: float = 24 * 3600) -> threading.Thread:
    """Фоновое обновление RDAP-bootstrap с IANA (сразу и затем раз в interval секунд)."""
    def loop() -> None:
        while True:
            rdap_bootstrap.refresh_from_iana()
            time.sleep(interval)
    t = threading.Thread(target=loop, name="rdap-bootstrap-refresh", daemon=True)
    t.start()
    return t
