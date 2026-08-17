# CLAUDE.md

Этот файл содержит инструкции для Claude Code (claude.ai/code) по работе с кодом в этом репозитории.

## Команды

Запуск сервера (каталог запуска не важен — статика и `data/` берутся относительно `app.py`):

```bash
python3 app.py
```

Тесты (офлайн, сеть не нужна, ~1 с):

```bash
python3 -m unittest discover -s tests
```

Один тест:

```bash
python3 -m unittest tests.test_checker.NormalizeTests.test_idn -v
```

Живые тесты против реальных регистратур (TCI, Verisign, RDAP gTLD, IANA-discovery), ~20 с:

```bash
LIVE_TESTS=1 python3 -m unittest tests.test_live -v
```

Прямой запрос к API:

```bash
curl 'http://localhost:8080/api/check?domains=example.ru,пример.рф,test.com'
```

Docker: `docker build -t domain-checker . && docker run -p 8080:8080 domain-checker`. Прод: `docker compose up -d --build` (порт `127.0.0.1:8002`, `.env` из `.env.example`).

Зависимостей нет вообще — только stdlib Python 3.10+. Сборки и линтера нет. Все настройки — переменные окружения (таблица в README).

## Прод

Публичный адрес — **https://svobodomen.ru** (бренд «Свободомен», хаб экосистемы — delosvod.ru; с 16.08.2026 канон на бренд-домене, а www, старый поддомен svobodomen.delosvod.ru и свободомен.рф — 301 на него; все имена в одном `deploy/domain-checker.caddy`). VPS `lulu` (135.106.185.112, ssh-алиас `lulu`, пользователь `deploy`), каталог `/opt/domain-checker`, контейнер на `127.0.0.1:8002` за Caddy хоста (`/etc/caddy/conf.d/domain-checker.caddy` из `deploy/`). Соседи на той же машине: slovostat (8000, docker) и itogoskaz (8001, systemd) — их не трогать; общий `/etc/caddy/Caddyfile` приходит из репозитория slovostat, свои блоки — только в `conf.d/`. Обновление — `deploy/update.sh` (руками или из GitHub Actions `деплой` после зелёных `тесты` на `main`). Валидацию Caddy запускать как `sudo -u caddy caddy validate …`, иначе логи создаются от root и reload падает.

## Архитектура

- `checker.py` — ядро, не знает про HTTP. Публичный вход `check_domain(raw) -> dict`, никогда не бросает исключений.
- `app.py` — `ThreadingHTTPServer` + наследник `SimpleHTTPRequestHandler`: маршрутизация, лимиты, JSON-ошибки, статика.
- `static/index.html` — весь фронтенд (инлайновые CSS + ванильный JS).
- `static/privacy.html` — политика конфиденциальности, отдаётся по `/privacy`; ссылка в футере главной. Cookie-уведомление (`#cookie-notice`, cookie `nc_accepted` на 30 дней, как в «Крошке моей») живёт внутри блока Метрики — без счётчика сервис cookie не ставит.
- `data/rdap_dns.json` — снимок RDAP-bootstrap IANA (TLD → базовые URL RDAP). Загружается при импорте; при `RDAP_BOOTSTRAP_REFRESH=1` (по умолчанию) фоновый поток обновляет его с `data.iana.org` при старте и раз в сутки. Обновлять снимок в репозитории: скачать `https://data.iana.org/rdap/dns.json` и положить как есть.
- `tests/fixtures/whois/<tld>/{free,taken}.txt` — реальные ответы whois-серверов, записанные 2026-08-15. Это контракт паттернов: `test_checker.ClassifyWhoisFixturesTests` гоняет `classify_whois` по всем файлам.

### Порядок источников в `check_domain`

1. `normalize_domain` — срез схемы/пути/порта/`www.`/завершающей точки, IDN → punycode, проверка меток. Допускаются только домены второго уровня и `имя.<суффикс>` из `SECOND_LEVEL_SUFFIXES` (co.uk, com.ua…). Всё остальное — `InvalidDomain` с русским сообщением. Это не педантизм: TCI отвечает «No entries found» на `www2.yandex.ru` и на `WWW.YANDEX.RU`, то есть без этой проверки поддомены и `www.` давали бы ложное «Свободен».
2. RDAP, если TLD есть в bootstrap: `GET <base>/domain/<ascii>` → `404` = свободен, `200` с `objectClassName: domain` = занят, `429` = `ERR_QUOTA`, прочее = ошибка. Тело `404` не читается (Verisign рвёт TLS на чтении). Одна повторная попытка на сетевые сбои, затем следующий базовый URL.
3. Иначе whois по порту 43: сервер из `WHOIS_SERVERS` (верифицированная таблица), иначе через `whois.iana.org` (кэш 24 ч, в т.ч. отрицательный). Ответ классифицирует `classify_whois`: **QUOTA → FREE → TAKEN → unknown**. Порядок важен: DENIC/EURid/.it/.lt/.be печатают `Domain: x` и для свободных доменов, поэтому free-паттерны проверяются раньше taken-паттернов. `unknown` и `quota` — это ошибка, никогда не «свободен».
4. Если RDAP упал, а whois-сервер есть — идём в whois; если ни того ни другого — `ERR_UNSUPPORTED` либо первая ошибка RDAP.

`WHOIS_BLACKLIST_TLDS` (`.es`) — зоны, где whois отдаёт пустой ответ без белого списка IP; они не идут ни в таблицу, ни в IANA-discovery.

### Лимиты и защита (все в `app.py`/`checker.py`, настраиваются env)

- `MAX_DOMAINS` на запрос → `400` JSON с `max_domains`. Фронтенд читает `/api/limits` и режет ввод на батчи этого размера, выводя результаты прогрессивно.
- `RateLimiter` — token bucket на IP (`RATE_LIMIT_PER_MIN`/`RATE_LIMIT_BURST`), стоимость запроса = число доменов → `429` JSON + `Retry-After`. IP из `X-Forwarded-For` только при `TRUST_PROXY=1`.
- `HostGate` в `checker.py` — минимальный интервал между запросами к одному whois-/RDAP-хосту, общий для всех потоков (`WHOIS_MIN_INTERVAL`=0.5 с — TCI банит за частые запросы). Плюс `UPSTREAM_CONCURRENCY` (семафор на все исходящие) и `CHECK_WORKERS` (пул проверок на весь сервер). Меняя одно, помните про другие: пул больше семафора просто ждёт; интервал меньше 0.5 к TCI — риск бана IP.
- `TTLCache` — кэшируются только успешные результаты (`error is None`), `CACHE_TTL`=60 с. Ошибки не кэшируются намеренно.
- Статика: только `/` и `/static/<файл>` из каталога `static/` рядом со скриптом; листинг запрещён; `/app.py`, `/data/...` и traversal → 404. `HEAD` идёт через `super().do_HEAD()` — иначе базовый класс отдаст тело.
- `index.html` (по `/` и `/static/index.html`) отдаётся своим `send_index`, а не `SimpleHTTPRequestHandler`: блок Метрики между `<!-- metrika:start -->…<!-- metrika:end -->` с плейсхолдером `__METRIKA_ID__` либо получает номер из `METRIKA_ID`, либо вырезается целиком (`render_index`). Пустая переменная — ни одного внешнего запроса.

### Контракт API

`GET /api/check?domains=a,b,c` → JSON-массив в порядке ввода (дубли схлопываются без учёта регистра), элемент:

```json
{"domain": "пример.рф", "ascii": "xn--e1afmkfd.xn--p1ai", "free": true, "error": null, "source": "whois"}
```

`free` — `true` только при явном подтверждении; при `error` всегда `false`. Фронтенд смотрит `error` (жёлтый) → `free` (зелёный) → занят (красный) и `response.ok` (400/429 показываются баннером с текстом сервера). Меняя форму ответа, сохраняйте все пять полей.

Ошибки уровня запроса всегда JSON `{"error": "..."}`. Служебные: `/api/limits`, `/api/tlds`, `/healthz`.

## Соглашения

- Пользовательские строки (UI, значения `error`, `{"error": ...}` уровня запроса) — на русском; константы `ERR_*` в `checker.py`. Новый видимый текст — тоже по-русски.
- Добавляя зону в `WHOIS_SERVERS`, записывайте реальные ответы (свободный + занятый) в `tests/fixtures/whois/<tld>/` — иначе паттерны не верифицированы. Скрипт-сборщик не хранится в репозитории: достаточно `checker.whois_raw(server, domain)`.
- Тесты не должны ходить в сеть: в `test_checker` мокайте `checker._rdap_lookup`/`whois_server_for`/`whois_raw`, в `test_app` подменяйте `app.check_domain`. Живое — только в `test_live.py` под `LIVE_TESTS=1`.
- Стиль ответа сервиса: «не знаю» лучше, чем догадка. Если новый источник данных даёт неоднозначный ответ — возвращайте ошибку, а не `free`.
