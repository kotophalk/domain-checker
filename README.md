# Свободомен (domain-checker)

**https://svobodomen.ru** — бесплатный сервис для быстрой массовой проверки доступности доменов: `.ru`, `.рф`, `.su`, `.com`, `.net`, `.org`, `.info`, `.app`, `.online` и **более 1200 зон**. Списком, без регистрации. Инструмент экосистемы [Делосвод](https://delosvod.ru/).

## Особенности

* **Честный ответ.** «Свободен» — только когда регистратура явно это сказала (RDAP `404` или распознанный ответ whois). Ошибка сети, лимит регистратуры или нераспознанный ответ никогда не отображаются как «Свободен» или «Занят» — они показываются как ошибка с пояснением.
* **RDAP + whois.** Для зон с RDAP (все gTLD и ряд ccTLD — по bootstrap-файлу IANA) используется RDAP; для `.ru/.рф/.su` и других ccTLD — whois по порту 43 с паттернами, верифицированными на реальных ответах регистратур (`tests/fixtures/whois/`). Для прочих зон whois-сервер ищется через `whois.iana.org`.
* **Готов к публичной нагрузке.** Многопоточный сервер, лимит доменов на запрос, лимит на IP, интервалы между запросами к каждому регистратору, короткий кэш результатов, таймауты, валидация ввода (IDN → punycode, срез `https://`, `www.`, путей).
* **Ноль зависимостей.** Только стандартная библиотека Python 3.10+; ни `whois`-бинарник, ни pip-пакеты не нужны. Один `Dockerfile`.

## Запуск

```bash
python3 app.py
```

Откройте `http://localhost:8080`. Каталог запуска не важен — статика берётся из `static/` рядом со скриптом.

Через Docker:

```bash
docker build -t domain-checker .
docker run -d --name domain-checker -p 8080:8080 --restart unless-stopped domain-checker
```

Для публичного размещения ставьте перед сервисом reverse-proxy с TLS (nginx/Caddy) и включайте `TRUST_PROXY=1`, чтобы лимит на IP считался по реальному адресу клиента. Готовая схема для VPS — в разделе «Деплой».

## API

`GET /api/check?domains=example.ru,пример.рф,test.com` — до `MAX_DOMAINS` доменов через запятую (или `\n`, `;`). Ответ — JSON-массив в порядке ввода:

```json
[
  {"domain": "example.ru", "ascii": "example.ru", "free": false, "error": null, "source": "whois"},
  {"domain": "пример.рф", "ascii": "xn--e1afmkfd.xn--p1ai", "free": true, "error": null, "source": "whois"},
  {"domain": "abcd", "ascii": null, "free": false, "error": "Некорректный домен", "source": null}
]
```

* `free` — `true` только при явном подтверждении регистратуры; при `error` всегда `false`.
* `error` — `null` или человекочитаемое сообщение (по-русски): некорректный домен, поддомен, неподдерживаемая зона, регистратура не отвечает / ограничила запросы / ответ не распознан.
* `source` — `rdap` | `whois` | `null`.

Ошибки уровня запроса — JSON-объект `{"error": "..."}`: `400` (нет доменов / больше лимита, поле `max_domains`), `429` (лимит на IP, поле `retry_after` и заголовок `Retry-After`), `503` (перегрузка).

Служебные: `GET /api/limits` → `{"max_domains", "rate_limit_per_min"}`; `GET /api/tlds` → список зон, для которых источник известен заранее; `GET /healthz`.

## Настройки (переменные окружения)

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `HOST`, `PORT` | `0.0.0.0`, `8080` | адрес и порт |
| `MAX_DOMAINS` | `20` | доменов в одном запросе |
| `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_BURST` | `60`, `60` | проверок домена в минуту на IP и размер «ведра» (`0` — выключить лимит) |
| `TRUST_PROXY` | `0` | `1` — брать IP клиента из `X-Forwarded-For` / `X-Real-IP` |
| `CORS_ALLOW_ORIGIN` | пусто | `*` или список origin через запятую — разрешить вызовы API с других сайтов |
| `METRIKA_ID` | пусто | Номер счётчика Яндекс.Метрики; пусто — сниппет из `index.html` вырезается |
| `CHECK_WORKERS` | `16` | одновременных проверок доменов на весь сервер |
| `UPSTREAM_CONCURRENCY` | `8` | одновременных соединений с регистратурами |
| `WHOIS_MIN_INTERVAL`, `RDAP_MIN_INTERVAL` | `0.5`, `0.1` | пауза (сек) между запросами к одному whois-/RDAP-хосту |
| `WHOIS_TIMEOUT`, `RDAP_TIMEOUT` | `10`, `10` | таймауты (сек) |
| `CACHE_TTL`, `CACHE_MAX` | `60`, `10000` | кэш успешных результатов, сек / записей (`0` — выключить) |
| `RDAP_BOOTSTRAP_REFRESH` | `1` | обновлять список RDAP-серверов с IANA при старте и раз в сутки (иначе — снимок `data/rdap_dns.json`) |
| `LOG_LEVEL` | `INFO` | уровень логирования |

## Деплой

Схема та же, что у соседних инструментов на том же VPS (подробно — в `docs/deploy.md` репозитория [slovostat](https://github.com/kotophalk/slovostat)): Caddy на хосте терминирует TLS, каждый инструмент — свой каталог в `/opt` со своим `docker-compose.yml` и портом на `127.0.0.1`.

```bash
sudo install -d -o deploy -g deploy /opt/domain-checker
git clone https://github.com/kotophalk/domain-checker.git /opt/domain-checker
cd /opt/domain-checker
cp .env.example .env          # порт 8002 и лимиты — при необходимости поправить
docker compose up -d --build
curl -s http://127.0.0.1:8002/healthz
```

Домен: [`deploy/domain-checker.caddy`](deploy/domain-checker.caddy) (`svobodomen.ru` → `127.0.0.1:8002`; www, `svobodomen.delosvod.ru` и `свободомен.рф` → 301 на `svobodomen.ru`) кладётся в `/etc/caddy/conf.d/`, затем `sudo -u caddy caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy`. Сертификат Caddy получит сам. Редиректы с бренд-доменов `svobodomen.ru` / `свободомен.рф` — [`deploy/svobodomen-redirects.caddy`](deploy/svobodomen-redirects.caddy), ставится отдельно, когда их A-записи укажут на сервер.

Обновление: `/opt/domain-checker/deploy/update.sh` (подтягивает `origin/main`, пересобирает, ждёт `/healthz`). Автодеплой: GitHub Actions после зелёных тестов на `main` запускает тот же скрипт по SSH-ключу с forced command; секреты `DEPLOY_SSH_KEY`, `DEPLOY_HOST`, `DEPLOY_KNOWN_HOSTS` — как у slovostat.

## Тесты

```bash
python3 -m unittest discover -s tests
```

Офлайн (сеть не нужна): нормализация, классификация записанных ответов всех регистратур, RDAP-клиент с моками, HTTP-контракт. Живые проверки против реальных регистратур:

```bash
LIVE_TESTS=1 python3 -m unittest tests.test_live -v
```

## Структура

* `app.py` — HTTP-сервер (API, статика, лимиты).
* `checker.py` — ядро: нормализация, RDAP, whois, паттерны, лимитеры, кэш.
* `data/rdap_dns.json` — снимок RDAP-bootstrap IANA.
* `static/index.html` — фронтенд (ванильный JS/CSS, без сборки).
* `tests/` — тесты и фикстуры реальных whois-ответов.

## Лицензия

MIT License
