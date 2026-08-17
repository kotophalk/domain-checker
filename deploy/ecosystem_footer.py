#!/usr/bin/env python3
"""Единый футер экосистемы Делосвод — синхронизация из реестра хаба.

ВЕНДОРНАЯ КОПИЯ. Канонический исходник — репозиторий kotophalk/delosvod,
snippets/ecosystem_footer.py; тело одинаковое во всех инструментах, отличается
только блок CONFIG. Логику править там и раскатывать копии, здесь — только CONFIG.

Режимы:
  python3 deploy/ecosystem_footer.py sync   # REST хаба → deploy/ecosystem-tools.json,
                                            # рендер между маркерами в файлах CONFIG["files"]
  python3 deploy/ecosystem_footer.py check  # рендер из снапшота == содержимое файлов
                                            # (без сети; это же вызывает тест)
  python3 deploy/ecosystem_footer.py render # напечатать HTML из снапшота

Маркеры в HTML (ровно один раз на файл):
  <!-- ecosystem-footer:start --> … <!-- ecosystem-footer:end -->

Стили рендера:
  list   — <li> для nav.other-tools (Словостат, Свободомен, Доменомер);
           бесплатные инструменты первыми, платные — последними, внутри — порядок реестра.
  inline — одна строка для .lp-footer-eco (Словоправ): «X — проект лаборатории
           Делосвод. Другие инструменты: A · B · C · все инструменты →», с Umami-атрибутами.

Только stdlib (Python ≥ 3.9). Ошибка сети в sync — понятное сообщение и exit 2;
check никогда не ходит в сеть.
"""
import html
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIG — единственное, что отличается между репозиториями.
# ---------------------------------------------------------------------------
CONFIG = {
    "self": "svobodomen",
    "style": "list",
    "files": [
        "static/index.html",
    ],
    "snapshot": "deploy/ecosystem-tools.json",
    "target_blank": False,
    "utm": {"utm_medium": "footer", "utm_campaign": "ecosystem"},  # utm_source = self
}
# ---------------------------------------------------------------------------

REGISTRY_URL = (
    "https://delosvod.ru/wp-json/delosvod/v1/tools"
    "?kind=tool&status=release&fields=id,name,tagline,url,pricing,order"
)
START = "<!-- ecosystem-footer:start -->"
END = "<!-- ecosystem-footer:end -->"
ROOT = Path(__file__).resolve().parents[1]


def _utm(url: str, content: str) -> str:
    """URL с UTM-метками; & экранирован для HTML-атрибута."""
    params = {"utm_source": CONFIG["self"], **CONFIG["utm"], "utm_content": content}
    if not urllib.parse.urlsplit(url).path:
        url += "/"  # в реестре url без пути → https://host/?utm…, а не https://host?utm…
    sep = "&" if "?" in url else "?"
    return html.escape(url + sep + urllib.parse.urlencode(params), quote=True)


def fetch() -> dict:
    req = urllib.request.Request(REGISTRY_URL, headers={"User-Agent": f"ecosystem-footer/{CONFIG['self']}"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 — фиксированный https-URL
        data = json.load(resp)
    tools = sorted(data["tools"], key=lambda t: (t.get("pricing") == "paid", t.get("order", 100)))
    return {
        "updated": data.get("updated"),
        "hub": {"name": data["hub"]["name"], "url": data["hub"]["url"].rstrip("/")},
        "tools": [
            {k: t.get(k) for k in ("id", "name", "tagline", "url", "pricing", "order")}
            for t in tools
        ],
    }


def load_snapshot() -> dict:
    return json.loads((ROOT / CONFIG["snapshot"]).read_text(encoding="utf-8"))


def save_snapshot(data: dict) -> None:
    path = ROOT / CONFIG["snapshot"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _others(data: dict) -> list:
    return [t for t in data["tools"] if t["id"] != CONFIG["self"] and t.get("url")]


def render(data: dict) -> str:
    hub = data["hub"]
    if CONFIG["style"] == "list":
        tb = ' target="_blank" rel="noopener"' if CONFIG["target_blank"] else ""
        items = [
            f'<li><a href="{_utm(t["url"], t["id"])}"{tb}>'
            f'<span class="tool-name">{html.escape(t["name"])}</span>'
            f'<span class="tool-desc">{html.escape(t["tagline"])}</span></a></li>'
            for t in _others(data)
        ]
        return "\n      " + "\n      ".join(items) + "\n      "

    if CONFIG["style"] == "inline":
        me = next((t["name"] for t in data["tools"] if t["id"] == CONFIG["self"]), CONFIG["self"])

        def a(url, content, text):
            return (
                f'<a href="{_utm(url, content)}" rel="noopener" data-umami-event="ecosystem-click" '
                f'data-umami-event-tool="{html.escape(content)}">{html.escape(text)}</a>'
            )

        links = " · ".join(a(t["url"], t["id"], t["name"]) for t in _others(data))
        return (
            f"{html.escape(me)} — проект лаборатории {a(hub['url'] + '/', 'delosvod', hub['name'])}. "
            f"Другие инструменты: {links} · {a(hub['url'] + '/tools/', 'all', 'все инструменты →')}"
        )

    raise SystemExit(f"неизвестный style: {CONFIG['style']}")


def _split(text: str, path: Path):
    s = text.count(START)
    e = text.count(END)
    if s != 1 or e != 1:
        raise SystemExit(f"{path}: маркеры должны встречаться ровно по разу (start={s}, end={e})")
    i = text.index(START) + len(START)
    j = text.index(END)
    if j < i:
        raise SystemExit(f"{path}: маркер end раньше start")
    return text[:i], text[i:j], text[j:]


def apply(rendered: str) -> list:
    changed = []
    for rel in CONFIG["files"]:
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        head, current, tail = _split(text, path)
        if current != rendered:
            path.write_text(head + rendered + tail, encoding="utf-8")
            changed.append(rel)
    return changed


def check() -> list:
    """Список файлов, где содержимое между маркерами != рендеру из снапшота."""
    rendered = render(load_snapshot())
    drift = []
    for rel in CONFIG["files"]:
        path = ROOT / rel
        _, current, _ = _split(path.read_text(encoding="utf-8"), path)
        if current != rendered:
            drift.append(rel)
    return drift


def main(argv: list) -> int:
    mode = argv[1] if len(argv) > 1 else "check"
    if mode == "sync":
        try:
            data = fetch()
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            print(f"не удалось получить реестр {REGISTRY_URL}: {exc}", file=sys.stderr)
            return 2
        save_snapshot(data)
        changed = apply(render(data))
        print(f"реестр от {data['updated']}: {len(_others(data))} инструментов; "
              f"обновлено файлов: {len(changed)}" + (f" ({', '.join(changed)})" if changed else ""))
        return 0
    if mode == "check":
        drift = check()
        if drift:
            print("футер расходится со снапшотом (запустите sync): " + ", ".join(drift), file=sys.stderr)
            return 1
        print("футер синхронен со снапшотом")
        return 0
    if mode == "render":
        print(render(load_snapshot()))
        return 0
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
