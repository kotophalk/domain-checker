"""Футер «Другие инструменты» сгенерирован из снапшота реестра хаба.

Источник правды — реестр Делосвода (delosvod.ru/wp-json/delosvod/v1/tools).
`deploy/ecosystem_footer.py sync` кладёт снапшот в deploy/ecosystem-tools.json и
рендерит HTML между маркерами; этот тест (без сети) ловит ручные правки футера
мимо скрипта. Если реестр изменился — запустить sync и закоммитить оба файла.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("ecosystem_footer", ROOT / "deploy" / "ecosystem_footer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EcosystemFooterTests(unittest.TestCase):
    def test_footer_matches_registry_snapshot(self):
        mod = _load()
        self.assertEqual(mod.check(), [], "футер разошёлся со снапшотом — python3 deploy/ecosystem_footer.py sync")

    def test_snapshot_has_hub_and_others(self):
        mod = _load()
        data = mod.load_snapshot()
        self.assertEqual(data["hub"]["url"], "https://delosvod.ru")
        self.assertGreaterEqual(len(mod._others(data)), 3)
        self.assertNotIn(mod.CONFIG["self"], [t["id"] for t in mod._others(data)])
