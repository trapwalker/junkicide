"""Smoke-тест интерфейса: живые сканеры процессов/системы + искусственные находки, без реальных действий."""

from pathlib import Path

from wtf.config import Config
from wtf.journal import Journal
from wtf.model import Action, ActionKind, Finding, Resource, Risk
from wtf.scanners.processes import ProcessScanner
from wtf.scanners.system import SystemScanner
from wtf.tui.app import WtfApp
from wtf.tui.screens import ActionMenu, Confirm, Help


def make_app(tmp_path: Path) -> WtfApp:
    cfg = Config(path=tmp_path / "config.toml")
    app = WtfApp(cfg, Journal(tmp_path / "j.jsonl"), [SystemScanner(), ProcessScanner()])
    long_title = "Очень длинное имя файла с [квадратными скобками] " * 4
    app.store.upsert([
        Finding("t:1", "test", Resource.DISK, long_title, location="/tmp/nonexistent", bytes=5 * 1024**3,
                risk=Risk.SAFE, confidence=0.9, what="что", origin="откуда", danger="чем грозит",
                facts=[("Путь", "/tmp/a\n/tmp/b")],
                actions=[Action(ActionKind.TRASH, "В Корзину", paths=["/tmp/wtf-nonexistent"])],
                paths=["/tmp/wtf-nonexistent"]),
    ])
    return app


async def test_tui_smoke(tmp_path, monkeypatch):
    monkeypatch.setattr("wtf.cache.save", lambda *a, **k: None)
    monkeypatch.setattr("wtf.cache.load", lambda *a, **k: [])
    for size in [(160, 45), (80, 30)]:
        app = make_app(tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause(2.5)
            table = app.query_one("#table")
            assert table.row_count >= 1
            assert "t:1" in app.row_ids
            app.query_one("#table").move_cursor(row=app.row_ids.index("t:1"))
            await pilot.pause(0.2)
            await pilot.press("a")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ActionMenu)
            await pilot.press("escape")
            await pilot.press("d")
            await pilot.pause(0.2)
            assert isinstance(app.screen, Confirm)
            await pilot.press("escape")
            for key in "2345":
                await pilot.press(key)
                await pilot.pause(0.3)
            await pilot.press("1")
            await pilot.press("slash")
            await pilot.press(*"длинное")
            await pilot.pause(0.6)
            assert app.row_ids == ["t:1"]
            await pilot.press("escape")
            await pilot.press("question_mark")
            await pilot.pause(0.2)
            assert isinstance(app.screen, Help)
            await pilot.press("escape")
            await pilot.press("q")
