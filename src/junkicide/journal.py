"""Журнал: всё, что сделано пользователем и что случилось при сканировании. JSONL, по строке на событие."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .util import HOME

LOG_DIR = HOME / "Library" / "Logs" / "junkicide"
LOG_FILE = LOG_DIR / "journal.jsonl"

LEVELS = ("debug", "info", "action", "warn", "error")


@dataclass
class Entry:
    ts: float
    level: str
    event: str
    msg: str
    data: dict

    @property
    def text(self) -> str:
        return f"{self.level} {self.event} {self.msg} {json.dumps(self.data, ensure_ascii=False)}".lower()


class Journal:
    def __init__(self, path: Path = LOG_FILE, keep_in_memory: int = 5000) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.entries: list[Entry] = []
        self.keep = keep_in_memory
        self.version = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self._load_tail()

    def _load_tail(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-500:]
        except OSError:
            return
        for line in lines:
            try:
                d = json.loads(line)
                self.entries.append(Entry(d["ts"], d["level"], d["event"], d["msg"], d.get("data", {})))
            except (ValueError, KeyError):
                continue

    def log(self, level: str, event: str, msg: str, **data) -> Entry:
        e = Entry(time.time(), level, event, msg, data)
        with self._lock:
            self.entries.append(e)
            if len(self.entries) > self.keep:
                del self.entries[: len(self.entries) - self.keep]
            self.version += 1
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(e.__dict__, ensure_ascii=False, default=str) + "\n")
            except OSError:
                pass
        return e

    def info(self, event: str, msg: str, **data) -> Entry:
        return self.log("info", event, msg, **data)

    def warn(self, event: str, msg: str, **data) -> Entry:
        return self.log("warn", event, msg, **data)

    def error(self, event: str, msg: str, **data) -> Entry:
        return self.log("error", event, msg, **data)

    def action(self, event: str, msg: str, **data) -> Entry:
        return self.log("action", event, msg, **data)

    def snapshot(self) -> list[Entry]:
        with self._lock:
            return list(self.entries)
