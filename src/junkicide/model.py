"""Модель находок: что нашли, насколько это вероятно не нужно, чем грозит устранение и как устранить."""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any


class Resource(enum.StrEnum):
    CPU = "cpu"
    MEMORY = "mem"
    DISK = "disk"
    INFO = "info"


class Risk(enum.IntEnum):
    """Риск устранения находки (не самой находки)."""

    SAFE = 0  # мусор/кэш, пересоздастся сам и быстро
    REBUILDABLE = 1  # пересоздастся, но придётся ждать/качать
    CAUTION = 2  # может оказаться нужным — посмотрите сами
    PERSONAL = 3  # личные данные, вернуть можно только из Корзины/бэкапа
    SYSTEM = 4  # системное — устранять не нужно/нельзя


RISK_META: dict[Risk, tuple[str, str, float]] = {
    # иконка, подпись, множитель в рейтинге
    Risk.SAFE: ("🟢", "безопасно", 1.0),
    Risk.REBUILDABLE: ("🔵", "пересоздаётся", 0.8),
    Risk.CAUTION: ("🟡", "осторожно", 0.5),
    Risk.PERSONAL: ("🔴", "личные данные", 0.3),
    Risk.SYSTEM: ("⚪", "системное", 0.05),
}

RESOURCE_ICON = {Resource.CPU: "🔥", Resource.MEMORY: "🧠", Resource.DISK: "💾", Resource.INFO: "ℹ️"}


class ActionKind(enum.StrEnum):
    KILL = "kill"  # SIGTERM → (по желанию) SIGKILL
    QUIT_APP = "quit_app"  # штатный выход GUI-приложения через AppleScript
    TRASH = "trash"  # переместить в Корзину
    COMMAND = "command"  # выполнить команду (очистка кэша, docker prune, …)
    EMPTY_TRASH = "empty_trash"
    REVEAL = "reveal"  # показать в Finder
    SHOW = "show"  # выполнить безопасную команду и показать вывод


@dataclass
class Action:
    kind: ActionKind
    label: str
    note: str = ""  # что именно произойдёт — показывается в подтверждении
    pids: list[tuple[int, float]] = field(default_factory=list)  # (pid, create_time) — защита от переиспользования pid
    paths: list[str] = field(default_factory=list)
    argv: list[str] = field(default_factory=list)
    cwd: str | None = None
    app_name: str | None = None
    destructive: bool = True
    force: bool = False  # для KILL: сразу SIGKILL

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Action:
        d = dict(d)
        d["kind"] = ActionKind(d["kind"])
        d["pids"] = [tuple(x) for x in d.get("pids", [])]
        return Action(**d)


@dataclass
class Finding:
    id: str
    scanner: str
    resource: Resource
    title: str
    location: str = ""  # путь или команда
    bytes: int = 0  # для диска — сколько освободится; для процессов — память
    cpu: float = 0.0  # % одного ядра, сглаженный
    risk: Risk = Risk.CAUTION
    confidence: float = 0.5  # насколько вероятно, что это не нужно (0..1)
    tags: list[str] = field(default_factory=list)
    what: str = ""  # что это такое
    origin: str = ""  # откуда взялось и почему
    danger: str = ""  # что будет, если устранить
    facts: list[tuple[str, str]] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)  # для ленивого обогащения (Spotlight) и игнора
    created: float | None = None
    modified: float | None = None
    last_used: float | None = None
    started: float | None = None  # для процессов
    found_at: float = field(default_factory=time.time)
    stale: bool = False  # загружено из кэша прошлого сканирования
    resolved: str | None = None  # что с находкой уже сделали
    pinned_score: float | None = None  # для служебных/инфо-находок

    @property
    def score(self) -> float:
        """Рейтинг «сколько ресурса освободим и насколько это безопасно»."""
        if self.pinned_score is not None:
            return self.pinned_score
        mult = RISK_META[self.risk][2]
        gb = self.bytes / 1024**3
        if self.resource == Resource.DISK:
            base = gb
        elif self.resource in (Resource.CPU, Resource.MEMORY):
            # 100% одного ядра ≈ 2 ГБ памяти ≈ 2 ГБ диска по «ценности» для пользователя
            base = gb * 1.5 + self.cpu / 100 * 2
        else:
            base = 0.0
        return base * mult * (0.3 + self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Finding:
        d = dict(d)
        d["resource"] = Resource(d["resource"])
        d["risk"] = Risk(d["risk"])
        d["facts"] = [tuple(x) for x in d.get("facts", [])]
        d["actions"] = [Action.from_dict(a) for a in d.get("actions", [])]
        return Finding(**d)


class FindingStore:
    """Потокобезопасное хранилище находок. UI опрашивает `version` и перерисовывается при изменении."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Finding] = {}
        self._run_seen: dict[str, set[str]] = {}
        self._ignored: set[str] = set()
        self.version = 0

    def set_ignored(self, ids: set[str]) -> None:
        with self._lock:
            self._ignored = set(ids)
            self.version += 1

    def is_ignored(self, f: Finding) -> bool:
        if f.id in self._ignored:
            return True
        return any(p in self._ignored for p in f.paths)

    def begin_run(self, scanner: str) -> None:
        with self._lock:
            self._run_seen[scanner] = set()

    def finish_run(self, scanner: str) -> None:
        """Убрать находки сканера, которые в этом проходе не подтвердились (кроме уже устранённых)."""
        with self._lock:
            seen = self._run_seen.pop(scanner, None)
            if seen is None:
                return
            for fid in [k for k, v in self._items.items() if v.scanner == scanner and k not in seen]:
                if not self._items[fid].resolved:
                    del self._items[fid]
            self.version += 1

    def upsert(self, findings: list[Finding]) -> None:
        with self._lock:
            for f in findings:
                old = self._items.get(f.id)
                if old is not None and old.resolved:
                    # устранённое остаётся в списке с пометкой до конца сессии
                    continue
                self._items[f.id] = f
                seen = self._run_seen.get(f.scanner)
                if seen is not None:
                    seen.add(f.id)
            self.version += 1

    def replace_scanner(self, scanner: str, findings: list[Finding]) -> None:
        with self._lock:
            for fid in [k for k, v in self._items.items() if v.scanner == scanner and not v.resolved]:
                del self._items[fid]
            seen = self._run_seen.get(scanner)
            for f in findings:
                old = self._items.get(f.id)
                if old is not None and old.resolved:
                    continue
                self._items[f.id] = f
                if seen is not None:
                    seen.add(f.id)
            self.version += 1

    def remove(self, ids: list[str]) -> None:
        with self._lock:
            changed = False
            for fid in ids:
                if self._items.pop(fid, None) is not None:
                    changed = True
            if changed:
                self.version += 1

    def get(self, fid: str) -> Finding | None:
        with self._lock:
            return self._items.get(fid)

    def mark_resolved(self, fid: str, text: str) -> None:
        with self._lock:
            f = self._items.get(fid)
            if f:
                f.resolved = text
                self.version += 1

    def snapshot(self) -> list[Finding]:
        with self._lock:
            return [f for f in self._items.values() if not self.is_ignored(f)]

    def by_scanner(self, scanner: str) -> list[Finding]:
        with self._lock:
            return [f for f in self._items.values() if f.scanner == scanner]
