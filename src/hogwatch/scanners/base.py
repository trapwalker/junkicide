"""Каркас сканеров: каждый работает в своём потоке, пишет находки в общее хранилище и свой статус."""

from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass

from ..config import Config
from ..journal import Journal
from ..model import FindingStore


@dataclass
class ScanStatus:
    title: str
    state: str = "ждёт"  # ждёт | идёт | готово | ошибка | остановлен
    message: str = ""
    started: float | None = None
    finished: float | None = None
    runs: int = 0

    @property
    def icon(self) -> str:
        return {"ждёт": "·", "идёт": "⟳", "готово": "✓", "ошибка": "✗", "остановлен": "■"}.get(self.state, "?")


class ScanContext:
    def __init__(self, store: FindingStore, journal: Journal, config: Config) -> None:
        self.store = store
        self.journal = journal
        self.config = config
        self.stop = threading.Event()
        self.status: dict[str, ScanStatus] = {}
        self.system: dict = {}  # сводка о системе (заполняет SystemScanner)

    def progress(self, scanner: str, message: str) -> None:
        st = self.status.get(scanner)
        if st:
            st.message = message


class Scanner:
    name = "base"
    title = "сканер"
    interval: float | None = None  # период повтора; None — однократно (повтор по запросу)
    delay: float = 0.0  # задержка первого запуска, чтобы быстрые сканеры успели первыми

    def run(self, ctx: ScanContext) -> None:  # pragma: no cover - интерфейс
        raise NotImplementedError


class Runner:
    """Запускает сканеры в фоновых потоках; повтор по интервалу или по запросу."""

    def __init__(self, ctx: ScanContext, scanners: list[Scanner]) -> None:
        self.ctx = ctx
        self.scanners = scanners
        self._wake: dict[str, threading.Event] = {s.name: threading.Event() for s in scanners}
        self._threads: list[threading.Thread] = []
        for s in scanners:
            ctx.status[s.name] = ScanStatus(s.title)

    def start(self) -> None:
        for s in self.scanners:
            t = threading.Thread(target=self._loop, args=(s,), name=f"scan-{s.name}", daemon=True)
            t.start()
            self._threads.append(t)

    def rescan(self, name: str | None = None) -> None:
        for s in self.scanners:
            if name is None or s.name == name:
                self._wake[s.name].set()

    def stop(self) -> None:
        self.ctx.stop.set()
        for ev in self._wake.values():
            ev.set()

    def _loop(self, s: Scanner) -> None:
        ctx = self.ctx
        st = ctx.status[s.name]
        if s.delay and ctx.stop.wait(s.delay):
            return
        while not ctx.stop.is_set():
            st.state, st.started, st.message = "идёт", time.time(), ""
            ctx.store.begin_run(s.name)
            try:
                s.run(ctx)
                ctx.store.finish_run(s.name)
                st.state = "готово"
                if st.runs == 0 and s.interval is None:
                    n = len(ctx.store.by_scanner(s.name))
                    ctx.journal.info("scan.done", f"{s.title}: {n} находок за {time.time() - st.started:.1f} с",
                                     scanner=s.name)
            except Exception as e:
                st.state, st.message = "ошибка", repr(e)
                ctx.journal.error("scan.error", f"{s.title}: {e!r}", scanner=s.name,
                                  trace=traceback.format_exc(limit=6))
            st.finished = time.time()
            st.runs += 1
            if ctx.stop.is_set():
                break
            ev = self._wake[s.name]
            if s.interval is None:
                ev.wait()
            else:
                ev.wait(s.interval)
            ev.clear()
        st.state = "остановлен"
