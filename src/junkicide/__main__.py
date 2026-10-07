"""Точка входа: `junkicide` (TUI) или `junkicide --report` (текстовый отчёт для терминала/скриптов)."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .config import Config
from .journal import Journal


def make_scanners(args) -> list:
    from .scanners.apps_unused import UnusedAppsScanner
    from .scanners.disk_known import KnownPathsScanner
    from .scanners.disk_walk import HomeWalkScanner, SpotlightBigFiles
    from .scanners.docker import DockerScanner
    from .scanners.processes import ProcessScanner
    from .scanners.system import SystemScanner

    scanners = [SystemScanner(), ProcessScanner(), DockerScanner()]
    if not args.no_disk:
        scanners += [SpotlightBigFiles(), KnownPathsScanner(), UnusedAppsScanner()]
        if not args.no_walk:
            scanners.append(HomeWalkScanner())
    return scanners


def report(args, config: Config, journal: Journal) -> int:
    from .model import RISK_META, FindingStore, Resource
    from .scanners.base import Runner, ScanContext
    from .util import human_bytes

    store = FindingStore()
    store.set_ignored(set(config.ignore_ids))
    ctx = ScanContext(store, journal, config)
    runner = Runner(ctx, make_scanners(args))
    runner.start()
    deadline = time.time() + args.report
    once = [n for n, st in ctx.status.items() if n not in ("system", "processes", "docker")]
    while time.time() < deadline:
        time.sleep(0.5)
        if time.time() > deadline - args.report + 5 and all(ctx.status[n].runs > 0 for n in once):
            break
        if sys.stderr.isatty():
            busy = [f"{st.title}: {st.message}" for st in ctx.status.values() if st.state == "идёт"]
            print("\r\033[K⟳ " + "; ".join(busy)[:150], end="", file=sys.stderr, flush=True)
    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr)
    runner.stop()
    items = sorted(store.snapshot(), key=lambda f: -f.score)
    sections = [
        ("🔥 Нагрузка на CPU и 🧠 память", [f for f in items if f.resource in (Resource.CPU, Resource.MEMORY)]),
        ("💾 Диск", [f for f in items if f.resource == Resource.DISK]),
        ("ℹ️  Сведения", [f for f in items if f.resource == Resource.INFO]),
    ]
    for title, fs in sections:
        print(f"\n{title}")
        for f in fs[: args.top]:
            cpu = f" CPU {f.cpu:.0f}%" if f.cpu >= 1 else ""
            size = human_bytes(f.bytes) if f.bytes else ""
            print(f"  {RISK_META[f.risk][0]} {size:>9}{cpu:>10}  {f.confidence * 100:3.0f}%  {f.title}")
            if f.location and args.verbose:
                print(f"{'':30}{f.location}")
    print()
    not_done = [st.title for st in ctx.status.values() if st.runs == 0]
    if not_done:
        print(f"(не успели за {args.report} с: {', '.join(not_done)} — увеличьте --report)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="junkicide",
        description="Найти и осознанно прибить забытые прожорливые процессы и ненужные гигабайты на macOS.",
    )
    p.add_argument("--report", type=int, metavar="СЕК", nargs="?", const=120,
                   help="не открывать интерфейс: просканировать (до СЕК секунд, по умолчанию 120) и вывести отчёт")
    p.add_argument("--top", type=int, default=15, help="сколько строк в каждом разделе отчёта")
    p.add_argument("-v", "--verbose", action="store_true", help="в отчёте показывать пути")
    p.add_argument("--no-walk", action="store_true", help="не делать полный обход домашней папки (быстрее)")
    p.add_argument("--no-disk", action="store_true", help="только процессы, без анализа диска")
    p.add_argument("--version", action="version", version=f"junkicide {__version__}")
    args = p.parse_args(argv)

    if sys.platform != "darwin":
        print("junkicide рассчитан на macOS.", file=sys.stderr)
    config = Config.load()
    journal = Journal()
    if args.report is not None:
        return report(args, config, journal)

    from .tui.app import JunkicideApp

    JunkicideApp(config, journal, make_scanners(args)).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
