"""Программы, которые давно не запускали: размер самой программы и её данных в ~/Library."""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

from ..apps import installed_apps
from ..model import Action, ActionKind, Finding, Resource, Risk
from ..util import HOME, du_bytes, newest_mtime, fmt_date, human_bytes, human_duration, run, short_path, spotlight_meta, which
from .base import ScanContext, Scanner
from .disk_known import reveal_action, trash_action

MB = 1024**2


def brew_casks() -> dict[str, str]:
    """Имя .app → имя cask'а Homebrew (чтобы удалять «правильно»)."""
    brew = which("brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew")
    if not brew:
        return {}
    code, out, _ = run([brew, "list", "--cask", "-1"], timeout=30)
    casks = out.split()
    res = {}
    caskroom = "/opt/homebrew/Caskroom" if os.path.isdir("/opt/homebrew/Caskroom") else "/usr/local/Caskroom"
    for c in casks:
        try:
            for ver in os.scandir(os.path.join(caskroom, c)):
                for e in os.scandir(ver.path):
                    if e.name.endswith(".app"):
                        res[e.name] = c
        except OSError:
            continue
    return res


def activity_trace(bundle_id: str, name: str) -> float | None:
    """Последнее изменение настроек/состояния программы — программа пишет их, когда работает."""
    if not bundle_id:
        return None
    cands = [
        HOME / "Library/Preferences" / f"{bundle_id}.plist",
        HOME / "Library/Saved Application State" / f"{bundle_id}.savedState",
        HOME / "Library/Containers" / bundle_id / "Data/Library/Preferences" / f"{bundle_id}.plist",
        HOME / "Library/Application Support" / name, HOME / "Library/Application Support" / bundle_id,
        HOME / "Library/Caches" / bundle_id, HOME / "Library/HTTPStorages" / bundle_id,
    ]
    best = None
    for p in cands:
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        best = m if best is None or m > best else best
    # IDE JetBrains/Android Studio: ~/Library/{Application Support,Logs}/<Вендор>/<Продукт><версия>
    token = name.replace(" ", "")
    for pattern in (f"Library/Application Support/*/{token}*", f"Library/Logs/*/{token}*"):
        for d in HOME.glob(pattern):
            m = newest_mtime(d, 400)
            if m and (best is None or m > best):
                best = m
    return best


def app_data_paths(bundle_id: str, name: str) -> list[str]:
    cands = [
        HOME / "Library/Application Support" / name, HOME / "Library/Application Support" / bundle_id,
        HOME / "Library/Containers" / bundle_id, HOME / "Library/Caches" / bundle_id,
        HOME / "Library/Caches" / name, HOME / "Library/Saved Application State" / f"{bundle_id}.savedState",
        HOME / "Library/HTTPStorages" / bundle_id, HOME / "Library/WebKit" / bundle_id,
        HOME / "Library/Logs" / name,
    ]
    return [str(p) for p in cands if bundle_id and p.exists()]


class UnusedAppsScanner(Scanner):
    name = "apps"
    title = "давно не запускавшиеся программы"
    delay = 1.0

    def run(self, ctx: ScanContext) -> None:
        cfg = ctx.config
        running = set()
        for p in psutil.process_iter(["exe"]):
            exe = p.info.get("exe") or ""
            if ".app/" in exe:
                running.add(exe[: exe.find(".app/") + 4])
        apps = [a for a in installed_apps()
                if not a.path.startswith("/System/") and not a.bundle_id.startswith("com.apple.")
                and a.path not in running]
        casks = brew_casks()
        now = time.time()

        def check(a):
            meta = spotlight_meta(a.path)
            last = meta.get("kMDItemLastUsedDate")
            try:
                st = os.stat(a.path)
                added = getattr(st, "st_birthtime", 0) or st.st_mtime
                if added < 10 * 365 * 86400:  # «1970 год» — дата не сохранилась при установке
                    added = st.st_mtime
            except OSError:
                return None
            # Spotlight в новых macOS не всегда помнит запуски — смотрим на следы активности программы
            trace = activity_trace(a.bundle_id, a.name)
            last = max(filter(None, (last, trace)), default=None)
            ref = last or added
            if now - ref < cfg.stale_days * 86400:
                return None
            size = du_bytes(a.path)
            data = app_data_paths(a.bundle_id, a.name)
            data_size = sum(du_bytes(p) for p in data)
            if size + data_size < 100 * MB:
                return None
            return a, last, added, size, data, data_size, meta.get("kMDItemUseCount")

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = [r for r in pool.map(check, apps) if r]
        out = []
        for a, last, added, size, data, data_size, uses in results:
            idle = now - (last or added)
            conf = 0.5 + min(idle / (3 * 365 * 86400), 1) * 0.35
            cask = casks.get(os.path.basename(a.path))
            acts: list[Action] = []
            if cask and (brew := which("brew", "/opt/homebrew/bin/brew")):
                acts.append(Action(ActionKind.COMMAND, f"brew uninstall --cask {cask}",
                                   "Удалит программу так, чтобы Homebrew тоже знал об этом (иначе `brew upgrade` "
                                   "будет пытаться её обновлять).", argv=[brew, "uninstall", "--cask", cask]))
            acts.append(trash_action([a.path], "Программу — в Корзину"))
            if data:
                acts.append(trash_action([a.path] + data, "Программу и её данные — в Корзину"))
            acts.append(reveal_action(a.path))
            out.append(Finding(
                id=f"app-unused:{a.path}", scanner=self.name, resource=Resource.DISK,
                title=f"{a.name}: не использовалась {human_duration(idle)}" if last
                else f"{a.name}: ни разу не запускалась (установлена {human_duration(idle)} назад)",
                location=short_path(a.path), bytes=size + data_size, risk=Risk.CAUTION, confidence=conf,
                tags=["app", "unused"] + (["brew"] if cask else []),
                what=f"Программа «{a.name}»" + (f" версии {a.version}" if a.version else "")
                     + f". Сама программа — {human_bytes(size)}, её данные в ~/Library — {human_bytes(data_size)}.",
                origin=("Последняя активность (по Spotlight и изменению файлов настроек программы) — "
                        + fmt_date(last) + "." if last else
                        "Нет ни записи о запуске в Spotlight, ни файлов настроек — похоже, ни разу не запускалась.")
                       + (" Установлена через Homebrew." if cask else ""),
                danger="Программу можно поставить снова, но платные лицензии иногда требуют повторной активации. "
                       "Вместе с данными пропадут её настройки и локальные файлы (документы — если программа "
                       "хранит их внутри ~/Library).",
                facts=[("Путь", short_path(a.path)), ("Bundle ID", a.bundle_id or "—"),
                       ("Последняя активность ≈", fmt_date(last)), ("Число запусков", str(uses or "—")),
                       ("Установлена", fmt_date(added))]
                + ([("Данные", "\n".join(short_path(p) for p in data))] if data else []),
                actions=acts, paths=[a.path], last_used=last, created=added,
            ))
        ctx.store.upsert(out)
