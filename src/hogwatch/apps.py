"""Индекс установленных приложений: bundle id → имя/путь/версия. Нужен для «чей это кэш» и «уже установлено»."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

from .util import HOME, app_info

APP_DIRS = [Path("/Applications"), Path("/Applications/Utilities"), HOME / "Applications",
            Path("/System/Applications"), Path("/System/Applications/Utilities")]


@dataclass
class App:
    name: str
    bundle_id: str
    version: str
    path: str


_lock = threading.Lock()
_index: list[App] | None = None


def installed_apps() -> list[App]:
    global _index
    with _lock:
        if _index is not None:
            return _index
        apps = []
        for d in APP_DIRS:
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                if e.name.endswith(".app"):
                    info = app_info(e.path)
                    apps.append(App(info["name"], info["bundle_id"], info["version"], e.path))
                elif e.is_dir() and not e.name.startswith(".") and d == Path("/Applications"):
                    # папки-«комплекты» вроде /Applications/Microsoft Office/
                    try:
                        for sub in os.scandir(e.path):
                            if sub.name.endswith(".app"):
                                info = app_info(sub.path)
                                apps.append(App(info["name"], info["bundle_id"], info["version"], sub.path))
                    except OSError:
                        pass
        _index = apps
        return apps


def by_bundle_id() -> dict[str, App]:
    return {a.bundle_id.lower(): a for a in installed_apps() if a.bundle_id}


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9а-я]", "", s.lower())


def app_for_bundle_like(name: str) -> App | None:
    """Найти приложение по имени папки вида com.vendor.app (в т.ч. с суффиксами .helper, .ShipIt)."""
    idx = by_bundle_id()
    key = name.lower()
    while key:
        if key in idx:
            return idx[key]
        if "." not in key:
            break
        key = key.rsplit(".", 1)[0]
        if key.count(".") < 1:
            break
    return None


def match_installer(filename: str) -> App | None:
    """Дистрибутив «Telegram-4.2.1.dmg» → установленное приложение Telegram."""
    stem = norm(re.sub(r"\.(dmg|pkg|zip|xip|iso)$", "", filename, flags=re.I))
    stem = re.sub(r"(v?\d+)+.*$", "", stem) or stem  # отрезать версию
    best = None
    for a in installed_apps():
        n = norm(a.name)
        if len(n) < 4:
            continue
        if stem.startswith(n) or (len(stem) >= 5 and n.startswith(stem)):
            if best is None or len(norm(best.name)) < len(n):
                best = a
    return best
