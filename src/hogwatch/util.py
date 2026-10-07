"""Мелкие помощники: форматирование, запуск команд, размеры каталогов, метаданные Spotlight."""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

HOME = Path.home()


def human_bytes(n: float) -> str:
    if n <= 0:
        return "0"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") or n >= 100 else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def plural(n: int, one: str, few: str, many: str) -> str:
    n100 = abs(n) % 100
    n10 = n100 % 10
    if 10 < n100 < 20:
        return many
    if n10 == 1:
        return one
    if 2 <= n10 <= 4:
        return few
    return many


def human_duration(seconds: float) -> str:
    s = int(max(seconds, 0))
    if s < 60:
        return f"{s} с"
    if s < 3600:
        return f"{s // 60} мин"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} ч {m} мин" if m else f"{h} ч"
    d = s // 86400
    if d < 60:
        h = (s % 86400) // 3600
        return f"{d} {plural(d, 'день', 'дня', 'дней')}" + (f" {h} ч" if h and d < 3 else "")
    if d < 730:
        mo = d // 30
        return f"{mo} {plural(mo, 'месяц', 'месяца', 'месяцев')}"
    y = d // 365
    return f"{y} {plural(y, 'год', 'года', 'лет')}"


def ago(ts: float | None) -> str:
    if not ts:
        return "—"
    return human_duration(time.time() - ts) + " назад"


def fmt_date(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")


def short_path(p: str | os.PathLike) -> str:
    s = str(p)
    h = str(HOME)
    return "~" + s[len(h):] if s == h or s.startswith(h + "/") else s


def run(argv: list[str], timeout: float = 30, cwd: str | None = None) -> tuple[int, str, str]:
    """Запустить команду, не падая: (код, stdout, stderr)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"не найдено: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"таймаут {timeout} с: {' '.join(argv)}"
    except OSError as e:
        return 126, "", str(e)


def which(name: str, *extra: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for p in extra:
        p = os.path.expanduser(p)
        if os.access(p, os.X_OK):
            return p
    return None


def du_bytes(path: str | os.PathLike, timeout: float = 600) -> int:
    """Занятое место (выделенные блоки) — через системный du, он быстрее Python-обхода."""
    code, out, _ = run(["du", "-skx", str(path)], timeout=timeout)
    try:
        return int(out.split("\t", 1)[0]) * 1024
    except (ValueError, IndexError):
        return 0


def disk_usage_of_file(st: os.stat_result) -> int:
    return getattr(st, "st_blocks", 0) * 512 or st.st_size


def stat_times(path: str | os.PathLike) -> tuple[float | None, float | None]:
    """(создан, изменён)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None, None
    return getattr(st, "st_birthtime", None), st.st_mtime


def newest_mtime(path: str | os.PathLike, max_entries: int = 3000) -> float | None:
    """Самое свежее изменение внутри каталога (ограниченный обход — для оценки «давно не трогали»)."""
    best = None
    stack = [str(path)]
    seen = 0
    while stack and seen < max_entries:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if best is None or st.st_mtime > best:
                        best = st.st_mtime
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
        except OSError:
            continue
    return best


# --- Spotlight -------------------------------------------------------------------------------

_MD_ATTRS = [
    "kMDItemLastUsedDate",
    "kMDItemWhereFroms",
    "kMDItemDurationSeconds",
    "kMDItemPixelHeight",
    "kMDItemPixelWidth",
    "kMDItemUseCount",
    "kMDItemContentCreationDate",
    "kMDItemAcquisitionMake",
    "kMDItemAcquisitionModel",
    "kMDItemVersion",
    "kMDItemCFBundleIdentifier",
]


def spotlight_meta(path: str) -> dict:
    """Метаданные Spotlight для файла: когда открывали, откуда скачан, длительность видео и т.п."""
    args = ["mdls", "-plist", "-"]
    for a in _MD_ATTRS:
        args[1:1] = ["-name", a]
    args.append(path)
    code, out, _ = run(args, timeout=10)
    if code != 0 or not out:
        return {}
    try:
        data = plistlib.loads(out.encode())
    except Exception:
        return {}
    res = {}
    for k, v in data.items():
        if isinstance(v, datetime):
            v = v.timestamp()
        res[k] = v
    return res


def mdfind(query: str, onlyin: str | None = None, timeout: float = 60) -> list[str]:
    argv = ["mdfind"]
    if onlyin:
        argv += ["-onlyin", onlyin]
    argv.append(query)
    code, out, _ = run(argv, timeout=timeout)
    return [line for line in out.splitlines() if line]


def read_plist(path: str | os.PathLike) -> dict:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return {}


def app_info(app_path: str | os.PathLike) -> dict:
    """Имя, bundle id, версия приложения из Info.plist."""
    info = read_plist(Path(app_path) / "Contents" / "Info.plist")
    return {
        "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or Path(app_path).stem,
        "bundle_id": info.get("CFBundleIdentifier", ""),
        "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "",
    }


def is_cloud_synced(path: str) -> str | None:
    """Если путь внутри синхронизируемой облачной папки — вернуть её название."""
    p = str(path)
    checks = [
        (str(HOME / "Library" / "Mobile Documents"), "iCloud Drive"),
        (str(HOME / "Library" / "CloudStorage"), "облачное хранилище"),
        (str(HOME / "Dropbox"), "Dropbox"),
        (str(HOME / "Google Drive"), "Google Drive"),
    ]
    for root, name in checks:
        if p.startswith(root + "/"):
            return name
    for entry in ("Yandex.Disk.localized", "Yandex.Disk"):
        if p.startswith(str(HOME / entry) + "/"):
            return "Яндекс Диск"
    return None
