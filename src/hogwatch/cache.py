"""Кэш находок о диске: при запуске сразу показываем прошлую картину (помеченную ⏳), пока идёт пересканирование."""

from __future__ import annotations

import json
import os
import time

from .config import CACHE_DIR
from .model import Finding, Resource

CACHE_FILE = CACHE_DIR / "findings.json"
VERSION = 1
CACHED_SCANNERS = {"known", "walk", "spotlight", "apps"}


def save(findings: list[Finding]) -> None:
    data = {
        "version": VERSION,
        "saved": time.time(),
        "findings": [f.to_dict() for f in findings
                     if f.scanner in CACHED_SCANNERS and f.resource in (Resource.DISK, Resource.INFO) and not f.resolved],
    }
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, CACHE_FILE)  # атомарно: либо старый, либо новый файл целиком
    except OSError:
        pass


def load(max_age_days: float = 30) -> list[Finding]:
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if data.get("version") != VERSION or time.time() - data.get("saved", 0) > max_age_days * 86400:
        return []
    out = []
    for d in data.get("findings", []):
        try:
            f = Finding.from_dict(d)
        except (TypeError, ValueError, KeyError):
            continue
        # то, чего уже нет на диске, не показываем
        if f.paths and not any(os.path.lexists(p) for p in f.paths):
            continue
        f.stale = True
        out.append(f)
    return out
