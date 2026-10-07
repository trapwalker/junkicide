"""Настройки и списки исключений. Один TOML-файл — его же можно переносить на другой Mac как есть."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .util import HOME

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config")) / "hogwatch"
CONFIG_FILE = CONFIG_DIR / "config.toml"
CACHE_DIR = HOME / "Library" / "Caches" / "hogwatch"


@dataclass
class Config:
    cpu_percent: float = 25.0  # с какой устойчивой загрузки процесс считается «греющим» (% одного ядра)
    app_memory_mb: int = 800  # с какого объёма памяти приложение показывается
    big_file_mb: int = 300  # с какого размера файл считается крупным
    min_dir_mb: int = 200  # с какого размера показывать кэши/артефакты
    stale_days: int = 180  # «давно не пользовались»
    ignore_ids: list[str] = field(default_factory=list)  # находки и пути, скрытые пользователем
    extra_scan_roots: list[str] = field(default_factory=list)
    path: Path = CONFIG_FILE

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> Config:
        cfg = cls(path=path)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return cfg
        th = data.get("thresholds", {})
        for k in ("cpu_percent", "app_memory_mb", "big_file_mb", "min_dir_mb", "stale_days"):
            if k in th:
                setattr(cfg, k, type(getattr(cfg, k))(th[k]))
        cfg.ignore_ids = list(data.get("ignore", {}).get("ids", []))
        cfg.extra_scan_roots = list(data.get("scan", {}).get("extra_roots", []))
        return cfg

    def save(self) -> None:
        def arr(items: list[str]) -> str:
            if not items:
                return "[]"
            return "[\n" + "".join(f"  {json.dumps(i, ensure_ascii=False)},\n" for i in items) + "]"

        text = (
            "# hogwatch — настройки. Файл можно копировать между компьютерами.\n\n"
            "[thresholds]\n"
            f"cpu_percent = {self.cpu_percent}  # устойчивая загрузка, % одного ядра\n"
            f"app_memory_mb = {self.app_memory_mb}\n"
            f"big_file_mb = {self.big_file_mb}\n"
            f"min_dir_mb = {self.min_dir_mb}\n"
            f"stale_days = {self.stale_days}\n\n"
            "[scan]\n"
            f"extra_roots = {arr(self.extra_scan_roots)}\n\n"
            "[ignore]\n"
            "# id находок или пути, которые не надо больше показывать\n"
            f"ids = {arr(self.ignore_ids)}\n"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self.path)  # атомарно
