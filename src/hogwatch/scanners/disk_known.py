"""Известные места на диске: кэши, артефакты разработки, эмуляторы, бэкапы, остатки удалённых программ."""

from __future__ import annotations

import glob
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..apps import app_for_bundle_like
from ..knowledge.paths import RULES, PathRule
from ..model import Action, ActionKind, Finding, Resource, Risk
from ..util import HOME, du_bytes, fmt_date, human_duration, newest_mtime, read_plist, short_path, stat_times, which
from .base import ScanContext, Scanner

MB = 1024**2


def expand(pattern: str) -> list[str]:
    base = pattern if pattern.startswith("/") else str(HOME / pattern)
    return sorted(glob.glob(base))


def rule_roots() -> list[str]:
    """Пути, которые покрывает база знаний (полный обход их пропускает)."""
    roots = []
    for r in RULES:
        for g in r.globs:
            for p in expand(g):
                roots.append(p)
    return roots


def trash_action(paths: list[str], label: str = "Переместить в Корзину") -> Action:
    return Action(ActionKind.TRASH, label, "Можно вернуть из Корзины, пока она не очищена.", paths=paths)


def reveal_action(path: str) -> Action:
    return Action(ActionKind.REVEAL, "Показать в Finder", paths=[path], destructive=False)


def stale_conf(base: float, mtime: float | None, stale_days: int) -> tuple[float, str]:
    if not mtime:
        return base, ""
    age = time.time() - mtime
    if age > stale_days * 86400:
        return min(base + 0.2, 0.95), f"Не менялось {human_duration(age)}."
    if age > 30 * 86400:
        return min(base + 0.1, 0.95), f"Не менялось {human_duration(age)}."
    return base, f"Менялось {human_duration(age)} назад — похоже, используется."


class KnownPathsScanner(Scanner):
    name = "known"
    title = "известные места"

    def run(self, ctx: ScanContext) -> None:
        cfg = ctx.config
        jobs: list[tuple[PathRule, list[str]]] = []
        for rule in RULES:
            matched = [p for g in rule.globs for p in expand(g)]
            if not matched:
                continue
            if rule.each:
                jobs.extend((rule, [p]) for p in matched)
            else:
                jobs.append((rule, matched))
        ctx.progress(self.name, f"{len(jobs)} мест")
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(self._rule_finding, rule, paths, cfg) for rule, paths in jobs]
            specials = [pool.submit(fn, cfg) for fn in (
                self._avds, self._system_images, self._ios_backups, self._jetbrains, self._library_caches,
                self._orphan_containers, self._brew)]
            done = 0
            for fut in futures + specials:
                if ctx.stop.is_set():
                    return
                try:
                    res = fut.result()
                except Exception as e:
                    ctx.journal.warn("scan.known", f"ошибка: {e!r}")
                    continue
                done += 1
                ctx.progress(self.name, f"{done}/{len(futures) + len(specials)}")
                if res:
                    ctx.store.upsert(res if isinstance(res, list) else [res])

    # --- по правилам --------------------------------------------------------------------------

    def _rule_finding(self, rule: PathRule, paths: list[str], cfg) -> Finding | None:
        size = sum(du_bytes(p) for p in paths)
        if size < (rule.min_mb or cfg.min_dir_mb) * MB:
            return None
        name = ", ".join(os.path.basename(p).removesuffix(".app") for p in paths)
        mtime = max((newest_mtime(p, 2000) or 0) for p in paths) or None
        created, _ = stat_times(paths[0])
        conf, note = (stale_conf(rule.confidence, mtime, cfg.stale_days) if rule.stale_boost
                      else (rule.confidence, ""))
        acts: list[Action] = []
        if rule.command and (exe := which(rule.command[0])):
            acts.append(Action(ActionKind.COMMAND, rule.command_label or " ".join(rule.command),
                               "Штатная очистка средствами самой программы.", argv=[exe] + rule.command[1:]))
        if rule.risk != Risk.SYSTEM:
            acts.append(trash_action(paths))
        acts.append(reveal_action(paths[0]))
        facts = [("Путь" if len(paths) == 1 else "Пути", "\n".join(short_path(p) for p in paths)),
                 ("Создано", fmt_date(created)), ("Последнее изменение внутри", fmt_date(mtime))]
        return Finding(
            id=f"known:{rule.id}:{paths[0]}", scanner=self.name, resource=Resource.DISK,
            title=rule.title.format(name=name).replace(" ()", "").strip(),
            location=short_path(paths[0]) + (f" (+{len(paths) - 1})" if len(paths) > 1 else ""),
            bytes=size, risk=rule.risk, confidence=conf, tags=list(rule.tags), what=rule.what,
            origin=(rule.origin + (" " + note if note else "")).strip(), danger=rule.danger, facts=facts,
            actions=acts, paths=paths, created=created, modified=mtime,
        )

    # --- Android ------------------------------------------------------------------------------

    def _avds(self, cfg) -> list[Finding]:
        out = []
        avd_dir = HOME / ".android" / "avd"
        for ini in sorted(avd_dir.glob("*.ini")):
            text = ini.read_text(errors="ignore")
            m = re.search(r"^path=(.+)$", text, re.M)
            path = Path(m.group(1).strip()) if m else ini.with_suffix(".avd")
            if not path.is_dir():
                continue
            conf_txt = (path / "config.ini").read_text(errors="ignore") if (path / "config.ini").exists() else ""

            def cfgval(key: str) -> str:
                mm = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", conf_txt, re.M)
                return mm.group(1).strip() if mm else ""

            running = any(path.glob("*.lock"))
            size = du_bytes(path)
            if size < cfg.min_dir_mb * MB:
                continue
            used = max((f.stat().st_mtime for f in path.iterdir()
                        if f.name.endswith((".img", ".qcow2", ".ini")) or f.name == "snapshots"), default=None)
            created, _ = stat_times(path)
            conf, note = stale_conf(0.5, used, cfg.stale_days)
            if running:
                conf, note = 0.05, "Сейчас запущен (есть .lock-файлы)."
            name = cfgval("avd.ini.displayname") or ini.stem
            out.append(Finding(
                id=f"avd:{path}", scanner=self.name, resource=Resource.DISK,
                title=f"Виртуальное устройство Android «{name}»", location=short_path(path), bytes=size,
                risk=Risk.REBUILDABLE, confidence=conf, tags=["dev", "android", "vm"],
                what="Эмулируемое Android-устройство (AVD): диск с системой, данными приложений и снапшотами "
                     "быстрого запуска (snapshots занимают гигабайты).",
                origin="Создано в Android Studio → Device Manager или `avdmanager create avd`; для каждой версии "
                       f"API обычно создают новое, а старые остаются. {note}",
                danger="Пропадут установленные в эмулятор приложения и их данные. Само устройство легко "
                       "пересоздать в Device Manager за минуту.",
                facts=[("Путь", short_path(path)), ("Образ системы", cfgval("image.sysdir.1") or "?"),
                       ("Устройство", cfgval("hw.device.name") or "?"), ("Создано", fmt_date(created)),
                       ("Последний запуск ≈", fmt_date(used))],
                actions=[trash_action([str(path), str(ini)], "Удалить AVD в Корзину"), reveal_action(str(path))],
                paths=[str(path), str(ini)], created=created, modified=used,
            ))
        return out

    def _system_images(self, cfg) -> list[Finding]:
        sdk = Path(os.environ.get("ANDROID_HOME") or HOME / "Library/Android/sdk")
        root = sdk / "system-images"
        if not root.is_dir():
            return []
        used: set[str] = set()
        for cfg_ini in (HOME / ".android" / "avd").glob("*.avd/config.ini"):
            m = re.search(r"^image\.sysdir\.1\s*=\s*(.+)$", cfg_ini.read_text(errors="ignore"), re.M)
            if m:
                used.add(m.group(1).strip().rstrip("/"))
        out = []
        for img in root.glob("*/*/*"):
            rel = str(img.relative_to(sdk))
            size = du_bytes(img)
            if size < cfg.min_dir_mb * MB:
                continue
            in_use = rel in used
            created, mtime = stat_times(img)
            out.append(Finding(
                id=f"sysimg:{img}", scanner=self.name, resource=Resource.DISK,
                title=f"Образ Android {img.parts[-3]} ({img.parts[-2]}, {img.parts[-1]})"
                      + ("" if in_use else " — не используется ни одним AVD"),
                location=short_path(img), bytes=size, risk=Risk.REBUILDABLE,
                confidence=0.2 if in_use else 0.8, tags=["dev", "android"],
                what="Системный образ Android для эмулятора.",
                origin="Скачивается при создании виртуального устройства на этой версии API. Остаётся после "
                       "удаления устройства.",
                danger=("Используется AVD — без образа устройство не запустится." if in_use else
                        "Безопасно: SDK Manager скачает образ снова, если понадобится."),
                facts=[("Путь", short_path(img)), ("Скачан", fmt_date(created))],
                actions=[trash_action([str(img)]), reveal_action(str(img))], paths=[str(img)], created=created,
            ))
        return out

    # --- iPhone backups -----------------------------------------------------------------------

    def _ios_backups(self, cfg) -> list[Finding]:
        root = HOME / "Library/Application Support/MobileSync/Backup"
        try:
            entries = list(root.iterdir())
        except OSError:
            return []
        out = []
        for b in entries:
            info = read_plist(b / "Info.plist")
            size = du_bytes(b)
            if size < cfg.min_dir_mb * MB:
                continue
            last = info.get("Last Backup Date")
            last_ts = last.timestamp() if hasattr(last, "timestamp") else None
            dev = info.get("Device Name") or info.get("Display Name") or b.name[:12]
            out.append(Finding(
                id=f"iosbackup:{b}", scanner=self.name, resource=Resource.DISK,
                title=f"Резервная копия «{dev}» (iOS {info.get('Product Version', '?')})",
                location=short_path(b), bytes=size, risk=Risk.PERSONAL,
                confidence=0.6 if last_ts and time.time() - last_ts > 365 * 86400 else 0.3,
                tags=["ios", "backup", "data"],
                what="Локальная резервная копия iPhone/iPad: фото (если не в iCloud), сообщения, данные приложений.",
                origin="Создаётся Finder/iTunes при синхронизации или перед обновлением/восстановлением "
                       "устройства. Копии старых устройств остаются навсегда.",
                danger="Это единственная копия данных устройства на этом Mac. Удаляйте, если у устройства есть "
                       "свежая копия в iCloud или устройство давно продано/не нужно.",
                facts=[("Устройство", str(dev)), ("Модель", info.get("Product Type", "?")),
                       ("Последний бэкап", fmt_date(last_ts)), ("Путь", short_path(b))],
                actions=[trash_action([str(b)]), reveal_action(str(b))], paths=[str(b)], modified=last_ts,
            ))
        return out

    # --- старые версии IDE --------------------------------------------------------------------

    def _jetbrains(self, cfg) -> list[Finding]:
        bases = [HOME / "Library/Caches/JetBrains", HOME / "Library/Application Support/JetBrains",
                 HOME / "Library/Logs/JetBrains", HOME / "Library/Caches/Google",
                 HOME / "Library/Application Support/Google", HOME / "Library/Logs/Google"]
        rx = re.compile(r"^([A-Za-z]+?)(\d{4}\.\d+)$")
        groups: dict[str, list[tuple[str, Path]]] = {}
        for base in bases:
            try:
                for d in base.iterdir():
                    m = rx.match(d.name)
                    if m and d.is_dir():
                        groups.setdefault(m.group(1), []).append((m.group(2), d))
            except OSError:
                continue
        out = []
        for product, items in groups.items():
            versions = sorted({v for v, _ in items}, key=lambda v: [int(x) for x in v.split(".")])
            if len(versions) < 2:
                continue
            latest = versions[-1]
            for v in versions[:-1]:
                paths = [str(p) for vv, p in items if vv == v]
                size = sum(du_bytes(p) for p in paths)
                if size < 50 * MB:
                    continue
                out.append(Finding(
                    id=f"ide-old:{product}{v}", scanner=self.name, resource=Resource.DISK,
                    title=f"Данные старой версии {product} {v}", location=short_path(paths[0]), bytes=size,
                    risk=Risk.SAFE, confidence=0.85, tags=["dev", "editor", "cache"],
                    what=f"Кэши, индексы, логи и настройки IDE {product} версии {v}. Сейчас используется {latest}.",
                    origin="JetBrains IDE и Android Studio при обновлении создают папки новой версии, импортируют "
                           "настройки, а старые папки не удаляют.",
                    danger="Безопасно: актуальная версия использует свои папки. Настройки уже перенесены.",
                    facts=[("Пути", "\n".join(short_path(p) for p in paths)), ("Актуальная версия", latest)],
                    actions=[trash_action(paths), reveal_action(paths[0])], paths=paths,
                ))
        return out

    # --- кэши приложений и остатки удалённых программ -----------------------------------------

    def _library_caches(self, cfg) -> list[Finding]:
        root = HOME / "Library/Caches"
        covered = {os.path.normpath(p) for p in rule_roots()}
        out = []
        try:
            entries = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return []
        for e in entries:
            if e.path in covered or e.name in ("JetBrains", "Google", "hogwatch"):
                continue
            size = du_bytes(e.path)
            if size < cfg.min_dir_mb * MB:
                continue
            app = app_for_bundle_like(e.name)
            who = app.name if app else e.name
            installed = app is not None or "." not in e.name
            mtime = newest_mtime(e.path, 1500)
            out.append(Finding(
                id=f"cache:{e.path}", scanner=self.name, resource=Resource.DISK, title=f"Кэш {who}",
                location=short_path(e.path), bytes=size, risk=Risk.SAFE,
                confidence=0.75 if installed else 0.9, tags=["cache"] + ([] if installed else ["удалённое"]),
                what=f"Папка кэша программы «{who}» в ~/Library/Caches — по правилам macOS сюда кладут только то, "
                     "что можно пересоздать.",
                origin=("Программа кэширует загрузки, превью, скомпилированный код."
                        + ("" if installed else " Программа, похоже, уже удалена — кэш остался сиротой.")),
                danger=CACHE_TEXT,
                facts=[("Путь", short_path(e.path)), ("Изменялся", fmt_date(mtime))] + (
                    [("Приложение", app.path)] if app else []),
                actions=[trash_action([e.path]), reveal_action(e.path)], paths=[e.path], modified=mtime,
            ))
        return out

    def _orphan_containers(self, cfg) -> list[Finding]:
        out = []
        for root in (HOME / "Library/Containers", HOME / "Library/Application Support"):
            try:
                entries = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
            except OSError:
                continue
            for e in entries:
                n = e.name
                if n.count(".") < 2 or n.lower().startswith(("com.apple.", "group.com.apple")):
                    continue
                if app_for_bundle_like(n):
                    continue
                size = du_bytes(e.path)
                if size < max(cfg.min_dir_mb, 100) * MB:
                    continue
                mtime = newest_mtime(e.path, 1500)
                conf, note = stale_conf(0.55, mtime, cfg.stale_days)
                out.append(Finding(
                    id=f"orphan:{e.path}", scanner=self.name, resource=Resource.DISK,
                    title=f"Данные удалённой программы {n}", location=short_path(e.path), bytes=size,
                    risk=Risk.CAUTION, confidence=conf, tags=["удалённое", "app-data"],
                    what=f"Папка данных программы с идентификатором `{n}`, которой нет среди установленных "
                         "приложений.",
                    origin="При удалении программы перетаскиванием в Корзину macOS не удаляет её данные в "
                           f"~/Library. {note}",
                    danger="Если программу поставите снова — её настройки и данные начнутся с нуля. "
                           "Иногда это helper установленной программы с другим идентификатором — проверьте путь.",
                    facts=[("Путь", short_path(e.path)), ("Изменялось", fmt_date(mtime))],
                    actions=[trash_action([e.path]), reveal_action(e.path)], paths=[e.path], modified=mtime,
                ))
        return out

    # --- Homebrew -----------------------------------------------------------------------------

    def _brew(self, cfg) -> list[Finding]:
        brew = which("brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew")
        if not brew:
            return []
        from ..util import run

        code, out, _ = run([brew, "cleanup", "-n", "--prune=all"], timeout=120)
        m = re.search(r"free approximately ([\d.]+)\s*([KMGT]?B)", out)
        if not m:
            return []
        mult = {"B": 1, "KB": 1024, "MB": MB, "GB": 1024**3, "TB": 1024**4}[m.group(2)]
        size = int(float(m.group(1)) * mult)
        if size < cfg.min_dir_mb * MB:
            return []
        lines = [ln for ln in out.splitlines() if ln.startswith("Would remove")]
        return [Finding(
            id="brew:cleanup", scanner=self.name, resource=Resource.DISK,
            title="Старые версии пакетов Homebrew", location="brew cleanup", bytes=size, risk=Risk.SAFE,
            confidence=0.9, tags=["dev", "cache"],
            what="Предыдущие версии формул и cask'ов, оставшиеся после `brew upgrade`, и устаревшие загрузки.",
            origin="Homebrew чистит автоматически лишь раз в 30 дней и не всё.",
            danger="Безопасно: удаляются только неактивные старые версии.",
            facts=[("Будет удалено", "\n".join(short_path(ln.removeprefix("Would remove: ")) for ln in lines[:20])
                    + (f"\n… и ещё {len(lines) - 20}" if len(lines) > 20 else ""))],
            actions=[Action(ActionKind.COMMAND, "brew cleanup --prune=all", "Штатная очистка Homebrew.",
                            argv=[brew, "cleanup", "--prune=all"])],
        )]


CACHE_TEXT = ("Безопасно: кэш пересоздаётся. Лучше закрыть программу перед удалением — иначе она может сразу "
              "начать заполнять его снова.")
