"""Полный обход домашней папки: крупные файлы, папки с видео (регистратор!), артефакты сборки, дубликаты.

Быстрая фаза — Spotlight (`mdfind`) находит крупные файлы за секунды; затем медленный обход уточняет картину.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor

from ..knowledge.files import (
    CAMERA_RX,
    DASHCAM_DIR_RX,
    VIDEO,
    artifact_kind,
    classify_file,
    ext_of,
    is_dashcam_name,
    rebuild_hint,
)
from ..model import Finding, Resource, Risk
from ..util import (
    HOME,
    du_bytes,
    fmt_date,
    human_bytes,
    human_duration,
    is_cloud_synced,
    mdfind,
    plural,
    short_path,
)
from .base import ScanContext, Scanner
from .disk_known import reveal_action, rule_roots, trash_action

MB = 1024**2
PACKAGE_SUFFIXES = (".photoslibrary", ".musiclibrary", ".imovielibrary", ".fcpbundle", ".tvlibrary",
                    ".lrlibrary", ".aplibrary", ".band", ".logicx")
VM_SUFFIXES = (".utm", ".pvm", ".vmwarevm", ".vbox")


def walk_skip_set() -> set[str]:
    skip = {str(HOME / "Library"), str(HOME / ".Trash"), str(HOME / ".android" / "avd"), str(HOME / ".orbstack"),
            str(HOME / ".docker"), str(HOME / "OrbStack"), str(HOME / ".colima"), str(HOME / ".lima")}
    skip.update(os.path.normpath(p) for p in rule_roots())
    return skip


def walk_roots(extra: list[str]) -> list[str]:
    roots = [str(HOME)]
    icloud = HOME / "Library/Mobile Documents/com~apple~CloudDocs"
    if icloud.is_dir():
        roots.append(str(icloud))
    try:
        roots += [e.path for e in os.scandir(HOME / "Library/CloudStorage") if e.is_dir()]
    except OSError:
        pass
    roots += [os.path.expanduser(r) for r in extra]
    return roots


def file_finding(scanner: str, path: str, size: int, mtime: float, birth: float | None, stale_days: int) -> Finding:
    v = classify_file(path, size, mtime, stale_days)
    return Finding(
        id=f"file:{path}", scanner=scanner, resource=Resource.DISK, title=v.title, location=short_path(path),
        bytes=size, risk=v.risk, confidence=v.confidence, tags=v.tags + [v.kind], what=v.what, origin=v.origin,
        danger=v.danger,
        facts=[("Путь", short_path(path)), ("Размер", human_bytes(size)), ("Создан", fmt_date(birth)),
               ("Изменён", fmt_date(mtime))],
        actions=[trash_action([path]), reveal_action(path)], paths=[path], created=birth, modified=mtime,
    )


def partial_hash(path: str, size: int) -> str | None:
    h = hashlib.blake2b(digest_size=16)
    try:
        with open(path, "rb") as fh:
            for off in (0, size // 2, max(size - MB, 0)):
                fh.seek(off)
                h.update(fh.read(MB))
    except OSError:
        return None
    return h.hexdigest()


class SpotlightBigFiles(Scanner):
    """Быстрая фаза: крупные файлы из индекса Spotlight."""

    name = "spotlight"
    title = "крупные файлы (Spotlight)"

    def run(self, ctx: ScanContext) -> None:
        cfg = ctx.config
        skip = walk_skip_set()
        paths = mdfind(f"kMDItemFSSize > {cfg.big_file_mb * MB}", onlyin=str(HOME))
        out = []
        for p in paths:
            if any(p == s or p.startswith(s + "/") for s in skip) or "/node_modules/" in p or "/.git/" in p:
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p):
                continue
            size = st.st_blocks * 512
            if size < cfg.big_file_mb * MB:
                continue
            out.append(file_finding(self.name, p, size, st.st_mtime, getattr(st, "st_birthtime", None),
                                    cfg.stale_days))
        ctx.store.upsert(out)
        ctx.progress(self.name, f"{len(out)} файлов")


class HomeWalkScanner(Scanner):
    name = "walk"
    title = "обход домашней папки"
    delay = 1.5

    def run(self, ctx: ScanContext) -> None:
        cfg = ctx.config
        self.ctx = ctx
        big = cfg.big_file_mb * MB
        skip = walk_skip_set()
        pool = ThreadPoolExecutor(max_workers=4)
        artifacts: dict[str, list[tuple[str, str, Future]]] = defaultdict(list)  # проект → [(путь, имя, du)]
        packages: list[tuple[str, Future]] = []
        by_size: dict[int, list[tuple[str, int, float]]] = defaultdict(list)  # для поиска дубликатов
        top: dict[str, int] = defaultdict(int)
        self.files = 0
        self.bytes = 0
        denied = 0
        last_flush = time.time()
        home = str(HOME)

        for root in walk_roots(cfg.extra_scan_roots):
            try:
                root_dev = os.stat(root).st_dev
            except OSError:
                continue
            stack: list[tuple[str, str | None]] = [(root, None)]
            while stack:
                if ctx.stop.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    return
                d, project = stack.pop()
                try:
                    with os.scandir(d) as it:
                        entries = list(it)
                except PermissionError:
                    denied += 1
                    continue
                except OSError:
                    continue
                names = {e.name for e in entries}
                if ".git" in names or project is None and any(
                        n in names for n in ("package.json", "pyproject.toml", "Cargo.toml", "build.gradle",
                                             "build.gradle.kts", "platformio.ini", "pubspec.yaml", "go.mod")):
                    project = d
                videos: list[tuple[str, int, float, float | None]] = []
                bigs: list[tuple[str, int, float, float | None]] = []
                for e in entries:
                    try:
                        if e.is_symlink():
                            continue
                        is_dir = e.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        if e.path in skip or e.name == ".git":
                            continue
                        try:
                            if e.stat(follow_symlinks=False).st_dev != root_dev:
                                continue  # другой том/виртуальная ФС (OrbStack, смонтированные образы)
                        except OSError:
                            continue
                        if e.name.endswith(PACKAGE_SUFFIXES + VM_SUFFIXES) or (
                                e.name.endswith(".app") and d != str(HOME / "Applications")):
                            packages.append((e.path, pool.submit(du_bytes, e.path)))
                            continue
                        if artifact_kind(e.name, names):
                            artifacts[project or d].append((e.path, e.name, pool.submit(du_bytes, e.path)))
                            continue
                        stack.append((e.path, project))
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    size = st.st_blocks * 512
                    self.files += 1
                    self.bytes += size
                    rel = e.path[len(home) + 1:] if e.path.startswith(home + "/") else e.path
                    top[rel.split("/", 1)[0] if "/" in rel else "(файлы в ~)"] += size
                    birth = getattr(st, "st_birthtime", None)
                    if ext_of(e.name) in VIDEO and size >= 20 * MB:
                        videos.append((e.path, size, st.st_mtime, birth))
                    if size >= big:
                        bigs.append((e.path, size, st.st_mtime, birth))
                    if size >= 100 * MB and st.st_nlink == 1:
                        by_size[st.st_size].append((e.path, size, st.st_mtime))
                grouped = self._video_dir(d, videos, cfg) if len(videos) >= 5 else None
                out = [grouped] if grouped else []
                grouped_paths = {v[0] for v in videos} if grouped else set()
                for p, size, mtime, birth in bigs:
                    if p not in grouped_paths:
                        out.append(file_finding(self.name, p, size, mtime, birth, cfg.stale_days))
                if grouped_paths:
                    ctx.store.remove([f"file:{p}" for p in grouped_paths])
                if out:
                    ctx.store.upsert(out)
                if time.time() - last_flush > 3:
                    ctx.progress(self.name, f"{self.files:,} файлов, {human_bytes(self.bytes)} · {short_path(d)[:60]}"
                                 .replace(",", " "))
                    self._flush_artifacts(artifacts, cfg, wait=False)
                    last_flush = time.time()

        ctx.progress(self.name, "досчитываю размеры папок…")
        self._flush_artifacts(artifacts, cfg, wait=True)
        self._packages(packages, cfg)
        pool.shutdown(wait=True)
        ctx.progress(self.name, "ищу дубликаты…")
        self._duplicates(by_size, ctx)
        self._overview(top, denied)
        ctx.progress(self.name, f"{self.files:,} файлов, {human_bytes(self.bytes)}".replace(",", " "))

    # --- видео-папки --------------------------------------------------------------------------

    def _video_dir(self, d: str, videos, cfg) -> Finding | None:
        total = sum(v[1] for v in videos)
        if total < max(cfg.big_file_mb * MB, 1024**3):
            return None
        names = [os.path.basename(v[0]) for v in videos]
        dash_share = sum(1 for n in names if is_dashcam_name(n)) / len(names)
        dashcam = dash_share >= 0.5 or bool(DASHCAM_DIR_RX.match(os.path.basename(d)))
        first = min(v[2] for v in videos)
        last = max(v[2] for v in videos)
        paths = [v[0] for v in videos]
        n = len(videos)
        span = f"{fmt_date(first)[:10]} — {fmt_date(last)[:10]}"
        cloud = is_cloud_synced(d)
        age = time.time() - last
        camera_share = sum(1 for n in names if CAMERA_RX.search(n)) / len(names)
        if camera_share >= 0.5 and not dashcam:
            title = f"Видео с камеры/телефона: {n} {plural(n, 'файл', 'файла', 'файлов')} в {os.path.basename(d)}"
            return Finding(
                id=f"videodir:{d}", scanner=self.name, resource=Resource.DISK, title=title, location=short_path(d),
                bytes=total, risk=Risk.PERSONAL, confidence=0.15, tags=["media", "video", "personal"],
                what="Исходные видео с телефона/камеры (имена IMG_, VID_, DJI_, GOPR…).",
                origin=f"Скопировано с устройства. Период: {span}.",
                danger="Личные съёмки — возможно, единственная копия. Удаляйте, только если они есть в Фото/облаке.",
                facts=[("Папка", short_path(d)), ("Файлов", str(n)), ("Период", span),
                       ("Примеры", "\n".join(sorted(names)[:6]))],
                actions=[reveal_action(d)], paths=[d], modified=last, created=first,
            )
        if dashcam:
            title = f"Записи видеорегистратора: {n} {plural(n, 'файл', 'файла', 'файлов')} в {os.path.basename(d)}"
            conf = 0.7 if age > 30 * 86400 else 0.5
            what = ("Серия видеофайлов с именами в формате видеорегистратора (дата_время, F/R — передняя/задняя "
                    "камера, NORMAL/EVENT/PARKING). Регистратор пишет непрерывно короткими роликами.")
            origin = (f"Скопировано с карты памяти регистратора. Период записей: {span}. Обычно такие записи "
                      "нужны, только если в них попал важный эпизод.")
            danger = ("Сначала сохраните отдельно ролики с важными событиями (ДТП, спорные ситуации) — обычно "
                      "они в папке EVENT/EMR. Остальное — поток рутинной езды.")
            tags = ["media", "video", "dashcam"]
        else:
            title = f"Папка с видео: {n} {plural(n, 'файл', 'файла', 'файлов')} в {os.path.basename(d)}"
            conf = 0.35
            what = "Папка, в которой лежит много видеофайлов."
            origin = f"Период: {span}."
            danger = "Посмотрите, что за видео: личные съёмки могут быть единственной копией."
            tags = ["media", "video"]
        if age > cfg.stale_days * 86400:
            conf = min(conf + 0.15, 0.9)
            origin += f" Последнее изменение {human_duration(age)} назад."
        if cloud:
            danger += f" **Папка в {cloud}: удаление удалит файлы и из облака.**"
        return Finding(
            id=f"videodir:{d}", scanner=self.name, resource=Resource.DISK, title=title, location=short_path(d),
            bytes=total, risk=Risk.CAUTION, confidence=conf, tags=tags, what=what, origin=origin, danger=danger,
            facts=[("Папка", short_path(d)), ("Файлов", str(n)), ("Период", span),
                   ("Примеры", "\n".join(sorted(names)[:6]))],
            actions=[trash_action(paths, f"Удалить {n} видеофайлов в Корзину"), reveal_action(d)],
            paths=[d], modified=last, created=first,
        )

    # --- артефакты сборки ---------------------------------------------------------------------

    def _flush_artifacts(self, artifacts, cfg, wait: bool) -> None:
        out = []
        for proj, items in artifacts.items():
            if not wait and not all(f.done() for _, _, f in items):
                continue
            sizes = [(p, n, f.result()) for p, n, f in items]
            total = sum(s for _, _, s in sizes)
            if total < cfg.min_dir_mb * MB:
                continue
            touched = project_touched(proj, {n for _, n, _ in sizes})
            age = time.time() - touched if touched else 0
            if age > cfg.stale_days * 86400:
                conf, state = 0.9, f"Проект не менялся {human_duration(age)} — заброшен?"
            elif age > 30 * 86400:
                conf, state = 0.7, f"Проект не менялся {human_duration(age)}."
            else:
                conf, state = 0.3, f"Проект менялся {human_duration(age)} назад — активный."
            kinds = sorted({n for _, n, _ in sizes})
            hints = sorted({rebuild_hint(n) for n in kinds})
            out.append(Finding(
                id=f"artifacts:{proj}", scanner=self.name, resource=Resource.DISK,
                title=f"Артефакты сборки в {os.path.basename(proj)} ({', '.join(kinds)})",
                location=short_path(proj), bytes=total, risk=Risk.REBUILDABLE, confidence=conf,
                tags=["dev", "build"] + (["заброшено"] if conf >= 0.9 else []),
                what=("Зависимости и результаты сборки проекта: " + ", ".join(kinds) + ". Это не исходники — "
                      "всё восстанавливается командами сборки."),
                origin=f"Появляются при установке зависимостей и сборке. {state}",
                danger=f"Пересоздаётся: {'; '.join(hints)}. Нужен интернет для скачивания зависимостей.",
                facts=[("Проект", short_path(proj)), ("Последнее изменение исходников", fmt_date(touched))]
                + [(short_path(p).removeprefix(short_path(proj) + "/"), human_bytes(s))
                   for p, _, s in sorted(sizes, key=lambda x: -x[2])[:12]],
                actions=[trash_action([p for p, _, _ in sizes], "Удалить артефакты в Корзину"), reveal_action(proj)],
                paths=[p for p, _, _ in sizes], modified=touched,
            ))
        if out:
            self.ctx.store.upsert(out)

    # --- пакеты (медиатеки, ВМ, программы вне /Applications) ----------------------------------

    def _packages(self, packages, cfg) -> None:
        out = []
        for path, fut in packages:
            size = fut.result()
            if size < cfg.big_file_mb * MB:
                continue
            name = os.path.basename(path)
            mtime = os.stat(path).st_mtime
            if name.endswith(VM_SUFFIXES):
                f = Finding(
                    id=f"pkg:{path}", scanner=self.name, resource=Resource.DISK,
                    title=f"Виртуальная машина {name}", location=short_path(path), bytes=size, risk=Risk.PERSONAL,
                    confidence=0.35, tags=["vm"], what="Пакет виртуальной машины (диск + настройки).",
                    origin="Создан в UTM/Parallels/VMware/VirtualBox.", danger="Вместе с ВМ пропадут данные внутри.",
                    facts=[("Путь", short_path(path))], actions=[trash_action([path]), reveal_action(path)],
                    paths=[path], modified=mtime)
            elif name.endswith(".app"):
                f = Finding(
                    id=f"pkg:{path}", scanner=self.name, resource=Resource.DISK,
                    title=f"Программа вне «Программ»: {name}", location=short_path(path), bytes=size,
                    risk=Risk.CAUTION, confidence=0.55, tags=["app"],
                    what="Приложение, лежащее не в /Applications (часто — распакованное из архива в «Загрузках» "
                         "или копия).", origin="Скачано/распаковано и запущено прямо из этой папки.",
                    danger="Если это единственная копия программы — её придётся скачать снова.",
                    facts=[("Путь", short_path(path))], actions=[trash_action([path]), reveal_action(path)],
                    paths=[path], modified=mtime)
            else:
                f = Finding(
                    id=f"pkg:{path}", scanner=self.name, resource=Resource.DISK,
                    title=f"Медиатека/проект {name}", location=short_path(path), bytes=size, risk=Risk.PERSONAL,
                    confidence=0.05, tags=["media", "personal"],
                    what="Библиотека приложения (Фото, Музыка, iMovie, Final Cut, Logic, GarageBand…).",
                    origin="Личные медиаданные. Показано, чтобы было видно, куда ушло место.",
                    danger="Не удаляйте целиком. Чистить — внутри соответствующего приложения (например, в Фото "
                           "включить «Оптимизировать хранилище»).",
                    facts=[("Путь", short_path(path))], actions=[reveal_action(path)], paths=[path], modified=mtime)
            out.append(f)
        if out:
            self.ctx.store.upsert(out)

    # --- дубликаты ----------------------------------------------------------------------------

    def _duplicates(self, by_size, ctx: ScanContext) -> None:
        out = []
        for size, items in by_size.items():
            if len(items) < 2:
                continue
            by_hash: dict[str, list] = defaultdict(list)
            for path, alloc, mtime in items:
                if ctx.stop.is_set():
                    return
                h = partial_hash(path, size)
                if h:
                    by_hash[h].append((path, alloc, mtime))
            for h, group in by_hash.items():
                if len(group) < 2:
                    continue
                group.sort(key=lambda x: x[2])
                keep = group[0]
                extra = sum(a for _, a, _ in group[1:])
                name = os.path.basename(keep[0])
                out.append(Finding(
                    id=f"dup:{h}", scanner=self.name, resource=Resource.DISK,
                    title=f"Дубликаты: {name} × {len(group)}", location=short_path(keep[0]), bytes=extra,
                    risk=Risk.CAUTION, confidence=0.75, tags=["duplicate"],
                    what=f"{len(group)} одинаковых файла по {human_bytes(size)} (совпали размер и выборочные хеши "
                         "начала, середины и конца файла).",
                    origin="Обычно — повторное скачивание, копия при переносе или импорте.",
                    danger="Удаляйте лишние копии, оставив одну. Если копии сделаны в APFS через «Дублировать», "
                           "они могут делить место на диске, и удаление освободит меньше, чем показано.",
                    facts=[(f"Копия {i + 1}", f"{short_path(p)} (изменён {fmt_date(m)})")
                           for i, (p, _, m) in enumerate(group)],
                    actions=[trash_action([p], f"Удалить копию: {short_path(p)}") for p, _, _ in group[1:]]
                    + [reveal_action(keep[0])],
                    paths=[p for p, _, _ in group[1:]],
                ))
        if out:
            ctx.store.upsert(out)

    def _overview(self, top: dict[str, int], denied: int) -> None:
        items = sorted(top.items(), key=lambda kv: -kv[1])
        facts = [(f"~/{k}" if not k.startswith("(") else k, human_bytes(v)) for k, v in items[:25]]
        if denied:
            facts.append(("Нет доступа к папкам", f"{denied} — дайте терминалу «Полный доступ к диску» для полной картины"))
        self.ctx.store.upsert([Finding(
            id="walk:overview", scanner=self.name, resource=Resource.INFO,
            title=f"Обзор домашней папки: {human_bytes(self.bytes)} в {self.files:,} файлах".replace(",", " "),
            location="~", risk=Risk.SYSTEM, confidence=0, pinned_score=0.01, tags=["overview"],
            what="Сколько места занимают папки верхнего уровня (без ~/Library — она разобрана отдельно в "
                 "известных местах).",
            origin="", danger="", facts=facts,
        )])


def project_touched(proj: str, artifact_names: set[str]) -> float | None:
    """Когда последний раз меняли исходники проекта: .git/index и верхний уровень папки (без артефактов)."""
    best = None
    for p in (os.path.join(proj, ".git", "index"), os.path.join(proj, ".git", "HEAD"), os.path.join(proj, ".git", "logs", "HEAD")):
        try:
            m = os.stat(p).st_mtime
            best = m if best is None or m > best else best
        except OSError:
            pass
    try:
        with os.scandir(proj) as it:
            for e in it:
                if e.name in artifact_names or e.name in (".git", ".DS_Store", ".idea", ".vscode"):
                    continue
                try:
                    m = e.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                best = m if best is None or m > best else best
                if e.is_dir(follow_symlinks=False) and e.name in ("src", "app", "lib"):
                    for sub in os.scandir(e.path):
                        try:
                            m = sub.stat(follow_symlinks=False).st_mtime
                            best = m if m > best else best
                        except OSError:
                            pass
    except OSError:
        pass
    return best
