"""Docker: работающие контейнеры (CPU/память) и место под образы, тома, кэш сборки."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime

import psutil

from ..model import Action, ActionKind, Finding, Resource, Risk
from ..util import human_bytes, human_duration, newest_mtime, run, short_path, which
from .base import ScanContext, Scanner

MB = 1024**2
_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
          "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4}
_VM_RX = re.compile(r"(OrbStack Helper|com\.docker\.(backend|virtualization)|limactl|colima|gvproxy|vfkit)", re.I)


def parse_size(s: str) -> int:
    m = re.match(r"\s*([\d.]+)\s*([a-zA-Z]*)", s or "")
    if not m:
        return 0
    return int(float(m.group(1)) * _UNITS.get(m.group(2).lower() or "b", 1))


def parse_labels(s: str) -> dict[str, str]:
    out = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def parse_created(s: str) -> float | None:
    try:
        return datetime.strptime(s[:25], "%Y-%m-%d %H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        return None


def docker_vm_running() -> bool:
    for p in psutil.process_iter(["name", "exe"]):
        try:
            if _VM_RX.search((p.info.get("exe") or "") + " " + (p.info.get("name") or "")):
                return True
        except psutil.Error:
            continue
    return False


def _jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


class DockerScanner(Scanner):
    name = "docker"
    title = "Docker"
    interval = 30.0

    def run(self, ctx: ScanContext) -> None:
        docker = which("docker", "~/.orbstack/bin/docker", "/usr/local/bin/docker", "/opt/homebrew/bin/docker")
        if not docker:
            ctx.progress(self.name, "docker не установлен")
            return
        # Не дёргаем docker CLI, если ВМ не запущена: OrbStack/Desktop могут запуститься от вызова.
        if not docker_vm_running():
            ctx.progress(self.name, "Docker не запущен")
            return
        code, _, err = run([docker, "version", "--format", "{{.Server.Version}}"], timeout=8)
        if code != 0:
            ctx.progress(self.name, "демон Docker не отвечает")
            return
        findings = self._containers(docker, ctx)
        findings += self._disk(docker, ctx)
        ctx.store.upsert(findings)

    # --- контейнеры ---------------------------------------------------------------------------

    def _containers(self, docker: str, ctx: ScanContext) -> list[Finding]:
        _, out, _ = run([docker, "ps", "--format", "{{json .}}"], timeout=15)
        ps = {c["ID"]: c for c in _jsonl(out)}
        if not ps:
            return []
        _, out, _ = run([docker, "stats", "--no-stream", "--format", "{{json .}}"], timeout=20)
        stats = {s["ID"][:12]: s for s in _jsonl(out)}
        res = []
        now = time.time()
        for cid, c in ps.items():
            s = stats.get(cid[:12], {})
            cpu = float((s.get("CPUPerc") or "0").rstrip("%") or 0)
            mem = parse_size((s.get("MemUsage") or "0").split("/")[0])
            labels = parse_labels(c.get("Labels", ""))
            project = labels.get("com.docker.compose.project")
            workdir = labels.get("com.docker.compose.project.working_dir")
            created = parse_created(c.get("CreatedAt", ""))
            touched = newest_mtime(workdir, 2000) if workdir and os.path.isdir(workdir) else None
            conf = 0.35
            notes = []
            if touched and now - touched > 14 * 86400:
                conf += 0.3
                notes.append(f"Файлы проекта `{short_path(workdir)}` не менялись {human_duration(now - touched)} — "
                             "похоже, контейнер просто забыли остановить.")
            elif workdir and not os.path.isdir(workdir):
                conf += 0.35
                notes.append(f"Папки проекта `{short_path(workdir)}` уже нет.")
            if cpu >= 10 and created and now - created > 86400:
                notes.append(f"Постоянная нагрузка {cpu:.0f}% CPU у контейнера, работающего "
                             f"{c.get('RunningFor', '')} — проверьте, не крутится ли там фоновая задача/цикл.")
            if cpu < 3 and mem < 150 * MB and conf < 0.6:
                continue  # тихий маленький контейнер — не шум
            name = c.get("Names", cid)
            acts = [Action(ActionKind.COMMAND, f"Остановить контейнер ({name})",
                           "`docker stop` — штатная остановка (SIGTERM, затем SIGKILL через 10 с). Данные в томах "
                           "сохраняются, контейнер можно снова запустить `docker start`.",
                           argv=[docker, "stop", name])]
            if project:
                acts.append(Action(ActionKind.COMMAND, f"Остановить весь compose-проект «{project}»",
                                   f"`docker compose -p {project} stop` — остановит все сервисы проекта.",
                                   argv=[docker, "compose", "-p", project, "stop"]))
            facts = [
                ("Образ", c.get("Image", "")), ("Статус", c.get("Status", "")), ("CPU", f"{cpu:.0f}%"),
                ("Память", s.get("MemUsage", "?")), ("Порты", c.get("Ports") or "—"),
                ("Диск (чтение/запись)", s.get("BlockIO", "?")), ("Сеть", s.get("NetIO", "?")),
            ]
            if project:
                facts.append(("Compose-проект", project))
            if workdir:
                facts.append(("Папка проекта", short_path(workdir)))
            if touched:
                facts.append(("Проект менялся", human_duration(now - touched) + " назад"))
            res.append(Finding(
                id=f"docker:container:{cid}", scanner=self.name,
                resource=Resource.CPU if cpu / 100 * 2 >= mem / 1024**3 * 1.5 else Resource.MEMORY,
                title=f"Контейнер {name}", location=c.get("Image", ""), bytes=mem, cpu=cpu,
                risk=Risk.SAFE, confidence=min(conf, 0.9), tags=["docker", "dev"] + (["забытое"] if conf >= 0.6 else []),
                what=f"Работающий Docker-контейнер из образа `{c.get('Image')}`"
                     + (f", сервис «{labels.get('com.docker.compose.service')}» compose-проекта «{project}»"
                        if project else "") + ".",
                origin=("Запущен `docker compose up` / `docker run`. Контейнеры с `restart: always/unless-stopped` "
                        "поднимаются заново при каждом старте Docker — поэтому живут неделями незаметно.\n\n"
                        + "\n\n".join(notes)).strip(),
                danger="Остановка безопасна для данных в томах; несохранённое состояние в памяти пропадёт. "
                       "Сервис станет недоступен до следующего запуска.",
                facts=facts, actions=acts, started=created,
            ))
        return res

    # --- диск ---------------------------------------------------------------------------------

    def _disk(self, docker: str, ctx: ScanContext) -> list[Finding]:
        code, out, _ = run([docker, "system", "df", "-v", "--format", "{{json .}}"], timeout=120)
        if code != 0:
            return []
        try:
            d = json.loads(out)
        except ValueError:
            return []
        res: list[Finding] = []
        min_b = ctx.config.min_dir_mb * MB
        now = time.time()

        unused = [i for i in d.get("Images") or [] if str(i.get("Containers", "0")) in ("0", "")]
        total_unused = sum(parse_size(i.get("UniqueSize") or i.get("Size")) for i in unused)
        if total_unused >= min_b:
            top = sorted(unused, key=lambda i: -parse_size(i.get("UniqueSize") or i.get("Size")))
            res.append(Finding(
                id="docker:images:unused", scanner=self.name, resource=Resource.DISK,
                title=f"Неиспользуемые образы Docker × {len(unused)}", location="docker images",
                bytes=total_unused, risk=Risk.REBUILDABLE, confidence=0.7, tags=["docker", "dev", "cache"],
                what="Образы, из которых сейчас не создан ни один контейнер (даже остановленный).",
                origin="Копятся от `docker pull`, пересборок (`docker build` оставляет старые версии как "
                       "<none>), экспериментов с разными тегами и версиями.",
                danger="Безопасно для данных. Если образ понадобится — он будет скачан/собран заново "
                       "(трафик и время). Локально собранные образы без Dockerfile восстановить нельзя.",
                facts=[(f"{i.get('Repository')}:{i.get('Tag')}",
                        f"{human_bytes(parse_size(i.get('UniqueSize') or i.get('Size')))}, создан "
                        f"{i.get('CreatedSince', '')}") for i in top[:15]],
                actions=[Action(ActionKind.COMMAND, "Удалить все неиспользуемые образы (docker image prune -a)",
                                "Удалит образы без контейнеров. Необратимо, но восстанавливается скачиванием.",
                                argv=[docker, "image", "prune", "-a", "-f"])],
            ))
        bc = d.get("BuildCache") or []
        bc_size = sum(parse_size(b.get("Size", "0")) for b in bc if str(b.get("InUse", "false")).lower() != "true")
        if bc_size >= min_b:
            res.append(Finding(
                id="docker:buildcache", scanner=self.name, resource=Resource.DISK, title="Кэш сборки Docker",
                location="docker builder", bytes=bc_size, risk=Risk.SAFE, confidence=0.85,
                tags=["docker", "dev", "cache"],
                what="Промежуточные слои BuildKit, ускоряющие повторные `docker build`.",
                origin="Накапливается при каждой сборке образов; сам почти не чистится.",
                danger="Безопасно: следующая сборка будет медленнее, пока кэш не наполнится снова.",
                actions=[Action(ActionKind.COMMAND, "Очистить кэш сборки (docker builder prune)",
                                "Удалит неиспользуемый кэш сборки.", argv=[docker, "builder", "prune", "-f"])],
            ))
        stopped = [c for c in d.get("Containers") or [] if c.get("State") not in ("running", "paused")]
        st_size = sum(parse_size(c.get("Size", "0")) for c in stopped)
        if stopped and st_size >= min_b:
            res.append(Finding(
                id="docker:containers:stopped", scanner=self.name, resource=Resource.DISK,
                title=f"Остановленные контейнеры × {len(stopped)}", location="docker ps -a", bytes=st_size,
                risk=Risk.CAUTION, confidence=0.6, tags=["docker", "dev"],
                what="Контейнеры, которые не работают, но хранят свой записываемый слой (изменения внутри "
                     "контейнера, не в томах).",
                origin="Остаются после `docker run` без `--rm`, после `docker compose stop`, упавших запусков.",
                danger="Изменения внутри контейнеров (не в томах) пропадут. Тома не удаляются.",
                facts=[(c.get("Names", ""), f"{c.get('Image')}, {c.get('Status')}, {c.get('Size')}")
                       for c in stopped[:15]],
                actions=[Action(ActionKind.COMMAND, "Удалить остановленные контейнеры (docker container prune)",
                                "Необратимо удалит остановленные контейнеры.",
                                argv=[docker, "container", "prune", "-f"])],
            ))
        for v in d.get("Volumes") or []:
            size = parse_size(v.get("Size", "0"))
            if str(v.get("Links", "0")) != "0" or size < min_b:
                continue
            labels = parse_labels(v.get("Labels", ""))
            proj = labels.get("com.docker.compose.project")
            anon = "com.docker.volume.anonymous" in labels
            res.append(Finding(
                id=f"docker:volume:{v['Name']}", scanner=self.name, resource=Resource.DISK,
                title=f"Том Docker без контейнера: {v['Name'][:40]}", location=f"docker volume {v['Name']}",
                bytes=size, risk=Risk.PERSONAL if not anon else Risk.CAUTION, confidence=0.45 if not anon else 0.7,
                tags=["docker", "data"],
                what="Том с данными, к которому не подключён ни один контейнер. Обычно это данные БД, "
                     "загрузки, кэши сервисов." + (" Анонимный том (без имени) — создан автоматически." if anon else ""),
                origin=(f"Принадлежал compose-проекту «{proj}». " if proj else "")
                       + "Остаётся после удаления контейнеров (`docker compose down` без `-v`).",
                danger="**Необратимо**: удаление тома не проходит через Корзину. Если там была база данных "
                       "проекта — она пропадёт. Убедитесь, что проект больше не нужен.",
                facts=[("Имя", v["Name"]), ("Размер", v.get("Size", "")), ("Метки", v.get("Labels") or "—")],
                actions=[Action(ActionKind.COMMAND, "Удалить том (docker volume rm)",
                                "НЕОБРАТИМО удалит том со всеми данными.", argv=[docker, "volume", "rm", v["Name"]])],
                found_at=now,
            ))
        return res
