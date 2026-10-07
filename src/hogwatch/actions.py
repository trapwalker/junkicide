"""Исполнение действий. Каждое действие журналируется; удаление — только в Корзину."""

from __future__ import annotations

import os
import shutil
import signal
import time
from dataclasses import dataclass

import psutil

from .journal import Journal
from .model import Action, ActionKind, Finding
from .util import du_bytes, human_bytes, run, short_path


@dataclass
class Result:
    ok: bool
    message: str
    output: str = ""
    freed: int = 0
    resolved: bool = False  # находку можно считать устранённой


def _same_process(pid: int, ctime: float) -> psutil.Process | None:
    try:
        p = psutil.Process(pid)
        if ctime and abs(p.create_time() - ctime) > 1:
            return None  # pid уже занят другим процессом
        return p
    except psutil.Error:
        return None


def kill(pids: list[tuple[int, float]], force: bool, wait: float = 5.0) -> Result:
    procs = [p for pid, ct in pids if (p := _same_process(pid, ct))]
    if not procs:
        return Result(True, "Процесс уже завершён", resolved=True)
    sig = signal.SIGKILL if force else signal.SIGTERM
    errors = []
    for p in procs:
        try:
            p.send_signal(sig)
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            errors.append(f"{p.pid}: нет прав (процесс другого пользователя или системный)")
    _, alive = psutil.wait_procs(procs, timeout=wait)
    if errors:
        return Result(False, "; ".join(errors))
    if alive:
        names = ", ".join(str(p.pid) for p in alive)
        return Result(
            False,
            f"Ещё живы: {names}. Процесс не ответил на SIGTERM за {wait:.0f} с — "
            "можно завершить принудительно (SIGKILL).",
        )
    return Result(True, f"Завершено процессов: {len(procs)} ({sig.name})", resolved=True)


def quit_app(app_name: str, wait: float = 10.0) -> Result:
    code, out, err = run(["osascript", "-e", f'tell application "{app_name}" to quit'], timeout=wait + 20)
    if code != 0:
        return Result(False, f"Приложение не закрылось: {err.strip() or out.strip()}")
    return Result(True, f"{app_name}: отправлена команда выхода", resolved=True)


def _trash_one(path: str) -> tuple[bool, str]:
    if not os.path.lexists(path):
        return True, "уже нет"
    trash_bin = shutil.which("trash") or ("/usr/bin/trash" if os.path.exists("/usr/bin/trash") else None)
    if trash_bin:
        code, out, err = run([trash_bin, path], timeout=600)
        if code == 0 and not os.path.lexists(path):
            return True, ""
    # Запасной путь — Finder (он же умеет «Вернуть» из Корзины)
    escaped = path.replace("\\", "\\\\").replace('"', '\\"')
    code, out, err = run(
        ["osascript", "-e", f'tell application "Finder" to delete (POSIX file "{escaped}" as alias)'], timeout=600
    )
    if code == 0 and not os.path.lexists(path):
        return True, ""
    return False, (err or out).strip() or "не удалось"


def trash(paths: list[str]) -> Result:
    freed = 0
    failed = []
    for p in paths:
        size = du_bytes(p) if os.path.isdir(p) else (os.lstat(p).st_blocks * 512 if os.path.lexists(p) else 0)
        ok, msg = _trash_one(p)
        if ok:
            freed += size
        else:
            failed.append(f"{short_path(p)}: {msg}")
    if failed:
        return Result(bool(freed), "Не всё удалось переместить: " + "; ".join(failed), freed=freed,
                      resolved=False)
    return Result(True, f"В Корзину: {human_bytes(freed)}. Место освободится после очистки Корзины.",
                  freed=freed, resolved=True)


def command(argv: list[str], cwd: str | None = None, timeout: float = 1800) -> Result:
    code, out, err = run(argv, timeout=timeout, cwd=cwd)
    text = (out + ("\n" + err if err else "")).strip()
    if code == 0:
        return Result(True, "Готово: " + " ".join(argv), output=text, resolved=True)
    return Result(False, f"Команда завершилась с кодом {code}: {' '.join(argv)}", output=text)


def trash_size() -> tuple[int, int | None]:
    """(байт, количество объектов или None, если нет доступа)."""
    from .util import HOME

    tpath = HOME / ".Trash"
    try:
        n = len(os.listdir(tpath))
        return du_bytes(tpath), n
    except PermissionError:
        # Без Full Disk Access каталог закрыт — спросим Finder
        code, out, _ = run(["osascript", "-e", 'tell application "Finder" to count items of trash'], timeout=20)
        try:
            n = int(out.strip())
        except ValueError:
            n = None
        return 0, n
    except OSError:
        return 0, 0


def empty_trash() -> Result:
    before = psutil.disk_usage("/").free
    code, out, err = run(
        ["osascript", "-e", 'tell application "Finder" to empty trash'], timeout=3600
    )
    time.sleep(1)
    freed = max(psutil.disk_usage("/").free - before, 0)
    if code != 0:
        return Result(False, f"Не удалось очистить Корзину: {(err or out).strip()}")
    return Result(True, f"Корзина очищена, освобождено ≈ {human_bytes(freed)}", freed=freed, resolved=True)


def execute(action: Action, finding: Finding | None, journal: Journal) -> Result:
    target = finding.title if finding else ""
    k = action.kind
    try:
        if k == ActionKind.KILL:
            res = kill(action.pids, action.force)
        elif k == ActionKind.QUIT_APP:
            res = quit_app(action.app_name or "")
        elif k == ActionKind.TRASH:
            res = trash(action.paths)
        elif k in (ActionKind.COMMAND, ActionKind.SHOW):
            res = command(action.argv, action.cwd)
            if k == ActionKind.SHOW:
                res.resolved = False
        elif k == ActionKind.EMPTY_TRASH:
            res = empty_trash()
        elif k == ActionKind.REVEAL:
            path = action.paths[0] if action.paths else ""
            code, _, err = run(["open", "-R", path])
            res = Result(code == 0, "Показано в Finder" if code == 0 else err.strip())
        else:
            res = Result(False, f"Неизвестное действие {k}")
    except Exception as e:  # действие не должно ронять интерфейс
        res = Result(False, f"Ошибка: {e!r}")
    if k not in (ActionKind.REVEAL, ActionKind.SHOW):
        journal.log(
            "action" if res.ok else "error",
            f"action.{k}",
            f"{action.label} — {target}: {res.message}",
            finding=finding.id if finding else None,
            paths=action.paths,
            pids=[p for p, _ in action.pids],
            argv=action.argv,
            freed=res.freed,
            ok=res.ok,
        )
    return res
