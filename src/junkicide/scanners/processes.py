"""Процессы: кто греет CPU и съел память. Сглаженная загрузка, группировка по приложениям, браузерные вкладки."""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict

import psutil

from ..knowledge.processes import (
    RULES,
    SYSTEM_PREFIXES,
    Proc,
    ProcRule,
    force_action,
    quit_app_action,
    term_action,
)
from ..model import Action, ActionKind, Finding, Resource, Risk
from ..util import fmt_date, human_bytes, human_duration, short_path
from .base import ScanContext, Scanner

MB = 1024**2
ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
FIREFOX_SITE = re.compile(r"(?:webIsolated|webCOOP\+COEP|webServiceWorker)=(\S+)")


def app_of(exe: str) -> tuple[str | None, str | None]:
    i = exe.find(".app/")
    if i < 0:
        return None, None
    path = exe[: i + 4]
    return path, os.path.basename(path)[:-4]


class ProcessScanner(Scanner):
    name = "processes"
    title = "процессы"
    interval = 3.0

    def __init__(self) -> None:
        self._static: dict[tuple[int, float], dict] = {}
        self._prev: dict[tuple[int, float], tuple[float, float]] = {}  # key → (время, cpu-секунды)
        self._ewma: dict[tuple[int, float], float] = {}
        self._extra: dict[tuple[int, float], tuple[float, str | None, list[int]]] = {}  # cwd/порты с отметкой
        self._me = psutil.Process().username()
        self._my_pid = os.getpid()

    # --- сбор ---------------------------------------------------------------------------------

    def _sample(self) -> list[Proc]:
        now = time.time()
        procs: list[Proc] = []
        alive = set()
        for p in psutil.process_iter():
            try:
                with p.oneshot():
                    ctime = p.create_time()
                    key = (p.pid, ctime)
                    alive.add(key)
                    st = self._static.get(key)
                    if st is None:
                        st = p.as_dict(ATTRS, ad_value=None)
                        self._static[key] = st
                    try:
                        ct = p.cpu_times()
                        cpu_s = ct.user + ct.system
                        rss = p.memory_info().rss
                    except psutil.AccessDenied:
                        cpu_s, rss = None, 0
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                continue
            cpu = 0.0
            if cpu_s is not None:
                prev = self._prev.get(key)
                if prev:
                    dt = now - prev[0]
                    inst = max(cpu_s - prev[1], 0) / dt * 100 if dt > 0 else 0.0
                    old = self._ewma.get(key)
                    cpu = inst if old is None else old * 0.5 + inst * 0.5
                    self._ewma[key] = cpu
                self._prev[key] = (now, cpu_s)
            life = max(now - ctime, 1)
            exe = st.get("exe") or ""
            app_path, app_name = app_of(exe)
            procs.append(Proc(
                pid=p.pid, ppid=st.get("ppid") or 0, name=st.get("name") or "", exe=exe,
                cmdline=st.get("cmdline") or [], username=st.get("username") or "", create_time=ctime,
                rss=rss, cpu=cpu, cpu_life=(cpu_s or 0) / life * 100, app_path=app_path, app_name=app_name,
                mine=(st.get("username") == self._me),
            ))
        for d in (self._static, self._prev, self._ewma, self._extra):
            for k in [k for k in d if k not in alive]:
                del d[k]
        return procs

    def _enrich(self, p: Proc) -> None:
        """cwd и прослушиваемые порты — только для попавших в находки процессов, с кэшем на минуту."""
        if not p.mine:
            return
        cached = self._extra.get(p.key)
        if cached and time.time() - cached[0] < 60:
            _, p.cwd, p.ports = cached
            return
        cwd, ports = None, []
        try:
            proc = psutil.Process(p.pid)
            cwd = proc.cwd()
            ports = sorted({c.laddr.port for c in proc.net_connections("inet") if c.status == "LISTEN"})
        except (psutil.Error, OSError):
            pass
        p.cwd, p.ports = cwd, ports
        self._extra[p.key] = (time.time(), cwd, ports)

    # --- анализ -------------------------------------------------------------------------------

    def run(self, ctx: ScanContext) -> None:
        procs = self._sample()
        if not self._ewma:  # первый запуск: быстро снять второй замер, чтобы сразу была загрузка CPU
            time.sleep(1.0)
            procs = self._sample()
        procs = [p for p in procs if p.pid != self._my_pid]
        by_pid = {p.pid: p for p in procs}
        cfg = ctx.config
        findings: list[Finding] = []
        used: set[int] = set()

        # 1. Известные случаи
        grouped: dict[str, list[Proc]] = defaultdict(list)
        single: list[tuple[ProcRule, Proc]] = []
        for p in procs:
            for rule in RULES:
                try:
                    hit = rule.match(p)
                except Exception:
                    hit = False
                if hit:
                    if rule.group:
                        grouped[rule.id].append(p)
                    else:
                        single.append((rule, p))
                    used.add(p.pid)
                    break
        rules = {r.id: r for r in RULES}
        for rid, ps in grouped.items():
            if f := self._rule_finding(rules[rid], ps, cfg, by_pid):
                findings.append(f)
        for rule, p in single:
            if f := self._rule_finding(rule, [p], cfg, by_pid):
                findings.append(f)

        # 2. Браузеры
        apps: dict[str, list[Proc]] = defaultdict(list)
        for p in procs:
            if p.pid not in used:
                apps[p.app_path or p.exe or p.name].append(p)
        for key, ps in list(apps.items()):
            if any("--type=renderer" in x.cmdline for x in ps):
                findings.extend(self._chromium(ps, cfg, by_pid))
                del apps[key]
            elif any(x.name in ("firefox", "plugin-container") or "Firefox" in (x.app_name or "") for x in ps) \
                    and any("-contentproc" in x.cmdline for x in ps):
                findings.extend(self._firefox(ps, cfg, by_pid))
                del apps[key]

        # 3. Всё остальное, сгруппированное по приложениям
        for ps in apps.values():
            cpu = sum(p.cpu for p in ps)
            rss = sum(p.rss for p in ps)
            if cpu >= cfg.cpu_percent or rss >= cfg.app_memory_mb * MB:
                findings.append(self._generic(ps, cfg, by_pid))

        ctx.store.replace_scanner(self.name, findings)
        ctx.system["proc_count"] = len(procs)
        ctx.system["top_cpu"] = sorted(procs, key=lambda p: -p.cpu)[:5]

    # --- конструкторы находок ------------------------------------------------------------------

    def _resource(self, cpu: float, rss: int) -> Resource:
        return Resource.CPU if cpu / 100 * 2 >= rss / 1024**3 * 1.5 else Resource.MEMORY

    def _facts(self, ps: list[Proc], by_pid: dict[int, Proc]) -> list[tuple[str, str]]:
        p = max(ps, key=lambda x: x.rss + x.cpu * 20 * MB)
        facts: list[tuple[str, str]] = []
        if len(ps) > 1:
            facts.append(("Процессов", str(len(ps))))
            facts.append(("PID", ", ".join(str(x.pid) for x in sorted(ps, key=lambda x: -x.rss)[:12])
                          + (" …" if len(ps) > 12 else "")))
        else:
            facts.append(("PID", str(p.pid)))
        facts.append(("Пользователь", p.username or "?"))
        oldest = min(x.create_time for x in ps)
        facts.append(("Запущен", f"{fmt_date(oldest)} ({human_duration(time.time() - oldest)} назад)"))
        facts.append(("CPU сейчас", f"{sum(x.cpu for x in ps):.0f}% (100% = одно ядро из {psutil.cpu_count()})"))
        facts.append(("CPU в среднем за жизнь", f"{max(x.cpu_life for x in ps):.0f}%"))
        facts.append(("Память (RSS)", human_bytes(sum(x.rss for x in ps))))
        parent = by_pid.get(p.ppid)
        if p.ppid == 1:
            facts.append(("Родитель", "launchd (PPID 1) — запустивший процесс уже завершился или это служба"))
        elif parent:
            facts.append(("Родитель", f"{parent.name} (PID {parent.pid})"))
        if p.cwd and p.cwd != "/":
            facts.append(("Рабочая папка", short_path(p.cwd)))
        if p.ports:
            facts.append(("Слушает порты", ", ".join(map(str, p.ports[:15]))))
        facts.append(("Программа", short_path(p.exe or p.name)))
        if p.cmdline:
            facts.append(("Команда", short_path(p.cmd)[:400]))
        return facts

    def _rule_finding(self, rule: ProcRule, ps: list[Proc], cfg, by_pid) -> Finding | None:
        cpu = sum(p.cpu for p in ps)
        rss = sum(p.rss for p in ps)
        min_cpu = rule.min_cpu or cfg.cpu_percent
        min_mem = rule.min_mem or cfg.app_memory_mb * MB
        if rule.always:
            show = rss >= rule.min_mem or cpu >= min_cpu
        else:
            show = cpu >= min_cpu or rss >= min_mem
        if not show:
            return None
        for p in ps:
            self._enrich(p)
        main = max(ps, key=lambda x: x.rss)
        conf = rule.confidence
        orphan = all(p.ppid == 1 for p in ps) and not rule.system and not main.app_path
        origin = rule.origin
        if orphan and rule.always:
            conf = min(conf + 0.1, 0.98)
            origin += "\n\n**Сейчас:** родительский процесс уже завершён (PPID 1)" + (
                f", рабочая папка — `{short_path(main.cwd)}`." if main.cwd and main.cwd != "/" else ".")
        age = time.time() - min(p.create_time for p in ps)
        if rule.always and age > 6 * 3600:
            conf = min(conf + 0.05, 0.98)
        acts = rule.actions(ps) if rule.actions else []
        if not rule.system and not acts:
            acts = [term_action(ps), force_action(ps)]
        key = f"rule:{rule.id}" if rule.group else f"rule:{rule.id}:{main.pid}:{main.create_time:.0f}"
        tags = list(rule.tags)
        if orphan:
            tags.append("сирота")
        return Finding(
            id=key, scanner=self.name, resource=self._resource(cpu, rss), title=rule.title(ps),
            location=short_path(main.cmd)[:200], bytes=rss, cpu=cpu,
            risk=rule.risk if (main.mine or rule.system) else Risk.SYSTEM,
            confidence=conf, tags=tags, what=rule.what, origin=origin, danger=rule.danger,
            facts=self._facts(ps, by_pid), actions=acts, started=min(p.create_time for p in ps),
        )

    def _generic(self, ps: list[Proc], cfg, by_pid) -> Finding:
        main = max(ps, key=lambda x: x.rss + x.cpu * 20 * MB)
        for p in ps:
            self._enrich(p)
        cpu = sum(p.cpu for p in ps)
        rss = sum(p.rss for p in ps)
        age = time.time() - min(p.create_time for p in ps)
        system = (not main.mine) or (main.exe or "").startswith(SYSTEM_PREFIXES)
        is_app = bool(main.app_path)
        name = main.app_name or main.name
        orphan = main.ppid == 1 and not is_app and main.cwd not in (None, "/")
        tags = []
        conf = 0.3
        if is_app:
            what = f"Приложение «{name}»" + (f" — {len(ps)} процессов (основной и вспомогательные)"
                                             if len(ps) > 1 else "") + "."
            origin = f"Запущено {human_duration(age)} назад."
            danger = ("При штатном закрытии приложение предложит сохранить данные. Принудительное "
                      "завершение может потерять несохранённое.")
            risk = Risk.CAUTION
            tags.append("app")
        else:
            what = f"Программа `{short_path(main.exe or main.name)}`."
            origin = f"Работает {human_duration(age)}."
            danger = "Работа процесса прервётся; если это чья-то задача (сборка, сервер) — её придётся перезапустить."
            risk = Risk.CAUTION
        if orphan:
            origin += (f" Родительский процесс уже завершился (PPID 1), рабочая папка — `{short_path(main.cwd)}`: "
                       "вероятно, запущен из терминала, IDE или AI-агента и забыт.")
            conf += 0.3
            tags.append("сирота")
        if main.cpu_life > 50 and age > 3600:
            origin += f" В среднем за всю жизнь грузит CPU на {main.cpu_life:.0f}% — это не разовый всплеск."
            conf += 0.15
            tags.append("греет")
        if system:
            risk = Risk.SYSTEM
            conf = 0.05
            tags.append("system")
            danger = ("Процесс системный или другого пользователя — завершить без прав администратора нельзя, "
                      "и обычно не нужно: macOS перезапустит его.")
        acts: list[Action] = []
        if not system:
            if is_app and main.app_name:
                acts.append(quit_app_action(main.app_name))
            acts.append(term_action(ps))
            acts.append(force_action(ps))
        if main.app_path:
            acts.append(Action(ActionKind.REVEAL, "Показать приложение в Finder", paths=[main.app_path],
                               destructive=False))
        return Finding(
            id=f"app:{main.app_path or main.exe or main.name}", scanner=self.name,
            resource=self._resource(cpu, rss), title=name + (f" × {len(ps)}" if len(ps) > 1 else ""),
            location=short_path(main.app_path or main.cmd)[:200], bytes=rss, cpu=cpu, risk=risk,
            confidence=min(conf, 0.9), tags=tags, what=what, origin=origin, danger=danger,
            facts=self._facts(ps, by_pid), actions=acts, started=min(p.create_time for p in ps),
        )

    # --- браузеры -----------------------------------------------------------------------------

    def _chromium(self, ps: list[Proc], cfg, by_pid) -> list[Finding]:
        name = ps[0].app_name or "Браузер"
        renderers = [p for p in ps if "--type=renderer" in p.cmdline]
        ext = [p for p in renderers if "--extension-process" in p.cmdline]
        gpu = [p for p in ps if "--type=gpu-process" in p.cmdline]
        main = next((p for p in ps if not any(a.startswith("--type=") for a in p.cmdline)), ps[0])
        cpu = sum(p.cpu for p in ps)
        rss = sum(p.rss for p in ps)
        out: list[Finding] = []
        heavy = sorted([p for p in renderers if p.rss >= 700 * MB or p.cpu >= cfg.cpu_percent],
                       key=lambda p: -(p.rss + p.cpu * 20 * MB))
        show_tabs = Action(
            ActionKind.SHOW, "Показать список открытых вкладок",
            "AppleScript попросит у macOS разрешение управлять браузером (один раз).",
            argv=["osascript", "-e", _chromium_tabs_script(name)], destructive=False,
        )
        hint = (f"Точно узнать, какая вкладка в каком процессе, можно в Диспетчере задач самого браузера: "
                f"окно {name} → **Shift+Esc** (или меню Окно → Диспетчер задач), сортировка по памяти.")
        if cpu >= cfg.cpu_percent or rss >= cfg.app_memory_mb * MB:
            top = sorted(renderers, key=lambda p: -p.rss)[:6]
            f = Finding(
                id=f"browser:{name}", scanner=self.name, resource=self._resource(cpu, rss),
                title=f"{name}: {len(renderers)} процессов вкладок",
                location=short_path(main.app_path or main.exe), bytes=rss, cpu=cpu, risk=Risk.CAUTION,
                confidence=0.35, tags=["browser"],
                what=(f"Браузер {name} на движке Chromium. Каждая вкладка/сайт и каждое расширение живут в "
                      f"отдельном процессе-рендерере, плюс GPU-процесс и служебные. Сейчас рендереров "
                      f"{len(renderers)} (из них расширений {len(ext)})."),
                origin=("Память копится от множества открытых вкладок, «тяжёлых» сайтов (карты, WebGL, "
                        "видео, Figma, дашборды), долго открытых SPA с утечками памяти и расширений.\n\n" + hint),
                danger=("Закрытие браузера закроет все вкладки (Chrome/Яндекс восстанавливают их при запуске, "
                        "если включено «Продолжить с того же места»). Отдельную тяжёлую вкладку лучше выгрузить — "
                        "см. находки «Тяжёлая вкладка»."),
                facts=self._facts([main], by_pid) + [("Всего процессов", str(len(ps))),
                                                     ("Память всех процессов", human_bytes(rss)),
                                                     ("Крупнейшие рендереры", "; ".join(
                                                         f"PID {p.pid}: {human_bytes(p.rss)}, CPU {p.cpu:.0f}%"
                                                         for p in top))],
                actions=[show_tabs, quit_app_action(name)] + (
                    [Action(ActionKind.KILL, f"Выгрузить {len(heavy)} тяжёлых вкладок",
                            "Рендереры будут завершены — на вкладках появится «Опаньки…/Aw, Snap», их можно "
                            "перезагрузить. Несохранённый ввод в формах на этих вкладках пропадёт.",
                            pids=[p.key for p in heavy])] if heavy else []),
                started=main.create_time,
            )
            out.append(f)
        for p in heavy[:8]:
            kind = "Расширение" if p in ext else "Тяжёлая вкладка"
            out.append(Finding(
                id=f"tab:{name}:{p.pid}:{p.create_time:.0f}", scanner=self.name,
                resource=self._resource(p.cpu, p.rss),
                title=f"{kind} {name} (рендерер {p.pid})", location=f"{name} → процесс {p.pid}",
                bytes=p.rss, cpu=p.cpu, risk=Risk.CAUTION, confidence=0.55, tags=["browser", "tab"],
                what=(f"Процесс-рендерер {name}: одна или несколько вкладок одного сайта"
                      + (" (расширение браузера)" if p in ext else "") + "."),
                origin=("Тяжёлые вкладки — карты, 3D/WebGL, видео, онлайн-редакторы, дашборды с автообновлением; "
                        "долгоживущие одностраничные приложения со временем «текут» по памяти.\n\n" + hint),
                danger=("Вкладка покажет страницу сбоя («Опаньки…»), кнопка «Перезагрузить» вернёт её. "
                        "Несохранённый ввод на странице пропадёт."),
                facts=self._facts([p], by_pid), actions=[
                    Action(ActionKind.KILL, "Выгрузить эту вкладку (завершить рендерер)",
                           "Вкладки этого процесса упадут, их можно перезагрузить.", pids=[p.key]),
                    show_tabs],
                started=p.create_time,
            ))
        for p in gpu:
            if p.cpu >= max(cfg.cpu_percent, 40) or p.rss >= 1500 * MB:
                out.append(Finding(
                    id=f"gpu:{name}", scanner=self.name, resource=self._resource(p.cpu, p.rss),
                    title=f"GPU-процесс {name}", location=f"{name} → процесс {p.pid}", bytes=p.rss, cpu=p.cpu,
                    risk=Risk.SAFE, confidence=0.4, tags=["browser", "graphics"],
                    what="Процесс, рисующий всё содержимое браузера через видеоядро.",
                    origin="Нагружают анимации, видео, WebGL/Canvas-страницы, много окон на внешнем мониторе.",
                    danger="Браузер сразу перезапустит GPU-процесс; окна на секунду мигнут.",
                    facts=self._facts([p], by_pid), actions=[term_action([p])], started=p.create_time,
                ))
        return out

    def _firefox(self, ps: list[Proc], cfg, by_pid) -> list[Finding]:
        out: list[Finding] = []
        cpu = sum(p.cpu for p in ps)
        rss = sum(p.rss for p in ps)
        content = [p for p in ps if "-contentproc" in p.cmdline]
        main = next((p for p in ps if "-contentproc" not in p.cmdline), ps[0])
        hint = "Подробно по вкладкам: адресная строка Firefox → `about:processes`."
        if cpu >= cfg.cpu_percent or rss >= cfg.app_memory_mb * MB:
            out.append(Finding(
                id="browser:Firefox", scanner=self.name, resource=self._resource(cpu, rss),
                title=f"Firefox: {len(content)} контент-процессов", location=short_path(main.app_path or main.exe),
                bytes=rss, cpu=cpu, risk=Risk.CAUTION, confidence=0.35, tags=["browser"],
                what="Firefox держит сайты в изолированных контент-процессах (Fission).",
                origin="Много вкладок, тяжёлые сайты, расширения.\n\n" + hint,
                danger="Закрытие закроет все вкладки (сессия восстанавливается при запуске).",
                facts=self._facts([main], by_pid) + [("Память всех процессов", human_bytes(rss))],
                actions=[quit_app_action("Firefox")], started=main.create_time,
            ))
        for p in sorted(content, key=lambda x: -x.rss):
            if not (p.rss >= 700 * MB or p.cpu >= cfg.cpu_percent):
                continue
            m = FIREFOX_SITE.search(p.cmd)
            site = m.group(1) if m else None
            out.append(Finding(
                id=f"tab:Firefox:{p.pid}:{p.create_time:.0f}", scanner=self.name,
                resource=self._resource(p.cpu, p.rss),
                title="Тяжёлая вкладка Firefox" + (f": {site}" if site else f" (процесс {p.pid})"),
                location=site or f"Firefox → процесс {p.pid}", bytes=p.rss, cpu=p.cpu, risk=Risk.CAUTION,
                confidence=0.55, tags=["browser", "tab"],
                what="Контент-процесс Firefox" + (f" сайта {site}" if site else "") + ".",
                origin="Тяжёлый сайт или долго открытая вкладка.\n\n" + hint,
                danger="Вкладка покажет «Вкладка упала», её можно восстановить.",
                facts=self._facts([p], by_pid),
                actions=[Action(ActionKind.KILL, "Выгрузить вкладку (завершить процесс)", pids=[p.key])],
                started=p.create_time,
            ))
        return out


def _chromium_tabs_script(app: str) -> str:
    return (
        'set out to ""\n'
        f'tell application "{app}"\n'
        "  set wi to 0\n"
        "  repeat with w in windows\n"
        "    set wi to wi + 1\n"
        '    set out to out & "— окно " & wi & " —" & linefeed\n'
        "    repeat with t in tabs of w\n"
        '      set out to out & (title of t) & "  " & (URL of t) & linefeed\n'
        "    end repeat\n"
        "  end repeat\n"
        "end tell\n"
        "return out"
    )
