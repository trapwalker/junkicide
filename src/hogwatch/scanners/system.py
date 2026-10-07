"""Сводка о системе (для шапки) и связанные находки: давление памяти, swap, мало места, перегрев, Корзина."""

from __future__ import annotations

import os
import re
import time

import psutil

from .. import actions as act
from ..model import Action, ActionKind, Finding, Resource, Risk
from ..util import HOME, human_bytes, run
from .base import ScanContext, Scanner

PRESSURE = {1: "норма", 2: "повышенное", 4: "критическое"}


def memory_pressure() -> int:
    code, out, _ = run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"], timeout=3)
    try:
        return int(out.strip())
    except ValueError:
        return 0


def thermal_state() -> str | None:
    code, out, _ = run(["pmset", "-g", "therm"], timeout=5)
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", out)
    if m and int(m.group(1)) < 100:
        return f"процессор замедлен до {m.group(1)}% из-за нагрева"
    m = re.search(r"thermal warning level.*?(\d+)", out, re.I)
    if m and "No thermal warning" not in out and int(m.group(1)) > 0:
        return f"уровень термопредупреждения {m.group(1)}"
    return None


class SystemScanner(Scanner):
    name = "system"
    title = "система"
    interval = 5.0

    def __init__(self) -> None:
        self._last_slow = 0.0
        self._therm: str | None = None
        self._trash: tuple[int, int | None] = (0, 0)
        psutil.cpu_percent(None)

    def run(self, ctx: ScanContext) -> None:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        du = psutil.disk_usage("/")
        pressure = memory_pressure()
        now = time.time()
        if now - self._last_slow > 60:
            self._therm = thermal_state()
            self._trash = act.trash_size()
            self._last_slow = now
        bat = None
        try:
            bat = psutil.sensors_battery()
        except Exception:
            pass
        ctx.system.update(
            cpu=psutil.cpu_percent(None), cores=psutil.cpu_count(), load=os.getloadavg(),
            mem_total=vm.total, mem_used=vm.total - vm.available, pressure=pressure,
            swap_used=sw.used, disk_total=du.total, disk_free=du.free, thermal=self._therm,
            battery=(bat.percent, bat.power_plugged) if bat else None, trash=self._trash, updated=now,
        )
        findings: list[Finding] = []
        if pressure >= 2 or sw.used > 4 * 1024**3:
            findings.append(Finding(
                id="sys:memory", scanner=self.name, resource=Resource.INFO,
                title=f"Памяти не хватает: давление {PRESSURE.get(pressure, '?')}, swap {human_bytes(sw.used)}",
                risk=Risk.SYSTEM, confidence=1.0, pinned_score=50 if pressure >= 4 else 20, tags=["system", "memory"],
                what="macOS сжимает память и выгружает её на диск (swap). Всё начинает тормозить, а SSD изнашивается.",
                origin="Причина — процессы во вкладке «🧠 Память»: обычно браузер с множеством вкладок, "
                       "Docker/эмуляторы/виртуальные машины, IDE и локальные нейросети.",
                danger="Освободите память, завершив самые прожорливые находки.",
                facts=[("Всего памяти", human_bytes(vm.total)), ("Занято", human_bytes(vm.total - vm.available)),
                       ("Swap", human_bytes(sw.used))],
            ))
        if du.free < max(20 * 1024**3, du.total * 0.08):
            findings.append(Finding(
                id="sys:disk", scanner=self.name, resource=Resource.INFO,
                title=f"Мало места на диске: свободно {human_bytes(du.free)} из {human_bytes(du.total)}",
                risk=Risk.SYSTEM, confidence=1.0, pinned_score=40, tags=["system", "disk"],
                what="Когда свободно меньше ~10%, macOS не может нормально обновляться, swap и кэши начинают "
                     "мешать работе.",
                origin="Смотрите вкладку «💾 Диск» — там отсортировано по тому, что проще всего удалить.",
                danger="",
            ))
        if self._therm:
            findings.append(Finding(
                id="sys:thermal", scanner=self.name, resource=Resource.INFO, title=f"Перегрев: {self._therm}",
                risk=Risk.SYSTEM, confidence=1.0, pinned_score=30, tags=["system", "thermal"],
                what="macOS снижает частоту процессора, чтобы остыть.",
                origin="Смотрите вкладку «🔥 CPU»: процессы с постоянной высокой загрузкой.", danger="",
            ))
        tsize, tcount = self._trash
        if tsize >= 500 * 1024**2 or (tsize == 0 and tcount):
            findings.append(Finding(
                id="sys:trash", scanner=self.name, resource=Resource.DISK,
                title=f"Корзина: {human_bytes(tsize) if tsize else '?'}" + (f", объектов: {tcount}" if tcount else ""),
                location="~/.Trash", bytes=tsize, risk=Risk.CAUTION, confidence=0.8, tags=["trash"],
                what="Файлы в Корзине по-прежнему занимают место на диске.",
                origin="Сюда же попадает всё, что удалено из hogwatch — чтобы можно было передумать.",
                danger="Очистка Корзины НЕОБРАТИМА. Перед очисткой можно открыть Корзину и посмотреть содержимое."
                       + ("" if tsize else "\n\nРазмер неизвестен: у терминала нет доступа к ~/.Trash "
                          "(Системные настройки → Конфиденциальность → Полный доступ к диску)."),
                actions=[
                    Action(ActionKind.REVEAL, "Открыть Корзину в Finder", paths=[str(HOME / ".Trash")],
                           destructive=False),
                    Action(ActionKind.EMPTY_TRASH, "Очистить Корзину",
                           "Все файлы в Корзине будут удалены безвозвратно."),
                ],
            ))
        ctx.store.upsert(findings)
