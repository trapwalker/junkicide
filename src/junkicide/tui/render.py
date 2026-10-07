"""Как находки выглядят: строки таблицы, карточка с подробностями, сводка в шапке."""

from __future__ import annotations

import time

from rich.text import Text

from ..model import RESOURCE_ICON, RISK_META, ActionKind, Finding, Resource, Risk
from ..util import ago, human_bytes, human_duration

VIEWS = {
    "main": "⚡ Главное",
    "cpu": "🔥 CPU",
    "mem": "🧠 Память",
    "disk": "💾 Диск",
    "journal": "📜 Журнал",
}

PROCESS_SCANNERS = {"processes", "docker"}


def view_items(findings: list[Finding], view: str, sort_by_size: bool, query: str) -> list[Finding]:
    q = query.lower().strip()
    if q:
        findings = [f for f in findings if q in f"{f.title} {f.location} {' '.join(f.tags)}".lower()]
    if view == "main":
        items = [f for f in findings if f.resource == Resource.INFO and f.pinned_score and f.pinned_score > 1
                 or f.score >= 0.15 and f.risk != Risk.SYSTEM
                 or f.resource in (Resource.CPU, Resource.MEMORY) and f.score >= 1]
        key = (lambda f: -f.bytes) if sort_by_size else (lambda f: -f.score)
    elif view == "cpu":
        items = [f for f in findings if f.resource in (Resource.CPU, Resource.MEMORY) and f.cpu >= 1]
        key = lambda f: -f.cpu
    elif view == "mem":
        items = [f for f in findings if f.resource in (Resource.CPU, Resource.MEMORY)]
        key = lambda f: -f.bytes
    elif view == "disk":
        items = [f for f in findings if f.resource == Resource.DISK or f.id == "walk:overview"]
        key = (lambda f: -f.bytes) if sort_by_size else (lambda f: -f.score)
    else:
        items = []
        key = lambda f: 0
    items.sort(key=key)
    items.sort(key=lambda f: bool(f.resolved))  # устранённое — вниз (сортировка стабильна)
    return items


def age_text(f: Finding) -> str:
    if f.started:
        return "⏱ " + human_duration(time.time() - f.started)
    ts = f.last_used or f.modified
    return ("✎ " + human_duration(time.time() - ts)) if ts else ""


COLUMNS = [("✓", 2), ("", 2), ("", 2), ("Объём", 9), ("CPU", 6), ("Что", 0), ("Давность", 13), ("Не нужно", 9)]


def row_cells(f: Finding, marked: bool, title_width: int) -> list[Text]:
    risk_icon = RISK_META[f.risk][0]
    style = ""
    if f.resolved:
        style = "dim strike"
    elif f.stale:
        style = "italic dim"
    title = f.title if not f.resolved else f"{f.title} — {f.resolved}"
    if len(title) > title_width:
        title = title[: max(title_width - 1, 1)] + "…"
    conf = "" if f.resource == Resource.INFO else f"{f.confidence * 100:.0f}%"
    size = human_bytes(f.bytes) if f.bytes else ""
    cpu = f"{f.cpu:.0f}%" if f.cpu >= 1 else ""
    return [
        Text("●" if marked else " ", style="bold yellow"),
        Text(risk_icon),
        Text(RESOURCE_ICON.get(f.resource, "")),
        Text(size, style=style, justify="right"),
        Text(cpu, style=("bold red " if f.cpu >= 100 else "") + style, justify="right"),
        Text(title, style=style),
        Text(age_text(f), style="dim"),
        Text(conf, style=style, justify="right"),
    ]


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def details_markdown(f: Finding, extra_facts: list[tuple[str, str]] | None = None) -> str:
    icon, label, _ = RISK_META[f.risk]
    head = [f"## {RESOURCE_ICON.get(f.resource, '')} {f.title}", ""]
    meta = [f"{icon} **{label}**"]
    if f.resource != Resource.INFO:
        meta.append(f"вероятно не нужно: **{f.confidence * 100:.0f}%**")
    if f.bytes:
        meta.append(("освободит " if f.resource == Resource.DISK else "память ") + f"**{human_bytes(f.bytes)}**")
    if f.cpu >= 1:
        meta.append(f"CPU **{f.cpu:.0f}%**")
    head.append(" · ".join(meta))
    if f.resolved:
        head += ["", f"> ✅ {f.resolved}"]
    if f.stale:
        head += ["", f"> ⏳ Из прошлого сканирования ({ago(f.found_at)}), сейчас перепроверяется."]
    if f.location:
        head += ["", f"`{f.location}`"]
    parts = ["\n".join(head)]
    if f.what:
        parts.append("### Что это\n" + f.what)
    if f.origin:
        parts.append("### Откуда взялось\n" + f.origin)
    if f.danger:
        parts.append("### Чем грозит устранение\n" + f.danger)
    facts = list(f.facts) + list(extra_facts or [])
    if facts:
        lines = []
        for k, v in facts:
            v = str(v)
            if "\n" in v:
                lines.append(f"- **{k}:**")
                lines += [f"    - `{x}`" for x in v.splitlines() if x.strip()]
            else:
                lines.append(f"- **{k}:** {v}")
        parts.append("### Факты\n" + "\n".join(lines))
    if f.actions and not f.resolved:
        acts = []
        for a in f.actions:
            mark = "⚠️ " if a.destructive and a.kind in (ActionKind.TRASH, ActionKind.KILL, ActionKind.COMMAND,
                                                          ActionKind.EMPTY_TRASH) else ""
            acts.append(f"- {mark}{a.label}")
        parts.append("### Что можно сделать  (Enter — выбрать)\n" + "\n".join(acts))
    if f.tags:
        parts.append(" ".join(f"`#{t}`" for t in f.tags))
    return "\n\n".join(parts)


def summary_line(sys: dict, freed: int, trashed: int = 0) -> Text:
    t = Text()
    if not sys:
        return Text("Собираю сведения о системе…", style="dim")
    cpu = sys.get("cpu", 0)
    t.append("🔥 CPU ", style="bold")
    t.append(f"{cpu:.0f}%", style="bold red" if cpu > 70 else "")
    load = sys.get("load", (0, 0, 0))
    t.append(f" (нагрузка {load[0]:.1f} на {sys.get('cores', '?')} ядер)   ")
    used, total = sys.get("mem_used", 0), sys.get("mem_total", 1)
    pr = sys.get("pressure", 0)
    t.append("🧠 ", style="bold")
    t.append(f"{human_bytes(used)}/{human_bytes(total)}")
    pr_txt = {1: "норма", 2: "повышенное", 4: "КРИТИЧНО"}.get(pr, "?")
    t.append(f" давление: {pr_txt}", style="bold red" if pr >= 4 else ("yellow" if pr == 2 else "green"))
    sw = sys.get("swap_used", 0)
    if sw > 512 * 1024**2:
        t.append(f", swap {human_bytes(sw)}", style="yellow" if sw > 4 * 1024**3 else "")
    t.append("   💾 ", style="bold")
    free, dtotal = sys.get("disk_free", 0), sys.get("disk_total", 1)
    t.append(f"свободно {human_bytes(free)} из {human_bytes(dtotal)}",
             style="bold red" if free < dtotal * 0.08 else "")
    tr = sys.get("trash", (0, 0))
    if tr and tr[0] > 100 * 1024**2:
        t.append(f"   🗑 {human_bytes(tr[0])}")
    if sys.get("thermal"):
        t.append(f"   🌡 {sys['thermal']}", style="bold red")
    bat = sys.get("battery")
    if bat:
        t.append(f"   🔋{bat[0]:.0f}%" + ("⚡" if bat[1] else ""))
    if trashed:
        t.append(f"   🗑 в Корзину: {human_bytes(trashed)}", style="green")
    if freed:
        t.append(f"   ✅ освобождено: {human_bytes(freed)}", style="bold green")
    return t


def potential_line(findings: list[Finding]) -> Text:
    disk = []
    seen: set[str] = set()  # одни и те же пути встречаются в разных находках (дубликаты, файл в папке)
    for f in sorted(findings, key=lambda x: -x.score):
        if f.resource != Resource.DISK or f.resolved or f.id == "sys:trash":
            continue
        if f.paths and any(p in seen or any(p.startswith(s + "/") for s in seen) for p in f.paths):
            continue
        seen.update(f.paths)
        disk.append(f)
    safe = sum(f.bytes for f in disk if f.risk <= Risk.REBUILDABLE and f.confidence >= 0.6)
    likely = sum(f.bytes for f in disk if f.risk <= Risk.CAUTION and f.confidence >= 0.5)
    procs = [f for f in findings if f.resource in (Resource.CPU, Resource.MEMORY) and not f.resolved
             and f.risk <= Risk.SAFE and f.confidence >= 0.6]
    t = Text("Можно освободить: ", style="bold")
    t.append(f"💾 {human_bytes(safe)} без потери данных", style="green")
    t.append(f" (до {human_bytes(likely)} с проверкой)")
    if procs:
        t.append(f"   🧠 {human_bytes(sum(f.bytes for f in procs))} и 🔥 {sum(f.cpu for f in procs):.0f}% CPU "
                 f"в {len(procs)} забытых процессах", style="yellow")
    return t
