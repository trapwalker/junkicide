"""Главное окно wtf."""

from __future__ import annotations

import os

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import ContentSwitcher, DataTable, Footer, Input, Markdown, Static, Tab, Tabs

from .. import actions as act
from .. import cache
from ..config import Config
from ..journal import Journal
from ..model import Action, ActionKind, Finding, FindingStore
from ..scanners.base import Runner, ScanContext
from ..util import fmt_date, human_bytes, short_path, spotlight_meta
from .render import COLUMNS, VIEWS, details_markdown, potential_line, row_cells, summary_line, view_items
from .screens import ActionMenu, Confirm, Help, Output, confirm_text

DISK_SCANNERS = ("known", "walk", "spotlight", "apps")


class WtfApp(App):
    TITLE = "wtf"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("q", "quit", "Выход"),
        Binding("question_mark,f1", "help", "Помощь"),
        Binding("1", "view('main')", "Главное", show=False),
        Binding("2", "view('cpu')", "CPU", show=False),
        Binding("3", "view('mem')", "Память", show=False),
        Binding("4", "view('disk')", "Диск", show=False),
        Binding("5", "view('journal')", "Журнал", show=False),
        Binding("enter,a", "actions", "Действия"),
        Binding("k", "kill(False)", "Завершить"),
        Binding("K", "kill(True)", "Убить", show=False),
        Binding("d", "trash", "В Корзину"),
        Binding("space", "mark", "Отметить"),
        Binding("o", "reveal", "Finder"),
        Binding("i", "ignore", "Скрыть"),
        Binding("E", "empty_trash", "Очистить Корзину", show=False),
        Binding("s", "sort", "Сортировка", show=False),
        Binding("slash", "filter", "Фильтр"),
        Binding("r", "rescan", "Пересканировать", show=False),
        Binding("escape", "clear_filter", show=False),
    ]

    def __init__(self, config: Config, journal: Journal, scanners: list) -> None:
        super().__init__()
        self.config = config
        self.journal = journal
        self.store = FindingStore()
        self.store.set_ignored(set(config.ignore_ids))
        self.ctx = ScanContext(self.store, journal, config)
        self.runner = Runner(self.ctx, scanners)
        self.view = "main"
        self.sort_by_size = False
        self.query = ""
        self.marked: set[str] = set()
        self.row_ids: list[str] = []
        self._shown_version = -1
        self._shown_view = ""
        self._journal_version = -1
        self._details_id: str | None = None
        self._details_version = -1
        self._enriched: dict[str, list[tuple[str, str]]] = {}
        self._saved_runs: dict[str, int] = {}
        self.freed = 0  # реально освобождено (после очистки Корзины, prune и т.п.)
        self.trashed = 0  # перемещено в Корзину
        self.busy = False

    # --- построение ---------------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(id="summary")
        yield Static(id="potential")
        yield Tabs(*[Tab(label, id=key) for key, label in VIEWS.items()], id="tabs")
        yield Input(placeholder="Фильтр: текст или тег (#dev, #cache, #забытое…), Esc — сбросить", id="filter")
        with ContentSwitcher(initial="findings", id="switcher"):
            with Horizontal(id="findings"):
                yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
                with VerticalScroll(id="details-box"):
                    yield Markdown("Выберите строку, чтобы увидеть подробности.", id="details")
            with Vertical(id="journal"):
                yield DataTable(id="journal-table", cursor_type="row", zebra_stripes=True)
        yield Static(id="status")
        yield Footer()

    def on_mount(self) -> None:
        jt = self.query_one("#journal-table", DataTable)
        jt.add_column("Время", width=17)
        jt.add_column("Уровень", width=7)
        jt.add_column("Событие", width=16)
        jt.add_column("Сообщение")
        self.query_one("#filter", Input).display = False
        cached = cache.load()
        if cached:
            self.store.upsert(cached)
            self.journal.info("cache.load", f"Показаны результаты прошлого сканирования: {len(cached)} находок")
        self.journal.info("start", "wtf запущен")
        self.runner.start()
        self._layout_for(self.size.width)
        self._rebuild_columns()
        self.call_after_refresh(self._rebuild_columns)  # ширина таблицы известна только после раскладки
        self.set_interval(0.5, self.tick)
        self.query_one("#table", DataTable).focus()

    def on_resize(self, ev) -> None:
        self._layout_for(ev.size.width)
        self.call_after_refresh(self._rebuild_columns)

    def _layout_for(self, width: int) -> None:
        # На узком экране подробности уходят под таблицу, а не сжимают её
        self.query_one("#findings").set_class(width < 130, "narrow")

    def _title_width(self) -> int:
        table = self.query_one("#table", DataTable)
        w = table.size.width or (self.size.width * (1 if self.size.width < 130 else 0.58))
        fixed = sum(width + 2 for _, width in COLUMNS if width) + 2
        return max(int(w) - fixed, 16)

    def _rebuild_columns(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear(columns=True)
        tw = self._title_width()
        for label, width in COLUMNS:
            table.add_column(label, width=width or tw)
        self._shown_version = -1

    # --- периодическое обновление --------------------------------------------------------------

    def tick(self) -> None:
        self.query_one("#summary", Static).update(summary_line(self.ctx.system, self.freed, self.trashed))
        snap = self.store.snapshot()
        self.query_one("#potential", Static).update(potential_line(snap))
        self._update_status()
        self._maybe_save_cache(snap)
        if self.view == "journal":
            self._refresh_journal()
        elif self.store.version != self._shown_version or self._shown_view != self.view:
            self._refresh_table(snap)

    def _update_status(self) -> None:
        t = Text()
        for name, st in self.ctx.status.items():
            if name == "system":
                continue
            style = {"идёт": "yellow", "готово": "green", "ошибка": "red"}.get(st.state, "dim")
            t.append(f"{st.icon} {st.title}", style=style)
            if st.message and st.state in ("идёт", "ошибка") or (st.message and name == "docker"):
                t.append(f" ({st.message})", style="dim")
            t.append("  ")
        if self.busy:
            t.append("  ⟳ выполняю действие…", style="bold yellow")
        self.query_one("#status", Static).update(t)

    def _maybe_save_cache(self, snap: list[Finding]) -> None:
        changed = False
        for name in DISK_SCANNERS:
            st = self.ctx.status.get(name)
            if st and st.state == "готово" and self._saved_runs.get(name) != st.runs:
                self._saved_runs[name] = st.runs
                changed = True
        if changed:
            cache.save(snap)

    def _refresh_table(self, snap: list[Finding]) -> None:
        table = self.query_one("#table", DataTable)
        items = view_items(snap, self.view, self.sort_by_size, self.query)
        current = self.row_ids[table.cursor_row] if self.row_ids and 0 <= table.cursor_row < len(self.row_ids) else None
        scroll_y = table.scroll_y
        table.clear()
        tw = self._title_width()
        self.row_ids = []
        for f in items:
            table.add_row(*row_cells(f, f.id in self.marked, tw), key=f.id)
            self.row_ids.append(f.id)
        if current in self.row_ids:
            table.move_cursor(row=self.row_ids.index(current), scroll=False)
            table.scroll_y = scroll_y
        self._shown_version = self.store.version
        self._shown_view = self.view
        self._show_details()

    def _refresh_journal(self) -> None:
        if self.journal.version == self._journal_version and self._shown_view == "journal":
            return
        self._journal_version = self.journal.version
        self._shown_view = "journal"
        jt = self.query_one("#journal-table", DataTable)
        jt.clear()
        q = self.query.lower().strip()
        styles = {"error": "bold red", "warn": "yellow", "action": "bold green", "info": ""}
        for e in reversed(self.journal.snapshot()):
            if q and q not in e.text:
                continue
            st = styles.get(e.level, "dim")
            jt.add_row(Text(fmt_date(e.ts)), Text(e.level, style=st), Text(e.event, style="dim"),
                       Text(e.msg, style=st))

    # --- подробности --------------------------------------------------------------------------

    def current(self) -> Finding | None:
        table = self.query_one("#table", DataTable)
        if not self.row_ids or not (0 <= table.cursor_row < len(self.row_ids)):
            return None
        return self.store.get(self.row_ids[table.cursor_row])

    @on(DataTable.RowSelected, "#table")
    def _row_selected(self, ev: DataTable.RowSelected) -> None:
        self.action_actions()

    @on(DataTable.RowHighlighted, "#table")
    def _row_changed(self, ev: DataTable.RowHighlighted) -> None:
        self._show_details()

    def _show_details(self) -> None:
        f = self.current()
        md = self.query_one("#details", Markdown)
        if f is None:
            if self._details_id is not None:
                md.update("Здесь пока пусто — сканирование ещё идёт или фильтр ничего не нашёл.")
                self._details_id = None
            return
        if f.id == self._details_id and self._details_version == self.store.version:
            return
        self._details_id = f.id
        self._details_version = self.store.version
        md.update(details_markdown(f, self._enriched.get(f.id)))
        if f.id not in self._enriched and f.paths and f.resource.value == "disk":
            self._enriched[f.id] = []
            self.enrich(f)

    @work(thread=True, exclusive=False, group="enrich")
    def enrich(self, f: Finding) -> None:
        """Spotlight знает, откуда файл скачан и когда его открывали, — подтягиваем лениво."""
        path = f.paths[0]
        if not os.path.exists(path):
            return
        meta = spotlight_meta(path)
        facts: list[tuple[str, str]] = []
        wf = meta.get("kMDItemWhereFroms")
        if wf:
            facts.append(("Скачано с", "\n".join(str(x) for x in wf[:3])))
        if meta.get("kMDItemLastUsedDate"):
            facts.append(("Последнее открытие", fmt_date(meta["kMDItemLastUsedDate"])))
        if meta.get("kMDItemDurationSeconds"):
            d = int(meta["kMDItemDurationSeconds"])
            facts.append(("Длительность", f"{d // 3600} ч {d % 3600 // 60} мин" if d >= 3600 else f"{d // 60} мин"))
        if meta.get("kMDItemPixelHeight"):
            facts.append(("Разрешение", f"{meta.get('kMDItemPixelWidth')}×{meta['kMDItemPixelHeight']}"))
        if meta.get("kMDItemAcquisitionModel"):
            facts.append(("Снято на", f"{meta.get('kMDItemAcquisitionMake', '')} {meta['kMDItemAcquisitionModel']}"))
        if facts:
            self._enriched[f.id] = facts
            self.call_from_thread(self._force_details)

    def _force_details(self) -> None:
        self._details_version = -1
        self._show_details()

    # --- действия -----------------------------------------------------------------------------

    def action_view(self, view: str) -> None:
        self.query_one("#tabs", Tabs).active = view

    @on(Tabs.TabActivated)
    def _tab(self, ev: Tabs.TabActivated) -> None:
        self.view = ev.tab.id or "main"
        self.query_one("#switcher", ContentSwitcher).current = "journal" if self.view == "journal" else "findings"
        self._journal_version = -1
        self.tick()
        self.query_one("#journal-table" if self.view == "journal" else "#table", DataTable).focus()

    def action_help(self) -> None:
        self.push_screen(Help())

    def action_sort(self) -> None:
        self.sort_by_size = not self.sort_by_size
        self.notify("Сортировка: " + ("по размеру" if self.sort_by_size else "по выгоде"), timeout=2)
        self._shown_version = -1

    def action_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.display = True
        inp.focus()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, ev: Input.Changed) -> None:
        self.query = ev.value.lstrip("#") if ev.value.startswith("#") else ev.value
        self._shown_version = -1
        self._journal_version = -1

    @on(Input.Submitted, "#filter")
    def _filter_done(self, ev: Input.Submitted) -> None:
        self.query_one("#journal-table" if self.view == "journal" else "#table", DataTable).focus()

    def action_clear_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        if inp.display:
            inp.value = ""
            inp.display = False
            self.query = ""
            self._shown_version = -1
            self._journal_version = -1
            self.query_one("#table", DataTable).focus()

    def action_mark(self) -> None:
        f = self.current()
        if not f:
            return
        self.marked.symmetric_difference_update({f.id})
        self._shown_version = -1
        table = self.query_one("#table", DataTable)
        if table.cursor_row < len(self.row_ids) - 1:
            table.move_cursor(row=table.cursor_row + 1)

    def action_actions(self) -> None:
        if self.view == "journal":
            return
        f = self.current()
        if not f:
            return
        if f.resolved:
            self.notify("Уже сделано: " + f.resolved, timeout=3)
            return
        if not f.actions:
            self.notify("Для этой находки нет действий — только сведения.", timeout=3)
            return

        def chosen(a: Action | None) -> None:
            if a:
                self.ask_and_run(a, [f])

        self.push_screen(ActionMenu(f), chosen)

    def _first(self, f: Finding, kind: ActionKind, force: bool | None = None) -> Action | None:
        for a in f.actions:
            if a.kind == kind and (force is None or a.force == force):
                return a
        return None

    def action_kill(self, force: bool) -> None:
        f = self.current()
        if not f or f.resolved:
            return
        a = self._first(f, ActionKind.KILL, force)
        if not a:
            self.notify("Здесь нечего завершать" + (" — процесс системный" if f.risk.name == "SYSTEM" else ""),
                        severity="warning", timeout=3)
            return
        self.ask_and_run(a, [f])

    def action_trash(self) -> None:
        targets = [self.store.get(i) for i in self.marked] if self.marked else [self.current()]
        targets = [f for f in targets if f and not f.resolved]
        pairs = [(f, a) for f in targets if (a := self._first(f, ActionKind.TRASH))]
        if not pairs:
            self.notify("Нечего переносить в Корзину (у этой находки другое действие — Enter).", timeout=3)
            return
        if len(pairs) == 1:
            self.ask_and_run(pairs[0][1], [pairs[0][0]])
            return
        combined = Action(ActionKind.TRASH, f"Переместить в Корзину: {len(pairs)} находок",
                          "Можно вернуть из Корзины, пока она не очищена.",
                          paths=[p for _, a in pairs for p in a.paths])
        self.ask_and_run(combined, [f for f, _ in pairs])

    def action_reveal(self) -> None:
        f = self.current()
        if not f:
            return
        a = self._first(f, ActionKind.REVEAL)
        path = a.paths[0] if a else (f.paths[0] if f.paths else None)
        if path:
            act.execute(Action(ActionKind.REVEAL, "Finder", paths=[path], destructive=False), f, self.journal)
        else:
            self.notify("У этой находки нет пути на диске.", timeout=2)

    def action_ignore(self) -> None:
        f = self.current()
        if not f:
            return

        def done(ok: bool) -> None:
            if not ok:
                return
            self.config.ignore_ids.append(f.id)
            try:
                self.config.save()
            except OSError as e:
                self.notify(f"Не удалось сохранить настройки: {e}", severity="error")
            self.store.set_ignored(set(self.config.ignore_ids))
            self.journal.info("ignore", f"Скрыто: {f.title}", id=f.id)
            self.notify(f"Скрыто. Вернуть можно в {short_path(self.config.path)}", timeout=4)

        self.push_screen(Confirm("Больше не показывать?", f"**{f.title}**\n\n`{f.id}`", False), done)

    def action_empty_trash(self) -> None:
        tsize, tcount = self.ctx.system.get("trash", (0, 0))
        a = Action(ActionKind.EMPTY_TRASH, "Очистить Корзину",
                   f"Все файлы в Корзине ({human_bytes(tsize) if tsize else 'размер неизвестен'}"
                   f"{', объектов: ' + str(tcount) if tcount else ''}) будут удалены НЕОБРАТИМО.")
        self.ask_and_run(a, [])

    def action_rescan(self) -> None:
        for name in DISK_SCANNERS + ("docker",):
            self.runner.rescan(name)
        self.notify("Пересканирую диск…", timeout=2)

    def ask_and_run(self, action: Action, findings: list[Finding]) -> None:
        if not action.destructive:
            self.execute_action(action, findings)
            return
        title, body, risky = confirm_text(action, findings)

        def answered(ok: bool) -> None:
            if ok:
                self.execute_action(action, findings)

        self.push_screen(Confirm(title, body, risky), answered)

    @work(thread=True, group="actions")
    def execute_action(self, action: Action, findings: list[Finding]) -> None:
        self.busy = True
        try:
            f0 = findings[0] if findings else None
            res = act.execute(action, f0, self.journal)
        finally:
            self.busy = False
        self.call_from_thread(self._action_done, action, findings, res)

    def _action_done(self, action: Action, findings: list[Finding], res: act.Result) -> None:
        if res.resolved and action.kind != ActionKind.SHOW:
            label = {ActionKind.TRASH: "в Корзине", ActionKind.KILL: "завершено",
                     ActionKind.QUIT_APP: "закрыто"}.get(action.kind, "сделано")
            for f in findings:
                self.store.mark_resolved(f.id, label)
                self.marked.discard(f.id)
            if action.kind == ActionKind.TRASH:
                self.trashed += res.freed
        if action.kind in (ActionKind.EMPTY_TRASH, ActionKind.COMMAND) and res.ok:
            self.freed += res.freed
        self.notify(res.message, severity="information" if res.ok else "error", timeout=6)
        if res.output and (action.kind == ActionKind.SHOW or not res.ok):
            self.push_screen(Output(action.label, res.output))
        if action.kind == ActionKind.KILL and not res.ok and not action.force:
            self.notify("Можно убить принудительно: K", severity="warning", timeout=6)
        # обновить сводку и связанные сканеры
        self.runner.rescan("system")
        if action.kind in (ActionKind.COMMAND, ActionKind.KILL, ActionKind.QUIT_APP):
            self.runner.rescan("docker")
        self._shown_version = -1

    def on_unmount(self) -> None:
        self.runner.stop()
        cache.save(self.store.snapshot())
        self.journal.info("stop", f"wtf закрыт: в Корзину {human_bytes(self.trashed)}, освобождено {human_bytes(self.freed)}")
