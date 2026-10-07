"""Модальные окна: выбор действия, подтверждение, вывод команды, справка."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Markdown, OptionList, Static
from textual.widgets.option_list import Option

from ..model import RISK_META, Action, ActionKind, Finding, Risk
from ..util import human_bytes, short_path

IRREVERSIBLE = (ActionKind.EMPTY_TRASH,)


def is_irreversible(a: Action) -> bool:
    if a.kind in IRREVERSIBLE:
        return True
    if a.kind == ActionKind.COMMAND and any(w in a.note.upper() for w in ("НЕОБРАТИМ",)):
        return True
    return False


class ActionMenu(ModalScreen[Action | None]):
    BINDINGS = [Binding("escape", "dismiss(None)", "Отмена")]

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text(self.finding.title, style="bold"), id="dialog-title")
            opts = []
            for i, a in enumerate(self.finding.actions):
                t = Text()
                t.append(("⚠️  " if a.destructive else "   ") + a.label, style="bold" if a.destructive else "")
                if a.note:
                    t.append("\n   " + a.note, style="dim")
                opts.append(Option(t, id=str(i)))
            yield OptionList(*opts, id="action-list")
            yield Static("Enter — выбрать · Esc — отмена", classes="hint")

    def on_option_list_option_selected(self, ev: OptionList.OptionSelected) -> None:
        self.dismiss(self.finding.actions[int(ev.option.id)])


class Confirm(ModalScreen[bool]):
    BINDINGS = [Binding("escape,n", "dismiss(False)", "Отмена"), Binding("y", "dismiss(True)", "Да")]

    def __init__(self, title: str, body: str, risky: bool) -> None:
        super().__init__()
        self.title_text = title
        self.body = body
        self.risky = risky

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="risky" if self.risky else ""):
            yield Static(Text(self.title_text, style="bold"), id="dialog-title")
            with VerticalScroll(id="confirm-body"):
                yield Markdown(self.body)
            with Horizontal(id="buttons"):
                yield Button("Выполнить (y)", variant="error" if self.risky else "warning", id="yes")
                yield Button("Отмена (Esc)", variant="default", id="no")
            yield Static("Необратимое действие: подтвердите клавишей y" if self.risky
                         else "Enter на кнопке или y — выполнить", classes="hint")

    def on_mount(self) -> None:
        # Для рискованного по умолчанию в фокусе «Отмена» — случайный Enter ничего не удалит
        self.query_one("#no" if self.risky else "#yes", Button).focus()

    def on_button_pressed(self, ev: Button.Pressed) -> None:
        self.dismiss(ev.button.id == "yes")


def confirm_text(action: Action, findings: list[Finding]) -> tuple[str, str, bool]:
    f0 = findings[0] if findings else None
    risk = max((f.risk for f in findings), default=Risk.SAFE)
    risky = is_irreversible(action) or risk >= Risk.PERSONAL
    lines = []
    if len(findings) > 1:
        total = sum(f.bytes for f in findings)
        lines.append(f"**{len(findings)} находок**, всего **{human_bytes(total)}**:")
        lines += [f"- {RISK_META[f.risk][0]} {f.title} — {human_bytes(f.bytes)}" for f in findings[:15]]
        if len(findings) > 15:
            lines.append(f"- … и ещё {len(findings) - 15}")
    elif f0:
        lines.append(f"**{f0.title}**")
        lines.append(f"{RISK_META[f0.risk][0]} {RISK_META[f0.risk][1]}"
                     + (f" · {human_bytes(f0.bytes)}" if f0.bytes else ""))
        if f0.danger:
            lines += ["", f0.danger]
    if action.note:
        lines += ["", f"**Что произойдёт:** {action.note}"]
    if action.paths:
        lines += ["", "**Пути:**"] + [f"- `{short_path(p)}`" for p in action.paths[:12]]
        if len(action.paths) > 12:
            lines.append(f"- … и ещё {len(action.paths) - 12}")
    if action.argv:
        lines += ["", f"**Команда:** `{' '.join(short_path(a) for a in action.argv)[:300]}`"]
    if action.pids:
        lines += ["", f"**PID:** {', '.join(str(p) for p, _ in action.pids[:20])}"]
    return action.label, "\n".join(lines), risky


class Output(ModalScreen[None]):
    BINDINGS = [Binding("escape,enter,q", "dismiss(None)", "Закрыть")]

    def __init__(self, title: str, text: str) -> None:
        super().__init__()
        self.title_text = title
        self.text = text

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="wide"):
            yield Static(Text(self.title_text, style="bold"), id="dialog-title")
            with VerticalScroll(id="output-body"):
                yield Static(Text(self.text or "(пусто)"))
            yield Static("Esc — закрыть", classes="hint")


HELP = """
# junkicide — помощник по поиску забытых прожорливых процессов и ненужных гигабайт

Сначала утилита быстро показывает очевидное (процессы, известные места, крупные файлы из Spotlight), а затем
в фоне обходит домашнюю папку и находит мелочи: артефакты сборки, видео, дубликаты, давно не используемые
программы. Строка состояния внизу показывает, что ещё сканируется.

## Вкладки
| Клавиша | Вкладка |
|---|---|
| `1` | ⚡ Главное — всё вместе, по «выгоде»: сколько освободится × насколько вероятно не нужно × безопасность |
| `2` | 🔥 CPU — что греет процессор (сглаженная загрузка; 100% = одно ядро) |
| `3` | 🧠 Память — кто съел память |
| `4` | 💾 Диск — что можно удалить |
| `5` | 📜 Журнал — всё, что сделано и что произошло |

## Действия
| Клавиша | |
|---|---|
| `Enter` / `a` | меню действий для выбранной находки |
| `k` / `K` | завершить процесс (SIGTERM) / убить принудительно (SIGKILL) |
| `d` | переместить в Корзину (для отмеченных пробелом — все разом) |
| `пробел` | отметить строку |
| `o` | показать в Finder |
| `i` | больше не показывать эту находку (список в ~/.config/junkicide/config.toml) |
| `E` | очистить Корзину (необратимо) |
| `s` | сортировка: по выгоде ↔ по размеру |
| `/` | фильтр по тексту и тегам (`#dev`, `#cache`, `#забытое` …) · `Esc` — сбросить |
| `r` | пересканировать диск |
| `q` | выход |

## Значки
🟢 безопасно · 🔵 пересоздаётся (придётся ждать/качать) · 🟡 осторожно, посмотрите · 🔴 личные данные · ⚪ системное

🔥 CPU · 🧠 память · 💾 диск · ℹ️ сведения · ⏱ работает столько · ✎ не менялось столько

«Не нужно» — оценка вероятности, что объект вам не нужен, по признакам: давность, расположение, родительский
процесс завершён, проект заброшен и т. п.

## Безопасность
- Файлы удаляются **только в Корзину** — их можно вернуть, пока Корзина не очищена.
- Процессы сначала получают SIGTERM (штатное завершение); SIGKILL — только по вашему выбору.
- Перед каждым действием — подтверждение; для необратимых нужно нажать `y`.
- Всё записывается в журнал `~/Library/Logs/junkicide/journal.jsonl`.
"""


class Help(ModalScreen[None]):
    BINDINGS = [Binding("escape,q,question_mark", "dismiss(None)", "Закрыть")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="wide"):
            with VerticalScroll():
                yield Markdown(HELP)
            yield Static("Esc — закрыть", classes="hint")
