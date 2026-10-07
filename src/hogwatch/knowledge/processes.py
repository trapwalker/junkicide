"""База знаний о процессах: кто это, откуда берётся, можно ли прибить и как правильнее."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from ..model import Action, ActionKind, Risk
from ..util import short_path, which


@dataclass
class Proc:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: list[str]
    username: str
    create_time: float
    rss: int
    cpu: float  # сглаженный % одного ядра
    cpu_life: float  # средний % за всю жизнь процесса
    app_path: str | None  # внешний .app, если есть
    app_name: str | None
    mine: bool
    cwd: str | None = None
    ports: list[int] = field(default_factory=list)

    @property
    def cmd(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else self.exe or self.name

    def arg_after(self, flag: str) -> str | None:
        try:
            i = self.cmdline.index(flag)
            return self.cmdline[i + 1]
        except (ValueError, IndexError):
            return None

    @property
    def key(self) -> tuple[int, float]:
        return (self.pid, self.create_time)


def term_action(procs: list[Proc], label: str = "Завершить (SIGTERM)", note: str = "") -> Action:
    return Action(
        ActionKind.KILL, label, note or "Процессу посылается SIGTERM — штатный сигнал завершения.",
        pids=[p.key for p in procs],
    )


def force_action(procs: list[Proc]) -> Action:
    return Action(
        ActionKind.KILL, "Убить принудительно (SIGKILL)",
        "Немедленное завершение без возможности сохранить состояние. Используйте, если SIGTERM не помог.",
        pids=[p.key for p in procs], force=True,
    )


def quit_app_action(app_name: str) -> Action:
    return Action(
        ActionKind.QUIT_APP, f"Закрыть {app_name} штатно",
        "Как ⌘Q: приложение само предложит сохранить несохранённое.", app_name=app_name,
    )


@dataclass
class ProcRule:
    id: str
    match: Callable[[Proc], bool]
    title: Callable[[list[Proc]], str]
    what: str
    origin: str
    danger: str
    risk: Risk = Risk.SAFE
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    group: bool = False  # все совпавшие процессы — одна находка
    always: bool = False  # показывать даже при небольшом потреблении (типичный «забытый» процесс)
    min_cpu: float = 0.0
    min_mem: int = 0
    actions: Callable[[list[Proc]], list[Action]] | None = None
    system: bool = False


def _rx(pattern: str, where: str = "cmd") -> Callable[[Proc], bool]:
    r = re.compile(pattern, re.I)
    if where == "exe":
        return lambda p: bool(r.search(p.exe or p.name))
    if where == "name":
        return lambda p: bool(r.search(p.name))
    return lambda p: bool(r.search(p.cmd))


def _sys(names: str) -> Callable[[Proc], bool]:
    s = set(names.split())
    return lambda p: p.name in s


# --- конкретные случаи ----------------------------------------------------------------------

def _is_android_emu(p: Proc) -> bool:
    e = (p.exe or p.name).lower()
    return ("qemu-system" in e or e.endswith("/emulator")) and ("/emulator/" in e or "android" in e)


def _emu_title(ps: list[Proc]) -> str:
    p = ps[0]
    avd = p.arg_after("-avd") or next((a[1:] for a in p.cmdline if a.startswith("@")), None)
    headless = " без окна" if "headless" in (p.exe or "") or "-no-window" in p.cmdline else ""
    return f"Эмулятор Android{headless}" + (f" «{avd}»" if avd else "")


def _emu_actions(ps: list[Proc]) -> list[Action]:
    acts = []
    adb = which("adb", "~/Library/Android/sdk/platform-tools/adb",
                os.path.join(os.environ.get("ANDROID_HOME", "~/Library/Android/sdk"), "platform-tools/adb"))
    for p in ps:
        console = next((port for port in sorted(p.ports) if 5554 <= port <= 5682 and port % 2 == 0), None)
        if adb and console:
            acts.append(Action(
                ActionKind.COMMAND, f"Остановить штатно через adb (emulator-{console})",
                f"`adb -s emulator-{console} emu kill` — эмулятор корректно выключится.",
                argv=[adb, "-s", f"emulator-{console}", "emu", "kill"],
            ))
    acts.append(term_action(ps, note="SIGTERM — эмулятор завершится; данные AVD не теряются, "
                                     "следующий запуск может быть холодным (дольше)."))
    acts.append(force_action(ps))
    return acts


def _gradle_title(ps: list[Proc]) -> str:
    vers = set()
    for p in ps:
        m = re.search(r"gradle-(?:launcher|daemon-main)-([\d.]+)\.jar", p.cmd)
        if m:
            vers.add(m.group(1))
    v = f" ({', '.join(sorted(vers))})" if vers else ""
    n = len(ps)
    return f"Демоны Gradle{v} × {n}" if n > 1 else f"Демон Gradle{v}"


def _gradle_actions(ps: list[Proc]) -> list[Action]:
    return [term_action(ps, "Остановить все демоны Gradle",
                        "SIGTERM всем демонам. Gradle запустит новый при следующей сборке."), force_action(ps)]


def _node_tool(p: Proc) -> str:
    m = re.search(r"(vite|next(?:-server| dev| start)?|webpack(?:-dev-server)?|react-scripts|nodemon|nuxt|astro|"
                  r"expo|metro|ng serve|parcel|storybook|tsc|esbuild|turbo|remix|svelte-kit|vitest|jest|"
                  r"tsx|ts-node|serve|http-server|live-server|electron)", p.cmd, re.I)
    return m.group(1) if m else "node"


def _py_tool(p: Proc) -> str:
    m = re.search(r"(jupyter[- ]?\w*|ipykernel|uvicorn|gunicorn|flask|runserver|streamlit|gradio|http\.server|"
                  r"celery|tensorboard|mkdocs|hypercorn|daphne)", p.cmd, re.I)
    return m.group(1) if m else "python"


def _where(p: Proc) -> str:
    return f" в {short_path(p.cwd)}" if p.cwd and p.cwd not in ("/", "") else ""


def _docker_vm_title(ps: list[Proc]) -> str:
    c = " ".join(p.cmd for p in ps).lower()
    if "orbstack" in c:
        kind = "OrbStack"
    elif "colima" in c or "lima" in c:
        kind = "Colima/Lima"
    elif "podman" in c or "gvproxy" in c:
        kind = "Podman"
    else:
        kind = "Docker Desktop"
    return f"Виртуальная машина контейнеров ({kind})"


def _docker_vm_actions(ps: list[Proc]) -> list[Action]:
    c = " ".join(p.cmd for p in ps).lower()
    acts = []
    if "orbstack" in c and (orb := which("orb", "/opt/homebrew/bin/orb", "~/.orbstack/bin/orb")):
        acts.append(Action(ActionKind.COMMAND, "Остановить OrbStack (orb stop)",
                           "Остановит ВМ и все контейнеры. Данные (volumes, образы) сохранятся.", argv=[orb, "stop"]))
        acts.append(quit_app_action("OrbStack"))
    elif "colima" in c and (col := which("colima")):
        acts.append(Action(ActionKind.COMMAND, "Остановить Colima (colima stop)",
                           "Остановит ВМ и все контейнеры. Данные сохранятся.", argv=[col, "stop"]))
    elif "podman" in c and (pod := which("podman")):
        acts.append(Action(ActionKind.COMMAND, "Остановить podman machine",
                           "Остановит ВМ и все контейнеры. Данные сохранятся.", argv=[pod, "machine", "stop"]))
    else:
        acts.append(quit_app_action("Docker"))
    return acts


def _sim_actions(ps: list[Proc]) -> list[Action]:
    return [
        Action(ActionKind.COMMAND, "Выключить все симуляторы (simctl shutdown all)",
               "Корректно выключит все запущенные iOS/watchOS симуляторы.",
               argv=["xcrun", "simctl", "shutdown", "all"]),
        quit_app_action("Simulator"),
    ]


def _llm_actions(ps: list[Proc]) -> list[Action]:
    acts = []
    if any("ollama" in p.cmd.lower() for p in ps) and (ol := which("ollama", "/opt/homebrew/bin/ollama")):
        acts.append(Action(ActionKind.SHOW, "Какие модели загружены (ollama ps)", "Только показать.",
                           argv=[ol, "ps"], destructive=False))
    acts.append(term_action(ps, note="Модель выгрузится из памяти. Ollama/LM Studio загрузит её снова при "
                                     "следующем запросе."))
    return acts


def _vm_title(ps: list[Proc]) -> str:
    c = " ".join(p.cmd for p in ps)
    for key, name in (("UTM", "UTM"), ("prl_", "Parallels"), ("VBox", "VirtualBox"), ("vmware", "VMware"),
                      ("tart", "Tart"), ("Virtualization", "Apple Virtualization")):
        if key.lower() in c.lower():
            return f"Виртуальная машина ({name})"
    return "Виртуальная машина"


RULES: list[ProcRule] = [
    ProcRule(
        "android_emulator", _is_android_emu, _emu_title,
        what="Эмулятор Android на базе QEMU из Android SDK. Держит в памяти целую гостевую ОС Android и "
             "постоянно крутит её виртуальные ядра — даже когда окна не видно (режим -no-window/headless), "
             "поэтому греет ноутбук и сажает батарею.",
        origin="Запускается из Android Studio (Device Manager / Run на виртуальном устройстве), "
               "`flutter run`, `npx expo run:android`, `react-native run-android`, Maestro/Detox или вручную "
               "`emulator -avd …`. Когда IDE, терминал или агент, запустивший эмулятор, закрывается — эмулятор "
               "часто остаётся жить сам по себе (родитель = launchd, PPID 1). Без окна его не видно в Dock.",
        danger="Остановить безопасно. Данные внутри виртуального устройства сохраняются; при запуске с "
               "-no-snapshot-save следующий старт будет «холодным» (на 20–60 с дольше).",
        risk=Risk.SAFE, confidence=0.9, tags=["dev", "vm", "android", "забытое"], always=True,
        actions=_emu_actions,
    ),
    ProcRule(
        "ios_simulator", _rx(r"(Simulator\.app|launchd_sim|CoreSimulator/.*/(SpringBoard|backboardd))"),
        lambda ps: "Симулятор iOS/watchOS",
        what="iOS Simulator из Xcode и процессы внутри симулируемых устройств (launchd_sim, SpringBoard…).",
        origin="Запускается Xcode при Run, `xcrun simctl boot`, `flutter run`, `npx expo run:ios`, тестами UI. "
               "Устройства продолжают работать после закрытия окна Simulator.",
        danger="Безопасно: устройство выключится, данные приложений в нём сохранятся.",
        risk=Risk.SAFE, confidence=0.8, tags=["dev", "ios", "забытое"], group=True, always=True,
        min_mem=200 * 1024**2, actions=_sim_actions,
    ),
    ProcRule(
        "docker_vm",
        _rx(r"(OrbStack Helper|com\.docker\.(backend|virtualization|hyperkit|vpnkit)|Docker Desktop\.app|"
            r"limactl|colima|gvproxy|podman.*machine|vfkit)"),
        _docker_vm_title,
        what="Linux-виртуальная машина, внутри которой работают Docker-контейнеры. Её память — это память всех "
             "контейнеров плюс кэш файловой системы ВМ; она редко отдаёт память обратно macOS.",
        origin="Стартует вместе с Docker Desktop / OrbStack / Colima (часто — автоматически при входе в систему) "
               "и живёт, пока её явно не остановить, даже если контейнеры давно не нужны.",
        danger="Остановка ВМ остановит ВСЕ контейнеры (базы данных в них корректно завершатся). Образы, "
               "volumes и настройки сохраняются. Отдельные контейнеры можно остановить во вкладке процессов.",
        risk=Risk.CAUTION, confidence=0.5, tags=["dev", "docker", "vm"], group=True,
        min_mem=500 * 1024**2, actions=_docker_vm_actions,
    ),
    ProcRule(
        "vm", _rx(r"(UTM\.app.*QEMULauncher|prl_vm_app|VBoxHeadless|VirtualBoxVM|vmware-vmx|"
                  r"Virtualization\.VirtualMachine|/tart )"),
        _vm_title,
        what="Работающая виртуальная машина. Память гостя целиком занята в macOS.",
        origin="Запущена из UTM/Parallels/VirtualBox/VMware/Tart. Нередко остаётся в фоне или в «приостановке».",
        danger="Остановка без выключения гостевой ОС равносильна выдёргиванию питания — лучше выключить "
               "гостя изнутри или через приложение ВМ.",
        risk=Risk.CAUTION, confidence=0.5, tags=["vm"], group=True, always=True,
        actions=lambda ps: [term_action(ps)],
    ),
    ProcRule(
        "gradle_daemon", _rx(r"(GradleDaemon|GradleWorkerMain|gradle-launcher-|gradle-daemon-main)"),
        _gradle_title,
        what="Фоновый демон Gradle (JVM). Ускоряет повторные сборки, но каждый держит 0.5–4 ГБ памяти. "
             "Для разных версий Gradle/JDK/настроек поднимаются отдельные демоны, и они копятся.",
        origin="Остаётся после сборки Android/Java/Kotlin-проекта (Android Studio, `./gradlew`). Сам "
               "завершается только через 3 часа простоя.",
        danger="Безопасно. Следующая сборка будет на несколько секунд медленнее (прогрев демона).",
        risk=Risk.SAFE, confidence=0.85, tags=["dev", "jvm", "android", "забытое"], group=True, always=True,
        actions=_gradle_actions,
    ),
    ProcRule(
        "kotlin_daemon", _rx(r"(KotlinCompileDaemon|kotlin-daemon)"),
        lambda ps: "Демон компилятора Kotlin" + (f" × {len(ps)}" if len(ps) > 1 else ""),
        what="JVM-процесс компилятора Kotlin, переиспользуется между сборками Gradle.",
        origin="Поднимается сборкой Kotlin/Android-проекта и живёт после неё.",
        danger="Безопасно, перезапустится при следующей сборке.",
        risk=Risk.SAFE, confidence=0.85, tags=["dev", "jvm", "забытое"], group=True, always=True,
        actions=lambda ps: [term_action(ps)],
    ),
    ProcRule(
        "watchman", _rx(r"/watchman( |$)", "exe"), lambda ps: "Watchman (слежение за файлами)",
        what="Сервис Meta для слежения за изменениями файлов (React Native, Jest, Buck). Со временем "
             "раздувается по памяти и нагружает fseventsd.",
        origin="Запускается React Native/Metro/Jest и остаётся навсегда.",
        danger="Безопасно — запустится снова при необходимости.",
        risk=Risk.SAFE, confidence=0.8, tags=["dev", "js", "забытое"], group=True, always=True,
        min_mem=100 * 1024**2,
        actions=lambda ps: [Action(ActionKind.COMMAND, "watchman shutdown-server", "Штатная остановка.",
                                   argv=[ps[0].exe or "watchman", "shutdown-server"]), term_action(ps)],
    ),
    ProcRule(
        "node_dev",
        lambda p: p.name in ("node", "bun", "deno") and bool(re.search(
            r"(vite|next|webpack|react-scripts|nodemon|nuxt|astro|expo|metro|ng serve|parcel|storybook|"
            r"tsc .*--watch|esbuild|turbo|remix|svelte-kit|vitest|jest .*--watch|tsx watch|ts-node-dev|"
            r"http-server|live-server|serve |npm run dev|pnpm dev|yarn dev)", p.cmd, re.I)),
        lambda ps: f"Dev-сервер {_node_tool(ps[0])}{_where(ps[0])}",
        what="Сервер разработки или watcher на Node.js: пересобирает проект при изменении файлов, держит "
             "в памяти граф модулей и кэши.",
        origin="Запущен `npm run dev`/`vite`/`next dev` и т. п. — в терминале, IDE или агентом. Если окно "
               "терминала/сессия агента закрылись, процесс мог остаться работать в фоне.",
        danger="Безопасно: это не данные, а работающий сервер. Перезапустите, когда снова понадобится.",
        risk=Risk.SAFE, confidence=0.6, tags=["dev", "js"], always=True, min_mem=150 * 1024**2,
        actions=lambda ps: [term_action(ps), force_action(ps)],
    ),
    ProcRule(
        "python_dev",
        lambda p: p.name.lower().startswith("python") and bool(re.search(
            r"(jupyter|ipykernel|uvicorn|gunicorn|flask|manage\.py runserver|streamlit|gradio|"
            r"http\.server|celery|tensorboard|mkdocs serve|hypercorn|daphne)", p.cmd, re.I)),
        lambda ps: f"Python-сервер {_py_tool(ps[0])}{_where(ps[0])}",
        what="Сервер разработки/ноутбук/воркер на Python. Ядра Jupyter держат в памяти все переменные "
             "(датафреймы, модели) до перезапуска ядра.",
        origin="Запущен вручную, IDE или агентом; часто переживает закрытие вкладки браузера с ноутбуком.",
        danger="Несохранённые результаты в памяти ядра Jupyter будут потеряны; сами файлы — нет.",
        risk=Risk.CAUTION, confidence=0.55, tags=["dev", "python"], always=True, min_mem=150 * 1024**2,
        actions=lambda ps: [term_action(ps), force_action(ps)],
    ),
    ProcRule(
        "local_llm", _rx(r"(ollama (runner|serve)|llama-server|llama\.cpp|LM Studio|lms |mlx_lm|"
                         r"text-generation-launcher|koboldcpp|vllm)"),
        lambda ps: "Локальная LLM держит модель в памяти",
        what="Сервер локальной нейросети. Загруженная модель занимает 4–40+ ГБ единой памяти (RAM/GPU).",
        origin="Ollama/LM Studio держат модель после запроса (по умолчанию ~5 мин, но часто настроено дольше "
               "или модель «прибита»).",
        danger="Безопасно: модель выгрузится, при следующем запросе загрузится снова (несколько секунд).",
        risk=Risk.SAFE, confidence=0.6, tags=["ai", "dev"], group=True, min_mem=1024**3,
        actions=_llm_actions,
    ),
    ProcRule(
        "lsp", _rx(r"(tsserver|typescript-language-server|pyright|pylance|basedpyright|gopls|rust-analyzer|"
                   r"clangd|sourcekit-lsp|jdtls|jdt\.ls|kotlin-language-server|metals|lua-language-server|"
                   r"eslintServer|vscode-eslint|tailwindcss-language-server|intelephense)"),
        lambda ps: "Языковые серверы редактора" + (f" × {len(ps)}" if len(ps) > 1 else ""),
        what="Анализаторы кода для автодополнения и подсветки ошибок (LSP). На больших проектах занимают "
             "гигабайты; иногда зацикливаются и греют CPU.",
        origin="Запускаются редактором (VS Code, Cursor, Zed, Neovim, JetBrains) для открытых проектов; "
               "после краша редактора могут остаться сиротами.",
        danger="Безопасно: редактор перезапустит сервер (подсветка ненадолго пропадёт).",
        risk=Risk.SAFE, confidence=0.5, tags=["dev", "editor"], group=True, min_mem=700 * 1024**2,
        min_cpu=40, actions=lambda ps: [term_action(ps)],
    ),
    ProcRule(
        "editor_ext_host", _rx(r"(Code Helper \(Plugin\)|Cursor Helper \(Plugin\)|Windsurf Helper \(Plugin\)|"
                               r"extensionHost)"),
        lambda ps: "Хост расширений редактора (VS Code/Cursor)",
        what="Процесс, в котором работают все расширения VS Code-подобного редактора. Высокая загрузка "
             "обычно значит, что какое-то расширение зациклилось или индексирует огромную папку.",
        origin="Редактор открыт с тяжёлыми расширениями или большим рабочим пространством (node_modules, "
               "датасеты без исключений в files.watcherExclude).",
        danger="Редактор покажет «Extension host terminated» и предложит перезапуск. Несохранённые файлы "
               "не теряются (они в основном процессе).",
        risk=Risk.CAUTION, confidence=0.4, tags=["dev", "editor"], min_cpu=50, min_mem=1500 * 1024**2,
        actions=lambda ps: [term_action(ps)],
    ),
    ProcRule(
        "xcode_build", _rx(r"(XCBBuildService|SourceKitService|swift-frontend|IBAgent|ibtoold)"),
        lambda ps: "Фоновые процессы Xcode",
        what="Сервис сборки, индексатор SourceKit и компилятор Swift.",
        origin="Xcode индексирует проект или собирает. Могут остаться после закрытия Xcode.",
        danger="Безопасно; если Xcode открыт — он перезапустит их.",
        risk=Risk.SAFE, confidence=0.5, tags=["dev", "ios"], group=True, min_mem=800 * 1024**2, min_cpu=50,
        actions=lambda ps: [term_action(ps)],
    ),
    ProcRule(
        "torrent", _rx(r"(qbittorrent|Transmission\.app|uTorrent|Folx|Motrix|aria2c)"),
        lambda ps: "Торрент-клиент",
        what="Качает и раздаёт файлы: постоянная нагрузка на диск, сеть и fseventsd/Spotlight.",
        origin="Остаётся раздавать скачанное после завершения загрузки.",
        danger="Раздачи остановятся; скачанные файлы не пострадают.",
        risk=Risk.SAFE, confidence=0.5, tags=["network"], group=True, min_cpu=10, min_mem=500 * 1024**2,
        actions=lambda ps: [quit_app_action(ps[0].app_name or "qbittorrent"), term_action(ps)],
    ),
    # --- системные: объясняем, но не предлагаем убивать -------------------------------------
    ProcRule(
        "spotlight", _sys("mds mds_stores mdworker mdworker_shared mdsync corespotlightd"),
        lambda ps: "Индексация Spotlight",
        what="Spotlight индексирует содержимое файлов для поиска.",
        origin="Всплеск после установки программ, копирования/распаковки множества файлов, сборок "
               "(node_modules, build/) или подключения диска. Обычно проходит сам за минуты–часы.",
        danger="Не завершайте: процессы системные и тут же перезапустятся. Лучше исключить папки с "
               "артефактами сборки: Системные настройки → Spotlight → Конфиденциальность (Search Privacy).",
        risk=Risk.SYSTEM, confidence=0.1, tags=["system", "spotlight"], group=True, system=True, min_cpu=30,
        actions=lambda ps: [Action(ActionKind.SHOW, "Статус индексации (mdutil -s /)", "Только показать.",
                                   argv=["mdutil", "-s", "/"], destructive=False)],
    ),
    ProcRule(
        "fseventsd", _sys("fseventsd"), lambda ps: "fseventsd — журнал изменений файлов",
        what="Системный журнал изменений файловой системы (на нём работают Spotlight, Time Machine, "
             "файловые watcher'ы).",
        origin="Высокая нагрузка = кто-то очень много пишет на диск: сборки, dev-серверы с watch, торренты, "
               "облачная синхронизация, эмуляторы и Docker. Ищите виновника среди других находок.",
        danger="Системный процесс — завершать нельзя.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system"], system=True, min_cpu=30,
    ),
    ProcRule(
        "windowserver", _sys("WindowServer"), lambda ps: "WindowServer — отрисовка экрана",
        what="Системный композитор окон.",
        origin="Нагрузка растёт от множества окон и мониторов, анимаций, видео, тяжёлых вкладок с "
               "WebGL/Canvas, прозрачности. Закройте тяжёлые вкладки/окна.",
        danger="Завершение = принудительный выход из учётной записи. Не трогать.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system", "graphics"], system=True, min_cpu=40,
    ),
    ProcRule(
        "kernel_task", _sys("kernel_task"), lambda ps: "kernel_task — ядро",
        what="Ядро macOS. Высокий CPU у kernel_task часто — искусственное «занятие» процессора для "
             "охлаждения (термозащита).",
        origin="Перегрев: тяжёлые процессы, зарядка + нагрузка, внешний монитор, плохая вентиляция.",
        danger="Не завершается. Уберите источник нагрева — другие находки в списке.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system", "thermal"], system=True, min_cpu=50,
    ),
    ProcRule(
        "media_analysis", _sys("photoanalysisd mediaanalysisd photolibraryd mediastream_mirror"),
        lambda ps: "Анализ фото/видео (Фото)",
        what="Распознавание лиц, объектов и текста в медиатеке «Фото».",
        origin="Идёт после импорта большого количества фото/видео или обновления macOS; работает, когда "
               "Mac простаивает и подключён к сети.",
        danger="Системный, перезапустится. Проходит сам.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system"], group=True, system=True, min_cpu=30,
    ),
    ProcRule(
        "icloud", _sys("bird cloudd fileproviderd nsurlsessiond CloudKeychainProxy"),
        lambda ps: "Синхронизация iCloud",
        what="Синхронизация iCloud Drive и других облачных данных.",
        origin="Загрузка/выгрузка большого объёма данных в iCloud.",
        danger="Системный, не завершать.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system", "cloud"], group=True, system=True, min_cpu=30,
    ),
    ProcRule(
        "backupd", _sys("backupd backupd-helper"), lambda ps: "Резервное копирование Time Machine",
        what="Time Machine делает резервную копию.",
        origin="Плановое копирование каждый час.",
        danger="Можно пропустить текущую копию через меню Time Machine; процесс не убивать.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system", "backup"], group=True, system=True, min_cpu=30,
    ),
    ProcRule(
        "security_scan", _sys("syspolicyd trustd XprotectService XProtect MRT"),
        lambda ps: "Проверка безопасности (Gatekeeper/XProtect)",
        what="Проверка подписей и сканирование на вредоносное ПО.",
        origin="Всплески после скачивания/распаковки программ, запуска новых бинарников (сборки, "
               "node_modules с нативными модулями).",
        danger="Системный, не завершать.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system"], group=True, system=True, min_cpu=30,
    ),
    ProcRule(
        "airportd", _sys("airportd"), lambda ps: "airportd — Wi-Fi",
        what="Системный демон Wi-Fi.",
        origin="Постоянная загрузка бывает при частом сканировании сетей (слабый сигнал, переключение "
               "сетей, VPN/сетевые утилиты, Wireless Diagnostics), иногда из-за бага macOS.",
        danger="Системный. Помогает выключить/включить Wi-Fi или перезагрузка.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system", "network"], system=True, min_cpu=30,
    ),
    ProcRule(
        "reportcrash", _sys("ReportCrash ReportMemoryException spindump"),
        lambda ps: "Сбор отчётов о сбоях",
        what="macOS собирает отчёт о падении или зависании какой-то программы.",
        origin="Если висит постоянно — какая-то программа падает в цикле (смотрите ~/Library/Logs/"
               "DiagnosticReports).",
        danger="Системный, завершится сам.",
        risk=Risk.SYSTEM, confidence=0.05, tags=["system"], group=True, system=True, min_cpu=30,
    ),
]

SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/bin/", "/Library/Apple/")
