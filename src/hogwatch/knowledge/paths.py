"""База знаний об известных местах, где копятся гигабайты: что это, откуда, чем грозит удаление."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import Risk


@dataclass
class PathRule:
    id: str
    globs: list[str]  # относительно ~ (или абсолютные)
    title: str  # {name} — имя найденного элемента
    what: str
    origin: str
    danger: str
    risk: Risk = Risk.SAFE
    confidence: float = 0.7
    tags: list[str] = field(default_factory=list)
    each: bool = False  # каждый элемент glob — отдельная находка
    command: list[str] | None = None  # штатная команда очистки (первый элемент — имя программы)
    command_label: str = ""
    stale_boost: bool = False  # давно не менялось → вероятнее не нужно
    min_mb: int | None = None


CACHE_DANGER = "Безопасно: это кэш, программа пересоздаст его при необходимости (первый запуск будет медленнее)."

RULES: list[PathRule] = [
    # --- Xcode / iOS -------------------------------------------------------------------------
    PathRule("xcode_derived", ["Library/Developer/Xcode/DerivedData"], "Xcode DerivedData",
             "Промежуточные результаты сборки и индексы всех проектов, когда-либо открытых в Xcode.",
             "Растёт с каждым проектом и веткой; Xcode сам почти не чистит.",
             "Безопасно: следующая сборка каждого проекта будет полной (дольше).",
             Risk.SAFE, 0.9, ["dev", "ios", "cache"]),
    PathRule("xcode_archives", ["Library/Developer/Xcode/Archives"], "Архивы Xcode (Archives)",
             "Сборки приложений, сделанные через Product → Archive, вместе с dSYM-символами.",
             "Создаются при каждой публикации в App Store/TestFlight или ad-hoc сборке.",
             "dSYM нужны для расшифровки крашей уже выпущенных версий. Старые архивы обычно не нужны.",
             Risk.CAUTION, 0.45, ["dev", "ios"], stale_boost=True),
    PathRule("xcode_devsupport", ["Library/Developer/Xcode/*DeviceSupport/*"], "Символы отладки устройства {name}",
             "Отладочные символы конкретной версии iOS/watchOS/tvOS, скачанные с подключённого устройства.",
             "Xcode копирует их при первом подключении устройства с новой версией ОС; старые версии остаются "
             "навсегда.",
             "Безопасно: при подключении устройства с этой версией ОС Xcode скопирует символы заново.",
             Risk.REBUILDABLE, 0.75, ["dev", "ios"], each=True, stale_boost=True, min_mb=100),
    PathRule("coresim_caches", ["Library/Developer/CoreSimulator/Caches"], "Кэш симуляторов iOS",
             "Кэши dyld и прочие производные данные симуляторов.", "Создаются при запуске симуляторов.",
             CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "ios", "cache"]),
    PathRule("coresim_devices", ["Library/Developer/CoreSimulator/Devices"], "Симулированные устройства iOS",
             "Диски всех созданных симуляторов (iPhone/iPad/Watch) с установленными приложениями и данными.",
             "Xcode создаёт набор устройств для каждой версии iOS; после обновления Xcode старые "
             "становятся «unavailable», но место занимают.",
             "Команда удалит только недоступные (для несуществующих рантаймов) устройства. Данные приложений "
             "в них пропадут.",
             Risk.CAUTION, 0.5, ["dev", "ios"],
             command=["xcrun", "simctl", "delete", "unavailable"], command_label="Удалить недоступные симуляторы"),
    PathRule("xcode_previews", ["Library/Developer/Xcode/UserData/Previews"], "Кэш SwiftUI Previews",
             "Данные симуляторов для SwiftUI-превью.", "Создаются при работе с Canvas в Xcode.",
             CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "ios", "cache"]),
    PathRule("ipsw", ["Library/iTunes/iPhone Software Updates", "Library/iTunes/iPad Software Updates"],
             "Прошивки iOS (IPSW)",
             "Скачанные образы прошивок iPhone/iPad.", "Остаются после обновления/восстановления устройства "
                                                       "через Finder/iTunes.",
             "Безопасно: при необходимости прошивка скачается заново.", Risk.SAFE, 0.95, ["ios", "installer"]),
    # --- Android / JVM -----------------------------------------------------------------------
    PathRule("gradle_caches", [".gradle/caches"], "Кэш Gradle",
             "Скачанные зависимости, трансформированные артефакты и кэш сборок всех Gradle-проектов.",
             "Растёт с каждым Android/Java/Kotlin-проектом и каждой версией зависимостей; Gradle чистит лишь "
             "очень старые записи.",
             "Пересоздаётся: следующая сборка заново скачает зависимости (трафик, время). Закройте IDE перед "
             "удалением.", Risk.REBUILDABLE, 0.7, ["dev", "android", "jvm", "cache"]),
    PathRule("gradle_dists", [".gradle/wrapper/dists/*"], "Дистрибутив Gradle {name}",
             "Конкретная версия Gradle, скачанная gradle-wrapper'ом.",
             "Каждый проект может требовать свою версию Gradle; старые версии остаются после обновления "
             "проектов.", "Безопасно: wrapper скачает версию заново, если проекту она понадобится.",
             Risk.REBUILDABLE, 0.7, ["dev", "jvm"], each=True, stale_boost=True, min_mb=100),
    PathRule("gradle_daemon_logs", [".gradle/daemon"], "Логи демонов Gradle",
             "Логи и служебные файлы фоновых демонов Gradle.", "Пишутся при каждой сборке.",
             "Безопасно.", Risk.SAFE, 0.9, ["dev", "jvm", "logs"]),
    PathRule("m2", [".m2/repository"], "Локальный репозиторий Maven",
             "Скачанные зависимости Maven-проектов.", "Растёт при сборке Java-проектов.",
             "Пересоздаётся: зависимости скачаются заново.", Risk.REBUILDABLE, 0.6, ["dev", "jvm", "cache"]),
    PathRule("android_ndk", ["Library/Android/sdk/ndk/*"], "Android NDK {name}",
             "Набор инструментов для нативного кода (C/C++) Android определённой версии.",
             "Ставится Android Studio/Gradle по требованию проекта; старые версии остаются после обновлений.",
             "Пересоздаётся: Gradle/SDK Manager скачает нужную версию снова (~1–2 ГБ).",
             Risk.REBUILDABLE, 0.55, ["dev", "android"], each=True, stale_boost=True),
    PathRule("android_cache", [".android/cache"], "Кэш Android SDK", "Кэш SDK Manager.", "Скачивания SDK.",
             CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "android", "cache"]),
    # --- JS / Python / Rust / Go ---------------------------------------------------------------
    PathRule("npm", [".npm/_cacache"], "Кэш npm",
             "Кэш скачанных npm-пакетов.", "Пополняется при каждом `npm install`.", CACHE_DANGER,
             Risk.SAFE, 0.85, ["dev", "js", "cache"], command=["npm", "cache", "clean", "--force"],
             command_label="npm cache clean --force"),
    PathRule("npx", [".npm/_npx"], "Кэш npx", "Пакеты, временно установленные через `npx`.",
             "Каждый `npx пакет` кладёт сюда копию.", CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "js", "cache"]),
    PathRule("pnpm", ["Library/pnpm/store", ".pnpm-store", ".local/share/pnpm/store"], "Хранилище pnpm",
             "Общее хранилище пакетов pnpm (проекты ссылаются на него жёсткими ссылками).",
             "Пополняется при `pnpm install` во всех проектах.",
             "`pnpm store prune` удалит только пакеты, на которые не ссылается ни один проект.",
             Risk.REBUILDABLE, 0.7, ["dev", "js", "cache"], command=["pnpm", "store", "prune"],
             command_label="pnpm store prune"),
    PathRule("yarn", ["Library/Caches/Yarn", ".yarn/berry/cache"], "Кэш Yarn", "Кэш пакетов Yarn.",
             "Пополняется при `yarn install`.", CACHE_DANGER, Risk.SAFE, 0.85, ["dev", "js", "cache"]),
    PathRule("bun", [".bun/install/cache"], "Кэш Bun", "Кэш пакетов Bun.", "Пополняется при `bun install`.",
             CACHE_DANGER, Risk.SAFE, 0.85, ["dev", "js", "cache"]),
    PathRule("uv", [".cache/uv"], "Кэш uv",
             "Кэш пакетов и сборок Python-менеджера uv (в том числе для uvx-утилит).",
             "Пополняется при каждом `uv sync`/`uvx`.", CACHE_DANGER, Risk.SAFE, 0.8, ["dev", "python", "cache"],
             command=["uv", "cache", "prune"], command_label="uv cache prune (удалить неиспользуемое)"),
    PathRule("pip", ["Library/Caches/pip", ".cache/pip"], "Кэш pip", "Кэш скачанных Python-пакетов.",
             "Пополняется при `pip install`.", CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "python", "cache"]),
    PathRule("poetry", ["Library/Caches/pypoetry"], "Кэш Poetry", "Кэш пакетов и виртуальных окружений Poetry.",
             "Пополняется при `poetry install`.", "Окружения Poetry придётся пересоздать.",
             Risk.REBUILDABLE, 0.75, ["dev", "python", "cache"]),
    PathRule("conda_pkgs", ["miniconda3/pkgs", "anaconda3/pkgs", "miniforge3/pkgs", "mambaforge/pkgs", ".conda/pkgs"],
             "Кэш пакетов Conda", "Скачанные архивы и распакованные пакеты Conda.",
             "Conda хранит все когда-либо скачанные версии пакетов.",
             "Безопасно для существующих окружений (`conda clean -a` удаляет только неиспользуемое).",
             Risk.SAFE, 0.8, ["dev", "python", "cache"], command=["conda", "clean", "-a", "-y"],
             command_label="conda clean -a"),
    PathRule("pyenv", [".pyenv/versions/*"], "Python {name} (pyenv)", "Установленная через pyenv версия Python.",
             "Ставится `pyenv install`; старые версии остаются.",
             "Окружения/проекты на этой версии перестанут работать.", Risk.CAUTION, 0.4, ["dev", "python"],
             each=True, stale_boost=True, min_mb=100),
    PathRule("cargo", [".cargo/registry"], "Реестр Cargo", "Скачанные исходники крейтов Rust.",
             "Пополняется при сборке Rust-проектов.", "Пересоздаётся: крейты скачаются заново.",
             Risk.REBUILDABLE, 0.6, ["dev", "rust", "cache"]),
    PathRule("rustup", [".rustup/toolchains/*"], "Тулчейн Rust {name}", "Установленный тулчейн Rust.",
             "Ставится rustup; nightly-версии копятся.", "Проекты, закреплённые на этой версии, скачают её снова.",
             Risk.CAUTION, 0.4, ["dev", "rust"], each=True, stale_boost=True, min_mb=300),
    PathRule("gomod", ["go/pkg/mod"], "Кэш модулей Go", "Скачанные модули Go.", "Пополняется при сборке.",
             "Пересоздаётся.", Risk.REBUILDABLE, 0.6, ["dev", "go", "cache"],
             command=["go", "clean", "-modcache"], command_label="go clean -modcache"),
    PathRule("gobuild", ["Library/Caches/go-build"], "Кэш сборки Go", "Кэш компиляции Go.",
             "Пополняется при каждой сборке.", CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "go", "cache"],
             command=["go", "clean", "-cache"], command_label="go clean -cache"),
    PathRule("pubcache", [".pub-cache"], "Кэш пакетов Dart/Flutter", "Скачанные пакеты pub.",
             "Пополняется при `flutter pub get`.", "Пересоздаётся.", Risk.REBUILDABLE, 0.55,
             ["dev", "flutter", "cache"]),
    PathRule("playwright", ["Library/Caches/ms-playwright"], "Браузеры Playwright",
             "Chromium/Firefox/WebKit, скачанные Playwright для автотестов и браузерных агентов.",
             "`npx playwright install` и MCP-серверы Playwright скачивают свои браузеры; при обновлении "
             "Playwright старые версии остаются.",
             "Пересоздаётся: при следующем запуске тестов Playwright попросит `playwright install`.",
             Risk.REBUILDABLE, 0.65, ["dev", "js", "cache"]),
    PathRule("cocoapods", ["Library/Caches/CocoaPods"], "Кэш CocoaPods", "Кэш подов.", "`pod install`.",
             CACHE_DANGER, Risk.SAFE, 0.85, ["dev", "ios", "cache"]),
    PathRule("homebrew", ["Library/Caches/Homebrew"], "Кэш Homebrew",
             "Скачанные бутылки/архивы формул и cask'ов Homebrew.", "Остаётся после каждой установки/обновления.",
             CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "cache"],
             command=["brew", "cleanup", "-s", "--prune=all"], command_label="brew cleanup -s --prune=all"),
    # --- Встраиваемые системы (ESP/Arduino) ---------------------------------------------------
    PathRule("platformio", [".platformio/packages", ".platformio/platforms"], "PlatformIO: {name}",
             "Тулчейны, фреймворки и платформы микроконтроллеров (ESP32, STM32, AVR…).",
             "Скачиваются при первой сборке проекта под платформу; старые версии не удаляются.",
             "Пересоздаётся: PlatformIO скачает нужное при следующей сборке (сотни МБ – ГБ).",
             Risk.REBUILDABLE, 0.45, ["dev", "embedded"], each=True, stale_boost=True),
    PathRule("platformio_cache", [".platformio/.cache"], "Кэш PlatformIO", "Кэш загрузок PlatformIO.",
             "Загрузки пакетов.", CACHE_DANGER, Risk.SAFE, 0.9, ["dev", "embedded", "cache"]),
    PathRule("espressif", [".espressif/tools", ".espressif/python_env", ".espressif/dist"], "ESP-IDF: {name}",
             "Тулчейны, Python-окружения и дистрибутивы ESP-IDF.",
             "Ставятся `install.sh` каждой версии ESP-IDF; версии копятся.",
             "Пересоздаётся запуском install.sh нужной версии ESP-IDF.", Risk.REBUILDABLE, 0.45,
             ["dev", "embedded"], stale_boost=True),
    PathRule("arduino", ["Library/Arduino15/staging", "Library/Arduino15/packages"], "Arduino: {name}",
             "Скачанные ядра плат и тулчейны Arduino (staging — архивы загрузок).",
             "Менеджер плат Arduino IDE.", "staging — безопасно; packages — пересоздаётся менеджером плат.",
             Risk.REBUILDABLE, 0.5, ["dev", "embedded"], each=True),
    # --- Нейросети ----------------------------------------------------------------------------
    PathRule("ollama", [".ollama/models"], "Модели Ollama",
             "Скачанные веса локальных нейросетей Ollama.", "`ollama pull`/`ollama run модель`.",
             "Модели придётся скачивать заново (гигабайты). Удалять лучше выборочно: `ollama rm модель`.",
             Risk.CAUTION, 0.35, ["ai", "models"], stale_boost=True),
    PathRule("hf", [".cache/huggingface/hub/*"], "Hugging Face: {name}",
             "Скачанная модель или датасет из Hugging Face.",
             "Скачивается автоматически библиотеками transformers/diffusers/whisper при первом использовании.",
             "Скачается заново при следующем использовании (трафик).", Risk.REBUILDABLE, 0.5, ["ai", "models", "cache"],
             each=True, stale_boost=True),
    PathRule("lmstudio", [".lmstudio/models", ".cache/lm-studio/models"], "Модели LM Studio",
             "Скачанные веса моделей LM Studio.", "Скачаны в LM Studio.", "Придётся скачивать заново.",
             Risk.CAUTION, 0.35, ["ai", "models"], stale_boost=True),
    PathRule("torch", [".cache/torch", ".cache/whisper", ".keras"], "Кэш моделей ({name})",
             "Предобученные веса, скачанные PyTorch/Whisper/Keras.", "Скачиваются при первом использовании.",
             "Скачается заново.", Risk.REBUILDABLE, 0.6, ["ai", "cache"], each=True),
    # --- Виртуализация ------------------------------------------------------------------------
    PathRule("docker_raw", ["Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"],
             "Диск виртуальной машины Docker Desktop",
             "Один большой файл-диск Linux-ВМ, в котором лежат все образы, контейнеры и тома.",
             "Растёт по мере скачивания образов; после `docker prune` место внутри освобождается, но файл "
             "сжимается не сразу.", "Не удаляйте файл напрямую — потеряете все контейнеры и тома. Освобождайте "
                                   "место находками Docker (prune) или в настройках Docker Desktop.",
             Risk.SYSTEM, 0.1, ["docker", "vm"]),
    PathRule("orbstack_data", ["Library/Group Containers/HUAQ24HBR6.dev.orbstack/data"], "Данные OrbStack",
             "Диск Linux-машины OrbStack: образы, контейнеры, тома и Linux-машины.",
             "Растёт по мере работы с Docker.", "Не удаляйте напрямую. Чистите через находки Docker (prune).",
             Risk.SYSTEM, 0.1, ["docker", "vm"]),
    PathRule("vagrant", [".vagrant.d/boxes/*"], "Vagrant box {name}", "Базовый образ ВМ Vagrant.",
             "`vagrant up` скачивает образ один раз и хранит.", "Скачается заново при следующем `vagrant up`.",
             Risk.REBUILDABLE, 0.6, ["vm"], each=True, stale_boost=True),
    PathRule("utm", ["Library/Containers/com.utmapp.UTM/Data/Documents/*.utm"], "Виртуальная машина UTM «{name}»",
             "Диск и настройки виртуальной машины UTM.", "Создана в UTM.",
             "Вместе с ВМ пропадут все данные внутри неё.", Risk.PERSONAL, 0.35, ["vm"], each=True, stale_boost=True),
    PathRule("parallels", ["Parallels/*.pvm", "Virtual Machines.localized/*"], "Виртуальная машина «{name}»",
             "Диск и настройки виртуальной машины Parallels/VMware.", "Создана в Parallels/VMware Fusion.",
             "Вместе с ВМ пропадут все данные внутри неё.", Risk.PERSONAL, 0.35, ["vm"], each=True, stale_boost=True),
    PathRule("minikube", [".minikube"], "Minikube", "Локальный Kubernetes-кластер и его образы.",
             "`minikube start`.", "Кластер придётся создать заново.", Risk.REBUILDABLE, 0.5, ["dev", "vm"],
             stale_boost=True),
    # --- Приложения ---------------------------------------------------------------------------
    PathRule("mail_downloads", ["Library/Containers/com.apple.mail/Data/Library/Mail Downloads"],
             "Вложения, открытые из Почты", "Копии вложений, которые вы открывали из писем.",
             "Почта сохраняет вложение при открытии; сами письма с вложениями остаются в ящике.",
             "Безопасно: вложения остаются в письмах.", Risk.SAFE, 0.85, ["mail", "cache"]),
    PathRule("telegram_mac", ["Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/*/account-*/postbox/media"],
             "Кэш медиа Telegram",
             "Фото, видео и файлы из чатов и каналов, которые Telegram сохранил на диск при просмотре.",
             "Telegram кэширует всё просмотренное; лимит кэша по умолчанию — без ограничения.",
             "Файлы останутся в облаке Telegram и скачаются снова при открытии. Удобнее очистить в Telegram: "
             "Настройки → Данные и память → Использование памяти (там же можно ограничить размер кэша).",
             Risk.REBUILDABLE, 0.75, ["cache", "messenger"]),
    PathRule("telegram_desktop", ["Library/Application Support/Telegram Desktop/tdata/user_data"],
             "Кэш медиа Telegram Desktop", "Медиафайлы из чатов, сохранённые при просмотре.",
             "Telegram Desktop кэширует просмотренное.",
             "Скачается заново из облака. Очистить можно в Telegram: Настройки → Продвинутые → Управление "
             "памятью устройства. Закройте Telegram перед удалением вручную.",
             Risk.REBUILDABLE, 0.75, ["cache", "messenger"]),
    PathRule("spotify", ["Library/Application Support/Spotify/PersistentCache"], "Кэш Spotify",
             "Кэш треков Spotify.", "Spotify кэширует прослушанное.", CACHE_DANGER, Risk.SAFE, 0.85, ["cache"]),
    PathRule("vscode_cache", ["Library/Application Support/Code/Cache", "Library/Application Support/Code/CachedData",
                              "Library/Application Support/Code/CachedExtensionVSIXs",
                              "Library/Application Support/Cursor/Cache", "Library/Application Support/Cursor/CachedData"],
             "Кэш редактора ({name})", "Кэш Electron/VS Code: скомпилированный код, старые версии, установщики "
                                       "расширений.", "Копится при обновлениях редактора и расширений.",
             CACHE_DANGER + " Закройте редактор перед удалением.", Risk.SAFE, 0.8, ["dev", "editor", "cache"],
             each=True),
    PathRule("vscode_ws", ["Library/Application Support/Code/User/workspaceStorage",
                           "Library/Application Support/Cursor/User/workspaceStorage"],
             "Данные рабочих пространств редактора",
             "Состояние для каждого когда-либо открытого проекта: индексы расширений, история, кэши ИИ-помощников.",
             "Копится годами, в том числе для давно удалённых проектов.",
             "Пропадут локальные состояния проектов (открытые вкладки, история некоторых расширений).",
             Risk.CAUTION, 0.5, ["dev", "editor"]),
    PathRule("steam", ["Library/Application Support/Steam/steamapps/common/*"], "Игра Steam «{name}»",
             "Установленная игра.", "Установлена через Steam.",
             "Удаляйте через Steam (Управление → Удалить) — так Steam не будет считать игру установленной. "
             "Сохранения обычно в облаке Steam.", Risk.REBUILDABLE, 0.4, ["games"], each=True, stale_boost=True),
    PathRule("logs", ["Library/Logs"], "Логи программ", "Журналы работы программ и отчёты о сбоях.",
             "Пишутся программами постоянно; некоторые не чистят за собой.", "Безопасно, если не нужно "
                                                                            "расследовать проблему.",
             Risk.SAFE, 0.6, ["logs"]),
    PathRule("macos_installer", ["/Applications/Install macOS*.app"], "Установщик {name}",
             "Полный установщик macOS (12–15 ГБ).", "Скачан через App Store/Software Update для "
                                                    "установки или создания загрузочной флешки.",
             "Безопасно: при необходимости скачивается снова.", Risk.SAFE, 0.9, ["installer", "macos"], each=True),
]
