"""Классификация крупных файлов и папок: дистрибутив, фильм, записи регистратора, архив, образ ВМ…"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from ..apps import match_installer
from ..model import Risk
from ..util import HOME, human_duration, is_cloud_synced

VIDEO = {"mp4", "mov", "mkv", "avi", "m4v", "ts", "mts", "m2ts", "wmv", "flv", "webm", "mpg", "mpeg", "3gp", "vob"}
INSTALLER = {"dmg", "pkg", "mpkg", "xip"}
DISK_IMAGE = {"iso", "img", "toast", "cdr"}
ARCHIVE = {"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "tbz", "tbz2", "zst", "lz4"}
VM_DISK = {"qcow2", "vmdk", "vdi", "vhd", "vhdx", "hdd", "ova", "ovf"}
MODEL = {"gguf", "safetensors", "ckpt", "pt", "pth", "onnx", "mlmodel", "tflite", "h5"}
BUILD_OUT = {"apk", "aab", "ipa", "xcarchive"}
DUMP = {"sql", "dump", "bak", "backup", "sqlite", "db"}
AUDIO = {"wav", "flac", "aiff", "aif", "caf"}

MOVIE_RX = re.compile(r"(s\d{1,2}e\d{1,3}|\b(480|720|1080|2160)p\b|bdrip|brrip|web-?dl|webrip|hdrip|dvdrip|"
                      r"\bx26[45]\b|\bhevc\b|\bh\.?26[45]\b|\bremux\b|\bhdtv\b|\bdub\b|\bmvo\b|\bavo\b|сезон|серия)",
                      re.I)
SCREEN_RX = re.compile(r"(screen ?recording|запись экрана|screencast|снимок экрана|record_\d|obs[-_ ]?\d)", re.I)
CAMERA_RX = re.compile(r"^(img_\d|dsc[_f]?\d|mvi_\d|gopr\d|gh\d{6}|gx\d{6}|dji_\d|pxl_\d|vid_\d{8}|"
                       r"video_\d{8}|mov_\d|c\d{4}\.mp4|\d{8}_\d{6}\.(mp4|mov)$)", re.I)
PARTIAL = {"crdownload", "part", "download", "partial", "!qb", "!ut", "aria2", "opdownload"}
YTDLP_RX = re.compile(r"\[[\w-]{11}\]")
YTDLP_FRAGMENT_RX = re.compile(r"\.f\d{2,4}\.(mp4|webm|m4a|mkv)$", re.I)
COMPRESSED_IMAGE_RX = re.compile(r"\.(img|iso|dmg)\.(gz|xz|zip|bz2|zst|7z)$", re.I)
BACKUP_RX = re.compile(r"(backup|бэкап|резервн|\bbk\b|_bk\b|bak\b)", re.I)
SOFT_IMAGE_RX = re.compile(r"(office|setup|install|adobe|autodesk|x64|x86|portable|repack)", re.I)
OS_IMAGE_RX = re.compile(r"(ubuntu|debian|fedora|arch|mint|kali|windows|win1[01]|raspios|raspbian|armbian|"
                         r"openwrt|dietpi|freebsd|proxmox|centos|alpine|manjaro|elementary|pop-os|tails|"
                         r"macos|osx|recovery|firmware|flightaware|piaware|batocera|retropie|lineage)", re.I)

# Видеорегистраторы: типичные имена файлов разных производителей
DASHCAM_NAME_RX = [
    re.compile(r"^\d{8}[_-]?\d{6}"),  # 20230512_143012…
    re.compile(r"^\d{4}_\d{4}_\d{6}"),  # 2023_0512_143012_001F (Viofo)
    re.compile(r"^(NO|EV|PA|EMER|EVT|NOR|EVN|PAR)\d{6,}", re.I),  # NO20230512-…
    re.compile(r"^(FILE|REC|MOVI|CarDV|DCAM)\d", re.I),  # FILE230512-143012F
    re.compile(r"^(NORM|EVENT|PARK|EMR|LOCK)", re.I),
    re.compile(r"\d{6}[_-]\d{6}[_-]?\d*[FRIB]\.(mp4|mov|ts|avi)$", re.I),  # …_F / _R камеры
]
DASHCAM_DIR_RX = re.compile(r"^(normal|event|parking|emergency|emr|lock|movie|cardv|dashcam|dvr|"
                            r"регистратор|видеорегистратор|front|rear|ro|rw)$", re.I)


def ext_of(name: str) -> str:
    n = name.lower()
    for double in (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst"):
        if n.endswith(double):
            return "tar"
    return n.rsplit(".", 1)[-1] if "." in n else ""


@dataclass
class Verdict:
    title: str
    kind: str
    risk: Risk
    confidence: float
    what: str
    origin: str
    danger: str
    tags: list[str] = field(default_factory=list)


def classify_file(path: str, size: int, mtime: float, stale_days: int) -> Verdict:
    name = os.path.basename(path)
    ext = ext_of(name)
    parent = os.path.dirname(path)
    age = time.time() - mtime
    in_downloads = parent.startswith(str(HOME / "Downloads"))
    if ext in PARTIAL:
        v = Verdict(f"Недокачанный файл {name}", "partial", Risk.SAFE, 0.85,
                    "Временный файл незавершённой загрузки браузера/торрент-клиента/менеджера загрузок.",
                    "Загрузку прервали или забыли; файл остаётся, пока его не удалить.",
                    "Безопасно, если загрузка не идёт прямо сейчас. Докачать с этого места обычно не получится.",
                    ["download"])
    elif COMPRESSED_IMAGE_RX.search(name):
        os_img = bool(OS_IMAGE_RX.search(name))
        v = Verdict(f"Сжатый образ диска {name}", "image", Risk.REBUILDABLE if os_img else Risk.CAUTION,
                    0.65 if os_img else 0.4,
                    "Сжатый образ диска/SD-карты (img/iso, упакованный gz/xz/zip).",
                    "Скачан для записи на флешку/SD-карту (Raspberry Pi и т.п.) или снят как бэкап карты.",
                    "Официальные образы ОС скачиваются заново; самодельные снимки карт — нет.", ["image"])
    elif ext in INSTALLER:
        app = match_installer(name)
        if app:
            v = Verdict(f"Дистрибутив {name}: «{app.name}» уже установлено", "installer", Risk.SAFE, 0.9,
                        f"Установочный образ программы. Программа уже установлена: `{app.path}`"
                        + (f" (версия {app.version})" if app.version else "") + ".",
                        "Скачан для установки; после установки .dmg/.pkg больше не нужен.",
                        "Безопасно: установленная программа от него не зависит; дистрибутив всегда можно "
                        "скачать заново.", ["installer"])
        else:
            v = Verdict(f"Дистрибутив {name}", "installer", Risk.REBUILDABLE, 0.65,
                        "Установочный образ/пакет программы. Соответствующее приложение не найдено среди "
                        "установленных.",
                        "Скачан для установки; возможно, программу так и не поставили или уже удалили.",
                        "Обычно можно скачать заново с сайта разработчика. Осторожно, если это редкая/старая "
                        "версия, которую больше нигде не найти.", ["installer"])
    elif ext in DISK_IMAGE and SOFT_IMAGE_RX.search(name) and not OS_IMAGE_RX.search(name):
        v = Verdict(f"Установочный образ {name}", "installer", Risk.REBUILDABLE, 0.65,
                    "ISO-образ с дистрибутивом программы (часто для Windows/виртуальной машины).",
                    "Скачан для установки программы.",
                    "После установки обычно не нужен; можно скачать заново.", ["installer", "image"])
    elif ext == "mbtiles":
        v = Verdict(f"Тайлы карты {name}", "tiles", Risk.CAUTION, 0.4,
                    "Офлайн-тайлы карты в формате MBTiles (SQLite).",
                    "Скачаны/сгенерированы для офлайн-карт или тайл-сервера; часто это кэш.",
                    "Если это кэш тайлов — пересоздаётся скачиванием (трафик!); если сгенерировано вами — "
                    "придётся генерировать снова.", ["gis", "cache"])
    elif ext in DISK_IMAGE:
        os_img = bool(OS_IMAGE_RX.search(name))
        v = Verdict(("Образ ОС " if os_img else "Образ диска ") + name, "image", Risk.REBUILDABLE,
                    0.7 if os_img else 0.45,
                    "Образ операционной системы для установки, загрузочной флешки или SD-карты (Raspberry Pi, "
                    "одноплатники, роутеры)." if os_img else "Образ диска (ISO/IMG).",
                    "Скачан, чтобы установить систему или записать на флешку/SD-карту; после записи обычно "
                    "не нужен — новые версии всё равно выходят.",
                    "Скачивается заново. Осторожно с самодельными образами (бэкап SD-карты и т.п.) — их "
                    "уже не восстановить.", ["installer", "image"])
    elif ext in ARCHIVE:
        stem = re.sub(r"(\.tar)?\.(zip|rar|7z|tar|gz|tgz|bz2|xz|tbz2?|zst|lz4)$", "", name, flags=re.I)
        extracted = os.path.isdir(os.path.join(parent, stem))
        if extracted:
            v = Verdict(f"Архив {name} — уже распакован рядом", "archive", Risk.CAUTION, 0.8,
                        f"Архив, рядом с которым лежит папка `{stem}/` с распакованным содержимым.",
                        "Скачан и распакован; сам архив остался.",
                        "Если распакованная папка полная и не изменялась — архив не нужен. Проверьте, что "
                        "распаковка не была частичной.", ["archive"])
        else:
            v = Verdict(f"Архив {name}", "archive", Risk.CAUTION, 0.4,
                        "Архив (zip/rar/7z/tar).",
                        "Скачан или создан как бэкап/передача файлов.",
                        "Может оказаться единственной копией (бэкап, выгрузка). Посмотрите содержимое.",
                        ["archive"])
    elif ext in VM_DISK:
        v = Verdict(f"Диск виртуальной машины {name}", "vm", Risk.PERSONAL, 0.35,
                    "Файл-диск виртуальной машины (QEMU/VirtualBox/VMware/Hyper-V).",
                    "Создан при установке ВМ или скачан готовый образ.",
                    "Вместе с файлом пропадут все данные внутри ВМ.", ["vm"])
    elif ext in MODEL:
        v = Verdict(f"Веса нейросети {name}", "model", Risk.REBUILDABLE, 0.5,
                    "Файл модели машинного обучения (GGUF/SafeTensors/PyTorch/ONNX…).",
                    "Скачан для локального запуска нейросети или получен при обучении.",
                    "Скачанные модели можно скачать снова; обученные вами — нет.", ["ai", "models"])
    elif ext in BUILD_OUT:
        v = Verdict(f"Сборка приложения {name}", "build", Risk.REBUILDABLE, 0.7,
                    "Собранный пакет мобильного приложения (APK/AAB/IPA).",
                    "Результат сборки; копится при каждой публикации/тесте.",
                    "Пересобирается из исходников; осторожно, если это релизная сборка без исходников.",
                    ["dev", "build"])
    elif ext in DUMP:
        v = Verdict(f"Дамп/база данных {name}", "dump", Risk.PERSONAL, 0.3,
                    "Дамп или файл базы данных/резервная копия.",
                    "Создан при переносе/бэкапе базы.",
                    "Может быть единственной копией данных.", ["data", "backup"])
    elif ext == "log":
        v = Verdict(f"Лог {name}", "log", Risk.SAFE, 0.8,
                    "Текстовый журнал работы программы.", "Программа пишет и не ротирует журнал.",
                    "Безопасно, если не нужно расследовать проблему.", ["logs"])
    elif ext in VIDEO:
        v = classify_video(name, size)
    elif ext in AUDIO:
        v = Verdict(f"Аудио без сжатия {name}", "audio", Risk.CAUTION, 0.35,
                    "Несжатая звукозапись (WAV/AIFF/FLAC).", "Запись, экспорт или исходник проекта.",
                    "Может быть уникальной записью.", ["media", "audio"])
    else:
        v = Verdict(f"Крупный файл {name}", "other", Risk.CAUTION, 0.25,
                    f"Файл типа «.{ext or 'без расширения'}».", "", "Проверьте, что это за файл, прежде чем удалять.",
                    [])
    # Возраст и расположение
    notes = []
    if age > stale_days * 86400:
        v.confidence = min(v.confidence + 0.1, 0.95)
        notes.append(f"Не изменялся {human_duration(age)}.")
    if in_downloads:
        v.confidence = min(v.confidence + 0.1, 0.95)
        notes.append("Лежит в «Загрузках» — обычно это временные файлы.")
    if BACKUP_RX.search(path[len(str(HOME)):]) and v.kind not in ("partial", "installer"):
        v.risk = max(v.risk, Risk.PERSONAL)
        v.confidence = min(v.confidence, 0.3)
        notes.append("Путь похож на резервную копию — возможно, это единственный экземпляр данных.")
        v.tags.append("backup")
    cloud = is_cloud_synced(path)
    if cloud:
        notes.append(f"**Файл в папке {cloud}: удаление удалит его и из облака на всех устройствах.**")
        if v.risk < Risk.CAUTION:
            v.risk = Risk.CAUTION
        v.tags.append("облако")
    if notes:
        v.origin = (v.origin + " " + " ".join(notes)).strip()
    return v


def classify_video(name: str, size: int) -> Verdict:
    if YTDLP_FRAGMENT_RX.search(name):
        return Verdict(f"Брошенный фрагмент загрузки yt-dlp {name}", "ytdlp", Risk.SAFE, 0.85,
                       "Отдельная дорожка (только видео или только звук) с суффиксом формата .fNNN, которую yt-dlp "
                       "скачивает перед склейкой.",
                       "Остаётся, если склейка (ffmpeg) не удалась, загрузку прервали или запускали с -k.",
                       "Безопасно, если рядом есть итоговый файл или видео можно скачать снова.",
                       ["media", "video", "download"])
    if YTDLP_RX.search(name):
        return Verdict(f"Видео, скачанное с YouTube: {name}", "youtube", Risk.CAUTION, 0.6,
                       "Видео, сохранённое yt-dlp/youtube-dl (в имени — ID ролика в квадратных скобках).",
                       "Скачано для офлайн-просмотра.",
                       "Можно скачать снова, пока ролик доступен на YouTube.", ["media", "video", "download"])
    if SCREEN_RX.search(name):
        return Verdict(f"Запись экрана {name}", "screen", Risk.CAUTION, 0.6,
                       "Видеозапись экрана (QuickTime, ⇧⌘5, OBS).",
                       "Записывалась для демонстрации/созвона/бага; часто нужна один раз.",
                       "Пропадёт запись — убедитесь, что она уже отправлена/выложена.", ["media", "video"])
    if MOVIE_RX.search(name):
        return Verdict(f"Фильм/сериал {name}", "movie", Risk.CAUTION, 0.65,
                       "Видео, по имени похожее на фильм или серию (качество, рип, кодек в названии).",
                       "Скачано для просмотра; после просмотра обычно не нужно.",
                       "Можно найти и скачать заново. Если это редкая запись — сохраните.", ["media", "video", "movie"])
    if CAMERA_RX.search(name):
        return Verdict(f"Видео с камеры {name}", "camera", Risk.PERSONAL, 0.2,
                       "Исходное видео с телефона/камеры/дрона/экшн-камеры.",
                       "Скопировано с устройства.",
                       "Личная съёмка — возможно, единственная копия. Удаляйте, только если есть копия "
                       "в Фото/облаке.", ["media", "video", "personal"])
    if is_dashcam_name(name):
        return Verdict(f"Запись видеорегистратора {name}", "dashcam", Risk.CAUTION, 0.6,
                       "Видеофайл с именем в формате видеорегистратора.",
                       "Скопирован с карты памяти регистратора.",
                       "Если здесь важный эпизод (ДТП, спорная ситуация) — сохраните его отдельно.",
                       ["media", "video", "dashcam"])
    return Verdict(f"Видео {name}", "video", Risk.CAUTION, 0.4,
                   "Видеофайл.", "", "Посмотрите, что это за видео, прежде чем удалять.", ["media", "video"])


def is_dashcam_name(name: str) -> bool:
    return any(rx.search(name) for rx in DASHCAM_NAME_RX)


# --- артефакты сборки ----------------------------------------------------------------------------

ARTIFACTS: dict[str, tuple[tuple[str, ...], str]] = {
    # имя папки: (признаки проекта рядом, как восстановить)
    "node_modules": (("package.json",), "npm install / pnpm install / yarn"),
    ".venv": (("pyproject.toml", "requirements.txt", "setup.py", "uv.lock", "Pipfile", "poetry.lock"),
              "uv sync / pip install -r requirements.txt"),
    "venv": (("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"), "python -m venv venv && pip install …"),
    "target": (("Cargo.toml", "pom.xml", "build.sbt"), "cargo build / mvn package"),
    "build": (("build.gradle", "build.gradle.kts", "CMakeLists.txt", "pubspec.yaml", "setup.py", "package.json"),
              "повторная сборка"),
    ".gradle": (("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"),
                "./gradlew build"),
    ".next": (("package.json",), "next build / next dev"),
    ".nuxt": (("package.json",), "nuxt build"),
    ".svelte-kit": (("package.json",), "vite build"),
    ".turbo": (("package.json", "turbo.json"), "turbo"),
    ".parcel-cache": (("package.json",), "parcel"),
    ".angular": (("angular.json",), "ng build"),
    "Pods": (("Podfile",), "pod install"),
    ".pio": (("platformio.ini",), "pio run"),
    ".dart_tool": (("pubspec.yaml",), "flutter pub get"),
    ".tox": (("tox.ini", "pyproject.toml", "setup.py"), "tox"),
    ".nox": (("noxfile.py",), "nox"),
    "_build": (("mix.exs",), "mix compile"),
    "deps": (("mix.exs",), "mix deps.get"),
    ".stack-work": (("stack.yaml",), "stack build"),
    ".zig-cache": (("build.zig",), "zig build"),
    "zig-cache": (("build.zig",), "zig build"),
    "DerivedData": (("*.xcodeproj",), "сборка в Xcode"),
    ".cxx": (("build.gradle", "build.gradle.kts", "CMakeLists.txt"), "./gradlew build"),
    ".expo": (("package.json", "app.json"), "expo start"),
}


def artifact_kind(name: str, parent_entries: set[str]) -> str | None:
    spec = ARTIFACTS.get(name)
    if not spec:
        if name.startswith("cmake-build-"):
            return "CLion cmake-build"
        return None
    markers, _ = spec
    for m in markers:
        if m.startswith("*"):
            if any(e.endswith(m[1:]) for e in parent_entries):
                return name
        elif m in parent_entries:
            return name
    return None


def rebuild_hint(name: str) -> str:
    spec = ARTIFACTS.get(name)
    return spec[1] if spec else "повторная сборка"
