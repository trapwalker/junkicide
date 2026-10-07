# wtf — управление проектом
.PHONY: help install run report report-quick test lint fmt build clean uvx journal config

help:            ## Показать команды
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:         ## Установить зависимости (uv sync)
	uv sync

run:             ## Запустить TUI из исходников
	uv run wtf

report:          ## Текстовый отчёт без интерфейса (полный обход, до 2 минут)
	uv run wtf --report 120 -v

report-quick:    ## Быстрый отчёт: процессы и известные места, без обхода диска
	uv run wtf --report 40 --no-walk

test:            ## Тесты
	uv run pytest -q

lint:            ## Проверка стиля
	uv run ruff check src tests

fmt:             ## Автоисправление стиля
	uv run ruff check --fix src tests

build:           ## Собрать wheel/sdist в dist/
	uv build

uvx:             ## Запустить так, как это сделает пользователь (uvx из локальной папки)
	uvx --from . wtf

journal:         ## Открыть журнал действий
	open -R ~/Library/Logs/wtf/journal.jsonl

config:          ## Открыть файл настроек
	@test -f ~/.config/wtf/config.toml || uv run python -c "from wtf.config import Config; Config.load().save()"
	open ~/.config/wtf/config.toml

clean:           ## Удалить артефакты сборки и кэш прошлых сканирований
	rm -rf dist build .pytest_cache .ruff_cache
	rm -f ~/Library/Caches/wtf/findings.json
