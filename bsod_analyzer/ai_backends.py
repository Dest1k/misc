# -*- coding: utf-8 -*-
"""Интеграция с установленными ИИ через их CLI (без API, на подписке).

Идея: у пользователя уже установлены и авторизованы приложения/CLI
(Claude Code, Codex CLI, Grok CLI и т.п.). Мы просто запускаем их
исполняемые файлы как подпроцесс и передаём промпт — работа идёт через
подписку пользователя, отдельного биллинга по API нет.

Команды запуска настраиваются: они хранятся в конфиге и легко правятся,
т.к. точный синтаксис у разных версий CLI отличается. В шаблоне команды
можно использовать плейсхолдер {prompt}. Если {prompt} отсутствует,
промпт подаётся в stdin.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AIBackend:
    key: str                      # внутренний идентификатор
    label: str                    # что видит пользователь
    # Имена исполняемых файлов для автоопределения на PATH.
    executables: List[str] = field(default_factory=list)
    # Шаблон команды. {exe} -> найденный путь, {prompt} -> текст промпта.
    # Если {prompt} нет в шаблоне — промпт уходит в stdin.
    command_template: str = ""
    # Доп. каталоги для поиска исполняемого файла (Windows).
    search_dirs: List[str] = field(default_factory=list)
    # Только копирование промпта в буфер (для GUI-приложений без CLI).
    clipboard_only: bool = False
    notes: str = ""

    def resolve_exe(self) -> Optional[str]:
        if self.clipboard_only:
            return None
        for name in self.executables:
            found = shutil.which(name)
            if found:
                return found
        # Ищем в дополнительных каталогах (с учётом .cmd/.exe на Windows).
        for d in self.search_dirs:
            expanded = os.path.expandvars(os.path.expanduser(d))
            for name in self.executables:
                for ext in ("", ".cmd", ".exe", ".bat"):
                    cand = os.path.join(expanded, name + ext)
                    if os.path.isfile(cand):
                        return cand
        return None

    def is_available(self) -> bool:
        return self.clipboard_only or self.resolve_exe() is not None


# %APPDATA%\npm — типичное место глобальных npm-CLI на Windows.
_NPM_DIR = r"%APPDATA%\npm"
_LOCAL_BIN = r"%LOCALAPPDATA%\Programs"


def default_backends() -> List[AIBackend]:
    return [
        AIBackend(
            key="claude",
            label="Claude Code (подписка)",
            executables=["claude"],
            command_template='{exe} -p {prompt}',
            search_dirs=[_NPM_DIR, r"%USERPROFILE%\.local\bin"],
            notes="Headless-режим Claude Code: claude -p \"...\". "
                  "Работает на вашей подписке Claude.",
        ),
        AIBackend(
            key="codex",
            label="Codex CLI (подписка ChatGPT)",
            executables=["codex"],
            command_template='{exe} exec {prompt}',
            search_dirs=[_NPM_DIR, _LOCAL_BIN],
            notes="Неинтерактивный режим: codex exec \"...\". "
                  "Использует вход в ChatGPT.",
        ),
        AIBackend(
            key="grok",
            label="Grok CLI (SuperGrok)",
            executables=["grok"],
            command_template='{exe} {prompt}',
            search_dirs=[_NPM_DIR, _LOCAL_BIN],
            notes="CLI xAI Grok. Точный синтаксис зависит от версии — при "
                  "необходимости поправьте шаблон команды в настройках.",
        ),
        AIBackend(
            key="claude_desktop",
            label="Claude Desktop (скопировать промпт)",
            clipboard_only=True,
            notes="У Claude Desktop нет CLI. Промпт копируется в буфер обмена — "
                  "вставьте его в окно Claude Desktop.",
        ),
        AIBackend(
            key="clipboard",
            label="Просто скопировать промпт в буфер",
            clipboard_only=True,
            notes="Скопировать готовый промпт, чтобы вставить в любой чат "
                  "(Grok Build, ChatGPT, Gemini и т.д.).",
        ),
    ]


@dataclass
class AIResult:
    ok: bool
    text: str
    backend: str
    error: Optional[str] = None


class AIRunner:
    """Хранит бэкенды и умеет запускать выбранный с заданным промптом."""

    def __init__(self, backends: Optional[List[AIBackend]] = None):
        self.backends: List[AIBackend] = backends or default_backends()

    def by_key(self, key: str) -> Optional[AIBackend]:
        for b in self.backends:
            if b.key == key:
                return b
        return None

    def available(self) -> List[AIBackend]:
        return [b for b in self.backends if b.is_available()]

    def run(self, key: str, prompt: str, timeout: int = 300) -> AIResult:
        backend = self.by_key(key)
        if backend is None:
            return AIResult(False, "", key, "Неизвестный бэкенд.")
        if backend.clipboard_only:
            return AIResult(False, "", key,
                            "Это бэкенд только для копирования — "
                            "используйте кнопку копирования промпта.")

        exe = backend.resolve_exe()
        if not exe:
            return AIResult(False, "", key,
                            f"Исполняемый файл не найден: "
                            f"{', '.join(backend.executables)}. "
                            f"Проверьте, что CLI установлен и в PATH.")

        template = backend.command_template or "{exe} {prompt}"
        use_stdin = "{prompt}" not in template

        try:
            if use_stdin:
                cmd = template.replace("{exe}", _q(exe))
                argv = shlex.split(cmd, posix=(os.name != "nt"))
                proc = subprocess.run(
                    argv, input=prompt, capture_output=True, text=True,
                    timeout=timeout, errors="replace",
                )
            else:
                cmd = template.replace("{exe}", _q(exe)).replace(
                    "{prompt}", _q(prompt))
                argv = shlex.split(cmd, posix=(os.name != "nt"))
                proc = subprocess.run(
                    argv, capture_output=True, text=True,
                    timeout=timeout, errors="replace",
                )
        except subprocess.TimeoutExpired:
            return AIResult(False, "", key,
                            f"Превышено время ожидания ответа ({timeout} c).")
        except (OSError, ValueError) as exc:
            return AIResult(False, "", key, f"Ошибка запуска: {exc}")

        text = (proc.stdout or "").strip()
        if proc.returncode != 0 and not text:
            err = (proc.stderr or "").strip() or f"код возврата {proc.returncode}"
            return AIResult(False, "", key, err)
        # Иногда полезный вывод идёт вместе с предупреждениями в stderr.
        if not text and proc.stderr:
            text = proc.stderr.strip()
        return AIResult(True, text, key)


def _q(value: str) -> str:
    """Аккуратно закавычить аргумент для командной строки текущей ОС."""
    if os.name == "nt":
        # На Windows shlex.split(posix=False) сохраняет кавычки — обрамляем.
        if not value:
            return '""'
        if any(c in value for c in ' \t"\n'):
            escaped = value.replace('"', '\\"')
            return f'"{escaped}"'
        return value
    return shlex.quote(value)
