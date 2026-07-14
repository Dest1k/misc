# -*- coding: utf-8 -*-
"""Optional integrations with locally installed AI CLIs.

AI support is opt-in in :mod:`config` and never participates in the primary
local diagnosis.  Default templates send the prompt through stdin, keeping the
full diagnostic text out of the process list.  User templates may still use
``{prompt}`` for an unusual CLI that cannot read stdin; the settings UI warns
that this exposes the prompt in process arguments.
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
    key: str
    label: str
    executables: List[str] = field(default_factory=list)
    command_template: str = ""
    search_dirs: List[str] = field(default_factory=list)
    clipboard_only: bool = False
    notes: str = ""

    def resolve_exe(self) -> Optional[str]:
        if self.clipboard_only:
            return None
        for executable in self.executables:
            found = shutil.which(executable)
            if found:
                return found
        extensions = ("", ".cmd", ".exe", ".bat") if os.name == "nt" else ("",)
        for raw_dir in self.search_dirs:
            directory = os.path.expandvars(os.path.expanduser(raw_dir))
            for executable in self.executables:
                for extension in extensions:
                    candidate = os.path.join(directory, executable + extension)
                    if os.path.isfile(candidate):
                        return candidate
        return None

    def is_available(self) -> bool:
        return self.clipboard_only or self.resolve_exe() is not None


_NPM_DIR = r"%APPDATA%\npm"
_LOCAL_PROGRAMS = r"%LOCALAPPDATA%\Programs"
_USER_LOCAL_BIN = r"%USERPROFILE%\.local\bin"


def default_backends() -> List[AIBackend]:
    return [
        AIBackend(
            key="claude",
            label="Claude Code (подписка)",
            executables=["claude"],
            command_template="{exe} -p",
            search_dirs=[_NPM_DIR, _USER_LOCAL_BIN],
            notes="Неинтерактивный print-режим; промпт подаётся через stdin.",
        ),
        AIBackend(
            key="codex",
            label="Codex CLI (подписка ChatGPT)",
            executables=["codex"],
            command_template="{exe} exec -",
            search_dirs=[_NPM_DIR, _LOCAL_PROGRAMS, _USER_LOCAL_BIN],
            notes="Неинтерактивный exec; '-' означает чтение задания из stdin.",
        ),
        AIBackend(
            key="grok",
            label="Grok CLI (если установлен)",
            executables=["grok"],
            command_template="{exe}",
            search_dirs=[_NPM_DIR, _LOCAL_PROGRAMS, _USER_LOCAL_BIN],
            notes="Синтаксис сторонних Grok CLI различается; шаблон можно исправить в настройках.",
        ),
        AIBackend(
            key="claude_desktop",
            label="Claude Desktop (скопировать промпт)",
            clipboard_only=True,
            notes="Исходный дамп не передаётся; в буфер попадает только текстовый отчёт.",
        ),
        AIBackend(
            key="clipboard",
            label="Просто скопировать промпт",
            clipboard_only=True,
            notes="Для ручной вставки в любой чат.",
        ),
    ]


@dataclass
class AIResult:
    ok: bool
    text: str
    backend: str
    error: Optional[str] = None
    exit_code: Optional[int] = None


def _strip_windows_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _template_argv(template: str, executable: str, prompt: str) -> tuple:
    """Build argv without invoking a shell; return ``(argv, stdin_text)``."""
    raw_tokens = shlex.split(template or "{exe}", posix=(os.name != "nt"))
    if os.name == "nt":
        raw_tokens = [_strip_windows_quotes(token) for token in raw_tokens]
    if not raw_tokens:
        raise ValueError("Пустой шаблон команды ИИ.")

    if not any("{exe}" in token for token in raw_tokens):
        raise ValueError("Шаблон команды должен содержать {exe}.")
    prompt_in_argv = any("{prompt}" in token for token in raw_tokens)
    argv: List[str] = []
    for token in raw_tokens:
        token = token.replace("{exe}", executable)
        if prompt_in_argv:
            token = token.replace("{prompt}", prompt)
        argv.append(token)
    return argv, None if prompt_in_argv else prompt


class AIRunner:
    def __init__(self, backends: Optional[List[AIBackend]] = None):
        self.backends: List[AIBackend] = (
            list(backends) if backends is not None else default_backends()
        )

    def by_key(self, key: str) -> Optional[AIBackend]:
        return next((backend for backend in self.backends if backend.key == key), None)

    def available(self) -> List[AIBackend]:
        return [backend for backend in self.backends if backend.is_available()]

    def run(self, key: str, prompt: str, timeout: int = 300) -> AIResult:
        backend = self.by_key(key)
        if backend is None:
            return AIResult(False, "", key, "Неизвестный ИИ-бэкенд.")
        if backend.clipboard_only:
            return AIResult(False, "", key, "Этот бэкенд предназначен только для копирования промпта.")
        executable = backend.resolve_exe()
        if not executable:
            return AIResult(
                False, "", key,
                "Исполняемый файл не найден: {0}.".format(", ".join(backend.executables)),
            )
        try:
            argv, stdin_text = _template_argv(backend.command_template, executable, prompt)
            environment: Dict[str, str] = dict(os.environ)
            environment.setdefault("NO_COLOR", "1")
            process = subprocess.run(
                argv,
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout)),
                errors="replace",
                env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            return AIResult(
                False, partial.strip(), key,
                "Превышен таймаут ответа ({0} сек.).".format(timeout),
            )
        except (OSError, ValueError) as exc:
            return AIResult(False, "", key, "Ошибка запуска: {0}".format(exc))

        stdout = (process.stdout or "").strip()
        stderr = (process.stderr or "").strip()
        if process.returncode != 0:
            return AIResult(
                False,
                stdout,
                key,
                stderr or "ИИ-CLI завершился с кодом {0}.".format(process.returncode),
                process.returncode,
            )
        text = stdout or stderr
        if not text:
            return AIResult(False, "", key, "ИИ-CLI завершился без текстового ответа.", process.returncode)
        return AIResult(True, text, key, None, process.returncode)
