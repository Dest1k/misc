# -*- coding: utf-8 -*-
"""Исполнение безопасных шагов Autofix и запуск отдельных команд.

Windows-специфично. На других ОС функции возвращают понятную ошибку.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import List, Tuple

from .remediation import FixStep


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    """Проверить, запущены ли мы с правами администратора (Windows)."""
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_safe_batch(steps: List[FixStep]) -> str:
    """Сформировать .bat из безопасных команд и вернуть путь к нему."""
    lines = [
        "@echo off",
        "chcp 65001 >nul",
        "echo ============================================",
        "echo   BSOD Analyzer - безопасные проверки",
        "echo ============================================",
        "echo.",
    ]
    for s in steps:
        if not s.command:
            continue
        lines.append(f"echo === {s.title} ===")
        lines.append(s.command)
        lines.append("echo.")
    lines.append("echo === Готово. Проверьте результаты выше. ===")
    lines.append("pause")

    fd, path = tempfile.mkstemp(suffix=".bat", prefix="bsod_autofix_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\r\n".join(lines))
    return path


def run_safe_steps(steps: List[FixStep]) -> Tuple[bool, str]:
    """Запустить безопасные шаги в отдельной консоли с правами администратора.

    Возвращает (успех_запуска, сообщение). Сам ход выполнения виден в
    открывшемся окне консоли — так пользователь контролирует процесс.
    """
    if not is_windows():
        return False, ("Автоматический запуск проверок доступен только в "
                       "Windows. На этой ОС команды можно посмотреть в плане "
                       "и выполнить вручную.")
    runnable = [s for s in steps if s.command]
    if not runnable:
        return False, "Нет команд для автоматического выполнения."

    batch = build_safe_batch(runnable)
    try:
        # Запускаем консоль с батником от имени администратора через UAC.
        ps = (
            "Start-Process -FilePath cmd.exe "
            f"-ArgumentList '/c \"{batch}\"' -Verb RunAs"
        )
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", ps],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True, ("Открылось окно консоли с запросом прав администратора. "
                      "Подтвердите UAC и следите за ходом проверок там.")
    except OSError as exc:
        return False, f"Не удалось запустить проверки: {exc}"


def run_command(command: str, elevated: bool = True) -> Tuple[bool, str]:
    """Запустить одну команду (например devmgmt.msc или mdsched.exe)."""
    if not is_windows():
        return False, "Команду можно выполнить только в Windows."
    try:
        if elevated and not is_admin():
            ps = f"Start-Process -FilePath cmd.exe -ArgumentList '/c {command}' -Verb RunAs"
            subprocess.Popen(["powershell", "-NoProfile", "-Command", ps])
        else:
            subprocess.Popen(command, shell=True)
        return True, f"Запущено: {command}"
    except OSError as exc:
        return False, f"Ошибка запуска: {exc}"
