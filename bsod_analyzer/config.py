# -*- coding: utf-8 -*-
"""Загрузка/сохранение пользовательских настроек (пути, команды ИИ)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .ai_backends import AIBackend, default_backends


def config_dir() -> Path:
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") \
        or os.path.expanduser("~/.config")
    d = Path(base) / "BSODAnalyzer"
    return d


def config_path() -> Path:
    return config_dir() / "config.json"


DEFAULT_CONFIG: Dict[str, Any] = {
    "extra_locations": [],       # дополнительные папки поиска дампов
    "use_cdb": True,             # запускать ли cdb.exe при анализе
    "cdb_path": "",              # ручной путь к cdb.exe (если не найден авто)
    "ai_timeout": 300,           # таймаут ответа ИИ, секунды
    "ai_backends": {},           # переопределения шаблонов команд по ключу
}


def load_config() -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    path = config_path()
    try:
        if path.is_file():
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            if isinstance(user, dict):
                cfg.update(user)
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    d = config_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        with open(config_path(), "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def backends_from_config(cfg: Dict[str, Any]) -> List[AIBackend]:
    """Применить пользовательские переопределения команд к бэкендам."""
    backends = default_backends()
    overrides = cfg.get("ai_backends", {}) or {}
    for b in backends:
        ov = overrides.get(b.key)
        if isinstance(ov, dict):
            if "command_template" in ov:
                b.command_template = ov["command_template"]
            if "executables" in ov and isinstance(ov["executables"], list):
                b.executables = ov["executables"]
    return backends
