# -*- coding: utf-8 -*-
"""Persistent application settings with conservative defaults."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .ai_backends import AIBackend, default_backends


def config_dir() -> Path:
    base = (
        os.environ.get("APPDATA")
        or os.environ.get("XDG_CONFIG_HOME")
        or os.path.expanduser("~/.config")
    )
    return Path(base) / "BSODAnalyzer"


def config_path() -> Path:
    return config_dir() / "config.json"


DEFAULT_CONFIG: Dict[str, Any] = {
    "extra_locations": [],
    "use_cdb": True,
    "cdb_path": "",
    "cdb_timeout": 240,
    # AI is an optional second opinion.  Missing keys in legacy configs must
    # stay disabled as well; enabling it always requires an explicit checkbox.
    "ai_enabled": False,
    "ai_timeout": 300,
    "ai_backends": {},
}


def normalize_config(user: Any) -> Dict[str, Any]:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(user, dict):
        return cfg

    for key in (
        "extra_locations", "use_cdb", "cdb_path", "cdb_timeout",
        "ai_timeout", "ai_backends",
    ):
        if key in user:
            cfg[key] = user[key]

    # Deliberately do not infer this from old AI backend settings.
    cfg["ai_enabled"] = bool(user.get("ai_enabled", False))

    if not isinstance(cfg["extra_locations"], list):
        cfg["extra_locations"] = []
    if not isinstance(cfg["ai_backends"], dict):
        cfg["ai_backends"] = {}
    try:
        cfg["cdb_timeout"] = max(30, min(1800, int(cfg["cdb_timeout"])))
    except (TypeError, ValueError):
        cfg["cdb_timeout"] = DEFAULT_CONFIG["cdb_timeout"]
    try:
        cfg["ai_timeout"] = max(30, min(3600, int(cfg["ai_timeout"])))
    except (TypeError, ValueError):
        cfg["ai_timeout"] = DEFAULT_CONFIG["ai_timeout"]
    cfg["use_cdb"] = bool(cfg["use_cdb"])
    cfg["cdb_path"] = str(cfg["cdb_path"] or "")
    return cfg


def load_config() -> Dict[str, Any]:
    path = config_path()
    try:
        if path.is_file():
            with open(path, "r", encoding="utf-8") as handle:
                return normalize_config(json.load(handle))
    except (OSError, json.JSONDecodeError):
        pass
    return normalize_config({})


def save_config(cfg: Dict[str, Any]) -> None:
    normalized = normalize_config(cfg)
    directory = config_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        temporary = config_path().with_suffix(".json.tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(normalized, handle, ensure_ascii=False, indent=2)
        os.replace(str(temporary), str(config_path()))
        cfg.clear()
        cfg.update(normalized)
    except OSError:
        # The GUI reports operational failures where action is possible; a
        # read-only profile must not crash the analyzer at startup.
        pass


def backends_from_config(cfg: Dict[str, Any]) -> List[AIBackend]:
    backends = default_backends()
    overrides = cfg.get("ai_backends", {}) or {}
    for backend in backends:
        override = overrides.get(backend.key)
        if not isinstance(override, dict):
            continue
        command_template = override.get("command_template")
        executables = override.get("executables")
        if isinstance(command_template, str):
            backend.command_template = command_template
        if isinstance(executables, list) and all(
                isinstance(item, str) for item in executables):
            backend.executables = executables
    return backends
