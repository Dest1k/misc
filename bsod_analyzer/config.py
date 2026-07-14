# -*- coding: utf-8 -*-
"""Configuration with conservative migration and AI disabled by default."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .ai_backends import AIBackend, default_backends

SCHEMA_VERSION = 2


def default_symbol_cache() -> str:
    """Use a per-user writable symbol cache when LOCALAPPDATA is available."""
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return str(Path(local) / "BSODAnalyzer" / "symbols")
    return r"C:\Symbols"


DEFAULT_CONFIG: Dict[str, Any] = {
    "schema_version": SCHEMA_VERSION,
    "extra_locations": [],
    "use_cdb": True,
    "cdb_path": "",
    "cdb_timeout": 300,
    "symbol_cache": default_symbol_cache(),
    "ai_enabled": False,
    "ai_timeout": 300,
    "ai_backends": {},
}


def config_dir() -> Path:
    base = (os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
            or os.path.expanduser("~/.config"))
    return Path(base) / "BSODAnalyzer"


def config_path() -> Path:
    return config_dir() / "config.json"


def normalize_config(user: Any) -> Dict[str, Any]:
    """Return a validated config. Missing legacy ``ai_enabled`` stays False."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(user, dict):
        return cfg

    for key in ("cdb_path", "symbol_cache"):
        if isinstance(user.get(key), str):
            cfg[key] = user[key]
    for key in ("use_cdb", "ai_enabled"):
        if isinstance(user.get(key), bool):
            cfg[key] = user[key]
    for key, low, high in (("cdb_timeout", 30, 1800), ("ai_timeout", 30, 3600)):
        value = user.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            cfg[key] = max(low, min(high, value))
    locations = user.get("extra_locations")
    if isinstance(locations, list):
        cfg["extra_locations"] = [x for x in locations if isinstance(x, str)]
    overrides = user.get("ai_backends")
    if isinstance(overrides, dict):
        cfg["ai_backends"] = copy.deepcopy(overrides)
    cfg["schema_version"] = SCHEMA_VERSION
    return cfg


def load_config() -> Dict[str, Any]:
    try:
        with config_path().open("r", encoding="utf-8") as handle:
            return normalize_config(json.load(handle))
    except (OSError, ValueError, TypeError):
        return normalize_config({})


def save_config(cfg: Dict[str, Any]) -> None:
    normalized = normalize_config(cfg)
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    temporary = config_path().with_suffix(".json.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(normalized, handle, ensure_ascii=False, indent=2)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass
    os.replace(str(temporary), str(config_path()))
    cfg.clear()
    cfg.update(normalized)


def backends_from_config(cfg: Dict[str, Any]) -> List[AIBackend]:
    backends = default_backends()
    overrides = cfg.get("ai_backends") if isinstance(cfg, dict) else None
    if not isinstance(overrides, dict):
        return backends
    for backend in backends:
        value = overrides.get(backend.key)
        if not isinstance(value, dict):
            continue
        template = value.get("command_template")
        if isinstance(template, str) and template.strip():
            backend.command_template = template.strip()
        executables = value.get("executables")
        if isinstance(executables, list):
            backend.executables = [x for x in executables if isinstance(x, str) and x]
    return backends


def ai_enabled(cfg: Dict[str, Any]) -> bool:
    """Return the explicit opt-in state; missing/legacy values are disabled."""
    return bool(normalize_config(cfg).get("ai_enabled", False))
