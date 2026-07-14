# -*- coding: utf-8 -*-
"""Поиск файлов дампов памяти (BSOD и user-mode) в системе."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass
class DumpFile:
    path: Path
    size: int
    mtime: float
    kind: str  # 'minidump', 'memory', 'crashdump', 'livekernel', 'other'

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def size_human(self) -> str:
        return human_size(self.size)

    @property
    def mtime_str(self) -> str:
        return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def kind_ru(self) -> str:
        return {
            "minidump": "Мини-дамп ядра (BSOD)",
            "memory": "Полный дамп памяти",
            "livekernel": "Live Kernel отчёт",
            "crashdump": "Дамп приложения",
            "other": "Дамп",
        }.get(self.kind, "Дамп")


def human_size(num: int) -> str:
    step = float(num)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if step < 1024.0:
            return f"{step:.0f} {unit}" if unit == "Б" else f"{step:.1f} {unit}"
        step /= 1024.0
    return f"{step:.1f} ПБ"


def default_locations() -> List[Path]:
    """Стандартные места, где Windows хранит дампы.

    На не-Windows системах возвращает пустой список — реальные пути
    подставляются только из переменных окружения Windows.
    """
    locations: List[Path] = []
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if system_root:
        root = Path(system_root)
        locations.append(root / "Minidump")
        locations.append(root / "MEMORY.DMP")           # файл, не папка
        locations.append(root / "LiveKernelReports")

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        locations.append(Path(local_appdata) / "CrashDumps")

    # Общесистемные WER-дампы приложений.
    program_data = os.environ.get("ProgramData")
    if program_data:
        locations.append(Path(program_data) / "Microsoft" / "Windows" /
                         "WER" / "ReportQueue")
    return locations


def classify(path: Path) -> str:
    name = path.name.lower()
    parent = path.parent.name.lower()
    if name == "memory.dmp":
        return "memory"
    if "minidump" in parent:
        return "minidump"
    if "livekernelreports" in parent:
        return "livekernel"
    if "crashdumps" in parent or parent == "reportqueue":
        return "crashdump"
    return "other"


def _iter_dumps_in(location: Path) -> Iterable[Path]:
    try:
        if location.is_file():
            if location.suffix.lower() == ".dmp" or location.name.lower() == "memory.dmp":
                yield location
            return
        if not location.is_dir():
            return
        # Рекурсивно, но неглубоко — WER-очереди бывают вложенными.
        for p in location.rglob("*.dmp"):
            if p.is_file():
                yield p
    except (PermissionError, OSError):
        # Часть системных папок требует прав администратора — просто пропускаем.
        return


def find_dumps(extra_locations: Optional[Iterable[Path]] = None) -> List[DumpFile]:
    """Найти все дампы в стандартных и дополнительных местах.

    Результат отсортирован по времени изменения (свежие сверху).
    """
    seen = set()
    results: List[DumpFile] = []
    locations = list(default_locations())
    if extra_locations:
        locations.extend(Path(p) for p in extra_locations)

    for loc in locations:
        for path in _iter_dumps_in(loc):
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                st = path.stat()
            except OSError:
                continue
            results.append(DumpFile(
                path=path,
                size=st.st_size,
                mtime=st.st_mtime,
                kind=classify(path),
            ))

    results.sort(key=lambda d: d.mtime, reverse=True)
    return results


def delete_dumps(dumps: Iterable[DumpFile]) -> List[tuple]:
    """Удалить дампы. Возвращает список (DumpFile, error_or_None)."""
    outcome = []
    for d in dumps:
        try:
            d.path.unlink()
            outcome.append((d, None))
        except OSError as exc:
            outcome.append((d, str(exc)))
    return outcome
