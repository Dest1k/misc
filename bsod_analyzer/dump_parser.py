# -*- coding: utf-8 -*-
"""Разбор файлов дампов Windows без сторонних библиотек.

Умеет:
  * читать заголовок DUMP_HEADER64 / DUMP_HEADER32 (дампы ядра, BSOD) и
    извлекать STOP-код (bugcheck) и его 4 параметра;
  * распознавать user-mode дампы формата MDMP и доставать код исключения;
  * при наличии cdb.exe (Debugging Tools for Windows) запускать `!analyze -v`
    для глубокого анализа (виновный драйвер, стек, bucket).

Формат заголовка дампа ядра (x64), ключевые смещения:
    0x00 Signature        "PAGE"
    0x04 ValidDump        "DU64"  (или "DUMP" для x86)
    0x30 MachineImageType (ULONG)
    0x34 NumberProcessors (ULONG)
    0x38 BugCheckCode     (ULONG)
    0x40 BugCheckParameter1..4 (ULONG64 x4; для x86 — ULONG x4 с 0x3C)
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import bugcheck_db


@dataclass
class DumpAnalysis:
    path: Path
    dump_format: str = "unknown"        # 'kernel64', 'kernel32', 'userdump', 'unknown'
    arch: str = ""
    bugcheck_code: Optional[int] = None
    bugcheck_params: List[int] = field(default_factory=list)
    exception_code: Optional[int] = None
    bugcheck: Optional[bugcheck_db.BugCheck] = None
    # Данные, извлечённые из вывода cdb (если он запускался):
    probable_module: Optional[str] = None
    failure_bucket: Optional[str] = None
    process_name: Optional[str] = None
    cdb_output: Optional[str] = None
    cdb_used: bool = False
    parse_error: Optional[str] = None

    @property
    def bugcheck_hex(self) -> Optional[str]:
        if self.bugcheck_code is None:
            return None
        return f"0x{self.bugcheck_code:08X}"


# --- Низкоуровневый разбор заголовков --------------------------------------

_SIG_PAGE = b"PAGE"
_VALID_DU64 = b"DU64"
_VALID_DUMP = b"DUMP"
_SIG_MDMP = b"MDMP"

_IMAGE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "ARM64",
    0x01C4: "ARM",
}


def parse_header(path: Path) -> DumpAnalysis:
    """Прочитать заголовок дампа и заполнить базовые поля (без cdb)."""
    result = DumpAnalysis(path=path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x2000)
    except OSError as exc:
        result.parse_error = f"Не удалось прочитать файл: {exc}"
        return result

    if len(head) < 16:
        result.parse_error = "Файл слишком мал для дампа."
        return result

    sig = head[0:4]
    valid = head[4:8]

    if sig == _SIG_PAGE and valid in (_VALID_DU64, _VALID_DUMP):
        if len(head) < 0x60:
            result.parse_error = "Обрезанный заголовок дампа ядра."
            return result
        _parse_kernel_dump(head, valid, result)
    elif sig == _SIG_MDMP:
        _parse_user_dump(path, head, result)
    else:
        result.parse_error = (
            "Неизвестный формат: сигнатура "
            f"{sig!r}/{valid!r}. Возможно, это не файл дампа Windows."
        )
    return result


def _parse_kernel_dump(head: bytes, valid: bytes, result: DumpAnalysis) -> None:
    machine = struct.unpack_from("<I", head, 0x30)[0]
    result.arch = _IMAGE_TYPES.get(machine, f"0x{machine:04X}")

    if valid == _VALID_DU64:
        result.dump_format = "kernel64"
        code = struct.unpack_from("<I", head, 0x38)[0]
        params = list(struct.unpack_from("<4Q", head, 0x40))
    else:
        result.dump_format = "kernel32"
        code = struct.unpack_from("<I", head, 0x38)[0]
        params = list(struct.unpack_from("<4I", head, 0x3C))

    result.bugcheck_code = code
    result.bugcheck_params = params
    result.bugcheck = bugcheck_db.lookup(code)


def _parse_user_dump(path: Path, head: bytes, result: DumpAnalysis) -> None:
    """Разобрать MINIDUMP (user-mode) и достать код исключения из ExceptionStream."""
    result.dump_format = "userdump"
    try:
        number_of_streams = struct.unpack_from("<I", head, 8)[0]
        stream_dir_rva = struct.unpack_from("<I", head, 12)[0]
    except struct.error:
        result.parse_error = "Повреждённый заголовок MDMP."
        return

    # Читаем директорию потоков целиком.
    try:
        with open(path, "rb") as fh:
            fh.seek(stream_dir_rva)
            directory = fh.read(number_of_streams * 12)
            for i in range(number_of_streams):
                off = i * 12
                if off + 12 > len(directory):
                    break
                stream_type, data_size, rva = struct.unpack_from("<III", directory, off)
                if stream_type == 6:  # ExceptionStream
                    fh.seek(rva)
                    ex = fh.read(data_size if data_size else 168)
                    # MINIDUMP_EXCEPTION_STREAM: ThreadId(4), align(4),
                    # затем MINIDUMP_EXCEPTION: ExceptionCode(4) ...
                    if len(ex) >= 12:
                        exc_code = struct.unpack_from("<I", ex, 8)[0]
                        result.exception_code = exc_code
                    break
    except OSError as exc:
        result.parse_error = f"Ошибка чтения MDMP: {exc}"


# --- Глубокий анализ через cdb.exe -----------------------------------------

_CDB_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\11\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Windows Kits\11\Debuggers\x64\cdb.exe",
]

_MS_SYMBOLS = "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols"


def find_cdb() -> Optional[str]:
    """Найти cdb.exe на PATH или в стандартных каталогах Windows Kits."""
    on_path = shutil.which("cdb")
    if on_path:
        return on_path
    for candidate in _CDB_SEARCH_PATHS:
        if os.path.isfile(candidate):
            return candidate
    return None


def run_cdb(path: Path, cdb_exe: Optional[str] = None,
            timeout: int = 240, use_symbols: bool = True) -> Optional[str]:
    """Запустить cdb `!analyze -v` над дампом и вернуть текст вывода.

    Возвращает None, если cdb не найден. Бросает исключение только при
    неожиданных ошибках запуска — таймаут обрабатывается как частичный вывод.
    """
    cdb_exe = cdb_exe or find_cdb()
    if not cdb_exe:
        return None

    args = [cdb_exe, "-z", str(path), "-c", "!analyze -v; q"]
    env = dict(os.environ)
    if use_symbols and "_NT_SYMBOL_PATH" not in env:
        env["_NT_SYMBOL_PATH"] = _MS_SYMBOLS

    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            env=env, errors="replace",
        )
        return proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        return partial + "\n[cdb: превышен таймаут анализа]"


_RE_MODULE = re.compile(r"MODULE_NAME:\s*(\S+)", re.IGNORECASE)
_RE_IMAGE = re.compile(r"IMAGE_NAME:\s*(\S+)", re.IGNORECASE)
_RE_BUCKET = re.compile(r"FAILURE_BUCKET_ID:\s*(\S+)", re.IGNORECASE)
_RE_PROCESS = re.compile(r"PROCESS_NAME:\s*(\S+)", re.IGNORECASE)
_RE_FAULTING = re.compile(r"FAULTING_MODULE:\s*\S+\s+(\S+)", re.IGNORECASE)


def enrich_from_cdb(result: DumpAnalysis, cdb_output: str) -> None:
    """Достать из вывода cdb ключевые поля (виновный модуль, bucket и т.д.)."""
    result.cdb_output = cdb_output
    result.cdb_used = True

    m = _RE_IMAGE.search(cdb_output) or _RE_MODULE.search(cdb_output)
    if m:
        result.probable_module = m.group(1)
    fb = _RE_BUCKET.search(cdb_output)
    if fb:
        result.failure_bucket = fb.group(1)
    pn = _RE_PROCESS.search(cdb_output)
    if pn:
        result.process_name = pn.group(1)
    # Если IMAGE_NAME пуст, попробуем FAULTING_MODULE.
    if not result.probable_module:
        fm = _RE_FAULTING.search(cdb_output)
        if fm:
            result.probable_module = fm.group(1)


def analyze(path: Path, use_cdb: bool = True,
            cdb_exe: Optional[str] = None) -> DumpAnalysis:
    """Полный разбор: заголовок + (опционально) cdb `!analyze -v`."""
    result = parse_header(path)
    if use_cdb:
        cdb_exe = cdb_exe or find_cdb()
        if cdb_exe:
            output = run_cdb(path, cdb_exe=cdb_exe)
            if output:
                enrich_from_cdb(result, output)
    return result
