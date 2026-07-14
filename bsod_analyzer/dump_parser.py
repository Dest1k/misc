# -*- coding: utf-8 -*-
"""Разбор файлов дампов Windows без сторонних библиотек.

Ответственность модуля — извлечь ФАКТЫ из файла дампа и (при наличии cdb.exe)
из вывода отладчика. Интерпретация фактов и назначение виновника — задача
`diagnosis.py`; здесь мы намеренно не делаем выводов.

Ключевые смещения заголовков:

DUMP_HEADER64 (x64):
    0x00 Signature "PAGE"      0x04 ValidDump "DU64"
    0x30 MachineImageType      0x34 NumberProcessors
    0x38 BugCheckCode          0x40 BugCheckParameter1..4 (ULONG64 x4)

DUMP_HEADER32 (x86) — смещения ДРУГИЕ, не как у x64:
    0x00 Signature "PAGE"      0x04 ValidDump "DUMP"
    0x20 MachineImageType      0x24 NumberProcessors
    0x28 BugCheckCode          0x2C BugCheckParameter1..4 (ULONG x4)

MINIDUMP (user-mode) начинается с сигнатуры "MDMP"; здесь важнее всего
безопасно проверять смещения потоков относительно размера файла.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import bugcheck_db


@dataclass
class DriverDetails:
    """Метаданные образа драйвера, полученные из `lmvm`."""
    module: Optional[str] = None
    image_path: Optional[str] = None
    image_name: Optional[str] = None
    timestamp: Optional[str] = None
    image_size: Optional[str] = None
    file_version: Optional[str] = None
    product_version: Optional[str] = None
    company_name: Optional[str] = None
    product_name: Optional[str] = None
    file_description: Optional[str] = None


@dataclass
class DumpAnalysis:
    path: Path
    dump_format: str = "unknown"        # kernel64 / kernel32 / userdump / unknown
    arch: str = ""
    # --- факты из заголовка ---
    bugcheck_code: Optional[int] = None
    bugcheck_params: List[int] = field(default_factory=list)
    exception_code: Optional[int] = None
    bugcheck: Optional[bugcheck_db.BugCheck] = None
    parse_error: Optional[str] = None
    analysis_warnings: List[str] = field(default_factory=list)
    # --- факты из вывода cdb/WinDbg ---
    cdb_used: bool = False
    cdb_command: Optional[str] = None
    cdb_output: Optional[str] = None
    cdb_exit_code: Optional[int] = None
    cdb_timed_out: bool = False
    cdb_duration_seconds: Optional[float] = None
    cdb_bugcheck_code: Optional[int] = None
    cdb_bugcheck_params: List[int] = field(default_factory=list)
    bugcheck_mismatch: bool = False
    caused_by: Optional[str] = None
    image_name: Optional[str] = None
    module_name: Optional[str] = None
    symbol_name: Optional[str] = None
    process_name: Optional[str] = None
    failure_bucket: Optional[str] = None
    failure_hash: Optional[str] = None
    stack_modules: List[str] = field(default_factory=list)
    symbol_status: str = "unknown"      # good / partial / poor / unknown
    symbol_warnings: List[str] = field(default_factory=list)
    driver_details: Optional[DriverDetails] = None
    # Обратная совместимость: диагностика читает `image_name or probable_module`.
    probable_module: Optional[str] = None
    # Заполняется diagnosis.diagnose(); тип не импортируем во избежание цикла.
    diagnosis: Optional[object] = None

    @property
    def bugcheck_hex(self) -> Optional[str]:
        if self.bugcheck_code is None:
            return None
        return "0x{:08X}".format(self.bugcheck_code)


# --- Сигнатуры и константы --------------------------------------------------

_SIG_PAGE = b"PAGE"
_VALID_DU64 = b"DU64"
_VALID_DUMP = b"DUMP"
_SIG_MDMP = b"MDMP"

_MAX_MDMP_STREAMS = 4096            # защита от подделанного/битого заголовка
_STREAM_TYPE_EXCEPTION = 6
_MINIDUMP_EXCEPTION_MIN = 12       # ThreadId(4)+align(4)+ExceptionCode(4)

_IMAGE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "ARM64",
    0x01C4: "ARM",
}

# Строгий шаблон безопасного токена модуля: только имя файла, никаких пробелов
# и метасимволов оболочки/отладчика.
_SAFE_MODULE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# --- Разбор заголовков ------------------------------------------------------

def parse_header(path: Path) -> DumpAnalysis:
    """Прочитать заголовок дампа и заполнить фактические поля (без cdb)."""
    result = DumpAnalysis(path=path)
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(0x2000)
    except OSError as exc:
        result.parse_error = "Не удалось прочитать файл: {}".format(exc)
        return result

    if len(head) < 16:
        result.parse_error = "Файл слишком мал для дампа."
        return result

    sig = head[0:4]
    valid = head[4:8]

    if sig == _SIG_PAGE and valid == _VALID_DU64:
        if len(head) < 0x60:
            result.parse_error = "Обрезанный заголовок дампа ядра (x64)."
            return result
        _parse_kernel64(head, result)
    elif sig == _SIG_PAGE and valid == _VALID_DUMP:
        if len(head) < 0x3C:
            result.parse_error = "Обрезанный заголовок дампа ядра (x86)."
            return result
        _parse_kernel32(head, result)
    elif sig == _SIG_MDMP:
        _parse_user_dump(path, head, file_size, result)
    else:
        result.parse_error = (
            "Неизвестный формат: сигнатура {!r}/{!r}. "
            "Возможно, это не файл дампа Windows.".format(sig, valid)
        )
    return result


def _parse_kernel64(head: bytes, result: DumpAnalysis) -> None:
    result.dump_format = "kernel64"
    machine = struct.unpack_from("<I", head, 0x30)[0]
    result.arch = _IMAGE_TYPES.get(machine, "0x{:04X}".format(machine))
    code = struct.unpack_from("<I", head, 0x38)[0]
    params = list(struct.unpack_from("<4Q", head, 0x40))
    _apply_bugcheck(result, code, params)


def _parse_kernel32(head: bytes, result: DumpAnalysis) -> None:
    result.dump_format = "kernel32"
    machine = struct.unpack_from("<I", head, 0x20)[0]
    result.arch = _IMAGE_TYPES.get(machine, "0x{:04X}".format(machine))
    code = struct.unpack_from("<I", head, 0x28)[0]
    params = list(struct.unpack_from("<4I", head, 0x2C))
    _apply_bugcheck(result, code, params)


def _apply_bugcheck(result: DumpAnalysis, code: int, params: List[int]) -> None:
    result.bugcheck_code = code
    result.bugcheck_params = params
    result.bugcheck = bugcheck_db.lookup(code)


def _parse_user_dump(path: Path, head: bytes, file_size: int,
                     result: DumpAnalysis) -> None:
    """Разобрать MINIDUMP и достать код исключения, проверяя все смещения."""
    result.dump_format = "userdump"
    try:
        number_of_streams = struct.unpack_from("<I", head, 8)[0]
        stream_dir_rva = struct.unpack_from("<I", head, 12)[0]
    except struct.error:
        result.parse_error = "Повреждённый заголовок MDMP."
        return

    if number_of_streams > _MAX_MDMP_STREAMS:
        result.parse_error = (
            "Слишком много потоков в MDMP ({}); файл повреждён или подделан."
            .format(number_of_streams)
        )
        return

    directory_bytes = number_of_streams * 12
    if stream_dir_rva + directory_bytes > file_size:
        result.parse_error = (
            "Директория потоков MDMP выходит за границы файла."
        )
        return

    try:
        with open(path, "rb") as fh:
            fh.seek(stream_dir_rva)
            directory = fh.read(directory_bytes)
            for i in range(number_of_streams):
                off = i * 12
                if off + 12 > len(directory):
                    break
                stream_type, data_size, rva = struct.unpack_from(
                    "<III", directory, off)
                if stream_type != _STREAM_TYPE_EXCEPTION:
                    continue
                if data_size < _MINIDUMP_EXCEPTION_MIN or \
                        rva + data_size > file_size:
                    result.analysis_warnings.append(
                        "Поток исключения MDMP выходит за границы файла — "
                        "пропущен.")
                    continue
                fh.seek(rva)
                ex = fh.read(data_size)
                if len(ex) >= _MINIDUMP_EXCEPTION_MIN:
                    result.exception_code = struct.unpack_from("<I", ex, 8)[0]
                break
    except OSError as exc:
        result.parse_error = "Ошибка чтения MDMP: {}".format(exc)


# --- Построение команд отладчика --------------------------------------------

def build_cdb_commands(a: DumpAnalysis) -> List[str]:
    """Собрать список команд WinDbg под конкретный STOP-код.

    Команды строятся ТОЛЬКО из численных параметров дампа, а не из строк —
    поэтому в них невозможно протащить произвольный код.
    """
    commands: List[str] = ["!analyze -v", ".bugcheck", "kv 40", "lm kv"]

    code = (a.bugcheck_code or 0) & 0xFFFFFFFF
    params = a.bugcheck_params or []

    def arg(index: int) -> int:
        return params[index] if index < len(params) else 0

    # WHEA_UNCORRECTABLE_ERROR: параметр 2 — адрес WHEA_ERROR_RECORD.
    if code == 0x124 and arg(1):
        commands.append("!errrec 0x{:X}".format(arg(1)))
    # DRIVER_POWER_STATE_FAILURE: при arg1==3 параметр 4 — адрес IRP.
    if code == 0x9F and arg(0) == 3 and arg(3):
        commands.append("!irp 0x{:X}".format(arg(3)))
    return commands


# --- Поиск и запуск cdb.exe -------------------------------------------------

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


def run_cdb(path: Path, commands: List[str], cdb_exe: Optional[str] = None,
            timeout: int = 240, use_symbols: bool = True):
    """Запустить cdb с заданным списком команд.

    Возвращает кортеж (stdout, exit_code, timed_out, duration, command_str)
    или None, если cdb не найден.
    """
    cdb_exe = cdb_exe or find_cdb()
    if not cdb_exe:
        return None

    script = "; ".join(commands + ["q"])
    args = [cdb_exe, "-z", str(path), "-c", script]
    env = dict(os.environ)
    if use_symbols and "_NT_SYMBOL_PATH" not in env:
        env["_NT_SYMBOL_PATH"] = _MS_SYMBOLS

    started = time.monotonic()
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            env=env, errors="replace",
        )
        duration = time.monotonic() - started
        out = proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
        return out, proc.returncode, False, duration, script
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        partial += "\n[cdb: превышен таймаут анализа]"
        return partial, None, True, duration, script


# --- Разбор вывода cdb ------------------------------------------------------

_RE_MODULE = re.compile(r"MODULE_NAME:\s*(\S+)", re.IGNORECASE)
_RE_IMAGE = re.compile(r"IMAGE_NAME:\s*(\S+)", re.IGNORECASE)
_RE_SYMBOL = re.compile(r"SYMBOL_NAME:\s*(\S+)", re.IGNORECASE)
_RE_BUCKET = re.compile(r"FAILURE_BUCKET_ID:\s*(\S+)", re.IGNORECASE)
_RE_HASH = re.compile(r"FAILURE_ID_HASH(?:_STRING)?:\s*(\S+)", re.IGNORECASE)
_RE_PROCESS = re.compile(r"PROCESS_NAME:\s*(\S+)", re.IGNORECASE)
_RE_CAUSED = re.compile(r"Probably caused by\s*:\s*(\S+)", re.IGNORECASE)
_RE_CDB_CODE = re.compile(r"Bugcheck code\s+([0-9A-Fa-f]+)", re.IGNORECASE)
_RE_CDB_ARGS = re.compile(r"Arguments\s+(.+)", re.IGNORECASE)
_RE_STACK_BLOCK = re.compile(r"STACK_TEXT:\s*\n(.*?)(?:\n\s*\n|\Z)", re.S)
_RE_STACK_MODULE = re.compile(r"([A-Za-z_][A-Za-z0-9_]{1,63})!")
_RE_SYMBOL_PROBLEM = re.compile(
    r"\*\*\* ERROR|could not be loaded|Wrong symbols|checksum does not match|"
    r"Unable to load image|symbols are wrong|defaulted to export symbols",
    re.IGNORECASE)


def _hexint(token: str) -> Optional[int]:
    token = token.replace("`", "").strip()
    try:
        return int(token, 16)
    except ValueError:
        return None


def enrich_from_cdb(result: DumpAnalysis, cdb_output: str) -> None:
    """Извлечь из вывода cdb факты и сверить STOP-код с заголовком."""
    result.cdb_output = cdb_output
    result.cdb_used = True

    m = _RE_IMAGE.search(cdb_output)
    if m:
        result.image_name = m.group(1)
    m = _RE_MODULE.search(cdb_output)
    if m:
        result.module_name = m.group(1)
    m = _RE_SYMBOL.search(cdb_output)
    if m:
        result.symbol_name = m.group(1)
    m = _RE_CAUSED.search(cdb_output)
    if m:
        result.caused_by = m.group(1)
    m = _RE_BUCKET.search(cdb_output)
    if m:
        result.failure_bucket = m.group(1)
    m = _RE_HASH.search(cdb_output)
    if m:
        result.failure_hash = m.group(1)
    m = _RE_PROCESS.search(cdb_output)
    if m:
        result.process_name = m.group(1)

    result.probable_module = result.image_name or result.module_name

    # Стек вызовов — только из блока STACK_TEXT, чтобы не смешивать источники.
    stack_block = _RE_STACK_BLOCK.search(cdb_output)
    if stack_block:
        result.stack_modules = _RE_STACK_MODULE.findall(stack_block.group(1))

    # Кросс-проверка STOP-кода из заголовка и из вывода отладчика.
    cm = _RE_CDB_CODE.search(cdb_output)
    if cm:
        cdb_code = _hexint(cm.group(1))
        if cdb_code is not None:
            result.cdb_bugcheck_code = cdb_code
            if result.bugcheck_code is not None and \
                    (result.bugcheck_code & 0xFFFFFFFF) != (cdb_code & 0xFFFFFFFF):
                result.bugcheck_mismatch = True
    am = _RE_CDB_ARGS.search(cdb_output)
    if am:
        args = [_hexint(tok) for tok in am.group(1).split()]
        result.cdb_bugcheck_params = [x for x in args if x is not None][:4]

    # Качество символов (грубая эвристика; точную оценку задаёт вызывающий).
    if _RE_SYMBOL_PROBLEM.search(cdb_output):
        result.symbol_status = "poor"
        for line in cdb_output.splitlines():
            if _RE_SYMBOL_PROBLEM.search(line):
                result.symbol_warnings.append(line.strip())
        result.symbol_warnings = result.symbol_warnings[:10]
    elif result.symbol_name or result.caused_by:
        result.symbol_status = "good"


# --- Метаданные драйвера (lmvm) ---------------------------------------------

_LMVM_FIELDS = {
    "image_path": re.compile(r"Image path:\s*(.+)", re.IGNORECASE),
    "image_name": re.compile(r"Image name:\s*(.+)", re.IGNORECASE),
    "timestamp": re.compile(r"Timestamp:\s*(.+)", re.IGNORECASE),
    "image_size": re.compile(r"ImageSize:\s*(\S+)", re.IGNORECASE),
    "company_name": re.compile(r"CompanyName\s+(.+)"),
    "product_name": re.compile(r"ProductName\s+(.+)"),
    "product_version": re.compile(r"ProductVersion\s+(.+)"),
    "file_version": re.compile(r"FileVersion\s+(.+)"),
    "file_description": re.compile(r"FileDescription\s+(.+)"),
}


def parse_lmvm(text: str, module: Optional[str] = None) -> DriverDetails:
    """Разобрать вывод `lmvm <module>` в структуру метаданных."""
    details = DriverDetails(module=module)
    for attr, pattern in _LMVM_FIELDS.items():
        m = pattern.search(text)
        if m:
            setattr(details, attr, m.group(1).strip())
    return details


def safe_module_for_lmvm(a: DumpAnalysis) -> Optional[str]:
    """Вернуть безопасный токен модуля для команды `lmvm`, иначе None.

    Никогда не пропускает значения с пробелами, `;`, `!`, `&` и прочими
    метасимволами — даже если они пришли из полей дампа.
    """
    for raw in (a.image_name, a.module_name, a.caused_by):
        if not raw:
            continue
        candidate = raw.strip()
        if not _SAFE_MODULE_RE.fullmatch(candidate):
            continue
        # Для lmvm нужен модуль без расширения.
        return candidate.rsplit(".", 1)[0]
    return None


# --- Полный разбор ----------------------------------------------------------

def analyze(path: Path, use_cdb: bool = True, cdb_exe: Optional[str] = None,
            timeout: int = 240) -> DumpAnalysis:
    """Полный разбор: заголовок + (опционально) сеанс cdb с целевыми командами.

    Итоговая диагностика вычисляется здесь один раз и сохраняется в
    ``result.diagnosis``, чтобы отчёт, план и GUI использовали один и тот же
    вывод, а не пересчитывали его.
    """
    result = parse_header(path)
    if use_cdb:
        cdb_exe = cdb_exe or find_cdb()
        if cdb_exe:
            commands = build_cdb_commands(result)
            ran = run_cdb(path, commands, cdb_exe=cdb_exe, timeout=timeout)
            if ran:
                output, exit_code, timed_out, duration, script = ran
                result.cdb_command = script
                result.cdb_exit_code = exit_code
                result.cdb_timed_out = timed_out
                result.cdb_duration_seconds = duration
                enrich_from_cdb(result, output)

                # Целевой lmvm по безопасному токену модуля, без shell.
                token = safe_module_for_lmvm(result)
                if token:
                    lmvm = run_cdb(path, ["lmvm {}".format(token)],
                                   cdb_exe=cdb_exe, timeout=min(timeout, 120))
                    if lmvm and lmvm[0]:
                        result.driver_details = parse_lmvm(lmvm[0], token)

    # Ленивый импорт разрывает цикл dump_parser <-> diagnosis.
    from .diagnosis import diagnose
    result.diagnosis = diagnose(result)
    return result
