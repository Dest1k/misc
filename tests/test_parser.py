# -*- coding: utf-8 -*-
"""Тесты парсера дампов на синтетических файлах (без сторонних зависимостей).

Запуск: python -m unittest discover -s tests
"""

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bsod_analyzer import bugcheck_db, dump_parser, remediation, report  # noqa: E402


def make_kernel64_dump(bugcheck: int, params, machine=0x8664) -> bytes:
    """Собрать минимально валидный заголовок DUMP_HEADER64."""
    buf = bytearray(0x2000)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DU64"
    struct.pack_into("<I", buf, 0x30, machine)     # MachineImageType
    struct.pack_into("<I", buf, 0x34, 8)           # NumberProcessors
    struct.pack_into("<I", buf, 0x38, bugcheck)    # BugCheckCode
    struct.pack_into("<4Q", buf, 0x40, *params)    # 4 x ULONG64
    return bytes(buf)


def make_kernel32_dump(bugcheck: int, params, machine=0x014C) -> bytes:
    buf = bytearray(0x1000)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DUMP"
    struct.pack_into("<I", buf, 0x30, machine)
    struct.pack_into("<I", buf, 0x38, bugcheck)
    struct.pack_into("<4I", buf, 0x3C, *params)
    return bytes(buf)


def make_user_minidump(exception_code: int) -> bytes:
    """Собрать MINIDUMP с одним ExceptionStream (type 6).

    MINIDUMP_HEADER (32 байта): Signature(4) Version(4) NumberOfStreams(4)
    StreamDirectoryRva(4) CheckSum(4) TimeDateStamp(4) Flags(8).
    """
    header_size = 32
    dir_size = 12                       # одна запись директории (12 байт)
    ex_stream_off = header_size + dir_size
    # MINIDUMP_EXCEPTION_STREAM: ThreadId(4) align(4) ExceptionCode(4) ...
    ex_stream = struct.pack("<III", 1234, 0, exception_code) + b"\x00" * 20

    header = struct.pack("<4sIIIIIQ",
                         b"MDMP",         # signature
                         0xA793,          # version
                         1,               # NumberOfStreams
                         header_size,     # StreamDirectoryRva
                         0,               # CheckSum
                         0,               # TimeDateStamp
                         0)               # Flags (ULONG64)
    assert len(header) == header_size
    # Директория: StreamType=6, DataSize, Rva
    directory = struct.pack("<III", 6, len(ex_stream), ex_stream_off)
    return header + directory + ex_stream


class TestKernelParsing(unittest.TestCase):
    def _write(self, data: bytes) -> Path:
        fd, path = tempfile.mkstemp(suffix=".dmp")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return Path(path)

    def test_kernel64_d1(self):
        data = make_kernel64_dump(0xD1, [0x28, 0x2, 0x1, 0xFFFFF800A1B2C3D4])
        path = self._write(data)
        a = dump_parser.parse_header(path)
        self.assertEqual(a.dump_format, "kernel64")
        self.assertEqual(a.arch, "x64")
        self.assertEqual(a.bugcheck_code, 0xD1)
        self.assertEqual(a.bugcheck.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL")
        self.assertEqual(a.bugcheck_params[0], 0x28)
        self.assertEqual(a.bugcheck_params[3], 0xFFFFF800A1B2C3D4)

    def test_kernel64_unknown_code(self):
        data = make_kernel64_dump(0xDEADBE, [0, 0, 0, 0])
        a = dump_parser.parse_header(self._write(data))
        self.assertEqual(a.bugcheck_code, 0xDEADBE)
        self.assertIsNone(a.bugcheck)  # нет в базе, но код извлечён

    def test_kernel32(self):
        data = make_kernel32_dump(0x1A, [0x41790, 0, 0, 0])
        a = dump_parser.parse_header(self._write(data))
        self.assertEqual(a.dump_format, "kernel32")
        self.assertEqual(a.bugcheck_code, 0x1A)
        self.assertEqual(a.bugcheck.name, "MEMORY_MANAGEMENT")

    def test_user_minidump(self):
        data = make_user_minidump(0xC0000005)
        a = dump_parser.parse_header(self._write(data))
        self.assertEqual(a.dump_format, "userdump")
        self.assertEqual(a.exception_code, 0xC0000005)

    def test_garbage(self):
        a = dump_parser.parse_header(self._write(b"not a dump at all" * 10))
        self.assertEqual(a.dump_format, "unknown")
        self.assertIsNotNone(a.parse_error)


class TestReportAndPlan(unittest.TestCase):
    def _analysis(self, code, params):
        a = dump_parser.DumpAnalysis(path=Path("C:/Windows/Minidump/test.dmp"))
        a.dump_format = "kernel64"
        a.arch = "x64"
        a.bugcheck_code = code
        a.bugcheck_params = params
        a.bugcheck = bugcheck_db.lookup(code)
        return a

    def test_human_report_contains_name_and_fix(self):
        a = self._analysis(0xD1, [0x28, 2, 1, 0xFFFF])
        text = report.build_human_report(a)
        self.assertIn("DRIVER_IRQL_NOT_LESS_OR_EQUAL", text)
        self.assertIn("STOP-код", text)
        self.assertIn("КАК ИСПРАВИТЬ", text)

    def test_ai_prompt_has_params(self):
        a = self._analysis(0x116, [0, 0, 0, 0])
        prompt = report.build_ai_prompt(a)
        self.assertIn("0x00000116", prompt)
        self.assertIn("Параметр 1", prompt)

    def test_plan_memory_code_has_memtest(self):
        a = self._analysis(0x1A, [0x41790, 0, 0, 0])
        plan = remediation.build_plan(a)
        titles = " ".join(s.title.lower() for s in plan)
        self.assertIn("памяти", titles)  # должен быть шаг с диагностикой ОЗУ
        auto = remediation.auto_steps(plan)
        self.assertTrue(all(s.safe_auto and s.command for s in auto))
        self.assertTrue(any("sfc" in (s.command or "") for s in auto))

    def test_plan_gpu_code_has_ddu(self):
        a = self._analysis(0x116, [0, 0, 0, 0])
        text = remediation.format_plan(remediation.build_plan(a))
        self.assertIn("DDU", text)


class TestBugcheckDB(unittest.TestCase):
    def test_lookup_low_bits(self):
        # Расширенный код должен находиться по младшим 32 битам.
        b = bugcheck_db.lookup(0x1000007E)
        self.assertIsNotNone(b)

    def test_exception_lookup(self):
        self.assertIn("ACCESS_VIOLATION",
                      bugcheck_db.lookup_exception(0xC0000005))


if __name__ == "__main__":
    unittest.main(verbosity=2)
