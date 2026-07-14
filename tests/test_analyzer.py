# -*- coding: utf-8 -*-
"""Core parser, debugger-evidence and report tests."""

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bsod_analyzer import bugcheck_db, dump_parser, remediation, report  # noqa: E402
from bsod_analyzer.diagnosis import diagnose  # noqa: E402


def make_kernel64_dump(bugcheck, params, machine=0x8664):
    buf = bytearray(0x2000)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DU64"
    struct.pack_into("<I", buf, 0x30, machine)
    struct.pack_into("<I", buf, 0x34, 8)
    struct.pack_into("<I", buf, 0x38, bugcheck)
    struct.pack_into("<4Q", buf, 0x40, *params)
    return bytes(buf)


def make_kernel32_dump(bugcheck, params, machine=0x014C):
    """Real DUMP_HEADER32 offsets, deliberately unlike DUMP_HEADER64."""
    buf = bytearray(0x1000)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DUMP"
    struct.pack_into("<I", buf, 0x20, machine)
    struct.pack_into("<I", buf, 0x24, 4)
    struct.pack_into("<I", buf, 0x28, bugcheck)
    struct.pack_into("<4I", buf, 0x2C, *params)
    # Poison the old, wrong offsets so the regression cannot pass by accident.
    struct.pack_into("<I", buf, 0x38, 0xDEADC0DE)
    return bytes(buf)


def make_user_minidump(exception_code):
    header_size = 32
    directory_size = 12
    exception_offset = header_size + directory_size
    exception_stream = struct.pack("<III", 1234, 0, exception_code) + b"\x00" * 20
    header = struct.pack(
        "<4sIIIIIQ", b"MDMP", 0xA793, 1, header_size, 0, 0, 0,
    )
    directory = struct.pack("<III", 6, len(exception_stream), exception_offset)
    return header + directory + exception_stream


class TemporaryDumpMixin:
    def write_dump(self, data):
        fd, path = tempfile.mkstemp(suffix=".dmp")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return Path(path)


class TestKernelParsing(TemporaryDumpMixin, unittest.TestCase):
    def test_kernel64_d1(self):
        path = self.write_dump(
            make_kernel64_dump(0xD1, [0x28, 0x2, 0x1, 0xFFFFF800A1B2C3D4])
        )
        analysis = dump_parser.parse_header(path)
        self.assertEqual(analysis.dump_format, "kernel64")
        self.assertEqual(analysis.arch, "x64")
        self.assertEqual(analysis.bugcheck_code, 0xD1)
        self.assertEqual(analysis.bugcheck.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL")
        self.assertEqual(analysis.bugcheck_params[3], 0xFFFFF800A1B2C3D4)

    def test_kernel32_uses_real_header_offsets(self):
        path = self.write_dump(make_kernel32_dump(0x1A, [0x41790, 1, 2, 3]))
        analysis = dump_parser.parse_header(path)
        self.assertEqual(analysis.dump_format, "kernel32")
        self.assertEqual(analysis.arch, "x86")
        self.assertEqual(analysis.bugcheck_code, 0x1A)
        self.assertEqual(analysis.bugcheck_params, [0x41790, 1, 2, 3])
        self.assertNotEqual(analysis.bugcheck_code, 0xDEADC0DE)

    def test_unknown_code_is_preserved(self):
        analysis = dump_parser.parse_header(
            self.write_dump(make_kernel64_dump(0xDEADBE, [0, 0, 0, 0]))
        )
        self.assertEqual(analysis.bugcheck_code, 0xDEADBE)
        self.assertIsNone(analysis.bugcheck)

    def test_garbage_is_rejected(self):
        analysis = dump_parser.parse_header(
            self.write_dump(b"not a dump at all" * 10)
        )
        self.assertEqual(analysis.dump_format, "unknown")
        self.assertIsNotNone(analysis.parse_error)


class TestMinidumpParsing(TemporaryDumpMixin, unittest.TestCase):
    def test_user_exception_stream(self):
        analysis = dump_parser.parse_header(
            self.write_dump(make_user_minidump(0xC0000005))
        )
        self.assertEqual(analysis.dump_format, "userdump")
        self.assertEqual(analysis.exception_code, 0xC0000005)

    def test_stream_directory_out_of_bounds(self):
        data = struct.pack(
            "<4sIIIIIQ", b"MDMP", 0xA793, 1, 0x7FFFFFF0, 0, 0, 0,
        )
        analysis = dump_parser.parse_header(self.write_dump(data))
        self.assertIn("границы", analysis.parse_error)

    def test_exception_stream_out_of_bounds_is_not_read(self):
        header = struct.pack(
            "<4sIIIIIQ", b"MDMP", 0xA793, 1, 32, 0, 0, 0,
        )
        directory = struct.pack("<III", 6, 168, 0x100000)
        analysis = dump_parser.parse_header(self.write_dump(header + directory))
        self.assertIsNone(analysis.exception_code)
        self.assertTrue(any("границы" in item for item in analysis.analysis_warnings))

    def test_absurd_stream_count_is_rejected(self):
        data = struct.pack(
            "<4sIIIIIQ", b"MDMP", 0xA793, 999999, 32, 0, 0, 0,
        )
        analysis = dump_parser.parse_header(self.write_dump(data))
        self.assertIn("много потоков", analysis.parse_error)


class TestCdbEvidence(unittest.TestCase):
    def make_analysis(self, code=0xD1, params=None):
        analysis = dump_parser.DumpAnalysis(path=Path("C:/test.dmp"))
        analysis.dump_format = "kernel64"
        analysis.arch = "x64"
        analysis.bugcheck_code = code
        analysis.bugcheck_params = params or [0, 0, 0, 0]
        analysis.bugcheck = bugcheck_db.lookup(code)
        return analysis

    def test_whea_selects_errrec(self):
        analysis = self.make_analysis(0x124, [0, 0xFFFFAABBCCDDEEFF, 0, 0])
        commands = dump_parser.build_cdb_commands(analysis)
        self.assertIn("!errrec 0xFFFFAABBCCDDEEFF", commands)
        self.assertIn(".bugcheck", commands)
        self.assertIn("kv 40", commands)

    def test_power_state_selects_irp_for_arg1_three(self):
        analysis = self.make_analysis(0x9F, [3, 0, 0, 0xFFFF1234])
        self.assertIn("!irp 0xFFFF1234", dump_parser.build_cdb_commands(analysis))

    def test_lmvm_metadata_parsing(self):
        text = """
            Image path: \\SystemRoot\\System32\\drivers\\acme.sys
            Image name: acme.sys
            Timestamp: Tue Jan 02 12:34:56 2024
            ImageSize: 00012000
            CompanyName      Acme Devices Ltd.
            ProductName      Acme Filter
            ProductVersion   4.2.1
            FileVersion      4.2.1.7
            FileDescription  Acme kernel filter
        """
        details = dump_parser.parse_lmvm(text, "acme")
        self.assertEqual(details.company_name, "Acme Devices Ltd.")
        self.assertEqual(details.file_version, "4.2.1.7")
        self.assertIn("drivers", details.image_path)

    def test_cdb_cross_check_detects_mismatch(self):
        analysis = self.make_analysis(0xD1, [1, 2, 3, 4])
        output = """
Bugcheck code 0000000a
Arguments 00000000`00000001 00000000`00000002 00000000`00000003 00000000`00000004
IMAGE_NAME: acme.sys
MODULE_NAME: acme
SYMBOL_NAME: acme!Crash
"""
        dump_parser.enrich_from_cdb(analysis, output)
        self.assertTrue(analysis.bugcheck_mismatch)

    def test_malicious_module_is_never_used_for_lmvm(self):
        analysis = self.make_analysis()
        analysis.image_name = "evil;!process 0 0"
        self.assertIsNone(dump_parser.safe_module_for_lmvm(analysis))


class TestEvidenceDiagnosis(unittest.TestCase):
    def make_analysis(self, code=0xD1):
        analysis = dump_parser.DumpAnalysis(path=Path("C:/Windows/Minidump/test.dmp"))
        analysis.dump_format = "kernel64"
        analysis.arch = "x64"
        analysis.bugcheck_code = code
        analysis.bugcheck_params = [0x28, 2, 1, 0xFFFF]
        analysis.bugcheck = bugcheck_db.lookup(code)
        analysis.cdb_used = True
        analysis.symbol_status = "good"
        return analysis

    def test_system_proxy_is_not_named_culprit(self):
        analysis = self.make_analysis()
        analysis.caused_by = "ntkrnlmp.exe"
        analysis.image_name = "ntkrnlmp.exe"
        analysis.module_name = "nt"
        analysis.stack_modules = ["nt", "ntkrnlmp"]
        diagnosis = diagnose(analysis)
        self.assertIsNone(diagnosis.suspected_module)
        self.assertNotEqual(diagnosis.confidence, "high")

    def test_lone_probably_caused_by_is_only_a_lead(self):
        analysis = self.make_analysis()
        analysis.caused_by = "acmeflt.sys"
        diagnosis = diagnose(analysis)
        self.assertIsNone(diagnosis.suspected_module)
        self.assertIn(diagnosis.confidence, ("very_low", "low"))

    def test_consistent_third_party_signals_raise_confidence(self):
        analysis = self.make_analysis()
        analysis.caused_by = "acmeflt.sys"
        analysis.image_name = "acmeflt.sys"
        analysis.module_name = "acmeflt"
        analysis.symbol_name = "acmeflt!FilterDispatch"
        analysis.stack_modules = ["acmeflt", "nt", "acmeflt"]
        analysis.failure_bucket = "AV_acmeflt!FilterDispatch"
        diagnosis = diagnose(analysis)
        self.assertEqual(diagnosis.suspected_module, "acmeflt.sys")
        self.assertIn(diagnosis.confidence, ("medium", "high"))

    def test_bad_symbols_reduce_confidence(self):
        analysis = self.make_analysis()
        analysis.caused_by = "acmeflt.sys"
        analysis.image_name = "acmeflt.sys"
        analysis.module_name = "acmeflt"
        analysis.stack_modules = ["acmeflt", "acmeflt"]
        good = diagnose(analysis)
        analysis.symbol_status = "poor"
        analysis.symbol_warnings = ["symbols could not be loaded", "wrong symbols"]
        poor = diagnose(analysis)
        confidence_order = {"very_low": 0, "low": 1, "medium": 2, "high": 3}
        self.assertLessEqual(
            confidence_order[poor.confidence], confidence_order[good.confidence]
        )
        self.assertTrue(any("символ" in item.lower() for item in poor.confidence_reducers))

    def test_nvme_is_not_mistaken_for_nvidia(self):
        analysis = self.make_analysis()
        analysis.image_name = "stornvme.sys"
        analysis.module_name = "stornvme"
        analysis.stack_modules = ["stornvme", "storport"]
        diagnosis = diagnose(analysis)
        self.assertEqual(diagnosis.category, "storage")
        self.assertNotEqual(diagnosis.category, "gpu")

    def test_memory_report_does_not_claim_ram_is_proven_broken(self):
        analysis = self.make_analysis(0x1A)
        analysis.bugcheck = bugcheck_db.lookup(0x1A)
        analysis.diagnosis = diagnose(analysis)
        text = report.build_human_report(analysis)
        self.assertIn("не доказательство", text)
        self.assertIn("СПРАВОЧНЫЙ ФОН", text)


class TestPlanCompatibility(unittest.TestCase):
    def test_report_and_plan_still_build_without_cdb(self):
        analysis = dump_parser.DumpAnalysis(path=Path("C:/test.dmp"))
        analysis.dump_format = "kernel64"
        analysis.bugcheck_code = 0x116
        analysis.bugcheck_params = [0, 0, 0, 0]
        analysis.bugcheck = bugcheck_db.lookup(0x116)
        analysis.diagnosis = diagnose(analysis)
        self.assertIn("STOP-код", report.build_human_report(analysis))
        plan = remediation.build_plan(analysis)
        self.assertTrue(plan)
        self.assertTrue(all(step.title for step in plan))


class TestBugcheckDB(unittest.TestCase):
    def test_lookup_low_bits(self):
        self.assertIsNotNone(bugcheck_db.lookup(0x1000007E))

    def test_exception_lookup(self):
        self.assertIn("ACCESS_VIOLATION", bugcheck_db.lookup_exception(0xC0000005))


if __name__ == "__main__":
    unittest.main(verbosity=2)
