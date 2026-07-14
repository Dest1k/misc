# -*- coding: utf-8 -*-
"""Тесты корреляции серии дампов."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bsod_analyzer import bugcheck_db, correlation, dump_parser  # noqa: E402
from bsod_analyzer.diagnosis import diagnose  # noqa: E402


def make(name, code, *, image=None, stack=None, bucket=None):
    a = dump_parser.DumpAnalysis(path=Path("C:/Windows/Minidump/{}".format(name)))
    a.dump_format = "kernel64"
    a.arch = "x64"
    a.bugcheck_code = code
    a.bugcheck_params = [0, 0, 0, 0]
    a.bugcheck = bugcheck_db.lookup(code)
    a.cdb_used = True
    a.symbol_status = "good"
    if image:
        a.caused_by = image
        a.image_name = image
        a.module_name = image.rsplit(".", 1)[0]
    if stack:
        a.stack_modules = stack
    if bucket:
        a.failure_bucket = bucket
    a.diagnosis = diagnose(a)
    return a


class TestCorrelation(unittest.TestCase):
    def test_recurring_third_party_module_is_strongest(self):
        analyses = [
            make("d1.dmp", 0xD1, image="acmeflt.sys",
                 stack=["acmeflt", "nt", "acmeflt"], bucket="AV_acmeflt"),
            make("d2.dmp", 0xD1, image="acmeflt.sys",
                 stack=["acmeflt", "nt"], bucket="AV_acmeflt"),
            make("d3.dmp", 0x50, image="acmeflt.sys", stack=["acmeflt"]),
        ]
        report = correlation.correlate(analyses)
        self.assertEqual(report.total, 3)
        top = report.recurring_modules[0]
        self.assertEqual(top.module, "acmeflt.sys")
        self.assertEqual(top.dump_count, 3)
        text = correlation.format_report(report)
        self.assertIn("acmeflt.sys", text)
        self.assertIn("в 3 из 3", text)

    def test_system_proxy_is_not_a_recurring_culprit(self):
        analyses = [
            make("d1.dmp", 0xD1, image="ntoskrnl.exe", stack=["nt", "ntoskrnl"]),
            make("d2.dmp", 0xD1, image="ntoskrnl.exe", stack=["nt", "ntoskrnl"]),
        ]
        report = correlation.correlate(analyses)
        modules = [r.module for r in report.recurring_modules]
        self.assertNotIn("ntoskrnl.exe", modules)

    def test_bugcheck_distribution_and_dominant(self):
        analyses = [make("a.dmp", 0xD1), make("b.dmp", 0xD1), make("c.dmp", 0x1A)]
        report = correlation.correlate(analyses)
        self.assertEqual(sum(report.bugcheck_distribution.values()), 3)
        self.assertIn("0x000000D1", report.dominant_bugcheck)

    def test_single_dump_has_no_strong_recurrence(self):
        report = correlation.correlate([make("only.dmp", 0xD1, image="acmeflt.sys")])
        text = correlation.format_report(report)
        self.assertIn("Устойчивого", text)

    def test_bucket_grouping(self):
        analyses = [
            make("a.dmp", 0xD1, image="acmeflt.sys", bucket="AV_acmeflt"),
            make("b.dmp", 0xD1, image="acmeflt.sys", bucket="AV_acmeflt"),
        ]
        report = correlation.correlate(analyses)
        self.assertIn("AV_acmeflt", report.bucket_groups)
        self.assertEqual(len(report.bucket_groups["AV_acmeflt"]), 2)

    def test_empty_series(self):
        report = correlation.correlate([])
        self.assertEqual(report.total, 0)
        self.assertIn("Нет дампов", correlation.format_report(report))


if __name__ == "__main__":
    unittest.main(verbosity=2)
