# -*- coding: utf-8 -*-

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bsod_analyzer import autofix, bugcheck_db, config, dump_parser, remediation  # noqa: E402
from bsod_analyzer.diagnosis import diagnose  # noqa: E402


class TestConfigDefaults(unittest.TestCase):
    def test_ai_is_disabled_by_default(self):
        cfg = config.normalize_config({})
        self.assertIs(cfg["ai_enabled"], False)

    def test_legacy_config_with_ai_commands_stays_disabled(self):
        legacy = {
            "ai_timeout": 900,
            "ai_backends": {"claude": {"command_template": "{exe} -p {prompt}"}},
        }
        cfg = config.normalize_config(legacy)
        self.assertIs(cfg["ai_enabled"], False)
        self.assertEqual(cfg["ai_timeout"], 900)

    def test_explicit_opt_in_is_preserved(self):
        self.assertIs(config.normalize_config({"ai_enabled": True})["ai_enabled"], True)

    def test_invalid_timeouts_are_normalized(self):
        cfg = config.normalize_config({"cdb_timeout": "bad", "ai_timeout": -100})
        self.assertEqual(cfg["cdb_timeout"], 240)
        self.assertEqual(cfg["ai_timeout"], 30)


class PlanMixin:
    def analysis(self, code, image=None):
        value = dump_parser.DumpAnalysis(path=Path("C:/test.dmp"))
        value.dump_format = "kernel64"
        value.arch = "x64"
        value.bugcheck_code = code
        value.bugcheck_params = [0, 0, 0, 0]
        value.bugcheck = bugcheck_db.lookup(code)
        value.cdb_used = True
        value.symbol_status = "good"
        if image:
            value.caused_by = image
            value.image_name = image
            value.module_name = image.rsplit(".", 1)[0]
            value.stack_modules = [value.module_name, value.module_name]
        value.diagnosis = diagnose(value)
        return value


class TestTargetedRemediation(PlanMixin, unittest.TestCase):
    def test_storage_plan_contains_chkdsk_scan_but_not_system_repair(self):
        plan = remediation.build_plan(self.analysis(0x7A))
        commands = [step.command or "" for step in plan]
        self.assertIn(remediation.CMD_CHKDSK_SCAN, commands)
        self.assertNotIn(remediation.CMD_SFC, commands)
        self.assertNotIn(remediation.CMD_DISM_RESTORE, commands)

    def test_memory_plan_does_not_run_chkdsk_or_sfc(self):
        plan = remediation.build_plan(self.analysis(0x1A))
        commands = [step.command or "" for step in plan]
        self.assertNotIn(remediation.CMD_CHKDSK_SCAN, commands)
        self.assertNotIn(remediation.CMD_SFC, commands)
        self.assertTrue(any(step.step_id == "collect-memory-info" for step in plan))

    def test_system_corruption_orders_dism_before_sfc(self):
        plan = remediation.build_plan(self.analysis(0xC000021A))
        ids = [step.step_id for step in plan]
        self.assertLess(ids.index("dism-scan"), ids.index("dism-restore"))
        self.assertLess(ids.index("dism-restore"), ids.index("sfc-repair"))

    def test_driver_verifier_never_enters_autofix(self):
        plan = remediation.build_plan(self.analysis(0xD1, "acmeflt.sys"))
        automatic = remediation.auto_steps(plan)
        self.assertTrue(any(step.step_id == "driver-verifier-manual-only" for step in plan))
        self.assertFalse(any("verifier" in (step.command or "").lower() for step in automatic))

    def test_dump_controlled_module_never_reaches_command(self):
        analysis = self.analysis(0xD1)
        analysis.caused_by = "evil.sys & calc.exe"
        analysis.image_name = analysis.caused_by
        analysis.module_name = analysis.caused_by
        analysis.stack_modules = []
        analysis.diagnosis = diagnose(analysis)
        plan = remediation.build_plan(analysis)
        self.assertFalse(any("evil" in (step.command or "").lower() for step in plan))
        self.assertFalse(any("calc" in (step.command or "").lower() for step in plan))


class TestAutofixBoundary(unittest.TestCase):
    def test_safe_auto_flag_cannot_bypass_allowlist(self):
        forged = remediation.FixStep(
            title="forged",
            command="cmd /c whoami & calc.exe",
            explanation="bad",
            safe_auto=True,
            step_id="collect-systeminfo",
            risk="low",
        )
        self.assertFalse(remediation.is_auto_safe_step(forged))
        self.assertEqual(remediation.auto_steps([forged]), [])

    def test_high_risk_step_is_filtered_even_with_known_id(self):
        forged = remediation.FixStep(
            title="forged",
            command=remediation.CMD_SYSTEMINFO,
            explanation="bad",
            safe_auto=True,
            step_id="collect-systeminfo",
            risk="high",
        )
        self.assertFalse(remediation.is_auto_safe_step(forged))

    def test_generated_script_logs_exit_and_verification(self):
        step = remediation.FixStep(
            title="System info",
            command=remediation.CMD_SYSTEMINFO,
            explanation="read only",
            safe_auto=True,
            step_id="collect-systeminfo",
            risk="read-only",
            verify_command="ver",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = autofix.build_safe_script([step], Path(directory))
            text = path.read_text(encoding="utf-8-sig")
            self.assertIn("exit_code", text)
            self.assertIn("verification_status", text)
            self.assertIn("summary.json", text)
            self.assertIn("stdout.txt", text)
            self.assertIn("stderr.txt", text)
            manifest = json.loads((path.parent / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["steps"][0]["id"], "collect-systeminfo")
            self.assertEqual(manifest["steps"][0]["verification_command"], "ver")

    def test_dangerous_operations_are_absent_from_allowlist(self):
        joined = "\n".join(remediation.AUTO_COMMAND_ALLOWLIST.values()).lower()
        for marker in ("verifier", " /f", " /r", "ddu", "delete-driver", "bcdedit"):
            self.assertNotIn(marker, joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
