# -*- coding: utf-8 -*-
"""Controlled execution of low-risk remediation steps with durable reports."""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .remediation import FixStep, auto_steps, is_auto_safe


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def reports_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    return Path(base) / "BSODAnalyzer" / "reports"


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:80] or "step"


def _plan_literal(steps: Sequence[FixStep]) -> List[str]:
    lines = ["$plan = @("]
    for step in steps:
        lines.append(
            "  [pscustomobject]@{{id={0}; title={1}; risk={2}; command={3}; verification_command={4}; needs_admin=${5}}}".format(
                _ps_quote(_safe_filename(step.id)),
                _ps_quote(step.title),
                _ps_quote(step.risk),
                _ps_quote(step.command or ""),
                _ps_quote(step.verify_command or ""),
                "true" if step.needs_admin else "false",
            )
        )
    lines.append(")")
    return lines


def build_powershell_script(steps: Sequence[FixStep], root: Optional[Path] = None) -> Path:
    selected = [step for step in steps if is_auto_safe(step)]
    if not selected:
        raise ValueError("Нет разрешённых шагов Autofix.")
    report_root = Path(root) if root else reports_dir()
    report_root.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(prefix="bsod_autofix_", suffix=".ps1", dir=str(report_root))
    os.close(fd)
    path = Path(raw_path)

    lines: List[str] = [
        "$ErrorActionPreference = 'Continue'",
        "$ProgressPreference = 'SilentlyContinue'",
        "$stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'",
        "$reportDir = Join-Path {0} ('run_' + $stamp)".format(_ps_quote(str(report_root))),
        "New-Item -ItemType Directory -Force -Path $reportDir | Out-Null",
        "Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $reportDir 'runner.ps1') -Force",
        "$summary = New-Object System.Collections.ArrayList",
        "",
    ]
    lines.extend(_plan_literal(selected))
    lines.extend([
        "$plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDir 'plan.json') -Encoding UTF8",
        "",
        "function Save-PartialSummary {",
        "  param([System.Collections.IEnumerable]$Items)",
        "  ConvertTo-Json -InputObject @($Items) -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDir 'summary.partial.json') -Encoding UTF8",
        "}",
        "",
        "function Invoke-BSODStep {",
        "  param([string]$Id, [string]$Title, [string]$Command, [string]$VerifyCommand, [string]$Risk)",
        "  $started = Get-Date",
        "  $stdoutPath = Join-Path $reportDir ($Id + '.stdout.txt')",
        "  $stderrPath = Join-Path $reportDir ($Id + '.stderr.txt')",
        "  $verifyStdoutPath = Join-Path $reportDir ($Id + '.verify.stdout.txt')",
        "  $verifyStderrPath = Join-Path $reportDir ($Id + '.verify.stderr.txt')",
        "  $exitCode = -1",
        "  $verifyExitCode = $null",
        "  $verified = $null",
        "  $launchError = $null",
        "  try {",
        "    & cmd.exe /d /s /c $Command 1> $stdoutPath 2> $stderrPath",
        "    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }",
        "  } catch {",
        "    $launchError = $_.Exception.Message",
        "    $launchError | Set-Content -LiteralPath $stderrPath -Encoding UTF8",
        "  }",
        "  if (-not [string]::IsNullOrWhiteSpace($VerifyCommand)) {",
        "    try {",
        "      & cmd.exe /d /s /c $VerifyCommand 1> $verifyStdoutPath 2> $verifyStderrPath",
        "      $verifyExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }",
        "      $verified = ($verifyExitCode -eq 0)",
        "    } catch {",
        "      $verifyExitCode = -1",
        "      $verified = $false",
        "      $_.Exception.Message | Set-Content -LiteralPath $verifyStderrPath -Encoding UTF8",
        "    }",
        "  }",
        "  $ended = Get-Date",
        "  $status = if (($exitCode -eq 0) -and (($verified -eq $null) -or $verified)) { 'passed' } else { 'failed' }",
        "  $record = [pscustomobject]@{",
        "    id=$Id; title=$Title; risk=$Risk; status=$status; command=$Command; exit_code=$exitCode;",
        "    launch_error=$launchError; verification_command=$VerifyCommand;",
        "    verification_exit_code=$verifyExitCode; verified=$verified;",
        "    started=$started.ToString('o'); ended=$ended.ToString('o');",
        "    duration_seconds=[math]::Round(($ended-$started).TotalSeconds,3);",
        "    stdout_log=$stdoutPath; stderr_log=$stderrPath;",
        "    verification_stdout_log=$verifyStdoutPath; verification_stderr_log=$verifyStderrPath",
        "  }",
        "  [void]$summary.Add($record)",
        "  Save-PartialSummary -Items $summary",
        "  return $record",
        "}",
        "",
    ])
    for step in selected:
        lines.extend([
            "Write-Host ''",
            "Write-Host ('=== ' + {0} + ' ===')".format(_ps_quote(step.title)),
            "$record = Invoke-BSODStep -Id {0} -Title {1} -Command {2} -VerifyCommand {3} -Risk {4}".format(
                _ps_quote(_safe_filename(step.id)), _ps_quote(step.title), _ps_quote(step.command or ""),
                _ps_quote(step.verify_command or ""), _ps_quote(step.risk),
            ),
            "Write-Host ('Status: ' + $record.status + '; exit code: ' + $record.exit_code)",
        ])
    lines.extend([
        "",
        "$jsonPath = Join-Path $reportDir 'summary.json'",
        "$textPath = Join-Path $reportDir 'summary.txt'",
        "ConvertTo-Json -InputObject @($summary) -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8",
        "$summary | Format-List * | Out-String | Set-Content -LiteralPath $textPath -Encoding UTF8",
        "Remove-Item -LiteralPath (Join-Path $reportDir 'summary.partial.json') -ErrorAction SilentlyContinue",
        "Write-Host ''",
        "Write-Host ('Готово. Отчёт: ' + $reportDir)",
        "Start-Process explorer.exe -ArgumentList @($reportDir) -ErrorAction SilentlyContinue",
        "Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null",
    ])
    path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8-sig")
    return path


def run_safe_steps(plan: Sequence[FixStep]) -> Tuple[bool, str]:
    selected = auto_steps(plan)
    if not selected:
        return False, "В текущем плане нет разрешённых шагов Autofix."
    if not is_windows():
        return False, "Autofix запускается только в Windows; план и команды доступны для просмотра."
    try:
        script = build_powershell_script(selected)
        powershell = shutil_which_powershell()
        if not powershell:
            return False, "Не найден powershell.exe/pwsh."
        base_args = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
        needs_elevation = any(step.needs_admin for step in selected)
        creation_flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        if needs_elevation and not is_admin():
            argument_line = subprocess.list2cmdline(base_args[1:])
            elevate = [
                powershell, "-NoProfile", "-Command",
                "Start-Process -FilePath {0} -ArgumentList {1} -Verb RunAs".format(
                    _ps_quote(powershell), _ps_quote(argument_line)
                ),
            ]
            subprocess.Popen(elevate, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            subprocess.Popen(base_args, creationflags=creation_flags)
        return True, (
            "Запущено {0} контролируемых шагов. Для каждого сохраняются plan, stdout/stderr, "
            "exit code, длительность, verification и инкрементальный итог в {1}."
        ).format(len(selected), reports_dir())
    except (OSError, ValueError) as exc:
        return False, "Не удалось запустить Autofix: {0}".format(exc)


def shutil_which_powershell() -> Optional[str]:
    # Local import keeps this small module friendly to static tests on non-Windows hosts.
    import shutil
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
