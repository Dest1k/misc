# -*- coding: utf-8 -*-
"""Controlled Autofix execution with per-step logs and verification."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .remediation import FixStep, is_auto_safe_step


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def reports_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    return Path(base) / "BSODAnalyzer" / "reports"


def _ps_quote(value: str) -> str:
    """PowerShell single-quoted literal for trusted generated data."""
    return "'{}'".format(value.replace("'", "''"))


def _safe_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in value)
    return (cleaned or "step")[:80]


def build_safe_script(
    steps: Iterable[FixStep], report_root: Optional[Path] = None,
) -> Path:
    """Create a retained PowerShell runner for allow-listed steps only."""
    selected = [step for step in steps if is_auto_safe_step(step)]
    if not selected:
        raise ValueError("Нет разрешённых безопасных шагов для Autofix.")

    root = Path(report_root) if report_root is not None else reports_dir()
    run_id = "{}_{}".format(
        datetime.now().strftime("%Y%m%d_%H%M%S"),
        uuid.uuid4().hex[:8],
    )
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    script_path = run_dir / "run_autofix.ps1"

    lines: List[str] = [
        "$ErrorActionPreference = 'Continue'",
        "$ProgressPreference = 'SilentlyContinue'",
        "$RunDir = {}".format(_ps_quote(str(run_dir))),
        "$Results = @()",
        "$StartedAt = (Get-Date).ToString('o')",
        "",
        "function Invoke-BsodCommand {",
        "    param(",
        "        [string]$StepId,",
        "        [string]$Title,",
        "        [string]$Command,",
        "        [string]$VerifyCommand",
        "    )",
        "    $SafeId = ($StepId -replace '[^A-Za-z0-9_-]', '_')",
        "    $StdoutPath = Join-Path $RunDir ($SafeId + '.stdout.txt')",
        "    $StderrPath = Join-Path $RunDir ($SafeId + '.stderr.txt')",
        "    $VerifyOutPath = Join-Path $RunDir ($SafeId + '.verify.stdout.txt')",
        "    $VerifyErrPath = Join-Path $RunDir ($SafeId + '.verify.stderr.txt')",
        "    $Watch = [System.Diagnostics.Stopwatch]::StartNew()",
        "    $ExitCode = $null",
        "    $LaunchError = $null",
        "    try {",
        "        & $env:ComSpec /d /s /c $Command 1> $StdoutPath 2> $StderrPath",
        "        $ExitCode = $LASTEXITCODE",
        "    } catch {",
        "        $LaunchError = $_.Exception.Message",
        "        $_ | Out-String | Set-Content -LiteralPath $StderrPath -Encoding UTF8",
        "    }",
        "    $Watch.Stop()",
        "",
        "    $VerifyExitCode = $null",
        "    $VerifyStatus = 'not_requested'",
        "    if ($VerifyCommand) {",
        "        try {",
        "            & $env:ComSpec /d /s /c $VerifyCommand 1> $VerifyOutPath 2> $VerifyErrPath",
        "            $VerifyExitCode = $LASTEXITCODE",
        "            if ($VerifyExitCode -eq 0) { $VerifyStatus = 'passed' } else { $VerifyStatus = 'failed' }",
        "        } catch {",
        "            $VerifyStatus = 'error'",
        "            $_ | Out-String | Set-Content -LiteralPath $VerifyErrPath -Encoding UTF8",
        "        }",
        "    }",
        "",
        "    $Status = 'failed'",
        "    if (($ExitCode -eq 0) -and ($VerifyStatus -in @('passed','not_requested'))) { $Status = 'succeeded' }",
        "    if ($LaunchError) { $Status = 'launch_error' }",
        "    $Result = [ordered]@{",
        "        id = $StepId",
        "        title = $Title",
        "        command = $Command",
        "        exit_code = $ExitCode",
        "        duration_ms = $Watch.ElapsedMilliseconds",
        "        stdout_path = $StdoutPath",
        "        stderr_path = $StderrPath",
        "        launch_error = $LaunchError",
        "        verification_command = $VerifyCommand",
        "        verification_exit_code = $VerifyExitCode",
        "        verification_status = $VerifyStatus",
        "        verification_stdout_path = if ($VerifyCommand) { $VerifyOutPath } else { $null }",
        "        verification_stderr_path = if ($VerifyCommand) { $VerifyErrPath } else { $null }",
        "        status = $Status",
        "    }",
        "    return [pscustomobject]$Result",
        "}",
        "",
    ]

    for step in selected:
        lines.extend([
            "Write-Host ''",
            "Write-Host {} -ForegroundColor Cyan".format(
                _ps_quote("=== {} ===".format(step.title))
            ),
            "$Results += Invoke-BsodCommand -StepId {} -Title {} -Command {} -VerifyCommand {}".format(
                _ps_quote(step.step_id),
                _ps_quote(step.title),
                _ps_quote(step.command or ""),
                _ps_quote(step.verify_command or ""),
            ),
        ])

    lines.extend([
        "",
        "$FinishedAt = (Get-Date).ToString('o')",
        "$Succeeded = @($Results | Where-Object { $_.status -eq 'succeeded' }).Count",
        "$Failed = @($Results | Where-Object { $_.status -ne 'succeeded' }).Count",
        "$Summary = [ordered]@{",
        "    schema_version = 1",
        "    run_id = {}".format(_ps_quote(run_id)),
        "    started_at = $StartedAt",
        "    finished_at = $FinishedAt",
        "    computer = $env:COMPUTERNAME",
        "    user = $env:USERNAME",
        "    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        "    succeeded = $Succeeded",
        "    failed = $Failed",
        "    steps = $Results",
        "}",
        "$JsonPath = Join-Path $RunDir 'summary.json'",
        "$TextPath = Join-Path $RunDir 'summary.txt'",
        "$Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $JsonPath -Encoding UTF8",
        "@(",
        "    'BSOD Analyzer Autofix'",
        "    ('Run: ' + {}),".format(_ps_quote(run_id)),
        "    ('Started: ' + $StartedAt),",
        "    ('Finished: ' + $FinishedAt),",
        "    ('Succeeded: ' + $Succeeded),",
        "    ('Failed: ' + $Failed),",
        "    '',",
        "    ($Results | ForEach-Object { '{0}: {1} (exit={2}, verify={3})' -f $_.id,$_.status,$_.exit_code,$_.verification_status })",
        ") | Set-Content -LiteralPath $TextPath -Encoding UTF8",
        "Write-Host ''",
        "Write-Host ('Отчёт сохранён: ' + $RunDir) -ForegroundColor Green",
        "Write-Host ('Успешно: {0}; с ошибкой: {1}' -f $Succeeded,$Failed)",
        "Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null",
    ])

    script_path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8-sig")
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": datetime.now().isoformat(),
        "steps": [
            {
                "id": step.step_id,
                "title": step.title,
                "command": step.command,
                "verification_command": step.verify_command,
                "risk": step.risk,
            }
            for step in selected
        ],
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return script_path


def build_safe_batch(steps: List[FixStep]) -> str:
    """Compatibility alias retained for callers from version 1.0."""
    return str(build_safe_script(steps))


def run_safe_steps(steps: Iterable[FixStep]) -> Tuple[bool, str]:
    if not is_windows():
        return False, (
            "Автоматический запуск доступен только в Windows. План и команды "
            "можно изучить без выполнения."
        )
    selected = [step for step in steps if is_auto_safe_step(step)]
    if not selected:
        return False, "Нет разрешённых безопасных шагов для автоматического запуска."

    try:
        script = build_safe_script(selected)
        # ArgumentList is built from a fixed script path, not dump-controlled data.
        ps_command = (
            "Start-Process -FilePath 'powershell.exe' "
            "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',{}) "
            "-Verb RunAs"
        ).format(_ps_quote(str(script)))
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False,
        )
        return True, (
            "Запущен контролируемый Autofix. После подтверждения UAC откроется "
            "консоль. Полные stdout/stderr, exit code, проверка и JSON-резюме "
            "будут сохранены в: {}"
        ).format(script.parent)
    except (OSError, ValueError) as exc:
        return False, "Не удалось запустить безопасные действия: {}".format(exc)


def run_command(command: str, elevated: bool = True) -> Tuple[bool, str]:
    """Launch one explicitly selected manual command.

    This helper is not part of Autofix and rejects multiline/null-containing
    values.  The UI should only pass commands from the local plan.
    """
    if not is_windows():
        return False, "Команду можно выполнить только в Windows."
    if not command or len(command) > 2048 or "\x00" in command or "\n" in command or "\r" in command:
        return False, "Некорректная команда."
    try:
        if elevated and not is_admin():
            quoted = _ps_quote(command)
            ps = (
                "Start-Process -FilePath $env:ComSpec "
                "-ArgumentList @('/d','/s','/c',{}) -Verb RunAs"
            ).format(quoted)
            subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-Command", ps], shell=False,
            )
        else:
            subprocess.Popen(
                [os.environ.get("ComSpec", "cmd.exe"), "/d", "/s", "/c", command],
                shell=False,
            )
        return True, "Запущено: {}".format(command)
    except OSError as exc:
        return False, "Ошибка запуска: {}".format(exc)
