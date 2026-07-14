@echo off
chcp 65001 >nul
title BSOD Dump Analyzer
cd /d "%~dp0"

rem Пытаемся запустить без окна консоли (pythonw), иначе обычным python.
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw run_analyzer.pyw
    goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
    python run_analyzer.pyw
    goto :eof
)

echo Python не найден. Установите Python 3.8+ с https://www.python.org/downloads/
echo и обязательно отметьте "Add Python to PATH" при установке.
pause
