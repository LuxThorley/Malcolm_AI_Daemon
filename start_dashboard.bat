@echo off
cd /d "%~dp0"

rem Prefer 'python', fallback to 'py'
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON=python
) else (
    set PYTHON=py
)

echo Starting local Malcolm AI Daemon dashboard...
start "" http://127.0.0.1:80/
%PYTHON% monitor_server.py
