@echo off
set SCRIPT_DIR=%~dp0

if exist "F:\ai\torch\venv\Scripts\python.exe" (
    "F:\ai\torch\venv\Scripts\python.exe" "%SCRIPT_DIR%\stego_eval.py" %*
) else (
    "%SCRIPT_DIR%\.venv\Scripts\python.exe" "%SCRIPT_DIR%\stego_eval.py" %*
)
