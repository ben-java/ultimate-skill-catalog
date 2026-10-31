@echo off
REM Launcher for Hermes-HardGate-Daily-Monitor scheduled task.
REM Resolves a working python dynamically (environment over tool-dir pin),
REM so an upgrade of the Hermes tools folder never silently breaks the gate.
setlocal
set "PYTHONIOENCODING=utf-8"


REM 1) Explicit override wins.
if defined HERMES_PYTHON (
    set "PYTHON=%HERMES_PYTHON%"
) else (
    REM 2) Newest hermes tools python (dirs sort by name; 3.14.x newest).
    set "PYTHON="
    for /f "delims=" %%i in ('dir /b /ad "C:\Users\AMMAR\AppData\Local\hermes\tools\python-*" 2^>nul') do set "PYTHON=C:\Users\AMMAR\AppData\Local\hermes\tools\%%i\python.exe"
)
if not defined PYTHON (
    echo [cron] FATAL: no hermes tools python found 1>&2
    exit /b 2
)
if not exist "%PYTHON%" (
    echo [cron] FATAL: python not found: %PYTHON% 1>&2
    exit /b 2
)

REM 3) Health probe (deterministic env; no __pycache__ in audited tree)
set "PYTHONDONTWRITEBYTECODE=1"
REM P5 A3: self-repair on by default (sync canonical -> replicas on drift)
if not defined REPAIR_FLAG set "REPAIR_FLAG=1"
"%PYTHON%" -c "import hashlib" >nul 2>&1
if errorlevel 1 (
    echo [cron] FATAL: python broken at %PYTHON% 1>&2
    exit /b 2
)

REM 4) Put its dir first on PATH so bash/find_python resolves the same env.
for %%P in ("%PYTHON%") do set "PYDIR=%%~dpP"
set "PATH=%PYDIR%;%PATH%"

"C:\Program Files\Git\bin\bash.exe" -lc "/c/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode/scripts/cron-hard-gate-monitor.sh"
exit /b %errorlevel%
