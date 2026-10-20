@echo off
setlocal EnableExtensions
rem Windows may default to cp1252; keep Python output and errors in UTF-8.
set "PYTHONIOENCODING=utf-8"
rem 自動尋找可用 Python；只讀檢測，不安裝套件、不修改審查紀錄。
set "SKILL_ROOT=%~dp0.."
set "CHECKER=%~dp0check_python_env.py"
set "PY_BIN="
set "PY_LAUNCHER="
set "FIRST_BIN="
set "FIRST_LAUNCHER="

if defined SECURITY_CODE_REVIEW_PYTHON (
    call :probe "%SECURITY_CODE_REVIEW_PYTHON%"
) else (
    call :probe "python"
    if not defined PY_BIN call :probe "python3"
    if not defined PY_BIN call :probe_launcher
)

if not defined PY_BIN (
    if defined FIRST_BIN (
        if defined FIRST_LAUNCHER (
            "%FIRST_BIN%" -3 "%CHECKER%" 1>&2
            >&2 echo 請先執行：py -3 -m pip install -r "%SKILL_ROOT%\requirements.txt"
        ) else (
            "%FIRST_BIN%" "%CHECKER%" 1>&2
            >&2 echo 請先執行："%FIRST_BIN%" -m pip install -r "%SKILL_ROOT%\requirements.txt"
        )
    ) else (
        >&2 echo ERROR: 此執行環境找不到 Python 3.10+。請安裝 Python 並確認 python、python3 或 py -3 可用。
    )
    exit /b 2
)

if /I "%~1"=="--check" (
    if defined PY_LAUNCHER (
        "%PY_BIN%" -3 "%CHECKER%"
    ) else (
        "%PY_BIN%" "%CHECKER%"
    )
    if errorlevel 1 exit /b 2
    exit /b 0
)
if "%~1"=="" (
    >&2 echo ERROR: 需指定已存在的 Python 腳本，或使用 --check。
    exit /b 2
)
if not exist "%~1" (
    >&2 echo ERROR: Python 腳本不存在：%~1
    exit /b 2
)
if defined PY_LAUNCHER (
    "%PY_BIN%" -3 %*
) else (
    "%PY_BIN%" %*
)
exit /b %errorlevel%

:probe
"%~1" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
if not defined FIRST_BIN set "FIRST_BIN=%~1"
"%~1" "%CHECKER%" --quiet >nul 2>&1
if errorlevel 1 exit /b 0
set "PY_BIN=%~1"
exit /b 0

:probe_launcher
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
if not defined FIRST_BIN (
    set "FIRST_BIN=py"
    set "FIRST_LAUNCHER=1"
)
py -3 "%CHECKER%" --quiet >nul 2>&1
if errorlevel 1 exit /b 0
set "PY_BIN=py"
set "PY_LAUNCHER=1"
exit /b 0
