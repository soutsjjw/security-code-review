@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Python 3.10+ runner. Read-only discovery; never install packages or change review data.
set "PYTHONIOENCODING=utf-8"
set "SKILL_ROOT=%~dp0.."
set "CHECKER=%~dp0check_python_env.py"
set "PY_BIN="
set "FIRST_BIN="
set "FOUND_ENTRY="

rem A pinned interpreter is strict: never silently switch during a review.
if defined SECURITY_CODE_REVIEW_PYTHON_PINNED (
    call :probe "%SECURITY_CODE_REVIEW_PYTHON_PINNED%"
    if not defined PY_BIN (
        >&2 echo ERROR [pinned_python_unavailable]: Pinned Python cannot be executed or fails Python 3.10+ / requirements validation.
        if defined FIRST_BIN call :report_first
        exit /b 2
    )
) else (
    rem User preference is advisory. Fall back when it is stale or incomplete.
    if defined SECURITY_CODE_REVIEW_PYTHON (
        call :probe "%SECURITY_CODE_REVIEW_PYTHON%"
        if not defined PY_BIN >&2 echo WARN [preferred_python_unavailable]: Trying other installed Python interpreters.
    )
    if not defined PY_BIN if defined VIRTUAL_ENV call :probe "%VIRTUAL_ENV%\Scripts\python.exe"
    if not defined PY_BIN if defined CONDA_PREFIX call :probe "%CONDA_PREFIX%\python.exe"
    if not defined PY_BIN call :probe "%SKILL_ROOT%\.venv\Scripts\python.exe"
    if not defined PY_BIN call :probe_by_name "python"
    if not defined PY_BIN call :probe_by_name "python3"
    if not defined PY_BIN call :probe_launcher
    rem Per-user and machine-wide installations may be missing from Codex's PATH.
    if not defined PY_BIN if defined LOCALAPPDATA (
        for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
            if not defined PY_BIN if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
        )
    )
    if not defined PY_BIN if defined ProgramFiles (
        for /d %%D in ("%ProgramFiles%\Python3*") do (
            if not defined PY_BIN if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
        )
    )
    if not defined PY_BIN if defined USERPROFILE (
        if exist "%USERPROFILE%\scoop\apps\python\current\python.exe" call :probe "%USERPROFILE%\scoop\apps\python\current\python.exe"
        for /d %%D in ("%USERPROFILE%\.pyenv\pyenv-win\versions\*") do (
            if not defined PY_BIN if exist "%%~fD\python.exe" call :probe "%%~fD\python.exe"
        )
    )
)
if not defined PY_BIN (
    if defined FIRST_BIN (
        >&2 echo ERROR [python_dependencies_invalid]: Found Python 3.10+, but Skill dependencies are missing or incompatible.
        "%FIRST_BIN%" "%CHECKER%" 1>&2
    ) else (
        if defined FOUND_ENTRY (
            >&2 echo ERROR [python_not_executable]: Python files were found but could not run Python 3.10+. Check versions and sandbox permissions.
        ) else (
            >&2 echo ERROR [python_not_visible]: No usable Python 3.10+ is visible from this CMD/Codex environment. Check PATH, WSL or sandbox isolation.
        )
    )
    exit /b 2
)
if /I "%~1"=="--resolve" (
    echo(%PY_BIN%
    exit /b 0
)
if /I "%~1"=="--check" (
    "%PY_BIN%" "%CHECKER%"
    if errorlevel 1 exit /b 2
    exit /b 0
)
if "%~1"=="" (
    >&2 echo ERROR: Provide a Python script or --check/--resolve.
    exit /b 2
)
if not exist "%~1" (
    >&2 echo ERROR: Python script not found: %~1
    exit /b 2
)
"%PY_BIN%" %*
exit /b %errorlevel%

:probe
if defined PY_BIN exit /b 0
if not exist "%~1" exit /b 1
set "FOUND_ENTRY=1"
"%~1" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 1
if not defined FIRST_BIN set "FIRST_BIN=%~1"
"%~1" "%CHECKER%" --quiet >nul 2>&1
if errorlevel 1 exit /b 1
set "PY_BIN=%~f1"
exit /b 0

:probe_by_name
if defined PY_BIN exit /b 0
if not exist "%SystemRoot%\System32\where.exe" exit /b 1
for /f "delims=" %%P in ('"%SystemRoot%\System32\where.exe" "%~1" 2^>nul') do (
    if /I not "%%~dpP"=="%CD%\" if not defined PY_BIN call :probe "%%P"
)
exit /b 0

:probe_launcher
if defined PY_BIN exit /b 0
for %%V in (3 3.15 3.14 3.13 3.12 3.11 3.10) do (
    if not defined PY_BIN call :launcher_version %%V
)
exit /b 0

:launcher_version
for /f "delims=" %%P in ('py -%~1 -c "import sys; print(sys.executable)" 2^>nul') do (
    if not defined PY_BIN call :probe "%%P"
)
exit /b 0

:report_first
"%FIRST_BIN%" "%CHECKER%" 1>&2
exit /b 0
