@echo off
REM Launch the HVAC Network Scanner GUI on Windows.
REM Requires Python 3.10+ on PATH.
REM Auto-installs the package on first run.

setlocal

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: python not found on PATH.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if the package is importable; install in editable mode if not
python -c "import hvac_scanner" >nul 2>&1
if errorlevel 1 (
    echo First-run install: pip install -e .
    echo.
    python -m pip install -e . --quiet
    if errorlevel 1 (
        echo.
        echo ERROR: pip install failed. Check Python and pip are working.
        pause
        exit /b 1
    )
    echo Install complete.
    echo.
)

python -m hvac_scanner
if errorlevel 1 (
    echo.
    echo Scanner exited with error code %errorlevel%.
    pause
)

endlocal
