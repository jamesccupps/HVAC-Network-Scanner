@echo off
REM Launch the HVAC Network Scanner GUI on Windows.
REM Requires Python 3.10+ on PATH.

setlocal

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: python not found on PATH.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/
    pause
    exit /b 1
)

python -m hvac_scanner
if errorlevel 1 (
    echo.
    echo Scanner exited with error code %errorlevel%.
    pause
)

endlocal
