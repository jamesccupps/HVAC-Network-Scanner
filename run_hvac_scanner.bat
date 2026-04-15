@echo off
title HVAC Network Scanner
echo ========================================
echo  HVAC Network Scanner - Full Discovery
echo ========================================
echo.

:: Find Python - try py launcher with versions, then generic python
set PYEXE=

py -3.13 --version >nul 2>&1
if %errorlevel% equ 0 (set PYEXE=py -3.13& goto :found)

py -3.12 --version >nul 2>&1
if %errorlevel% equ 0 (set PYEXE=py -3.12& goto :found)

py -3.11 --version >nul 2>&1
if %errorlevel% equ 0 (set PYEXE=py -3.11& goto :found)

py -3.10 --version >nul 2>&1
if %errorlevel% equ 0 (set PYEXE=py -3.10& goto :found)

python --version >nul 2>&1
if %errorlevel% equ 0 (set PYEXE=python& goto :found)

echo [ERROR] Python 3.10+ not found.
echo Install from https://python.org
pause
exit /b 1

:found
echo Using: %PYEXE%
echo Checking dependencies...

:: pymodbus is optional (enhances Modbus deep scan)
%PYEXE% -c "import pymodbus" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing pymodbus...
    %PYEXE% -m pip install pymodbus -q
)

echo Dependencies OK.
echo.
echo Launching scanner...
echo.

cd /d "%~dp0"
%PYEXE% hvac_scanner.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Scanner exited with an error.
    pause
)
