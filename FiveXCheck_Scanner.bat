@echo off
REM FiveX.check Scanner - Windows Launcher
REM This script installs dependencies and runs the scanner

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   FiveX.check Scanner Launcher
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8+ from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo [OK] Python detected
echo.

REM Install required packages
echo [*] Installing required packages...
python -m pip install requests psutil -q

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [OK] Dependencies installed
echo.

REM Run the scanner
echo [*] Starting FiveX.check Scanner...
echo.

python FiveXCheck_Scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Scanner failed to start
    pause
    exit /b 1
)

endlocal
