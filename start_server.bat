@echo off
REM ===========================================================================
REM  Black Downloader My System - Windows launcher
REM
REM  Double-click this file to:
REM    1. Check if all requirements are installed
REM    2. If not, open a visible window to install them
REM    3. Start the local file server and the public tunnel
REM
REM  Optional arguments are forwarded to server.py, e.g.:
REM    start_server.bat --port 9000
REM    start_server.bat --no-tunnel
REM ===========================================================================

setlocal EnableExtensions
cd /d "%~dp0"
title Black Downloader My System

echo ========================================
echo     BLACK DOWNLOADER MY SYSTEM
echo ========================================
echo.

REM --------------------------------------------------------------------------
REM  Step 1 - find Python
REM --------------------------------------------------------------------------
set "PY_CMD="
python --version >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=python"
) else (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "PY_CMD=py -3"
)

if not defined PY_CMD (
    echo [ERROR] Python was not found on this computer.
    echo.
    echo   Install Python 3 from: https://www.python.org/downloads/
    echo   During setup, tick "Add python.exe to PATH", then run this file again.
    echo.
    pause
    exit /b 1
)

REM --------------------------------------------------------------------------
REM  Step 2 - check all requirements (Python version, cloudflared, etc.)
REM --------------------------------------------------------------------------
%PY_CMD% check_requirements.py
set "CHK=%ERRORLEVEL%"

if "%CHK%"=="0" (
    REM All requirements met - launch server directly
    goto :launch
)

if "%CHK%"=="2" (
    REM Install window was opened - exit this launcher
    echo [i] Install window opened. After installation, the server will start.
    echo.
    timeout /t 3 >nul
    exit /b 0
)

REM Unexpected error
echo [ERROR] Requirements check failed.
pause
exit /b 1

:launch
REM --------------------------------------------------------------------------
REM  Step 3 - make sure folders exist
REM --------------------------------------------------------------------------
if not exist "downloads" mkdir "downloads"
if not exist "logs"      mkdir "logs"
if not exist "bin"       mkdir "bin"
if not exist "downloads\.gitkeep" type nul > "downloads\.gitkeep"

REM --------------------------------------------------------------------------
REM  Step 4 - start the file server + tunnel
REM --------------------------------------------------------------------------
echo.
%PY_CMD% -u server.py %*
set "EXITCODE=%ERRORLEVEL%"
echo.

if not "%EXITCODE%"=="0" (
    echo [ERROR] The server exited with code %EXITCODE%.
    echo         See logs\server.log for details.
) else (
    echo [i] Server stopped.
)

echo.
pause
exit /b %EXITCODE%
