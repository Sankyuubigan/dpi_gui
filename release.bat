@echo off
cd /d "%~dp0"

REM Release build ^& publish to GitHub (signed updater artifacts)
echo ========================================
echo   DPI GUI - Release Build ^& Publish
echo ========================================
node release.cjs
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo   RELEASE ERROR! Press any key to exit...
    echo ========================================
    pause >nul
    exit /b 1
)