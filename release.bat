@echo off
cd /d "%~dp0"

REM Init MSVC (Visual Studio Build Tools) so cl.exe is on PATH
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -legacy -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
    )
)

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