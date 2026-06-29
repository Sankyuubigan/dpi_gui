@echo off
cd /d "%~dp0"

:: Auto-detect and init MSVC (Visual Studio Build Tools)
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -legacy -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
    )
)

node build.cjs
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo   BUILD ERROR! Press any key to exit...
    echo ========================================
    pause >nul
    exit /b 1
)

echo.
echo ========================================
echo   Checking DLL dependencies...
echo ========================================
set "EXE_PATH=src-tauri\target\release\dpi_gui.exe"
if exist "%EXE_PATH%" (
    dumpbin /dependents "%EXE_PATH%" 2>nul | findstr /i "\.dll"
    if %ERRORLEVEL% NEQ 0 (
        echo   (dumpbin unavailable, skipping)
    )
)

echo.
echo ========================================
echo   Launching DPI GUI...
echo ========================================
start "" /D "src-tauri\target\release" "%EXE_PATH%"
echo.
echo ========================================
echo   App launched! If nothing appears, check above
echo   for missing DLLs. Window closes in 10s...
echo ========================================
timeout /t 10 >nul 2>&1