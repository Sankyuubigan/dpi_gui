@echo off
cd /d "%~dp0"

:: Auto-detect and init MSVC (Visual Studio Build Tools)
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -legacy -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
    )
)

echo ========================================
echo   DPI GUI - Installer Generation
echo ========================================

:: Step 1: Prep (npm install, sidecars, icons)
echo [1/3] Preparing environment...
echo.
node build.cjs
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo   PREP ERROR! Press any key...
    echo ========================================
    pause >nul
    exit /b 1
)

:: Step 2: Tauri build (full with installer)
echo.
echo ========================================
echo [2/3] Building Tauri app (release with installer)...
echo ========================================
echo.

npx tauri build
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo   BUILD ERROR!
    echo   Fix compilation errors and run generate_installer.bat again.
    echo ========================================
    pause >nul
    exit /b 1
)

:: Step 3: Post-build
echo.
echo ========================================
echo [3/3] Post-build operations...
echo ========================================

:: Copy sidecars next to exe
set "BIN_DIR=bin"
set "RELEASE_DIR=src-tauri\target\release"
set "RELEASE_BIN_DIR=%RELEASE_DIR%\bin"

if exist "%BIN_DIR%" if exist "%RELEASE_DIR%" (
    if not exist "%RELEASE_BIN_DIR%" mkdir "%RELEASE_BIN_DIR%"
    for %%f in ("%BIN_DIR%\*") do (
        copy /Y "%%f" "%RELEASE_BIN_DIR%\" >nul 2>&1
    )
    echo   Sidecars copied to release/bin/.
)

:: Verify exe exists
set "EXE_PATH=%RELEASE_DIR%\dpi_gui.exe"
if not exist "%EXE_PATH%" (
    echo.
    echo dpi_gui.exe not found! Build failed.
    pause >nul
    exit /b 1
)

:: Show output locations
echo.
echo ========================================
echo  Build complete!
echo  EXE: %RELEASE_DIR%\dpi_gui.exe
if exist "%RELEASE_DIR%\bundle\nsis\*.exe" (
    for %%f in ("%RELEASE_DIR%\bundle\nsis\*.exe") do (
        echo  Installer: %%f
    )
)
echo ========================================

:: Launch app
echo.
echo Launching DPI GUI...
start "" "%EXE_PATH%"
echo App launched!
timeout /t 2 >nul 2>&1
exit /b 0
