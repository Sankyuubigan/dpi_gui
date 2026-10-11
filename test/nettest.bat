@echo off
REM Temporary wrapper (lives in test/ per core rules 1.2) to run the
REM network-dependent ignored tests that prove the DNS-poisoning fix.
setlocal enableextensions

for %%I in ("%~dp0..") do set "PROJ=%%~fI"

set "VS_INIT_OK="
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%%i\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
        set "VS_INIT_OK=1"
    )
)
if not defined VS_INIT_OK (
  echo [ERROR] Visual Studio not found.
  exit /b 1
)

set "CC="
set "CXX="
set "CMAKE_C_COMPILER_LAUNCHER="
set "CMAKE_CXX_COMPILER_LAUNCHER="
set "RUSTC_WRAPPER="
set "CARGO_BUILD_RUSTC_WRAPPER="

cd /d "%PROJ%\src-tauri"
cargo test -- --ignored --nocapture %*
endlocal