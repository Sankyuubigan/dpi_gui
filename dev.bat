@echo off
cd /d "%~dp0"
echo ========================================
echo   Starting DPI GUI in Developer Mode
echo ========================================

echo [1/2] Cleaning old packages to avoid version conflicts...
if exist "package-lock.json" del /q "package-lock.json"
if exist "node_modules" rmdir /s /q "node_modules"

echo [2/2] Installing dependencies and launching Tauri...
call npm install
call npm run tauri dev
pause