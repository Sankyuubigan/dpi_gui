@echo off
chcp 65001 >nul
cd /d "%~dp0"
title DPI GUI Updater
setlocal

:: ОЧИСТКА ПЕРЕМЕННЫХ СРЕДЫ ОТ PYINSTALLER (На всякий случай оставляем)
set PYTHONHOME=
set PYTHONPATH=
set _MEIPASS2=
set _MEIPASS=

echo ==========================================
echo       DPI GUI - ЗАПУСК ОБНОВЛЕНИЯ
echo ==========================================
echo.
echo [1/3] Ожидание закрытия программы...
timeout /t 3 /nobreak >nul

echo [2/3] Принудительная остановка процессов...
taskkill /F /IM "winws.exe" >nul 2>&1
taskkill /F /IM "ZapretDPIBypass" >nul 2>&1
taskkill /F /IM "dpi_gui_launcher.exe" >nul 2>&1
taskkill /F /IM "pythonw.exe" /FI "WINDOWTITLE eq DPI_GUI*" >nul 2>&1

echo [3/3] Запуск лаунчера в режиме обновления...
if exist "dpi_gui_launcher.exe" (
    "dpi_gui_launcher.exe" --update
) else (
    if exist "launcher.py" (
        if exist "python_runtime\python.exe" (
            "python_runtime\python.exe" "launcher.py" --update
        ) else (
            python "launcher.py" --update
        )
    ) else (
        echo.
        echo [ОШИБКА] Файл dpi_gui_launcher.exe не найден!
        echo Пожалуйста, переустановите программу.
        pause
    )
)
exit
