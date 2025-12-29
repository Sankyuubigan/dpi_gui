# -*- coding: utf-8 -*-

def get_update_bat_content(exe_name="dpi_gui_launcher.exe", launcher_script="launcher.py", python_runtime="python_runtime\\python.exe"):
    """
    Возвращает содержимое update.bat.
    Единый источник правды для генерации скрипта обновления.
    """
    return f"""@echo off
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
taskkill /F /IM "{exe_name}" >nul 2>&1
taskkill /F /IM "pythonw.exe" /FI "WINDOWTITLE eq DPI_GUI*" >nul 2>&1

echo [3/3] Запуск лаунчера в режиме обновления...
if exist "{exe_name}" (
    "{exe_name}" --update
) else (
    if exist "{launcher_script}" (
        if exist "{python_runtime}" (
            "{python_runtime}" "{launcher_script}" --update
        ) else (
            python "{launcher_script}" --update
        )
    ) else (
        echo.
        echo [ОШИБКА] Файл {exe_name} не найден!
        echo Пожалуйста, переустановите программу.
        pause
    )
)
exit
"""