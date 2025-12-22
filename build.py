import os
import subprocess
import sys
import argparse

# --- Конфигурация ---
LAUNCHER_SCRIPT = "launcher.py"
PROJECT_NAME = "dpi_gui_launcher"
ICON_FILE = "app_src/icon.ico"
# --------------------

def create_update_bat(dist_dir):
    """Создает файл update.bat в папке сборки."""
    bat_path = os.path.join(dist_dir, "update.bat")
    
    # Содержимое батника
    bat_content = f"""@echo off
chcp 65001 >nul
title DPI GUI Updater
setlocal

:: ОЧИСТКА ПЕРЕМЕННЫХ СРЕДЫ ОТ PYINSTALLER
set PYTHONHOME=
set PYTHONPATH=

echo ==========================================
echo       DPI GUI - ЗАПУСК ОБНОВЛЕНИЯ
echo ==========================================
echo.
echo [1/3] Ожидание закрытия программы...
timeout /t 3 /nobreak >nul

echo [2/3] Принудительная остановка процессов...
taskkill /F /IM "winws.exe" >nul 2>&1
taskkill /F /IM "ZapretDPIBypass" >nul 2>&1
taskkill /F /IM "{PROJECT_NAME}.exe" >nul 2>&1
taskkill /F /IM "pythonw.exe" /FI "WINDOWTITLE eq DPI_GUI*" >nul 2>&1

echo [3/3] Запуск лаунчера в режиме обновления...
if exist "{PROJECT_NAME}.exe" (
    start "" "{PROJECT_NAME}.exe" --update
) else (
    echo.
    echo [ОШИБКА] Файл {PROJECT_NAME}.exe не найден!
    pause
)
exit
"""
    try:
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(bat_content)
        print(f"-> [OK] Файл update.bat успешно создан в: {dist_dir}")
    except Exception as e:
        print(f"!!! ОШИБКА при создании update.bat: {e}")

def build(debug=False):
    """Собирает launcher.py в один .exe файл."""
    print("--- Начало сборки лаунчера ---")

    if not os.path.exists(LAUNCHER_SCRIPT):
        print(f"!!! ОШИБКА: Скрипт лаунчера '{LAUNCHER_SCRIPT}' не найден.")
        return

    # Определяем режим консоли
    console_mode = "--console" if debug else "--windowed"
    print(f"-> Режим сборки: {'DEBUG (с консолью)' if debug else 'RELEASE (без консоли)'}")

    command = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        console_mode,
        f"--name={PROJECT_NAME}"
    ]

    if os.path.exists(ICON_FILE):
        print(f"-> Использую иконку: {ICON_FILE}")
        command.append(f"--icon={ICON_FILE}")
    else:
        print("-> ВНИМАНИЕ: Файл иконки не найден. Сборка будет без иконки.")

    command.append(LAUNCHER_SCRIPT)

    print(f"-> Выполняю команду: {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
        print("\n--- Сборка exe завершена ---")
        
        # Создаем update.bat в папке dist
        dist_path = os.path.join(os.getcwd(), 'dist')
        if os.path.exists(dist_path):
            create_update_bat(dist_path)
            print(f"\nГотовый проект находится в папке: {dist_path}")
        else:
            print("!!! ОШИБКА: Папка dist не найдена после сборки.")
            
    except subprocess.CalledProcessError as e:
        print(f"!!! ОШИБКА СБОРКИ: {e}")
    except FileNotFoundError:
        print("!!! ОШИБКА: PyInstaller не найден. Установите его: pip install pyinstaller")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Скрипт сборки лаунчера.")
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Собрать лаунчер с видимой консолью для отладки.'
    )
    args = parser.parse_args()
    
    build(debug=args.debug)