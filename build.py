import os
import subprocess
import sys
import argparse

# --- Конфигурация ---
LAUNCHER_SCRIPT = "launcher.py"
PROJECT_NAME = "dpi_gui_launcher"
ICON_FILE = "app_src/icon.ico"
# --------------------

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
        print("\n--- Сборка успешно завершена! ---")
        print(f"Готовый .exe файл находится в папке: {os.path.join(os.getcwd(), 'dist')}")
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