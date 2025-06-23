import os
import sys
import subprocess
import datetime
import shutil

# --- Конфигурация проекта ---
PROJECT_NAME = "dpi_gui"
SPEC_FILE = f"{PROJECT_NAME}.spec"
DIST_DIR = "dist"
VERSION_FILE = "_version.py"
# -----------------------------

def get_git_commit_date():
    """Получает дату последнего коммита в формате YY.MM.DD."""
    try:
        command = ['git', 'log', '-1', '--format=%cd', '--date=format:%y.%m.%d']
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        version = result.stdout.strip()
        if version:
            print(f"Найдена версия из Git: {version}")
            return version
    except Exception:
        print("Не удалось получить версию из Git. Использую текущую дату.")
        return datetime.date.today().strftime('%y.%m.%d')

def build_project():
    """Собирает проект с помощью PyInstaller, внедряя версию."""
    version_string = get_git_commit_date()
    try:
        with open(VERSION_FILE, 'w', encoding='utf-8') as f:
            f.write(f'__version__ = "{version_string}"\n')
        print(f"Файл версии '{VERSION_FILE}' успешно создан.")
    except IOError as e:
        print(f"!!! ОШИБКА: Не удалось записать файл версии: {e}")
        return False

    if not os.path.exists(SPEC_FILE):
        print(f"!!! ОШИБКА: Файл '{SPEC_FILE}' не найден.")
        if os.path.exists(VERSION_FILE): os.remove(VERSION_FILE)
        return False

    print(f"--- Начало сборки проекта '{PROJECT_NAME}' v{version_string} ---")
    
    try:
        python_executable = sys.executable
        print("Шаг 1/1: Запуск PyInstaller...")
        command = [
            python_executable, "-m", "PyInstaller",
            "--noconfirm", "--clean", SPEC_FILE
        ]
        subprocess.run(command, check=True)
        print("PyInstaller успешно завершил работу.")
        
        # *** ИЗМЕНЕНО: Больше не переименовываем папку ***
        # PyInstaller создаст папку dist/dpi_gui
        build_dir = os.path.abspath(os.path.join(DIST_DIR, PROJECT_NAME))
        print("\n--- Сборка успешно завершена! ---")
        print(f"Готовая программа находится в папке: {build_dir}")
        
    except Exception as e:
        print(f"!!! ОШИБКА НА ЭТАПЕ СБОРКИ: {e}")
        return False
    finally:
        if os.path.exists(VERSION_FILE):
            os.remove(VERSION_FILE)
            print(f"Временный файл '{VERSION_FILE}' удален.")
            
    return True

if __name__ == "__main__":
    build_project()