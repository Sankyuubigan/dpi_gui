import os
import sys
import requests
import zipfile
import shutil
import subprocess

# --- КОНФИГУРАЦИЯ ---
GITHUB_REPO = 'YOUR_GITHUB_USERNAME/YOUR_REPO_NAME' 
BRANCH = 'main'
# ----------------------

TEMP_DIR = "_update_temp"
DOWNLOAD_URL = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/{BRANCH}.zip"

def cleanup():
    """Удаляет временную папку."""
    if os.path.isdir(TEMP_DIR):
        print("-> Удаляю временные файлы...")
        shutil.rmtree(TEMP_DIR)

def update():
    """Выполняет полный цикл обновления."""
    cleanup()
    
    # 1. Скачивание ZIP-архива
    print(f"-> Скачиваю последнюю версию из {GITHUB_REPO}...")
    try:
        response = requests.get(DOWNLOAD_URL, stream=True)
        response.raise_for_status()
        zip_path = os.path.join(TEMP_DIR, 'source.zip')
        os.makedirs(TEMP_DIR, exist_ok=True)
        with open(zip_path, 'wb') as f:
            shutil.copyfileobj(response.raw, f)
    except requests.RequestException as e:
        print(f"!!! ОШИБКА СКАЧИВАНИЯ: {e}")
        cleanup()
        return False

    # 2. Распаковка
    print("-> Распаковываю архив...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(TEMP_DIR)
        os.remove(zip_path)
        unpacked_folder_name = os.listdir(TEMP_DIR)[0]
        source_path = os.path.abspath(os.path.join(TEMP_DIR, unpacked_folder_name))
    except Exception as e:
        print(f"!!! ОШИБКА РАСПАКОВКИ: {e}")
        cleanup()
        return False

    # 3. Сборка нового проекта ИЗ СКАЧАННЫХ ИСХОДНИКОВ
    print("-> Запускаю сборку новой версии...")
    try:
        python_executable = sys.executable
        # Путь к build.py внутри скачанной папки
        build_script_path = os.path.join(source_path, 'build.py')
        
        # *** ИЗМЕНЕНО: Запускаем build.py и передаем ему путь к его же исходникам ***
        command = [
            python_executable,
            build_script_path,
            '--source-dir',
            source_path
        ]
        
        # Запускаем команду, но не устанавливаем cwd, чтобы пути остались глобальными
        subprocess.run(command, check=True)
        print("-> Сборка новой версии успешно завершена.")
    except Exception as e:
        print(f"!!! ОШИБКА СБОРКИ НОВОЙ ВЕРСИИ: {e}")
        cleanup()
        return False

    print("\n--- Обновление готово к установке. ---")
    print("Закройте это окно, и .bat файл завершит установку.")
    return True


if __name__ == "__main__":
    if GITHUB_REPO == 'YOUR_GITHUB_USERNAME/YOUR_REPO_NAME':
        print("="*60)
        print("!!! ВНИМАНИЕ: НЕ НАСТРОЕН РЕПОЗИТОРИЙ GITHUB !!!")
        print("Пожалуйста, откройте файл 'update.py' и укажите ваш репозиторий")
        print("в переменной GITHUB_REPO.")
        print("="*60)
        sys.exit(1)

    if not update():
        sys.exit(1)