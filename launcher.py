import os
import sys
import subprocess
import requests
import zipfile
import shutil
import hashlib

# --- КОНФИГУРАЦИЯ ---
# Владелец и имя репозитория на GitHub, откуда будут скачиваться скрипты
GITHUB_REPO_OWNER = "Sankyuubigan"
GITHUB_REPO_NAME = "dpi_gui"
# Ветка, за которой следим
GITHUB_BRANCH = "main"

# Используем WinPython, который включает Tkinter
PYTHON_VERSION = "3.10.11.0"
PYTHON_URL = f"https://github.com/winpython/winpython/releases/download/{PYTHON_VERSION}/Winpython64-{PYTHON_VERSION}dot.zip"

# Названия папок
PYTHON_DIR = "python_runtime"
APP_DIR = "app_src"
VERSION_FILE = os.path.join(APP_DIR, ".version_hash")
# --------------------

def print_status(message):
    """Выводит статусное сообщение."""
    print(f"[Launcher] >> {message}")

def download_file(url, dest_path):
    """Скачивает файл с отображением прогресса."""
    try:
        print_status(f"Скачиваю {url.split('/')[-1]}...")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        
        with open(dest_path, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                
                f.write(chunk)
                downloaded += len(chunk)
                
                if total_size > 0:
                    done = int(50 * downloaded / total_size)
                    sys.stdout.write(f"\r    -> [{'=' * done}{' ' * (50 - done)}] {downloaded / (1024 * 1024):.2f} / {total_size / (1024 * 1024):.2f} MB")
                else:
                    sys.stdout.write(f"\r    -> Скачано: {downloaded / (1024 * 1024):.2f} MB")
                
                sys.stdout.flush()

        sys.stdout.write('\n')
        return True
    except requests.exceptions.RequestException as e:
        print_status(f"ОШИБКА: Не удалось скачать файл. Проверьте интернет. {e}")
        return False

def setup_python():
    """Проверяет и при необходимости скачивает портативный WinPython."""
    python_exe_path = os.path.join(PYTHON_DIR, 'python.exe')
    if os.path.exists(python_exe_path):
        print_status("Портативный Python уже установлен.")
        return True

    print_status(f"Портативный Python не найден. Скачиваю WinPython {PYTHON_VERSION}...")
    temp_zip_path = 'python.zip'
    
    if not download_file(PYTHON_URL, temp_zip_path):
        return False

    print_status("Распаковываю Python...")
    with zipfile.ZipFile(temp_zip_path, 'r') as zf:
        # Находим имя корневой папки в архиве, например 'WPy64-310110'
        top_level_folder = next((info.filename for info in zf.infolist() if info.is_dir()), None)
        for member in zf.infolist():
            # Извлекаем файлы, убирая из пути корневую папку архива
            if top_level_folder and member.filename.startswith(top_level_folder):
                 target_path = os.path.join(PYTHON_DIR, os.path.relpath(member.filename, top_level_folder))
            else:
                 target_path = os.path.join(PYTHON_DIR, member.filename)

            if not target_path or target_path.endswith(os.path.sep):
                continue
            
            if not os.path.exists(os.path.dirname(target_path)):
                os.makedirs(os.path.dirname(target_path))
            
            if not member.is_dir():
                with open(target_path, 'wb') as f:
                    f.write(zf.read(member.filename))

    os.remove(temp_zip_path)
    print_status("Портативный Python успешно установлен.")
    return True

def get_latest_commit_hash():
    """Получает хэш последнего коммита из GitHub."""
    api_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/{GITHUB_BRANCH}"
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        return response.json()['sha']
    except Exception:
        return None

def get_local_commit_hash():
    """Получает хэш локальной версии из файла."""
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f:
            return f.read().strip()
    return None

def update_app_scripts(commit_hash):
    """Скачивает и обновляет скрипты приложения. Возвращает True/False."""
    print_status("Обновляю скрипты приложения...")
    
    zip_url = f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/archive/{commit_hash}.zip"
    temp_zip_path = 'app_update.zip'

    if not download_file(zip_url, temp_zip_path):
        return False

    temp_extract_dir = "temp_extract"
    if os.path.exists(temp_extract_dir):
        shutil.rmtree(temp_extract_dir)
    
    print_status("Распаковываю скрипты во временную папку...")
    try:
        with zipfile.ZipFile(temp_zip_path, 'r') as zf:
            zf.extractall(temp_extract_dir)
        os.remove(temp_zip_path)
    except Exception as e:
        print_status(f"ОШИБКА: Не удалось распаковать архив. {e}")
        return False

    source_dir = os.path.join(temp_extract_dir, f"{GITHUB_REPO_NAME}-{commit_hash}", "app_src")
    
    if not os.path.exists(source_dir) or not os.path.exists(os.path.join(source_dir, "main.py")):
        print_status(f"ОШИБКА: Папка 'app_src' с файлом 'main.py' не найдена в скачанном архиве.")
        shutil.rmtree(temp_extract_dir)
        return False

    print_status("Проверка пройдена. Заменяю старые файлы...")
    if os.path.exists(APP_DIR):
        shutil.rmtree(APP_DIR)
    
    shutil.move(source_dir, APP_DIR)
    shutil.rmtree(temp_extract_dir)

    with open(VERSION_FILE, 'w') as f:
        f.write(commit_hash)
        
    print_status("Скрипты успешно обновлены.")
    return True

def main():
    """Основная функция лаунчера."""
    print_status("="*40)
    print_status("Запуск DPI-GUI Launcher")
    print_status("="*40)

    if not setup_python():
        print_status("Критическая ошибка: не удалось установить Python. Выход.")
        input("Нажмите Enter для выхода...")
        return

    print_status("Проверка обновлений скриптов...")
    latest_hash = get_latest_commit_hash()
    local_hash = get_local_commit_hash()

    if latest_hash is None:
        print_status("Не удалось проверить обновления. Запускаю локальную версию, если она есть.")
    elif local_hash != latest_hash:
        print_status(f"Найдена новая версия (коммит: {latest_hash[:7]}).")
        if not update_app_scripts(latest_hash):
            print_status("ОБНОВЛЕНИЕ НЕ УДАЛОСЬ. Запускаю старую версию, если возможно.")
    else:
        print_status("У вас последняя версия скриптов.")

    # --- ИЗМЕНЕНО: Запускаем main.py вместо gui.py ---
    main_script_path = os.path.join(APP_DIR, 'main.py')
    if not os.path.exists(main_script_path):
        print_status(f"ОШИБКА: Основной скрипт 'main.py' не найден по пути {main_script_path}")
        print_status("Попробуйте удалить папки 'app_src' и 'python_runtime' и перезапустить лаунчер.")
        input("Нажмите Enter для выхода...")
        return
        
    python_exe = os.path.join(PYTHON_DIR, 'python.exe')
    command = [python_exe, main_script_path]
    
    print_status("Запускаю основное приложение...")
    print_status("-" * 40)
    
    subprocess.run(command)
    
    print_status("="*40)
    print_status("Приложение завершило работу. Лаунчер закрывается.")

if __name__ == "__main__":
    main()