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

# Версия портативного Python для скачивания
PYTHON_VERSION = "3.10.11"
PYTHON_URL = f"https://www.python.org/ftp/python/{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip"

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
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        
        print_status(f"Скачиваю {url.split('/')[-1]}...")
        with open(dest_path, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                
                f.write(chunk)
                downloaded += len(chunk)
                
                # Если размер известен, показываем прогресс-бар
                if total_size > 0:
                    done = int(50 * downloaded / total_size)
                    sys.stdout.write(f"\r    -> [{'=' * done}{' ' * (50 - done)}] {downloaded / (1024 * 1024):.2f} / {total_size / (1024 * 1024):.2f} MB")
                # Если размер неизвестен, показываем только скачанный объем
                else:
                    sys.stdout.write(f"\r    -> Скачано: {downloaded / (1024 * 1024):.2f} MB")
                
                sys.stdout.flush()

        sys.stdout.write('\n')
        return True
    except requests.exceptions.RequestException as e:
        print_status(f"ОШИБКА: Не удалось скачать файл. Проверьте интернет. {e}")
        return False

def setup_python():
    """Проверяет и при необходимости скачивает портативный Python."""
    python_exe_path = os.path.join(PYTHON_DIR, 'python.exe')
    if os.path.exists(python_exe_path):
        print_status("Портативный Python уже установлен.")
        return True

    print_status(f"Портативный Python не найден. Скачиваю версию {PYTHON_VERSION}...")
    if not os.path.exists(PYTHON_DIR):
        os.makedirs(PYTHON_DIR)
    
    zip_path = os.path.join(PYTHON_DIR, 'python.zip')
    
    if not download_file(PYTHON_URL, zip_path):
        return False

    print_status("Распаковываю Python...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(PYTHON_DIR)
    
    os.remove(zip_path)
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
    """Скачивает и обновляет скрипты приложения."""
    print_status("Обновляю скрипты приложения...")
    
    zip_url = f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/archive/{commit_hash}.zip"
    temp_zip_path = 'app_update.zip'

    if not download_file(zip_url, temp_zip_path):
        return

    # Временная папка для безопасной распаковки
    temp_extract_dir = "temp_extract"
    if os.path.exists(temp_extract_dir):
        shutil.rmtree(temp_extract_dir)
    os.makedirs(temp_extract_dir)

    print_status("Распаковываю скрипты во временную папку...")
    with zipfile.ZipFile(temp_zip_path, 'r') as zf:
        zf.extractall(temp_extract_dir)

    os.remove(temp_zip_path)
    
    # GitHub упаковывает все в папку типа 'repo-name-hash'
    # Нам нужно найти эту папку
    source_dir = os.path.join(temp_extract_dir, f"{GITHUB_REPO_NAME}-{commit_hash}", "app_src")
    
    if not os.path.exists(source_dir):
        print_status(f"ОШИБКА: Не найдена папка 'app_src' в скачанном архиве.")
        shutil.rmtree(temp_extract_dir)
        return

    # Удаляем старую папку и перемещаем новую на ее место
    if os.path.exists(APP_DIR):
        shutil.rmtree(APP_DIR)
    
    shutil.move(source_dir, APP_DIR)
    
    # Очищаем временную папку
    shutil.rmtree(temp_extract_dir)

    # Сохраняем хэш новой версии
    with open(VERSION_FILE, 'w') as f:
        f.write(commit_hash)
        
    print_status("Скрипты успешно обновлены.")

def main():
    """Основная функция лаунчера."""
    print_status("="*40)
    print_status("Запуск DPI-GUI Launcher")
    print_status("="*40)

    # 1. Настройка Python
    if not setup_python():
        print_status("Критическая ошибка: не удалось установить Python. Выход.")
        input("Нажмите Enter для выхода...")
        return

    # 2. Проверка и обновление скриптов
    print_status("Проверка обновлений скриптов...")
    latest_hash = get_latest_commit_hash()
    local_hash = get_local_commit_hash()

    if latest_hash is None:
        print_status("Не удалось проверить обновления. Запускаю локальную версию, если она есть.")
    elif local_hash != latest_hash:
        print_status(f"Найдена новая версия (коммит: {latest_hash[:7]}).")
        update_app_scripts(latest_hash)
    else:
        print_status("У вас последняя версия скриптов.")

    # 3. Запуск основного приложения
    main_script_path = os.path.join(APP_DIR, 'gui.py')
    if not os.path.exists(main_script_path):
        print_status(f"ОШИБКА: Основной скрипт не найден по пути {main_script_path}")
        print_status("Попробуйте удалить папки 'app_src' и 'python_runtime' и перезапустить лаунчер.")
        input("Нажмите Enter для выхода...")
        return
        
    python_exe = os.path.join(PYTHON_DIR, 'python.exe')
    command = [python_exe, main_script_path]
    
    print_status("Запускаю основное приложение...")
    print_status("-" * 40)
    
    # Запускаем GUI и ждем его завершения
    subprocess.run(command)
    
    print_status("="*40)
    print_status("Приложение завершило работу. Лаунчер закрывается.")

if __name__ == "__main__":
    main()