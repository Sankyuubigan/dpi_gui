import os
import sys
import subprocess
import requests
import zipfile
import shutil
import ctypes

# --- КОНФИГУРАЦИЯ ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GITHUB_REPO_OWNER = "Sankyuubigan"
GITHUB_REPO_NAME = "dpi_gui"
GITHUB_BRANCH = "main"

PYTHON_DIR = os.path.join(BASE_DIR, "python_runtime")
APP_DIR = os.path.join(BASE_DIR, "app_src")
VERSION_FILE = os.path.join(APP_DIR, ".version_hash")
# --------------------

def show_critical_error(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Критическая ошибка лаунчера", 0x10)

def print_status(message):
    if sys.stdout:
        print(f"[Launcher] >> {message}")

def get_latest_winpython_url():
    print_status("Поиск последней портативной версии WinPython на GitHub...")
    api_url = "https://api.github.com/repos/winpython/winpython/releases"
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        releases = response.json()
        for release in releases:
            if release.get('prerelease') or release.get('draft'):
                continue
            for asset in release.get('assets', []):
                if "Winpython64" in asset['name'] and asset['name'].endswith("dot.zip"):
                    print_status(f"Найдена подходящая версия: {release['tag_name']}")
                    print_status(f"Файл: {asset['name']}")
                    return asset['browser_download_url']
        return None
    except requests.exceptions.RequestException as e:
        show_critical_error(f"Не удалось получить список версий Python с GitHub.\n\nОшибка: {e}")
        return None

def download_file(url, dest_path):
    try:
        print_status(f"Скачиваю {url.split('/')[-1]}...")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        with open(dest_path, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk: continue
                f.write(chunk)
                downloaded += len(chunk)
                if sys.stdout:
                    if total_size > 0:
                        done = int(50 * downloaded / total_size)
                        sys.stdout.write(f"\r    -> [{'=' * done}{' ' * (50 - done)}] {downloaded / (1024 * 1024):.2f} / {total_size / (1024 * 1024):.2f} MB")
                    else:
                        sys.stdout.write(f"\r    -> Скачано: {downloaded / (1024 * 1024):.2f} MB")
                    sys.stdout.flush()
        if sys.stdout:
            sys.stdout.write('\n')
        return True
    except requests.exceptions.RequestException as e:
        show_critical_error(f"Не удалось скачать файл: {url}\n\nПроверьте подключение к интернету.\n\nОшибка: {e}")
        return False

def setup_python():
    python_exe_path = os.path.join(PYTHON_DIR, 'python.exe')
    if os.path.exists(python_exe_path):
        print_status("Портативный Python уже установлен.")
        return True

    python_url = get_latest_winpython_url()
    if not python_url:
        show_critical_error("Не удалось найти подходящую для скачивания версию WinPython на GitHub.")
        return False

    print_status(f"Портативный Python не найден. Скачиваю...")
    temp_zip_path = os.path.join(BASE_DIR, 'python.zip')
    if not download_file(python_url, temp_zip_path):
        return False

    print_status("Распаковываю Python...")
    temp_unpack_dir = os.path.join(BASE_DIR, "temp_python_unpack")
    if os.path.exists(temp_unpack_dir):
        shutil.rmtree(temp_unpack_dir)
    
    try:
        with zipfile.ZipFile(temp_zip_path, 'r') as zf:
            zf.extractall(temp_unpack_dir)
        os.remove(temp_zip_path)

        # --- ИСПРАВЛЕНО: Надежный поиск и перемещение папки 'python' ---
        unpacked_root_name = next(os.scandir(temp_unpack_dir)).name
        unpacked_root_path = os.path.join(temp_unpack_dir, unpacked_root_name)
        
        source_python_dir = os.path.join(unpacked_root_path, 'python')

        if not os.path.exists(source_python_dir):
            raise RuntimeError("Не удалось найти папку 'python' в распакованном архиве.")

        if os.path.exists(PYTHON_DIR):
            shutil.rmtree(PYTHON_DIR)
        
        shutil.move(source_python_dir, PYTHON_DIR)

    except Exception as e:
        show_critical_error(f"Не удалось распаковать или переместить архив с Python.\n\nОшибка: {e}")
        return False
    finally:
        if os.path.exists(temp_unpack_dir):
            shutil.rmtree(temp_unpack_dir)
        
    print_status("Портативный Python успешно установлен.")
    return True

def get_latest_commit_hash():
    api_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/{GITHUB_BRANCH}"
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        return response.json()['sha']
    except Exception: return None

def get_local_commit_hash():
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f: return f.read().strip()
    return None

def update_app_scripts(commit_hash):
    print_status("Обновляю скрипты приложения...")
    zip_url = f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/archive/{commit_hash}.zip"
    temp_zip_path = os.path.join(BASE_DIR, 'app_update.zip')
    if not download_file(zip_url, temp_zip_path): return False

    temp_extract_dir = os.path.join(BASE_DIR, "temp_extract")
    if os.path.exists(temp_extract_dir): shutil.rmtree(temp_extract_dir)
    
    print_status("Распаковываю скрипты во временную папку...")
    try:
        with zipfile.ZipFile(temp_zip_path, 'r') as zf: zf.extractall(temp_extract_dir)
        os.remove(temp_zip_path)
    except Exception as e:
        show_critical_error(f"Не удалось распаковать архив со скриптами.\n\nОшибка: {e}")
        return False

    source_dir = os.path.join(temp_extract_dir, f"{GITHUB_REPO_NAME}-{commit_hash}", "app_src")
    if not os.path.exists(source_dir) or not os.path.exists(os.path.join(source_dir, "main.py")):
        show_critical_error(f"Папка 'app_src' с файлом 'main.py' не найдена в скачанном архиве.")
        shutil.rmtree(temp_extract_dir)
        return False

    print_status("Проверка пройдена. Заменяю старые файлы...")
    if os.path.exists(APP_DIR): shutil.rmtree(APP_DIR)
    shutil.move(source_dir, APP_DIR)
    shutil.rmtree(temp_extract_dir)

    with open(VERSION_FILE, 'w') as f: f.write(commit_hash)
    print_status("Скрипты успешно обновлены.")
    return True

def main():
    is_windowed = sys.stdout is None or not sys.stdout.isatty()
    
    if is_windowed:
        log_dir = os.path.join(BASE_DIR, 'logs')
        if not os.path.exists(log_dir): os.makedirs(log_dir)
        sys.stdout = open(os.path.join(log_dir, 'launcher.log'), 'w', encoding='utf-8')
        sys.stderr = sys.stdout

    print_status("="*40)
    print_status(f"Запуск DPI-GUI Launcher из {BASE_DIR}")
    print_status("="*40)

    if not setup_python(): return

    python_exe = os.path.join(PYTHON_DIR, 'python.exe')
    requirements_path = os.path.join(APP_DIR, 'requirements.txt')
    if os.path.exists(requirements_path):
        pip_command = [python_exe, '-m', 'pip', 'install', '-r', requirements_path]
        print_status("Проверка и установка зависимостей (requests)...")
        subprocess.run(pip_command, check=True, capture_output=True, text=True)

    print_status("Проверка обновлений скриптов...")
    latest_hash = get_latest_commit_hash()
    local_hash = get_local_commit_hash()

    if not os.path.exists(APP_DIR):
        print_status("Папка с приложением не найдена, скачиваю последнюю версию...")
        if not update_app_scripts(latest_hash):
             show_critical_error("Не удалось скачать скрипты приложения в первый раз. Выход.")
             return
    elif latest_hash is None:
        print_status("Не удалось проверить обновления. Запускаю локальную версию.")
    elif local_hash != latest_hash:
        print_status(f"Найдена новая версия (коммит: {latest_hash[:7]}).")
        if not update_app_scripts(latest_hash):
            print_status("ОБНОВЛЕНИЕ НЕ УДАЛОСЬ. Запускаю старую версию.")
    else:
        print_status("У вас последняя версия скриптов.")

    main_script_path = os.path.join(APP_DIR, 'main.py')
    if not os.path.exists(main_script_path):
        show_critical_error(f"Основной скрипт 'main.py' не найден по пути:\n{main_script_path}")
        return
        
    command = [python_exe, main_script_path]
    
    print_status("Запускаю основное приложение...")
    print_status(f"Команда: {command}")
    print_status("-" * 40)
    
    try:
        subprocess.Popen(command, cwd=APP_DIR)
    except FileNotFoundError:
        show_critical_error(f"Не удалось запустить Python. Исполняемый файл не найден по пути:\n{python_exe}")
    except Exception as e:
        show_critical_error(f"Неизвестная ошибка при запуске приложения.\n\n{e}")
    
    if not is_windowed:
        print_status("Приложение запущено. Лаунчер завершает работу.")

if __name__ == "__main__":
    main()