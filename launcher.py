import os
import sys
import subprocess
import requests
import zipfile
import shutil
import ctypes
import datetime
import stat
import time

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
VERSION_DATE_FILE = os.path.join(APP_DIR, ".version_date")
# --------------------

def show_critical_error(message):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, "Критическая ошибка лаунчера", 0x10)
    except:
        print(f"CRITICAL ERROR: {message}")

def print_status(message):
    if sys.stdout:
        print(f"[Launcher] >> {message}")

def force_stop_processes():
    """Принудительно останавливает процессы winws.exe и службу перед обновлением"""
    print_status("Попытка остановки процессов...")
    try:
        # Остановка службы
        subprocess.run(['sc', 'stop', "ZapretDPIBypass"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        # Убийство процесса
        subprocess.run(['taskkill', '/F', '/IM', 'winws.exe'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(0.5) 
    except Exception:
        pass

def safe_copy_overwrite(src_dir, dst_dir):
    """
    Копирует файлы из src_dir в dst_dir с перезаписью.
    Если файл занят (PermissionError), он пропускается (актуально для драйверов).
    """
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
        
    for item in os.listdir(src_dir):
        s = os.path.join(src_dir, item)
        d = os.path.join(dst_dir, item)
        
        if os.path.isdir(s):
            safe_copy_overwrite(s, d)
        else:
            try:
                # Пытаемся снять атрибут "Только чтение" если файл существует
                if os.path.exists(d):
                    try:
                        os.chmod(d, stat.S_IWRITE)
                    except: pass
                
                shutil.copy2(s, d)
            except PermissionError:
                # САМОЕ ВАЖНОЕ: Если файл занят (драйвер или exe), мы его ПРОПУСКАЕМ,
                # но не крашимся. Скрипты (.py) обновятся, а бинарники останутся старыми (они редко меняются).
                if item.endswith('.sys') or item.endswith('.exe') or item.endswith('.dll'):
                    print_status(f"⚠ Файл занят, пропускаю обновление: {item}")
                else:
                    print_status(f"⚠ Ошибка доступа к файлу: {item}")
            except Exception as e:
                print_status(f"⚠ Ошибка при копировании {item}: {e}")

def get_latest_winpython_url():
    print_status("Поиск Python...")
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
                    return asset['browser_download_url']
        return None
    except:
        return None

def download_file(url, dest_path):
    try:
        print_status(f"Скачиваю компонент...")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk: continue
                f.write(chunk)
        return True
    except Exception as e:
        show_critical_error(f"Ошибка загрузки: {e}")
        return False

def setup_python():
    python_exe_path = os.path.join(PYTHON_DIR, 'python.exe')
    if os.path.exists(python_exe_path):
        return True

    python_url = get_latest_winpython_url()
    if not python_url:
        show_critical_error("Не удалось найти ссылку на Python.")
        return False

    temp_zip_path = os.path.join(BASE_DIR, 'python.zip')
    if not download_file(python_url, temp_zip_path):
        return False

    print_status("Распаковка Python...")
    temp_unpack_dir = os.path.join(BASE_DIR, "temp_python_unpack")
    
    try:
        if os.path.exists(temp_unpack_dir): shutil.rmtree(temp_unpack_dir, ignore_errors=True)
        with zipfile.ZipFile(temp_zip_path, 'r') as zf: zf.extractall(temp_unpack_dir)
        os.remove(temp_zip_path)

        unpacked_root_name = next(os.scandir(temp_unpack_dir)).name
        unpacked_root_path = os.path.join(temp_unpack_dir, unpacked_root_name)
        source_python_dir = os.path.join(unpacked_root_path, 'python')

        if os.path.exists(PYTHON_DIR): shutil.rmtree(PYTHON_DIR, ignore_errors=True)
        shutil.move(source_python_dir, PYTHON_DIR)
        shutil.rmtree(temp_unpack_dir, ignore_errors=True)
    except Exception as e:
        show_critical_error(f"Ошибка установки Python: {e}")
        return False
        
    return True

def get_latest_commit_info():
    api_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/{GITHUB_BRANCH}"
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['sha'], data['commit']['committer']['date']
    except: pass
    return None, None

def get_local_commit_hash():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return f.read().strip()
        except: pass
    return None

def update_app_scripts(commit_hash, commit_date):
    print_status("Загрузка обновления...")
    
    force_stop_processes()

    zip_url = f"https://github.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/archive/{commit_hash}.zip"
    temp_zip_path = os.path.join(BASE_DIR, 'app_update.zip')
    if not download_file(zip_url, temp_zip_path): return False

    temp_extract_dir = os.path.join(BASE_DIR, "temp_extract")
    
    try:
        if os.path.exists(temp_extract_dir): shutil.rmtree(temp_extract_dir, ignore_errors=True)
        with zipfile.ZipFile(temp_zip_path, 'r') as zf: zf.extractall(temp_extract_dir)
        os.remove(temp_zip_path)
    except Exception as e:
        show_critical_error(f"Ошибка распаковки: {e}")
        return False

    source_dir = os.path.join(temp_extract_dir, f"{GITHUB_REPO_NAME}-{commit_hash}", "app_src")
    if not os.path.exists(source_dir):
        show_critical_error("Неверная структура архива обновления.")
        return False

    print_status("Установка обновления (безопасный режим)...")
    
    # ВМЕСТО УДАЛЕНИЯ ПАПКИ - КОПИРУЕМ С ПЕРЕЗАПИСЬЮ И ПРОПУСКОМ ОШИБОК
    safe_copy_overwrite(source_dir, APP_DIR)

    try:
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        with open(VERSION_FILE, 'w') as f: f.write(commit_hash)
        if commit_date:
            with open(VERSION_DATE_FILE, 'w') as f: f.write(commit_date)
    except: pass
        
    print_status("Обновление завершено.")
    return True

def main():
    is_windowed = sys.stdout is None or not sys.stdout.isatty()
    
    if is_windowed:
        log_dir = os.path.join(BASE_DIR, 'logs')
        if not os.path.exists(log_dir): os.makedirs(log_dir)
        sys.stdout = open(os.path.join(log_dir, 'launcher.log'), 'w', encoding='utf-8')
        sys.stderr = sys.stdout

    if not setup_python(): return

    latest_hash, latest_date = get_latest_commit_info()
    local_hash = get_local_commit_hash()

    if not os.path.exists(APP_DIR):
        print_status("Первичная установка...")
        if latest_hash and not update_app_scripts(latest_hash, latest_date):
             show_critical_error("Не удалось установить приложение.")
             return
    elif latest_hash and local_hash != latest_hash:
        print_status(f"Обновление: {latest_hash[:7]}")
        update_app_scripts(latest_hash, latest_date)
    else:
        print_status("Версия актуальна.")
        # Создаем файл даты, если его нет
        if latest_date and not os.path.exists(VERSION_DATE_FILE):
             try:
                with open(VERSION_DATE_FILE, 'w') as f: f.write(latest_date)
             except: pass

    # Установка зависимостей
    pip_python_exe = os.path.join(PYTHON_DIR, 'python.exe')
    requirements_path = os.path.join(APP_DIR, 'requirements.txt')
    if os.path.exists(requirements_path):
        print_status("Проверка библиотек...")
        creation_flags = subprocess.CREATE_NO_WINDOW if is_windowed else 0
        subprocess.run([pip_python_exe, '-m', 'pip', 'install', '-r', requirements_path], 
                      capture_output=True, creationflags=creation_flags)

    main_script_path = os.path.join(APP_DIR, 'main.py')
    if not os.path.exists(main_script_path):
        show_critical_error(f"Файл main.py не найден!")
        return
        
    python_gui_exe = os.path.join(PYTHON_DIR, 'pythonw.exe')
    
    print_status("Запуск...")
    try:
        subprocess.Popen([python_gui_exe, main_script_path], cwd=APP_DIR)
    except Exception as e:
        show_critical_error(f"Ошибка запуска: {e}")

if __name__ == "__main__":
    main()