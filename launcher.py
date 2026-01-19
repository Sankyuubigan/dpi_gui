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
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import traceback

# --- КОНФИГУРАЦИЯ ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    LAUNCHER_EXE = sys.executable
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LAUNCHER_EXE = os.path.abspath(__file__)

GITHUB_REPO_OWNER = "Sankyuubigan"
GITHUB_REPO_NAME = "dpi_gui"
GITHUB_BRANCH = "main"

PYTHON_DIR = os.path.join(BASE_DIR, "python_runtime")
APP_DIR = os.path.join(BASE_DIR, "app_src")
VERSION_FILE = os.path.join(APP_DIR, ".version_hash")
VERSION_DATE_FILE = os.path.join(APP_DIR, ".version_date")
LOG_FILE = os.path.join(BASE_DIR, "launcher.log")
APP_DEBUG_LOG = os.path.join(BASE_DIR, "app_debug.log")
# --------------------

def log_to_file(msg):
    """Пишет лог в файл и в консоль"""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {msg}"
        print(entry)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except:
        pass

try:
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("--- Start Launcher ---\n")
except: pass

class LauncherGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DPI GUI Launcher")
        self.root.geometry("450x200")
        self.root.resizable(False, False)
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (450 // 2)
        y = (screen_height // 2) - (200 // 2)
        self.root.geometry(f"450x200+{x}+{y}")

        style = ttk.Style()
        style.theme_use('clam')

        self.status_label = ttk.Label(self.root, text="Инициализация...", anchor="center")
        self.status_label.pack(pady=(20, 10), fill=tk.X, padx=10)

        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10, padx=20, fill=tk.X)

        self.detail_label = ttk.Label(self.root, text="", font=("Arial", 8), foreground="gray", anchor="center")
        self.detail_label.pack(pady=5)
        
        self.should_close = False

    def update_status(self, text):
        self.root.after(0, lambda: self.status_label.config(text=text))

    def update_detail(self, text):
        self.root.after(0, lambda: self.detail_label.config(text=text))

    def update_progress(self, value, maximum=100):
        self.root.after(0, lambda: self._set_progress(value, maximum))

    def _set_progress(self, value, maximum):
        self.progress["maximum"] = maximum
        self.progress["value"] = value

    def hide_window(self):
        """Скрывает окно (для фона)"""
        self.root.after(0, self.root.withdraw)

    def show_window(self):
        """Показывает окно обратно (если ошибка)"""
        self.root.after(0, self.root.deiconify)

    def show_error_and_wait(self, message):
        log_to_file(f"ERROR GUI: {message}")
        def _show():
            # Убеждаемся, что окно видно перед показом ошибки
            self.root.deiconify() 
            messagebox.showerror("Критическая ошибка", message)
            self.root.destroy()
        self.root.after(0, _show)

    def close_success(self):
        log_to_file("Closing launcher (Success)")
        self.root.after(0, self.root.destroy)

    def start(self):
        self.root.mainloop()

gui = None

def print_status(message):
    log_to_file(message)
    if gui:
        gui.update_status(message)

def force_stop_processes():
    print_status("Остановка старых процессов...")
    try:
        subprocess.run(['sc', 'stop', "ZapretDPIBypass"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(['taskkill', '/F', '/IM', 'winws.exe'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(0.5) 
    except Exception as e:
        log_to_file(f"Error stopping processes: {e}")

def safe_copy_overwrite(src_dir, dst_dir):
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
        
    for item in os.listdir(src_dir):
        s = os.path.join(src_dir, item)
        d = os.path.join(dst_dir, item)
        
        if os.path.isdir(s):
            safe_copy_overwrite(s, d)
        else:
            try:
                if os.path.exists(d):
                    try:
                        os.chmod(d, stat.S_IWRITE)
                    except: pass
                shutil.copy2(s, d)
            except PermissionError:
                log_to_file(f"Permission error copying {item}")
            except Exception as e:
                log_to_file(f"Error copying {item}: {e}")

def get_latest_winpython_url():
    print_status("Поиск Python на GitHub...")
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
    except Exception as e:
        log_to_file(f"Error finding python: {e}")
        return None

def download_file(url, dest_path):
    try:
        filename = url.split('/')[-1]
        print_status(f"Скачивание {filename}...")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        
        with open(dest_path, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk: continue
                f.write(chunk)
                downloaded += len(chunk)
                if gui and total_size > 0:
                    gui.update_progress(downloaded, total_size)
                    mb_downloaded = downloaded / (1024 * 1024)
                    mb_total = total_size / (1024 * 1024)
                    gui.update_detail(f"{mb_downloaded:.1f} / {mb_total:.1f} MB")
        return True
    except Exception as e:
        log_to_file(f"Download error: {e}")
        if gui: gui.show_error_and_wait(f"Ошибка загрузки: {e}")
        return False

def setup_python():
    python_exe_path = os.path.join(PYTHON_DIR, 'python.exe')
    if os.path.exists(python_exe_path):
        log_to_file("Python found.")
        return True

    print_status("Python не найден. Установка...")
    python_url = get_latest_winpython_url()
    if not python_url:
        if gui: gui.show_error_and_wait("Не удалось найти ссылку на Python.")
        return False

    temp_zip_path = os.path.join(BASE_DIR, 'python.zip')
    if not download_file(python_url, temp_zip_path):
        return False

    print_status("Распаковка Python...")
    if gui: gui.update_progress(0, 0)
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
        log_to_file("Python installed successfully.")
    except Exception as e:
        log_to_file(f"Python install error: {e}")
        if gui: gui.show_error_and_wait(f"Ошибка установки Python: {e}")
        return False
        
    return True

def get_latest_commit_info():
    api_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/{GITHUB_BRANCH}"
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['sha'], data['commit']['committer']['date']
    except Exception as e:
        log_to_file(f"GitHub API error: {e}")
    return None, None

def get_local_commit_hash():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return f.read().strip()
        except: pass
    return None

def update_app_scripts(commit_hash, commit_date):
    print_status("Загрузка обновления скриптов...")
    
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
        log_to_file(f"Unzip error: {e}")
        if gui: gui.show_error_and_wait(f"Ошибка распаковки: {e}")
        return False

    source_dir = os.path.join(temp_extract_dir, f"{GITHUB_REPO_NAME}-{commit_hash}", "app_src")
    if not os.path.exists(source_dir):
        log_to_file("Invalid archive structure")
        if gui: gui.show_error_and_wait("Неверная структура архива.")
        return False

    print_status("Применение обновления...")
    if gui: gui.update_progress(0, 0)
    
    safe_copy_overwrite(source_dir, APP_DIR)

    try:
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        with open(VERSION_FILE, 'w') as f: f.write(commit_hash)
        if commit_date:
            with open(VERSION_DATE_FILE, 'w') as f: f.write(commit_date)
    except: pass
        
    return True

def work_thread():
    try:
        force_update = "--update" in sys.argv
        log_to_file(f"Work thread started. Force update: {force_update}")

        if not setup_python(): 
            log_to_file("Failed to setup Python. Aborting.")
            return

        should_update = False
        if not os.path.exists(APP_DIR):
            print_status("Приложение не найдено. Установка...")
            should_update = True
        elif force_update:
            print_status("Принудительное обновление...")
            should_update = True
        else:
            print_status("Запуск приложения...")

        if should_update:
            latest_hash, latest_date = get_latest_commit_info()
            if latest_hash:
                if not update_app_scripts(latest_hash, latest_date):
                    log_to_file("Update failed.")
                    return 
            else:
                log_to_file("Could not get latest commit info.")
                if not os.path.exists(APP_DIR):
                     if gui: gui.show_error_and_wait("Не удалось получить информацию о версии для загрузки.")
                     return

        pip_python_exe = os.path.join(PYTHON_DIR, 'python.exe')
        requirements_path = os.path.join(APP_DIR, 'requirements.txt')
        
        if os.path.exists(requirements_path):
            print_status("Проверка библиотек...")
            gui.update_progress(0, 0)
            try:
                subprocess.run([pip_python_exe, '-m', 'pip', 'install', '-r', requirements_path], 
                              capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
            except subprocess.CalledProcessError as e:
                log_to_file(f"Pip install failed: {e}")

        main_script_path = os.path.join(APP_DIR, 'main.py')
        if not os.path.exists(main_script_path):
            log_to_file(f"main.py not found at {main_script_path}")
            if gui: gui.show_error_and_wait(f"Файл main.py не найден!\n{main_script_path}")
            return
            
        python_gui_exe = os.path.join(PYTHON_DIR, 'pythonw.exe')
        if not os.path.exists(python_gui_exe):
            log_to_file(f"pythonw.exe not found at {python_gui_exe}")
            if gui: gui.show_error_and_wait("Интерпретатор pythonw.exe не найден!")
            return
        
        print_status("Запуск...")
        gui.update_progress(100, 100)
        time.sleep(0.5)
        
        try:
            env = os.environ.copy()
            env["LAUNCHER_PATH"] = LAUNCHER_EXE
            
            if "TCL_LIBRARY" in env:
                del env["TCL_LIBRARY"]
            if "TK_LIBRARY" in env:
                del env["TK_LIBRARY"]
            
            debug_file = open(APP_DEBUG_LOG, "w", encoding="utf-8")
            
            log_to_file(f"Executing: {python_gui_exe} {main_script_path}")
            
            # --- ЗАПУСК ---
            proc = subprocess.Popen(
                [python_gui_exe, main_script_path], 
                cwd=APP_DIR, 
                env=env,
                stdout=debug_file,
                stderr=debug_file
            )
            
            # --- СКРЫВАЕМ ОКНО ЛАУНЧЕРА СРАЗУ ---
            if gui: gui.hide_window()

            # Ждем 2 секунды в фоне
            time.sleep(2)
            
            if proc.poll() is not None:
                # --- ЕСЛИ УПАЛО: ПОКАЗЫВАЕМ ОКНО ОБРАТНО ---
                log_to_file(f"Process exited prematurely with code {proc.returncode}")
                debug_file.close()
                
                error_msg = "Процесс завершился сразу после запуска."
                if os.path.exists(APP_DEBUG_LOG):
                    try:
                        with open(APP_DEBUG_LOG, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().strip()
                            if content:
                                # Читаем последние 1500 символов, чтобы влез Traceback
                                error_msg = f"Ошибка запуска:\n...\n{content[-1500:]}" if len(content) > 1500 else f"Ошибка запуска:\n{content}"
                    except Exception as e:
                        error_msg += f"\n(Не удалось прочитать лог: {e})"
                
                if gui: gui.show_error_and_wait(error_msg)
            else:
                # --- ВСЕ ОК: ЗАКРЫВАЕМСЯ ---
                log_to_file("Process started successfully.")
                debug_file.close()
                if gui: gui.close_success()
            
        except Exception as e:
            log_to_file(f"Launch exception: {e}")
            if gui: gui.show_error_and_wait(f"Ошибка запуска процесса: {e}")
            
    except Exception as e:
        log_to_file(f"Critical thread exception: {traceback.format_exc()}")
        if gui: gui.show_error_and_wait(f"Критическая ошибка лаунчера:\n{e}")

def main():
    global gui
    gui = LauncherGUI()
    
    thread = threading.Thread(target=work_thread, daemon=True)
    thread.start()
    
    try:
        gui.start()
    except Exception as e:
        log_to_file(f"GUI Loop exception: {e}")
        messagebox.showerror("Fatal Error", str(e))

if __name__ == "__main__":
    main()