import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import os
import sys
import threading
import queue
import subprocess
import glob
import requests
import zipfile
import shutil
import time
from executor import (
    find_bat_files, run_bat_file, kill_existing_processes, 
    analyze_site_domains, update_zapret_tool
)
from text_utils import setup_text_widget_bindings
from version_checker import check_zapret_version

try:
    from _version import __version__
except ImportError:
    __version__ = "dev"

def get_base_path():
    """
    Возвращает правильный базовый путь для внутренних ресурсов.
    Для скомпилированного .exe это будет папка _internal (_MEIPASS).
    Для исходников - текущая директория.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return sys._MEIPASS
    else:
        return os.path.abspath(".")

class UpdateDialog(tk.Toplevel):
    # ... (содержимое этого класса без изменений)
    def __init__(self, parent, repo_url):
        super().__init__(parent)
        self.repo_url = repo_url
        self.title("Обновление Лаунчера")
        self.geometry("500x150")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        self.status_label = tk.Label(self, text="Подготовка к обновлению...")
        self.status_label.pack(pady=(10, 5))
        self.progress = ttk.Progressbar(self, mode='determinate', length=480)
        self.progress.pack(pady=10)
        self.worker_thread = threading.Thread(target=self._update_worker, daemon=True)
        self.worker_thread.start()

    def log(self, message, value=None):
        self.status_label.config(text=message)
        if value is not None:
            self.progress['value'] = value
        self.update_idletasks()

    def _update_worker(self):
        try:
            self.log("Поиск последнего релиза на GitHub...", 10)
            api_url = f"https://api.github.com/repos/{self.repo_url}/releases/latest"
            response = requests.get(api_url)
            response.raise_for_status()
            release_data = response.json()
            assets = release_data.get('assets', [])
            zip_url = None
            for asset in assets:
                if asset.get('name', '').endswith('.zip'):
                    zip_url = asset['browser_download_url']
                    break
            if not zip_url:
                messagebox.showerror("Ошибка обновления", "В последнем релизе не найден ZIP-архив.")
                self.destroy()
                return
            self.log(f"Скачивание версии {release_data['tag_name']}...", 30)
            # Для обновления, временная папка создается рядом с EXE
            update_temp_dir = os.path.join(os.path.dirname(sys.executable), "_update_temp")
            if os.path.exists(update_temp_dir): shutil.rmtree(update_temp_dir)
            os.makedirs(update_temp_dir)
            zip_path = os.path.join(update_temp_dir, 'update.zip')
            with requests.get(zip_url, stream=True) as r:
                r.raise_for_status()
                with open(zip_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
            self.log("Распаковка архива...", 80)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(update_temp_dir)
            os.remove(zip_path)
            self.log("Запуск установщика...", 100)
            time.sleep(1)
            # Батник должен лежать рядом с EXE
            updater_bat_path = os.path.join(os.path.dirname(sys.executable), '_run_updater.bat')
            subprocess.Popen([updater_bat_path], creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=os.path.dirname(sys.executable))
            self.master.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка обновления", f"Произошла ошибка:\n{e}")
            self.destroy()

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Zapret Launcher v{__version__}")
        self.root.geometry("850x500")
        self.process = None
        self.log_queue = queue.Queue()

        # Путь для внешних файлов (конфиги, папки zapret), находящихся рядом с .exe
        self.app_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.abspath(".")
        # Путь для внутренних ресурсов, упакованных с программой (например, иконка)
        self.resources_path = get_base_path()

        self.set_app_icon()
        self.create_widgets()
        self.populate_bat_files()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # В фоновом режиме проверяем последнюю версию Zapret
        threading.Thread(target=check_zapret_version, args=(self.log_message,), daemon=True).start()

    def set_app_icon(self):
        """Устанавливает иконку для главного окна, если файл icon.ico существует."""
        try:
            # Иконка должна быть добавлена как data-файл в .spec или лежать рядом
            # и будет доступна в _MEIPASS или в корневой папке
            icon_path = os.path.join(self.resources_path, 'icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            # Игнорируем ошибки, если иконку не удалось установить (например, в Linux)
            pass

    def create_widgets(self):
        # ... (код виджетов без изменений)
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill=tk.X)
        self.run_button = tk.Button(top_frame, text="Запустить профиль", command=self.select_and_run_bat)
        self.run_button.pack(side=tk.LEFT)
        self.stop_button = tk.Button(top_frame, text="Остановить/Проверить", command=self.stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.add_site_button = tk.Button(top_frame, text="Анализ сайта", command=self.open_add_site_dialog)
        self.add_site_button.pack(side=tk.LEFT, padx=5)
        self.update_launcher_button = tk.Button(top_frame, text="Обновить Лаунчер", command=self.run_self_update)
        self.update_launcher_button.pack(side=tk.RIGHT, padx=(10, 0))
        self.update_zapret_button = tk.Button(top_frame, text="Обновить Zapret", command=self.open_zapret_update_dialog)
        self.update_zapret_button.pack(side=tk.RIGHT)
        list_frame = tk.Frame(self.root)
        list_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        tk.Label(list_frame, text="Выберите профиль для запуска:").pack(anchor=tk.W)
        self.bat_listbox = tk.Listbox(list_frame)
        self.bat_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.bat_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.bat_listbox.config(yscrollcommand=scrollbar.set)
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        tk.Label(log_frame, text="Логи:").pack(anchor=tk.W)
        self.log_window = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)
        setup_text_widget_bindings(self.bat_listbox)
    
    def run_self_update(self):
        if messagebox.askyesno("Подтверждение", "Программа скачает последнюю версию с GitHub и закроется для обновления.\n\nПродолжить?"):
            UpdateDialog(self.root, 'Sankyuubigan/dpi_gui')

    def open_add_site_dialog(self):
        AddSiteDialog(self.root, self.add_domains_to_list)

    def open_zapret_update_dialog(self):
        if messagebox.askyesno("Подтверждение", "Это скачает последнюю версию утилиты Zapret от разработчика Flowseal.\n\nВсе активные процессы будут остановлены. Продолжить?"):
            update_thread = threading.Thread(target=self._zapret_update_worker, daemon=True)
            update_thread.start()

    def _zapret_update_worker(self):
        update_zapret_tool(self.app_dir, self.log_message)
        self.root.after(0, self.refresh_bat_list)

    def refresh_bat_list(self):
        self.log_message("-> Обновляю список профилей...")
        self.populate_bat_files()

    def add_domains_to_list(self, new_domains):
        custom_list_path = os.path.join(self.app_dir, 'custom_list.txt')
        try:
            existing_domains = set()
            if os.path.exists(custom_list_path):
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_domains.add(line)
            added_domains = [d for d in new_domains if d not in existing_domains]
            if not added_domains:
                self.log_message("\n--- Анализ сайта завершен. Новых доменов для добавления не найдено. ---")
                return
            all_domains = sorted(list(existing_domains.union(set(new_domains))))
            with open(custom_list_path, 'w', encoding='utf-8') as f:
                f.write("# Список доменов, сгенерированный программой.\n")
                for domain in all_domains:
                    f.write(domain + '\n')
            self.log_message("\n--- Добавлены новые домены в custom_list.txt: ---")
            for domain in sorted(added_domains):
                self.log_message(f"  + {domain}")
            self.log_message("--------------------------------------------------")
        except Exception as e:
            messagebox.showerror("Ошибка файла", f"Не удалось записать в {custom_list_path}:\n{e}")

    def populate_bat_files(self):
        self.bat_listbox.delete(0, tk.END)
        # Ищем все папки с утилитой в каталоге программы
        zapret_folders = glob.glob(os.path.join(self.app_dir, 'zapret-discord-youtube-*'))
        
        if not zapret_folders:
            messagebox.showerror("Ошибка", f"Папки 'zapret-discord-youtube-*' не найдены в каталоге программы:\n{self.app_dir}")
            self.bat_files = []
            return

        all_bat_files = []
        # Проходим по каждой найденной папке и собираем bat-файлы
        for folder in zapret_folders:
            all_bat_files.extend(find_bat_files(folder))
        
        # Сортируем, чтобы порядок был предсказуемым и одинаковым при каждом запуске
        self.bat_files = sorted(all_bat_files)

        if not self.bat_files:
            self.log_message("ПРЕДУПРЕЖДЕНИЕ: Не найдено ни одного .bat файла в папках 'zapret-discord-youtube-*'.")
            return

        for abs_path in self.bat_files:
            try:
                # Показываем путь относительно папки программы для наглядности
                display_path = os.path.relpath(abs_path, self.app_dir).replace('\\', '/')
            except (ValueError, AttributeError):
                # Фоллбэк, если что-то пошло не так
                display_path = os.path.join(os.path.basename(os.path.dirname(abs_path)), os.path.basename(abs_path))
            self.bat_listbox.insert(tk.END, display_path)

    def select_and_run_bat(self):
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Информация", "Процесс уже запущен.")
            return
        selected_indices = self.bat_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите профиль из списка.")
            return
        selected_index = selected_indices
        file_path = self.bat_files[selected_index]
        self.run_process(file_path)

    def run_process(self, file_path):
        self.log_window.config(state='normal')
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state='disabled')
        kill_existing_processes(self.log_message)
        self.log_message(f"Запуск профиля: {os.path.basename(file_path)}")
        self.process = run_bat_file(file_path, self.app_dir, self.log_message)
        if not self.process:
            self.log_message("Не удалось запустить процесс.")
            return
        self.run_button.config(state=tk.DISABLED)
        self.bat_listbox.config(state=tk.DISABLED)
        self.worker_thread = threading.Thread(target=self.read_process_output, args=(self.process, self.log_queue))
        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.monitor_process()

    def read_process_output(self, process, q):
        for line in iter(process.stdout.readline, ''):
            q.put(line)
        q.put(None)

    def monitor_process(self):
        try:
            line = self.log_queue.get_nowait()
            if line is None:
                self.process_finished()
                return
            self.log_message(line.strip())
        except queue.Empty:
            pass
        if self.process:
            self.root.after(100, self.monitor_process)

    def process_finished(self):
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"\nПроцесс завершен с кодом {return_code}.")
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None

    def stop_process(self):
        self.log_message("\n" + "="*40)
        self.log_message("--- ОСТАНОВКА / ПРОВЕРКА ПРОЦЕССА ---")
        kill_existing_processes(self.log_message)
        self.check_process_status()
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None
        
    def check_process_status(self):
        self.log_message("Проверка статуса через системный tasklist...")
        try:
            command = 'tasklist /FI "IMAGENAME eq winws.exe"'
            result = subprocess.run(command, capture_output=True, text=True, check=False, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if 'winws.exe' in result.stdout.lower():
                self.log_message("!!! ВНИМАНИЕ: Процесс winws.exe все еще активен!")
            else:
                self.log_message("ПОДТВЕРЖДЕНО: Процесс winws.exe в системе не найден.")
        except Exception as e:
            self.log_message(f"ERROR: Ошибка при проверке статуса: {e}")
        self.log_message("="*40 + "\n")

    def on_closing(self):
        self.stop_process()
        self.root.destroy()

    def log_message(self, message):
        self.log_window.config(state='normal')
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.config(state='disabled')
        self.log_window.see(tk.END)