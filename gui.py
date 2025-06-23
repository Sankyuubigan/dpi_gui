import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import os
import sys
import threading
import queue
import subprocess
import glob
from executor import (
    find_bat_files, run_bat_file, kill_existing_processes, 
    analyze_site_domains, update_zapret_tool
)
from text_utils import setup_text_widget_bindings

try:
    from _version import __version__
except ImportError:
    __version__ = "dev"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class AddSiteDialog(tk.Toplevel):
    # ... (содержимое этого класса без изменений)
    def __init__(self, parent, on_complete_callback):
        super().__init__(parent)
        self.parent = parent
        self.on_complete_callback = on_complete_callback
        self.title("Анализ доменов сайта")
        self.geometry("500x350")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        tk.Label(self, text="Введите URL сайта для анализа:").pack(pady=(10, 5))
        self.url_entry = tk.Entry(self, width=60)
        self.url_entry.pack(pady=5, padx=10)
        self.url_entry.insert(0, "https://")
        self.analyze_button = tk.Button(self, text="Начать анализ", command=self.start_analysis)
        self.analyze_button.pack(pady=10)
        self.progress = ttk.Progressbar(self, mode='indeterminate', length=480)
        self.progress.pack(pady=5)
        self.log_widget = scrolledtext.ScrolledText(self, height=10, state='disabled', bg='black', fg='lightgray')
        self.log_widget.pack(pady=10, padx=10, fill="both", expand=True)

    def log(self, message):
        self.log_widget.config(state='normal')
        self.log_widget.insert(tk.END, message + "\n")
        self.log_widget.config(state='disabled')
        self.log_widget.see(tk.END)

    def start_analysis(self):
        url = self.url_entry.get()
        if not url or url == "https://":
            messagebox.showerror("Ошибка", "Пожалуйста, введите URL.", parent=self)
            return
        self.analyze_button.config(state="disabled")
        self.url_entry.config(state="disabled")
        self.progress.start(10)
        self.analysis_thread = threading.Thread(target=self._analysis_worker, args=(url,), daemon=True)
        self.analysis_thread.start()

    def _analysis_worker(self, url):
        found_domains = analyze_site_domains(url, self.log)
        self.parent.after(0, self.analysis_complete, found_domains)

    def analysis_complete(self, domains):
        self.progress.stop()
        if domains:
            self.on_complete_callback(domains)
            messagebox.showinfo("Успех", "Анализ завершен.", parent=self)
        else:
            messagebox.showerror("Ошибка", "Не удалось получить домены.", parent=self)
        self.destroy()

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(f"AntiZapret Launcher v{__version__}")
        self.root.geometry("850x850")
        self.process = None
        self.log_queue = queue.Queue()
        self.create_widgets()
        self.populate_bat_files()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # --- Верхняя панель с кнопками ---
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill=tk.X)
        
        self.run_button = tk.Button(top_frame, text="Запустить профиль", command=self.select_and_run_bat)
        self.run_button.pack(side=tk.LEFT)
        self.stop_button = tk.Button(top_frame, text="Остановить/Проверить", command=self.stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.add_site_button = tk.Button(top_frame, text="Анализ сайта", command=self.open_add_site_dialog)
        self.add_site_button.pack(side=tk.LEFT, padx=5)
        
        # --- Кнопки обновления справа ---
        self.update_launcher_button = tk.Button(top_frame, text="Обновить Лаунчер", command=self.run_self_update)
        self.update_launcher_button.pack(side=tk.RIGHT, padx=(10, 0))
        self.update_zapret_button = tk.Button(top_frame, text="Обновить Zapret", command=self.open_zapret_update_dialog)
        self.update_zapret_button.pack(side=tk.RIGHT)

        # ... остальной код виджетов без изменений
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
        """Запускает процесс самообновления лаунчера."""
        if messagebox.askyesno("Подтверждение", "Программа скачает последнюю версию с GitHub и закроется для обновления.\n\nПродолжить?"):
            try:
                updater_path = resource_path('_run_updater.bat')
                if not os.path.exists(updater_path):
                    messagebox.showerror("Ошибка", "Файл '_run_updater.bat' не найден!")
                    return

                # Запускаем батник в новом, отдельном процессе и консольном окне
                subprocess.Popen([updater_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
                
                # Сразу же закрываем текущее приложение
                self.root.destroy()
            except Exception as e:
                messagebox.showerror("Ошибка запуска", f"Не удалось запустить процесс обновления:\n{e}")

    def open_add_site_dialog(self):
        AddSiteDialog(self.root, self.add_domains_to_list)

    def open_zapret_update_dialog(self):
        if messagebox.askyesno("Подтверждение", "Это скачает последнюю версию утилиты Zapret от разработчика Flowseal.\n\nВсе активные процессы будут остановлены. Продолжить?"):
            update_thread = threading.Thread(target=self._zapret_update_worker, daemon=True)
            update_thread.start()

    def _zapret_update_worker(self):
        update_zapret_tool(resource_path('.'), self.log_message)
        self.root.after(0, self.refresh_bat_list)

    def refresh_bat_list(self):
        self.log_message("-> Обновляю список профилей...")
        self.bat_listbox.delete(0, tk.END)
        self.populate_bat_files()

    def add_domains_to_list(self, new_domains):
        custom_list_path = resource_path('custom_list.txt')
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
        base_path = resource_path('.')
        zapret_folders = glob.glob(os.path.join(base_path, 'zapret-discord-youtube-*'))
        if not zapret_folders:
            messagebox.showerror("Ошибка", f"Папка 'zapret-discord-youtube-*' не найдена.")
            self.bat_files = []
            return
        zapret_dir = zapret_folders[0]
        self.bat_files = find_bat_files(zapret_dir)
        self.bat_listbox.delete(0, tk.END)
        for abs_path in self.bat_files:
            try:
                display_path = os.path.relpath(abs_path, base_path).replace('\\', '/')
            except ValueError:
                display_path = os.path.join(os.path.basename(zapret_dir), os.path.basename(abs_path))
            self.bat_listbox.insert(tk.END, display_path)

    def select_and_run_bat(self):
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Информация", "Процесс уже запущен.")
            return
        selected_indices = self.bat_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите профиль из списка.")
            return
        selected_index = selected_indices[0]
        file_path = self.bat_files[selected_index]
        self.run_process(file_path)

    def run_process(self, file_path):
        self.log_window.config(state='normal')
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state='disabled')
        kill_existing_processes(self.log_message)
        self.log_message(f"Запуск профиля: {os.path.basename(file_path)}")
        self.process = run_bat_file(file_path, self.log_message)
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