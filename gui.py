import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import os
import sys
import threading
import queue
import subprocess
from executor import find_bat_files, run_bat_file, kill_existing_processes, analyze_site_domains
from text_utils import setup_text_widget_bindings

# --- Внедрение версии ---
try:
    from _version import __version__
except ImportError:
    __version__ = "dev"
# -------------------------

def resource_path(relative_path):
    """
    Получает абсолютный путь к ресурсу. Работает и для исходников,
    и для скомпилированного приложения.
    """
    try:
        # PyInstaller создает временную папку и сохраняет путь в _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # Если мы не в скомпилированном приложении, base_path - это папка, где лежит main.py
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class AddSiteDialog(tk.Toplevel):
    # ... (содержимое этого класса без изменений)
    """Диалоговое окно для анализа и добавления доменов сайта."""
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
            messagebox.showinfo("Успех", "Анализ завершен. Новые домены добавлены в custom_list.txt.", parent=self)
        else:
            messagebox.showerror("Ошибка", "Не удалось получить домены. Проверьте лог на наличие ошибок.", parent=self)
        self.destroy()

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Zapret Launcher v{__version__}")
        self.root.geometry("700x500")
        self.process = None
        self.log_queue = queue.Queue()
        self.create_widgets()
        self.populate_bat_files()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # ... (содержимое без изменений)
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill=tk.X)
        self.run_button = tk.Button(top_frame, text="Запустить профиль", command=self.select_and_run_bat)
        self.run_button.pack(side=tk.LEFT)
        self.stop_button = tk.Button(top_frame, text="Остановить/Проверить", command=self.stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.add_site_button = tk.Button(top_frame, text="Анализ сайта", command=self.open_add_site_dialog)
        self.add_site_button.pack(side=tk.LEFT, padx=5)
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

    def open_add_site_dialog(self):
        AddSiteDialog(self.root, self.add_domains_to_list)

    def add_domains_to_list(self, new_domains):
        # *** ИЗМЕНЕНО: Используем resource_path для доступа к файлу ***
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
        # *** ИЗМЕНЕНО: Используем resource_path для поиска папки ***
        zapret_dir = resource_path('zapret-discord-youtube-1.8.1')
        if not os.path.isdir(zapret_dir):
            messagebox.showerror("Ошибка", f"Папка 'zapret-discord-youtube-1.8.1' не найдена.")
            self.bat_files = []
            return
        self.bat_files = find_bat_files(zapret_dir)
        
        # Отображаемый путь строим относительно основной папки, а не временной
        project_root = os.path.abspath(".")
        for abs_path in self.bat_files:
            # Нам нужно показать простой путь, а не временный
            try:
                # Пытаемся построить путь относительно папки, где лежит exe
                display_path = os.path.relpath(abs_path, resource_path('')).replace('\\', '/')
            except ValueError:
                # Если не получается (например, разные диски), показываем только имя файла
                display_path = os.path.join('zapret-discord-youtube-1.8.1', os.path.basename(abs_path))
            self.bat_listbox.insert(tk.END, display_path)

    def select_and_run_bat(self):
        # ... (код без изменений)
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Информация", "Процесс уже запущен. Для перезапуска сначала остановите его.")
            return
        selected_indices = self.bat_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите профиль из списка.")
            return
        selected_index = selected_indices[0]
        file_path = self.bat_files[selected_index]
        self.run_process(file_path)

    def run_process(self, file_path):
        # ... (код без изменений)
        self.log_window.config(state='normal')
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state='disabled')
        kill_existing_processes(self.log_message)
        self.log_message(f"Запуск профиля: {os.path.basename(file_path)}")
        self.process = run_bat_file(file_path, self.log_message)
        if not self.process:
            self.log_message("Не удалось запустить процесс. Проверьте логи выше на наличие ошибок.")
            return
        self.run_button.config(state=tk.DISABLED)
        self.bat_listbox.config(state=tk.DISABLED)
        self.worker_thread = threading.Thread(target=self.read_process_output, args=(self.process, self.log_queue))
        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.monitor_process()

    def read_process_output(self, process, q):
        # ... (код без изменений)
        for line in iter(process.stdout.readline, ''):
            q.put(line)
        q.put(None)

    def monitor_process(self):
        # ... (код без изменений)
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
        # ... (код без изменений)
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"\nПроцесс завершен с кодом {return_code}.")
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None

    def stop_process(self):
        # ... (код без изменений)
        self.log_message("\n" + "="*40)
        self.log_message("--- ОСТАНОВКА / ПРОВЕРКА ПРОЦЕССА ---")
        kill_existing_processes(self.log_message)
        self.check_process_status()
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None
        
    def check_process_status(self):
        # ... (код без изменений)
        self.log_message("Проверка статуса через системный tasklist...")
        try:
            command = 'tasklist /FI "IMAGENAME eq winws.exe"'
            result = subprocess.run(command, capture_output=True, text=True, check=False, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if 'winws.exe' in result.stdout.lower():
                self.log_message("!!! ВНИМАНИЕ: Процесс winws.exe все еще активен!")
                self.log_message("    Возможно, для его остановки требуются права администратора.")
            else:
                self.log_message("ПОДТВЕРЖДЕНО: Процесс winws.exe в системе не найден.")
        except FileNotFoundError:
             self.log_message("WARNING: Команда 'tasklist' не найдена. Не могу проверить статус.")
        except Exception as e:
            self.log_message(f"ERROR: Ошибка при проверке статуса: {e}")
        self.log_message("="*40 + "\n")

    def on_closing(self):
        # ... (код без изменений)
        self.stop_process()
        self.root.destroy()

    def log_message(self, message):
        # ... (код без изменений)
        self.log_window.config(state='normal')
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.config(state='disabled')
        self.log_window.see(tk.END)