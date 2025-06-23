import tkinter as tk
from tkinter import scrolledtext, messagebox
import os
import threading
import queue
from executor import find_bat_files, run_bat_file, kill_existing_processes
from text_utils import setup_text_widget_bindings

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Zapret Launcher")
        self.root.geometry("700x500")
        self.process = None
        self.log_queue = queue.Queue()

        self.create_widgets()
        self.populate_bat_files()
        
        # Убедимся, что при закрытии окна процесс тоже завершается
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill=tk.X)

        self.run_button = tk.Button(top_frame, text="Запустить выбранный файл", command=self.select_and_run_bat)
        self.run_button.pack(side=tk.LEFT)
        
        self.stop_button = tk.Button(top_frame, text="Остановить", command=self.stop_process, state=tk.NORMAL) # Кнопка доступна всегда
        self.stop_button.pack(side=tk.LEFT, padx=5)

        list_frame = tk.Frame(self.root)
        list_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        list_label = tk.Label(list_frame, text="Выберите профиль для запуска:")
        list_label.pack(anchor=tk.W)

        self.bat_listbox = tk.Listbox(list_frame)
        self.bat_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL)
        scrollbar.config(command=self.bat_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.bat_listbox.config(yscrollcommand=scrollbar.set)
        
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        log_label = tk.Label(log_frame, text="Логи:")
        log_label.pack(anchor=tk.W)
        
        self.log_window = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        
        setup_text_widget_bindings(self.log_window)
        setup_text_widget_bindings(self.bat_listbox)

    def populate_bat_files(self):
        zapret_dir = 'zapret-discord-youtube-1.8.1'
        if not os.path.isdir(zapret_dir):
            messagebox.showerror("Ошибка", f"Папка '{zapret_dir}' не найдена в корне проекта.")
            self.bat_files = []
            return
        self.bat_files = find_bat_files(zapret_dir)
        project_root = os.path.abspath('.')
        for abs_path in self.bat_files:
            display_path = os.path.relpath(abs_path, project_root).replace('\\', '/')
            self.bat_listbox.insert(tk.END, display_path)

    def select_and_run_bat(self):
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
        self.log_window.config(state='normal')
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state='disabled')
        
        # *** ГЛАВНОЕ ИСПРАВЛЕНИЕ: Убиваем старые процессы ПЕРЕД запуском ***
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
        for line in iter(process.stdout.readline, ''):
            q.put(line)
        # Сообщаем главному потоку, что процесс завершился
        q.put(None)

    def monitor_process(self):
        try:
            line = self.log_queue.get_nowait()
            if line is None: # Маркер завершения процесса
                self.process_finished()
                return
            self.log_message(line.strip())
        except queue.Empty:
            pass # Нет новых сообщений, это нормально
        
        # Продолжаем мониторинг, только если процесс еще не был отмечен как завершенный
        if self.process:
            self.root.after(100, self.monitor_process)

    def process_finished(self):
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"\nПроцесс завершен с кодом {return_code}.")
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None

    def stop_process(self):
        self.log_message("\n--- Остановка процесса ---")
        kill_existing_processes(self.log_message)
        self.run_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None
        
    def on_closing(self):
        """Обработчик закрытия окна."""
        self.stop_process()
        self.root.destroy()

    def log_message(self, message):
        self.log_window.config(state='normal')
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.config(state='disabled')
        self.log_window.see(tk.END)