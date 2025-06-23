import tkinter as tk
from tkinter import scrolledtext, messagebox
import os
from executor import find_bat_files, run_bat_file
from text_utils import setup_text_widget_bindings

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Zapret Launcher")
        self.root.geometry("700x500")
        self.process = None

        self.create_widgets()
        self.populate_bat_files()

    def create_widgets(self):
        # Frame for buttons and list
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill=tk.X)

        self.run_button = tk.Button(top_frame, text="Запустить выбранный файл", command=self.select_and_run_bat)
        self.run_button.pack(side=tk.LEFT)
        
        self.stop_button = tk.Button(top_frame, text="Остановить", command=self.stop_process, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Frame for the list of bat files
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
        
        # Log window
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        log_label = tk.Label(log_frame, text="Логи:")
        log_label.pack(anchor=tk.W)
        
        self.log_window = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        
        # Setup copy-paste bindings
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
        selected_indices = self.bat_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите .bat файл из списка.")
            return
            
        selected_index = selected_indices[0]
        file_path = self.bat_files[selected_index]
        self.run_process(file_path)

    def run_process(self, file_path):
        self.log_window.config(state='normal')
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state='disabled')
        
        self.log_message(f"Запуск профиля: {os.path.basename(file_path)}")
        self.process = run_bat_file(file_path, self.log_message)
        
        if not self.process:
             self.log_message("Не удалось запустить процесс. Проверьте логи выше на наличие ошибок.")
             return

        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.bat_listbox.config(state=tk.DISABLED)
        self.root.after(100, self.check_process)

    def check_process(self):
        if self.process and self.process.poll() is None:
            try:
                for line in iter(self.process.stdout.readline, ''):
                    if line:
                        self.log_message(line.strip())
                    else:
                        break
            except Exception as e:
                self.log_message(f"Ошибка чтения вывода: {e}")
            self.root.after(100, self.check_process)
        else:
            return_code = self.process.poll() if self.process else 'N/A'
            if return_code == 0:
                self.log_message(f"Процесс успешно завершен (код {return_code}).")
            else:
                self.log_message(f"Процесс завершен с ошибкой (код {return_code}).")
                self.log_message("ПОДСКАЗКА: Проверьте пути в 'Собранной команде' выше. Убедитесь, что они корректны и файлы существуют.")
            
            self.run_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.bat_listbox.config(state=tk.NORMAL)
            self.process = None

    def stop_process(self):
        if self.process and self.process.poll() is None:
            self.process.terminate() # Terminate the winws.exe process
            self.log_message("Процесс остановлен пользователем.")
        else:
            self.log_message("Нет активного процесса для остановки.")
        
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.bat_listbox.config(state=tk.NORMAL)
        self.process = None

    def log_message(self, message):
        self.log_window.config(state='normal')
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.config(state='disabled')
        self.log_window.see(tk.END)