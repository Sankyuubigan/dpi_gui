import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import datetime
import glob
from text_utils import setup_text_widget_bindings

class UIManager:
    """Класс для управления пользовательским интерфейсом"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.notebook = None
        self.status_text = None
        self.log_window = None
        self.status_indicator = None
        self.all_logs = []
        self.filtered_logs = []
        
    def setup_window(self):
        """Настраивает главное окно"""
        version_hash = "unknown"
        version_file_path = os.path.join(self.app.app_dir, ".version_hash")
        if os.path.exists(version_file_path):
            with open(version_file_path, 'r') as f:
                full_hash = f.read().strip()
                if full_hash:
                    version_hash = full_hash[:7]
        self.app.root.title(f"DPI_GUI Launcher (Commit: {version_hash})")
        self.app.root.geometry("850x750")
        try:
            icon_path = os.path.join(self.app.app_dir, 'icon.ico')
            if os.path.exists(icon_path):
                self.app.root.iconbitmap(icon_path)
        except Exception:
            pass

    def create_widgets(self):
        """Создает все виджеты интерфейса"""
        self.notebook = ttk.Notebook(self.app.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        
        tab_control = ttk.Frame(self.notebook, padding=10)
        tab_tools = ttk.Frame(self.notebook, padding=10)
        tab_testing = ttk.Frame(self.notebook, padding=10)
        tab_domains = ttk.Frame(self.notebook, padding=10)
        tab_logs = ttk.Frame(self.notebook, padding=10)
        
        self.notebook.add(tab_control, text="Управление")
        self.notebook.add(tab_tools, text="Инструменты и Настройки")
        self.notebook.add(tab_testing, text="Тестирование")
        self.notebook.add(tab_domains, text="Домены")
        self.notebook.add(tab_logs, text="Логи")
        
        self.create_control_tab(tab_control)
        self.create_tools_tab(tab_tools)
        self.create_testing_tab(tab_testing)
        self.create_domains_tab(tab_domains)
        self.create_logs_tab(tab_logs)

    def create_control_tab(self, parent):
        """Создает вкладку управления"""
        profile_frame = ttk.LabelFrame(parent, text="Профиль обхода")
        profile_frame.pack(fill=tk.X, pady=5)

        self.app.profile_var = tk.StringVar()
        self.app.profiles_combobox = ttk.Combobox(profile_frame, textvariable=self.app.profile_var, state="readonly")
        self.app.profiles_combobox.pack(fill=tk.X, padx=5, pady=5)
        
        self.app.list_manager.create_list_selection_ui(parent)
        
        # Добавляем чекбокс для выбора кастомного списка
        custom_list_frame = ttk.Frame(parent)
        custom_list_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.app.use_custom_list_var = tk.BooleanVar()
        self.app.use_custom_list_check = ttk.Checkbutton(
            custom_list_frame, 
            text="Использовать кастомный список", 
            variable=self.app.use_custom_list_var,
            command=self.app.on_custom_list_toggle
        )
        self.app.use_custom_list_check.pack(side=tk.LEFT, padx=5)
        
        self.app.custom_list_path_label = tk.Label(custom_list_frame, text="(не выбран)", fg="gray")
        self.app.custom_list_path_label.pack(side=tk.LEFT, padx=5)
        
        actions_frame = ttk.Frame(parent)
        actions_frame.pack(fill=tk.X, pady=5)
        
        self.app.run_button = ttk.Button(actions_frame, text="Запустить", command=self.app.run_selected_profile)
        self.app.run_button.pack(side=tk.LEFT, padx=5)
        self.app.stop_button = ttk.Button(actions_frame, text="Остановить", command=self.app.stop_process)
        self.app.stop_button.pack(side=tk.LEFT, padx=5)

        self.app.status_label = tk.Label(actions_frame, text="Статус:")
        self.app.status_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_indicator = tk.Label(actions_frame, text="ОСТАНОВЛЕНО", bg="#cccccc", fg="white", padx=10, pady=2, relief=tk.RAISED, borderwidth=2)
        self.status_indicator.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Добавляем индикатор статуса на основную вкладку
        status_frame = ttk.LabelFrame(parent, text="Индикатор статуса")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.status_text = tk.Text(status_frame, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.status_text)
        
        # Кнопка очистки статуса
        clear_status_btn = ttk.Button(status_frame, text="Очистить", command=self.clear_status)
        clear_status_btn.pack(pady=5)

    def create_domains_tab(self, parent):
        """Создает вкладку доменов"""
        self.app.domain_manager.create_domains_tab(parent)

    def create_logs_tab(self, parent):
        """Создает вкладку с объединенными логами"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="Объединенные логи приложения", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Очистить все", command=self.clear_all_logs).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="Сохранить в файл", command=self.save_logs_to_file).pack(side=tk.RIGHT, padx=5)
        
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_window = scrolledtext.ScrolledText(log_frame, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)
        
        filter_frame = ttk.LabelFrame(parent, text="Фильтры логов")
        filter_frame.pack(fill=tk.X, pady=5)
        
        self.show_main_logs = tk.BooleanVar(value=True)
        self.show_domain_logs = tk.BooleanVar(value=True)
        self.show_status_logs = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(filter_frame, text="Основные логи", variable=self.show_main_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Логи анализа доменов", variable=self.show_domain_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Логи статуса", variable=self.show_status_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)

    def create_tools_tab(self, parent):
        """Создает вкладку инструментов"""
        tools_top_frame = ttk.Frame(parent)
        tools_top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(tools_top_frame, text="Проверить статус", command=self.app.check_status).pack(side=tk.LEFT, padx=5, pady=5)
        
        settings_frame = ttk.LabelFrame(parent, text="Настройки")
        settings_frame.pack(fill=tk.X, pady=10)
        
        self.app.game_filter_var = tk.BooleanVar()
        self.app.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (для всех профилей)", variable=self.app.game_filter_var)
        self.app.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # --- IPSet Selection UI ---
        ipset_frame = ttk.LabelFrame(parent, text="Настройки IPSet")
        ipset_frame.pack(fill=tk.X, pady=10, padx=0)
        
        self.app.ipset_selection_var = tk.StringVar(value="OFF")
        
        # Кнопка "Выкл"
        ttk.Radiobutton(ipset_frame, text="Выключено (Не использовать IPSet)", 
                        variable=self.app.ipset_selection_var, value="OFF").pack(anchor=tk.W, padx=5, pady=2)
        
        # Поиск файлов в папке ipsets
        ipsets_dir = os.path.join(self.app.app_dir, 'ipsets')
        if os.path.exists(ipsets_dir):
            txt_files = glob.glob(os.path.join(ipsets_dir, '*.txt'))
            if txt_files:
                ttk.Label(ipset_frame, text="Выберите файл:", font=("", 8, "bold")).pack(anchor=tk.W, padx=5, pady=(5,0))
                for file_path in txt_files:
                    filename = os.path.basename(file_path)
                    ttk.Radiobutton(ipset_frame, text=filename, 
                                    variable=self.app.ipset_selection_var, value=filename).pack(anchor=tk.W, padx=15, pady=1)
            else:
                ttk.Label(ipset_frame, text="В папке ipsets нет .txt файлов", fg="gray").pack(anchor=tk.W, padx=5, pady=2)
        else:
            ttk.Label(ipset_frame, text="Папка ipsets не найдена", fg="red").pack(anchor=tk.W, padx=5, pady=2)
        # --------------------------
        
        service_frame = ttk.LabelFrame(parent, text="Автозапуск (Системная служба)")
        service_frame.pack(fill=tk.X, pady=10)
        self.app.install_service_button = ttk.Button(service_frame, text="Установить в автозапуск", command=self.app.install_service)
        self.app.install_service_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.app.uninstall_service_button = ttk.Button(service_frame, text="Удалить из автозапуска", command=self.app.uninstall_service)
        self.app.uninstall_service_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        domain_frame = ttk.LabelFrame(parent, text="Пользовательские списки")
        domain_frame.pack(fill=tk.X, pady=10)
        ttk.Button(domain_frame, text="Открыть кастомный список", command=self.app.open_custom_list).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(domain_frame, text="Выбрать кастомный список...", command=self.app.select_custom_list_file).pack(side=tk.LEFT, padx=5, pady=5)

    def create_testing_tab(self, parent):
        """Создает вкладку тестирования"""
        site_test_frame = ttk.LabelFrame(parent, text="Автоматический тест по сайту")
        site_test_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(site_test_frame, text="Адрес сайта (например, rutracker.org):").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.app.site_test_url = tk.StringVar(value="rutracker.org")
        self.app.site_test_url_entry = ttk.Entry(site_test_frame, textvariable=self.app.site_test_url)
        self.app.site_test_url_entry.pack(fill=tk.X, padx=5, pady=5)

        self.app.site_test_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.app.site_test_url_menu.add_command(label="Вставить", command=self.app.paste_site_test_url)
        self.app.site_test_url_entry.bind("<Button-3>", self.app.show_site_test_url_menu)
        self.app.site_test_url_entry.bind("<Control-v>", lambda e: self.app.paste_site_test_url())

        ttk.Button(site_test_frame, text="Начать тест по сайту", command=self.app.run_site_test).pack(pady=5)
        
        discord_test_frame = ttk.LabelFrame(parent, text="Интерактивный тест для Discord")
        discord_test_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(discord_test_frame, text="Очистить кэш Discord", command=lambda: self.app.run_in_thread(self.app.settings_manager.clear_discord_cache, self.app.app_dir, self.app.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(discord_test_frame, text="Начать тест для Discord", command=self.app.run_discord_test).pack(side=tk.LEFT, padx=5, pady=5)

    def update_status_indicator(self, is_running):
        """Обновляет индикатор статуса"""
        if self.status_indicator:
            if is_running:
                self.status_indicator.config(text="ЗАПУЩЕНО", bg="#4CAF50")
                if hasattr(self.app, 'domain_manager') and self.app.domain_manager.domain_start_btn:
                    self.app.domain_manager.domain_start_btn.config(state=tk.NORMAL)
            else:
                self.status_indicator.config(text="ОСТАНОВЛЕНО", bg="#cccccc")
                if hasattr(self.app, 'domain_manager') and self.app.domain_manager.domain_start_btn:
                    self.app.domain_manager.domain_start_btn.config(state=tk.NORMAL)

    def update_status_display(self, message, log_type):
        """Обновляет индикатор статуса на основной вкладке"""
        try:
            if self.status_text:
                self.status_text.config(state='normal')
                color = "white"
                if log_type == "error": color = "#ff6b6b"
                elif log_type == "success": color = "#51cf66"
                elif log_type == "status": color = "#74c0fc"
                
                self.status_text.tag_configure(log_type, foreground=color)
                self.status_text.insert(tk.END, f"{message}\n", log_type)
                self.status_text.see(tk.END)
                
                lines = int(self.status_text.index('end-1c').split('.')[0])
                if lines > 50:
                    self.status_text.delete('1.0', '2.0')
                self.status_text.config(state='disabled')
        except:
            pass

    def update_log_display(self):
        """Обновляет отображение логов согласно фильтрам"""
        if not self.log_window: return
        try:
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            self.filtered_logs = []
            for log_entry in self.all_logs:
                if (log_entry["type"] == "main" and self.show_main_logs.get()) or \
                   (log_entry["type"] == "domain" and self.show_domain_logs.get()) or \
                   (log_entry["type"] in ["status", "error", "success"] and self.show_status_logs.get()):
                    self.filtered_logs.append(log_entry)
                    self.log_window.insert(tk.END, log_entry["text"] + "\n")
            self.log_window.config(state='disabled')
            self.log_window.see(tk.END)
        except:
            pass

    def update_log_filter(self):
        self.update_log_display()

    def clear_all_logs(self):
        self.all_logs.clear()
        self.filtered_logs.clear()
        if self.log_window:
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            self.log_window.config(state='disabled')
        self.app.log_message("Все логи очищены", "status")

    def clear_status(self):
        if self.status_text:
            self.status_text.config(state='normal')
            self.status_text.delete('1.0', tk.END)
            self.status_text.config(state='disabled')

    def save_logs_to_file(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Логи DPI GUI\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Сохранено: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    for log_entry in self.all_logs:
                        f.write(log_entry["text"] + "\n")
                messagebox.showinfo("Успех", f"Логи сохранены в файл:\n{filename}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить логи:\n{e}")

    def set_controls_state(self, state):
        self.app.run_button.config(state=state)
        self.app.install_service_button.config(state=state)
        combobox_state = "readonly" if state == tk.NORMAL else tk.DISABLED
        self.app.profiles_combobox.config(state=combobox_state)
        self.app.use_custom_list_check.config(state=state)