import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import threading
import queue
import subprocess
import traceback
import logging
import datetime
import ctypes
import time
# --- Начальная настройка и проверка прав ---
# Определяем базовую директорию приложения (папка app_src)
APP_SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_SOURCE_DIR)
# --- Импорты модулей проекта ---
from executor import is_custom_list_valid
from domain_finder import check_dependencies, analyze_site_domains_performance, analyze_site_domains_playwright, analyze_site_domains_selenium, analyze_site_domains_simple
from text_utils import setup_text_widget_bindings
from list_manager import ListManager
from profiles import PROFILES
import process_manager
import settings_manager
import testing_utils
import power_handler

def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        messagebox.showerror("Ошибка запуска", f"Не удалось перезапустить с правами администратора:\n{e}")

class App:
    def __init__(self, root):
        self.root = root
        self.process = None
        self.log_queue = queue.Queue()
        self.app_dir = APP_SOURCE_DIR
        self.profiles = PROFILES
        self.test_thread = None
        self.list_manager = ListManager(self.app_dir)
        self.domain_analysis_thread = None
        self._monitoring_active = False

        # Настройка логирования для status indicator
        os.makedirs("roo_tests", exist_ok=True)
        self.status_logger = logging.getLogger("status_indicators")
        handler = logging.FileHandler("roo_tests/status_runtime.log")
        formatter = logging.Formatter("%(asctime)s - %(message)s")
        handler.setFormatter(formatter)
        self.status_logger.addHandler(handler)
        self.status_logger.setLevel(logging.INFO)

        self.setup_window()
        self.create_widgets()
        self.populate_profiles_list()
        self.load_app_settings()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Устанавливаем обработчик событий питания
        power_handler.setup_power_handler(self)
        
    def setup_window(self):
        version_hash = "unknown"
        version_file_path = os.path.join(self.app_dir, ".version_hash")
        if os.path.exists(version_file_path):
            with open(version_file_path, 'r') as f:
                full_hash = f.read().strip()
                if full_hash:
                    version_hash = full_hash[:7]
        self.root.title(f"DPI_GUI Launcher (Commit: {version_hash})")
        self.root.geometry("850x700")
        try:
            icon_path = os.path.join(self.app_dir, 'icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=5)
        tab_control = ttk.Frame(notebook, padding=10)
        tab_tools = ttk.Frame(notebook, padding=10)
        tab_testing = ttk.Frame(notebook, padding=10)
        tab_domains = ttk.Frame(notebook, padding=10)
        tab_logs = ttk.Frame(notebook, padding=10)
        notebook.add(tab_control, text="Управление")
        notebook.add(tab_tools, text="Инструменты и Настройки")
        notebook.add(tab_testing, text="Тестирование")
        notebook.add(tab_domains, text="Домены")
        notebook.add(tab_logs, text="Логи")
        
        self.create_control_tab(tab_control)
        self.create_tools_tab(tab_tools)
        self.create_testing_tab(tab_testing)
        self.create_domains_tab(tab_domains)
        self.create_logs_tab(tab_logs)

    def create_control_tab(self, parent):
        profile_frame = ttk.LabelFrame(parent, text="Профиль обхода")
        profile_frame.pack(fill=tk.X, pady=5)

        self.profile_var = tk.StringVar()
        self.profiles_combobox = ttk.Combobox(profile_frame, textvariable=self.profile_var, state="readonly")
        self.profiles_combobox.pack(fill=tk.X, padx=5, pady=5)
        
        self.list_manager.create_list_selection_ui(parent)
        
        # Добавляем чекбокс для выбора кастомного списка
        custom_list_frame = ttk.Frame(parent)
        custom_list_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.use_custom_list_var = tk.BooleanVar()
        self.use_custom_list_check = ttk.Checkbutton(
            custom_list_frame, 
            text="Использовать кастомный список", 
            variable=self.use_custom_list_var,
            command=self.on_custom_list_toggle
        )
        self.use_custom_list_check.pack(side=tk.LEFT, padx=5)
        
        self.custom_list_path_label = tk.Label(custom_list_frame, text="(не выбран)", fg="gray")
        self.custom_list_path_label.pack(side=tk.LEFT, padx=5)
        
        actions_frame = ttk.Frame(parent)
        actions_frame.pack(fill=tk.X, pady=5)
        
        self.run_button = ttk.Button(actions_frame, text="Запустить", command=self.run_selected_profile)
        self.run_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(actions_frame, text="Остановить", command=self.stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(actions_frame, text="Статус:")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_indicator = tk.Label(actions_frame, text="ОСТАНОВЛЕНО", bg="#cccccc", fg="white", padx=10, pady=2, relief=tk.RAISED, borderwidth=2)
        self.status_indicator.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Добавляем индикатор статуса на основную вкладку - РАСТЯГИВАЕМ НА ВСЮ ВЫСОТУ
        status_frame = ttk.LabelFrame(parent, text="Индикатор статуса")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.status_text = tk.Text(status_frame, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.status_text)
        
        # Кнопка очистки статуса
        clear_status_btn = ttk.Button(status_frame, text="Очистить", command=self.clear_status)
        clear_status_btn.pack(pady=5)

    def create_domains_tab(self, parent):
        # Метод анализа
        method_frame = ttk.LabelFrame(parent, text="Метод анализа")
        method_frame.pack(fill=tk.X, pady=5)

        self.domain_method_var = tk.StringVar()
        method_choices = []
        self.domain_method_map = {}
        
        available_methods = check_dependencies()

        if available_methods.get('selenium', False):
            display_name = "Performance API (рекомендуется)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "performance"

        if available_methods.get('simple', False):
            display_name = "Simple Parser (без браузера)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "simple"

        if available_methods.get('playwright', False):
            display_name = "Playwright (быстрый, современный)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "playwright"
        
        if available_methods.get('selenium', False):
            display_name = "Selenium (классический)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "selenium"
            
        if not method_choices:
            method_choices.append("Нет доступных методов")
            self.domain_method_map["Нет доступных методов"] = "none"
            
        self.domain_method_combo = ttk.Combobox(method_frame, textvariable=self.domain_method_var, 
                                               values=method_choices, state="readonly")
        self.domain_method_combo.pack(fill=tk.X, padx=5, pady=5)
        if method_choices:
            self.domain_method_combo.current(0)

        # URL сайта
        url_frame = ttk.LabelFrame(parent, text="URL сайта для анализа")
        url_frame.pack(fill=tk.X, pady=5)
        self.domain_url_entry = tk.Entry(url_frame, width=60)
        self.domain_url_entry.pack(fill=tk.X, padx=5, pady=5)

        # Создаем контекстное меню для поля ввода URL
        self.domain_url_menu = tk.Menu(self.root, tearoff=0)
        self.domain_url_menu.add_command(label="Вставить", command=self.paste_domain_url)
        self.domain_url_entry.bind("<Button-3>", self.show_domain_url_menu)
        self.domain_url_entry.bind("<Control-v>", lambda e: self.paste_domain_url())
        
        # Кнопка анализа
        self.domain_start_btn = ttk.Button(parent, text="🔍 Начать анализ и добавить домены", command=self.start_domain_analysis, state=tk.NORMAL)
        self.domain_start_btn.pack(pady=10)
        
        # Информационная метка о логах
        info_label = tk.Label(parent, text="Все логи анализа отображаются на вкладке 'Логи'", fg="gray")
        info_label.pack(pady=5)

    def create_logs_tab(self, parent):
        """Создает вкладку с объединенными логами"""
        # Заголовок
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="Объединенные логи приложения", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        # Кнопки управления
        ttk.Button(header_frame, text="Очистить все", command=self.clear_all_logs).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="Сохранить в файл", command=self.save_logs_to_file).pack(side=tk.RIGHT, padx=5)
        
        # Основное окно логов
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_window = scrolledtext.ScrolledText(log_frame, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)
        
        # Фильтры логов
        filter_frame = ttk.LabelFrame(parent, text="Фильтры логов")
        filter_frame.pack(fill=tk.X, pady=5)
        
        self.show_main_logs = tk.BooleanVar(value=True)
        self.show_domain_logs = tk.BooleanVar(value=True)
        self.show_status_logs = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(filter_frame, text="Основные логи", variable=self.show_main_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Логи анализа доменов", variable=self.show_domain_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Логи статуса", variable=self.show_status_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        
        # Хранилище всех логов
        self.all_logs = []
        self.filtered_logs = []

    def create_tools_tab(self, parent):
        tools_top_frame = ttk.Frame(parent)
        tools_top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(tools_top_frame, text="Проверить статус", command=self.check_status).pack(side=tk.LEFT, padx=5, pady=5)
        
        settings_frame = ttk.LabelFrame(parent, text="Настройки")
        settings_frame.pack(fill=tk.X, pady=10)
        
        self.game_filter_var = tk.BooleanVar()
        self.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (для всех профилей)", variable=self.game_filter_var)
        self.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        self.use_ipset_var = tk.BooleanVar(value=False)
        self.use_ipset_check = ttk.Checkbutton(settings_frame, text="Использовать IPSet (требует ручного обновления)", variable=self.use_ipset_var)
        self.use_ipset_check.pack(anchor=tk.W, padx=5, pady=5)
        
        service_frame = ttk.LabelFrame(parent, text="Автозапуск (Системная служба)")
        service_frame.pack(fill=tk.X, pady=10)
        self.install_service_button = ttk.Button(service_frame, text="Установить в автозапуск", command=self.install_service)
        self.install_service_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.uninstall_service_button = ttk.Button(service_frame, text="Удалить из автозапуска", command=self.uninstall_service)
        self.uninstall_service_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        domain_frame = ttk.LabelFrame(parent, text="Пользовательские списки")
        domain_frame.pack(fill=tk.X, pady=10)
        ttk.Button(domain_frame, text="Открыть кастомный список", command=self.open_custom_list).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(domain_frame, text="Выбрать кастомный список...", command=self.select_custom_list_file).pack(side=tk.LEFT, padx=5, pady=5)

    def create_testing_tab(self, parent):
        site_test_frame = ttk.LabelFrame(parent, text="Автоматический тест по сайту")
        site_test_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(site_test_frame, text="Адрес сайта (например, rutracker.org):").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.site_test_url = tk.StringVar(value="rutracker.org")
        self.site_test_url_entry = ttk.Entry(site_test_frame, textvariable=self.site_test_url)
        self.site_test_url_entry.pack(fill=tk.X, padx=5, pady=5)

        # Создаем контекстное меню для поля ввода URL теста
        self.site_test_url_menu = tk.Menu(self.root, tearoff=0)
        self.site_test_url_menu.add_command(label="Вставить", command=self.paste_site_test_url)
        self.site_test_url_entry.bind("<Button-3>", self.show_site_test_url_menu)
        self.site_test_url_entry.bind("<Control-v>", lambda e: self.paste_site_test_url())

        ttk.Button(site_test_frame, text="Начать тест по сайту", command=self.run_site_test).pack(pady=5)
        discord_test_frame = ttk.LabelFrame(parent, text="Интерактивный тест для Discord")
        discord_test_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(discord_test_frame, text="Очистить кэш Discord", command=lambda: self.run_in_thread(settings_manager.clear_discord_cache, self.app_dir, self.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(discord_test_frame, text="Начать тест для Discord", command=self.run_discord_test).pack(side=tk.LEFT, padx=5, pady=5)

    def _handle_ui_error(self, e):
        error_details = traceback.format_exc()
        self.log_message("\n" + "="*20 + " КРИТИЧЕСКАЯ ОШИБКА GUI " + "="*20, "error")
        self.log_message("Произошла непредвиденная ошибка в интерфейсе:", "error")
        self.log_message(error_details, "error")
        self.log_message("="*62 + "\n", "error")
        messagebox.showerror("Критическая ошибка", f"Произошла ошибка:\n{e}\n\nПодробности записаны в окне логов.")

    def populate_profiles_list(self):
        profile_names = [p['name'] for p in self.profiles]
        self.profiles_combobox['values'] = profile_names
        if profile_names:
            self.profiles_combobox.current(0)
        # Добавляем обработчик смены профиля
        self.profiles_combobox.bind("<<ComboboxSelected>>", self.on_profile_change)

    def on_profile_change(self, event=None):
        """Обработчик изменения профиля. Обновляет состояние обязательных списков."""
        profile = self.get_selected_profile()
        if profile:
            required_lists = profile.get('required_lists', [])
            self.list_manager.set_required_lists(required_lists)
            self.log_message(f"Выбран профиль: {profile['name']}. Обязательные списки: {required_lists}", "main")

    def get_selected_profile(self):
        selected_name = self.profile_var.get()
        if not selected_name:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите профиль из списка.")
            return None
        
        return next((p for p in self.profiles if p['name'] == selected_name), None)

    def update_status_indicator(self, is_running):
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        bg_color = "#4CAF50" if is_running else "#cccccc"
        self.status_logger.info(f"time={time_str}, is_running={is_running}, bg_color={bg_color}")

        if is_running:
            self.status_indicator.config(text="ЗАПУЩЕНО", bg="#4CAF50")
            self.domain_start_btn.config(state=tk.NORMAL)
        else:
            self.status_indicator.config(text="ОСТАНОВЛЕНО", bg="#cccccc")
            self.domain_start_btn.config(state=tk.NORMAL)

    def run_selected_profile(self):
        print("!!! ДИАГНОСТИКА: ВЫПОЛНЯЕТСЯ НОВАЯ ВЕРСИЯ RUN_SELECTED_PROFILE !!!")
        try:
            if self.process and self.process.poll() is None:
                messagebox.showinfo("Информация", "Процесс уже запущен.")
                return
            
            profile = self.get_selected_profile()
            if not profile: return
            
            self.log_message(f"Запуск профиля: {profile['name']}", "main")
            process_manager.stop_all_processes(self.log_message)
            
            game_filter_enabled = self.game_filter_var.get()
            use_ipset = self.use_ipset_var.get()
            
            if use_ipset and not os.path.exists(os.path.join(self.app_dir, 'lists', 'ipset-all.txt')):
                self.log_message("ВНИМАНИЕ: ipset-all.txt не найден. Запустите обновление вручную в `launcher.py` или скачайте его.", "status")

            custom_list_path = None
            if self.use_custom_list_var.get():
                custom_list_path = self.list_manager.get_custom_list_path()
                self.log_message(f"Использование кастомного списка ВКЛЮЧЕНО. Путь: {custom_list_path}", "main")
                if not custom_list_path or not os.path.exists(custom_list_path):
                    messagebox.showwarning("Предупреждение", "Кастомный список не выбран или файл не существует.")
                    return
            else:
                self.log_message("Использование кастомного списка ВЫКЛЮЧЕНО", "main")

            combined_list_path = self.list_manager.get_combined_list_path(custom_list_path, self.log_message)
            
            if combined_list_path:
                 self.log_message(f"Объединенный список для запуска: {combined_list_path}", "main")
            else:
                 self.log_message("ВНИМАНИЕ: Объединенный список не был создан (пуст или не выбран). Обход будет работать без списков доменов.", "status")

            self.process = process_manager.start_process(
                profile, self.app_dir, game_filter_enabled, 
                self.log_message, combined_list_path, use_ipset
            )
            
            if not self.process:
                self.log_message("Не удалось запустить процесс. Проверьте логи выше на наличие ошибок.", "error")
                return
                
            self.set_controls_state(tk.DISABLED)
            self.update_status_indicator(True)
            self.worker_thread = threading.Thread(target=self.read_process_output, daemon=True)
            self.worker_thread.start()
            self.monitor_process()
        except Exception as e:
            self._handle_ui_error(e)

    def read_process_output(self):
        for line in iter(self.process.stdout.readline, ''):
            self.log_queue.put(line)
        self.log_queue.put(None)

    def monitor_process(self):
        """Мониторит процесс с защитой от рекурсивного создания"""
        try:
            if hasattr(self, '_monitoring_active') and self._monitoring_active:
                return
                
            self._monitoring_active = True
            
            line = self.log_queue.get_nowait()
            if line is None:
                self.process_finished()
                self._monitoring_active = False
                return
            self.log_message(line.strip(), "main")
        except queue.Empty:
            pass
        except Exception as e:
            self.log_message(f"Ошибка в мониторе процесса: {e}", "error")
            self._monitoring_active = False
            return
            
        if self.process and self.process.poll() is None:
            self.root.after(100, self.monitor_process)
        elif self.process:
            self.process_finished()
            self._monitoring_active = False
        else:
            self._monitoring_active = False

    def process_finished(self):
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"Процесс завершен с кодом {return_code}", "status")
        self.set_controls_state(tk.NORMAL)
        self.update_status_indicator(False)
        self.process = None

    def stop_process(self):
        try:
            self.log_message("ОСТАНОВКА ПРОЦЕССА", "status")
            
            self.stop_button.config(state=tk.DISABLED, text="Остановка...")
            self.root.update()
            
            process_manager.stop_all_processes(self.log_message)
            
            time.sleep(2)
            
            if not process_manager.is_process_running():
                self.log_message("✓ Все процессы успешно остановлены", "success")
            else:
                self.log_message("⚠ Некоторые процессы все еще активны", "error")
            
            self.check_status(log_header=False)
            self.set_controls_state(tk.NORMAL)
            self.update_status_indicator(False)
            
            if self.process:
                self.process = None
                
            self.stop_button.config(state=tk.NORMAL, text="Остановить")
            
        except Exception as e:
            self._handle_ui_error(e)
        finally:
            self.stop_button.config(state=tk.NORMAL, text="Остановить")

    def check_status(self, log_header=True):
        try:
            settings_manager.check_status(self.app_dir, self.log_message, log_header)
        except Exception as e:
            self._handle_ui_error(e)

    def set_controls_state(self, state):
        self.run_button.config(state=state)
        self.install_service_button.config(state=state)
        combobox_state = "readonly" if state == tk.NORMAL else tk.DISABLED
        self.profiles_combobox.config(state=combobox_state)
        self.use_custom_list_check.config(state=state)

    def on_closing(self):
        try:
            self.save_app_settings()
            if self.process and self.process.poll() is None:
                choice = self._ask_to_stop_on_close()
                if choice == 'yes':
                    self.stop_process()
                    self.root.destroy()
                elif choice == 'no':
                    self.root.destroy()
            else:
                self.root.destroy()
        except Exception as e:
            self._handle_ui_error(e)

    def _ask_to_stop_on_close(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Подтверждение выхода")
        dialog.geometry("350x120")
        dialog.resizable(False, False)
        
        dialog.transient(self.root)
        dialog.grab_set()
        
        result = {'choice': None}

        message = "Процесс еще активен. Остановить его перед выходом?"
        tk.Label(dialog, text=message, wraplength=300).pack(pady=10)

        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=10)

        def on_yes():
            result['choice'] = 'yes'
            dialog.destroy()

        def on_no():
            result['choice'] = 'no'
            dialog.destroy()

        def on_cancel():
            result['choice'] = 'cancel'
            dialog.destroy()

        tk.Button(button_frame, text="Да", command=on_yes, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Нет", command=on_no, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Отмена", command=on_cancel, width=10).pack(side=tk.LEFT, padx=5)
        
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        self.root.wait_window(dialog)
        
        return result['choice']

    def log_message(self, message, log_type="main"):
        """Универсальная функция логирования с типом"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        prefix = ""
        if log_type == "domain":
            prefix = "[ДОМЕНЫ] "
        elif log_type == "status":
            prefix = "[СТАТУС] "
        elif log_type == "error":
            prefix = "[ОШИБКА] "
        elif log_type == "success":
            prefix = "[УСПЕХ] "
        
        formatted_message = f"[{timestamp}] {prefix}{message}"
        
        log_entry = {"text": formatted_message, "type": log_type, "timestamp": timestamp}
        self.all_logs.append(log_entry)
        
        self.update_log_display()
        
        if log_type in ["main", "status", "error", "success"]:
            self.update_status_display(message, log_type)
    
    def update_status_display(self, message, log_type):
        """Обновляет индикатор статуса на основной вкладке"""
        try:
            self.status_text.config(state='normal')
            
            color = "white"
            if log_type == "error":
                color = "#ff6b6b"
            elif log_type == "success":
                color = "#51cf66"
            elif log_type == "status":
                color = "#74c0fc"
            
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
        if not hasattr(self, 'log_window'):
            return
            
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
        """Обновляет фильтр логов"""
        self.update_log_display()
    
    def clear_all_logs(self):
        """Очищает все логи"""
        self.all_logs.clear()
        self.filtered_logs.clear()
        if hasattr(self, 'log_window'):
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            self.log_window.config(state='disabled')
        self.log_message("Все логи очищены", "status")
    
    def clear_status(self):
        """Очищает индикатор статуса"""
        if hasattr(self, 'status_text'):
            self.status_text.config(state='normal')
            self.status_text.delete('1.0', tk.END)
            self.status_text.config(state='disabled')
    
    def save_logs_to_file(self):
        """Сохраняет логи в файл"""
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
                self.log_message(f"Логи сохранены в файл: {filename}", "success")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить логи:\n{e}")
            self.log_message(f"Ошибка сохранения логов: {e}", "error")
    
    def domain_log(self, message):
        """Логирование для анализа доменов"""
        self.log_message(message, "domain")

    def run_in_thread(self, target_func, *args):
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()

    def save_app_settings(self):
        settings_data = {
            "selected_profile": self.profile_var.get(),
            "game_filter": self.game_filter_var.get(),
            "use_ipset": self.use_ipset_var.get(),
            "selected_lists": self.list_manager.selected_lists,
            "use_custom_list": self.use_custom_list_var.get(),
            "custom_list_path": self.list_manager.get_custom_list_path()
        }
        settings_manager.save_app_settings(settings_data, self.app_dir)
        self.log_message("Настройки сохранены.", "success")

    def load_app_settings(self):
        settings = settings_manager.load_app_settings(self.app_dir)
        if not settings:
            self.log_message("Файл настроек не найден, используются значения по умолчанию.", "status")
            return
        
        profile_name = settings.get("selected_profile")
        profile_names = self.profiles_combobox['values']
        if profile_name in profile_names:
            self.profile_var.set(profile_name)
        
        self.game_filter_var.set(settings.get("game_filter", False))
        self.use_ipset_var.set(settings.get("use_ipset", False))
        self.use_custom_list_var.set(settings.get("use_custom_list", False))
        
        custom_list_path = settings.get("custom_list_path")
        if custom_list_path and os.path.exists(custom_list_path):
            self.list_manager.set_custom_list_path(custom_list_path)
            self.custom_list_path_label.config(text=os.path.basename(custom_list_path), fg="black")
        
        self.list_manager.set_selection_state(settings.get("selected_lists"))
        
        self.on_profile_change()
        
        self.log_message("Настройки успешно загружены.", "success")
        
    def open_custom_list(self):
        try:
            custom_list_path = self.list_manager.get_custom_list_path()
            if not custom_list_path:
                custom_list_path = os.path.join(self.app_dir, 'lists', 'custom_list.txt')
                if not os.path.exists(custom_list_path):
                    with open(custom_list_path, 'w', encoding='utf-8') as f:
                        f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
            os.startfile(custom_list_path)
        except Exception as e:
            self._handle_ui_error(e)

    def on_custom_list_toggle(self):
        """Обработчик переключения чекбокса кастомного списка."""
        if self.use_custom_list_var.get():
            self.select_custom_list_file()
        else:
            self.list_manager.set_custom_list_path(None)
            self.custom_list_path_label.config(text="(не выбран)", fg="gray")

    def select_custom_list_file(self):
        """Открывает диалог выбора файла для кастомного списка."""
        file_path = filedialog.askopenfilename(
            title="Выберите файл со списком доменов",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.list_manager.set_custom_list_path(file_path)
            self.custom_list_path_label.config(text=os.path.basename(file_path), fg="black")
        else:
            self.use_custom_list_var.set(False)
            self.list_manager.set_custom_list_path(None)

    def add_domains_to_list(self, new_domains):
        try:
            log_callback = self.domain_log
            
            custom_list_path = self.list_manager.get_custom_list_path()
            if not custom_list_path:
                custom_list_path = os.path.join(self.app_dir, 'lists', 'custom_list.txt')
                log_callback(f"Кастомный список не выбран, использую стандартный: {custom_list_path}")
            
            existing_domains = set()
            if os.path.exists(custom_list_path):
                log_callback("Читаю существующий список доменов...")
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_domains.add(line)
                log_callback(f"Найдено существующих доменов: {len(existing_domains)}")
            else:
                log_callback("Создаю новый файл списка доменов...")
            
            added_domains = []
            skipped_domains = []
            
            log_callback("Анализирую найденные домены:")
            for domain in new_domains:
                if domain in existing_domains:
                    skipped_domains.append(domain)
                    log_callback(f"  - {domain} (УЖЕ ЕСТЬ В СПИСКЕ)")
                else:
                    added_domains.append(domain)
                    log_callback(f"  + {domain} (НОВЫЙ ДОМЕН)")
            
            if not added_domains:
                log_callback("НОВЫХ ДОМЕНОВ ДЛЯ ДОБАВЛЕНИЯ НЕ НАЙДЕНО")
                if skipped_domains:
                    log_callback(f"Все найденные домены уже существуют в списке ({len(skipped_domains)} шт.)")
                return
            
            log_callback(f"ДОБАВЛЯЮ {len(added_domains)} НОВЫХ ДОМЕНОВ В СПИСОК...")
            
            all_domains = sorted(list(existing_domains.union(set(new_domains))))
            
            with open(custom_list_path, 'w', encoding='utf-8') as f:
                f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
                f.write("# Строки, начинающиеся с #, игнорируются.\n")
                f.write(f"# Обновлено: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#\n")
                for domain in all_domains:
                    f.write(domain + '\n')
            
            log_callback(f"✓ УСПЕШНО ДОБАВЛЕНО {len(added_domains)} НОВЫХ ДОМЕНОВ:")
            for domain in added_domains:
                log_callback(f"  ✓ {domain}")
            
            log_callback(f"✓ ОБЩЕЕ КОЛИЧЕСТВО ДОМЕНОВ В СПИСКЕ: {len(all_domains)}")
            
            self.root.after(0, self._propose_restart_after_domain_update)

        except Exception as e:
            self.domain_log(f"ОШИБКА при добавлении доменов: {e}")
            self._handle_ui_error(e)

    def _propose_restart_after_domain_update(self):
        """Предлагает перезапустить профиль после обновления списка доменов."""
        if process_manager.is_process_running():
            if messagebox.askyesno(
                "Перезапустить профиль?",
                "Новые домены добавлены. Для их применения требуется перезапустить профиль.\n\nСделать это сейчас?"
            ):
                self.domain_log("Перезапускаю профиль для применения новых доменов...")
                self.stop_process()
                self.root.after(1500, self.run_selected_profile)

    def start_domain_analysis(self):
        url = self.domain_url_entry.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL!")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        method_text = self.domain_method_var.get()
        method = self.domain_method_map.get(method_text)
        if not method or method == "none":
            messagebox.showerror("Ошибка", "Выберите доступный метод анализа.")
            return
            
        self.domain_start_btn.config(state=tk.DISABLED, text="⏳ Анализ...")
        
        self.domain_analysis_thread = threading.Thread(target=self.run_domain_analysis_loop, args=(url, method), daemon=True)
        self.domain_analysis_thread.start()

    def run_domain_analysis_loop(self, url, method):
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            self.domain_log(f"=== ПОПЫТКА {attempt}/{max_attempts} ===")
            self.domain_log(f"Анализирую URL: {url}")
            self.domain_log(f"Метод анализа: {method}")
            
            domains = self.run_single_analysis(url, method)
            
            if domains:
                self.domain_log(f"✓ АНАЛИЗ УСПЕШЕН - НАЙДЕНО {len(domains)} ДОМЕН(ОВ)")
                self.domain_log("НАЧИНАЮ ДОБАВЛЕНИЕ В СПИСОК...")
                self.add_domains_to_list(domains)
                
                if "ПРЕДУПРЕЖДЕНИЕ: Страница не загрузилась за 30 секунд" in self.domain_log_text.get('1.0', tk.END):
                    if attempt < max_attempts:
                        self.domain_log("Попытка завершилась по таймауту. Перезапускаю анализ...")
                        continue
                else:
                    self.domain_log("=== АНАЛИЗ УСПЕШНО ЗАВЕРШЕН ===")
                    break
            else:
                self.domain_log("✗ НЕ УДАЛОСЬ ПОЛУЧИТЬ ДОМЕНЫ НА ЭТОЙ ПОПЫТКЕ")
                if attempt < max_attempts:
                    self.domain_log("Перезапускаю анализ...")
                else:
                    self.domain_log("=== АНАЛИЗ НЕ УДАЛСЯ ПОСЛЕ НЕСКОЛЬКИХ ПОПЫТОК ===")

        self.root.after(0, lambda: self.domain_start_btn.config(state=tk.NORMAL, text="🔍 Начать анализ и добавить домены"))

    def run_single_analysis(self, url, method):
        try:
            domains = None
            if method == "performance":
                domains = analyze_site_domains_performance(url, self.domain_log)
            elif method == "playwright":
                domains = analyze_site_domains_playwright(url, self.domain_log)
            elif method == "selenium":
                domains = analyze_site_domains_selenium(url, self.domain_log)
            elif method == "simple":
                domains = analyze_site_domains_simple(url, self.domain_log)
            else:
                self.domain_log("НЕИЗВЕСТНЫЙ МЕТОД")
            return domains
        except Exception as e:
            self.domain_log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
            return None

    def show_domain_url_menu(self, event):
        """Показывает контекстное меню для поля ввода URL."""
        try:
            self.domain_url_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.domain_url_menu.grab_release()

    def paste_domain_url(self):
        """Вставляет текст из буфера обмена в поле ввода URL."""
        try:
            text = self.root.clipboard_get()
            self.domain_url_entry.delete(0, tk.END)
            self.domain_url_entry.insert(0, text)
        except tk.TclError:
            pass

    def show_site_test_url_menu(self, event):
        """Показывает контекстное меню для поля ввода URL теста."""
        try:
            self.site_test_url_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.site_test_url_menu.grab_release()

    def paste_site_test_url(self):
        """Вставляет текст из буфера обмена в поле ввода URL теста."""
        try:
            text = self.root.clipboard_get()
            self.site_test_url_entry.delete(0, tk.END)
            self.site_test_url_entry.insert(0, text)
        except tk.TclError:
            pass

    def install_service(self):
        try:
            profile = self.get_selected_profile()
            if not profile: return
            if messagebox.askyesno("Подтверждение", f"Установить профиль '{profile['name']}' как службу Windows?\n\nЭто позволит обходу запускаться автоматически при старте системы."):
                self.run_in_thread(settings_manager.install_service, self.app_dir, self.log_message, profile)
        except Exception as e:
            self._handle_ui_error(e)

    def uninstall_service(self):
        try:
            if messagebox.askyesno("Подтверждение", "Удалить службу автозапуска Zapret?"):
                self.run_in_thread(settings_manager.uninstall_service, self.app_dir, self.log_message)
        except Exception as e:
            self._handle_ui_error(e)

    def _check_test_running(self):
        if self.test_thread and self.test_thread.is_alive():
            messagebox.showwarning("Внимание", "Тест уже запущен. Дождитесь его окончания.")
            return True
        return False

    def run_site_test(self):
        try:
            if self._check_test_running(): return
            domain = self.site_test_url.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите адрес сайта для теста.")
                return
            
            self.test_thread = threading.Thread(
                target=testing_utils.run_site_test,
                args=(domain, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message),
                daemon=True
            )
            self.test_thread.start()
        except Exception as e:
            self._handle_ui_error(e)

    def run_discord_test(self):
        try:
            if self._check_test_running(): return
            def ask_user_callback(profile_name):
                return messagebox.askyesno(
                    "Интерактивный тест",
                    f"Профиль '{profile_name}' запущен.\n\nDiscord заработал корректно?",
                    icon='question'
                )
            self.test_thread = threading.Thread(
                target=testing_utils.run_discord_test,
                args=(self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, ask_user_callback),
                daemon=True
            )
            self.test_thread.start()
        except Exception as e:
            self._handle_ui_error(e)
            
if __name__ == "__main__":
    if not process_manager.is_admin():
        run_as_admin()
        sys.exit()
    
    root = tk.Tk()
    app = App(root)
    root.mainloop()