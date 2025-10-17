import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import threading
import queue
import subprocess
import traceback
import ctypes
import logging
import datetime
import win32con
import win32api
# --- Начальная настройка и проверка прав ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        messagebox.showerror("Ошибка запуска", f"Не удалось перезапустить с правами администратора:\n{e}")
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

class PowerEventHandler:
    """Класс для обработки событий питания (спящий/гибернация режим)"""
    def __init__(self, app_instance):
        self.app = app_instance
        
    def handle_power_event(self, hwnd, msg, wparam, lparam):
        """Обработчик событий питания"""
        if msg == win32con.WM_POWERBROADCAST:
            if wparam == win32con.PBT_APMRESUMEAUTOMATIC:
                # Система вышла из спящего режима
                if process_manager.is_process_running():
                    self.app.log_message("\n[СИСТЕМА] Обнаружен выход из спящего режима")
                    # Запускаем перезапуск в отдельном потоке
                    threading.Thread(target=self._restart_after_sleep, daemon=True).start()
        return True
        
    def _restart_after_sleep(self):
        """Перезапускает процесс после выхода из спящего режима"""
        time.sleep(3)  # Даем системе время на инициализацию сети
        new_process = process_manager.restart_process()
        if new_process:
            self.app.process = new_process
            self.app.worker_thread = threading.Thread(target=self.app.read_process_output, daemon=True)
            self.app.worker_thread.start()
            self.app.monitor_process()
            self.app.log_message("[СИСТЕМА] Профиль успешно перезапущен после выхода из спящего режима")
        else:
            self.app.log_message("[СИСТЕМА] ОШИБКА: Не удалось перезапустить профиль")

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
        self.setup_power_handler()
        
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
            
    def setup_power_handler(self):
        """Устанавливает обработчик событий питания"""
        try:
            # Создаем скрытое окно для получения сообщений системы
            self.hwnd = win32api.CreateWindowEx(
                0, "STATIC", "PowerHandler", 0, 0, 0, 0, 0, 0, 0, 0, None
            )
            
            # Регистрируем обработчик сообщений о питании
            self.power_handler = PowerEventHandler(self)
            win32api.SetWindowLong(self.hwnd, win32con.GWL_WNDPROC, self.power_handler.handle_power_event)
            
            # Регистрируем получение сообщений о питании
            win32api.RegisterPowerSettingNotification(
                self.hwnd, 
                win32api.GUID_SYSTEM_AWAYMODE, 
                win32con.DEVICE_NOTIFY_WINDOW_HANDLE
            )
            
            self.log_message("[СИСТЕМА] Обработчик событий питания успешно установлен")
        except Exception as e:
            self.log_message(f"[СИСТЕМА] Предупреждение: Не удалось установить обработчик событий питания: {e}")
            self.log_message("[СИСТЕМА] Автоматический перезапуск после спящего режима будет недоступен")

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=5)
        tab_control = ttk.Frame(notebook, padding=10)
        tab_tools = ttk.Frame(notebook, padding=10)
        tab_testing = ttk.Frame(notebook, padding=10)
        tab_domains = ttk.Frame(notebook, padding=10)
        notebook.add(tab_control, text="Управление")
        notebook.add(tab_tools, text="Инструменты и Настройки")
        notebook.add(tab_testing, text="Тестирование")
        notebook.add(tab_domains, text="Домены")
        
        self.create_control_tab(tab_control)
        self.create_tools_tab(tab_tools)
        self.create_testing_tab(tab_testing)
        self.create_domains_tab(tab_domains)
        
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        tk.Label(log_frame, text="Логи:").pack(anchor=tk.W)
        self.log_window = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)

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
        self.domain_url_entry.bind("<Control-v>", lambda e: self.paste_domain_url()) # Привязка Ctrl+V
        
        # Кнопка анализа
        self.domain_start_btn = ttk.Button(parent, text="🔍 Начать анализ и добавить домены", command=self.start_domain_analysis, state=tk.DISABLED)
        self.domain_start_btn.pack(pady=10)

        # Лог
        log_frame = ttk.LabelFrame(parent, text="Лог анализа доменов")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.domain_log_text = scrolledtext.ScrolledText(log_frame, height=15, bg='black', fg='white', state=tk.DISABLED)
        self.domain_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.domain_log_text)

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
        self.site_test_url_entry.bind("<Control-v>", lambda e: self.paste_site_test_url()) # Привязка Ctrl+V

        ttk.Button(site_test_frame, text="Начать тест по сайту", command=self.run_site_test).pack(pady=5)
        discord_test_frame = ttk.LabelFrame(parent, text="Интерактивный тест для Discord")
        discord_test_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(discord_test_frame, text="Очистить кэш Discord", command=lambda: self.run_in_thread(settings_manager.clear_discord_cache, self.app_dir, self.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(discord_test_frame, text="Начать тест для Discord", command=self.run_discord_test).pack(side=tk.LEFT, padx=5, pady=5)

    def _handle_ui_error(self, e):
        error_details = traceback.format_exc()
        self.log_message("\n" + "="*20 + " КРИТИЧЕСКАЯ ОШИБКА GUI " + "="*20)
        self.log_message("Произошла непредвиденная ошибка в интерфейсе:")
        self.log_message(error_details)
        self.log_message("="*62 + "\n")
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
            self.log_message(f"Выбран профиль: {profile['name']}. Обязательные списки: {required_lists}")

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
            self.domain_start_btn.config(state=tk.DISABLED)

    def run_selected_profile(self):
        print("!!! ДИАГНОСТИКА: ВЫПОЛНЯЕТСЯ НОВАЯ ВЕРСИЯ RUN_SELECTED_PROFILE !!!")
        try:
            if self.process and self.process.poll() is None:
                messagebox.showinfo("Информация", "Процесс уже запущен.")
                return
            
            profile = self.get_selected_profile()
            if not profile: return
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            self.log_window.config(state='disabled')
            
            process_manager.stop_all_processes(self.log_message)
            self.log_message(f"Запуск профиля: {profile['name']}")
            game_filter_enabled = self.game_filter_var.get()
            use_ipset = self.use_ipset_var.get()
            
            if use_ipset and not os.path.exists(os.path.join(self.app_dir, 'lists', 'ipset-all.txt')):
                self.log_message("ВНИМАНИЕ: ipset-all.txt не найден. Запустите обновление вручную в `launcher.py` или скачайте его.")

            custom_list_path = None
            if self.use_custom_list_var.get():
                custom_list_path = self.list_manager.get_custom_list_path()
                self.log_message(f"--- [Main] Использование кастомного списка ВКЛЮЧЕНО. Путь: {custom_list_path} ---")
                if not custom_list_path or not os.path.exists(custom_list_path):
                    messagebox.showwarning("Предупреждение", "Кастомный список не выбран или файл не существует.")
                    return
            else:
                self.log_message("--- [Main] Использование кастомного списка ВЫКЛЮЧЕНО ---")

            # Передаем log_callback в get_combined_list_path для детального логирования
            combined_list_path = self.list_manager.get_combined_list_path(custom_list_path, self.log_message)
            
            if combined_list_path:
                 self.log_message(f"--- [Main] Объединенный список для запуска: {combined_list_path} ---")
            else:
                 self.log_message("--- [Main] ВНИМАНИЕ: Объединенный список не был создан (пуст или не выбран). Обход будет работать без списков доменов. ---")

            self.process = process_manager.start_process(
                profile, self.app_dir, game_filter_enabled, 
                self.log_message, combined_list_path, use_ipset
            )
            
            if not self.process:
                self.log_message("Не удалось запустить процесс. Проверьте логи выше на наличие ошибок.")
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
        try:
            line = self.log_queue.get_nowait()
            if line is None:
                self.process_finished()
                return
            self.log_message(line.strip())
        except queue.Empty:
            pass
        if self.process and self.process.poll() is None:
            self.root.after(100, self.monitor_process)
        elif self.process:
            self.process_finished()

    def process_finished(self):
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"\nПроцесс завершен с кодом {return_code}.")
        self.set_controls_state(tk.NORMAL)
        self.update_status_indicator(False)
        self.process = None

    def stop_process(self):
        try:
            self.log_message("\n" + "="*40)
            self.log_message("--- ОСТАНОВКА ПРОЦЕССА ---")
            process_manager.stop_all_processes(self.log_message)
            self.check_status(log_header=False)
            self.set_controls_state(tk.NORMAL)
            self.update_status_indicator(False)
            if self.process:
                self.process = None
        except Exception as e:
            self._handle_ui_error(e)

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
                # Если choice == 'cancel' или None, ничего не делаем
            else:
                self.root.destroy()
        except Exception as e:
            self._handle_ui_error(e)

    def _ask_to_stop_on_close(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Подтверждение выхода")
        dialog.geometry("350x120")
        dialog.resizable(False, False)
        
        # Делаем окно модальным
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Переменная для хранения результата
        result = {'choice': None}

        # Сообщение
        message = "Процесс еще активен. Остановить его перед выходом?"
        tk.Label(dialog, text=message, wraplength=300).pack(pady=10)

        # Фрейм для кнопок
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
        
        # Центрируем диалог относительно главного окна
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Ждем закрытия диалога
        self.root.wait_window(dialog)
        
        return result['choice']

    def log_message(self, message):
        if self.log_window.winfo_exists():
            self.log_window.config(state='normal')
            self.log_window.insert(tk.END, str(message) + "\n")
            self.log_window.config(state='disabled')
            self.log_window.see(tk.END)

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
        self.log_message("Настройки сохранены.")

    def load_app_settings(self):
        settings = settings_manager.load_app_settings(self.app_dir)
        if not settings:
            self.log_message("Файл настроек не найден, используются значения по умолчанию.")
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
        
        # Вызываем обработчик смены профиля, чтобы применить обязательные списки
        self.on_profile_change()
        
        self.log_message("Настройки успешно загружены.")
        
    def open_custom_list(self):
        try:
            custom_list_path = self.list_manager.get_custom_list_path()
            if not custom_list_path:
                # Если кастомный список не выбран, используем стандартный
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
            custom_list_path = self.list_manager.get_custom_list_path()
            if not custom_list_path:
                custom_list_path = os.path.join(self.app_dir, 'lists', 'custom_list.txt')
            
            existing_domains = set()
            if os.path.exists(custom_list_path):
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_domains.add(line)
            added_domains = [d for d in new_domains if d not in existing_domains]
            if not added_domains:
                self.domain_log("Новых доменов для добавления не найдено.")
                return
            
            all_domains = sorted(list(existing_domains.union(set(new_domains))))
            with open(custom_list_path, 'w', encoding='utf-8') as f:
                f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
                f.write("# Строки, начинающиеся с #, игнорируются.\n")
                for domain in all_domains:
                    f.write(domain + '\n')
            
            self.domain_log(f"Автоматически добавлено {len(added_domains)} новых доменов в кастомный список.")
            for domain in sorted(added_domains):
                self.domain_log(f"  + {domain}")
            
            # Предлагаем перезапустить профиль, если он активен
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
                # Даем время на полную остановку процесса перед запуском
                self.root.after(1500, self.run_selected_profile)

    def domain_log(self, message):
        def _log():
            self.domain_log_text.config(state=tk.NORMAL)
            self.domain_log_text.insert(tk.END, message + "\n")
            self.domain_log_text.config(state=tk.DISABLED)
            self.domain_log_text.see(tk.END)
        if self.domain_log_text.winfo_exists():
            self.root.after(0, _log)

    def start_domain_analysis(self):
        if not process_manager.is_process_running():
            messagebox.showerror("Ошибка", "Сначала запустите профиль на вкладке 'Управление'.")
            return

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
        self.domain_log_text.config(state='normal')
        self.domain_log_text.delete('1.0', tk.END)
        self.domain_log_text.config(state='disabled')
        
        self.domain_analysis_thread = threading.Thread(target=self.run_domain_analysis_loop, args=(url, method), daemon=True)
        self.domain_analysis_thread.start()

    def run_domain_analysis_loop(self, url, method):
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            self.domain_log(f"=== ПОПЫТКА {attempt}/{max_attempts} ===")
            domains = self.run_single_analysis(url, method)
            
            if domains:
                self.domain_log(f"Найдено {len(domains)} доменов. Добавляю в список...")
                self.add_domains_to_list(domains)
                # Проверяем, был ли таймаут
                if "ПРЕДУПРЕЖДЕНИЕ: Страница не загрузилась за 30 секунд" in self.domain_log_text.get('1.0', tk.END):
                    if attempt < max_attempts:
                        self.domain_log("Попытка завершилась по таймауту. Перезапускаю анализ...")
                        continue
                else:
                    # Успешное завершение без таймаута
                    self.domain_log("=== АНАЛИЗ УСПЕШНО ЗАВЕРШЕН ===")
                    break
            else:
                self.domain_log("Не удалось получить домены на этой попытке.")
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
            # Буфер обмена пуст или содержит не текстовые данные
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
            # Буфер обмена пуст или содержит не текстовые данные
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
    if not is_admin():
        run_as_admin()
        sys.exit()
    
    root = tk.Tk()
    app = App(root)
    root.mainloop()