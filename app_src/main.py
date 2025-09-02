import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import os
import sys
import threading
import queue
import subprocess
import traceback
import ctypes
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
from executor import update_zapret_tool, is_custom_list_valid
from domain_finder import AnalysisDialog
from text_utils import setup_text_widget_bindings
from list_manager import ListManager
# from version_checker import check_zapret_version # УДАЛЕНО
from profiles import PROFILES
import process_manager
import settings_manager
import testing_utils
class App:
    def __init__(self, root):
        self.root = root
        self.process = None
        self.log_queue = queue.Queue()
        self.app_dir = APP_SOURCE_DIR
        self.profiles = PROFILES
        self.test_thread = None
        self.list_manager = ListManager(self.app_dir)
        self.setup_window()
        self.create_widgets()
        self.populate_profiles_list()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Первоначальная проверка
        self.update_game_filter_checkbox()
    def setup_window(self):
        version_hash = "unknown"
        version_file_path = os.path.join(self.app_dir, ".version_hash")
        if os.path.exists(version_file_path):
            with open(version_file_path, 'r') as f:
                full_hash = f.read().strip()
                if full_hash:
                    version_hash = full_hash[:7]
        self.root.title(f"Zapret Launcher (Commit: {version_hash})")
        self.root.geometry("850x700")
        try:
            icon_path = os.path.join(self.app_dir, 'icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass
    def create_widgets(self):
        # --- ОСНОВНАЯ СТРУКТУРА С ВКЛАДКАМИ ---
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=5)
        tab_control = ttk.Frame(notebook, padding=10)
        tab_tools = ttk.Frame(notebook, padding=10)
        tab_testing = ttk.Frame(notebook, padding=10)
        notebook.add(tab_control, text="Управление")
        notebook.add(tab_tools, text="Инструменты и Настройки")
        notebook.add(tab_testing, text="Тестирование")
        # --- ВКЛАДКА "УПРАВЛЕНИЕ" ---
        self.create_control_tab(tab_control)
        # --- ВКЛАДКА "ИНСТРУМЕНТЫ И НАСТРОЙКИ" ---
        self.create_tools_tab(tab_tools)
        # --- ВКЛАДКА "ТЕСТИРОВАНИЕ" ---
        self.create_testing_tab(tab_testing)
        # --- ОКНО ЛОГОВ ---
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        tk.Label(log_frame, text="Логи:").pack(anchor=tk.W)
        self.log_window = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)
    def create_control_tab(self, parent):
        list_frame = ttk.LabelFrame(parent, text="Профили")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.profiles_listbox = tk.Listbox(list_frame)
        self.profiles_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.profiles_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.profiles_listbox.config(yscrollcommand=scrollbar.set)
        setup_text_widget_bindings(self.profiles_listbox)
        
        # Добавляем интерфейс для выбора списков доменов
        self.list_manager.create_list_selection_ui(parent)
        
        actions_frame = ttk.Frame(parent)
        actions_frame.pack(fill=tk.X, pady=5)
        
        self.run_button = ttk.Button(actions_frame, text="Запустить профиль", command=self.run_selected_profile)
        self.run_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(actions_frame, text="Остановить", command=self.stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        service_frame = ttk.LabelFrame(parent, text="Автозапуск (Системная служба)")
        service_frame.pack(fill=tk.X, pady=10)
        self.install_service_button = ttk.Button(service_frame, text="Установить в автозапуск", command=self.install_service)
        self.install_service_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.uninstall_service_button = ttk.Button(service_frame, text="Удалить из автозапуска", command=self.uninstall_service)
        self.uninstall_service_button.pack(side=tk.LEFT, padx=5, pady=5)
    def create_tools_tab(self, parent):
        general_frame = ttk.LabelFrame(parent, text="Общие инструменты")
        general_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(general_frame, text="Проверить статус", command=self.check_status).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(general_frame, text="Обновить Zapret", command=self.run_zapret_update).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(general_frame, text="Обновить списки IP", command=lambda: self.run_in_thread(settings_manager.update_ipset_list, self.app_dir, self.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        settings_frame = ttk.LabelFrame(parent, text="Настройки")
        settings_frame.pack(fill=tk.X, pady=10)
        
        self.game_filter_var = tk.BooleanVar()
        self.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (для всех профилей)", variable=self.game_filter_var, command=self.toggle_game_filter)
        self.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Добавляем чекбокс для использования IPSet
        self.use_ipset_var = tk.BooleanVar(value=False)  # По умолчанию выключен
        self.use_ipset_check = ttk.Checkbutton(settings_frame, text="Использовать IPSet (дополнительные списки IP)", variable=self.use_ipset_var)
        self.use_ipset_check.pack(anchor=tk.W, padx=5, pady=5)
        
        domain_frame = ttk.LabelFrame(parent, text="Пользовательские списки")
        domain_frame.pack(fill=tk.X, pady=10)
        ttk.Button(domain_frame, text="Добавить домены с сайта...", command=self.open_add_site_dialog).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(domain_frame, text="Открыть custom_list.txt", command=self.open_custom_list).pack(side=tk.LEFT, padx=5, pady=5)
    def create_testing_tab(self, parent):
        site_test_frame = ttk.LabelFrame(parent, text="Автоматический тест по сайту")
        site_test_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(site_test_frame, text="Адрес сайта (например, rutracker.org):").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.site_test_url = tk.StringVar(value="rutracker.org")
        ttk.Entry(site_test_frame, textvariable=self.site_test_url).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(site_test_frame, text="Начать тест по сайту", command=self.run_site_test).pack(pady=5)
        discord_test_frame = ttk.LabelFrame(parent, text="Интерактивный тест для Discord")
        discord_test_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(discord_test_frame, text="Очистить кэш Discord", command=lambda: self.run_in_thread(settings_manager.clear_discord_cache, self.app_dir, self.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(discord_test_frame, text="Начать тест для Discord", command=self.run_discord_test).pack(side=tk.LEFT, padx=5, pady=5)
    def _handle_ui_error(self, e):
        """Централизованный обработчик ошибок для предотвращения падения GUI."""
        error_details = traceback.format_exc()
        self.log_message("\n" + "="*20 + " КРИТИЧЕСКАЯ ОШИБКА GUI " + "="*20)
        self.log_message("Произошла непредвиденная ошибка в интерфейсе:")
        self.log_message(error_details)
        self.log_message("="*62 + "\n")
        messagebox.showerror("Критическая ошибка", f"Произошла ошибка:\n{e}\n\nПодробности записаны в окне логов.")
    def populate_profiles_list(self):
        self.profiles_listbox.delete(0, tk.END)
        for profile in self.profiles:
            self.profiles_listbox.insert(tk.END, profile['name'])
        if self.profiles:
            self.profiles_listbox.select_set(0)
    def get_selected_profile(self):
        selected_indices = self.profiles_listbox.curselection()
        
        if not selected_indices:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите профиль из списка.")
            return None
        
        # ОКОНЧАТЕЛЬНОЕ ИСПРАВЛЕНИЕ: Извлечь первый элемент из кортежа.
        selected_index = int(selected_indices[0])
        return self.profiles[selected_index]
    def run_selected_profile(self):
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
            custom_list_path = os.path.join(self.app_dir, 'lists', 'custom_list.txt')
            use_custom_list = is_custom_list_valid(custom_list_path)
            use_ipset = self.use_ipset_var.get()
            
            # Если включен IPSet, проверяем наличие файла и скачиваем при необходимости
            if use_ipset:
                ipset_path = os.path.join(self.app_dir, 'lists', 'ipset-all.txt')
                if not os.path.exists(ipset_path):
                    self.log_message("Файл ipset-all.txt не найден. Скачиваю...")
                    settings_manager.update_ipset_list(self.app_dir, self.log_message)
            
            # Получаем путь к объединенному списку выбранных доменов
            selected_lists_path = None
            if any(self.list_manager.selected_lists.values()):
                selected_lists_path = self.list_manager.get_combined_list_path()
                self.log_message(f"Используются выбранные списки доменов: {', '.join([name for name, selected in self.list_manager.selected_lists.items() if selected])}")
            else:
                self.log_message("Не выбрано ни одного списка доменов. Будут использованы списки по умолчанию из профиля.")
            
            self.process = process_manager.start_process(profile, self.app_dir, game_filter_enabled, use_custom_list, self.log_message, selected_lists_path, use_ipset)
            
            if not self.process:
                self.log_message("Не удалось запустить процесс. Проверьте логи выше на наличие ошибок.")
                return
                
            self.set_controls_state(tk.DISABLED)
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
        if self.process:
            self.root.after(100, self.monitor_process)
    def process_finished(self):
        return_code = self.process.poll() if self.process else 'N/A'
        self.log_message(f"\nПроцесс завершен с кодом {return_code}.")
        self.set_controls_state(tk.NORMAL)
        self.process = None
    def stop_process(self):
        try:
            self.log_message("\n" + "="*40)
            self.log_message("--- ОСТАНОВКА ПРОЦЕССА ---")
            process_manager.stop_all_processes(self.log_message)
            self.check_status(log_header=False)
            self.set_controls_state(tk.NORMAL)
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
        self.profiles_listbox.config(state=state)
        self.install_service_button.config(state=state)
    def on_closing(self):
        try:
            if self.process and self.process.poll() is None:
                if messagebox.askyesno("Подтверждение", "Процесс еще активен. Остановить его перед выходом?"):
                    self.stop_process()
            self.root.destroy()
        except Exception as e:
            self._handle_ui_error(e)
    def log_message(self, message):
        if self.log_window.winfo_exists():
            self.log_window.config(state='normal')
            self.log_window.insert(tk.END, str(message) + "\n")
            self.log_window.config(state='disabled')
            self.log_window.see(tk.END)
    def run_in_thread(self, target_func, *args):
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()
    def run_zapret_update(self):
        try:
            if messagebox.askyesno("Подтверждение", "Это скачает последнюю версию утилиты Zapret от Flowseal.\n\nВсе активные процессы будут остановлены. Продолжить?"):
                update_thread = threading.Thread(target=update_zapret_tool, args=(self.app_dir, self.log_message), daemon=True)
                update_thread.start()
        except Exception as e:
            self._handle_ui_error(e)
    def update_game_filter_checkbox(self):
        is_enabled = settings_manager.get_game_filter_status(self.app_dir)
        self.game_filter_var.set(is_enabled)
    def toggle_game_filter(self):
        try:
            settings_manager.toggle_game_filter(self.app_dir, self.log_message)
            self.update_game_filter_checkbox()
        except Exception as e:
            self._handle_ui_error(e)
    def open_custom_list(self):
        try:
            list_path = os.path.join(self.app_dir, 'lists', 'custom_list.txt')
            if not os.path.exists(list_path):
                with open(list_path, 'w', encoding='utf-8') as f:
                    f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
            os.startfile(list_path)
        except Exception as e:
            self._handle_ui_error(e)
    def open_add_site_dialog(self):
        try:
            dialog = AnalysisDialog(self.root, title="Анализ сайта для добавления доменов")
            if dialog.result_domains:
                self.add_domains_to_list(dialog.result_domains)
        except Exception as e:
            self._handle_ui_error(e)
    def add_domains_to_list(self, new_domains):
        try:
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
                self.log_message("\n--- Анализ сайта завершен. Новых доменов для добавления не найдено. ---")
                return
            all_domains = sorted(list(existing_domains.union(set(new_domains))))
            with open(custom_list_path, 'w', encoding='utf-8') as f:
                f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
                f.write("# Строки, начинающиеся с #, игнорируются.\n")
                for domain in all_domains:
                    f.write(domain + '\n')
            self.log_message("\n--- Добавлены новые домены в custom_list.txt: ---")
            for domain in sorted(added_domains):
                self.log_message(f"  + {domain}")
            self.log_message("--------------------------------------------------")
        except Exception as e:
            self._handle_ui_error(e)
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