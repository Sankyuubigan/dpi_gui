import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import sys
import threading
import queue
import subprocess
import traceback
import logging
import time
import datetime
import ctypes

# Глобальный обработчик ошибок
def global_exception_handler(exc_type, exc_value, exc_traceback):
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(error_msg, file=sys.stderr) # Пишем в stderr, который ловит лаунчер
    with open("crash_report.txt", "a", encoding="utf-8") as f:
        f.write(f"\n--- CRASH {datetime.datetime.now()} ---\n")
        f.write(error_msg)
    try:
        messagebox.showerror("Critical Error", f"Application crashed:\n{exc_value}")
    except: pass

sys.excepthook = global_exception_handler

APP_SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_SOURCE_DIR)

try:
    from executor import is_custom_list_valid
    from list_manager import ListManager
    from profiles import PROFILES
    import process_manager
    import settings_manager
    import testing_utils
    import power_handler
    from ui_manager import UIManager
    from domain_manager import DomainManager
except Exception as e:
    # Ошибка импорта
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)

def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        messagebox.showerror("Ошибка запуска", f"Не удалось перезапустить с правами администратора:\n{e}")

class App:
    def __init__(self, root):
        self.root = root
        
        # Словарь активных процессов теперь будет содержать только один элемент при общем запуске
        self.active_processes = {}
        self.log_queue = queue.Queue()
        
        self.app_dir = APP_SOURCE_DIR
        self.profiles = PROFILES
        self.test_thread = None
        
        self.list_manager = ListManager(self.app_dir)
        self.ui_manager = UIManager(self)
        self.domain_manager = DomainManager(self)
        self.settings_manager = settings_manager
        
        os.makedirs("roo_tests", exist_ok=True)
        self.status_logger = logging.getLogger("status_indicators")
        handler = logging.FileHandler("roo_tests/status_runtime.log")
        formatter = logging.Formatter("%(asctime)s - %(message)s")
        handler.setFormatter(formatter)
        self.status_logger.addHandler(handler)
        self.status_logger.setLevel(logging.INFO)

        self.setup_window()
        self.create_widgets()
        self.load_app_settings()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        power_handler.setup_power_handler(self)
        self.run_in_thread(self.log_queue_monitor)

    def setup_window(self):
        self.ui_manager.setup_window()

    def create_widgets(self):
        self.ui_manager.create_widgets()

    def log_message(self, message, log_type="main"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = ""
        if log_type == "domain": prefix = "[ДОМЕНЫ] "
        elif log_type == "status": prefix = "[СТАТУС] "
        elif log_type == "error": prefix = "[ОШИБКА] "
        elif log_type == "success": prefix = "[УСПЕХ] "
        
        formatted_message = f"[{timestamp}] {prefix}{message}"
        log_entry = {"text": formatted_message, "type": log_type, "timestamp": timestamp}
        self.root.after(0, lambda: self._append_log(log_entry))

    def _append_log(self, log_entry):
        self.ui_manager.all_logs.append(log_entry)
        self.ui_manager.update_log_display()

    def run_in_thread(self, target_func, *args):
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()

    def run_all_configured(self):
        """Запускает ОДИН процесс для всех списков."""
        if self.active_processes:
            if not messagebox.askyesno("Перезапуск", "Процесс уже запущен. Перезапустить?"):
                return
            self.stop_process()
            time.sleep(1)

        self.log_message("=== ЗАПУСК ЕДИНОГО ПРОЦЕССА ===", "status")
        
        prof_mapping = self.list_manager.get_mapping()
        ipset_mapping = self.list_manager.get_ipset_mapping()
        available_lists = self.list_manager.get_available_files()
        
        configs_to_run = [] # Список кортежей (путь, профиль, путь_к_ipset)
        active_list_names = []
        
        for list_filename in available_lists:
            profile_name = prof_mapping.get(list_filename, "ОТКЛЮЧЕНО")
            
            if profile_name == "ОТКЛЮЧЕНО" or not profile_name:
                continue
                
            profile_obj = next((p for p in self.profiles if p['name'] == profile_name), None)
            if not profile_obj:
                self.log_message(f"Ошибка: Профиль '{profile_name}' не найден!", "error")
                continue
            
            full_list_path = os.path.join(self.app_dir, 'lists', list_filename)
            if not os.path.exists(full_list_path):
                self.log_message(f"Файл не найден: {list_filename}", "error")
                continue
            
            # Получаем IPSet для конкретного списка
            ipset_setting = ipset_mapping.get(list_filename, "OFF")
            ipset_path = None
            if ipset_setting and ipset_setting != "OFF":
                potential_path = os.path.join(self.app_dir, 'ipsets', ipset_setting)
                if os.path.exists(potential_path):
                    ipset_path = potential_path
                else:
                    self.log_message(f"Предупреждение: IPSet файл '{ipset_setting}' не найден для списка {list_filename}", "error")

            configs_to_run.append((full_list_path, profile_obj, ipset_path))
            active_list_names.append(list_filename)

        if not configs_to_run:
            self.log_message("Нет активных конфигураций для запуска.", "status")
            return

        # Запуск
        try:
            game_filter_enabled = self.game_filter_var.get()
            
            process = process_manager.start_combined_process(
                configs_to_run, self.app_dir, game_filter_enabled, 
                self.log_message
            )
            
            if process:
                pid = process.pid
                self.active_processes[pid] = {
                    'proc': process,
                    'lists': active_list_names
                }
                
                self.log_message(f"Процесс запущен (PID: {pid}). Активные списки: {len(active_list_names)}", "success")
                
                # ОБНОВЛЯЕМ СОСТОЯНИЕ КНОПОК
                self.ui_manager.update_buttons_state(True)
                
                threading.Thread(target=self.read_process_output, args=(process, "winws"), daemon=True).start()
                threading.Thread(target=self.wait_for_process_exit, args=(pid,), daemon=True).start()
                
                # Обновляем UI для всех активных списков
                for lname in active_list_names:
                    self.ui_manager.update_process_status_in_table(lname, True, pid)
                    
        except Exception as e:
            self.log_message(f"Ошибка запуска: {e}", "error")

    def read_process_output(self, process, prefix):
        try:
            for line in iter(process.stdout.readline, ''):
                if line:
                    self.log_queue.put(f"[{prefix}] {line.strip()}")
        except: pass

    def wait_for_process_exit(self, pid):
        if pid in self.active_processes:
            proc = self.active_processes[pid]['proc']
            try: proc.wait()
            except: pass
            self.root.after(0, lambda: self._cleanup_process(pid))

    def _cleanup_process(self, pid):
        if pid in self.active_processes:
            data = self.active_processes[pid]
            active_lists = data['lists']
            del self.active_processes[pid]
            
            for lname in active_lists:
                self.ui_manager.update_process_status_in_table(lname, False, None)
            
            self.log_message(f"Процесс остановлен (PID: {pid})", "status")
            
            # Если процессов больше нет (а он у нас всего один), обновляем кнопки
            if not self.active_processes:
                self.ui_manager.update_buttons_state(False)

    def log_queue_monitor(self):
        while True:
            try:
                msg = self.log_queue.get()
                self.log_message(msg, "main")
            except:
                time.sleep(0.1)

    def stop_process(self):
        """Останавливает все процессы"""
        self.log_message("Остановка...", "status")
        
        pids = list(self.active_processes.keys())
        for pid in pids:
            if pid in self.active_processes:
                proc = self.active_processes[pid]['proc']
                process_manager.kill_process(proc)
        
        process_manager.stop_all_processes(self.log_message)
        self.active_processes.clear()
        
        # Сброс статусов в таблице
        self.ui_manager.refresh_lists_table()
        
        # Обновляем кнопки
        self.ui_manager.update_buttons_state(False)

    def check_status(self, log_header=True):
        try:
            settings_manager.check_status(self.app_dir, self.log_message, log_header)
        except Exception as e:
            self._handle_ui_error(e)

    def trigger_update(self):
        """Перезапускает лаунчер с флагом обновления"""
        if messagebox.askyesno("Обновление", "Приложение будет закрыто для проверки и установки обновлений.\nПродолжить?"):
            try:
                self.save_app_settings()
                self.stop_process()
                
                launcher_path = os.environ.get("LAUNCHER_PATH")
                if not launcher_path or not os.path.exists(launcher_path):
                    # Пытаемся угадать, если запускаем из IDE
                    potential_path = os.path.join(os.path.dirname(self.app_dir), "launcher.py")
                    if os.path.exists(potential_path):
                        # Запуск python скрипта
                        subprocess.Popen([sys.executable, potential_path, "--update"], cwd=os.path.dirname(self.app_dir))
                    else:
                        # Пытаемся найти exe рядом
                        potential_exe = os.path.join(os.path.dirname(self.app_dir), "dpi_gui_launcher.exe")
                        if os.path.exists(potential_exe):
                            subprocess.Popen([potential_exe, "--update"], cwd=os.path.dirname(self.app_dir))
                        else:
                            messagebox.showerror("Ошибка", "Не удалось найти файл лаунчера для перезапуска.")
                            return
                else:
                    # Запуск exe
                    subprocess.Popen([launcher_path, "--update"], cwd=os.path.dirname(launcher_path))
                
                self.root.quit()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось запустить обновление:\n{e}")

    def on_closing(self):
        try:
            self.save_app_settings()
            if self.active_processes:
                if messagebox.askyesno("Выход", "Остановить процесс обхода перед выходом?"):
                    self.stop_process()
            self.root.destroy()
        except Exception as e:
            self.root.destroy()

    def _handle_ui_error(self, e):
        error_details = traceback.format_exc()
        self.log_message(error_details, "error")
        messagebox.showerror("Ошибка", f"Произошла ошибка:\n{e}")

    def save_app_settings(self):
        settings_data = {
            "game_filter": self.game_filter_var.get(),
            "list_profile_map": self.list_manager.get_mapping(),
            "list_ipset_map": self.list_manager.get_ipset_mapping()
        }
        settings_manager.save_app_settings(settings_data, self.app_dir)
        self.log_message("Настройки сохранены.", "success")

    def load_app_settings(self):
        settings = settings_manager.load_app_settings(self.app_dir)
        
        self.game_filter_var.set(settings.get("game_filter", False))
        
        self.list_manager.set_mappings(
            settings.get("list_profile_map", {}),
            settings.get("list_ipset_map", {})
        )
        
        self.ui_manager.refresh_lists_table()
        self.log_message("Настройки загружены.", "success")
        
    def open_custom_list(self):
        try:
            path = self.list_manager.get_custom_list_path()
            if not os.path.exists(path):
                with open(path, 'w', encoding='utf-8') as f: f.write("# Custom list\n")
            os.startfile(path)
        except Exception as e:
            self._handle_ui_error(e)
            
    def paste_site_test_url(self):
        try:
            text = self.root.clipboard_get()
            self.site_test_url_entry.delete(0, tk.END)
            self.site_test_url_entry.insert(0, text)
        except: pass
    
    def show_site_test_url_menu(self, event):
        self.site_test_url_menu.tk_popup(event.x_root, event.y_root)

    def run_site_test(self):
        domain = self.site_test_url.get()
        self.run_in_thread(testing_utils.run_site_test, domain, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message)

    def run_discord_test(self):
        def ask(name): return messagebox.askyesno("Тест", f"Работает ли Discord с профилем {name}?")
        self.run_in_thread(testing_utils.run_discord_test, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, ask)

if __name__ == "__main__":
    if not process_manager.is_admin():
        run_as_admin()
        sys.exit()
    root = tk.Tk()
    app = App(root)
    root.mainloop()