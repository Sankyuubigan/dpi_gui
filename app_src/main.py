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

APP_SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_SOURCE_DIR)

# Глобальная переменная для доступа к приложению из обработчиков ошибок
app_instance = None

# --- ГЛОБАЛЬНАЯ ОБРАБОТКА ОШИБОК ---
def log_crash_to_file(error_msg):
    """Пишет ошибку в файл crash_report.txt"""
    try:
        with open("crash_report.txt", "a", encoding="utf-8") as f:
            f.write(f"\n--- CRASH {datetime.datetime.now()} ---\n")
            f.write(error_msg + "\n")
    except: pass

def handle_exception(exc_type, exc_value, exc_traceback):
    """Обработчик для основного потока"""
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(error_msg, file=sys.stderr) # В консоль
    log_crash_to_file(error_msg)      # В файл
    
    # Пытаемся вывести в GUI лог
    if app_instance:
        app_instance.root.after(0, lambda: app_instance.log_message(f"КРИТИЧЕСКАЯ ОШИБКА:\n{exc_value}", "error"))
    
    # Показываем окно
    try:
        messagebox.showerror("Critical Error", f"Application crashed:\n{exc_value}\n\nSee crash_report.txt")
    except: pass

def handle_thread_exception(args):
    """Обработчик для фоновых потоков (threading)"""
    error_msg = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    print(error_msg, file=sys.stderr) # В консоль
    log_crash_to_file(error_msg)      # В файл
    
    # Пытаемся вывести в GUI лог
    if app_instance:
        # Используем after, так как мы в другом потоке
        app_instance.root.after(0, lambda: app_instance.log_message(f"ОШИБКА В ПОТОКЕ:\n{args.exc_value}", "error"))
        app_instance.root.after(0, lambda: messagebox.showerror("Thread Error", f"Error in background thread:\n{args.exc_value}"))

# Назначаем хуки
sys.excepthook = handle_exception
threading.excepthook = handle_thread_exception

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
    from batch_gen import get_update_bat_content
except Exception as e:
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)

def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        messagebox.showerror("Ошибка запуска", f"Не удалось перезапустить с правами администратора:\n{e}")

class App:
    def __init__(self, root):
        global app_instance
        app_instance = self # Сохраняем ссылку для глобальных обработчиков
        
        self.root = root
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
        self.create_update_script()
        self.check_admin_status_log()

    def check_admin_status_log(self):
        is_admin = process_manager.is_admin()
        status_msg = "ЕСТЬ (АКТИВЕН)" if is_admin else "НЕТ (ОГРАНИЧЕН)"
        log_type = "success" if is_admin else "error"
        self.root.after(500, lambda: self.log_message(f"=== ПРАВА АДМИНИСТРАТОРА: {status_msg} ===", log_type))
        if not is_admin:
            self.root.after(600, lambda: self.log_message("ВНИМАНИЕ: Без прав админа сканирование процессов (Telegram/Игры) работать НЕ БУДЕТ!", "error"))

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
        if self.active_processes:
            if not messagebox.askyesno("Перезапуск", "Процесс уже запущен. Перезапустить?"):
                return
            self.stop_process()
            time.sleep(1)

        self.log_message("=== ЗАПУСК ЕДИНОГО ПРОЦЕССА ===", "status")
        
        prof_mapping = self.list_manager.get_mapping()
        ipset_mapping = self.list_manager.get_ipset_mapping()
        available_lists = self.list_manager.get_available_files()
        
        configs_to_run = []
        active_list_names = []
        
        for list_identifier in available_lists:
            profile_name = prof_mapping.get(list_identifier, "ОТКЛЮЧЕНО")
            
            if profile_name == "ОТКЛЮЧЕНО" or not profile_name:
                continue
                
            profile_obj = next((p for p in self.profiles if p['name'] == profile_name), None)
            if not profile_obj:
                self.log_message(f"Ошибка: Профиль '{profile_name}' не найден для {list_identifier}!", "error")
                continue
            
            full_list_path = self.list_manager.get_full_path(list_identifier)
            if not full_list_path or not os.path.exists(full_list_path):
                self.log_message(f"Файл не найден: {full_list_path}", "error")
                continue
            
            ipset_setting = ipset_mapping.get(list_identifier, "OFF")
            ipset_path = None
            if ipset_setting and ipset_setting != "OFF":
                potential_path = os.path.join(self.app_dir, 'ipsets', ipset_setting)
                if os.path.exists(potential_path):
                    ipset_path = potential_path
                else:
                    self.log_message(f"Предупреждение: IPSet файл '{ipset_setting}' не найден для списка {list_identifier}", "error")

            configs_to_run.append((full_list_path, profile_obj, ipset_path))
            active_list_names.append(list_identifier)

        if not configs_to_run:
            self.log_message("Нет активных конфигураций для запуска.", "status")
            return

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
                self.ui_manager.update_buttons_state(True)
                
                threading.Thread(target=self.read_process_output, args=(process, "winws"), daemon=True).start()
                threading.Thread(target=self.wait_for_process_exit, args=(pid,), daemon=True).start()
                
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
        self.log_message("Остановка...", "status")
        pids = list(self.active_processes.keys())
        for pid in pids:
            if pid in self.active_processes:
                proc = self.active_processes[pid]['proc']
                process_manager.kill_process(proc)
        process_manager.stop_all_processes(self.log_message)
        self.active_processes.clear()
        self.ui_manager.refresh_lists_table()
        self.ui_manager.update_buttons_state(False)

    def check_status(self, log_header=True):
        try:
            settings_manager.check_status(self.app_dir, self.log_message, log_header)
        except Exception as e:
            self._handle_ui_error(e)

    def create_update_script(self):
        try:
            base_dir = os.path.dirname(self.app_dir)
            bat_path = os.path.join(base_dir, "update.bat")
            if getattr(sys, 'frozen', False):
                current_exe_name = os.path.basename(sys.executable)
            else:
                current_exe_name = "dpi_gui_launcher.exe"

            bat_content = get_update_bat_content(exe_name=current_exe_name)
            
            with open(bat_path, "w", encoding="utf-8") as f:
                f.write(bat_content)
        except Exception as e:
            print(f"Failed to create update.bat: {e}")

    def trigger_update(self):
        if messagebox.askyesno("Обновление", "Приложение будет закрыто для проверки и установки обновлений.\nПродолжить?"):
            try:
                self.save_app_settings()
                self.stop_process()
                self.create_update_script()
                
                base_dir = os.path.dirname(self.app_dir)
                bat_path = os.path.join(base_dir, "update.bat")
                
                if os.path.exists(bat_path):
                    # ИСПРАВЛЕНИЕ: Запускаем батник через EXPLORER.EXE.
                    # Это полностью разрывает связь с текущим процессом (и его переменными среды).
                    # Эффект точно такой же, как если бы пользователь кликнул дважды мышкой.
                    subprocess.Popen(['explorer.exe', bat_path])
                    
                    self.root.quit()
                else:
                    messagebox.showerror("Ошибка", "Файл update.bat не найден.")
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
            "list_ipset_map": self.list_manager.get_ipset_mapping(),
            "custom_list_path": self.list_manager.get_custom_list_path()
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
        custom_path = settings.get("custom_list_path", "")
        self.list_manager.set_custom_list_path(custom_path)
        self.ui_manager.refresh_lists_table()
        self.ui_manager.update_custom_list_label()
        self.log_message("Настройки загружены.", "success")
        
    def open_custom_list(self):
        try:
            path = self.list_manager.get_custom_list_path()
            if not path:
                messagebox.showwarning("Внимание", "Файл кастомного списка не выбран.\nУкажите его в настройках.")
                return
            if not os.path.exists(path):
                if messagebox.askyesno("Файл не найден", f"Файл не найден:\n{path}\n\nСоздать его?"):
                    try:
                        with open(path, 'w', encoding='utf-8') as f: f.write("# Custom list\n")
                    except Exception as e:
                        messagebox.showerror("Ошибка", f"Не удалось создать файл: {e}")
                        return
                else:
                    return
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
        custom_list = self.list_manager.get_custom_list_path()
        self.run_in_thread(testing_utils.run_site_test, domain, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, custom_list)

    def run_discord_test(self):
        def ask(name): return messagebox.askyesno("Тест", f"Работает ли Discord с профилем {name}?")
        custom_list = self.list_manager.get_custom_list_path()
        self.run_in_thread(testing_utils.run_discord_test, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, ask, custom_list)

if __name__ == "__main__":
    if not process_manager.is_admin():
        run_as_admin()
        sys.exit()
    root = tk.Tk()
    app = App(root)
    root.mainloop()