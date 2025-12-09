import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import threading
import queue
import datetime
import time
import ctypes
import traceback
import logging

# Глобальный обработчик ошибок
def global_exception_handler(exc_type, exc_value, exc_traceback):
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(error_msg, file=sys.stderr)
    with open("crash_report.txt", "a", encoding="utf-8") as f:
        f.write(f"\n--- CRASH {datetime.datetime.now()} ---\n")
        f.write(error_msg)
    try: messagebox.showerror("Critical Error", f"Application crashed:\n{exc_value}")
    except: pass
sys.excepthook = global_exception_handler

APP_SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_SOURCE_DIR)

try:
    from list_manager import ListManager
    from profiles import PROFILES
    import process_manager
    import settings_manager
    import testing_utils
    import power_handler
    from ui_manager import UIManager
    from domain_manager import DomainManager
except Exception as e:
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)

def run_as_admin():
    try: ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e: messagebox.showerror("Ошибка запуска", f"Не удалось перезапустить с правами администратора:\n{e}")

class App:
    def __init__(self, root):
        self.root = root
        self.active_processes = {}
        self.log_queue = queue.Queue()
        self.app_dir = APP_SOURCE_DIR
        self.profiles = PROFILES
        
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
        
        # === ПРОВЕРКА АДМИНА И ЗАПИСЬ В ЛОГ ===
        if process_manager.is_admin():
            self.log_message("Режим администратора: АКТИВЕН", "success")
        else:
            self.log_message("Режим администратора: НЕ АКТИВЕН (Требуется перезапуск)", "error")
        # ======================================

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        power_handler.setup_power_handler(self)
        self.run_in_thread(self.log_queue_monitor)

    def setup_window(self): self.ui_manager.setup_window()
    def create_widgets(self): self.ui_manager.create_widgets()

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
        """Запускает процессы на основе списка правил."""
        if self.active_processes:
            if not messagebox.askyesno("Перезапуск", "Процессы уже запущены. Перезапустить?"): return
            self.stop_process()
            time.sleep(1)

        self.log_message("=== ЗАПУСК ПО ПРАВИЛАМ ===", "status")
        
        rules = self.list_manager.get_rules()
        available_resources = self.list_manager.get_all_resources()
        
        configs_to_run = [] 
        active_rule_indices = []
        
        for idx, rule in enumerate(rules):
            filename = rule.get("file")
            profile_name = rule.get("profile")
            
            if not filename or not profile_name: continue
            
            # Если профиль "Отключено", пропускаем правило
            if profile_name == "Отключено":
                continue

            full_path = None
            is_ipset = (rule.get("type") == "ipset")
            
            for res in available_resources:
                if res["filename"] == filename:
                    full_path = res["path"]
                    is_ipset = (res["type"] == "ipset")
                    break
            
            if not full_path:
                if os.path.exists(filename): full_path = filename
            
            if not full_path or not os.path.exists(full_path):
                self.log_message(f"Правило #{idx+1}: Файл не найден ({filename})", "error")
                continue

            profile_obj = next((p for p in self.profiles if p['name'] == profile_name), None)
            if not profile_obj:
                self.log_message(f"Правило #{idx+1}: Профиль '{profile_name}' не найден", "error")
                continue
                
            configs_to_run.append({
                "path": full_path,
                "profile": profile_obj,
                "type": "ipset" if is_ipset else "list"
            })
            active_rule_indices.append(idx)

        if not configs_to_run:
            self.log_message("Нет активных правил для запуска.", "status")
            return

        try:
            game_filter_enabled = self.game_filter_var.get()
            
            legacy_configs = []
            for cfg in configs_to_run:
                if cfg["type"] == "list":
                    legacy_configs.append((cfg["path"], cfg["profile"], None))
                else:
                    legacy_configs.append((None, cfg["profile"], cfg["path"]))

            process = process_manager.start_combined_process(
                legacy_configs, self.app_dir, game_filter_enabled, self.log_message
            )
            
            if process:
                pid = process.pid
                self.active_processes[pid] = {
                    'proc': process,
                    'rule_indices': active_rule_indices
                }
                self.log_message(f"Процесс запущен (PID: {pid}). Правил: {len(active_rule_indices)}", "success")
                self.ui_manager.update_buttons_state(True)
                self.ui_manager.update_process_status_in_table()
                
                threading.Thread(target=self.read_process_output, args=(process, "winws"), daemon=True).start()
                threading.Thread(target=self.wait_for_process_exit, args=(pid,), daemon=True).start()

        except Exception as e:
            self.log_message(f"Ошибка запуска: {e}", "error")

    def read_process_output(self, process, prefix):
        try:
            for line in iter(process.stdout.readline, ''):
                if line: self.log_queue.put(f"[{prefix}] {line.strip()}")
        except: pass

    def wait_for_process_exit(self, pid):
        if pid in self.active_processes:
            proc = self.active_processes[pid]['proc']
            try: proc.wait()
            except: pass
            self.root.after(0, lambda: self._cleanup_process(pid))

    def _cleanup_process(self, pid):
        if pid in self.active_processes:
            del self.active_processes[pid]
            self.ui_manager.update_process_status_in_table()
            self.log_message(f"Процесс остановлен (PID: {pid})", "status")
            if not self.active_processes:
                self.ui_manager.update_buttons_state(False)

    def log_queue_monitor(self):
        while True:
            try:
                msg = self.log_queue.get()
                self.log_message(msg, "main")
            except: time.sleep(0.1)

    def stop_process(self):
        self.log_message("Остановка...", "status")
        pids = list(self.active_processes.keys())
        for pid in pids:
            if pid in self.active_processes:
                process_manager.kill_process(self.active_processes[pid]['proc'])
        process_manager.stop_all_processes(self.log_message)
        self.active_processes.clear()
        self.ui_manager.update_process_status_in_table()
        self.ui_manager.update_buttons_state(False)

    def save_app_settings(self):
        settings_data = {
            "game_filter": self.game_filter_var.get(),
            "rules": self.list_manager.get_rules(),
            "custom_list_path": self.list_manager.get_custom_list_path()
        }
        settings_manager.save_app_settings(settings_data, self.app_dir)
        self.log_message("Настройки сохранены.", "success")

    def load_app_settings(self):
        settings = settings_manager.load_app_settings(self.app_dir)
        self.game_filter_var.set(settings.get("game_filter", False))
        self.list_manager.set_rules(settings.get("rules", []))
        self.list_manager.set_custom_list_path(settings.get("custom_list_path", ""))
        
        self.ui_manager.refresh_lists_table()
        self.ui_manager.update_custom_list_label()
        self.log_message("Настройки загружены.", "success")

    def trigger_update(self):
        if messagebox.askyesno("Обновление", "Приложение будет закрыто для проверки и установки обновлений.\nПродолжить?"):
            try:
                self.save_app_settings()
                self.stop_process()
                env = os.environ.copy()
                for key in ['PYTHONPATH', 'PYTHONHOME', 'TCL_LIBRARY', 'TK_LIBRARY']: env.pop(key, None)
                
                launcher_path = os.environ.get("LAUNCHER_PATH")
                if not launcher_path or not os.path.exists(launcher_path):
                    potential_exe = os.path.join(os.path.dirname(self.app_dir), "dpi_gui_launcher.exe")
                    if os.path.exists(potential_exe):
                        subprocess.Popen([potential_exe, "--update"], cwd=os.path.dirname(self.app_dir), env=env)
                    else:
                        messagebox.showerror("Ошибка", "Не удалось найти файл лаунчера.")
                        return
                else:
                    subprocess.Popen([launcher_path, "--update"], cwd=os.path.dirname(launcher_path), env=env)
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

    def check_status(self): settings_manager.check_status(self.app_dir, self.log_message)
    def open_custom_list(self): 
        path = self.list_manager.get_custom_list_path()
        if path and os.path.exists(path): os.startfile(path)
    def paste_site_test_url(self): 
        try: self.site_test_url_entry.delete(0, tk.END); self.site_test_url_entry.insert(0, self.root.clipboard_get())
        except: pass
    def show_site_test_url_menu(self, e): self.site_test_url_menu.tk_popup(e.x_root, e.y_root)
    def run_site_test(self):
        self.run_in_thread(testing_utils.run_site_test, self.site_test_url.get(), self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, self.list_manager.get_custom_list_path())
    def run_discord_test(self):
        self.run_in_thread(testing_utils.run_discord_test, self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, lambda n: messagebox.askyesno("Test", f"Profile {n}?"), self.list_manager.get_custom_list_path())

if __name__ == "__main__":
    if not process_manager.is_admin(): run_as_admin(); sys.exit()
    root = tk.Tk()
    app = App(root)
    root.mainloop()