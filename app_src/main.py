import tkinter as tk
from tkinter import ttk, messagebox
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

from executor import is_custom_list_valid
from list_manager import ListManager
from profiles import PROFILES
import process_manager
import settings_manager
import testing_utils
import power_handler
from ui_manager import UIManager
from domain_manager import DomainManager

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
        self._monitoring_active = False
        
        self.list_manager = ListManager(self.app_dir)
        self.ui_manager = UIManager(self)
        self.domain_manager = DomainManager(self)
        
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
        
        power_handler.setup_power_handler(self)
        
    def setup_window(self):
        self.ui_manager.setup_window()

    def create_widgets(self):
        self.ui_manager.create_widgets()

    def populate_profiles_list(self):
        profile_names = [p['name'] for p in self.profiles]
        self.profiles_combobox['values'] = profile_names
        if profile_names:
            self.profiles_combobox.current(0)
        self.profiles_combobox.bind("<<ComboboxSelected>>", self.on_profile_change)

    def on_profile_change(self, event=None):
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

    def log_message(self, message, log_type="main"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = ""
        if log_type == "domain": prefix = "[ДОМЕНЫ] "
        elif log_type == "status": prefix = "[СТАТУС] "
        elif log_type == "error": prefix = "[ОШИБКА] "
        elif log_type == "success": prefix = "[УСПЕХ] "
        
        formatted_message = f"[{timestamp}] {prefix}{message}"
        log_entry = {"text": formatted_message, "type": log_type, "timestamp": timestamp}
        self.ui_manager.all_logs.append(log_entry)
        self.ui_manager.update_log_display()
        
        if log_type in ["main", "status", "error", "success"]:
            self.ui_manager.update_status_display(message, log_type)

    def run_in_thread(self, target_func, *args):
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()

    def run_selected_profile(self):
        try:
            if self.process and self.process.poll() is None:
                messagebox.showinfo("Информация", "Процесс уже запущен.")
                return
            
            profile = self.get_selected_profile()
            if not profile: return
            
            self.log_message(f"Запуск профиля: {profile['name']}", "main")
            process_manager.stop_all_processes(self.log_message)
            
            game_filter_enabled = self.game_filter_var.get()
            
            # Обработка выбора IPSet
            ipset_selection = self.ipset_selection_var.get()
            ipset_path = None
            if ipset_selection and ipset_selection != "OFF":
                potential_path = os.path.join(self.app_dir, 'ipsets', ipset_selection)
                if os.path.exists(potential_path):
                    ipset_path = potential_path
                    self.log_message(f"Используется IPSet файл: {ipset_selection}", "main")
                else:
                    self.log_message(f"ВНИМАНИЕ: Выбранный файл IPSet не найден: {ipset_selection}", "error")
            else:
                self.log_message("IPSet: Выключено", "main")

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
                 self.log_message("ВНИМАНИЕ: Объединенный список не был создан (пуст или не выбран).", "status")

            self.process = process_manager.start_process(
                profile, self.app_dir, game_filter_enabled, 
                self.log_message, combined_list_path, ipset_path
            )
            
            if not self.process:
                self.log_message("Не удалось запустить процесс. Проверьте логи.", "error")
                return
                
            self.ui_manager.set_controls_state(tk.DISABLED)
            self.ui_manager.update_status_indicator(True)
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
            if hasattr(self, '_monitoring_active') and self._monitoring_active: return
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
        self.ui_manager.set_controls_state(tk.NORMAL)
        self.ui_manager.update_status_indicator(False)
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
            self.ui_manager.set_controls_state(tk.NORMAL)
            self.ui_manager.update_status_indicator(False)
            if self.process: self.process = None
            
        except Exception as e:
            self._handle_ui_error(e)
        finally:
            self.stop_button.config(state=tk.NORMAL, text="Остановить")

    def check_status(self, log_header=True):
        try:
            settings_manager.check_status(self.app_dir, self.log_message, log_header)
        except Exception as e:
            self._handle_ui_error(e)

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
        tk.Label(dialog, text="Процесс еще активен. Остановить его перед выходом?", wraplength=300).pack(pady=10)
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

    def _handle_ui_error(self, e):
        error_details = traceback.format_exc()
        self.log_message("\n" + "="*20 + " КРИТИЧЕСКАЯ ОШИБКА GUI " + "="*20, "error")
        self.log_message(error_details, "error")
        messagebox.showerror("Критическая ошибка", f"Произошла ошибка:\n{e}\n\nПодробности записаны в окне логов.")

    def save_app_settings(self):
        settings_data = {
            "selected_profile": self.profile_var.get(),
            "game_filter": self.game_filter_var.get(),
            "ipset_selection": self.ipset_selection_var.get(),
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
        if profile_name in self.profiles_combobox['values']:
            self.profile_var.set(profile_name)
        
        self.game_filter_var.set(settings.get("game_filter", False))
        
        # Загрузка IPSet
        ipset_val = settings.get("ipset_selection")
        if ipset_val:
            self.ipset_selection_var.set(ipset_val)
        else:
            # Обратная совместимость
            if settings.get("use_ipset", False):
                self.ipset_selection_var.set("ipset-all.txt")
            else:
                self.ipset_selection_var.set("OFF")
        
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
                        f.write("# Личный список доменов\n")
            os.startfile(custom_list_path)
        except Exception as e:
            self._handle_ui_error(e)

    def on_custom_list_toggle(self):
        if self.use_custom_list_var.get():
            self.select_custom_list_file()
        else:
            self.list_manager.set_custom_list_path(None)
            self.custom_list_path_label.config(text="(не выбран)", fg="gray")

    def select_custom_list_file(self):
        file_path = filedialog.askopenfilename(
            title="Выберите файл со списком доменов",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.list_manager.set_custom_list_path(file_path)
            self.custom_list_path_label.config(text=os.path.basename(file_path), fg="black")
            self.use_custom_list_var.set(True)
        else:
            if not self.list_manager.get_custom_list_path():
                self.use_custom_list_var.set(False)

    def install_service(self):
        try:
            profile = self.get_selected_profile()
            if not profile: return
            if messagebox.askyesno("Подтверждение", f"Установить профиль '{profile['name']}' как службу Windows?"):
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
            messagebox.showwarning("Внимание", "Тест уже запущен.")
            return True
        return False

    def run_site_test(self):
        try:
            if self._check_test_running(): return
            domain = self.site_test_url.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите адрес сайта.")
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
                return messagebox.askyesno("Интерактивный тест", f"Профиль '{profile_name}' запущен.\n\nDiscord работает?", icon='question')
            self.test_thread = threading.Thread(
                target=testing_utils.run_discord_test,
                args=(self.profiles, self.app_dir, self.game_filter_var.get(), self.log_message, ask_user_callback),
                daemon=True
            )
            self.test_thread.start()
        except Exception as e:
            self._handle_ui_error(e)

    def show_site_test_url_menu(self, event):
        try:
            self.site_test_url_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.site_test_url_menu.grab_release()

    def paste_site_test_url(self):
        try:
            text = self.root.clipboard_get()
            self.site_test_url_entry.delete(0, tk.END)
            self.site_test_url_entry.insert(0, text)
        except tk.TclError:
            pass

if __name__ == "__main__":
    if not process_manager.is_admin():
        run_as_admin()
        sys.exit()
    
    root = tk.Tk()
    app = App(root)
    root.mainloop()