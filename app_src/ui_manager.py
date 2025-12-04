import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import datetime
import glob
import threading
import requests
import json
from text_utils import setup_text_widget_bindings

class UIManager:
    """Класс для управления пользовательским интерфейсом"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.notebook = None
        self.log_window = None
        
        # Хранилище виджетов строк таблицы: { "filename": { "combo": widget, "status": widget, "pid": widget } }
        self.list_widgets = {} 
        self.scroll_frame_inner = None
        
        self.all_logs = []
        
    def setup_window(self):
        """Настраивает главное окно"""
        version_hash = "unknown"
        version_file_path = os.path.join(self.app.app_dir, ".version_hash")
        if os.path.exists(version_file_path):
            with open(version_file_path, 'r') as f:
                full_hash = f.read().strip()
                if full_hash:
                    version_hash = full_hash[:7]
        
        version_date = ""
        date_file_path = os.path.join(self.app.app_dir, ".version_date")
        if os.path.exists(date_file_path):
            with open(date_file_path, 'r') as f:
                version_date = f" | {f.read().strip()}"

        self.app.root.title(f"DPI_GUI Launcher (Commit: {version_hash}{version_date})")
        self.app.root.geometry("1050x800")
        try:
            icon_path = os.path.join(self.app.app_dir, 'icon.ico')
            if os.path.exists(icon_path):
                self.app.root.iconbitmap(icon_path)
        except Exception:
            pass

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.app.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        
        tab_control = ttk.Frame(self.notebook, padding=10)
        tab_tools = ttk.Frame(self.notebook, padding=10)
        tab_testing = ttk.Frame(self.notebook, padding=10)
        tab_domains = ttk.Frame(self.notebook, padding=10)
        tab_logs = ttk.Frame(self.notebook, padding=10)
        
        self.notebook.add(tab_control, text="Управление")
        self.notebook.add(tab_tools, text="Настройки")
        self.notebook.add(tab_testing, text="Тестирование")
        self.notebook.add(tab_domains, text="Домены")
        self.notebook.add(tab_logs, text="Логи")
        
        self.create_control_tab(tab_control)
        self.create_tools_tab(tab_tools)
        self.create_testing_tab(tab_testing)
        self.create_domains_tab(tab_domains)
        self.create_logs_tab(tab_logs)

    def create_control_tab(self, parent):
        """Создает табличную вкладку управления с виджетами"""
        
        # --- Верхняя панель кнопок ---
        top_panel = ttk.Frame(parent)
        top_panel.pack(fill=tk.X, pady=(0, 15))
        
        self.btn_start_all = ttk.Button(top_panel, text="▶ ЗАПУСТИТЬ ВСЕ АКТИВНЫЕ", command=self.app.run_all_configured)
        self.btn_start_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_stop_all = ttk.Button(top_panel, text="⬛ ОСТАНОВИТЬ ВСЁ", command=self.app.stop_process)
        self.btn_stop_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # --- Заголовки таблицы ---
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, padx=5, pady=(5,0))
        
        # Grid weight configuration (ВАЖНО: uniform группирует колонки, чтобы они были одинаковыми в header и body)
        header_frame.columnconfigure(0, weight=3, uniform="col_name")
        header_frame.columnconfigure(1, weight=6, uniform="col_prof")
        header_frame.columnconfigure(2, weight=2, uniform="col_stat")
        header_frame.columnconfigure(3, weight=1, uniform="col_pid")
        
        ttk.Label(header_frame, text="Файл списка", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=10)
        ttk.Label(header_frame, text="Профиль обхода", font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Label(header_frame, text="Статус", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, padx=10)
        ttk.Label(header_frame, text="PID", font=("Segoe UI", 9, "bold")).grid(row=0, column=3, padx=10)
        
        ttk.Separator(parent, orient='horizontal').pack(fill='x', pady=5)

        # --- Скроллируемая область для строк ---
        canvas_frame = ttk.Frame(parent)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        
        self.scroll_frame_inner = ttk.Frame(self.canvas)
        
        # Привязка скролла
        self.scroll_frame_inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scroll_frame_inner, anchor="nw", width=canvas_frame.winfo_reqwidth())
        
        # Хак для растягивания inner frame по ширине canvas
        def on_canvas_configure(event):
            self.canvas.itemconfig(self.canvas_window_id, width=event.width)
        
        self.canvas_window_id = self.canvas.create_window((0, 0), window=self.scroll_frame_inner, anchor="nw")
        self.canvas.bind("<Configure>", on_canvas_configure)
        
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Mousewheel scroll
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_mousewheel(self, event):
        try:
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        except: pass

    def refresh_lists_table(self):
        """Перерисовывает строки таблицы"""
        # Очистка старых виджетов
        for widget in self.scroll_frame_inner.winfo_children():
            widget.destroy()
        self.list_widgets.clear()
        
        mapping = self.app.list_manager.get_mapping()
        active_procs = self.app.active_processes
        available_lists = self.app.list_manager.get_available_files()
        
        # Получаем список профилей для Combobox
        profile_names = ["ОТКЛЮЧЕНО"] + [p['name'] for p in self.app.profiles]

        # Конфигурация сетки (должна совпадать с header_frame по uniform)
        self.scroll_frame_inner.columnconfigure(0, weight=3, uniform="col_name")
        self.scroll_frame_inner.columnconfigure(1, weight=6, uniform="col_prof")
        self.scroll_frame_inner.columnconfigure(2, weight=2, uniform="col_stat")
        self.scroll_frame_inner.columnconfigure(3, weight=1, uniform="col_pid")

        for idx, list_filename in enumerate(available_lists):
            # 1. Имя файла
            lbl_name = ttk.Label(self.scroll_frame_inner, text=list_filename, anchor="w")
            lbl_name.grid(row=idx, column=0, sticky="ew", padx=10, pady=8)
            
            # 2. Выпадающий список (Combobox)
            current_profile = mapping.get(list_filename, "ОТКЛЮЧЕНО")
            combo = ttk.Combobox(self.scroll_frame_inner, values=profile_names, state="readonly")
            combo.set(current_profile)
            combo.grid(row=idx, column=1, sticky="ew", padx=10, pady=8)
            
            combo.bind("<<ComboboxSelected>>", lambda e, f=list_filename, c=combo: self._on_combo_change(f, c))
            
            # 3. Статус
            status_text = "Остановлен"
            status_color = "#999999" # Серый
            pid_text = "-"
            
            for pid, info in active_procs.items():
                if list_filename in info['lists']:
                    status_text = "ЗАПУЩЕН"
                    status_color = "#28a745" # Зеленый
                    pid_text = str(pid)
                    break
            
            lbl_status = tk.Label(self.scroll_frame_inner, text=status_text, fg=status_color, font=("Segoe UI", 9), anchor="center")
            lbl_status.grid(row=idx, column=2, sticky="ew", padx=10, pady=8)
            
            # 4. PID
            lbl_pid = ttk.Label(self.scroll_frame_inner, text=pid_text, anchor="center")
            lbl_pid.grid(row=idx, column=3, sticky="ew", padx=10, pady=8)
            
            # Разделитель
            sep = ttk.Separator(self.scroll_frame_inner, orient='horizontal')
            sep.grid(row=idx, column=0, columnspan=4, sticky="s", pady=0)

            self.list_widgets[list_filename] = {
                "combo": combo,
                "status_lbl": lbl_status,
                "pid_lbl": lbl_pid
            }

    def _on_combo_change(self, list_filename, combo_widget):
        new_profile = combo_widget.get()
        self.app.list_manager.set_profile_for_list(list_filename, new_profile)
        self.app.save_app_settings()

    def update_process_status_in_table(self, list_filename, is_running, pid=None):
        widgets = self.list_widgets.get(list_filename)
        if widgets:
            if is_running:
                widgets["status_lbl"].config(text="ЗАПУЩЕН", fg="#28a745")
                widgets["pid_lbl"].config(text=str(pid))
            else:
                widgets["status_lbl"].config(text="Остановлен", fg="#999999")
                widgets["pid_lbl"].config(text="-")

    def create_domains_tab(self, parent):
        self.app.domain_manager.create_domains_tab(parent)

    def create_logs_tab(self, parent):
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="Логи", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Button(header_frame, text="Очистить", command=self.clear_all_logs).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="Сохранить", command=self.save_logs_to_file).pack(side=tk.RIGHT, padx=5)
        
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_window = scrolledtext.ScrolledText(log_frame, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1)
        self.log_window.pack(fill=tk.BOTH, expand=True)
        setup_text_widget_bindings(self.log_window)
        
        filter_frame = ttk.LabelFrame(parent, text="Фильтры")
        filter_frame.pack(fill=tk.X, pady=5)
        
        self.show_main_logs = tk.BooleanVar(value=True)
        self.show_domain_logs = tk.BooleanVar(value=True)
        self.show_status_logs = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(filter_frame, text="Основные", variable=self.show_main_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Домены", variable=self.show_domain_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="Статус", variable=self.show_status_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)

    def create_tools_tab(self, parent):
        tools_top_frame = ttk.Frame(parent)
        tools_top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(tools_top_frame, text="Проверить системный статус", command=self.app.check_status).pack(side=tk.LEFT, padx=5, pady=5)
        
        settings_frame = ttk.LabelFrame(parent, text="Глобальные настройки")
        settings_frame.pack(fill=tk.X, pady=10)
        
        self.app.game_filter_var = tk.BooleanVar()
        self.app.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (применять ко всем новым запускам)", variable=self.app.game_filter_var)
        self.app.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        ipset_frame = ttk.LabelFrame(parent, text="Настройки IPSet")
        ipset_frame.pack(fill=tk.X, pady=10, padx=0)
        
        self.app.ipset_selection_var = tk.StringVar(value="OFF")
        ttk.Radiobutton(ipset_frame, text="Выключено (Не использовать IPSet)", 
                        variable=self.app.ipset_selection_var, value="OFF").pack(anchor=tk.W, padx=5, pady=2)
        
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
                ttk.Label(ipset_frame, text="Нет файлов в папке ipsets", fg="gray").pack(anchor=tk.W, padx=5, pady=2)
        
        domain_frame = ttk.LabelFrame(parent, text="Пользовательские списки")
        domain_frame.pack(fill=tk.X, pady=10)
        ttk.Button(domain_frame, text="Открыть файл кастомного списка", command=self.app.open_custom_list).pack(side=tk.LEFT, padx=5, pady=5)

    def create_testing_tab(self, parent):
        site_test_frame = ttk.LabelFrame(parent, text="Автоматический тест по сайту")
        site_test_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(site_test_frame, text="Адрес сайта:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.app.site_test_url = tk.StringVar(value="rutracker.org")
        self.app.site_test_url_entry = ttk.Entry(site_test_frame, textvariable=self.app.site_test_url)
        self.app.site_test_url_entry.pack(fill=tk.X, padx=5, pady=5)

        self.app.site_test_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.app.site_test_url_menu.add_command(label="Вставить", command=self.app.paste_site_test_url)
        self.app.site_test_url_entry.bind("<Button-3>", self.app.show_site_test_url_menu)
        self.app.site_test_url_entry.bind("<Control-v>", lambda e: self.app.paste_site_test_url())

        ttk.Button(site_test_frame, text="Начать тест", command=self.app.run_site_test).pack(pady=5)
        
        discord_test_frame = ttk.LabelFrame(parent, text="Интерактивный тест для Discord")
        discord_test_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(discord_test_frame, text="Очистить кэш Discord", command=lambda: self.app.run_in_thread(self.app.settings_manager.clear_discord_cache, self.app.app_dir, self.app.log_message)).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(discord_test_frame, text="Начать тест Discord", command=self.app.run_discord_test).pack(side=tk.LEFT, padx=5, pady=5)

    def update_log_display(self):
        if not self.log_window: return
        try:
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            for log_entry in self.all_logs:
                if (log_entry["type"] == "main" and self.show_main_logs.get()) or \
                   (log_entry["type"] == "domain" and self.show_domain_logs.get()) or \
                   (log_entry["type"] in ["status", "error", "success"] and self.show_status_logs.get()):
                    self.log_window.insert(tk.END, log_entry["text"] + "\n")
            self.log_window.config(state='disabled')
            self.log_window.see(tk.END)
        except:
            pass

    def update_log_filter(self):
        self.update_log_display()

    def clear_all_logs(self):
        self.all_logs.clear()
        if self.log_window:
            self.log_window.config(state='normal')
            self.log_window.delete('1.0', tk.END)
            self.log_window.config(state='disabled')

    def save_logs_to_file(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    for log_entry in self.all_logs:
                        f.write(log_entry["text"] + "\n")
                messagebox.showinfo("Успех", f"Логи сохранены.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить логи:\n{e}")