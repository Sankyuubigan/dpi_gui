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
        
        # Хранилище виджетов строк таблицы: { "filename": { "combo_prof": widget, "combo_ipset": widget, "status": widget, "pid": widget } }
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
        self.app.root.geometry("1100x850")
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
        tab_settings = ttk.Frame(self.notebook, padding=10)
        
        self.notebook.add(tab_control, text="Управление")
        self.notebook.add(tab_settings, text="Настройки")
        
        self.create_control_tab(tab_control)
        self.create_settings_tab(tab_settings)

    def create_control_tab(self, parent):
        """Создает главную вкладку управления (Таблица + Логи)"""
        
        # === ВЕРХНЯЯ ЧАСТЬ: КНОПКИ ===
        top_panel = ttk.Frame(parent)
        top_panel.pack(fill=tk.X, pady=(0, 10))
        
        self.btn_start_all = ttk.Button(top_panel, text="▶ ЗАПУСТИТЬ ВСЕ АКТИВНЫЕ", command=self.app.run_all_configured)
        self.btn_start_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_stop_all = ttk.Button(top_panel, text="⬛ ОСТАНОВИТЬ ВСЁ", command=self.app.stop_process)
        self.btn_stop_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # === СРЕДНЯЯ ЧАСТЬ: ТАБЛИЦА СПИСКОВ ===
        # Используем PanedWindow для разделения таблицы и логов, или просто Frame с весом
        # Сделаем Frame для таблицы с фиксированной высотой или весом
        
        table_container = ttk.Frame(parent)
        table_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Заголовки таблицы
        header_frame = ttk.Frame(table_container)
        header_frame.pack(fill=tk.X, padx=5, pady=(5,0))
        
        # Grid weight configuration
        header_frame.columnconfigure(0, weight=3, uniform="col_name")
        header_frame.columnconfigure(1, weight=5, uniform="col_prof")
        header_frame.columnconfigure(2, weight=3, uniform="col_ipset")
        header_frame.columnconfigure(3, weight=2, uniform="col_stat")
        header_frame.columnconfigure(4, weight=1, uniform="col_pid")
        
        ttk.Label(header_frame, text="Файл списка", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=5)
        ttk.Label(header_frame, text="Профиль обхода", font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(header_frame, text="IPSet (Фильтр IP)", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, sticky="w", padx=5)
        ttk.Label(header_frame, text="Статус", font=("Segoe UI", 9, "bold")).grid(row=0, column=3, padx=5)
        ttk.Label(header_frame, text="PID", font=("Segoe UI", 9, "bold")).grid(row=0, column=4, padx=5)
        
        ttk.Separator(table_container, orient='horizontal').pack(fill='x', pady=5)

        # Скроллируемая область для строк
        canvas_frame = ttk.Frame(table_container)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        
        self.scroll_frame_inner = ttk.Frame(self.canvas)
        
        self.scroll_frame_inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas_window_id = self.canvas.create_window((0, 0), window=self.scroll_frame_inner, anchor="nw")
        
        def on_canvas_configure(event):
            self.canvas.itemconfig(self.canvas_window_id, width=event.width)
        
        self.canvas.bind("<Configure>", on_canvas_configure)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # === НИЖНЯЯ ЧАСТЬ: ЛОГИ ===
        logs_container = ttk.LabelFrame(parent, text="Логи событий")
        logs_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Панель инструментов логов
        log_tools = ttk.Frame(logs_container)
        log_tools.pack(fill=tk.X, padx=5, pady=2)
        
        self.show_main_logs = tk.BooleanVar(value=True)
        self.show_domain_logs = tk.BooleanVar(value=True)
        self.show_status_logs = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(log_tools, text="Основные", variable=self.show_main_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(log_tools, text="Домены", variable=self.show_domain_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(log_tools, text="Статус", variable=self.show_status_logs, command=self.update_log_filter).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(log_tools, text="Сохранить", command=self.save_logs_to_file).pack(side=tk.RIGHT, padx=5)
        ttk.Button(log_tools, text="Очистить", command=self.clear_all_logs).pack(side=tk.RIGHT, padx=5)
        
        # Окно логов
        self.log_window = scrolledtext.ScrolledText(logs_container, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1, height=10)
        self.log_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.log_window)

    def _on_mousewheel(self, event):
        try:
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        except: pass

    def refresh_lists_table(self):
        """Перерисовывает строки таблицы"""
        for widget in self.scroll_frame_inner.winfo_children():
            widget.destroy()
        self.list_widgets.clear()
        
        prof_mapping = self.app.list_manager.get_mapping()
        ipset_mapping = self.app.list_manager.get_ipset_mapping()
        active_procs = self.app.active_processes
        available_lists = self.app.list_manager.get_available_files()
        available_ipsets = self.app.list_manager.get_available_ipsets()
        
        profile_names = ["ОТКЛЮЧЕНО"] + [p['name'] for p in self.app.profiles]

        self.scroll_frame_inner.columnconfigure(0, weight=3, uniform="col_name")
        self.scroll_frame_inner.columnconfigure(1, weight=5, uniform="col_prof")
        self.scroll_frame_inner.columnconfigure(2, weight=3, uniform="col_ipset")
        self.scroll_frame_inner.columnconfigure(3, weight=2, uniform="col_stat")
        self.scroll_frame_inner.columnconfigure(4, weight=1, uniform="col_pid")

        for idx, list_filename in enumerate(available_lists):
            # 1. Имя файла
            lbl_name = ttk.Label(self.scroll_frame_inner, text=list_filename, anchor="w")
            lbl_name.grid(row=idx, column=0, sticky="ew", padx=5, pady=8)
            
            # 2. Выбор профиля
            current_profile = prof_mapping.get(list_filename, "ОТКЛЮЧЕНО")
            combo_prof = ttk.Combobox(self.scroll_frame_inner, values=profile_names, state="readonly")
            combo_prof.set(current_profile)
            combo_prof.grid(row=idx, column=1, sticky="ew", padx=5, pady=8)
            combo_prof.bind("<<ComboboxSelected>>", lambda e, f=list_filename, c=combo_prof: self._on_profile_change(f, c))
            
            # 3. Выбор IPSet
            current_ipset = ipset_mapping.get(list_filename, "OFF")
            combo_ipset = ttk.Combobox(self.scroll_frame_inner, values=available_ipsets, state="readonly")
            combo_ipset.set(current_ipset)
            combo_ipset.grid(row=idx, column=2, sticky="ew", padx=5, pady=8)
            combo_ipset.bind("<<ComboboxSelected>>", lambda e, f=list_filename, c=combo_ipset: self._on_ipset_change(f, c))

            # 4. Статус
            status_text = "Остановлен"
            status_color = "#999999"
            pid_text = "-"
            
            for pid, info in active_procs.items():
                if list_filename in info['lists']:
                    status_text = "ЗАПУЩЕН"
                    status_color = "#28a745"
                    pid_text = str(pid)
                    break
            
            lbl_status = tk.Label(self.scroll_frame_inner, text=status_text, fg=status_color, font=("Segoe UI", 9), anchor="center")
            lbl_status.grid(row=idx, column=3, sticky="ew", padx=5, pady=8)
            
            # 5. PID
            lbl_pid = ttk.Label(self.scroll_frame_inner, text=pid_text, anchor="center")
            lbl_pid.grid(row=idx, column=4, sticky="ew", padx=5, pady=8)
            
            sep = ttk.Separator(self.scroll_frame_inner, orient='horizontal')
            sep.grid(row=idx, column=0, columnspan=5, sticky="s", pady=0)

            self.list_widgets[list_filename] = {
                "combo_prof": combo_prof,
                "combo_ipset": combo_ipset,
                "status_lbl": lbl_status,
                "pid_lbl": lbl_pid
            }

    def _on_profile_change(self, list_filename, combo_widget):
        new_profile = combo_widget.get()
        self.app.list_manager.set_profile_for_list(list_filename, new_profile)
        self.app.save_app_settings()

    def _on_ipset_change(self, list_filename, combo_widget):
        new_ipset = combo_widget.get()
        self.app.list_manager.set_ipset_for_list(list_filename, new_ipset)
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

    def create_settings_tab(self, parent):
        """Вкладка настроек, объединяющая Tools, Testing и Domains"""
        
        # Контейнер с прокруткой для настроек (на случай если не влезут)
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Привязка колесика мыши
        def _on_settings_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_settings_mousewheel)

        # --- Глобальные настройки ---
        settings_frame = ttk.LabelFrame(scrollable_frame, text="Глобальные настройки")
        settings_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.app.game_filter_var = tk.BooleanVar()
        self.app.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (применять ко всем новым запускам)", variable=self.app.game_filter_var)
        self.app.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        ttk.Button(settings_frame, text="Проверить системный статус", command=self.app.check_status).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(settings_frame, text="Открыть файл кастомного списка", command=self.app.open_custom_list).pack(side=tk.LEFT, padx=5, pady=5)

        # --- Раздел Тестирования ---
        testing_frame = ttk.LabelFrame(scrollable_frame, text="Тестирование")
        testing_frame.pack(fill=tk.X, pady=10, padx=10)
        
        # Сайт тест
        site_test_sub = ttk.Frame(testing_frame)
        site_test_sub.pack(fill=tk.X, pady=5)
        ttk.Label(site_test_sub, text="Тест доступности сайта:").pack(side=tk.LEFT, padx=5)
        self.app.site_test_url = tk.StringVar(value="rutracker.org")
        self.app.site_test_url_entry = ttk.Entry(site_test_sub, textvariable=self.app.site_test_url, width=30)
        self.app.site_test_url_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(site_test_sub, text="Начать тест", command=self.app.run_site_test).pack(side=tk.LEFT, padx=5)
        
        self.app.site_test_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.app.site_test_url_menu.add_command(label="Вставить", command=self.app.paste_site_test_url)
        self.app.site_test_url_entry.bind("<Button-3>", self.app.show_site_test_url_menu)
        self.app.site_test_url_entry.bind("<Control-v>", lambda e: self.app.paste_site_test_url())

        # Discord тест
        discord_test_sub = ttk.Frame(testing_frame)
        discord_test_sub.pack(fill=tk.X, pady=5)
        ttk.Button(discord_test_sub, text="Очистить кэш Discord", command=lambda: self.app.run_in_thread(self.app.settings_manager.clear_discord_cache, self.app.app_dir, self.app.log_message)).pack(side=tk.LEFT, padx=5)
        ttk.Button(discord_test_sub, text="Интерактивный тест Discord", command=self.app.run_discord_test).pack(side=tk.LEFT, padx=5)

        # --- Раздел Доменов ---
        domains_frame = ttk.LabelFrame(scrollable_frame, text="Поиск доменов (Performance API)")
        domains_frame.pack(fill=tk.X, pady=10, padx=10)
        # Передаем этот фрейм менеджеру доменов для заполнения
        self.app.domain_manager.create_domains_tab(domains_frame)

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