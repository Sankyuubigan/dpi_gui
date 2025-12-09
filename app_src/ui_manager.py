import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import datetime
import webbrowser
from text_utils import setup_text_widget_bindings
from ip_grabber import IPGrabberTab

class UIManager:
    """Класс для управления пользовательским интерфейсом"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.notebook = None
        self.log_window = None
        
        # Хранилище виджетов строк таблицы (теперь это список списков виджетов)
        # [ [combo_file, combo_profile, lbl_status, btn_del], ... ]
        self.rule_widgets = []
        self.scroll_frame_inner = None
        
        self.all_logs = []
        self.btn_start_all = None
        self.btn_stop_all = None
        self.lbl_custom_list_path = None
        
    def setup_window(self):
        """Настраивает главное окно"""
        version_hash = "unknown"
        try:
            with open(os.path.join(self.app.app_dir, ".version_hash"), 'r') as f:
                version_hash = f.read().strip()[:7]
        except: pass
        
        self.app.root.title(f"DPI_GUI Launcher (Commit: {version_hash})")
        self.app.root.geometry("1100x850")
        try:
            self.app.root.iconbitmap(os.path.join(self.app.app_dir, 'icon.ico'))
        except: pass

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.app.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        
        tab_control = ttk.Frame(self.notebook, padding=10)
        tab_ipgrabber = ttk.Frame(self.notebook, padding=10) # Новая вкладка
        tab_settings = ttk.Frame(self.notebook, padding=10)
        
        self.notebook.add(tab_control, text="Управление")
        self.notebook.add(tab_ipgrabber, text="Граббер IP (для игр)")
        self.notebook.add(tab_settings, text="Настройки")
        
        self.create_control_tab(tab_control)
        self.create_ipgrabber_tab(tab_ipgrabber)
        self.create_settings_tab(tab_settings)

    def create_ipgrabber_tab(self, parent):
        """Встраиваем граббер как вкладку"""
        grabber = IPGrabberTab(
            parent, 
            self.app.app_dir, 
            self.app.log_message, 
            self.refresh_lists_table # Обновить таблицу при сохранении нового ipset
        )
        grabber.pack(fill=tk.BOTH, expand=True)

    def create_control_tab(self, parent):
        """Главная вкладка: Таблица правил + Логи"""
        
        # === ВЕРХНЯЯ ЧАСТЬ: КНОПКИ ===
        top_panel = ttk.Frame(parent)
        top_panel.pack(fill=tk.X, pady=(0, 10))
        
        self.btn_start_all = ttk.Button(top_panel, text="▶ ЗАПУСТИТЬ ВСЕ", command=self.app.run_all_configured)
        self.btn_start_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_stop_all = ttk.Button(top_panel, text="⬛ ОСТАНОВИТЬ ВСЕ", command=self.app.stop_process, state=tk.DISABLED)
        self.btn_stop_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # === ТАБЛИЦА ПРАВИЛ ===
        table_container = ttk.LabelFrame(parent, text="Правила обхода (Домены и IP)")
        table_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Заголовки
        header_frame = ttk.Frame(table_container)
        header_frame.pack(fill=tk.X, padx=5, pady=(5,0))
        
        header_frame.columnconfigure(0, weight=4) # Файл
        header_frame.columnconfigure(1, weight=4) # Профиль
        header_frame.columnconfigure(2, weight=2) # Статус
        header_frame.columnconfigure(3, weight=1) # Кнопка удаления
        
        ttk.Label(header_frame, text="Цель (Файл списка или IPSet)", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=5)
        ttk.Label(header_frame, text="Профиль обхода", font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(header_frame, text="Статус", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, padx=5)
        ttk.Label(header_frame, text="Уд.", font=("Segoe UI", 9, "bold")).grid(row=0, column=3, padx=5)
        
        ttk.Separator(table_container, orient='horizontal').pack(fill='x', pady=5)

        # Скролл
        canvas_frame = ttk.Frame(table_container)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        
        self.scroll_frame_inner = ttk.Frame(self.canvas)
        self.scroll_frame_inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas_window_id = self.canvas.create_window((0, 0), window=self.scroll_frame_inner, anchor="nw")
        
        # Исправлена ошибка с event.width
        def on_canvas_configure(event):
            self.canvas.itemconfig(self.canvas_window_id, width=event.width)
            
        self.canvas.bind("<Configure>", on_canvas_configure)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Кнопка добавления строки
        add_btn_frame = ttk.Frame(table_container)
        add_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(add_btn_frame, text="+ Добавить правило", command=self.add_rule_row).pack(side=tk.LEFT)

        # === ЛОГИ ===
        logs_container = ttk.LabelFrame(parent, text="Логи событий")
        logs_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        log_tools = ttk.Frame(logs_container)
        log_tools.pack(fill=tk.X, padx=5, pady=2)
        
        self.show_main_logs = tk.BooleanVar(value=True)
        self.show_domain_logs = tk.BooleanVar(value=True)
        self.show_status_logs = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(log_tools, text="Основные", variable=self.show_main_logs, command=self.update_log_display).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(log_tools, text="Домены", variable=self.show_domain_logs, command=self.update_log_display).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(log_tools, text="Статус", variable=self.show_status_logs, command=self.update_log_display).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(log_tools, text="Очистить", command=self.clear_all_logs).pack(side=tk.RIGHT, padx=5)
        
        self.log_window = scrolledtext.ScrolledText(logs_container, state='disabled', bg='black', fg='white', height=8)
        self.log_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.log_window)

    def _on_mousewheel(self, event):
        try: self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        except: pass

    def _on_combo_scroll(self, event):
        """
        Обработчик прокрутки колеса над Combobox.
        Блокирует изменение значения (return "break"), 
        но принудительно вызывает прокрутку страницы, чтобы скролл не застревал.
        """
        self._on_mousewheel(event)
        return "break"

    def refresh_lists_table(self):
        """Полная перерисовка таблицы на основе данных из ListManager."""
        # Очистка старых виджетов
        for widgets in self.rule_widgets:
            for w in widgets: w.destroy()
        self.rule_widgets.clear()
        for child in self.scroll_frame_inner.winfo_children(): child.destroy()

        # Данные
        rules = self.app.list_manager.get_rules()
        available_resources = self.app.list_manager.get_all_resources()
        
        # Подготовка списков для комбобоксов
        resource_display_list = [r["display"] for r in available_resources]
        # Добавляем "Отключено" в начало списка профилей
        profile_names = ["Отключено"] + [p['name'] for p in self.app.profiles]

        # Настройка сетки
        self.scroll_frame_inner.columnconfigure(0, weight=4)
        self.scroll_frame_inner.columnconfigure(1, weight=4)
        self.scroll_frame_inner.columnconfigure(2, weight=2)
        self.scroll_frame_inner.columnconfigure(3, weight=1)

        for idx, rule in enumerate(rules):
            # 1. Выбор файла (Combobox)
            combo_file = ttk.Combobox(self.scroll_frame_inner, values=resource_display_list, state="readonly")
            # Блокируем смену значения колесом
            combo_file.bind("<MouseWheel>", self._on_combo_scroll)
            
            # Пытаемся найти текущее значение для отображения
            current_display = ""
            for res in available_resources:
                if res["filename"] == rule["file"]: # Сравниваем по filename (ID)
                    current_display = res["display"]
                    break
            
            if not current_display and rule["file"]:
                # Если файл удален, но есть в конфиге
                current_display = f"[MISSING] {rule['file']}"
                
            combo_file.set(current_display)
            combo_file.grid(row=idx, column=0, sticky="ew", padx=5, pady=2)
            
            # При изменении обновляем конфиг
            combo_file.bind("<<ComboboxSelected>>", lambda e, i=idx, c=combo_file: self._on_rule_file_change(i, c, available_resources))

            # 2. Выбор профиля
            combo_prof = ttk.Combobox(self.scroll_frame_inner, values=profile_names, state="readonly")
            # Блокируем смену значения колесом
            combo_prof.bind("<MouseWheel>", self._on_combo_scroll)
            
            combo_prof.set(rule["profile"])
            combo_prof.grid(row=idx, column=1, sticky="ew", padx=5, pady=2)
            combo_prof.bind("<<ComboboxSelected>>", lambda e, i=idx, c=combo_prof: self._on_rule_profile_change(i, c))

            # 3. Статус
            lbl_status = tk.Label(self.scroll_frame_inner, text="Остановлен", fg="#999999", anchor="center")
            lbl_status.grid(row=idx, column=2, sticky="ew", padx=5, pady=2)
            
            # Если профиль отключен, можно показать это явно
            if rule["profile"] == "Отключено":
                lbl_status.config(text="Отключено", fg="gray")
            else:
                # Проверяем, запущен ли процесс для этого правила
                active_pid = self._get_pid_for_rule(idx)
                if active_pid:
                    lbl_status.config(text=f"PID: {active_pid}", fg="#28a745")

            # 4. Удалить
            btn_del = ttk.Button(self.scroll_frame_inner, text="X", width=3, command=lambda i=idx: self.delete_rule_row(i))
            btn_del.grid(row=idx, column=3, padx=5, pady=2)

            self.rule_widgets.append([combo_file, combo_prof, lbl_status, btn_del])

    def _get_pid_for_rule(self, rule_index):
        # Проверяем активные процессы
        for pid, info in self.app.active_processes.items():
            # info['rule_indices'] должен хранить индексы запущенных правил
            if rule_index in info.get('rule_indices', []):
                return pid
        return None

    def add_rule_row(self):
        """Добавляет пустую строку."""
        # Берем первый попавшийся файл и профиль как дефолт
        res = self.app.list_manager.get_all_resources()
        default_file = res[0]["filename"] if res else ""
        default_type = res[0]["type"] if res else "list"
        default_prof = self.app.profiles[0]["name"]
        
        self.app.list_manager.add_rule(default_file, default_type, default_prof)
        self.app.save_app_settings()
        self.refresh_lists_table()

    def delete_rule_row(self, index):
        self.app.list_manager.remove_rule(index)
        self.app.save_app_settings()
        self.refresh_lists_table()

    def _on_rule_file_change(self, index, combo, resources):
        display_val = combo.get()
        # Ищем реальный filename и type по display name
        for res in resources:
            if res["display"] == display_val:
                self.app.list_manager.update_rule(index, "file", res["filename"])
                self.app.list_manager.update_rule(index, "type", res["type"])
                break
        self.app.save_app_settings()

    def _on_rule_profile_change(self, index, combo):
        new_profile = combo.get()
        self.app.list_manager.update_rule(index, "profile", new_profile)
        self.app.save_app_settings()
        
        # Обновляем статус лейбл сразу, чтобы видно было "Отключено"
        if index < len(self.rule_widgets):
             lbl_status = self.rule_widgets[index][2]
             if new_profile == "Отключено":
                 lbl_status.config(text="Отключено", fg="gray")
             else:
                 lbl_status.config(text="Остановлен", fg="#999999")

    def update_process_status_in_table(self):
        """Обновляет только колонку статуса (без перестройки всей таблицы)."""
        rules = self.app.list_manager.get_rules()
        for idx, widgets in enumerate(self.rule_widgets):
            lbl_status = widgets[2]
            
            # Если правило отключено, не показываем PID, даже если что-то странное
            if idx < len(rules) and rules[idx].get("profile") == "Отключено":
                lbl_status.config(text="Отключено", fg="gray")
                continue

            active_pid = self._get_pid_for_rule(idx)
            if active_pid:
                lbl_status.config(text=f"PID: {active_pid}", fg="#28a745")
            else:
                lbl_status.config(text="Остановлен", fg="#999999")

    def update_buttons_state(self, is_running):
        if is_running:
            self.btn_start_all.config(state=tk.DISABLED)
            self.btn_stop_all.config(state=tk.NORMAL)
        else:
            self.btn_start_all.config(state=tk.NORMAL)
            self.btn_stop_all.config(state=tk.DISABLED)

    def create_settings_tab(self, parent):
        """Облегченные настройки"""
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Глобальные
        settings_frame = ttk.LabelFrame(scrollable_frame, text="Глобальные настройки")
        settings_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.app.game_filter_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Игровой фильтр (применять ко всем запускам)", variable=self.app.game_filter_var).pack(anchor=tk.W, padx=5, pady=5)
        
        # Кастомный список
        list_frame = ttk.LabelFrame(settings_frame, text="Кастомный список доменов")
        list_frame.pack(fill=tk.X, padx=5, pady=5)
        self.lbl_custom_list_path = ttk.Label(list_frame, text="Файл не выбран", foreground="gray")
        self.lbl_custom_list_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.update_custom_list_label()
        ttk.Button(list_frame, text="📂 Выбрать", command=self.select_custom_list).pack(side=tk.RIGHT, padx=5)
        ttk.Button(list_frame, text="✏ Ред.", command=self.app.open_custom_list).pack(side=tk.RIGHT, padx=5)

        # Кнопки
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Проверить статус", command=self.app.check_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="♻ Обновить", command=self.app.trigger_update).pack(side=tk.LEFT, padx=5)
        
        # Домены и Тесты
        domains_frame = ttk.LabelFrame(scrollable_frame, text="Поиск доменов")
        domains_frame.pack(fill=tk.X, pady=10, padx=10)
        self.app.domain_manager.create_domains_tab(domains_frame)

        # --- Ссылка на донат (ВОЗВРАЩЕНО) ---
        support_frame = ttk.Frame(scrollable_frame)
        support_frame.pack(fill=tk.X, pady=(20, 10), padx=10)

        ttk.Label(support_frame, text="Отблагодарить автора (помощь и донаты):", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)

        link_url = "https://interesting-knowledges.vercel.app/docs/otblagodarit-avtora.-pomosch-proektam"
        link_lbl = tk.Label(support_frame, text=link_url, fg="blue", cursor="hand2", font=("Segoe UI", 9, "underline"))
        link_lbl.pack(anchor=tk.W, pady=2)
        link_lbl.bind("<Button-1>", lambda e: webbrowser.open_new(link_url))

    def select_custom_list(self):
        filename = filedialog.askopenfilename(title="Выберите файл списка", filetypes=[("Txt", "*.txt")])
        if filename:
            self.app.list_manager.set_custom_list_path(filename)
            self.app.save_app_settings()
            self.update_custom_list_label()
            self.app.domain_manager.update_list_status_label()
            self.refresh_lists_table() # Обновить список в комбобоксах

    def update_custom_list_label(self):
        path = self.app.list_manager.get_custom_list_path()
        if path: self.lbl_custom_list_path.config(text=path, foreground="black")
        else: self.lbl_custom_list_path.config(text="Файл не выбран", foreground="#aa0000")
    
    # ... (Остальные методы логов без изменений) ...
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
        except: pass

    def clear_all_logs(self):
        self.all_logs.clear()
        self.update_log_display()