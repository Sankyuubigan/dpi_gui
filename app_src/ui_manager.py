import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import os
import sys
import datetime
import glob
import threading
import requests
import json
import webbrowser
from text_utils import setup_text_widget_bindings
import ip_grabber

class UIManager:
    """Класс для управления пользовательским интерфейсом"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.notebook = None
        self.log_window = None
        
        self.list_widgets = {} 
        self.scroll_frame_inner = None
        
        self.all_logs = []
        self.btn_start_all = None
        self.btn_stop_all = None
        self.lbl_custom_list_path = None
        
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
        top_panel = ttk.Frame(parent)
        top_panel.pack(fill=tk.X, pady=(0, 10))
        
        self.btn_start_all = ttk.Button(top_panel, text="▶ ЗАПУСТИТЬ", command=self.app.run_all_configured)
        self.btn_start_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_stop_all = ttk.Button(top_panel, text="⬛ ОСТАНОВИТЬ", command=self.app.stop_process, state=tk.NORMAL)
        self.btn_stop_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        table_container = ttk.Frame(parent)
        table_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        header_frame = ttk.Frame(table_container)
        header_frame.pack(fill=tk.X, padx=5, pady=(5,0))
        
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

        logs_container = ttk.LabelFrame(parent, text="Логи событий")
        logs_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
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
        
        self.log_window = scrolledtext.ScrolledText(logs_container, state='disabled', bg='black', fg='white', relief=tk.SUNKEN, borderwidth=1, height=10)
        self.log_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        setup_text_widget_bindings(self.log_window)

    def _on_mousewheel(self, event):
        try:
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        except: pass

    def refresh_lists_table(self):
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
            display_name = list_filename
            fg_color = "black"
            
            if list_filename.startswith("[CUSTOM]"):
                fg_color = "blue"
            
            lbl_name = ttk.Label(self.scroll_frame_inner, text=display_name, anchor="w", foreground=fg_color)
            lbl_name.grid(row=idx, column=0, sticky="ew", padx=5, pady=8)
            
            current_profile = prof_mapping.get(list_filename, "ОТКЛЮЧЕНО")
            combo_prof = ttk.Combobox(self.scroll_frame_inner, values=profile_names, state="readonly")
            combo_prof.set(current_profile)
            combo_prof.grid(row=idx, column=1, sticky="ew", padx=5, pady=8)
            combo_prof.bind("<<ComboboxSelected>>", lambda e, f=list_filename, c=combo_prof: self._on_profile_change(f, c))
            
            current_ipset = ipset_mapping.get(list_filename, "OFF")
            combo_ipset = ttk.Combobox(self.scroll_frame_inner, values=available_ipsets, state="readonly")
            combo_ipset.set(current_ipset)
            combo_ipset.grid(row=idx, column=2, sticky="ew", padx=5, pady=8)
            combo_ipset.bind("<<ComboboxSelected>>", lambda e, f=list_filename, c=combo_ipset: self._on_ipset_change(f, c))

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

    def update_buttons_state(self, is_running):
        self.btn_stop_all.config(state=tk.NORMAL)
        if is_running:
            self.btn_start_all.config(state=tk.DISABLED)
        else:
            self.btn_start_all.config(state=tk.NORMAL)

    def create_settings_tab(self, parent):
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
        
        def _on_settings_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_settings_mousewheel)

        settings_frame = ttk.LabelFrame(scrollable_frame, text="Глобальные настройки")
        settings_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.app.game_filter_var = tk.BooleanVar()
        self.app.game_filter_check = ttk.Checkbutton(settings_frame, text="Игровой фильтр (применять ко всем новым запускам)", variable=self.app.game_filter_var)
        self.app.game_filter_check.pack(anchor=tk.W, padx=5, pady=5)
        
        list_frame = ttk.LabelFrame(settings_frame, text="Кастомный список доменов")
        list_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lbl_custom_list_path = ttk.Label(list_frame, text="Файл не выбран", foreground="gray")
        self.lbl_custom_list_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.update_custom_list_label()
        
        ttk.Button(list_frame, text="📂 Указать кастомный список", command=self.select_custom_list).pack(side=tk.RIGHT, padx=5)
        ttk.Button(list_frame, text="✏ Открыть/Редактировать", command=self.app.open_custom_list).pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(settings_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Проверить системный статус", command=self.app.check_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="♻ Обновить программу", command=self.app.trigger_update).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🔍 Создать IPSet из процесса", command=self.open_ip_grabber).pack(side=tk.LEFT, padx=5)

        updates_frame = ttk.LabelFrame(scrollable_frame, text="Обновления (Zapret)")
        updates_frame.pack(fill=tk.X, pady=10, padx=10)
        
        update_btns = ttk.Frame(updates_frame)
        update_btns.pack(fill=tk.X, pady=5)
        
        ttk.Button(update_btns, text="📥 Обновить IPSet (GitHub)", command=self.app.update_ipset_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(update_btns, text="📄 Скачать Hosts файл", command=self.app.update_hosts_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(update_btns, text="📂 Папка IPSet", command=self.app.open_ipset_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(update_btns, text="📂 Папка Hosts", command=self.app.open_hosts_folder).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(updates_frame, text="IPSet: фильтрует трафик по IP-адресам. Hosts: дополнительная защита через системный файл.", 
                  foreground="gray", font=("Segoe UI", 8)).pack(anchor=tk.W, padx=5, pady=(0, 5))

        testing_frame = ttk.LabelFrame(scrollable_frame, text="Тестирование")
        testing_frame.pack(fill=tk.X, pady=10, padx=10)
        
        site_test_sub = ttk.Frame(testing_frame)
        site_test_sub.pack(fill=tk.X, pady=5)
        ttk.Label(site_test_sub, text="Тест доступности сайта:").pack(side=tk.LEFT, padx=5)
        self.app.site_test_url = tk.StringVar(value="mixamo.com")
        self.app.site_test_url_entry = ttk.Entry(site_test_sub, textvariable=self.app.site_test_url, width=30)
        self.app.site_test_url_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(site_test_sub, text="Обычный пинг (Все профили)", command=self.app.run_site_test).pack(side=tk.LEFT, padx=5)
        
        # НОВАЯ КНОПКА ГЛУБОКОГО АНАЛИЗА
        ttk.Button(site_test_sub, text="Глубокий анализ (Playwright)", command=self.app.run_deep_site_analysis).pack(side=tk.LEFT, padx=5)
        
        self.app.site_test_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.app.site_test_url_menu.add_command(label="Вставить", command=self.app.paste_site_test_url)
        self.app.site_test_url_entry.bind("<Button-3>", self.app.show_site_test_url_menu)
        self.app.site_test_url_entry.bind("<Control-v>", lambda e: self.app.paste_site_test_url())

        discord_test_sub = ttk.Frame(testing_frame)
        discord_test_sub.pack(fill=tk.X, pady=5)
        ttk.Button(discord_test_sub, text="Очистить кэш Discord", command=lambda: self.app.run_in_thread(self.app.settings_manager.clear_discord_cache, self.app.app_dir, self.app.log_message)).pack(side=tk.LEFT, padx=5)

        domains_frame = ttk.LabelFrame(scrollable_frame, text="Поиск доменов (Performance API)")
        domains_frame.pack(fill=tk.X, pady=10, padx=10)
        self.app.domain_manager.create_domains_tab(domains_frame)

        support_frame = ttk.Frame(scrollable_frame)
        support_frame.pack(fill=tk.X, pady=(20, 10), padx=10)

        ttk.Label(support_frame, text="Отблагодарить автора (помощь и донаты):", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)

        link_url = "https://interesting-knowledges.vercel.app/docs/otblagodarit-avtora.-pomosch-proektam"
        link_lbl = tk.Label(support_frame, text=link_url, fg="blue", cursor="hand2", font=("Segoe UI", 9, "underline"))
        link_lbl.pack(anchor=tk.W, pady=2)
        link_lbl.bind("<Button-1>", lambda e: webbrowser.open_new(link_url))

    def select_custom_list(self):
        filename = filedialog.askopenfilename(
            title="Выберите файл списка доменов",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.app.list_manager.set_custom_list_path(filename)
            self.app.save_app_settings()
            self.update_custom_list_label()
            self.app.domain_manager.update_list_status_label()
            self.refresh_lists_table()

    def update_custom_list_label(self):
        if not self.lbl_custom_list_path: return
        
        path = self.app.list_manager.get_custom_list_path()
        if path:
            self.lbl_custom_list_path.config(text=path, foreground="black")
        else:
            self.lbl_custom_list_path.config(text="Файл не выбран (поиск доменов не будет сохранять результаты)", foreground="#aa0000")

    def open_ip_grabber(self):
        ip_grabber.show_ip_grabber(
            self.app.root, 
            self.app.app_dir, 
            self.app.log_message,
            self.refresh_lists_table
        )

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