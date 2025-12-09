import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import os

class IPGrabberTab(ttk.Frame):
    def __init__(self, parent, app_dir, log_callback, on_save_callback):
        super().__init__(parent)
        self.app_dir = app_dir
        self.log_callback = log_callback
        self.on_save_callback = on_save_callback
        
        self.selected_pid = None
        self.selected_name = None
        self.is_capturing = False
        self.captured_ips = set()
        self.capture_thread = None
        
        self.create_widgets()
        # Запускаем обновление процессов при первом показе
        self.after(500, self.refresh_processes)

    def create_widgets(self):
        # Разделяем окно на две панели: Слева (выбор процесса), Справа (результат)
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- ЛЕВАЯ ЧАСТЬ: Процессы ---
        left_frame = ttk.LabelFrame(paned, text="1. Выбор процесса")
        paned.add(left_frame, weight=1)
        
        # Поиск
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(search_frame, text="Поиск:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_processes)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(search_frame, text="↻", width=3, command=self.refresh_processes).pack(side=tk.RIGHT)

        # Таблица процессов
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(tree_frame, columns=("PID", "Name"), show="headings")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Имя процесса")
        self.tree.column("PID", width=50, stretch=False)
        self.tree.column("Name", width=150)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_process_select)

        # --- ПРАВАЯ ЧАСТЬ: Захват ---
        right_frame = ttk.LabelFrame(paned, text="2. Захват IP (IPSet)")
        paned.add(right_frame, weight=1)
        
        # Управление
        control_frame = ttk.Frame(right_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lbl_target = ttk.Label(control_frame, text="Процесс не выбран", foreground="gray")
        self.lbl_target.pack(anchor=tk.W, pady=2)
        
        self.btn_start = ttk.Button(control_frame, text="▶ НАЧАТЬ ЗАХВАТ", command=self.toggle_capture, state=tk.DISABLED)
        self.btn_start.pack(fill=tk.X, pady=5)
        
        self.lbl_count = ttk.Label(control_frame, text="Найдено IP: 0")
        self.lbl_count.pack(anchor=tk.W)

        # Список IP
        self.ip_listbox = tk.Listbox(right_frame)
        self.ip_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Сохранение
        save_frame = ttk.Frame(right_frame)
        save_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.entry_filename = ttk.Entry(save_frame)
        self.entry_filename.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry_filename.insert(0, "ipset-game.txt")
        
        self.btn_save = ttk.Button(save_frame, text="💾 Сохранить", command=self.save_to_file, state=tk.DISABLED)
        self.btn_save.pack(side=tk.RIGHT)

    def refresh_processes(self):
        self.all_processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    self.all_processes.append((proc.info['pid'], proc.info['name']))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception:
            pass
        
        self.all_processes.sort(key=lambda x: x[1].lower())
        self.filter_processes()

    def filter_processes(self, *args):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        
        for pid, name in self.all_processes:
            if query in name.lower() or query in str(pid):
                self.tree.insert("", "end", values=(pid, name))

    def on_process_select(self, event):
        if self.is_capturing: return

        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            self.selected_pid = item['values'][0]
            self.selected_name = item['values'][1]
            self.btn_start.config(state=tk.NORMAL)
            self.lbl_target.config(text=f"Цель: {self.selected_name} (все PID)", foreground="blue")
            
            # Автозаполнение имени файла
            safe_name = "".join(c for c in self.selected_name if c.isalnum() or c in ('-', '_')).rstrip()
            if safe_name.lower().endswith("exe"): safe_name = safe_name[:-3]
            self.entry_filename.delete(0, tk.END)
            self.entry_filename.insert(0, f"ipset-{safe_name.strip()}.txt")
        else:
            self.selected_pid = None
            self.btn_start.config(state=tk.DISABLED)
            self.lbl_target.config(text="Процесс не выбран", foreground="gray")

    def toggle_capture(self):
        if not self.is_capturing:
            # START
            self.is_capturing = True
            self.btn_start.config(text="⬛ ОСТАНОВИТЬ ЗАХВАТ")
            self.captured_ips.clear()
            self.ip_listbox.delete(0, tk.END)
            self.lbl_count.config(text="Идет сканирование...", foreground="green")
            self.btn_save.config(state=tk.DISABLED)
            
            self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
            self.capture_thread.start()
        else:
            # STOP
            self.is_capturing = False
            self.btn_start.config(text="▶ НАЧАТЬ ЗАХВАТ")
            self.lbl_count.config(text=f"Завершено. Найдено уникальных IP: {len(self.captured_ips)}", foreground="black")
            if self.captured_ips:
                self.btn_save.config(state=tk.NORMAL)

    def capture_loop(self):
        target_name = self.selected_name
        
        while self.is_capturing:
            try:
                # Ищем все процессы с таким именем (игры часто запускают дочерние процессы)
                target_procs = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'] == target_name:
                            target_procs.append(proc)
                    except: pass
                
                if not target_procs:
                    time.sleep(1)
                    continue

                for proc in target_procs:
                    try:
                        # net_connections требует прав, но пробуем
                        connections = proc.connections(kind='inet')
                        for conn in connections:
                            if conn.raddr:
                                ip = conn.raddr.ip
                                # Пропускаем локальные
                                if not ip.startswith(('127.', '192.168.', '10.', '0.')):
                                    if ip not in self.captured_ips:
                                        self.captured_ips.add(ip)
                                        self.after(0, lambda i=ip: self.ip_listbox.insert(0, i))
                                        self.after(0, lambda: self.lbl_count.config(text=f"Найдено IP: {len(self.captured_ips)}"))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass
            
            time.sleep(0.2) # Чаще опрос для игр

    def save_to_file(self):
        if not self.captured_ips: return

        filename = self.entry_filename.get().strip()
        if not filename.endswith(".txt"): filename += ".txt"
        
        ipsets_dir = os.path.join(self.app_dir, 'ipsets')
        os.makedirs(ipsets_dir, exist_ok=True)
        target_path = os.path.join(ipsets_dir, filename)
        
        # Режим добавления или перезаписи
        mode = 'w'
        if os.path.exists(target_path):
            if not messagebox.askyesno("Файл существует", f"Файл {filename} уже существует.\nПерезаписать? (Нет - добавить новые IP)"):
                mode = 'a'
                # Подгружаем старые чтобы не дублировать
                try:
                    with open(target_path, 'r') as f:
                        for line in f:
                            self.captured_ips.add(line.strip())
                except: pass

        try:
            with open(target_path, mode, encoding='utf-8') as f:
                if mode == 'w':
                    f.write(f"# IPSet for {self.selected_name}\n")
                
                # Сортируем и пишем
                for ip in sorted(list(self.captured_ips)):
                    if ip and not ip.startswith('#'):
                        f.write(ip + "\n")
            
            messagebox.showinfo("Успех", f"Сохранено в {filename}")
            if self.on_save_callback:
                self.on_save_callback() # Обновить списки в главной таблице
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить: {e}")