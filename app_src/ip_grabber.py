import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import socket
import os

class IPGrabberWindow(tk.Toplevel):
    def __init__(self, parent, app_dir, log_callback, on_save_callback):
        super().__init__(parent)
        self.app_dir = app_dir
        self.log_callback = log_callback
        self.on_save_callback = on_save_callback
        
        self.title("Создание IPSet из процесса")
        self.geometry("600x500")
        
        self.selected_pid = None
        self.selected_name = None
        self.is_capturing = False
        self.captured_ips = set()
        self.capture_thread = None
        
        self.create_widgets()
        self.refresh_processes()

    def create_widgets(self):
        # --- Верхняя часть: Выбор процесса ---
        top_frame = ttk.LabelFrame(self, text="1. Выберите процесс")
        top_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Поиск:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_processes)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(search_frame, text="Обновить список", command=self.refresh_processes).pack(side=tk.RIGHT)

        # Список процессов
        tree_frame = ttk.Frame(top_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(tree_frame, columns=("PID", "Name"), show="headings", height=10)
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Имя процесса")
        self.tree.column("PID", width=60)
        self.tree.column("Name", width=400)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_process_select)

        # --- Нижняя часть: Захват ---
        bottom_frame = ttk.LabelFrame(self, text="2. Захват IP-адресов")
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        control_frame = ttk.Frame(bottom_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_start = ttk.Button(control_frame, text="Начать захват", command=self.toggle_capture, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.lbl_status = ttk.Label(control_frame, text="Выберите процесс выше", foreground="gray")
        self.lbl_status.pack(side=tk.LEFT, padx=5)
        
        self.btn_save = ttk.Button(control_frame, text="Сохранить в файл", command=self.save_to_file, state=tk.DISABLED)
        self.btn_save.pack(side=tk.RIGHT, padx=5)

        # Список пойманных IP
        self.ip_listbox = tk.Listbox(bottom_frame, height=8)
        self.ip_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

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
        # Если идет захват, запрещаем менять выбор
        if self.is_capturing:
            return

        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            self.selected_pid = item['values'][0]
            self.selected_name = item['values'][1]
            self.btn_start.config(state=tk.NORMAL)
            self.lbl_status.config(text=f"Цель: все процессы '{self.selected_name}'")
        else:
            self.selected_pid = None
            self.selected_name = None
            self.btn_start.config(state=tk.DISABLED)

    def toggle_capture(self):
        if not self.is_capturing:
            # Старт
            self.is_capturing = True
            self.btn_start.config(text="Остановить захват")
            
            # Treeview не поддерживает state=DISABLED, поэтому просто не даем менять выбор в on_process_select
            
            self.captured_ips.clear()
            self.ip_listbox.delete(0, tk.END)
            self.lbl_status.config(text=f"Сканирую ВСЕ процессы {self.selected_name}...", foreground="green")
            
            self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
            self.capture_thread.start()
        else:
            # Стоп
            self.is_capturing = False
            self.btn_start.config(text="Начать захват")
            
            self.lbl_status.config(text=f"Захват остановлен. Найдено уникальных IP: {len(self.captured_ips)}", foreground="black")
            if self.captured_ips:
                self.btn_save.config(state=tk.NORMAL)

    def capture_loop(self):
        target_name = self.selected_name
        
        while self.is_capturing:
            try:
                # Ищем ВСЕ процессы с таким именем
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
                        connections = proc.connections(kind='inet')
                        for conn in connections:
                            if conn.raddr:
                                ip = conn.raddr.ip
                                # Фильтр локальных IP
                                if not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('0.'):
                                    if ip not in self.captured_ips:
                                        self.captured_ips.add(ip)
                                        self.after(0, lambda i=ip: self.ip_listbox.insert(0, i))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
            except Exception as e:
                print(f"Error grabbing: {e}")
            
            time.sleep(0.5)

    def save_to_file(self):
        if not self.captured_ips:
            return

        default_name = f"ipset-{self.selected_name.replace('.exe', '')}.txt"
        ipsets_dir = os.path.join(self.app_dir, 'ipsets')
        os.makedirs(ipsets_dir, exist_ok=True)
        
        target_path = os.path.join(ipsets_dir, default_name)
        
        mode = 'w'
        if os.path.exists(target_path):
            if messagebox.askyesno("Файл существует", f"Файл {default_name} уже существует.\nДа - перезаписать полностью.\nНет - добавить новые IP к существующим."):
                mode = 'w'
            else:
                mode = 'a'
                # Читаем старые, чтобы не дублировать
                try:
                    with open(target_path, 'r') as f:
                        for line in f:
                            self.captured_ips.add(line.strip())
                except: pass

        try:
            with open(target_path, mode, encoding='utf-8') as f:
                if mode == 'w':
                    f.write(f"# Auto-generated IPSet for {self.selected_name}\n")
                
                sorted_ips = sorted(list(self.captured_ips))
                for ip in sorted_ips:
                    if ip and not ip.startswith('#'):
                        f.write(ip + "\n")
            
            messagebox.showinfo("Успех", f"Сохранено {len(self.captured_ips)} IP в файл:\n{default_name}")
            
            if self.on_save_callback:
                self.on_save_callback()
                
            self.destroy()
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

def show_ip_grabber(parent, app_dir, log_callback, on_save_callback):
    window = IPGrabberWindow(parent, app_dir, log_callback, on_save_callback)
    window.grab_set()