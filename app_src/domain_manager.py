import os
import threading
import queue
import datetime
import tkinter as tk
from tkinter import messagebox
from domain_finder import check_dependencies, analyze_site_domains_performance, extract_domain_from_url

class DomainManager:
    """Класс для управления анализом доменов"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.domain_analysis_thread = None
        self.domain_log_queue = queue.Queue()
        self.domain_url_entry = None
        self.domain_start_btn = None
        
    def create_domains_tab(self, parent):
        """Создает вкладку для анализа доменов"""
        # Инфо о методе
        info_frame = tk.LabelFrame(parent, text="Информация")
        info_frame.pack(fill=tk.X, pady=5)
        
        deps = check_dependencies()
        if deps.get('selenium', False):
            status_text = "Метод анализа: Performance API (Активен)"
            status_color = "green"
            self.method_available = True
        else:
            status_text = "Ошибка: Не найдены библиотеки для Performance API (Selenium)"
            status_color = "red"
            self.method_available = False
            
        tk.Label(info_frame, text=status_text, fg=status_color).pack(padx=5, pady=5)

        # URL сайта
        url_frame = tk.LabelFrame(parent, text="URL сайта для анализа")
        url_frame.pack(fill=tk.X, pady=5)
        self.domain_url_entry = tk.Entry(url_frame, width=60)
        self.domain_url_entry.pack(fill=tk.X, padx=5, pady=5)

        # Контекстное меню
        self.domain_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.domain_url_menu.add_command(label="Вставить", command=self.paste_domain_url)
        self.domain_url_entry.bind("<Button-3>", self.show_domain_url_menu)
        self.domain_url_entry.bind("<Control-v>", lambda e: self.paste_domain_url())
        
        # Кнопка анализа
        self.domain_start_btn = tk.ttk.Button(
            parent, 
            text="🔍 Начать анализ", 
            command=self.start_domain_analysis, 
            state=tk.NORMAL if self.method_available else tk.DISABLED
        )
        self.domain_start_btn.pack(pady=10)
        
        # Отображение текущего списка
        current_list = self.app.list_manager.get_custom_list_path()
        if current_list:
            list_status = f"Домены будут добавлены в: {os.path.basename(current_list)}"
        else:
            list_status = "ВНИМАНИЕ: Кастомный список не выбран. Домены НЕ будут сохранены."
            
        self.lbl_list_status = tk.Label(parent, text=list_status, fg="gray", font=("Segoe UI", 8))
        self.lbl_list_status.pack(pady=2)
        
        tk.Label(parent, text="Все логи анализа отображаются на вкладке 'Логи'", fg="gray").pack(pady=5)

    def update_list_status_label(self):
        """Обновляет надпись о том, куда сохраняются домены"""
        try:
            current_list = self.app.list_manager.get_custom_list_path()
            if current_list:
                self.lbl_list_status.config(text=f"Домены будут добавлены в: {os.path.basename(current_list)}", fg="blue")
            else:
                self.lbl_list_status.config(text="ВНИМАНИЕ: Кастомный список не выбран. Домены НЕ будут сохранены.", fg="red")
        except: pass

    def show_domain_url_menu(self, event):
        try:
            self.domain_url_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.domain_url_menu.grab_release()

    def paste_domain_url(self):
        try:
            text = self.app.root.clipboard_get()
            self.domain_url_entry.delete(0, tk.END)
            self.domain_url_entry.insert(0, text)
        except tk.TclError:
            pass

    def domain_log(self, message):
        self.app.log_message(message, "domain")

    def start_domain_analysis(self):
        """Запускает анализ доменов"""
        url = self.domain_url_entry.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL!")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        self.domain_start_btn.config(state=tk.DISABLED, text="⏳ Анализ...")
        self.domain_analysis_thread = threading.Thread(target=self.run_domain_analysis_loop, args=(url,), daemon=True)
        self.domain_analysis_thread.start()

    def run_domain_analysis_loop(self, url):
        """Основной цикл анализа"""
        self.domain_log(f"Анализирую URL: {url}")
        self.domain_log("Метод: Performance API")
        
        try:
            domains = analyze_site_domains_performance(url, self.domain_log)
            
            if domains:
                self.domain_log(f"✓ УСПЕХ - НАЙДЕНО {len(domains)} ДОМЕН(ОВ)")
                self.add_domains_to_list(domains)
            else:
                self.domain_log("✗ НЕ УДАЛОСЬ ПОЛУЧИТЬ ДОМЕНЫ")
        except Exception as e:
            self.domain_log(f"Критическая ошибка: {e}")

        self.app.root.after(0, lambda: self.domain_start_btn.config(state=tk.NORMAL, text="🔍 Начать анализ"))

    def add_domains_to_list(self, new_domains):
        """Добавляет найденные домены в список"""
        try:
            log_callback = self.domain_log
            custom_list_path = self.app.list_manager.get_custom_list_path()
            
            # ПРОВЕРКА: Если список не задан, просто выходим
            if not custom_list_path:
                log_callback("⚠ Кастомный список не указан в настройках.")
                log_callback("⚠ Домены найдены, но НЕ сохранены.")
                return

            if not os.path.exists(custom_list_path):
                log_callback(f"⚠ Файл списка не найден по пути: {custom_list_path}")
                log_callback("⚠ Укажите существующий файл в настройках.")
                return
            
            existing_domains = set()
            try:
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_domains.add(line)
            except Exception as e:
                log_callback(f"Ошибка чтения файла списка: {e}")
                return
            
            added_domains = []
            for domain in new_domains:
                clean_domain = extract_domain_from_url(domain)
                if not clean_domain: continue
                
                if clean_domain not in existing_domains:
                    added_domains.append(clean_domain)
                    log_callback(f"  + {clean_domain}")
            
            if not added_domains:
                log_callback("Новых доменов не найдено (все уже есть в выбранном списке).")
                return
            
            # Добавляем новые домены в конец файла
            with open(custom_list_path, 'a', encoding='utf-8') as f:
                f.write("\n") # Гарантируем новую строку
                for domain in added_domains:
                    f.write(domain + '\n')
            
            log_callback(f"✓ Добавлено {len(added_domains)} новых доменов в {os.path.basename(custom_list_path)}")
            self.app.root.after(0, self._propose_restart_after_domain_update)

        except Exception as e:
            self.domain_log(f"ОШИБКА при сохранении: {e}")

    def _propose_restart_after_domain_update(self):
        if self.app.active_processes:
            if messagebox.askyesno("Обновление", "Домены добавлены. Чтобы изменения вступили в силу, нужно перезапустить процессы.\n\nОстановить все текущие процессы?"):
                self.app.stop_process()