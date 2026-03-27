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
        """Добавляет найденные домены в список, исключая дубликаты и домены из списков блокировки."""
        try:
            log_callback = self.domain_log
            custom_list_path = self.app.list_manager.get_custom_list_path()
            
            log_callback(f"[INFO] 🔍 Начало обработки доменов. Получено {len(new_domains)} доменов для проверки.")
            
            if not custom_list_path:
                log_callback("[WARN] ⚠ Кастомный список не указан в настройках.")
                log_callback("[WARN] ⚠ Домены найдены, но НЕ сохранены.")
                return
            
            if not os.path.exists(custom_list_path):
                log_callback(f"[WARN] ⚠ Файл списка не найден по пути: {custom_list_path}")
                log_callback("[WARN] ⚠ Укажите существующий файл в настройках.")
                return
            
            log_callback(f"[INFO] 📂 Чтение текущего кастомного списка: {custom_list_path}")
            
            # Чтение текущего кастомного списка
            existing_domains_set = set()
            existing_lines = []
            try:
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_lines.append(line)
                            existing_domains_set.add(line)
                        elif line.startswith('#'):
                            log_callback(f"[DEBUG] 📝 Комментарий в строке {line_num}: {line[:50]}...")
            except Exception as e:
                log_callback(f"[ERROR] ❌ Ошибка чтения файла списка: {e}")
                return
                
            log_callback(f"[INFO] 📊 Прочитано {len(existing_lines)} доменов из кастомного списка.")
 
            # Пути к спискам блокировки
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lists_dir = os.path.join(base_dir, 'lists')
            exclude_dir = os.path.join(base_dir, 'exclude')
            list_google_path = os.path.join(lists_dir, 'list-google.txt')
            list_general_path = os.path.join(lists_dir, 'list-general.txt')
            list_exclude_path = os.path.join(exclude_dir, 'list-exclude.txt')
            list_exclude_user_path = os.path.join(exclude_dir, 'list-exclude-user.txt')
            
            log_callback(f"[INFO] 🔒 Загрузка списков блокировки: {list_google_path}, {list_general_path}, {list_exclude_path}, {list_exclude_user_path}")
            
            blocked_domains_set = set()
            # Читаем list-google.txt
            try:
                with open(list_google_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blocked_domains_set.add(line)
                        elif line.startswith('#'):
                            log_callback(f"[DEBUG] 📝 Комментарий в списке блокировки Google строка {line_num}: {line[:50]}...")
            except Exception as e:
                log_callback(f"[WARN] ⚠ Ошибка чтения {list_google_path}: {e}")
                # Не прерываем, просто продолжаем без этого списка
            
            # Читаем list-general.txt
            try:
                with open(list_general_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blocked_domains_set.add(line)
                        elif line.startswith('#'):
                            log_callback(f"[DEBUG] 📝 Комментарий в общем списке блокировки строка {line_num}: {line[:50]}...")
            except Exception as e:
                log_callback(f"[WARN] ⚠ Ошибка чтения {list_general_path}: {e}")
            
            # Читаем list-exclude.txt
            try:
                with open(list_exclude_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blocked_domains_set.add(line)
                        elif line.startswith('#'):
                            log_callback(f"[DEBUG] 📝 Комментарий в списке исключений строка {line_num}: {line[:50]}...")
            except Exception as e:
                log_callback(f"[WARN] ⚠ Ошибка чтения {list_exclude_path}: {e}")
            
            # Читаем list-exclude-user.txt
            try:
                with open(list_exclude_user_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blocked_domains_set.add(line)
                        elif line.startswith('#'):
                            log_callback(f"[DEBUG] 📝 Комментарий в пользовательском списке исключений строка {line_num}: {line[:50]}...")
            except Exception as e:
                log_callback(f"[WARN] ⚠ Ошибка чтения {list_exclude_user_path}: {e}")
            
            log_callback(f"[INFO] 🔒 Загружено {len(blocked_domains_set)} уникальных доменов в списки блокировки.")
 
            # Определяем домены, которые нужно оставить (не в блокировке)
            kept_existing = []
            removed_blocked = 0
            removed_duplicates = 0
            seen = set()
            
            log_callback("[INFO] 🔄 Фильтрация существующих доменов (удаление дубликатов и заблокированных)...")
            for domain in existing_lines:
                if domain in blocked_domains_set:
                    removed_blocked += 1
                    log_callback(f"[DEBUG] 🗑 Удален заблокированный домен: {domain}")
                    continue
                if domain in seen:
                    removed_duplicates += 1
                    log_callback(f"[DEBUG] 🗑 Удален дубликат: {domain}")
                    continue
                seen.add(domain)
                kept_existing.append(domain)
 
            log_callback(f"[INFO] ✅ После фильтрации осталось {len(kept_existing)} доменов. Удалено: {removed_duplicates} дубликатов, {removed_blocked} заблокированных.")
 
            # Обрабатываем новые домены
            added_domains = []
            log_callback("[INFO] 🔄 Обработка новых доменов...")
            for domain in new_domains:
                clean_domain = extract_domain_from_url(domain)
                if not clean_domain:
                    log_callback(f"[WARN] ⚠ Не удалось извлечь домен из: {domain}")
                    continue
                if clean_domain in blocked_domains_set:
                    log_callback(f"[DEBUG] 🗑 Новый домен заблокирован, пропускаем: {clean_domain}")
                    continue
                if clean_domain in seen:
                    log_callback(f"[DEBUG] 🗑 Новый домен уже существует (дубликат), пропускаем: {clean_domain}")
                    continue
                seen.add(clean_domain)
                added_domains.append(clean_domain)
                log_callback(f"[INFO]   + {clean_domain}")
 
            if not added_domains and removed_blocked == 0 and removed_duplicates == 0:
                log_callback("[INFO] ℹ️ Новых доменов не найдено (все уже есть в выбранном списке или заблокированы).")
                return
 
            # Формируем новый список: оставшиеся существующие + новые
            new_lines = kept_existing + added_domains
            log_callback(f"[INFO] 📋 Формирование нового списка: {len(kept_existing)} существующих + {len(added_domains)} новых = {len(new_lines)} всего.")
 
            # Записываем обратно в файл
            try:
                log_callback(f"[INFO] 💾 Запись обновленного списка в файл: {custom_list_path}")
                with open(custom_list_path, 'w', encoding='utf-8') as f:
                    for line in new_lines:
                        f.write(line + '\n')
                log_callback("[INFO] ✅ Файл успешно записан.")
            except Exception as e:
                log_callback(f"[ERROR] ❌ Ошибка записи файла списка: {e}")
                return
 
            # Логируем результаты
            if removed_duplicates > 0:
                log_callback(f"[WARN] ⚠ Удалено {removed_duplicates} дубликатов из кастомного списка.")
            if removed_blocked > 0:
                log_callback(f"[WARN] ⚠ Удалено {removed_blocked} доменов, присутствующих в списках блокировки.")
            if added_domains:
                log_callback(f"[INFO] ✓ Добавлено {len(added_domains)} новых доменов в {os.path.basename(custom_list_path)}")
            else:
                log_callback(f"[INFO] ✓ Очистка кастомного списка завершена. Удалено дубликатов: {removed_duplicates}, заблокированных: {removed_blocked}.")
 
            log_callback(f"[INFO] 🏁 Обработка доменов завершена. Итоговый список содержит {len(new_lines)} доменов.")
            self.app.root.after(0, self._propose_restart_after_domain_update)
         
        except Exception as e:
            log_callback(f"[ERROR] ❌ КРИТИЧЕСКАЯ ОШИБКА при сохранении доменов: {e}")
            import traceback
            log_callback(f"[ERROR] 📋 Трассировка: {traceback.format_exc()}")
    
    def _propose_restart_after_domain_update(self):
        if self.app.active_processes:
            if messagebox.askyesno("Обновление", "Домены добавлены. Чтобы изменения вступили в силу, нужно перезапустить процессы.\n\nОстановить все текущие процессы?"):
                self.app.stop_process()