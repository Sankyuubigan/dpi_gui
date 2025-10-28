import os
import threading
import queue
import datetime
import tkinter as tk
from tkinter import messagebox
from domain_finder import check_dependencies, analyze_site_domains_performance, analyze_site_domains_playwright, analyze_site_domains_selenium, analyze_site_domains_simple, extract_domain_from_url

class DomainManager:
    """Класс для управления анализом доменов"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.domain_analysis_thread = None
        self.domain_log_queue = queue.Queue()
        self.domain_method_map = {}
        self.domain_method_var = None
        self.domain_url_entry = None
        self.domain_start_btn = None
        self.domain_method_combo = None
        
    def create_domains_tab(self, parent):
        """Создает вкладку для анализа доменов"""
        # Метод анализа
        method_frame = tk.LabelFrame(parent, text="Метод анализа")
        method_frame.pack(fill=tk.X, pady=5)

        self.domain_method_var = tk.StringVar()
        method_choices = []
        self.domain_method_map = {}
        
        available_methods = check_dependencies()

        if available_methods.get('selenium', False):
            display_name = "Performance API (рекомендуется)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "performance"

        if available_methods.get('simple', False):
            display_name = "Simple Parser (без браузера)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "simple"

        if available_methods.get('playwright', False):
            display_name = "Playwright (быстрый, современный)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "playwright"
        
        if available_methods.get('selenium', False):
            display_name = "Selenium (классический)"
            method_choices.append(display_name)
            self.domain_method_map[display_name] = "selenium"
            
        if not method_choices:
            method_choices.append("Нет доступных методов")
            self.domain_method_map["Нет доступных методов"] = "none"
            
        self.domain_method_combo = tk.ttk.Combobox(method_frame, textvariable=self.domain_method_var, 
                                                   values=method_choices, state="readonly")
        self.domain_method_combo.pack(fill=tk.X, padx=5, pady=5)
        if method_choices:
            self.domain_method_combo.current(0)

        # URL сайта
        url_frame = tk.LabelFrame(parent, text="URL сайта для анализа")
        url_frame.pack(fill=tk.X, pady=5)
        self.domain_url_entry = tk.Entry(url_frame, width=60)
        self.domain_url_entry.pack(fill=tk.X, padx=5, pady=5)

        # Создаем контекстное меню для поля ввода URL
        self.domain_url_menu = tk.Menu(self.app.root, tearoff=0)
        self.domain_url_menu.add_command(label="Вставить", command=self.paste_domain_url)
        self.domain_url_entry.bind("<Button-3>", self.show_domain_url_menu)
        self.domain_url_entry.bind("<Control-v>", lambda e: self.paste_domain_url())
        
        # Кнопка анализа
        self.domain_start_btn = tk.ttk.Button(parent, text="🔍 Начать анализ и добавить домены", command=self.start_domain_analysis, state=tk.NORMAL)
        self.domain_start_btn.pack(pady=10)
        
        # Информационная метка о логах
        info_label = tk.Label(parent, text="Все логи анализа отображаются на вкладке 'Логи'", fg="gray")
        info_label.pack(pady=5)

    def show_domain_url_menu(self, event):
        """Показывает контекстное меню для поля ввода URL."""
        try:
            self.domain_url_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.domain_url_menu.grab_release()

    def paste_domain_url(self):
        """Вставляет текст из буфера обмена в поле ввода URL."""
        try:
            text = self.app.root.clipboard_get()
            self.domain_url_entry.delete(0, tk.END)
            self.domain_url_entry.insert(0, text)
        except tk.TclError:
            pass

    def domain_log(self, message):
        """Логирование для анализа доменов"""
        self.app.log_message(message, "domain")

    def start_domain_analysis(self):
        """Запускает анализ доменов"""
        url = self.domain_url_entry.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL!")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        method_text = self.domain_method_var.get()
        method = self.domain_method_map.get(method_text)
        if not method or method == "none":
            messagebox.showerror("Ошибка", "Выберите доступный метод анализа.")
            return
            
        # Блокируем кнопку на время анализа
        self.domain_start_btn.config(state=tk.DISABLED, text="⏳ Анализ...")
        
        self.domain_analysis_thread = threading.Thread(target=self.run_domain_analysis_loop, args=(url, method), daemon=True)
        self.domain_analysis_thread.start()

    def run_domain_analysis_loop(self, url, method):
        """Основной цикл анализа доменов"""
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            self.domain_log(f"=== ПОПЫТКА {attempt}/{max_attempts} ===")
            self.domain_log(f"Анализирую URL: {url}")
            self.domain_log(f"Метод анализа: {method}")
            
            domains = self.run_single_analysis(url, method)
            
            if domains:
                self.domain_log(f"✓ АНАЛИЗ УСПЕШЕН - НАЙДЕНО {len(domains)} ДОМЕН(ОВ)")
                self.domain_log("НАЧИНАЮ ДОБАВЛЕНИЕ В СПИСОК...")
                self.add_domains_to_list(domains)
                
                # Проверяем, было ли предупреждение о таймауте
                if "ПРЕДУПРЕЖДЕНИЕ: Страница не загрузилась за 30 секунд" in self.get_last_logs():
                    if attempt < max_attempts:
                        self.domain_log("Попытка завершилась по таймауту. Перезапускаю анализ...")
                        continue
                else:
                    self.domain_log("=== АНАЛИЗ УСПЕШНО ЗАВЕРШЕН ===")
                    break
            else:
                self.domain_log("✗ НЕ УДАЛОСЬ ПОЛУЧИТЬ ДОМЕНЫ НА ЭТОЙ ПОПЫТКЕ")
                if attempt < max_attempts:
                    self.domain_log("Перезапускаю анализ...")
                else:
                    self.domain_log("=== АНАЛИЗ НЕ УДАЛСЯ ПОСЛЕ НЕСКОЛЬКИХ ПОПЫТОК ===")

        # Разблокируем кнопку после завершения анализа
        self.app.root.after(0, lambda: self.domain_start_btn.config(state=tk.NORMAL, text="🔍 Начать анализ и добавить домены"))

    def get_last_logs(self):
        """Получает последние логи для проверки"""
        # Получаем последние 10 записей из логов
        recent_logs = self.app.ui_manager.all_logs[-10:] if hasattr(self.app.ui_manager, 'all_logs') else []
        return ' '.join([log['text'] for log in recent_logs])

    def run_single_analysis(self, url, method):
        """Запускает один анализ"""
        try:
            domains = None
            if method == "performance":
                domains = analyze_site_domains_performance(url, self.domain_log)
            elif method == "playwright":
                domains = analyze_site_domains_playwright(url, self.domain_log)
            elif method == "selenium":
                domains = analyze_site_domains_selenium(url, self.domain_log)
            elif method == "simple":
                domains = analyze_site_domains_simple(url, self.domain_log)
            else:
                self.domain_log("НЕИЗВЕСТНЫЙ МЕТОД")
            return domains
        except Exception as e:
            self.domain_log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
            return None

    def add_domains_to_list(self, new_domains):
        """Добавляет найденные домены в список с улучшенной обработкой"""
        try:
            log_callback = self.domain_log
            
            custom_list_path = self.app.list_manager.get_custom_list_path()
            if not custom_list_path:
                custom_list_path = os.path.join(self.app.app_dir, 'lists', 'custom_list.txt')
                log_callback(f"Кастомный список не выбран, использую стандартный: {custom_list_path}")
            
            existing_domains = set()
            if os.path.exists(custom_list_path):
                log_callback("Читаю существующий список доменов...")
                with open(custom_list_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            existing_domains.add(line)
                log_callback(f"Найдено существующих доменов: {len(existing_domains)}")
            else:
                log_callback("Создаю новый файл списка доменов...")
            
            added_domains = []
            skipped_domains = []
            invalid_domains = []
            
            log_callback("Анализирую найденные домены:")
            for domain in new_domains:
                # Дополнительная очистка и проверка домена
                clean_domain = extract_domain_from_url(domain)
                
                if not clean_domain:
                    invalid_domains.append(domain)
                    log_callback(f"  ✗ {domain} (НЕКОРРЕКТНЫЙ ДОМЕН)")
                    continue
                    
                if clean_domain in existing_domains:
                    skipped_domains.append(clean_domain)
                    log_callback(f"  - {clean_domain} (УЖЕ ЕСТЬ В СПИСКЕ)")
                else:
                    added_domains.append(clean_domain)
                    log_callback(f"  + {clean_domain} (НОВЫЙ ДОМЕН)")
            
            # Сообщаем о некорректных доменах
            if invalid_domains:
                log_callback(f"⚠ ОБНАРУЖЕНО {len(invalid_domains)} НЕКОРРЕКТНЫХ ДОМЕНОВ, КОТОРЫЕ БЫЛИ ПРОПУЩЕНЫ")
            
            if not added_domains:
                log_callback("НОВЫХ ДОМЕНОВ ДЛЯ ДОБАВЛЕНИЯ НЕ НАЙДЕНО")
                if skipped_domains:
                    log_callback(f"Все найденные домены уже существуют в списке ({len(skipped_domains)} шт.)")
                return
            
            log_callback(f"ДОБАВЛЯЮ {len(added_domains)} НОВЫХ ДОМЕНОВ В СПИСОК...")
            
            all_domains = sorted(list(existing_domains.union(set(added_domains))))
            
            with open(custom_list_path, 'w', encoding='utf-8') as f:
                f.write("# Это ваш личный список доменов. Добавляйте по одному домену на строку.\n")
                f.write("# Строки, начинающиеся с #, игнорируются.\n")
                f.write(f"# Обновлено: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#\n")
                for domain in all_domains:
                    f.write(domain + '\n')
            
            log_callback(f"✓ УСПЕШНО ДОБАВЛЕНО {len(added_domains)} НОВЫХ ДОМЕНОВ:")
            for domain in added_domains:
                log_callback(f"  ✓ {domain}")
            
            log_callback(f"✓ ОБЩЕЕ КОЛИЧЕСТВО ДОМЕНОВ В СПИСКЕ: {len(all_domains)}")
            
            self.app.root.after(0, self._propose_restart_after_domain_update)

        except Exception as e:
            self.domain_log(f"ОШИБКА при добавлении доменов: {e}")
            self.app._handle_ui_error(e)

    def _propose_restart_after_domain_update(self):
        """Предлагает перезапустить профиль после обновления списка доменов."""
        import process_manager
        if process_manager.is_process_running():
            if messagebox.askyesno(
                "Перезапустить профиль?",
                "Новые домены добавлены. Для их применения требуется перезапустить профиль.\n\nСделать это сейчас?"
            ):
                self.domain_log("Перезапускаю профиль для применения новых доменов...")
                self.app.stop_process()
                self.app.root.after(1500, self.app.run_selected_profile)