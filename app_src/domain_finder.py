import tkinter as tk
from tkinter import scrolledtext, messagebox, Toplevel, Text, Button, Frame, Label, ttk
import threading
import subprocess
import sys
import os

def check_dependencies():
    """Проверяет какие библиотеки доступны"""
    available = {}
    
    # Проверяем Playwright
    try:
        from playwright.sync_api import sync_playwright
        available['playwright'] = True
    except ImportError:
        available['playwright'] = False
        
    # Проверяем Selenium
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        available['selenium'] = True
    except ImportError:
        available['selenium'] = False
        
    # Проверяем простые библиотеки
    try:
        import requests
        from bs4 import BeautifulSoup
        available['simple'] = True
    except ImportError:
        available['simple'] = False
        
    return available

def analyze_site_domains_selenium(url: str, log_callback):
    """Анализ через Selenium"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from urllib.parse import urlparse
        import json
        import time

        log_callback("Использую Selenium...")
        chrome_options = Options()
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        
        driver = None
        try:
            driver = webdriver.Chrome(options=chrome_options)
            log_callback(f"Перехожу на {url}...")
            driver.get(url)
            log_callback("Жду 7 секунд для загрузки...")
            time.sleep(7)
            
            logs = driver.get_log('performance')
            domains = set()
            
            for entry in logs:
                try:
                    log = json.loads(entry['message'])['message']
                    if log['method'] == 'Network.requestWillBeSent':
                        request_url = log['params']['request']['url']
                        domain = urlparse(request_url).netloc
                        if domain:
                            domains.add(domain)
                except:
                    continue
            
            found_domains = sorted(list(domains))
            log_callback(f"Найдено доменов: {len(found_domains)}")
            return found_domains
            
        finally:
            if driver:
                driver.quit()
    except Exception as e:
        log_callback(f"ОШИБКА Selenium: {str(e)}")
        return None

def analyze_site_domains_playwright(url: str, log_callback):
    """Анализ через Playwright"""
    try:
        from playwright.sync_api import sync_playwright
        from urllib.parse import urlparse
        
        log_callback("Использую Playwright...")
        
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception as e:
                log_callback(f"Не удалось запустить браузер Playwright: {e}")
                log_callback("Попробуйте перезапустить программу, чтобы лаунчер установил браузеры.")
                return None

            page = browser.new_page()
            
            domains = set()
            
            def handle_request(request):
                try:
                    domain = urlparse(request.url).netloc
                    if domain:
                        domains.add(domain)
                except:
                    pass
            
            page.on("request", handle_request)
            
            log_callback(f"Перехожу на {url}...")
            try:
                page.goto(url, wait_until='networkidle', timeout=30000)
            except Exception as e:
                log_callback(f"Не удалось дождаться полной загрузки, но продолжаю: {e}")

            log_callback("Жду дополнительно 5 секунд...")
            page.wait_for_timeout(5000)
            
            browser.close()
            
            found_domains = sorted(list(domains))
            log_callback(f"Найдено доменов: {len(found_domains)}")
            return found_domains
            
    except Exception as e:
        log_callback(f"ОШИБКА Playwright: {str(e)}")
        return None

def analyze_site_domains_simple(url: str, log_callback):
    """Анализ через requests + BeautifulSoup (без браузера)"""
    try:
        import requests
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, urljoin
        import re
        
        log_callback("Использую простой парсер (requests + BeautifulSoup)...")
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        log_callback(f"Загружаю {url}...")
        response = session.get(url, timeout=20, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        domains = set([urlparse(url).netloc])
        
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame', 'source']):
            attr = None
            if tag.has_attr('href'): attr = 'href'
            elif tag.has_attr('src'): attr = 'src'
            
            if attr and tag[attr]:
                try:
                    full_url = urljoin(url, tag[attr])
                    domain = urlparse(full_url).netloc
                    if domain and '.' in domain:
                        domains.add(domain)
                except:
                    continue
        
        text_domains = re.findall(r'[\'"](https?://)?([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)[\'"]', response.text)
        for _, domain in text_domains:
            if domain and '.' in domain:
                domains.add(domain)
        
        found_domains = sorted(list(domains))
        log_callback(f"Найдено доменов: {len(found_domains)}")
        return found_domains
        
    except Exception as e:
        log_callback(f"ОШИБКА простого парсера: {str(e)}")
        return None


class ResultsDialog(Toplevel):
    def __init__(self, parent, domains, title="Найденные домены"):
        super().__init__(parent)
        self.domains = domains
        self.title(title)
        self.geometry("600x400")
        self.setup_ui()
        self.grab_set()
        
    def setup_ui(self):
        main_frame = Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        Label(main_frame, text=f"Найдено доменов: {len(self.domains)}", 
              font=("Arial", 12, "bold")).pack(pady=(0, 10))
        
        text_frame = Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.text_widget = Text(text_frame, wrap=tk.NONE, height=15)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_widget.config(yscrollcommand=scrollbar.set)
        
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Копировать", command=self.copy_selection)
        self.menu.add_command(label="Копировать все", command=self.copy_all)
        self.text_widget.bind("<Button-3>", self.show_menu)
        self.text_widget.bind("<Control-c>", lambda e: self.copy_selection())
        
        for domain in self.domains:
            self.text_widget.insert(tk.END, domain + "\n")
        self.text_widget.config(state=tk.DISABLED)
        
        button_frame = Frame(main_frame)
        button_frame.pack(pady=(10, 0))
        
        Button(button_frame, text="Добавить в custom_list.txt", 
               command=self.add_all_domains, bg="green", fg="white").pack(side=tk.LEFT, padx=5)
        Button(button_frame, text="Копировать все", 
               command=self.copy_all).pack(side=tk.LEFT, padx=5)
        Button(button_frame, text="Закрыть", 
               command=self.destroy).pack(side=tk.LEFT, padx=5)
        
    def show_menu(self, event):
        self.menu.post(event.x_root, event.y_root)
        
    def copy_selection(self):
        try:
            selection = self.text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selection)
        except tk.TclError:
            pass
            
    def copy_all(self):
        text = "\n".join(self.domains)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Готово", "Все домены скопированы в буфер обмена!")
        
    def add_all_domains(self):
        self.result = self.domains
        self.destroy()
        
    def show(self):
        self.wait_window()
        return getattr(self, 'result', None)


class DomainFinderWindow(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Поиск доменов на сайте")
        self.geometry("700x550")
        self.result_domains = None
        self.analysis_thread = None
        
        self.available_methods = check_dependencies()
        
        frame = tk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        method_frame = Frame(frame)
        method_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(method_frame, text="Метод анализа:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.method_var = tk.StringVar()
        method_choices = []
        self.method_map = {}

        if self.available_methods.get('simple', False):
            display_name = "Simple Parser (рекомендуется, без браузера)"
            method_choices.append(display_name)
            self.method_map[display_name] = "simple"

        if self.available_methods.get('playwright', False):
            display_name = "Playwright (быстрый, современный)"
            method_choices.append(display_name)
            self.method_map[display_name] = "playwright"
        
        if self.available_methods.get('selenium', False):
            display_name = "Selenium (классический)"
            method_choices.append(display_name)
            self.method_map[display_name] = "selenium"
            
        if not method_choices:
            method_choices.append("Нет доступных методов")
            self.method_map["Нет доступных методов"] = "none"
            
        self.method_combo = ttk.Combobox(method_frame, textvariable=self.method_var, 
                                        values=method_choices, state="readonly")
        self.method_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        if method_choices:
            self.method_combo.current(0)
        
        tk.Label(frame, text="URL сайта:").pack(anchor=tk.W)
        self.url_entry = tk.Entry(frame, width=60)
        self.url_entry.pack(fill=tk.X, pady=5)
        
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Вставить", command=self.paste)
        self.url_entry.bind("<Button-3>", self.show_menu)
        
        btn_frame = Frame(frame)
        btn_frame.pack(pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="🔍 Начать анализ", command=self.start_analysis, bg="#4CAF50", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="✖ Закрыть", command=self.destroy).pack(side=tk.LEFT, padx=5)
        
        tk.Label(frame, text="Лог:").pack(anchor=tk.W, pady=(10,0))
        self.log_text = scrolledtext.ScrolledText(frame, height=15, bg='black', fg='white', state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.log_menu = tk.Menu(self, tearoff=0)
        self.log_menu.add_command(label="Копировать", command=self.copy_log)
        self.log_text.bind("<Button-3>", self.show_log_menu)
        
    def show_menu(self, event):
        self.menu.post(event.x_root, event.y_root)
        
    def paste(self):
        try:
            text = self.clipboard_get()
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, text)
        except tk.TclError:
            pass
            
    def show_log_menu(self, event):
        self.log_menu.post(event.x_root, event.y_root)
        
    def copy_log(self):
        try:
            selection = self.log_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selection:
                self.clipboard_clear()
                self.clipboard_append(selection)
        except tk.TclError:
            pass
            
    def set_ui_state(self, state):
        """Включает/выключает элементы управления на время анализа."""
        self.start_btn.config(state=state)
        self.method_combo.config(state="readonly" if state == tk.NORMAL else tk.DISABLED)
        self.url_entry.config(state=state)

    def get_selected_method(self):
        selected_text = self.method_var.get()
        return self.method_map.get(selected_text)
            
    def log(self, message):
        def _log():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.config(state=tk.DISABLED)
            self.log_text.see(tk.END)
        if self.winfo_exists():
            self.after(0, _log)
        
    def start_analysis(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL!")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        method = self.get_selected_method()
        if not method or method == "none":
            messagebox.showerror("Ошибка", "Выберите доступный метод анализа. Если список пуст, перезапустите программу, чтобы лаунчер установил зависимости.")
            return
            
        self.set_ui_state(tk.DISABLED)
        self.start_btn.config(text="⏳ Анализ...")
        
        self.log(f"=== НАЧИНАЮ АНАЛИЗ (метод: {method.upper()}) ===")
        self.analysis_thread = threading.Thread(target=self.run_analysis, args=(url, method), daemon=True)
        self.analysis_thread.start()
        
    def run_analysis(self, url, method):
        try:
            domains = None
            if method == "playwright":
                domains = analyze_site_domains_playwright(url, self.log)
            elif method == "selenium":
                domains = analyze_site_domains_selenium(url, self.log)
            elif method == "simple":
                domains = analyze_site_domains_simple(url, self.log)
            else:
                self.log("НЕИЗВЕСТНЫЙ МЕТОД")
                
            if domains is not None and self.winfo_exists():
                self.after(0, lambda: self.show_results(domains))
            elif self.winfo_exists():
                self.after(0, self.analysis_failed)
        except Exception as e:
            if self.winfo_exists():
                self.after(0, lambda: self.log(f"КРИТИЧЕСКАЯ ОШИБКА: {e}"))
                self.after(0, self.analysis_failed)
                
    def show_results(self, domains):
        self.log(f"\n=== НАЙДЕНО {len(domains)} ДОМЕНОВ ===")
        
        results_dialog = ResultsDialog(self, domains)
        added_domains = results_dialog.show()
        
        if added_domains:
            self.result_domains = added_domains
            self.destroy()
        else:
            self.set_ui_state(tk.NORMAL)
            self.start_btn.config(text="🔍 Начать анализ")
        
    def analysis_failed(self):
        self.log("=== АНАЛИЗ НЕ УДАЛСЯ ===")
        self.set_ui_state(tk.NORMAL)
        self.start_btn.config(text="🔍 Начать анализ")


def show_domain_finder(parent):
    window = DomainFinderWindow(parent)
    window.grab_set()
    parent.wait_window(window)
    return window.result_domains