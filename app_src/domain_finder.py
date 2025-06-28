import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import threading
import time
import json
from urllib.parse import urlparse

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

def analyze_site_domains(url: str, log_callback):
    """
    Analyzes a website to find all domains it communicates with using Selenium.
    This function is designed to be run in a separate thread.
    """
    if not SELENIUM_AVAILABLE:
        log_callback("ОШИБКА: Библиотека Selenium не установлена.\n"
                     "Пожалуйста, перезапустите лаунчер, чтобы он установил все зависимости.")
        return None

    log_callback("Запускаю браузер для анализа...")
    chrome_options = Options()
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        log_callback(f"Перехожу на {url}...")
        driver.get(url)
        log_callback("Жду 7 секунд для прогрузки всех ресурсов...")
        time.sleep(7)
        log_callback("Собираю сетевые логи...")
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
            except (KeyError, json.JSONDecodeError):
                continue
        
        log_callback(f"Найдено {len(domains)} уникальных доменов.")
        return sorted(list(domains))
    except WebDriverException as e:
        log_callback(f"\n!!! ОШИБКА SELENIUM !!!")
        log_callback("Возможные причины:")
        log_callback("1. Google Chrome не установлен или его версия устарела.")
        log_callback("2. Не удалось скачать или запустить chromedriver.")
        log_callback("3. Антивирус или файрвол блокирует запуск браузера.")
        log_callback(f"Техническая информация: {e.msg}")
        return None
    except Exception as e:
        log_callback(f"Произошла непредвиденная ошибка: {e}")
        return None
    finally:
        if driver:
            driver.quit()
        log_callback("Анализ завершен, браузер закрыт.")


class AnalysisDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None):
        self.url_var = tk.StringVar()
        self.result_domains = None
        self.analysis_thread = None
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text="Введите URL сайта для анализа (например, https://example.com):").pack(anchor="w")
        self.url_entry = tk.Entry(master, textvariable=self.url_var, width=50)
        self.url_entry.pack(padx=5, pady=5, fill="x", expand=True)
        
        tk.Label(master, text="Лог анализа:").pack(anchor="w", pady=(10, 0))
        self.log_text = scrolledtext.ScrolledText(master, height=15, width=70, state='disabled', bg='black', fg='white')
        self.log_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        return self.url_entry

    def buttons(self):
        box = tk.Frame(self)
        self.ok_button = tk.Button(box, text="Анализ", width=10, command=self.ok_pressed)
        self.ok_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.cancel_button = tk.Button(box, text="Закрыть", width=10, command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5, pady=5)
        box.pack()

    def log_message(self, message):
        if self.log_text.winfo_exists():
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.config(state='disabled')
            self.log_text.see(tk.END)

    def ok_pressed(self):
        url = self.url_var.get().strip()
        if not url.startswith(('http://', 'https://')):
            messagebox.showerror("Ошибка", "URL должен начинаться с http:// или https://", parent=self)
            return

        if self.analysis_thread and self.analysis_thread.is_alive():
            messagebox.showinfo("Информация", "Анализ уже запущен.", parent=self)
            return

        self.log_text.config(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.config(state='disabled')
        
        self.ok_button.config(state="disabled")
        self.cancel_button.config(text="Отмена")
        
        self.analysis_thread = threading.Thread(
            target=self.run_analysis, 
            args=(url,),
            daemon=True
        )
        self.analysis_thread.start()

    def run_analysis(self, url):
        self.result_domains = analyze_site_domains(url, self.log_message)
        if self.winfo_exists():
            self.parent.after(0, self.on_analysis_complete)

    def on_analysis_complete(self):
        if not self.winfo_exists(): return
        
        self.ok_button.config(state="normal")
        self.cancel_button.config(text="Закрыть")
        
        if self.result_domains is not None:
            self.log_message("\n--- УСПЕШНО ---")
            self.log_message(f"Нажмите 'Закрыть', чтобы добавить {len(self.result_domains)} доменов в custom_list.txt")
        else:
            self.log_message("\n--- НЕУДАЧА ---")
            self.log_message("Анализ не удался. Проверьте лог выше на наличие ошибок.")

    def cancel(self):
        if self.analysis_thread and self.analysis_thread.is_alive():
            messagebox.showwarning("Внимание", 
                                   "Процесс анализа работает в фоне и не может быть мгновенно остановлен. "
                                   "Окно закроется, но браузер может остаться активным на некоторое время.",
                                   parent=self)
        super().cancel()

    def apply(self):
        pass