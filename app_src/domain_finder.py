import tkinter as tk
from tkinter import scrolledtext, messagebox, Toplevel, Text, Button, Frame, Label, ttk
import threading
import subprocess
import sys
import os
import re
from urllib.parse import urlparse

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

def is_media_url(url):
    """Проверяет, является ли URL прямой ссылкой на медиафайл"""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Расширения медиафайлов
        media_extensions = [
            '.mp4', '.webm', '.avi', '.mov', '.flv', '.wmv', '.mkv',
            '.mp3', '.wav', '.ogg', '.flac', '.aac',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'
        ]
        
        # Проверяем расширение файла
        for ext in media_extensions:
            if path.endswith(ext):
                return True
                
        # Проверяем параметры URL, характерные для медиа
        query = parsed.query.lower()
        if 'rate=' in query and 'hash=' in query:
            return True
            
        # Проверяем домены, известные как хостинги медиа
        media_domains = [
            'phncdn.com', 'cdn', 'media', 'video', 'stream'
        ]
        
        for domain in media_domains:
            if domain in parsed.netloc.lower():
                return True
                
        return False
    except:
        return False

def extract_domain_from_url(url):
    """Извлекает домен из URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def analyze_site_domains_performance(url: str, log_callback):
    """Анализ через Performance API (JavaScript)"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import TimeoutException
        from urllib.parse import urlparse
        import json
        import time

        log_callback("Использую Performance API...")
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Добавляю домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")  # Используем новый режим headless
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")  # Для предотвращения проблем с ресурсами
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")  # Убираем флаг автоматизации
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        driver = None
        try:
            driver = webdriver.Chrome(options=chrome_options)
            # Устанавливаем таймаут для загрузки страницы в 30 секунд
            driver.set_page_load_timeout(30)
            
            log_callback(f"Перехожу на {url}...")
            try:
                driver.get(url)
            except TimeoutException:
                log_callback("ПРЕДУПРЕЖДЕНИЕ: Страница не загрузилась за 30 секунд.")
                log_callback("Это может означать, что сайт блокирует доступ автоматических браузеров.")
                log_callback("Попробую найти домены на том, что успело загрузиться...")
            
            log_callback("Жду 7 секунд для загрузки всех ресурсов...")
            time.sleep(7)
            
            # Выполняем JavaScript код для получения доменов
            script = """
            window.domains = [...new Set(performance.getEntriesByType('resource').map(r => (new URL(r.name)).hostname))];
            return window.domains;
            """
            
            domains = driver.execute_script(script)
            
            if domains:
                # Удаляем дубликаты и сортируем
                unique_domains = sorted(list(set(domains)))
                log_callback(f"Найдено доменов: {len(unique_domains)}")
                return unique_domains
            else:
                log_callback("Не удалось получить домены через Performance API (возможно, ничего не загрузилось).")
                return None
            
        finally:
            if driver:
                driver.quit()
    except Exception as e:
        log_callback(f"ОШИБКА Performance API: {str(e)}")
        return None

def analyze_site_domains_selenium(url: str, log_callback):
    """Анализ через Selenium"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from urllib.parse import urlparse
        import json
        import time

        log_callback("Использую Selenium...")
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Добавляю домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
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
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Добавляю домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
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
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Добавляю домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
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