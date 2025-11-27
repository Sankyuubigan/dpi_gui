import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess
import sys
import os
import re
from urllib.parse import urlparse
import gc
import psutil
import json
import time

def check_dependencies():
    """Проверяет наличие Selenium для Performance API"""
    available = {}
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        available['selenium'] = True
    except ImportError:
        available['selenium'] = False
    return available

def is_media_url(url):
    """Проверяет, является ли URL прямой ссылкой на медиафайл"""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        media_extensions = [
            '.mp4', '.webm', '.avi', '.mov', '.flv', '.wmv', '.mkv',
            '.mp3', '.wav', '.ogg', '.flac', '.aac',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'
        ]
        
        for ext in media_extensions:
            if path.endswith(ext):
                return True
                
        query = parsed.query.lower()
        if 'rate=' in query and 'hash=' in query:
            return True
            
        # Убрана проверка по ключевым словам в домене (video, media и т.д.),
        # так как она ложно срабатывала на сайты в зонах .video, .media и т.д.
        
        return False
    except:
        return False

def extract_domain_from_url(url):
    """Извлекает чистый домен из URL, убирает www и IP-адреса"""
    try:
        if not url:
            return None

        # Если передан просто домен без протокола
        if not url.startswith(('http://', 'https://', '//')):
            if '://' not in url:
                url = 'http://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Если не удалось извлечь через urlparse (например, кривой url)
        if not domain:
            # Пытаемся найти паттерн домена регуляркой
            match = re.search(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', url)
            if match:
                domain = match.group(0).lower()
            else:
                return None

        # Удаляем порт, если он есть (например site.com:8080)
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Удаляем префикс www.
        if domain.startswith('www.'):
            domain = domain[4:]

        # Фильтрация IP-адресов (нам нужны только доменные имена)
        # Проверка на IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return None

        # Базовая валидация
        # 1. Должна быть точка
        # 2. Длина более 3 символов (x.ru = 4, но com - 3, но com не домен для списка)
        if '.' not in domain or len(domain) < 4:
            return None
            
        # 3. Проверка на допустимые символы (буквы, цифры, дефис, точка)
        # Это отсеивает всякий мусор из JS кода
        if not re.match(r'^[a-z0-9\-\.]+$', domain):
            return None
            
        return domain
    except:
        return None

def cleanup_browser_resources():
    """Очищает ресурсы браузеров"""
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and ('chrome' in proc.info['name'].lower() or 'chromium' in proc.info['name'].lower()):
                    if proc.pid != os.getpid():
                        proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        gc.collect()
    except Exception as e:
        print(f"Ошибка при очистке ресурсов: {e}")

def extract_domains_from_js(js_content):
    """Извлекает домены из JavaScript кода"""
    domains = set()
    # Паттерны для поиска ссылок
    patterns = [
        r'["\']https?://([^"\']+)["\']',
        r'["\']//([^"\']+)["\']',
        r'api\s*:\s*["\']https?://([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            domain = extract_domain_from_url(match)
            if domain:
                domains.add(domain)
    return domains

def extract_domains_from_html(html_content):
    """Извлекает домены из HTML контента"""
    domains = set()
    tag_patterns = [
        r'src=["\']https?://([^"\']+)["\']',
        r'href=["\']https?://([^"\']+)["\']',
        r'action=["\']https?://([^"\']+)["\']',
    ]
    
    for pattern in tag_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            domain = extract_domain_from_url(match)
            if domain:
                domains.add(domain)
    return domains

def analyze_site_domains_performance(url: str, log_callback):
    """Анализ через Performance API (единственный оставшийся метод)"""
    driver = None
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import TimeoutException, WebDriverException
        import json
        import time

        log_callback("Использую Performance API с расширенным анализом...")
        
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Найден домен: {domain}")
                return [domain]
            return None
        
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ОСНОВНОЙ ДОМЕН ИЗ URL: {main_domain}")
        
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--ignore-certificate-errors")
        
        # Включаем логирование
        chrome_options.set_capability('goog:loggingPrefs', {
            'performance': 'ALL',
            'browser': 'ALL',
            'network': 'ALL'
        })
        
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(60)
            
            log_callback(f"Перехожу на {url}...")
            try:
                driver.get(url)
                log_callback("✓ Страница загружена")
            except TimeoutException:
                log_callback("ПРЕДУПРЕЖДЕНИЕ: Таймаут загрузки, анализирую то, что есть...")
            except WebDriverException as e:
                log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Ошибка загрузки: {str(e)[:100]}...")
            
            all_domains = set()
            if main_domain:
                all_domains.add(main_domain)
            
            def collect_domains_from_logs():
                domains_found = set()
                try:
                    logs = driver.get_log('performance')
                    for entry in logs:
                        try:
                            log_entry = json.loads(entry['message'])
                            message = log_entry.get('message', {})
                            
                            target_url = ""
                            if message.get('method') == 'Network.requestWillBeSent':
                                target_url = message['params']['request']['url']
                            elif message.get('method') == 'Network.responseReceived':
                                target_url = message['params']['response']['url']
                            elif message.get('method') == 'Network.loadingFailed':
                                if 'request' in message['params']:
                                    target_url = message['params']['request'].get('url', '')

                            if target_url:
                                domain = extract_domain_from_url(target_url)
                                if domain:
                                    domains_found.add(domain)
                        except:
                            continue
                    return domains_found
                except Exception as e:
                    log_callback(f"Ошибка чтения логов: {e}")
                    return set()
            
            # Сбор логов в несколько этапов
            for i in range(1, 4):
                time.sleep(2)
                batch = collect_domains_from_logs()
                all_domains.update(batch)
                log_callback(f"✓ Этап {i}: найдено {len(batch)} новых записей")

            # Прокрутка для ленивой загрузки
            try:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(2)
                batch = collect_domains_from_logs()
                all_domains.update(batch)
            except:
                pass
            
            # Анализ HTML
            try:
                html_content = driver.page_source
                if html_content:
                    html_domains = extract_domains_from_html(html_content)
                    all_domains.update(html_domains)
            except:
                pass

            # Анализ JS скриптов
            try:
                script_elements = driver.find_elements("tag name", "script")
                js_content = ""
                for script in script_elements:
                    try:
                        src = script.get_attribute("src")
                        if src and not src.startswith('data:'):
                            domain = extract_domain_from_url(src)
                            if domain: all_domains.add(domain)
                        else:
                            content = script.get_attribute("innerHTML")
                            if content: js_content += content + "\n"
                    except:
                        continue
                
                if js_content:
                    js_domains = extract_domains_from_js(js_content)
                    all_domains.update(js_domains)
            except:
                pass

            if all_domains:
                # Финальная очистка списка
                unique_domains = sorted(list(all_domains))
                # Дополнительная проверка перед возвратом
                clean_unique_domains = []
                for d in unique_domains:
                    clean = extract_domain_from_url(d) # Повторная проверка
                    if clean and clean not in clean_unique_domains:
                        clean_unique_domains.append(clean)
                
                log_callback(f"Всего найдено уникальных доменов: {len(clean_unique_domains)}")
                return clean_unique_domains
            else:
                if main_domain:
                    return [main_domain]
                return None
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                cleanup_browser_resources()
                
    except Exception as e:
        log_callback(f"ОШИБКА Performance API: {str(e)}")
        cleanup_browser_resources()
        main_domain = extract_domain_from_url(url)
        if main_domain:
            return [main_domain]
        return None