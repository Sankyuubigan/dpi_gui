import tkinter as tk
from tkinter import scrolledtext, messagebox, Toplevel, Text, Button, Frame, Label, ttk
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
    """Извлекает домен из URL с улучшенной обработкой"""
    try:
        # Если это не URL, а просто текст, пытаемся извлечь домен
        if not url.startswith(('http://', 'https://', '//')):
            # Проверяем, есть ли в тексте что-то похожее на домен
            domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)', url)
            if domain_match:
                return domain_match.group(1).lower()
            return None
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Удаляем порт, если он есть
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Проверяем, что это действительно домен (содержит точку и не слишком короткий)
        if '.' in domain and len(domain) > 3:
            return domain
            
        return None
    except:
        return None

def cleanup_browser_resources():
    """Очищает ресурсы браузеров для предотвращения утечек памяти"""
    try:
        # Закрываем все процессы chrome/chromium
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and ('chrome' in proc.info['name'].lower() or 'chromium' in proc.info['name'].lower()):
                    if proc.pid != os.getpid():  # Не убиваем свой процесс
                        proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Принудительная сборка мусора
        gc.collect()
        
    except Exception as e:
        print(f"Ошибка при очистке ресурсов: {e}")

def extract_domains_from_js(js_content):
    """Извлекает домены из JavaScript кода с улучшенной обработкой"""
    domains = set()
    
    # Ищем домены в строках
    # Шаблоны для поиска доменов в JS
    patterns = [
        r'["\']https?://([^"\']+)["\']',
        r'["\']//([^"\']+)["\']',
        r'url\s*:\s*["\']https?://([^"\']+)["\']',
        r'src\s*:\s*["\']https?://([^"\']+)["\']',
        r'href\s*:\s*["\']https?://([^"\']+)["\']',
        r'host\s*:\s*["\']([^"\']+)["\']',
        r'domain\s*:\s*["\']([^"\']+)["\']',
        r'server\s*:\s*["\']([^"\']+)["\']',
        r'endpoint\s*:\s*["\']https?://([^"\']+)["\']',
        r'api\s*:\s*["\']https?://([^"\']+)["\']',
        r'baseURL\s*:\s*["\']https?://([^"\']+)["\']',
        r'baseUrl\s*:\s*["\']https?://([^"\']+)["\']',
        r'ws://([^"\']+)["\']',
        r'wss://([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            # Извлекаем только домен, отбрасывая путь и параметры
            domain = extract_domain_from_url(match)
            if domain:
                domains.add(domain)
    
    # Ищем домены в переменных и объектах
    var_patterns = [
        r'var\s+(\w*[Dd]omain\w*)\s*=\s*["\']([^"\']+)["\']',
        r'let\s+(\w*[Hh]ost\w*)\s*=\s*["\']([^"\']+)["\']',
        r'const\s+(\w*[Ss]erver\w*)\s*=\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in var_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for var_name, value in matches:
            domain = extract_domain_from_url(value)
            if domain:
                domains.add(domain)
    
    return domains

def extract_domains_from_html(html_content):
    """Извлекает домены из HTML контента с улучшенной обработкой"""
    domains = set()
    
    # Ищем домены в атрибутах тегов
    tag_patterns = [
        r'<script[^>]+src=["\']https?://([^"\']+)["\']',
        r'<link[^>]+href=["\']https?://([^"\']+)["\']',
        r'<img[^>]+src=["\']https?://([^"\']+)["\']',
        r'<iframe[^>]+src=["\']https?://([^"\']+)["\']',
        r'<source[^>]+src=["\']https?://([^"\']+)["\']',
        r'<video[^>]+src=["\']https?://([^"\']+)["\']',
        r'<audio[^>]+src=["\']https?://([^"\']+)["\']',
        r'<form[^>]+action=["\']https?://([^"\']+)["\']',
        r'<a[^>]+href=["\']https?://([^"\']+)["\']',
    ]
    
    for pattern in tag_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            # Извлекаем только домен, отбрасывая путь и параметры
            domain = extract_domain_from_url(match)
            if domain:
                domains.add(domain)
    
    # Ищем домены в текстовом содержимом
    text_patterns = [
        r'connect to (https?://[^\s]+)',
        r'server at (https?://[^\s]+)',
        r'host: ([^\s]+)',
        r'domain: ([^\s]+)',
    ]
    
    for pattern in text_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            domain = extract_domain_from_url(match)
            if domain:
                domains.add(domain)
    
    return domains

def analyze_site_domains_performance(url: str, log_callback):
    """Анализ через Performance API с улучшенной обработкой ошибок"""
    driver = None
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import TimeoutException, WebDriverException, JavascriptException
        from urllib.parse import urlparse
        import json
        import time

        log_callback("Использую Performance API с расширенным анализом...")
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Найден домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
        # ВСЕГДА добавляем основной домен из URL
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ОСНОВНОЙ ДОМЕН ИЗ URL: {main_domain}")
        else:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Не удалось извлечь основной домен из URL")
        
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--allow-running-insecure-content")
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")
        chrome_options.add_argument("--memory-pressure-off")
        chrome_options.add_argument("--disable-session-crashed-bubble")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.add_argument("--disable-popup-blocking")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--ignore-ssl-errors")
        chrome_options.add_argument("--ignore-certificate-errors-spki-list")
        chrome_options.add_argument("--disable-background-timer-throttling")
        chrome_options.add_argument("--disable-backgrounding-occluded-windows")
        chrome_options.add_argument("--disable-renderer-backgrounding")
        chrome_options.add_argument("--disable-features=TranslateUI")
        chrome_options.add_argument("--disable-ipc-flooding-protection")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # Включаем расширенное логирование
        chrome_options.set_capability('goog:loggingPrefs', {
            'performance': 'ALL',
            'browser': 'ALL',
            'network': 'ALL',
            'driver': 'ALL'
        })
        
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(60)  # Увеличиваем таймаут
            
            log_callback(f"Перехожу на {url}...")
            page_loaded = False
            try:
                driver.get(url)
                page_loaded = True
                log_callback("✓ Страница загружена успешно")
            except TimeoutException:
                log_callback("ПРЕДУПРЕЖДЕНИЕ: Страница не загрузилась за 60 секунд.")
                log_callback("Это может означать, что сайт блокирует доступ автоматических браузеров.")
                log_callback("Попробую найти домены на том, что успело загрузиться...")
            except WebDriverException as e:
                log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Ошибка загрузки страницы: {str(e)[:100]}...")
                log_callback("Попробую найти домены в том, что загрузилось...")
            
            # ВСЕГДА добавляем основной домен к найденным
            all_domains = set()
            if main_domain:
                all_domains.add(main_domain)
                log_callback(f"✓ ДОБАВЛЕН ОСНОВНОЙ ДОМЕН: {main_domain}")
            
            # Создаем словарь для отслеживания запросов по ID
            request_urls = {}
            
            # Функция для сбора доменов из логов
            def collect_domains_from_logs():
                domains_found = set()
                try:
                    logs = driver.get_log('performance')
                    for entry in logs:
                        try:
                            log_entry = json.loads(entry['message'])
                            if 'message' not in log_entry:
                                continue
                                
                            log = log_entry['message']
                            
                            # Запоминаем URL запроса
                            if log['method'] == 'Network.requestWillBeSent':
                                request_id = log['params'].get('requestId', '')
                                request_url = log['params']['request']['url']
                                request_urls[request_id] = request_url
                                
                                # Извлекаем домен из URL запроса
                                domain = extract_domain_from_url(request_url)
                                if domain:
                                    domains_found.add(domain)
                                    
                            # Обрабатываем успешные ответы
                            elif log['method'] == 'Network.responseReceived':
                                request_id = log['params'].get('requestId', '')
                                response_url = log['params']['response']['url']
                                
                                # Обновляем URL в словаре
                                request_urls[request_id] = response_url
                                
                                # Извлекаем домен
                                domain = extract_domain_from_url(response_url)
                                if domain:
                                    domains_found.add(domain)
                                    
                            # Обрабатываем неудачные запросы (ВАЖНО!)
                            elif log['method'] == 'Network.loadingFailed':
                                request_id = log['params'].get('requestId', '')
                                
                                # Ищем URL по ID
                                failed_url = request_urls.get(request_id, '')
                                if not failed_url:
                                    # Пробуем найти URL в параметрах
                                    if 'request' in log['params']:
                                        failed_url = log['params']['request'].get('url', '')
                                
                                if failed_url:
                                    domain = extract_domain_from_url(failed_url)
                                    if domain:
                                        domains_found.add(domain)
                                        error_info = log['params'].get('errorText', 'Unknown error')
                                        log_callback(f"✓ Найден домен из неудачного запроса: {domain} ({error_info})")
                                        
                            # Дополнительные типы событий
                            elif log['method'] in ['Network.requestServedFromCache', 'Network.responseStarted']:
                                request_id = log['params'].get('requestId', '')
                                if request_id in request_urls:
                                    url = request_urls[request_id]
                                    domain = extract_domain_from_url(url)
                                    if domain:
                                        domains_found.add(domain)
                                        
                        except Exception as e:
                            # Игнорируем ошибки парсинга отдельных записей
                            continue
                    
                    return domains_found
                except Exception as e:
                    log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось получить сетевые логи: {str(e)[:50]}...")
                    return set()
            
            # Ждем и собираем домены несколько раз с интервалами
            log_callback("Начинаю сбор доменов с увеличенным временем ожидания...")
            
            # Первая сборка через 5 секунд
            time.sleep(5)
            domains_batch1 = collect_domains_from_logs()
            all_domains.update(domains_batch1)
            log_callback(f"✓ Первая порция: найдено {len(domains_batch1)} доменов")
            
            # Вторая сборка через 10 секунд
            time.sleep(5)
            domains_batch2 = collect_domains_from_logs()
            all_domains.update(domains_batch2)
            log_callback(f"✓ Вторая порция: найдено {len(domains_batch2)} доменов")
            
            # Третья сборка через 20 секунд
            time.sleep(10)
            domains_batch3 = collect_domains_from_logs()
            all_domains.update(domains_batch3)
            log_callback(f"✓ Третья порция: найдено {len(domains_batch3)} доменов")
            
            # Четвертая сборка через 30 секунд
            time.sleep(10)
            domains_batch4 = collect_domains_from_logs()
            all_domains.update(domains_batch4)
            log_callback(f"✓ Четвертая порция: найдено {len(domains_batch4)} доменов")
            
            # Пытаемся прокрутить страницу для активации ленивой загрузки
            try:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, 0);")
                time.sleep(2)
                
                # Финальная сборка после прокрутки
                domains_batch5 = collect_domains_from_logs()
                all_domains.update(domains_batch5)
                log_callback(f"✓ После прокрутки: найдено {len(domains_batch5)} доменов")
            except:
                pass
            
            # Дополнительный сбор логов из разных источников
            try:
                # Пробуем получить логи сети
                network_logs = driver.get_log('network')
                for entry in network_logs:
                    try:
                        # Ищем URL в сообщениях
                        url_match = re.search(r'https?://[^\s\']+', entry['message'])
                        if url_match:
                            url = url_match.group(0)
                            domain = extract_domain_from_url(url)
                            if domain:
                                all_domains.add(domain)
                    except:
                        continue
            except:
                pass
            
            # Пытаемся выполнить JavaScript для сбора доменов (если страница загрузилась)
            if page_loaded:
                try:
                    script = r"""
                    try {
                        window.domains = new Set();
                        
                        // Анализируем все ресурсы
                        if (performance && performance.getEntriesByType) {
                            performance.getEntriesByType('resource').forEach(r => {
                                try {
                                    const url = new URL(r.name);
                                    window.domains.add(url.hostname);
                                } catch(e) {}
                            });
                        }
                        
                        // Ищем домены в глобальных переменных
                        for (let prop in window) {
                            if (typeof window[prop] === 'string') {
                                const matches = window[prop].match(/https?:\/\/([^\/]+)/g);
                                if (matches) {
                                    matches.forEach(m => {
                                        const domain = m.replace(/https?:\/\//, '').split('/')[0];
                                        window.domains.add(domain);
                                    });
                                }
                            }
                        }
                        
                        // Ищем домены во всех скриптах на странице
                        const scripts = document.querySelectorAll('script[src]');
                        scripts.forEach(script => {
                            try {
                                const url = new URL(script.src);
                                window.domains.add(url.hostname);
                            } catch(e) {}
                        });
                        
                        return Array.from(window.domains);
                    } catch(e) {
                        return [];
                    }
                    """
                    
                    domains = driver.execute_script(script)
                    if domains:
                        for domain in domains:
                            if domain:  # Проверяем, что домен не пустой
                                # Дополнительная проверка и очистка домена
                                clean_domain = extract_domain_from_url(domain)
                                if clean_domain:
                                    all_domains.add(clean_domain)
                        log_callback(f"✓ Найдено {len(domains)} доменов через JavaScript")
                except JavascriptException as e:
                    log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Ошибка выполнения JavaScript: {str(e)[:50]}...")
                except Exception as e:
                    log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось выполнить JavaScript: {str(e)[:50]}...")
            
            # Получаем HTML страницы для дополнительного анализа
            try:
                html_content = driver.page_source
                if html_content and len(html_content) > 100:  # Проверяем, что HTML не пустой
                    html_domains = extract_domains_from_html(html_content)
                    for domain in html_domains:
                        all_domains.add(domain)
                    log_callback(f"✓ Найдено {len(html_domains)} доменов в HTML")
                else:
                    log_callback("ПРЕДУПРЕЖДЕНИЕ: HTML страница пустая или слишком короткая")
            except Exception as e:
                log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось получить HTML: {str(e)[:50]}...")
            
            # Получаем JavaScript код со страницы
            try:
                script_elements = driver.find_elements("tag name", "script")
                js_content = ""
                for script in script_elements:
                    try:
                        src = script.get_attribute("src")
                        if src and not src.startswith('data:'):
                            # Внешний скрипт - не загружаем, просто добавляем домен
                            domain = extract_domain_from_url(src)
                            if domain:
                                all_domains.add(domain)
                        else:
                            # Встроенный скрипт
                            content = script.get_attribute("innerHTML")
                            if content:
                                js_content += content + "\n"
                    except:
                        continue
                
                if js_content:
                    js_domains = extract_domains_from_js(js_content)
                    for domain in js_domains:
                        all_domains.add(domain)
                    log_callback(f"✓ Найдено {len(js_domains)} доменов в JavaScript")
            except Exception as e:
                log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось проанализировать JavaScript: {str(e)[:50]}...")
            
            if all_domains:
                unique_domains = sorted(list(all_domains))
                log_callback(f"Найдено доменов: {len(unique_domains)}")
                log_callback("СПИСОК НАЙДЕННЫХ ДОМЕНОВ:")
                for i, domain in enumerate(unique_domains, 1):
                    if domain == main_domain:
                        log_callback(f"  {i}. {domain} (ОСНОВНОЙ)")
                    else:
                        log_callback(f"  {i}. {domain}")
                return unique_domains
            else:
                log_callback("Не удалось получить домены через Performance API (возможно, ничего не загрузилось).")
                # Если ничего не найдено, но есть основной домен, возвращаем его
                if main_domain:
                    log_callback(f"ВОЗВРАЩАЮ ТОЛЬКО ОСНОВНОЙ ДОМЕН: {main_domain}")
                    return [main_domain]
                return None
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                # Принудительно закрываем все процессы chrome
                cleanup_browser_resources()
                
    except Exception as e:
        log_callback(f"ОШИБКА Performance API: {str(e)}")
        cleanup_browser_resources()
        # В случае ошибки, если есть основной домен, возвращаем его
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ВОЗВРАЩАЮ ОСНОВНОЙ ДОМЕН ПОСЛЕ ОШИБКИ: {main_domain}")
            return [main_domain]
        return None

def analyze_site_domains_selenium(url: str, log_callback):
    """Анализ через Selenium с улучшенным управлением памятью"""
    driver = None
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
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Найден домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
        # ВСЕГДА добавляем основной домен из URL
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ОСНОВНОЙ ДОМЕН ИЗ URL: {main_domain}")
        else:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Не удалось извлечь основной домен из URL")
        
        chrome_options = Options()
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--allow-running-insecure-content")
        chrome_options.add_argument("--memory-pressure-off")
        
        try:
            driver = webdriver.Chrome(options=chrome_options)
            log_callback(f"Перехожу на {url}...")
            driver.get(url)
            log_callback("Жду 7 секунд для загрузки...")
            time.sleep(7)
            
            logs = driver.get_log('performance')
            domains = set()
            
            # ВСЕГДА добавляем основной домен
            all_domains = set()
            if main_domain:
                all_domains.add(main_domain)
                log_callback(f"✓ ДОБАВЛЕН ОСНОВНОЙ ДОМЕН: {main_domain}")
            
            for entry in logs:
                try:
                    log = json.loads(entry['message'])['message']
                    if log['method'] == 'Network.requestWillBeSent':
                        request_url = log['params']['request']['url']
                        domain = extract_domain_from_url(request_url)
                        if domain:
                            all_domains.add(domain)
                except:
                    continue
            
            # Дополнительный анализ HTML
            try:
                html_content = driver.page_source
                html_domains = extract_domains_from_html(html_content)
                for domain in html_domains:
                    all_domains.add(domain)
                log_callback(f"✓ Найдено {len(html_domains)} доменов в HTML")
            except:
                pass
            
            found_domains = sorted(list(all_domains))
            log_callback(f"Найдено доменов: {len(found_domains)}")
            log_callback("СПИСОК НАЙДЕННЫХ ДОМЕНОВ:")
            for i, domain in enumerate(found_domains, 1):
                if domain == main_domain:
                    log_callback(f"  {i}. {domain} (ОСНОВНОЙ)")
                else:
                    log_callback(f"  {i}. {domain}")
            return found_domains
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                cleanup_browser_resources()
                
    except Exception as e:
        log_callback(f"ОШИБКА Selenium: {str(e)}")
        cleanup_browser_resources()
        # В случае ошибки, если есть основной домен, возвращаем его
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ВОЗВРАЩАЮ ОСНОВНОЙ ДОМЕН ПОСЛЕ ОШИБКИ: {main_domain}")
            return [main_domain]
        return None

def analyze_site_domains_playwright(url: str, log_callback):
    """Анализ через Playwright с улучшенным управлением памятью"""
    browser = None
    try:
        from playwright.sync_api import sync_playwright
        from urllib.parse import urlparse
        
        log_callback("Использую Playwright...")
        
        # Проверяем, не является ли URL прямой ссылкой на медиафайл
        if is_media_url(url):
            domain = extract_domain_from_url(url)
            if domain:
                log_callback(f"Обнаружена прямая ссылку на медиафайл. Найден домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
        # ВСЕГДА добавляем основной домен из URL
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ОСНОВНОЙ ДОМЕН ИЗ URL: {main_domain}")
        else:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Не удалось извлечь основной домен из URL")
        
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-gpu',
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-extensions',
                        '--disable-plugins',
                        '--disable-web-security',
                        '--allow-running-insecure-content',
                        '--disable-features=VizDisplayCompositor',
                        '--disable-background-timer-throttling',
                        '--disable-backgrounding-occluded-windows',
                        '--disable-renderer-backgrounding'
                    ]
                )
            except Exception as e:
                log_callback(f"Не удалось запустить браузер Playwright: {e}")
                log_callback("Попробуйте перезапустить программу, чтобы лаунчер установил браузеры.")
                return None

            page = browser.new_page()
            
            # Отключаем загрузку некоторых ресурсов для экономии памяти, но оставляем важные
            route_block = lambda route: route.abort() if route.resource_type in ['font', 'media'] else route.continue_()
            page.route('**/*', route_block)
            
            # ВСЕГДА добавляем основной домен
            all_domains = set()
            if main_domain:
                all_domains.add(main_domain)
                log_callback(f"✓ ДОБАВЛЕН ОСНОВНОЙ ДОМЕН: {main_domain}")
            
            def handle_request(request):
                try:
                    domain = extract_domain_from_url(request.url)
                    if domain:
                        all_domains.add(domain)
                except:
                    pass
            
            def handle_response(response):
                try:
                    domain = extract_domain_from_url(response.url)
                    if domain:
                        all_domains.add(domain)
                except:
                    pass
            
            def handle_request_failed(request):
                try:
                    domain = extract_domain_from_url(request.url)
                    if domain:
                        all_domains.add(domain)
                        log_callback(f"✓ Найден домен из неудачного запроса: {domain}")
                except:
                    pass
            
            page.on("request", handle_request)
            page.on("response", handle_response)
            page.on("requestfailed", handle_request_failed)
            
            log_callback(f"Перехожу на {url}...")
            try:
                page.goto(url, wait_until='networkidle', timeout=30000)
            except Exception as e:
                log_callback(f"Не удалось дождаться полной загрузки, но продолжаю: {e}")

            log_callback("Жду дополнительно 5 секунд...")
            page.wait_for_timeout(5000)
            
            # Анализируем HTML
            try:
                html_content = page.content()
                html_domains = extract_domains_from_html(html_content)
                for domain in html_domains:
                    all_domains.add(domain)
                log_callback(f"✓ Найдено {len(html_domains)} доменов в HTML")
            except:
                pass
            
            # Анализируем JavaScript
            try:
                script_elements = page.query_selector_all("script")
                js_content = ""
                for script in script_elements:
                    try:
                        src = script.get_attribute("src")
                        if src and not src.startswith('data:'):
                            # Внешний скрипт
                            try:
                                response = page.goto(src)
                                if response and response.ok:
                                    js_content += response.text()
                            except:
                                pass
                        else:
                            # Встроенный скрипт
                            js_content += script.inner_text() or ""
                    except:
                        continue
                
                if js_content:
                    js_domains = extract_domains_from_js(js_content)
                    for domain in js_domains:
                        all_domains.add(domain)
                    log_callback(f"✓ Найдено {len(js_domains)} доменов в JavaScript")
            except:
                pass
            
            browser.close()
            
            found_domains = sorted(list(all_domains))
            log_callback(f"Найдено доменов: {len(found_domains)}")
            log_callback("СПИСОК НАЙДЕННЫХ ДОМЕНОВ:")
            for i, domain in enumerate(found_domains, 1):
                if domain == main_domain:
                    log_callback(f"  {i}. {domain} (ОСНОВНОЙ)")
                else:
                    log_callback(f"  {i}. {domain}")
            return found_domains
            
    except Exception as e:
        log_callback(f"ОШИБКА Playwright: {str(e)}")
        if browser:
            try:
                browser.close()
            except:
                pass
        # В случае ошибки, если есть основной домен, возвращаем его
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ВОЗВРАЩАЮ ОСНОВНОЙ ДОМЕН ПОСЛЕ ОШИБКИ: {main_domain}")
            return [main_domain]
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
                log_callback(f"Обнаружена прямая ссылка на медиафайл. Найден домен: {domain}")
                return [domain]
            else:
                log_callback("Не удалось извлечь домен из URL медиафайла.")
                return None
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # ВСЕГДА добавляем основной домен из URL
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ОСНОВНОЙ ДОМЕН ИЗ URL: {main_domain}")
        else:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Не удалось извлечь основной домен из URL")

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        log_callback(f"Загружаю {url}...")
        response = session.get(url, timeout=20, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # ВСЕГДА начинаем с основного домена
        domains = set()
        if main_domain:
            domains.add(main_domain)
            log_callback(f"✓ ДОБАВЛЕН ОСНОВНОЙ ДОМЕН: {main_domain}")
        
        # Извлекаем домены из HTML
        html_domains = extract_domains_from_html(response.text)
        for domain in html_domains:
            domains.add(domain)
        
        # Дополнительный поиск в тегах
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame', 'source']):
            attr = None
            if tag.has_attr('href'): attr = 'href'
            elif tag.has_attr('src'): attr = 'src'
            
            if attr and tag[attr]:
                try:
                    full_url = urljoin(url, tag[attr])
                    domain = extract_domain_from_url(full_url)
                    if domain:
                        domains.add(domain)
                except:
                    continue
        
        # Поиск в тексте
        text_domains = re.findall(r'[\'"](https?://)?([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)[\'"]', response.text)
        for _, domain in text_domains:
            if domain and '.' in domain:
                domains.add(domain)
        
        # Анализ JavaScript кода
        script_tags = soup.find_all('script')
        js_content = ""
        for script in script_tags:
            if script.string:
                js_content += script.string + "\n"
        
        if js_content:
            js_domains = extract_domains_from_js(js_content)
            for domain in js_domains:
                domains.add(domain)
            log_callback(f"✓ Найдено {len(js_domains)} доменов в JavaScript")
        
        found_domains = sorted(list(domains))
        log_callback(f"Найдено доменов: {len(found_domains)}")
        log_callback("СПИСОК НАЙДЕННЫХ ДОМЕНОВ:")
        for i, domain in enumerate(found_domains, 1):
            if domain == main_domain:
                log_callback(f"  {i}. {domain} (ОСНОВНОЙ)")
            else:
                log_callback(f"  {i}. {domain}")
        return found_domains
        
    except Exception as e:
        log_callback(f"ОШИБКА простого парсера: {str(e)}")
        # В случае ошибки, если есть основной домен, возвращаем его
        main_domain = extract_domain_from_url(url)
        if main_domain:
            log_callback(f"ВОЗВРАЩАЮ ОСНОВНОЙ ДОМЕН ПОСЛЕ ОШИБКИ: {main_domain}")
            return [main_domain]
        return None