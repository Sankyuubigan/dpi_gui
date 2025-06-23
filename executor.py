import os
import subprocess
import shlex
import re
import time
import json
from urllib.parse import urlparse

# --- Selenium imports ---
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


def analyze_site_domains(url: str, log_callback):
    """
    Запускает Chrome в фоновом режиме для сбора всех доменов,
    к которым обращается сайт.
    """
    if not SELENIUM_AVAILABLE:
        log_callback("ОШИБКА: Библиотека Selenium не установлена.")
        log_callback("Пожалуйста, выполните в консоли: pip install selenium")
        return None

    log_callback("Запускаю браузер для анализа...")
    
    chrome_options = Options()
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--disable-gpu") # Часто помогает в headless режиме
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
            log = json.loads(entry['message'])['message']
            if log['method'] == 'Network.requestWillBeSent':
                request_url = log['params']['request']['url']
                domain = urlparse(request_url).netloc
                if domain:
                    domains.add(domain)
        
        log_callback(f"Найдено {len(domains)} уникальных доменов.")
        return sorted(list(domains))

    except WebDriverException as e:
        log_callback("\n!!! ОШИБКА SELENIUM !!!")
        log_callback("Не удалось запустить Chrome. Убедитесь, что он установлен.")
        log_callback(f"Текст ошибки: {e}")
        return None
    except Exception as e:
        log_callback(f"Произошла непредвиденная ошибка: {e}")
        return None
    finally:
        if driver:
            driver.quit()
        log_callback("Анализ завершен, браузер закрыт.")


# --- Остальной код executor.py без изменений ---
def find_bat_files(directory="."):
    bat_files = []
    if not os.path.isdir(directory): return []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".bat") and file.lower() != "service.bat":
                bat_files.append(os.path.abspath(os.path.join(root, file)))
    return sorted(bat_files)

def kill_existing_processes(log_callback):
    log_callback("Попытка остановить все существующие процессы winws.exe для чистого запуска...")
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/IM", "winws.exe"], check=False, capture_output=True, text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if result.returncode == 0:
            log_callback("INFO: Один или несколько процессов winws.exe были успешно остановлены.")
        else:
            log_callback("INFO: Активных процессов winws.exe не найдено, запуск продолжается.")
    except FileNotFoundError:
        log_callback("WARNING: Команда 'taskkill' не найдена.")
    except Exception as e:
        log_callback(f"ERROR: Ошибка при попытке остановить процессы: {e}")

def get_game_filter_value(base_dir):
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    return "1024-65535" if os.path.exists(game_flag_file) else "0"

def is_custom_list_valid(filepath, log_callback):
    if not os.path.exists(filepath): return False
    if os.path.getsize(filepath) == 0: return False
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip() and not line.strip().startswith('#'): return True
    except Exception: return False
    return False

def parse_command_from_bat(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
        marker = 'winws.exe"'
        idx = content.find(marker)
        if idx == -1: return ""
        command_str = content[idx + len(marker):]
        return command_str.replace('^', ' ').replace('\n', ' ').strip()
    except Exception: return ""

def run_bat_file(file_path, log_callback):
    base_dir = os.path.dirname(file_path)
    custom_list_path = os.path.abspath('custom_list.txt')
    custom_list_is_valid = is_custom_list_valid(custom_list_path, log_callback)
    game_filter = get_game_filter_value(base_dir)
    raw_command_str = parse_command_from_bat(file_path)
    if not raw_command_str:
        log_callback(f"ERROR: Не удалось извлечь команду из файла {os.path.basename(file_path)}")
        return None
    bin_path_with_sep = os.path.join(base_dir, 'bin') + os.sep
    lists_path_with_sep = os.path.join(base_dir, 'lists') + os.sep
    substituted_str = raw_command_str.replace('%GameFilter%', game_filter)
    substituted_str = substituted_str.replace('%BIN%', bin_path_with_sep)
    substituted_str = substituted_str.replace('%LISTS%', lists_path_with_sep)
    try:
        args = shlex.split(substituted_str, posix=False)
    except ValueError as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА РАЗБОРА КОМАНДЫ: {e}")
        return None
    cleaned_args = []
    pattern = re.compile(r"(--[a-zA-Z0-9_-]+)=(.+)")
    for arg in args:
        match = pattern.match(arg)
        if match:
            cleaned_args.extend([match.group(1), match.group(2).strip('"')])
        else:
            cleaned_args.append(arg)
    final_args = []
    blocks, current_block = [], []
    for arg in cleaned_args:
        if arg.lower() == '--new':
            if current_block: blocks.append(current_block)
            current_block = []
        else:
            current_block.append(arg)
    if current_block: blocks.append(current_block)
    for i, block in enumerate(blocks):
        has_hostlist_param = any('--hostlist' in arg.lower() for arg in block)
        final_args.extend(block)
        if has_hostlist_param and custom_list_is_valid:
            final_args.extend(['--hostlist', custom_list_path])
        if i < len(blocks) - 1:
            final_args.append('--new')
    executable_path = os.path.join(base_dir, 'bin', 'winws.exe')
    final_command = [executable_path] + final_args
    log_callback("="*40)
    log_callback("ДЕТАЛИ ЗАПУСКА ПРОЦЕССА")
    log_callback(f"ИСПОЛНЯЕМЫЙ ФАЙЛ:\n  {executable_path}")
    log_callback("АРГУМЕНТЫ:")
    for i, arg in enumerate(final_args):
        log_callback(f"  [{i}]: {arg}")
    log_callback("="*40)
    try:
        process = subprocess.Popen(
            final_command, cwd=base_dir, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            encoding='utf-8', errors='ignore'
        )
        return process
    except Exception as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА ПРИ ЗАПУСКЕ: {e}")
        return None