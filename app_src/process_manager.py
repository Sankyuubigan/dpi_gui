import os
import subprocess
import shlex
import threading
import time
import logging
import ctypes
import psutil
import re

WINWS_EXE = "winws.exe"
ZAPRET_SERVICE_NAME = "ZapretDPIBypass"

logger = logging.getLogger("process_manager")
if not logger.handlers:
    os.makedirs("roo_tests", exist_ok=True)
    handler = logging.FileHandler("roo_tests/process_manager.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def _clean_profile_args(args_str):
    cleaned = re.sub(r'--wf-tcp=[^ ]+', '', args_str)
    cleaned = re.sub(r'--wf-udp=[^ ]+', '', cleaned)
    return cleaned.strip()

def start_combined_process(configs, base_dir, game_filter_enabled, log_callback):
    """
    Запускает ОДИН процесс для нескольких конфигураций.
    configs: список кортежей [(list_path, profile_obj, ipset_path), ...]
    ВАЖНО: list_path может быть None (если это чисто ipset правило),
           ipset_path может быть None (если это чисто domain правило).
    """
    bin_dir = os.path.join(base_dir, 'bin')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    lists_dir = os.path.join(base_dir, 'lists')
    
    if not os.path.exists(executable_path):
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {executable_path}")
        return None

    # Глобальные настройки (фильтр WinDivert)
    game_ports = ",1024-65535" if game_filter_enabled else ""
    global_args = [
        f"--wf-tcp=80,443{game_ports}",
        f"--wf-udp=443,50000-65535{game_ports}"
    ]
    
    final_args = list(global_args)

    for i, (list_path, profile, ipset_path) in enumerate(configs):
        if i > 0:
            final_args.append("--new")
            
        raw_args = profile["args"].format(
            LISTS_DIR=lists_dir,
            BIN_DIR=bin_dir,
            GAME_FILTER="1024-65535" if game_filter_enabled else "0"
        )
        
        cleaned_args = _clean_profile_args(raw_args)
        try: args_list = shlex.split(cleaned_args)
        except: args_list = cleaned_args.split()
            
        # Подмена
        processed_args = []
        for arg in args_list:
            if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
                 # Если у нас есть list_path, подставляем его.
                 # Если list_path is None (это правило для ipset), то мы ПРОПУСКАЕМ этот аргумент,
                 # так как --hostlist без файла не нужен, а ipset мы добавим ниже.
                 if list_path:
                     prefix = arg.split('=')[0]
                     processed_args.append(f'{prefix}={list_path}')
                 else:
                     pass # Удаляем hostlist из аргументов профиля, так как это правило только для IP
            elif arg.startswith('--ipset='):
                if ipset_path:
                    processed_args.append(f'--ipset={ipset_path}')
                else:
                    pass # Удаляем ipset, если он не задан для этого правила
            else:
                processed_args.append(arg)
        
        # Если это правило IPSet и мы удалили hostlist, но ipset еще не добавлен (потому что в профиле его не было)
        # нужно проверить, добавился ли он.
        # Но логика выше: если arg startswith ipset -> заменяем.
        # А если в профиле НЕ БЫЛО --ipset? (например профиль только для доменов).
        # Тогда мы должны добавить его вручную, если ipset_path передан.
        
        # Простая проверка: если ipset_path есть, но в processed_args нет --ipset...
        has_ipset_arg = any(a.startswith('--ipset=') for a in processed_args)
        if ipset_path and not has_ipset_arg:
             processed_args.append(f'--ipset={ipset_path}')
             
        # То же самое для hostlist, хотя вряд ли профиль будет без него
        has_hostlist_arg = any(a.startswith('--hostlist') for a in processed_args)
        if list_path and not has_hostlist_arg:
            # Добавляем дефолтный hostlist аргумент, если профиль странный
             processed_args.append(f'--hostlist={list_path}')

        final_args.extend(processed_args)

    final_command = [executable_path] + final_args

    if not is_admin():
        log_callback("ОШИБКА: Требуются права администратора")
        return None

    log_callback(f"Запуск единого процесса для {len(configs)} правил...")
    
    try:
        process = subprocess.Popen(
            final_command,
            cwd=base_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            encoding='utf-8',
            errors='ignore'
        )
        threading.Thread(target=monitor_memory_usage, args=(process, log_callback), daemon=True).start()
        return process
    except Exception as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА ЗАПУСКА: {e}")
        return None

# ... (остальные функции monitor, kill, stop без изменений) ...
def monitor_memory_usage(process, log_callback):
    try:
        max_memory_mb = 1024
        while process and process.poll() is None:
            try:
                p = psutil.Process(process.pid)
                if p.memory_info().rss / 1024 / 1024 > max_memory_mb:
                    kill_process(process); break
            except: break
            time.sleep(5)
    except: pass

def kill_process(process):
    if not process: return
    try:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=2)
            except: process.kill()
    except: pass

def stop_all_processes(log_callback=None):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower(): proc.terminate()
        except: continue
    time.sleep(1)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower(): proc.kill()
        except: continue

def is_process_running():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower(): return True
        except: pass
    return False

def is_service_running():
    try:
        result = subprocess.run(['sc', 'query', ZAPRET_SERVICE_NAME], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return "RUNNING" in result.stdout
    except: return False
    
# Обновляем start_process для тестов (совместимость)
def start_process(profile, base_dir, game_filter_enabled, log_callback, list_path=None, wait=False):
    # Обертка для одиночного запуска (используется в тестах)
    config = (list_path, profile, None)
    return start_combined_process([config], base_dir, game_filter_enabled, log_callback)