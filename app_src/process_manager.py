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
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def _clean_profile_args(args_str):
    """
    Удаляет глобальные аргументы захвата (--wf-...), 
    чтобы они не конфликтовали при склейке через --new.
    """
    # Удаляем --wf-tcp=... и --wf-udp=...
    cleaned = re.sub(r'--wf-tcp=[^ ]+', '', args_str)
    cleaned = re.sub(r'--wf-udp=[^ ]+', '', cleaned)
    return cleaned.strip()

def start_process(profile, base_dir, game_filter_enabled, log_callback, custom_list_path=None, is_service=False):
    """
    Запускает одиночный процесс (используется для тестов и старой логики).
    Возвращает объект subprocess.Popen.
    """
    bin_dir = os.path.join(base_dir, 'bin')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    lists_dir = os.path.join(base_dir, 'lists')
    
    if not os.path.exists(executable_path):
        log_callback(f"Ошибка: Файл не найден: {executable_path}")
        return None

    # Формируем аргументы
    raw_args = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        GAME_FILTER="1024-65535" if game_filter_enabled else "0"
    )

    # Для одиночного запуска не обязательно чистить wf-аргументы, 
    # но если профиль рассчитан на --new, лучше оставить как есть в raw_args.
    # Но так как мы используем те же профили, что и для combined, 
    # в них могут быть wf-фильтры. Оставим их, так как это одиночный процесс.
    
    try:
        args_list = shlex.split(raw_args)
    except:
        args_list = raw_args.split()

    final_args = []
    for arg in args_list:
        # Подмена списка, если передан custom_list_path
        if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
             if custom_list_path and ('list-general.txt' in arg or 'custom_list.txt' in arg):
                 prefix = arg.split('=')[0]
                 final_args.append(f'{prefix}={custom_list_path}')
             else:
                 final_args.append(arg)
        else:
            final_args.append(arg)

    command = [executable_path] + final_args

    try:
        # Скрываем окно консоли
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        process = subprocess.Popen(
            command,
            cwd=base_dir,
            stdout=subprocess.DEVNULL, # Для тестов нам не нужен вывод в лог
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return process
    except Exception as e:
        log_callback(f"Ошибка запуска процесса тестирования: {e}")
        return None

def start_combined_process(configs, base_dir, game_filter_enabled, log_callback):
    """
    Запускает ОДИН процесс для нескольких конфигураций.
    configs: список кортежей [(list_path, profile_obj, ipset_path), ...]
    ipset_path может быть None, если выключен.
    """
    bin_dir = os.path.join(base_dir, 'bin')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    lists_dir = os.path.join(base_dir, 'lists')
    
    if not os.path.exists(executable_path):
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {executable_path}")
        return None

    # 1. Глобальные настройки захвата (фильтр WinDivert)
    game_ports = ",1024-65535" if game_filter_enabled else ""
    
    # Захватываем весь нужный трафик глобально
    global_args = [
        f"--wf-tcp=80,443{game_ports}",
        f"--wf-udp=443,50000-65535{game_ports}"
    ]
    
    final_args = list(global_args)

    # 2. Сборка аргументов для каждого списка
    for i, (list_path, profile, ipset_path) in enumerate(configs):
        if i > 0:
            final_args.append("--new")
            
        # Форматируем аргументы профиля
        raw_args = profile["args"].format(
            LISTS_DIR=lists_dir,
            BIN_DIR=bin_dir,
            GAME_FILTER="1024-65535" if game_filter_enabled else "0"
        )
        
        # Очищаем от глобальных wf-фильтров (они уже заданы в начале)
        cleaned_args = _clean_profile_args(raw_args)
        
        try:
            args_list = shlex.split(cleaned_args)
        except:
            args_list = cleaned_args.split()
            
        # Подмена списка и IPSet
        processed_args = []
        for arg in args_list:
            if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
                 if 'list-general.txt' in arg or 'custom_list.txt' in arg:
                     prefix = arg.split('=')[0]
                     processed_args.append(f'{prefix}={list_path}')
                 else:
                     processed_args.append(arg)
            elif arg.startswith('--ipset='):
                # Если передан конкретный ipset для этого списка - используем его
                if ipset_path:
                    processed_args.append(f'--ipset={ipset_path}')
                else:
                    # Если ipset выключен (None), мы пропускаем этот аргумент,
                    # тем самым убирая ipset из профиля (если он там был)
                    pass 
            else:
                processed_args.append(arg)
        
        final_args.extend(processed_args)

    final_command = [executable_path] + final_args

    if not is_admin():
        log_callback("ОШИБКА: Требуются права администратора")
        return None

    log_callback(f"Запуск единого процесса для {len(configs)} списков...")
    
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

def monitor_memory_usage(process, log_callback):
    try:
        max_memory_mb = 1024
        while process and process.poll() is None:
            try:
                p = psutil.Process(process.pid)
                memory_mb = p.memory_info().rss / 1024 / 1024
                if memory_mb > max_memory_mb:
                    kill_process(process)
                    break
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
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                proc.terminate()
        except: continue
    time.sleep(1)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                proc.kill()
        except: continue

def is_process_running():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                return True
        except: pass
    return False

def is_service_running():
    try:
        result = subprocess.run(['sc', 'query', ZAPRET_SERVICE_NAME], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return "RUNNING" in result.stdout
    except: return False