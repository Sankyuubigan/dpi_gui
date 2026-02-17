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
    cleaned = re.sub(r'--wf-tcp=[^ ]+', '', args_str)
    cleaned = re.sub(r'--wf-udp=[^ ]+', '', cleaned)
    return cleaned.strip()

def start_process(profile, base_dir, game_filter_enabled, log_callback, custom_list_path=None, is_service=False):
    # Используем прямые слеши для надежности и абсолютные пути
    bin_dir = os.path.join(base_dir, 'bin').replace('\\', '/')
    executable_path = os.path.join(bin_dir, WINWS_EXE).replace('\\', '/')
    lists_dir = os.path.join(base_dir, 'lists').replace('\\', '/')
    exclude_dir = os.path.join(base_dir, 'exclude').replace('\\', '/')
    
    if not os.path.exists(executable_path):
        log_callback(f"Ошибка: Файл не найден: {executable_path}")
        return None

    # Форматируем аргументы с абсолютными путями
    raw_args = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        EXCLUDE_DIR=exclude_dir,
        GAME_FILTER="1024-65535" if game_filter_enabled else "0"
    )

    try:
        args_list = shlex.split(raw_args)
    except:
        args_list = raw_args.split()

    final_args = []
    for arg in args_list:
        if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
             if custom_list_path and ('list-general.txt' in arg or 'custom_list.txt' in arg):
                 prefix = arg.split('=')[0]
                 clean_custom_path = custom_list_path.replace('\\', '/')
                 final_args.append(f'{prefix}={clean_custom_path}')
             else:
                 final_args.append(arg)
        else:
            final_args.append(arg)

    command = [executable_path] + final_args

    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        process = subprocess.Popen(
            command,
            cwd=bin_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return process
    except Exception as e:
        log_callback(f"Ошибка запуска процесса тестирования: {e}")
        return None

def start_combined_process(configs, base_dir, game_filter_enabled, log_callback):
    # Используем прямые слеши для надежности и абсолютные пути
    bin_dir = os.path.join(base_dir, 'bin').replace('\\', '/')
    executable_path = os.path.join(bin_dir, WINWS_EXE).replace('\\', '/')
    lists_dir = os.path.join(base_dir, 'lists').replace('\\', '/')
    exclude_dir = os.path.join(base_dir, 'exclude').replace('\\', '/')
    
    if not os.path.exists(executable_path):
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {executable_path}")
        return None

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
            EXCLUDE_DIR=exclude_dir,
            GAME_FILTER="1024-65535" if game_filter_enabled else "0"
        )
        
        cleaned_args = _clean_profile_args(raw_args)
        
        try:
            # posix=True корректно обрабатывает кавычки
            args_list = shlex.split(cleaned_args)
        except:
            args_list = cleaned_args.split()
            
        processed_args = []
        for arg in args_list:
            if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
                 if 'list-general.txt' in arg or 'custom_list.txt' in arg:
                     prefix = arg.split('=')[0]
                     clean_list_path = list_path.replace('\\', '/')
                     processed_args.append(f'{prefix}={clean_list_path}')
                 else:
                     processed_args.append(arg)
            elif arg.startswith('--ipset='):
                pass
            else:
                processed_args.append(arg)
        
        if ipset_path and ipset_path != "OFF":
            clean_ipset_path = ipset_path.replace('\\', '/')
            processed_args.append(f'--ipset={clean_ipset_path}')
        
        final_args.extend(processed_args)

    final_command = [executable_path] + final_args
    
    if not is_admin():
        log_callback("ОШИБКА: Требуются права администратора")
        return None

    log_callback(f"Запуск единого процесса для {len(configs)} списков...")
    
    try:
        process = subprocess.Popen(
            final_command,
            cwd=bin_dir,
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