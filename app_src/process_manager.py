import os
import subprocess
import shlex
import threading
import time
import logging
import ctypes
import psutil

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

process_lock = threading.Lock()
_current_process = None

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_process(profile, base_dir, game_filter_enabled, log_callback, combined_list_path=None, ipset_path=None):
    """Запускает процесс с поддержкой выбора IPSet"""
    global _current_process
    
    with process_lock:
        if _current_process and _current_process.poll() is None:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Процесс уже запущен!")
            return _current_process
        
        if is_process_running():
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Найден активный процесс winws.exe!")
            return None
        
        logger.info(f"Запуск профиля: {profile['name']}")
        
        bin_dir = os.path.join(base_dir, 'bin')
        executable_path = os.path.join(bin_dir, WINWS_EXE)
        
        if not os.path.exists(executable_path):
            log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {executable_path}")
            return None
            
        game_filter_value = "1024-65535" if game_filter_enabled else "0"
        
        args_str = profile["args"].format(
            LISTS_DIR=os.path.join(base_dir, 'lists'),
            BIN_DIR=bin_dir,
            GAME_FILTER=game_filter_value
        )
        
        try:
            base_args = shlex.split(args_str)
        except ValueError as e:
            log_callback(f"ОШИБКА АРГУМЕНТОВ: {e}")
            return None
        
        final_args = []
        for arg in base_args:
            if arg.startswith('--hostlist=') and 'list-general.txt' in arg:
                if combined_list_path:
                    final_args.append(f'--hostlist={combined_list_path}')
                else:
                    log_callback(f"WARNING: Объединенный список пуст, аргумент '{arg}' пропущен.")
            elif arg.startswith('--ipset='):
                if ipset_path:
                    # Заменяем стандартный путь из профиля на выбранный пользователем
                    final_args.append(f'--ipset="{ipset_path}"')
                else:
                    # Если IPSet выключен, пропускаем аргумент
                    pass 
            else:
                final_args.append(arg)
        
        final_command = [executable_path] + final_args
        
        log_callback("="*40)
        log_callback("ЗАПУСК ПРОЦЕССА")
        log_callback(f"Файл: {executable_path}")
        log_callback("Аргументы:")
        for i, arg in enumerate(final_args):
            log_callback(f"  [{i}]: {arg}")
        log_callback("="*40)
        
        if not is_admin():
            log_callback("ОШИБКА: Требуются права администратора")
            return None
        
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
            
            _current_process = process
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
                    log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Память > {max_memory_mb} МБ. Остановка.")
                    stop_all_processes(log_callback)
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(5)
    except Exception:
        pass

def stop_all_processes(log_callback):
    global _current_process
    with process_lock:
        try:
            if _current_process:
                if _current_process.poll() is None:
                    _current_process.terminate()
                    try:
                        _current_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        _current_process.kill()
                _current_process = None
            
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
        except Exception as e:
            log_callback(f"ERROR: {e}")

def is_process_running():
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                return True
        return False
    except:
        return False

def is_service_running():
    try:
        result = subprocess.run(
            ['sc', 'query', ZAPRET_SERVICE_NAME],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866'
        )
        return "RUNNING" in result.stdout
    except:
        return False