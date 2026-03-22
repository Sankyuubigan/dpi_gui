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
    # Файловый обработчик
    file_handler = logging.FileHandler("roo_tests/process_manager.log")
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    # Консольный обработчик для немедленной обратной связи
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    # Добавляем оба обработчика
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.setLevel(logging.DEBUG)

def is_admin():
    try:
        result = ctypes.windll.shell32.IsUserAnAdmin()
        logger.debug(f"is_admin check result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error checking admin rights: {e}")
        return False

def _clean_profile_args(args_str):
    """
    Удаляет глобальные аргументы захвата (--wf-...), 
    чтобы они не конфликтовали при склейке через --new.
    """
    cleaned = re.sub(r'--wf-tcp=[^ ]+', '', args_str)
    cleaned = re.sub(r'--wf-udp=[^ ]+', '', cleaned)
    return cleaned.strip()

def _ensure_file_exists(filepath, default_content="# Auto-generated list\n"):
    """Создает файл с дефолтным содержимым, если он не существует."""
    if not os.path.exists(filepath):
        try:
            dirname = os.path.dirname(filepath)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(default_content)
            logger.info(f"Created missing file: {filepath}")
        except Exception as e:
            logger.error(f"Failed to create file {filepath}: {e}")

def _resolve_ipset_path(requested_path, base_dir):
    """
    Находит реальный путь к ipset файлу.
    Профили ссылаются на lists/ipset-all.txt, но файл может быть в ipsets/.
    Если файл не найден - создаем заглушку.
    Возвращает ИСПРАВЛЕННЫЙ ПУТЬ.
    """
    # Если файл существует по запрошенному пути
    if os.path.exists(requested_path):
        return requested_path
    
    filename = os.path.basename(requested_path)
    
    # Ищем в папке ipsets
    ipsets_dir = os.path.join(base_dir, 'ipsets')
    alt_path = os.path.join(ipsets_dir, filename)
    if os.path.exists(alt_path):
        logger.info(f"IPSet found in alternative dir: {alt_path}")
        return alt_path
        
    # Если не нашли - создаем заглушку в папке ipsets (или там, где просят)
    logger.info(f"IPSet {filename} not found. Creating dummy...")
    
    # Предпочитаем создавать в ipsets, чтобы не мусорить в lists
    target_dir = ipsets_dir
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    final_path = os.path.join(target_dir, filename)
    _ensure_file_exists(final_path, "# Placeholder IPSet\n0.0.0.0/32\n")
    return final_path

def start_process(profile, base_dir, game_filter_enabled, log_callback, custom_list_path=None, is_service=False):
    logger.debug(f"Starting process with profile: {profile.get('name', 'unnamed')}")
    bin_dir = os.path.join(base_dir, 'bin').replace('\\', '/')
    executable_path = os.path.join(bin_dir, WINWS_EXE).replace('\\', '/')
    lists_dir = os.path.join(base_dir, 'lists').replace('\\', '/')
    exclude_dir = os.path.join(base_dir, 'exclude').replace('\\', '/')
    
    logger.debug(f"Checking executable path: {executable_path}")
    if not os.path.exists(executable_path):
        error_msg = f"Ошибка: Файл не найден: {executable_path}"
        log_callback(error_msg)
        logger.error(error_msg)
        return None

    raw_args = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        EXCLUDE_DIR=exclude_dir,
        GAME_FILTER="1024-65535" if game_filter_enabled else "12"
    )
    logger.debug(f"Raw args after formatting: {raw_args}")

    try:
        args_list = shlex.split(raw_args)
        logger.debug(f"Args after shlex.split: {args_list}")
    except Exception as e:
        logger.warning(f"Failed to shlex.split args, falling back to simple split: {e}")
        args_list = raw_args.split()
        logger.debug(f"Args after simple split: {args_list}")

    final_args = []
    for arg in args_list:
        if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
             if custom_list_path and ('list-general.txt' in arg or 'custom_list.txt' in arg):
                 prefix = arg.split('=')[0]
                 clean_custom_path = custom_list_path.replace('\\', '/')
                 final_args.append(f'{prefix}={clean_custom_path}')
                 logger.debug(f"Replaced custom list path: {prefix}={clean_custom_path}")
             else:
                 final_args.append(arg)
        else:
            final_args.append(arg)

    command = [executable_path] + final_args
    logger.info(f"Starting process with command: {' '.join(command)}")

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
        logger.info(f"Process started successfully with PID: {process.pid}")
        return process
    except Exception as e:
        error_msg = f"Ошибка запуска процесса тестирования: {e}"
        log_callback(error_msg)
        logger.error(error_msg, exc_info=True)
        return None

def start_combined_process(configs, base_dir, game_filter_enabled, log_callback):
    logger.debug(f"Starting combined process with {len(configs)} configs")
    bin_dir = os.path.join(base_dir, 'bin').replace('\\', '/')
    executable_path = os.path.join(bin_dir, WINWS_EXE).replace('\\', '/')
    lists_dir = os.path.join(base_dir, 'lists').replace('\\', '/')
    exclude_dir = os.path.join(base_dir, 'exclude').replace('\\', '/')
    
    logger.debug(f"Checking executable path: {executable_path}")
    if not os.path.exists(executable_path):
        error_msg = f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {executable_path}"
        log_callback(error_msg)
        logger.error(error_msg)
        return None

    game_ports = ",1024-65535" if game_filter_enabled else ""
    logger.debug(f"Game filter enabled: {game_filter_enabled}, ports: {game_ports}")
    
    global_args = [
        f"--wf-tcp=80,443,2053,2083,2087,2096,8443{game_ports}",
        f"--wf-udp=443,19294-19344,50000-50100{game_ports}",
        "--ctrack-disable=1"
    ]
    logger.debug(f"Global args: {global_args}")
    
    final_args = list(global_args)
    
    # Пути к пользовательским спискам (как в BAT файле)
    user_hostlist_exclude = os.path.join(base_dir, 'exclude', 'list-exclude-user.txt').replace('\\', '/')
    user_ipset_exclude = os.path.join(base_dir, 'exclude', 'ipset-exclude-user.txt').replace('\\', '/')
    logger.debug(f"User hostlist exclude: {user_hostlist_exclude}")
    logger.debug(f"User ipset exclude: {user_ipset_exclude}")
    
    # Создаем файлы, если их нет, чтобы winws не ругался
    logger.info(f"Ensuring user hostlist exclude file exists: {user_hostlist_exclude}")
    _ensure_file_exists(user_hostlist_exclude, "# User exclude domains\ndomain.example.abc\n")
    logger.info(f"Ensuring user ipset exclude file exists: {user_ipset_exclude}")
    _ensure_file_exists(user_ipset_exclude, "# User exclude IPs\n203.0.113.113/32\n")

    for i, (list_path, profile, ipset_path) in enumerate(configs):
        logger.debug(f"Processing config {i}: list_path={list_path}, profile={profile.get('name', 'unnamed')}, ipset_path={ipset_path}")
        if i > 0:
            final_args.append("--new")
            logger.debug("Added --new argument for combined process")
            
        raw_args = profile["args"].format(
            LISTS_DIR=lists_dir,
            BIN_DIR=bin_dir,
            EXCLUDE_DIR=exclude_dir,
            GAME_FILTER="1024-65535" if game_filter_enabled else "12"
        )
        logger.debug(f"Raw args for config {i}: {raw_args}")
        
        cleaned_args = _clean_profile_args(raw_args)
        logger.debug(f"Cleaned args for config {i}: {cleaned_args}")
        
        try:
            args_list = shlex.split(cleaned_args)
            logger.debug(f"Args after shlex.split for config {i}: {args_list}")
        except Exception as e:
            logger.warning(f"Failed to shlex.split args for config {i}, falling back to simple split: {e}")
            args_list = cleaned_args.split()
            logger.debug(f"Args after simple split for config {i}: {args_list}")
            
        processed_args = []
        
        for arg in args_list:
            # 1. Обработка hostlist (замена путей)
            if arg.startswith('--hostlist=') or arg.startswith('--hostlist-auto='):
                 if 'list-general.txt' in arg or 'custom_list.txt' in arg:
                     prefix = arg.split('=')[0]
                     clean_list_path = list_path.replace('\\', '/')
                     processed_args.append(f'{prefix}={clean_list_path}')
                     logger.debug(f"Replaced hostlist path: {prefix}={clean_list_path}")
                 else:
                     processed_args.append(arg)
             
            # 2. Инъекция пользовательских исключений доменов (HOSTLIST EXCLUDE)
            # В BAT: --hostlist-exclude="list-exclude.txt" --hostlist-exclude="list-exclude-user.txt"
            elif arg.startswith('--hostlist-exclude='):
                processed_args.append(arg) # Основной
                processed_args.append(f'--hostlist-exclude={user_hostlist_exclude}') # Пользовательский
                logger.debug(f"Added hostlist exclude: {arg} and --hostlist-exclude={user_hostlist_exclude}")

            # 3. Инъекция пользовательских исключений IP (IPSET EXCLUDE)
            # В BAT: --ipset-exclude="ipset-exclude.txt" --ipset-exclude="ipset-exclude-user.txt"
            elif arg.startswith('--ipset-exclude='):
                processed_args.append(arg) # Основной
                processed_args.append(f'--ipset-exclude={user_ipset_exclude}') # Пользовательский
                logger.debug(f"Added ipset exclude: {arg} and --ipset-exclude={user_ipset_exclude}")
            
            # 4. Обработка IPSet (ГЛАВНОЕ ИСПРАВЛЕНИЕ БАГА)
            elif arg.startswith('--ipset='):
                if ipset_path and ipset_path != "OFF":
                    # Если выбран в UI
                    clean_ipset_path = ipset_path.replace('\\', '/')
                    processed_args.append(f'--ipset={clean_ipset_path}')
                    logger.debug(f"Using UI-provided ipset path: --ipset={clean_ipset_path}")
                else:
                    # Берем из профиля и ИСПРАВЛЯЕМ ПУТЬ
                    raw_path = arg.split('=', 1)[1].strip('"')
                    logger.debug(f"Raw ipset path from profile: {raw_path}")
                    # Находим реальный путь (или создаем заглушку)
                    valid_path = _resolve_ipset_path(raw_path, base_dir).replace('\\', '/')
                    # ПЕРЕДАЕМ ИСПРАВЛЕННЫЙ ПУТЬ
                    processed_args.append(f'--ipset={valid_path}')
                    logger.debug(f"Resolved ipset path: --ipset={valid_path}")
            
            else:
                processed_args.append(arg)
        
        final_args.extend(processed_args)
        logger.debug(f"Processed args for config {i}: {processed_args}")

    final_command = [executable_path] + final_args
    logger.info(f"Final command for combined process: {' '.join(final_command)}")
    
    # Логируем команду для отладки
    log_file_path = os.path.join(base_dir, "..", "roo_tests", "last_launch_cmd.txt")
    try:
        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write(" ".join(final_command))
        logger.debug(f"Wrote command to {log_file_path}")
    except Exception as e:
        logger.warning(f"Failed to write command to file: {e}")
    
    if not is_admin():
        error_msg = "ОШИБКА: Требуются права администратора"
        log_callback(error_msg)
        logger.error(error_msg)
        return None

    log_callback(f"Запуск единого процесса для {len(configs)} списков...")
    logger.info(f"Starting combined process for {len(configs)} configs")
    
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
        logger.info(f"Combined process started successfully with PID: {process.pid}")
        
        threading.Thread(target=monitor_memory_usage, args=(process, log_callback), daemon=True).start()
        return process
    except Exception as e:
        error_msg = f"КРИТИЧЕСКАЯ ОШИБКА ЗАПУСКА: {e}"
        log_callback(error_msg)
        logger.error(error_msg, exc_info=True)
        return None

def monitor_memory_usage(process, log_callback):
    logger.debug("Starting memory usage monitoring")
    try:
        max_memory_mb = 1024
        while process and process.poll() is None:
            try:
                p = psutil.Process(process.pid)
                memory_mb = p.memory_info().rss / 1024 / 1024
                logger.debug(f"Process {process.pid} memory usage: {memory_mb:.2f} MB")
                if memory_mb > max_memory_mb:
                    warning_msg = f"Process {process.pid} exceeded memory limit ({memory_mb:.2f} MB > {max_memory_mb} MB), terminating"
                    log_callback(warning_msg)
                    logger.warning(warning_msg)
                    kill_process(process)
                    break
            except psutil.NoSuchProcess:
                logger.debug(f"Process {process.pid} no longer exists")
                break
            except Exception as e:
                logger.warning(f"Error monitoring memory usage: {e}")
                break
            time.sleep(5)
    except Exception as e:
        logger.error(f"Unexpected error in memory monitoring: {e}", exc_info=True)
    logger.debug("Memory usage monitoring stopped")

def kill_process(process):
    if not process:
        logger.debug("kill_process called with None process")
        return
    logger.debug(f"Attempting to kill process {process.pid}")
    try:
        if process.poll() is None:
            logger.info(f"Terminating process {process.pid}")
            process.terminate()
            try: 
                process.wait(timeout=2)
                logger.info(f"Process {process.pid} terminated gracefully")
            except: 
                logger.warning(f"Process {process.pid} did not terminate in time, killing forcefully")
                process.kill()
                logger.info(f"Process {process.pid} killed forcefully")
        else:
            logger.debug(f"Process {process.pid} already exited with code {process.poll()}")
    except Exception as e:
        logger.error(f"Error killing process {process.pid}: {e}", exc_info=True)

def stop_all_processes(log_callback=None):
    logger.info("Stopping all winws processes")
    terminated_count = 0
    killed_count = 0
    
    # First attempt graceful termination
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                pid = proc.info['pid']
                logger.debug(f"Attempting to terminate process {pid}")
                proc.terminate()
                terminated_count += 1
                if log_callback:
                    log_callback(f"Terminating process {pid}")
        except psutil.NoSuchProcess:
            # pid might not be defined here, but we don't need it
            logger.debug("Process already terminated")
            continue
        except Exception as e:
            logger.warning(f"Error terminating process: {e}")
    
    if terminated_count > 0:
        logger.info(f"Sent termination signal to {terminated_count} processes")
        if log_callback:
            log_callback(f"Sent termination signal to {terminated_count} processes")
    
    # Wait for graceful shutdown
    time.sleep(1)
    
    # Force kill any remaining processes
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                pid = proc.info['pid']
                logger.debug(f"Process {pid} still running, killing forcefully")
                proc.kill()
                killed_count += 1
                if log_callback:
                    log_callback(f"Force killing process {pid}")
        except psutil.NoSuchProcess:
            # pid might not be defined here, but we don't need it
            logger.debug("Process already terminated")
            continue
        except Exception as e:
            logger.warning(f"Error killing process: {e}")
    
    if killed_count > 0:
        logger.info(f"Force killed {killed_count} processes")
        if log_callback:
            log_callback(f"Force killed {killed_count} processes")
    
    total_processes = terminated_count + killed_count
    if total_processes > 0:
        logger.info(f"Finished stopping {total_processes} winws processes")
    else:
        logger.debug("No winws processes found to stop")

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