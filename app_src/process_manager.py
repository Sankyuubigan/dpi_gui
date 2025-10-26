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

# Настройка логирования
logger = logging.getLogger("process_manager")
if not logger.handlers:
    os.makedirs("roo_tests", exist_ok=True)
    handler = logging.FileHandler("roo_tests/process_manager.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Глобальная блокировка
process_lock = threading.Lock()

def is_admin():
    """Проверяет, запущен ли процесс с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Глобальные переменные для хранения параметров последнего запуска
_last_profile = None
_last_base_dir = None
_last_game_filter_enabled = None
_last_log_callback = None
_last_combined_list_path = None
_last_use_ipset = None
_current_process = None

def start_process(profile, base_dir, game_filter_enabled, log_callback, combined_list_path=None, use_ipset=False):
    """Запускает процесс с защитой от дублирования"""
    global _last_profile, _last_base_dir, _last_game_filter_enabled
    global _last_log_callback, _last_combined_list_path, _last_use_ipset, _current_process
    
    with process_lock:
        # Проверяем, не запущен ли уже процесс
        if _current_process and _current_process.poll() is None:
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Процесс уже запущен!")
            return _current_process
        
        # Дополнительная проверка через psutil
        if is_process_running():
            log_callback("ПРЕДУПРЕЖДЕНИЕ: Найден активный процесс winws.exe!")
            return None
        
        logger.info(f"Запуск процесса для профиля: {profile['name']}")
        
        # Сохраняем параметры
        _last_profile = profile
        _last_base_dir = base_dir
        _last_game_filter_enabled = game_filter_enabled
        _last_log_callback = log_callback
        _last_combined_list_path = combined_list_path
        _last_use_ipset = use_ipset
        
        bin_dir = os.path.join(base_dir, 'bin')
        executable_path = os.path.join(bin_dir, WINWS_EXE)
        
        if not os.path.exists(executable_path):
            log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл не найден: {executable_path}")
            return None
            
        game_filter_value = "1024-65535" if game_filter_enabled else "0"
        
        # Формируем аргументы
        args_str = profile["args"].format(
            LISTS_DIR=os.path.join(base_dir, 'lists'),
            BIN_DIR=bin_dir,
            GAME_FILTER=game_filter_value
        )
        
        try:
            base_args = shlex.split(args_str)
        except ValueError as e:
            log_callback(f"КРИТИЧЕСКАЯ ОШИБКА РАЗБОРА АРГУМЕНТОВ: {e}")
            return None
        
        # Обрабатываем аргументы
        final_args = []
        for arg in base_args:
            if arg.startswith('--hostlist=') and 'list-general.txt' in arg:
                if combined_list_path:
                    final_args.append(f'--hostlist={combined_list_path}')
                else:
                    log_callback(f"WARNING: Объединенный список пуст, аргумент '{arg}' пропущен.")
            elif arg.startswith('--ipset='):
                if use_ipset:
                    final_args.append(arg)
            else:
                final_args.append(arg)
        
        final_command = [executable_path] + final_args
        
        log_callback("="*40)
        log_callback("ЗАПУСК ПРОЦЕССА")
        log_callback(f"Исполняемый файл: {executable_path}")
        log_callback("Аргументы:")
        for i, arg in enumerate(final_args):
            log_callback(f"  [{i}]: {arg}")
        log_callback("="*40)
        
        if not is_admin():
            error_msg = "ОШИБКА: Требуются права администратора"
            logger.error(error_msg)
            log_callback(error_msg)
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
            logger.info(f"Процесс запущен: PID {process.pid}")
            
            # Запускаем мониторинг памяти
            threading.Thread(target=monitor_memory_usage, args=(process, log_callback), daemon=True).start()
            
            return process
        except Exception as e:
            logger.error(f"Ошибка запуска процесса: {e}")
            log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
            return None

def monitor_memory_usage(process, log_callback):
    """Мониторит потребление памяти"""
    try:
        max_memory_mb = 1024
        check_interval = 5
        
        while process and process.poll() is None:
            try:
                p = psutil.Process(process.pid)
                memory_mb = p.memory_info().rss / 1024 / 1024
                
                if memory_mb > max_memory_mb:
                    log_callback(f"ПРЕДУПРЕЖДЕНИЕ: Память ({memory_mb:.1f} МБ) > лимита ({max_memory_mb} МБ)")
                    log_callback("Принудительная остановка процесса")
                    stop_all_processes(log_callback)
                    break
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
                
            time.sleep(check_interval)
            
    except Exception as e:
        logger.error(f"Ошибка мониторинга памяти: {e}")

def stop_all_processes(log_callback):
    """Останавливает все процессы winws.exe"""
    global _current_process
    
    with process_lock:
        logger.info("Остановка всех процессов WinDivert")
        
        try:
            # Останавливаем отслеживаемый процесс
            if _current_process:
                try:
                    if _current_process.poll() is None:
                        _current_process.terminate()
                        try:
                            _current_process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            _current_process.kill()
                            _current_process.wait()
                        log_callback("Основной процесс остановлен")
                except Exception as e:
                    logger.error(f"Ошибка остановки основного процесса: {e}")
                finally:
                    _current_process = None
            
            # Ищем и останавливаем остальные процессы
            stopped_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                        proc.terminate()
                        stopped_count += 1
                        log_callback(f"Найден процесс winws.exe (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Ждем завершения
            time.sleep(2)
            
            # Принудительно убиваем оставшиеся
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                        proc.kill()
                        log_callback(f"Принудительно завершен процесс (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if stopped_count > 0:
                log_callback(f"INFO: Всего остановлено: {stopped_count}")
            else:
                log_callback("INFO: Активных процессов не найдено")
                
        except Exception as e:
            logger.error(f"Ошибка при остановке: {e}")
            log_callback(f"ERROR: {e}")

def restart_process():
    """Функция перезапуска ОТКЛЮЧЕНА - программа не должна ничего делать автоматически"""
    logger.info("Попытка автоматического перезапуска - ОТКЛЕНО")
    return None

def is_process_running():
    """Проверяет, запущен ли процесс winws.exe"""
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and proc.info['name'].lower() == WINWS_EXE.lower():
                logger.info(f"Процесс WinDivert запущен (PID: {proc.info['pid']})")
                return True
        logger.info("Процесс WinDivert не запущен")
        return False
    except Exception as e:
        logger.error(f"Ошибка проверки процесса: {e}")
        return False

def is_service_running():
    """Проверяет, запущена ли служба Zapret"""
    try:
        result = subprocess.run(
            ['sc', 'query', ZAPRET_SERVICE_NAME],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866'
        )
        is_running = "RUNNING" in result.stdout
        logger.info(f"Статус службы Zapret: {'Запущена' if is_running else 'Не запущена'}")
        return is_running
    except Exception as e:
        logger.error(f"Ошибка проверки службы: {e}")
        return False