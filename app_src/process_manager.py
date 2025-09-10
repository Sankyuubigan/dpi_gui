import os
import subprocess
import shlex

WINWS_EXE = "winws.exe"
ZAPRET_SERVICE_NAME = "ZapretDPIBypass"

def start_process(profile, base_dir, game_filter_enabled, log_callback, combined_list_path=None, use_ipset=False):
    """Собирает команду и запускает процесс winws.exe."""
    bin_dir = os.path.join(base_dir, 'bin')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    
    if not os.path.exists(executable_path):
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл не найден: {executable_path}")
        return None
        
    game_filter_value = "1024-65535" if game_filter_enabled else "0"
    
    # 1. Берем строку аргументов из профиля и форматируем ее
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
    
    # 2. Фильтруем аргументы, удаляя ненужные
    final_args = []
    i = 0
    while i < len(base_args):
        arg = base_args[i]
        
        # Удаляем все стандартные --hostlist, так как мы будем использовать свой объединенный список
        if arg == '--hostlist':
            i += 2  # Пропускаем сам --hostlist и его значение
            continue
            
        # Удаляем --ipset, если он не выбран в UI
        if arg == '--ipset' and not use_ipset:
            i += 2  # Пропускаем --ipset и его значение
            continue
            
        final_args.append(arg)
        i += 1
        
    # 3. Добавляем наш объединенный список, если он существует
    if combined_list_path:
        final_args.extend(['--hostlist', combined_list_path])
    
    # 4. Собираем и запускаем финальную команду
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
            final_command,
            cwd=base_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            encoding='utf-8',
            errors='ignore'
        )
        return process
    except Exception as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА ПРИ ЗАПУСКЕ ПРОЦЕССА: {e}")
        return None

def stop_all_processes(log_callback):
    """Принудительно останавливает все процессы winws.exe."""
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/IM", WINWS_EXE],
            check=False, capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            log_callback("INFO: Один или несколько процессов winws.exe были успешно остановлены.")
        elif "128" not in str(result.returncode):
            log_callback(f"INFO: Активных процессов winws.exe не найдено (код: {result.returncode}).")
    except Exception as e:
        log_callback(f"ERROR: Ошибка при попытке остановить процессы: {e}")

def is_process_running():
    """Проверяет, запущен ли процесс winws.exe."""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', f'IMAGENAME eq {WINWS_EXE}'],
            capture_output=True, text=True, check=True,
            creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866'
        )
        return WINWS_EXE.lower() in result.stdout.lower()
    except Exception:
        return False

def is_service_running():
    """Проверяет, запущена ли служба Zapret."""
    try:
        result = subprocess.run(
            ['sc', 'query', ZAPRET_SERVICE_NAME],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866'
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False