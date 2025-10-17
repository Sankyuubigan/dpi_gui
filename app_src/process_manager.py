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
    
    # 2. Обрабатываем аргументы, корректно заменяя hostlist и управляя ipset
    final_args = []
    for arg in base_args:
        # Ищем аргумент вида --hostlist=path
        if arg.startswith('--hostlist=') and 'list-general.txt' in arg:
            if combined_list_path:
                final_args.append(f'--hostlist={combined_list_path}')
                log_callback(f"!!! УСПЕХ: Аргумент '{arg}' заменен на '--hostlist={combined_list_path}'")
            else:
                # Если объединенного списка нет, пропускаем этот аргумент
                log_callback(f"WARNING: Объединенный список пуст, аргумент '{arg}' пропущен.")
        # Управляем --ipset в зависимости от настройки в UI
        elif arg.startswith('--ipset='):
            if use_ipset:
                final_args.append(arg)
            else:
                log_callback(f"INFO: IPSet отключен в настройках, аргумент '{arg}' пропущен.")
        else:
            # Все остальные аргументы оставляем как есть
            final_args.append(arg)
    
    # 3. Собираем и запускаем финальную команду
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