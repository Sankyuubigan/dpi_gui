import os
import subprocess
import shlex
WINWS_EXE = "winws.exe"
ZAPRET_SERVICE_NAME = "ZapretDPIBypass"
def start_process(profile, base_dir, game_filter_enabled, use_custom_list, log_callback, selected_lists=None, use_ipset=False):
    """Собирает команду и запускает процесс winws.exe."""
    bin_dir = os.path.join(base_dir, 'bin')
    lists_dir = os.path.join(base_dir, 'lists')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    if not os.path.exists(executable_path):
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл не найден: {executable_path}")
        return None
    game_filter_value = "1024-65535" if game_filter_enabled else "0"
    
    # Форматируем строку аргументов, заменяя плейсхолдеры
    args_str = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        GAME_FILTER=game_filter_value
    )
    # Используем shlex для безопасного разбора строки на аргументы
    try:
        base_args = shlex.split(args_str)
    except ValueError as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА РАЗБОРА АРГУМЕНТОВ: {e}")
        return None
    
    # Фильтруем аргументы: если use_ipset=False, удаляем все --ipset и следующий аргумент
    if not use_ipset:
        filtered_args = []
        i = 0
        while i < len(base_args):
            if base_args[i] == "--ipset":
                # Пропускаем этот аргумент и следующий (путь к файлу)
                i += 2
            else:
                filtered_args.append(base_args[i])
                i += 1
        base_args = filtered_args
    
    final_args = []
    
    # Добавляем --hostlist для custom_list.txt, если он валиден
    if use_custom_list:
        custom_list_path = os.path.join(lists_dir, 'custom_list.txt')
        # Проверяем, есть ли уже --hostlist в аргументах, чтобы не дублировать
        has_hostlist = any('--hostlist' in arg for arg in base_args)
        if not has_hostlist:
             final_args.extend(['--hostlist', custom_list_path])
    
    # Добавляем --hostlist для объединенного списка выбранных доменов
    if selected_lists:
        combined_list_path = selected_lists
        has_hostlist = any('--hostlist' in arg for arg in base_args)
        if not has_hostlist:
            final_args.extend(['--hostlist', combined_list_path])
    
    final_args.extend(base_args)
    
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
        else:
            # Код 128 означает, что процесс не найден, это не ошибка
            if "128" not in str(result.returncode):
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