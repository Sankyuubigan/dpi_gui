import os
import subprocess
import shlex
import re

def find_bat_files(directory="."):
    """Находит все .bat файлы рекурсивно, исключая service.bat."""
    bat_files = []
    if not os.path.isdir(directory):
        return []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".bat") and file.lower() != "service.bat":
                bat_files.append(os.path.abspath(os.path.join(root, file)))
    return sorted(bat_files)

def kill_existing_processes(log_callback):
    """Принудительно останавливает все процессы winws.exe на системе."""
    log_callback("Попытка остановить все существующие процессы winws.exe для чистого запуска...")
    try:
        # /F - принудительно, /IM - по имени образа.
        # CREATE_NO_WINDOW скрывает консольное окно.
        result = subprocess.run(
            ["taskkill", "/F", "/IM", "winws.exe"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if result.returncode == 0:
            log_callback("INFO: Один или несколько процессов winws.exe были успешно остановлены.")
        else:
            # Код 128 обычно означает "процесс не найден", что для нас не является ошибкой.
            log_callback("INFO: Активных процессов winws.exe не найдено, запуск продолжается.")
    except FileNotFoundError:
        log_callback("WARNING: Команда 'taskkill' не найдена. Не могу остановить предыдущие процессы.")
    except Exception as e:
        log_callback(f"ERROR: Ошибка при попытке остановить процессы: {e}")

def get_game_filter_value(base_dir):
    """Проверяет наличие game_filter.enabled и возвращает диапазон портов."""
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    return "1024-65535" if os.path.exists(game_flag_file) else "0"

def is_custom_list_valid(filepath, log_callback):
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0: return False
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