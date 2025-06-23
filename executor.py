import os
import subprocess
import shlex

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

def get_game_filter_value(base_dir):
    """Проверяет наличие game_filter.enabled и возвращает диапазон портов."""
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    return "1024-65535" if os.path.exists(game_flag_file) else "0"

def is_custom_list_valid(filepath, log_callback):
    """Проверяет, что файл существует и содержит хотя бы одну активную строку."""
    if not os.path.exists(filepath):
        log_callback(f"INFO: Файл '{os.path.basename(filepath)}' не найден, кастомные домены не будут добавлены.")
        return False
    if os.path.getsize(filepath) == 0:
        log_callback(f"INFO: Файл '{os.path.basename(filepath)}' пуст.")
        return False
        
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    log_callback(f"INFO: Найден валидный файл '{os.path.basename(filepath)}', домены будут добавлены.")
                    return True
    except Exception as e:
        log_callback(f"ERROR: Не удалось прочитать '{os.path.basename(filepath)}': {e}")
        return False
        
    log_callback(f"INFO: В файле '{os.path.basename(filepath)}' не найдено активных доменов.")
    return False

def parse_command_from_bat(file_path):
    """Извлекает и очищает команду запуска winws.exe из .bat файла."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        command_str = ""
        capturing = False
        for line in lines:
            stripped_line = line.strip()
            if not capturing and 'winws.exe' in stripped_line:
                capturing = True
                command_part = stripped_line.split('winws.exe"', 1)[1] if 'winws.exe"' in stripped_line else stripped_line.split('winws.exe', 1)[1]
                command_str += command_part
            elif capturing:
                command_str += " " + stripped_line
            
            if capturing and not line.strip().endswith('^'):
                break
        
        # Удаляем все символы переноса строки `^`
        command_str = command_str.replace('^', '')
        return command_str.strip()
    except Exception:
        return ""

def run_bat_file(file_path, log_callback):
    """
    Анализирует .bat файл, корректно формирует команду и запускает её.
    """
    base_dir = os.path.dirname(file_path)
    custom_list_path = os.path.abspath('custom_list.txt')

    custom_list_is_valid = is_custom_list_valid(custom_list_path, log_callback)
    game_filter = get_game_filter_value(base_dir)

    raw_command_args = parse_command_from_bat(file_path)
    if not raw_command_args:
        log_callback(f"ERROR: Не удалось извлечь команду из файла {os.path.basename(file_path)}")
        return None

    args = shlex.split(raw_command_args, posix=False)
    
    blocks = []
    current_block = []
    for arg in args:
        if arg.lower() == '--new':
            if current_block:
                blocks.append(current_block)
            current_block = []
        else:
            current_block.append(arg)
    if current_block:
        blocks.append(current_block)

    final_args = []
    for i, block in enumerate(blocks):
        has_hostlist = any('--hostlist' in arg.lower() for arg in block)
        final_args.extend(block)
        
        if has_hostlist and custom_list_is_valid:
            final_args.extend(['--hostlist', custom_list_path])
        
        if i < len(blocks) - 1:
            final_args.append('--new')

    # В .bat файлах переменные %BIN% и %LISTS% содержат слеш в конце.
    # Мы должны это воспроизвести. os.path.join(path, '') добавляет слеш.
    bin_path_with_sep = os.path.join(os.path.join(base_dir, 'bin'), '')
    lists_path_with_sep = os.path.join(os.path.join(base_dir, 'lists'), '')
    
    final_args_substituted = []
    for arg in final_args:
        arg_substituted = arg.replace('%GameFilter%', game_filter)
        arg_substituted = arg_substituted.replace('%BIN%', bin_path_with_sep)
        arg_substituted = arg_substituted.replace('%LISTS%', lists_path_with_sep)
        final_args_substituted.append(arg_substituted)
    
    final_command = [os.path.join(bin_path_with_sep, 'winws.exe')] + final_args_substituted

    log_callback("="*20)
    log_callback("Собранная команда для запуска:")
    log_callback(" ".join(final_command))
    log_callback("="*20)

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
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА ПРИ ЗАПУСКЕ: {e}")
        return None