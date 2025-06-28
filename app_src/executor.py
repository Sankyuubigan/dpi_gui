import os
import sys
import subprocess
import shlex
import re
import time
import json
from urllib.parse import urlparse
import requests
import zipfile
import shutil
import glob

def update_zapret_tool(base_dir, log_callback):
    """Скачивает и корректно распаковывает утилиту Zapret в папку с версией."""
    ZAPRET_REPO = "Flowseal/zapret-discord-youtube"
    API_URL = f"https://api.github.com/repos/{ZAPRET_REPO}/releases/latest"
    log_callback("\n--- Обновление утилиты Zapret ---")
    
    try:
        log_callback("-> Запрос к GitHub API для поиска последнего релиза...")
        response = requests.get(API_URL)
        response.raise_for_status()
        release_data = response.json()
        tag_name = release_data['tag_name']
        assets = release_data.get('assets', [])
        zip_url = None
        for asset in assets:
            if asset.get('name', '').endswith('.zip'):
                zip_url = asset['browser_download_url']
                break
        if not zip_url:
            log_callback("!!! ОШИБКА: В последнем релизе не найден .zip архив.")
            return
        log_callback(f"-> Найдена последняя версия: {tag_name}")
    except Exception as e:
        log_callback(f"!!! ОШИБКА: Не удалось получить информацию о релизе: {e}")
        return

    temp_zip_path = os.path.join(base_dir, '_zapret_update.zip')
    try:
        log_callback(f"-> Скачиваю архив: {zip_url}")
        with requests.get(zip_url, stream=True) as r:
            r.raise_for_status()
            with open(temp_zip_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except Exception as e:
        log_callback(f"!!! ОШИБКА СКАЧИВАНИЯ: {e}")
        if os.path.exists(temp_zip_path): os.remove(temp_zip_path)
        return

    try:
        log_callback("-> Остановка активных процессов winws.exe...")
        kill_existing_processes(log_callback)
        
        log_callback("-> Удаление старых версий папок 'zapret'...")
        old_zapret_folders = glob.glob(os.path.join(base_dir, 'zapret-discord-youtube-*'))
        for folder in old_zapret_folders:
            shutil.rmtree(folder)
            log_callback(f"   - Удалена папка: {os.path.basename(folder)}")

        target_dir = os.path.join(base_dir, f"zapret-discord-youtube-{tag_name}")
        os.makedirs(target_dir, exist_ok=True)
        log_callback(f"-> Создана папка: {os.path.basename(target_dir)}")

        log_callback("-> Распаковка новой версии...")
        with zipfile.ZipFile(temp_zip_path, 'r') as zf:
            zf.extractall(target_dir)
        
        log_callback(f"-> Утилита Zapret успешно обновлена до версии {tag_name}!")

    except Exception as e:
        log_callback(f"!!! ОШИБКА ПРИ УСТАНОВКЕ: {e}")
    finally:
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
            log_callback("-> Временный архив удален.")
        log_callback("--- Обновление утилиты Zapret завершено ---\n")


def find_bat_files(directory="."):
    bat_files = []
    if not os.path.isdir(directory): return []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".bat") and file.lower() != "service.bat":
                bat_files.append(os.path.abspath(os.path.join(root, file)))
    return sorted(bat_files)

def kill_existing_processes(log_callback):
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/IM", "winws.exe"], check=False, capture_output=True, text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if result.returncode == 0:
            log_callback("INFO: Один или несколько процессов winws.exe были успешно остановлены.")
        else:
            log_callback("INFO: Активных процессов winws.exe не найдено.")
    except Exception as e:
        log_callback(f"ERROR: Ошибка при попытке остановить процессы: {e}")

def get_game_filter_value(base_dir):
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    return "1024-65535" if os.path.exists(game_flag_file) else "0"

def is_custom_list_valid(filepath, log_callback):
    if not os.path.exists(filepath):
        return False
    if os.path.getsize(filepath) == 0:
        return False
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip() and not line.strip().startswith('#'):
                    return True
    except Exception:
        return False
    return False

def parse_command_from_bat(file_path, log_callback):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        marker = 'winws.exe"'
        parts = content.split(marker, 1)
        
        if len(parts) < 2:
            log_callback(f"DEBUG: Не удалось найти маркер '{marker}' в файле {os.path.basename(file_path)}")
            return ""
            
        command_str = parts
        command_str = command_str.replace('^', ' ').replace('\n', ' ').strip()
        log_callback(f"DEBUG: Успешно извлечена команда из {os.path.basename(file_path)}")
        return command_str
    except Exception as e:
        log_callback(f"DEBUG: Критическая ошибка при чтении файла {os.path.basename(file_path)}: {e}")
        return ""

def run_bat_file(file_path, app_base_path, log_callback):
    bat_base_dir = os.path.dirname(file_path)
    custom_list_path = os.path.join(app_base_path, 'custom_list.txt')
    custom_list_is_valid = is_custom_list_valid(custom_list_path, log_callback)
    game_filter = get_game_filter_value(bat_base_dir)
    
    raw_command_str = parse_command_from_bat(file_path, log_callback)
    
    if not raw_command_str:
        log_callback(f"ERROR: Не удалось извлечь команду из файла {os.path.basename(file_path)}. Проверьте содержимое .bat файла.")
        return None
        
    bin_path_with_sep = os.path.join(bat_base_dir, 'bin') + os.sep
    lists_path_with_sep = os.path.join(bat_base_dir, 'lists') + os.sep
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
    executable_path = os.path.join(bat_base_dir, 'bin', 'winws.exe')
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
            final_command, cwd=bat_base_dir, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            encoding='utf-8', errors='ignore'
        )
        return process
    except Exception as e:
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА ПРИ ЗАПУСКЕ: {e}")
        return None