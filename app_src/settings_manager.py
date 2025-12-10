import os
import subprocess
import shutil
import time
import json
import shlex

from process_manager import is_process_running, is_service_running, ZAPRET_SERVICE_NAME, WINWS_EXE

def save_app_settings(settings_data, app_dir):
    settings_file = os.path.join(app_dir, 'settings.json')
    try:
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings_data, f, indent=4)
    except Exception as e:
        print(f"Ошибка сохранения настроек: {e}")

def load_app_settings(app_dir):
    settings_file = os.path.join(app_dir, 'settings.json')
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def check_status(base_dir, log_callback, log_header=True):
    if log_header:
        log_callback("\n" + "="*40)
        log_callback("--- ПРОВЕРКА СТАТУСА ---")
    
    if is_process_running():
        log_callback("[+] Процессы winws.exe: ОБНАРУЖЕНЫ")
    else:
        log_callback("[-] Процессы winws.exe: НЕ ОБНАРУЖЕНЫ")
    
    if is_service_running():
        log_callback(f"[+] Служба {ZAPRET_SERVICE_NAME}: АКТИВНА")
    else:
        log_callback(f"[-] Служба {ZAPRET_SERVICE_NAME}: НЕ АКТИВНА")

    if log_header:
        log_callback("="*40 + "\n")

def install_service(base_dir, log_callback, profile, specific_list_path=None):
    """
    Установка службы с поддержкой конкретного списка.
    Если specific_list_path не передан, будет использоваться дефолтный list-general (как в профиле).
    """
    log_callback(f"\n--- Установка службы для профиля: {profile['name']} ---")
    
    bin_dir = os.path.join(base_dir, 'bin')
    lists_dir = os.path.join(base_dir, 'lists')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    
    raw_args = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        GAME_FILTER="1024-65535"
    )

    # Логика подмены списка для службы (аналогично process_manager)
    final_args_list = []
    if specific_list_path:
         try:
            args_list = shlex.split(raw_args)
         except:
            args_list = raw_args.split()
            
         for arg in args_list:
             if arg.startswith('--hostlist=') and 'list-general.txt' in arg:
                  prefix = arg.split('=')[0]
                  final_args_list.append(f'{prefix}={specific_list_path}')
             elif arg.startswith('--ipset='):
                 pass # Для службы пока игнорируем или берем дефолт, т.к. UI сложнее
             else:
                 final_args_list.append(arg)
    else:
         # Если список не передан, берем raw как есть
         final_args_list = shlex.split(raw_args)

    # Собираем строку аргументов обратно
    args_str = " ".join(final_args_list)
    
    bin_path = f'"{executable_path}" {args_str}'

    try:
        subprocess.run(['sc', 'stop', ZAPRET_SERVICE_NAME], capture_output=True)
        subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True)
        time.sleep(1)

        create_cmd = ['sc', 'create', ZAPRET_SERVICE_NAME, 'binPath=', bin_path, 'start=', 'auto', 'DisplayName=', 'Zapret DPI Bypass']
        subprocess.run(create_cmd, check=True, capture_output=True)
        subprocess.run(['sc', 'start', ZAPRET_SERVICE_NAME], check=True, capture_output=True)
        log_callback("\n[+] УСПЕХ! Служба запущена.")
    except Exception as e:
        log_callback(f"\n[!] ОШИБКА: {e}")
    log_callback("--- Установка службы завершена ---\n")

def uninstall_service(base_dir, log_callback):
    log_callback(f"\n--- Удаление службы '{ZAPRET_SERVICE_NAME}' ---")
    try:
        subprocess.run(['sc', 'stop', ZAPRET_SERVICE_NAME], capture_output=True)
        time.sleep(1)
        subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True)
        log_callback("[+] Команда удаления отправлена.")
    except Exception as e:
        log_callback(f"[!] Ошибка: {e}")
    log_callback("--- Удаление службы завершено ---\n")

def clear_discord_cache(base_dir, log_callback):
    log_callback("\n--- Очистка кэша Discord ---")
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'Discord.exe'], capture_output=True)
        time.sleep(1)
    except: pass

    appdata_path = os.getenv('APPDATA')
    if appdata_path:
        for cache_dir in ['Cache', 'Code Cache', 'GPUCache']:
            dir_to_delete = os.path.join(appdata_path, 'discord', cache_dir)
            if os.path.exists(dir_to_delete):
                try:
                    shutil.rmtree(dir_to_delete)
                    log_callback(f"[+] Удалено: {cache_dir}")
                except: pass
    log_callback("--- Очистка кэша завершена ---\n")