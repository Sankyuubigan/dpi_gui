import os
import subprocess
import shutil
import time
import json

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
        log_callback("[+] Разовый запуск (winws.exe): АКТИВЕН")
    else:
        log_callback("[-] Разовый запуск (winws.exe): НЕ АКТИВЕН")
    
    if is_service_running():
        log_callback(f"[+] Автозапуск (служба {ZAPRET_SERVICE_NAME}): АКТИВЕН")
    else:
        log_callback(f"[-] Автозапуск (служба {ZAPRET_SERVICE_NAME}): НЕ АКТИВЕН")
        
    app_settings = load_app_settings(base_dir)
    if app_settings.get("game_filter", False):
         log_callback("[+] Игровой фильтр: ВКЛЮЧЕН")
    else:
         log_callback("[-] Игровой фильтр: ВЫКЛЮЧЕН")

    ipset_sel = app_settings.get("ipset_selection", "OFF")
    if ipset_sel != "OFF":
        log_callback(f"[+] IPSet: ВКЛЮЧЕН (Файл: {ipset_sel})")
    else:
        log_callback("[-] IPSet: ВЫКЛЮЧЕН")

    if log_header:
        log_callback("="*40 + "\n")

def install_service(base_dir, log_callback, profile):
    log_callback(f"\n--- Установка службы для профиля: {profile['name']} ---")
    
    bin_dir = os.path.join(base_dir, 'bin')
    lists_dir = os.path.join(base_dir, 'lists')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    
    args_str = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        GAME_FILTER="1024-65535"
    )
    
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
                except:
                    log_callback(f"[!] Не удалось удалить: {cache_dir}")
    log_callback("--- Очистка кэша завершена ---\n")