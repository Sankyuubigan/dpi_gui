import os
import json
import subprocess
import shutil
import time

# ... (импорты process_manager) ...
from process_manager import is_process_running, is_service_running, ZAPRET_SERVICE_NAME, WINWS_EXE

def save_app_settings(settings_data, app_dir):
    settings_file = os.path.join(app_dir, 'settings.json')
    try:
        # Конвертируем данные в JSON-совместимый формат
        # (в данном случае list_manager.rules уже список словарей, все ок)
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings_data, f, indent=4)
    except Exception as e:
        print(f"Ошибка сохранения настроек: {e}")

def load_app_settings(app_dir):
    settings_file = os.path.join(app_dir, 'settings.json')
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # МИГРАЦИЯ: Если старый формат (с маппингами), создаем правила
                if "rules" not in data and "list_profile_map" in data:
                    new_rules = []
                    # Конвертируем старые списки
                    pmap = data.get("list_profile_map", {})
                    imap = data.get("list_ipset_map", {})
                    
                    for filename, profile in pmap.items():
                        if profile != "ОТКЛЮЧЕНО":
                            new_rules.append({"file": filename, "type": "list", "profile": profile})
                            
                            # Если был привязан ipset, добавляем его отдельной строкой
                            ipset_file = imap.get(filename, "OFF")
                            if ipset_file and ipset_file != "OFF":
                                new_rules.append({"file": ipset_file, "type": "ipset", "profile": profile})
                    
                    data["rules"] = new_rules
                
                return data
        except:
            return {}
    return {}

# ... (остальные функции check_status, install_service и т.д. без изменений) ...
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