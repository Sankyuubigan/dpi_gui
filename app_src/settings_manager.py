import os
import subprocess
import urllib.request
import shutil
import time

from process_manager import is_process_running, is_service_running, ZAPRET_SERVICE_NAME, WINWS_EXE

def get_game_filter_status(base_dir):
    """Проверяет, включен ли игровой фильтр."""
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    return os.path.exists(game_flag_file)

def toggle_game_filter(base_dir, log_callback):
    """Включает или выключает игровой фильтр."""
    game_flag_file = os.path.join(base_dir, 'bin', 'game_filter.enabled')
    if get_game_filter_status(base_dir):
        log_callback("Выключение игрового фильтра...")
        try:
            os.remove(game_flag_file)
            log_callback("[+] Фильтр выключен.")
        except OSError as e:
            log_callback(f"[!] Ошибка: {e}")
    else:
        log_callback("Включение игрового фильтра...")
        try:
            open(game_flag_file, 'w').close()
            log_callback("[+] Фильтр включен.")
        except OSError as e:
            log_callback(f"[!] Ошибка: {e}")
    log_callback("(!) Перезапустите обход или службу, чтобы изменения вступили в силу.")

def update_ipset_list(base_dir, log_callback):
    """Обновляет список ipset-all.txt с GitHub."""
    log_callback("\n--- Обновление списка ipset-all.txt ---")
    IPSET_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/lists/ipset-all.txt"
    target_path = os.path.join(base_dir, 'lists', 'ipset-all.txt')
    try:
        with urllib.request.urlopen(IPSET_URL) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        log_callback("[+] Список ipset-all.txt успешно обновлен.")
    except Exception as e:
        log_callback(f"\n[!] Не удалось обновить список: {e}")
    log_callback("-------------------------------------\n")

def check_status(base_dir, log_callback, log_header=True):
    """Проверяет и выводит в лог статус процессов и настроек."""
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
        
    if get_game_filter_status(base_dir):
        log_callback("[+] Игровой фильтр: ВКЛЮЧЕН")
    else:
        log_callback("[-] Игровой фильтр: ВЫКЛЮЧЕН")
    
    if log_header:
        log_callback("="*40 + "\n")

def install_service(base_dir, log_callback, profile):
    """Устанавливает профиль как службу Windows."""
    log_callback(f"\n--- Установка службы для профиля: {profile['name']} ---")
    
    bin_dir = os.path.join(base_dir, 'bin')
    lists_dir = os.path.join(base_dir, 'lists')
    executable_path = os.path.join(bin_dir, WINWS_EXE)
    
    # Для службы игровой фильтр всегда включен, как в оригинальном скрипте
    game_filter_value = "1024-65535"
    
    args_str = profile["args"].format(
        LISTS_DIR=lists_dir,
        BIN_DIR=bin_dir,
        GAME_FILTER=game_filter_value
    )
    
    # sc.exe требует особого форматирования binPath
    bin_path = f'"{executable_path}" {args_str}'

    try:
        # Сначала останавливаем и удаляем старую службу, если она есть
        subprocess.run(['sc', 'stop', ZAPRET_SERVICE_NAME], capture_output=True)
        subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True)
        time.sleep(1) # Пауза на удаление

        # Создаем новую службу
        create_cmd = ['sc', 'create', ZAPRET_SERVICE_NAME, 'binPath=', bin_path, 'start=', 'auto', 'DisplayName=', 'Zapret DPI Bypass']
        log_callback(f"Выполняю: {' '.join(create_cmd)}")
        subprocess.run(create_cmd, check=True, capture_output=True)
        
        # Запускаем службу
        subprocess.run(['sc', 'start', ZAPRET_SERVICE_NAME], check=True, capture_output=True)
        
        log_callback("\n[+] УСПЕХ! Служба запущена и добавлена в автозапуск.")
    except Exception as e:
        log_callback(f"\n[!] ПРОИЗОШЛА ОШИБКА: {e}")
        if hasattr(e, 'stderr'):
            log_callback(f"    Детали: {e.stderr.decode('cp866', errors='ignore')}")
    log_callback("--- Установка службы завершена ---\n")

def uninstall_service(base_dir, log_callback):
    """Удаляет службу из автозапуска."""
    log_callback(f"\n--- Удаление службы '{ZAPRET_SERVICE_NAME}' ---")
    try:
        # Останавливаем службу
        subprocess.run(['sc', 'stop', ZAPRET_SERVICE_NAME], capture_output=True)
        time.sleep(1)

        # Удаляем службу
        delete_result = subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True, text=True, encoding='cp866')
        
        if "SUCCESS" in delete_result.stdout or "[SC] DeleteService УСПЕХ" in delete_result.stdout:
            log_callback("[+] Служба успешно удалена.")
        elif "1060" in delete_result.stderr:
            log_callback("(-) Служба не найдена (уже удалена).")
        else:
            log_callback(f"[!] Не удалось удалить службу: {delete_result.stderr or 'Неизвестная ошибка'}")
    except Exception as e:
        log_callback(f"[!] Произошла ошибка: {e}")
    log_callback("--- Удаление службы завершено ---\n")

def clear_discord_cache(base_dir, log_callback):
    """Очищает кэш Discord."""
    log_callback("\n--- Очистка кэша Discord ---")
    try:
        result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Discord.exe'], capture_output=True, text=True, encoding='cp866')
        if result.stdout.lower().count('discord.exe') > 0:
            log_callback("Закрытие Discord...")
            subprocess.run(['taskkill', '/F', '/IM', 'Discord.exe'], capture_output=True)
            time.sleep(1)
    except FileNotFoundError:
        pass # tasklist не найден, ничего страшного

    appdata_path = os.getenv('APPDATA')
    if appdata_path:
        for cache_dir in ['Cache', 'Code Cache', 'GPUCache']:
            dir_to_delete = os.path.join(appdata_path, 'discord', cache_dir)
            if os.path.exists(dir_to_delete):
                try:
                    shutil.rmtree(dir_to_delete)
                    log_callback(f"[+] Папка '{cache_dir}' удалена.")
                except OSError as e:
                    log_callback(f"[!] Не удалось удалить '{cache_dir}': {e}")
            else:
                log_callback(f"(-) Папка '{cache_dir}' не найдена.")
    else:
        log_callback("[!] Не удалось найти папку AppData.")
    log_callback("--- Очистка кэша завершена ---\n")