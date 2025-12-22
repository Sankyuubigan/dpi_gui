import urllib.request
import time
import subprocess
import process_manager
from executor import is_custom_list_valid
import os
import socket
import traceback

def check_connection(url, log_callback):
    """Проверяет доступность URL."""
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        log_callback(f"  -> Пробую соединиться с {url}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=3).close()
        return True
    except socket.timeout:
        log_callback("  -> Соединение не удалось: Timeout")
        return False
    except Exception as e:
        err_str = str(e)
        if len(err_str) > 100: err_str = err_str[:100] + "..."
        log_callback(f"  -> Соединение не удалось: {err_str}")
        return False

def run_site_test(domain, profiles, base_dir, game_filter_enabled, log_callback, custom_list_path=None):
    """Запускает автоматический тест доступности сайта по всем профилям."""
    try:
        log_callback("\n" + "="*40)
        log_callback(f"--- Автоматический тест по сайту: {domain} ---")
        
        process_manager.stop_all_processes(log_callback)
        
        log_callback("\nШаг 1: Проверка доступности сайта БЕЗ обхода...")
        if check_connection(domain, log_callback):
            log_callback("\n[!] Сайт доступен без обхода. Тестирование не имеет смысла.")
            log_callback("="*40 + "\n")
            return
        log_callback("[+] Отлично, сайт заблокирован. Начинаем тестирование профилей.\n")
        
        results = {}
        
        list_to_use = None
        if custom_list_path and is_custom_list_valid(custom_list_path):
            list_to_use = custom_list_path
        
        for i, profile in enumerate(profiles):
            log_callback(f"--- Тест {i+1}/{len(profiles)}: \"{profile['name']}\" ---")
            
            # Если start_process не найден, здесь возникнет ошибка, которую мы теперь поймаем
            process = process_manager.start_process(profile, base_dir, game_filter_enabled, log_callback, list_to_use, False)
            
            if process:
                time.sleep(4) 
                is_success = check_connection(domain, log_callback)
                results[profile['name']] = "УСПЕХ" if is_success else "Неудача"
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
            else:
                results[profile['name']] = "ОШИБКА ЗАПУСКА"
                
            log_callback(f"  Результат: {results[profile['name']]}\n")
            process_manager.stop_all_processes(lambda msg: None) 
            time.sleep(1)
            
        log_callback("="*40)
        log_callback("--- РЕЗУЛЬТАТЫ АВТОМАТИЧЕСКОГО ТЕСТА ---")
        for name, status in results.items():
            log_callback(f"  {name:<30} : {status}")
        log_callback("="*40 + "\n")

    except Exception as e:
        error_info = traceback.format_exc()
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА В ТЕСТЕ:\n{error_info}")
        process_manager.stop_all_processes(lambda msg: None)

def run_discord_test(profiles, base_dir, game_filter_enabled, log_callback, ask_user_callback, custom_list_path=None):
    """Запускает интерактивный тест для Discord."""
    try:
        log_callback("\n" + "="*40)
        log_callback("--- Интерактивный тест для Discord ---")
        log_callback("Сейчас поочередно будут запущены все профили.")
        log_callback("После запуска каждого профиля проверяйте работу Discord.")
        log_callback("Затем отвечайте на всплывающий вопрос 'Да' или 'Нет'.")
        log_callback("="*40 + "\n")
        
        process_manager.stop_all_processes(log_callback)
        
        results = {}
        
        list_to_use = None
        if custom_list_path and is_custom_list_valid(custom_list_path):
            list_to_use = custom_list_path
        
        for i, profile in enumerate(profiles):
            log_callback(f"--- Тест {i+1}/{len(profiles)}: \"{profile['name']}\" ---")
            process = process_manager.start_process(profile, base_dir, game_filter_enabled, log_callback, list_to_use, False)
            
            if process:
                user_response = ask_user_callback(profile['name'])
                results[profile['name']] = "УСПЕХ" if user_response else "Неудача"
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
            else:
                results[profile['name']] = "ОШИБКА ЗАПУСКА"
                
            log_callback(f"  Результат: {results[profile['name']]}\n")
            process_manager.stop_all_processes(lambda msg: None) 
            time.sleep(1)
            
        log_callback("="*40)
        log_callback("--- РЕЗУЛЬТАТЫ ИНТЕРАКТИВНОГО ТЕСТА ---")
        for name, status in results.items():
            log_callback(f"  {name:<30} : {status}")
        log_callback("="*40 + "\n")

    except Exception as e:
        error_info = traceback.format_exc()
        log_callback(f"КРИТИЧЕСКАЯ ОШИБКА В ТЕСТЕ:\n{error_info}")
        process_manager.stop_all_processes(lambda msg: None)