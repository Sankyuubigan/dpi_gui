import urllib.request
import time
import subprocess
import process_manager
from executor import is_custom_list_valid
def check_connection(url, log_callback):
    """Проверяет доступность URL."""
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        log_callback(f"  -> Пробую соединиться с {url}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=5).close()
        return True
    except Exception as e:
        log_callback(f"  -> Соединение не удалось: {e}")
        return False
def run_site_test(domain, profiles, base_dir, game_filter_enabled, log_callback):
    """Запускает автоматический тест доступности сайта по всем профилям."""
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
    custom_list_path = f"{base_dir}\\lists\\custom_list.txt"
    use_custom_list = is_custom_list_valid(custom_list_path)
    for i, profile in enumerate(profiles):
        log_callback(f"--- Тест {i+1}/{len(profiles)}: \"{profile['name']}\" ---")
        process = process_manager.start_process(profile, base_dir, game_filter_enabled, use_custom_list, log_callback)
        
        if process:
            time.sleep(4) # Даем время на запуск и применение правил
            results[profile['name']] = "УСПЕХ" if check_connection(domain, log_callback) else "Неудача"
            process.terminate()
            process.wait()
        else:
            results[profile['name']] = "ОШИБКА ЗАПУСКА"
            
        log_callback(f"  Результат: {results[profile['name']]}\n")
        process_manager.stop_all_processes(lambda msg: None) # Тихая остановка
        time.sleep(1)
    log_callback("="*40)
    log_callback("--- РЕЗУЛЬТАТЫ АВТОМАТИЧЕСКОГО ТЕСТА ---")
    for name, status in results.items():
        log_callback(f"  {name:<30} : {status}")
    log_callback("="*40 + "\n")
def run_discord_test(profiles, base_dir, game_filter_enabled, log_callback, ask_user_callback):
    """Запускает интерактивный тест для Discord."""
    log_callback("\n" + "="*40)
    log_callback("--- Интерактивный тест для Discord ---")
    log_callback("Сейчас поочередно будут запущены все профили.")
    log_callback("После запуска каждого профиля проверяйте работу Discord.")
    log_callback("Затем отвечайте на всплывающий вопрос 'Да' или 'Нет'.")
    log_callback("="*40 + "\n")
    
    process_manager.stop_all_processes(log_callback)
    
    results = {}
    custom_list_path = f"{base_dir}\\lists\\custom_list.txt"
    use_custom_list = is_custom_list_valid(custom_list_path)
    for i, profile in enumerate(profiles):
        log_callback(f"--- Тест {i+1}/{len(profiles)}: \"{profile['name']}\" ---")
        process = process_manager.start_process(profile, base_dir, game_filter_enabled, use_custom_list, log_callback)
        
        if process:
            # Даем время на запуск и даем управление GUI для вопроса
            user_response = ask_user_callback(profile['name'])
            results[profile['name']] = "УСПЕХ" if user_response else "Неудача"
            process.terminate()
            process.wait()
        else:
            results[profile['name']] = "ОШИБКА ЗАПУСКА"
            
        log_callback(f"  Результат: {results[profile['name']]}\n")
        process_manager.stop_all_processes(lambda msg: None) # Тихая остановка
        time.sleep(1)
    log_callback("="*40)
    log_callback("--- РЕЗУЛЬТАТЫ ИНТЕРАКТИВНОГО ТЕСТА ---")
    for name, status in results.items():
        log_callback(f"  {name:<30} : {status}")
    log_callback("="*40 + "\n")