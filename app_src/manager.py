# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import ctypes
import time
import shutil
import urllib.request

# --- КОНФИГУРАЦИЯ ---
ZAPRET_SERVICE_NAME = "ZapretDPIBypass"
IPSET_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/lists/ipset-all.txt"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, 'bin')
LISTS_DIR = os.path.join(SCRIPT_DIR, 'lists')
WINWS_EXE = os.path.join(BIN_DIR, 'winws.exe')

# --- ПРОФИЛИ ЗАПУСКА ---
PROFILES = [
    {
        "name": "Игровой (Макс. совместимость)",
        "args": "--wf-tcp=80,443 --wf-udp=443,50000-50100 "
                "--filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-for-games.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new "
                "--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                "--filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-for-games.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                "--filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-for-games.txt\" --dpi-desync=fake,split --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\""
    },
    {
        "name": "General (Основной)",
        "args": "--wf-tcp=80,443,{GAME_FILTER} --wf-udp=443,50000-50100,{GAME_FILTER} --filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=8 --dpi-desync-fooling=md5sig,badseq --new --filter-udp=443 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-tcp=80 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443,{GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig,badseq --new --filter-udp={GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2"
    },
    {
        "name": "General (ALT)",
        "args": "--wf-tcp=80,443,{GAME_FILTER} --wf-udp=443,50000-50100,{GAME_FILTER} --filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp=443 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-tcp=80 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443,{GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp={GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3"
    },
    {
        "name": "General (ALT2)",
        "args": "--wf-tcp=80,443,{GAME_FILTER} --wf-udp=443,50000-50100,{GAME_FILTER} --filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=split2 --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp=443 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-tcp=80 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443,{GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=split2 --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp={GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2"
    },
    {
        "name": "General (FAKE TLS)",
        "args": "--wf-tcp=80,443,{GAME_FILTER} --wf-udp=443,50000-50100,{GAME_FILTER} --filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new --filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new --filter-udp=443 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-tcp=80 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new --filter-tcp=443,{GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new --filter-udp={GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3"
    },
    {
        "name": "General (МГТС)",
        "args": "--wf-tcp=80,443,{GAME_FILTER} --wf-udp=443,50000-50100,{GAME_FILTER} --filter-udp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-tcp=80 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443 --hostlist=\"{LISTS_DIR}\\list-general.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp=443 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --new --filter-tcp=80 --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new --filter-tcp=443,{GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"{BIN_DIR}\\tls_clienthello_www_google_com.bin\" --new --filter-udp={GAME_FILTER} --ipset=\"{LISTS_DIR}\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"{BIN_DIR}\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2"
    }
]

# --- УТИЛИТАРНЫЕ ФУНКЦИИ ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("=" * 45)
    print("    Менеджер обхода блокировок (Zapret)")
    print("=" * 45)
    print()

def press_enter_to_continue():
    input("\nНажмите Enter, чтобы вернуться в меню...")

def get_game_filter_status():
    return os.path.exists(os.path.join(BIN_DIR, 'game_filter.enabled'))

def get_game_filter_value():
    return "1024-65535" if get_game_filter_status() else "0"

def is_process_running(process_name):
    try:
        result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {process_name}'], capture_output=True, text=True, check=True, encoding='cp866')
        return process_name.lower() in result.stdout.lower()
    except: return False

def is_service_running(service_name):
    try:
        result = subprocess.run(['sc', 'query', service_name], capture_output=True, text=True, encoding='cp866')
        return "RUNNING" in result.stdout
    except: return False

def stop_all_bypass_processes():
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'winws.exe'], capture_output=True, text=True)
    except FileNotFoundError:
        pass

def check_dependencies():
    if not os.path.exists(WINWS_EXE):
        print_header()
        print("[!] КРИТИЧЕСКАЯ ОШИБКА: Файл не найден!")
        print(f"    Не удалось найти главный файл программы: {WINWS_EXE}")
        print("\n    Пожалуйста, убедитесь, что файл manager.py находится в той же папке,")
        print("    что и папки 'bin' и 'lists'.")
        press_enter_to_continue()
        return False
    return True

def check_connection(url):
    if not url.startswith('http'): url = 'https://' + url
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=5).close()
        return True
    except: return False

# --- ФУНКЦИИ ТЕСТИРОВАНИЯ И УПРАВЛЕНИЯ ---

def pre_run_checks():
    """Общая проверка перед запуском тестов или ручного режима."""
    if not check_dependencies():
        return False
    stop_all_bypass_processes()
    if is_service_running(ZAPRET_SERVICE_NAME):
        print("[!] Обнаружена работающая служба. Пожалуйста, остановите ее (пункт 6) и попробуйте снова.")
        press_enter_to_continue()
        return False
    return True

def choose_profile_from_menu():
    """Отображает меню выбора профиля и возвращает выбор пользователя."""
    print("Выберите профиль из списка:\n")
    for i, profile in enumerate(PROFILES):
        print(f"  {i + 1}. {profile['name']}")
    
    choice = -1
    while not (1 <= choice <= len(PROFILES)):
        try:
            choice = int(input(f"\nВведите номер профиля (1-{len(PROFILES)}): "))
        except ValueError:
            print("Неверный ввод. Пожалуйста, введите число.")
    return PROFILES[choice - 1]

def auto_test_by_site():
    print_header()
    print("--- Автоматический тест по сайту ---")
    target_domain = input("Введите адрес заблокированного сайта для теста (например, rutracker.org): ")
    if not target_domain: target_domain = "rutracker.org"
    
    print(f"\nШаг 1: Проверка блокировки '{target_domain}' без обхода...")
    if check_connection(target_domain):
        print("[!] Сайт доступен без обхода. Тестирование не имеет смысла.")
        press_enter_to_continue()
        return
    else:
        print("[+] Отлично, сайт заблокирован. Начинаем тестирование.\n")
    
    results = {}
    for i, profile in enumerate(PROFILES):
        print(f"--- Тест {i+1}/{len(PROFILES)}: \"{profile['name']}\" ---")
        process = subprocess.Popen(f'"{WINWS_EXE}" {profile["args"].format(GAME_FILTER=get_game_filter_value(), LISTS_DIR=LISTS_DIR, BIN_DIR=BIN_DIR)}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        results[profile['name']] = "УСПЕХ" if check_connection(target_domain) else "Неудача"
        print(f"  Результат: {results[profile['name']]}")
        process.terminate()
        stop_all_bypass_processes()
        time.sleep(1)

    print_header()
    print("--- Результаты автоматического теста ---")
    for name, status in results.items(): print(f"  {name:<30} : {status}")
    press_enter_to_continue()

def interactive_test_for_discord():
    print_header()
    print("--- Интерактивный тест для Discord ---")
    if input("Очистить кэш Discord перед тестом? (1 = Да, 0 = Нет): ") == '1':
        clear_discord_cache()

    print_header()
    print("--- Интерактивный тест для Discord ---")
    print("1. Откройте (или перезапустите) Discord.")
    print("2. Перейдите в проблемное место (чат, стрим).")
    input("\nКогда будете готовы, нажмите Enter, чтобы начать...")

    results = {}
    for i, profile in enumerate(PROFILES):
        clear_screen()
        print(f"--- Тест {i+1}/{len(PROFILES)}: \"{profile['name']}\" ---")
        process = subprocess.Popen(f'"{WINWS_EXE}" {profile["args"].format(GAME_FILTER=get_game_filter_value(), LISTS_DIR=LISTS_DIR, BIN_DIR=BIN_DIR)}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("\n[+] Профиль запущен. Пожалуйста, проверьте Discord.")
        answer = ""
        while answer not in ['1', '0']:
            answer = input("    Заработало? (1 = Да, 0 = Нет): ")
        results[profile['name']] = "УСПЕХ" if answer == '1' else "Неудача"
        process.terminate()
        stop_all_bypass_processes()
        print("\n[+] Профиль остановлен...")
        time.sleep(2)

    print_header()
    print("--- Результаты интерактивного теста ---")
    for name, status in results.items(): print(f"  {name:<30} : {status}")
    press_enter_to_continue()

def run_single_profile():
    print_header()
    print("--- Разовый запуск профиля ---")
    profile = choose_profile_from_menu()
    command = f'"{WINWS_EXE}" {profile["args"].format(GAME_FILTER=get_game_filter_value(), LISTS_DIR=LISTS_DIR, BIN_DIR=BIN_DIR)}'
    subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
    print(f"\n[+] Профиль \"{profile['name']}\" запущен в новом окне.")
    print("    Вы можете свернуть это окно, но не закрывайте его.")
    press_enter_to_continue()

def add_to_autostart():
    print_header()
    print("--- Установка профиля в автозапуск ---")
    profile = choose_profile_from_menu()
    bin_path = f'"{WINWS_EXE}" {profile["args"].format(GAME_FILTER=get_game_filter_value(), LISTS_DIR=LISTS_DIR, BIN_DIR=BIN_DIR)}'
    print(f"\nДобавление в автозапуск с профилем: {profile['name']}...")
    try:
        subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True)
        subprocess.run(['sc', 'create', ZAPRET_SERVICE_NAME, 'binPath=', bin_path, 'start=', 'auto', 'DisplayName=', 'Zapret DPI Bypass'], check=True, capture_output=True)
        subprocess.run(['sc', 'start', ZAPRET_SERVICE_NAME], check=True, capture_output=True)
        print("\n[+] УСПЕХ! Служба запущена и добавлена в автозапуск.")
    except Exception as e:
        print(f"\n[!] Произошла ошибка: {e}")
    press_enter_to_continue()

def remove_from_autostart():
    print_header()
    print(f"Удаление службы '{ZAPRET_SERVICE_NAME}' из автозапуска...")
    try:
        subprocess.run(['sc', 'stop', ZAPRET_SERVICE_NAME], capture_output=True)
        delete_result = subprocess.run(['sc', 'delete', ZAPRET_SERVICE_NAME], capture_output=True, text=True, encoding='cp866')
        if "SUCCESS" in delete_result.stdout or "[SC] DeleteService УСПЕХ" in delete_result.stdout:
            print("[+] Служба успешно удалена.")
        elif "1060" in delete_result.stderr:
            print("(-) Служба не найдена (уже удалена).")
        else:
            print(f"[!] Не удалось удалить службу: {delete_result.stderr or 'Неизвестная ошибка'}")
    except Exception as e:
        print(f"[!] Произошла ошибка: {e}")
    press_enter_to_continue()

def check_status():
    print_header()
    print("--- Проверка статуса ---")
    if is_process_running('winws.exe'): print("[+] Разовый запуск: АКТИВЕН")
    else: print("[-] Разовый запуск: НЕ АКТИВЕН")
    if is_service_running(ZAPRET_SERVICE_NAME): print(f"[+] Автозапуск (служба): АКТИВЕН")
    else: print(f"[-] Автозапуск (служба): НЕ АКТИВЕН")
    if get_game_filter_status(): print("[+] Игровой фильтр: ВКЛЮЧЕН")
    else: print("[-] Игровой фильтр: ВЫКЛЮЧЕН")
    press_enter_to_continue()

def toggle_game_filter():
    print_header()
    game_flag_file = os.path.join(BIN_DIR, 'game_filter.enabled')
    if get_game_filter_status():
        print("Выключение игрового фильтра...")
        try: os.remove(game_flag_file); print("[+] Фильтр выключен.")
        except OSError as e: print(f"[!] Ошибка: {e}")
    else:
        print("Включение игрового фильтра...")
        try: open(game_flag_file, 'w').close(); print("[+] Фильтр включен.")
        except OSError as e: print(f"[!] Ошибка: {e}")
    print("\n(!) Перезапустите обход или службу, чтобы изменения вступили в силу.")
    press_enter_to_continue()

def update_ipset_list():
    print_header()
    print(f"Обновление списка ipset-all.txt с GitHub...")
    try:
        with urllib.request.urlopen(IPSET_URL) as response, open(os.path.join(LISTS_DIR, 'ipset-all.txt'), 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        print("[+] Список ipset-all.txt успешно обновлен.")
    except Exception as e:
        print(f"\n[!] Не удалось обновить список: {e}")
    press_enter_to_continue()

def clear_discord_cache():
    print_header()
    print("--- Очистка кэша Discord ---")
    try:
        if subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Discord.exe'], capture_output=True, text=True, encoding='cp866').stdout.lower().count('discord.exe') > 0:
            print("Закрытие Discord..."); subprocess.run(['taskkill', '/F', '/IM', 'Discord.exe'], capture_output=True); time.sleep(1)
    except FileNotFoundError: pass
    appdata_path = os.getenv('APPDATA')
    if appdata_path:
        for cache_dir in ['Cache', 'Code Cache', 'GPUCache']:
            dir_to_delete = os.path.join(appdata_path, 'discord', cache_dir)
            if os.path.exists(dir_to_delete):
                try: shutil.rmtree(dir_to_delete); print(f"[+] Папка '{cache_dir}' удалена.")
                except OSError as e: print(f"[!] Не удалось удалить '{cache_dir}': {e}")
    else: print("[!] Не удалось найти папку AppData.")
    input("\nНажмите Enter, чтобы продолжить...")

def main():
    if not is_admin():
        print("Требуются права администратора. Перезапуск..."); run_as_admin(); sys.exit()

    while True:
        print_header()
        print("--- Тестирование ---")
        print("1. Интерактивный тест для Discord")
        print("2. Автоматический тест по сайту")
        print("\n--- Ручное управление ---")
        print("3. Запустить один профиль (разово)")
        print("4. Остановить разовый запуск")
        print("\n--- Автозапуск (Служба) ---")
        print("5. Установить профиль в автозапуск")
        print("6. Удалить из автозапуска")
        print("\n--- Настройки и информация ---")
        print("7. Проверить статус")
        print(f"8. Вкл/Выкл игровой фильтр (сейчас: {'ВКЛ' if get_game_filter_status() else 'ВЫКЛ'})")
        print("9. Обновить списки блокировок")
        print("0. Выход")
        
        choice = input("\nВведите ваш выбор: ")
        
        if choice in ['1', '2', '3', '5']:
            if not pre_run_checks(): continue
        
        if choice == '1': interactive_test_for_discord()
        elif choice == '2': auto_test_by_site()
        elif choice == '3': run_single_profile()
        elif choice == '4': stop_all_bypass_processes(); print("Разовый запуск остановлен."); time.sleep(1)
        elif choice == '5': add_to_autostart()
        elif choice == '6': remove_from_autostart()
        elif choice == '7': check_status()
        elif choice == '8': toggle_game_filter()
        elif choice == '9': update_ipset_list()
        elif choice == '0': sys.exit()
        else: print("Неверный выбор, попробуйте снова."); time.sleep(1)

if __name__ == "__main__":
    main()