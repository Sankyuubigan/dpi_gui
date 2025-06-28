import os
import subprocess
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
        # Используем taskkill напрямую, так как process_manager может быть недоступен
        subprocess.run(
            ["taskkill", "/F", "/IM", "winws.exe"], check=False, capture_output=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        
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

def is_custom_list_valid(filepath):
    """Проверяет, существует ли custom_list и не пуст ли он."""
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