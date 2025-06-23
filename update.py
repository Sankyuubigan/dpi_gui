import os
import sys
import requests
import zipfile
import shutil
import subprocess

# --- КОНФИГУРАЦИЯ ---
# *** ИЗМЕНЕНО: Добавлен ваш репозиторий ***
GITHUB_REPO = 'Sankyuubigan/dpi_gui' 
BRANCH = 'main'
# ----------------------

TEMP_DIR = "_update_temp"
USER_FILES = [
    "zapret-discord-youtube-1.8.1", # Это имя будет искаться для копирования
    "custom_list.txt"
]
DOWNLOAD_URL = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/{BRANCH}.zip"

def cleanup():
    if os.path.isdir(TEMP_DIR):
        print("-> Deleting temporary files...")
        shutil.rmtree(TEMP_DIR)

def copy_user_data(destination_dir):
    print("-> Preserving user data (zapret folder and custom list)...")
    
    # Ищем папку zapret по шаблону, так как версия может меняться
    zapret_folder_found = False
    for item in os.listdir('.'):
        if os.path.isdir(item) and item.startswith('zapret-discord-youtube-'):
            USER_FILES[0] = item # Обновляем имя папки на актуальное
            zapret_folder_found = True
            break

    for item in USER_FILES:
        if not os.path.exists(item):
            print(f"   - WARNING: '{item}' not found, skipping.")
            continue
        
        destination_path = os.path.join(destination_dir, item)
        try:
            if os.path.isdir(item):
                shutil.copytree(item, destination_path)
            else:
                shutil.copy2(item, destination_path)
            print(f"   - Copied '{item}' to the new version sources.")
        except Exception as e:
            print(f"   - !!! ERROR: Failed to copy '{item}': {e}")
            return False
    return True

def update():
    cleanup()
    
    print(f"-> Downloading latest GUI version from {GITHUB_REPO}...")
    try:
        response = requests.get(DOWNLOAD_URL, stream=True)
        response.raise_for_status()
        zip_path = os.path.join(TEMP_DIR, 'source.zip')
        os.makedirs(TEMP_DIR, exist_ok=True)
        with open(zip_path, 'wb') as f:
            shutil.copyfileobj(response.raw, f)
    except requests.RequestException as e:
        print(f"!!! DOWNLOAD ERROR: {e}")
        cleanup()
        return False

    print("-> Unpacking archive...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(TEMP_DIR)
        os.remove(zip_path)
        unpacked_folder_name = os.listdir(TEMP_DIR)[0]
        source_path = os.path.abspath(os.path.join(TEMP_DIR, unpacked_folder_name))
    except Exception as e:
        print(f"!!! UNPACK ERROR: {e}")
        cleanup()
        return False

    if not copy_user_data(source_path):
        cleanup()
        return False

    print("-> Starting the build process for the new GUI version...")
    try:
        python_executable = sys.executable
        build_script_path = os.path.join(source_path, 'build.py')
        command = [python_executable, build_script_path, '--source-dir', source_path]
        subprocess.run(command, check=True)
        print("-> New GUI version built successfully.")
    except Exception as e:
        print(f"!!! NEW VERSION BUILD ERROR: {e}")
        cleanup()
        return False

    print("\n--- Update is ready to be installed. ---")
    print("Close this window, and the .bat file will complete the installation.")
    return True

if __name__ == "__main__":
    if GITHUB_REPO == 'YOUR_GITHUB_USERNAME/YOUR_REPO_NAME':
        print("="*60)
        print("!!! ATTENTION: GITHUB REPOSITORY IS NOT CONFIGURED !!!")
        sys.exit(1)
    if not update():
        sys.exit(1)