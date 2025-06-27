import os
import sys
import subprocess
import datetime
import shutil
import argparse

# --- Конфигурация проекта ---
PROJECT_NAME = "dpi_gui"
SPEC_FILE = f"{PROJECT_NAME}.spec"
DIST_DIR = "dist"
VERSION_FILE = "_version.py"
RELEASES_TO_KEEP = 5 # Сколько последних релизов оставлять
# -----------------------------

def run_command(command, cwd=None, check=True):
    """Запускает команду и возвращает ее вывод."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=check,
            encoding='utf-8', cwd=cwd
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"!!! ОШИБКА: Команда '{command}' не найдена. Убедитесь, что она установлена и доступна в PATH.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"!!! ОШИБКА ВЫПОЛНЕНИЯ КОМАНДЫ: {command}")
        print(f"    вывод: {e.stderr.strip()}")
        return None

def get_git_info(source_directory):
    """Получает дату и сообщение последнего коммита."""
    date_cmd = ['git', 'log', '-1', '--format=%cd', '--date=format:%y.%m.%d']
    msg_cmd = ['git', 'log', '-1', '--format=%B']
    
    version = run_command(date_cmd, cwd=source_directory)
    message = run_command(msg_cmd, cwd=source_directory)

    if version and message:
        return version, message
    return datetime.date.today().strftime('%y.%m.%d'), "Сборка без Git"

def cleanup_old_releases():
    """Удаляет старые релизы, оставляя только RELEASES_TO_KEEP."""
    print("\n--- Очистка старых релизов на GitHub ---")
    
    # Получаем список всех релизов (тегов)
    list_cmd = ['gh', 'release', 'list', '--limit', '1000']
    releases_output = run_command(list_cmd)
    
    if releases_output is None:
        print("Не удалось получить список релизов. Пропускаю очистку.")
        return

    # Разделяем вывод на строки, чтобы получить каждый релиз
    # Первый столбец в выводе - это название релиза, второй - тег
    lines = releases_output.strip().split('\n')
    tags_to_delete = []
    
    # Пропускаем заголовок и RELEASES_TO_KEEP релизов
    if len(lines) > RELEASES_TO_KEEP + 1:
        for line in lines[RELEASES_TO_KEEP + 1:]:
            try:
                # Тег обычно находится во втором столбце
                tag = line.split('\t')
                tags_to_delete.append(tag)
            except IndexError:
                continue # Пропускаем строки с неверным форматом

    if not tags_to_delete:
        print("-> Старых релизов для удаления не найдено.")
        return

    print(f"-> Найдено {len(tags_to_delete)} старых релизов для удаления.")
    for tag in tags_to_delete:
        print(f"   - Удаляю релиз с тегом: {tag}")
        delete_cmd = ['gh', 'release', 'delete', tag, '--yes'] # --yes для подтверждения
        run_command(delete_cmd)

def build_project(source_dir, no_release=False):
    """Собирает проект и опционально создает/очищает релизы на GitHub."""
    
    version_string, release_notes = get_git_info(source_dir)
    tag_name = f"v{version_string}"
    
    version_file_path = os.path.join(source_dir, VERSION_FILE)
    try:
        with open(version_file_path, 'w', encoding='utf-8') as f:
            f.write(f'__version__ = "{version_string}"\n')
    except IOError as e:
        print(f"!!! ОШИБКА: Не удалось записать файл версии: {e}")
        return

    print(f"\n--- Начало сборки проекта '{PROJECT_NAME}' {tag_name} ---")
    try:
        python_executable = sys.executable
        spec_file_path = os.path.join(source_dir, SPEC_FILE)
        icon_file = os.path.join(source_dir, 'icon.ico')

        command = [
            python_executable, "-m", "PyInstaller", "--noconfirm", "--clean"
        ]
        
        # Добавляем иконку в .exe, если она существует
        if os.path.exists(icon_file):
            command.append(f"--icon={icon_file}")
        
        command.append(spec_file_path)

        subprocess.run(command, check=True, cwd=source_dir, capture_output=True)
        print("-> Сборка PyInstaller успешно завершена.")
    except Exception as e:
        print(f"!!! ОШИБКА СБОРКИ: {e}")
        if os.path.exists(version_file_path): os.remove(version_file_path)
        return
    
    build_dir = os.path.join(source_dir, DIST_DIR, PROJECT_NAME)
    archive_name = f"{PROJECT_NAME}_{tag_name}"
    archive_path = os.path.join(source_dir, DIST_DIR, archive_name)
    try:
        print(f"-> Создаю ZIP-архив: {archive_name}.zip")
        shutil.make_archive(archive_path, 'zip', build_dir)
        archive_path_zip = archive_path + '.zip'
    except Exception as e:
        print(f"!!! ОШИБКА АРХИВАЦИИ: {e}")
        if os.path.exists(version_file_path): os.remove(version_file_path)
        return

    if not no_release:
        print("\n--- Создание релиза на GitHub ---")
        gh_command = [
            'gh', 'release', 'create', tag_name,
            archive_path_zip,
            '--title', f"Релиз от {version_string}",
            '--notes', release_notes
        ]
        if run_command(gh_command) is not None:
            print("-> Релиз успешно создан на GitHub!")
            cleanup_old_releases() # Запускаем очистку после успешного создания
        else:
            print("!!! Не удалось создать релиз. Проверьте, что вы вошли в `gh auth login`.")
    
    if os.path.exists(version_file_path):
        os.remove(version_file_path)
    if os.path.exists(archive_path_zip):
        os.remove(archive_path_zip)
    
    print(f"\n--- Готово! Скомпилированная программа находится в: {build_dir} ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Скрипт сборки и релиза проекта.")
    parser.add_argument(
        '--no-release', action='store_true',
        help='Только собрать проект локально, без создания релиза на GitHub.'
    )
    args = parser.parse_args()

    build_project(os.path.abspath('.'), args.no_release)