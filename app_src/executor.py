import os
import subprocess
import requests
import zipfile
import shutil
import glob

def is_custom_list_valid(filepath):
    """Проверяет, существует ли custom_list и не пуст ли он."""
    if not os.path.exists(filepath):
        return False
    if os.path.getsize(filepath) == 0:
        return False
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Убираем пробелы и проверяем, что строка не пустая и не комментарий
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    return True
    except Exception:
        return False
    return False