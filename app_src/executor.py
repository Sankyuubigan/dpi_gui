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
                if line.strip() and not line.strip().startswith('#'):
                    return True
    except Exception:
        return False
    return False