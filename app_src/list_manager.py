import os
import tkinter as tk

class ListManager:
    """Класс для управления списками доменов."""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.lists_dir = os.path.join(app_dir, 'lists')
        
        # Словарь: { "имя_файла_списка": "имя_профиля" }
        self.list_profile_map = {}
        
    def get_available_files(self):
        """Возвращает список имен файлов в папке lists."""
        if not os.path.exists(self.lists_dir):
            return []
            
        files = []
        # Сначала ищем стандартные txt
        for filename in os.listdir(self.lists_dir):
            if filename.endswith('.txt') and filename != 'ipset-all.txt':
                files.append(filename)
        
        # Сортируем для красоты
        files.sort()
        return files

    def get_mapping(self):
        """Возвращает текущую карту настроек."""
        return self.list_profile_map

    def set_mapping(self, new_map):
        """Загружает карту настроек (из конфига)."""
        if isinstance(new_map, dict):
            self.list_profile_map = new_map

    def set_profile_for_list(self, list_name, profile_name):
        """Устанавливает профиль для конкретного списка."""
        self.list_profile_map[list_name] = profile_name

    def get_profile_for_list(self, list_name):
        return self.list_profile_map.get(list_name, "ОТКЛЮЧЕНО")

    def get_custom_list_path(self):
        return os.path.join(self.lists_dir, 'custom_list.txt')
    
    # Методы ниже оставлены для совместимости, если где-то еще вызываются, но могут быть пустыми
    def set_custom_list_path(self, path): pass
    def set_required_lists(self, req): pass