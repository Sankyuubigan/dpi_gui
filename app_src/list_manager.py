import os
import tkinter as tk

class ListManager:
    """Класс для управления списками доменов."""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.lists_dir = os.path.join(app_dir, 'lists')
        
        # Словарь: { "имя_файла_списка": "имя_профиля" }
        self.list_profile_map = {}
        # Словарь: { "имя_файла_списка": "имя_файла_ipset" или "OFF" }
        self.list_ipset_map = {}
        
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

    def get_available_ipsets(self):
        """Возвращает список доступных файлов ipset."""
        ipsets_dir = os.path.join(self.app_dir, 'ipsets')
        files = ["OFF"]
        if os.path.exists(ipsets_dir):
            for filename in os.listdir(ipsets_dir):
                if filename.endswith('.txt'):
                    files.append(filename)
        return files

    def get_mapping(self):
        """Возвращает текущую карту профилей."""
        return self.list_profile_map
    
    def get_ipset_mapping(self):
        """Возвращает текущую карту айписетов."""
        return self.list_ipset_map

    def set_mappings(self, profile_map, ipset_map):
        """Загружает карты настроек (из конфига)."""
        if isinstance(profile_map, dict):
            self.list_profile_map = profile_map
        if isinstance(ipset_map, dict):
            self.list_ipset_map = ipset_map

    def set_profile_for_list(self, list_name, profile_name):
        """Устанавливает профиль для конкретного списка."""
        self.list_profile_map[list_name] = profile_name

    def set_ipset_for_list(self, list_name, ipset_name):
        """Устанавливает ipset для конкретного списка."""
        self.list_ipset_map[list_name] = ipset_name

    def get_profile_for_list(self, list_name):
        return self.list_profile_map.get(list_name, "ОТКЛЮЧЕНО")
    
    def get_ipset_for_list(self, list_name):
        return self.list_ipset_map.get(list_name, "OFF")

    def get_custom_list_path(self):
        return os.path.join(self.lists_dir, 'custom_list.txt')
    
    # Методы ниже оставлены для совместимости
    def set_custom_list_path(self, path): pass
    def set_required_lists(self, req): pass