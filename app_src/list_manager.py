import os
import tkinter as tk

class ListManager:
    """Класс для управления списками доменов и IP-сетами."""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.lists_dir = os.path.join(app_dir, 'lists')
        self.ipsets_dir = os.path.join(app_dir, 'ipsets')
        self.custom_list_path = ""
        
        # Новая структура хранения правил: список словарей
        # [ { "file": "list-general.txt", "type": "list", "profile": "General" }, ... ]
        self.rules = []

    def get_all_resources(self):
        """
        Возвращает единый список всех доступных файлов (списки и ipset).
        Формат возврата: [ ("отображаемое_имя", "реальный_путь", "тип") ]
        Типы: 'list', 'ipset'
        """
        resources = []
        
        # 1. Списки доменов (lists/)
        if os.path.exists(self.lists_dir):
            for f in os.listdir(self.lists_dir):
                if f.endswith('.txt') and f != 'ipset-all.txt': # ipset-all служебный
                    resources.append({
                        "display": f"[DOMAINS] {f}",
                        "filename": f,
                        "type": "list",
                        "path": os.path.join(self.lists_dir, f)
                    })
        
        # 2. IP-сеты (ipsets/)
        if os.path.exists(self.ipsets_dir):
            for f in os.listdir(self.ipsets_dir):
                if f.endswith('.txt'):
                    resources.append({
                        "display": f"[IPSET] {f}",
                        "filename": f,
                        "type": "ipset",
                        "path": os.path.join(self.ipsets_dir, f)
                    })
        
        # 3. Кастомный список
        if self.custom_list_path and os.path.exists(self.custom_list_path):
            resources.append({
                "display": f"[CUSTOM] {os.path.basename(self.custom_list_path)}",
                "filename": self.custom_list_path, # Используем полный путь как ID
                "type": "list",
                "path": self.custom_list_path
            })
            
        # Сортировка по имени
        resources.sort(key=lambda x: x["display"])
        return resources

    def set_rules(self, rules_data):
        """Загружает правила из конфига."""
        self.rules = rules_data

    def get_rules(self):
        """Возвращает текущие правила."""
        return self.rules
    
    def add_rule(self, file_identifier, file_type, profile_name):
        """Добавляет новое правило."""
        self.rules.append({
            "file": file_identifier,
            "type": file_type,
            "profile": profile_name
        })

    def remove_rule(self, index):
        """Удаляет правило по индексу."""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)

    def update_rule(self, index, key, value):
        """Обновляет поле правила."""
        if 0 <= index < len(self.rules):
            self.rules[index][key] = value

    # Методы для кастомного списка
    def set_custom_list_path(self, path):
        self.custom_list_path = path

    def get_custom_list_path(self):
        return self.custom_list_path

    # Старые методы оставлены для совместимости, если где-то вызываются, но лучше не использовать
    def get_mapping(self): return {}
    def get_ipset_mapping(self): return {}
    def set_mappings(self, p, i): pass