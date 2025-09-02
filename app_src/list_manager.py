import os
import tkinter as tk
from tkinter import ttk

class ListManager:
    """Класс для управления списками доменов и их выбора в интерфейсе."""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.lists_dir = os.path.join(app_dir, 'lists')
        self.available_lists = self._discover_available_lists()
        self.selected_lists = {}
        
        # Инициализируем выбор всех списков по умолчанию
        for list_name in self.available_lists:
            self.selected_lists[list_name] = True
    
    def _discover_available_lists(self):
        """Обнаруживает все доступные списки доменов в папке lists."""
        lists = {}
        if not os.path.exists(self.lists_dir):
            return lists
            
        # Исключаем служебные файлы и файлы, которые не должны быть доступны для выбора
        exclude_files = {'custom_list.txt', 'ipset-all.txt'}
        
        for filename in os.listdir(self.lists_dir):
            if filename.endswith('.txt') and filename not in exclude_files:
                list_name = filename.replace('.txt', '')
                lists[list_name] = filename
                
        return lists
    
    def create_list_selection_ui(self, parent):
        """Создает интерфейс для выбора списков доменов с чекбоксами."""
        frame = ttk.LabelFrame(parent, text="Выбор списков доменов")
        frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.checkboxes = {}
        
        for list_name, filename in self.available_lists.items():
            var = tk.BooleanVar(value=self.selected_lists.get(list_name, True))
            self.checkboxes[list_name] = var
            
            cb = ttk.Checkbutton(
                frame, 
                text=list_name, 
                variable=var,
                command=lambda ln=list_name: self._on_list_toggle(ln)
            )
            cb.pack(anchor=tk.W, padx=5, pady=2)
            
        return frame
    
    def _on_list_toggle(self, list_name):
        """Обработчик изменения состояния чекбокса."""
        self.selected_lists[list_name] = self.checkboxes[list_name].get()
    
    def get_selected_lists_paths(self):
        """Возвращает пути к выбранным спискам доменов."""
        selected_paths = []
        for list_name, is_selected in self.selected_lists.items():
            if is_selected:
                filename = self.available_lists.get(list_name)
                if filename:
                    selected_paths.append(os.path.join(self.lists_dir, filename))
        return selected_paths
    
    def get_combined_list_path(self):
        """Возвращает путь к временному файлу с объединенными выбранными списками."""
        combined_path = os.path.join(self.lists_dir, 'combined_selected_lists.txt')
        
        with open(combined_path, 'w', encoding='utf-8') as combined_file:
            for list_name, is_selected in self.selected_lists.items():
                if is_selected:
                    filename = self.available_lists.get(list_name)
                    if filename:
                        list_path = os.path.join(self.lists_dir, filename)
                        if os.path.exists(list_path):
                            with open(list_path, 'r', encoding='utf-8') as list_file:
                                combined_file.write(f"# Содержимое из {filename}\n")
                                combined_file.write(list_file.read())
                                combined_file.write("\n")
        
        return combined_path