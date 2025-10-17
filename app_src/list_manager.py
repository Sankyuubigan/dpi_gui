import os
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class ListManager:
    """Класс для управления списками доменов и их выбора в интерфейсе."""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.lists_dir = os.path.join(app_dir, 'lists')
        self.available_lists = self._discover_available_lists()
        self.selected_lists = {}
        self.custom_list_path = None
        
        # Инициализируем выбор всех списков по умолчанию
        for list_name in self.available_lists:
            self.selected_lists[list_name] = True
    
    def _discover_available_lists(self):
        """Обнаруживает все доступные списки доменов в папке lists."""
        lists = {}
        if not os.path.exists(self.lists_dir):
            return lists
            
        # Исключаем служебные файлы
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
        
        self.checkbox_vars = {}  # Храним переменные BooleanVar
        self.checkbox_widgets = {} # Храним сами виджеты Checkbutton
        
        sorted_list_names = sorted(self.available_lists.keys())

        for list_name in sorted_list_names:
            var = tk.BooleanVar(value=self.selected_lists.get(list_name, True))
            self.checkbox_vars[list_name] = var
            
            cb = ttk.Checkbutton(
                frame, 
                text=list_name, 
                variable=var,
                command=lambda ln=list_name: self._on_list_toggle(ln)
            )
            cb.pack(anchor=tk.W, padx=5, pady=2)
            self.checkbox_widgets[list_name] = cb
            
        return frame
    
    def _on_list_toggle(self, list_name):
        """Обработчик изменения состояния чекбокса."""
        self.selected_lists[list_name] = self.checkbox_vars[list_name].get()

    def set_selection_state(self, selection_data):
        """Загружает состояние чекбоксов из сохраненных настроек."""
        if not isinstance(selection_data, dict):
            return
            
        for list_name, var in self.checkbox_vars.items():
            # Устанавливаем значение из конфига, если оно там есть, иначе оставляем по умолчанию (True)
            saved_state = selection_data.get(list_name, True)
            var.set(saved_state)
            self.selected_lists[list_name] = saved_state

    def set_required_lists(self, required_list_names):
        """Устанавливает списки, которые обязательны для текущего профиля."""
        for list_name in self.available_lists.keys():
            is_required = list_name in required_list_names
            if is_required:
                self.selected_lists[list_name] = True
                if list_name in self.checkbox_vars:
                    self.checkbox_vars[list_name].set(True)
                if list_name in self.checkbox_widgets:
                    self.checkbox_widgets[list_name].config(state=tk.DISABLED)
            else:
                if list_name in self.checkbox_widgets:
                    self.checkbox_widgets[list_name].config(state=tk.NORMAL)

    def get_combined_list_path(self, custom_list_path=None, log_callback=None):
        """
        Создает и возвращает путь к временному файлу в системной папке Temp,
        объединяя выбранные списки из UI и опционально custom_list.txt.
        """
        if log_callback:
            log_callback("--- [ListManager] Начинаю формирование объединенного списка ---")
        
        temp_dir = tempfile.gettempdir()
        combined_path = os.path.join(temp_dir, 'dpi_gui_combined_list.txt')
        
        has_content = False
        with open(combined_path, 'w', encoding='utf-8') as combined_file:
            # 1. Добавляем выбранные списки
            if log_callback:
                log_callback("  [ListManager] Проверяю выбранные списки из UI...")
            for list_name, is_selected in self.selected_lists.items():
                if is_selected:
                    filename = self.available_lists.get(list_name)
                    if filename:
                        list_path = os.path.join(self.lists_dir, filename)
                        if os.path.exists(list_path):
                            if log_callback:
                                log_callback(f"    + Найден выбранный список: {list_name} ({filename})")
                            with open(list_path, 'r', encoding='utf-8') as list_file:
                                content = list_file.read()
                                if content.strip():
                                    combined_file.write(f"# Содержимое из {filename}\n")
                                    combined_file.write(content)
                                    combined_file.write("\n\n")
                                    has_content = True
                        else:
                            if log_callback:
                                log_callback(f"    ! ВНИМАНИЕ: Файл для списка '{list_name}' не найден по пути: {list_path}")
                else:
                    if log_callback:
                        log_callback(f"    - Список '{list_name}' не выбран, пропускаю.")
            
            # 2. Добавляем кастомный список, если он предоставлен и валиден
            if log_callback:
                log_callback(f"  [ListManager] Проверяю кастомный список. Путь: {custom_list_path}")
            if custom_list_path and os.path.exists(custom_list_path) and os.path.getsize(custom_list_path) > 0:
                if log_callback:
                    log_callback(f"    + Кастомный список найден и не пуст. Добавляю его содержимое.")
                with open(custom_list_path, 'r', encoding='utf-8') as custom_file:
                    content = custom_file.read()
                    if content.strip():
                        combined_file.write(f"# Содержимое из {os.path.basename(custom_list_path)}\n")
                        combined_file.write(content)
                        combined_file.write("\n")
                        has_content = True
            elif custom_list_path:
                if log_callback:
                    if not os.path.exists(custom_list_path):
                        log_callback(f"    ! ОШИБКА: Файл кастомного списка не существует: {custom_list_path}")
                    elif os.path.getsize(custom_list_path) == 0:
                        log_callback(f"    ! ОШИБКА: Файл кастомного списка пуст: {custom_list_path}")
            else:
                if log_callback:
                    log_callback("    - Кастомный список не используется.")

        if has_content:
            if log_callback:
                log_callback(f"--- [ListManager] Объединенный список успешно создан: {combined_path} ---")
            return combined_path
        else:
            if log_callback:
                log_callback("--- [ListManager] ВНИМАНИЕ: Нет ни одного выбранного списка или кастомный список пуст. Объединенный файл не будет создан. ---")
            # Удаляем пустой файл, если он был создан
            if os.path.exists(combined_path):
                os.remove(combined_path)
            return None

    def set_custom_list_path(self, path):
        """Устанавливает путь к кастомному списку."""
        self.custom_list_path = path

    def get_custom_list_path(self):
        """Возвращает путь к кастомному списку."""
        return self.custom_list_path