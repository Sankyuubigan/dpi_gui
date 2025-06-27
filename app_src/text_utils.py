import tkinter as tk

# Константы для обработки событий
CONTROL_MASK = 0x0004

def handle_keypress(event):
    """Обрабатывает нажатия клавиш для копирования и выделения."""
    widget = event.widget
    
    # Ctrl+C (Copy) - \x03
    if event.char == '\x03' and (event.state & CONTROL_MASK):
        try:
            if isinstance(widget, (tk.Entry, tk.Text, tk.scrolledtext.ScrolledText)):
                selected_text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            elif isinstance(widget, tk.Listbox):
                selected_indices = widget.curselection()
                if not selected_indices: return 'break'
                selected_text = "\n".join(widget.get(i) for i in selected_indices)
            else:
                return
            
            widget.clipboard_clear()
            widget.clipboard_append(selected_text)
        except tk.TclError:
            # Ничего не выделено
            pass
        return 'break' # Предотвращаем стандартную обработку

    # Ctrl+A (Select All) - \x01
    if event.char == '\x01' and (event.state & CONTROL_MASK):
        try:
            if isinstance(widget, (tk.Entry, tk.Text, tk.scrolledtext.ScrolledText)):
                # Для текстовых виджетов нужно временно включить, чтобы выделить все
                original_state = widget.cget('state')
                widget.config(state=tk.NORMAL)
                widget.tag_add(tk.SEL, '1.0', tk.END)
                widget.config(state=original_state)
            elif isinstance(widget, tk.Listbox):
                widget.selection_set(0, tk.END)
        except Exception:
            pass # Игнорируем ошибки, если что-то пошло не так
        return 'break'

def setup_text_widget_bindings(widget):
    """Применяет обработчики событий к виджету."""
    widget.bind("<KeyPress>", handle_keypress)
