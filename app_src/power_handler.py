import os
import threading
import subprocess
import logging
import time
from uuid import UUID
import win32con
import win32api
import win32gui
import process_manager
import ctypes
from ctypes import wintypes
import psutil

# Определение GUID для системных событий питания
GUID_SYSTEM_AWAYMODE = (ctypes.c_byte * 16)(*UUID('98A7F580-01F7-48AA-9C0F-44352C29E5C0').bytes_le)

class PowerEventHandler:
    """Класс для обработки событий питания (ТОЛЬКО ЛОГИРОВАНИЕ, БЕЗ ДЕЙСТВИЙ)"""
    def __init__(self, app_instance):
        self.app = app_instance
        self.logger = logging.getLogger("power_events")
        if not self.logger.handlers:
            os.makedirs("roo_tests", exist_ok=True)
            handler = logging.FileHandler("roo_tests/power_events.log")
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
    def handle_power_event(self, hwnd, msg, wparam, lparam):
        """ТОЛЬКО ЛОГИРУЕТ СОБЫТИЯ, НИКАКИХ ДЕЙСТВИЙ"""
        try:
            if msg == win32con.WM_POWERBROADCAST:
                if wparam == win32con.PBT_APMSUSPEND:
                    self.logger.info("Событие: Вход в спящий режим")
                    self.app.log_message("[СИСТЕМА] Вход в спящий режим (только лог)")
                        
                elif wparam == win32con.PBT_APMRESUMEAUTOMATIC:
                    self.logger.info("Событие: Выход из спящего режима")
                    self.app.log_message("[СИСТЕМА] Выход из спящего режима (только лог)")
                    # НИКАКИХ ДЕЙСТВИЙ - только логирование
                    
        except Exception as e:
            self.logger.error(f"Ошибка в обработчике событий питания: {e}")
            
        return True

def setup_power_handler(app_instance):
    """Устанавливает обработчик событий питания (ТОЛЬКО ДЛЯ ЛОГИРОВАНИЯ)"""
    try:
        hwnd = app_instance.root.winfo_id()
        if not hwnd:
            raise Exception("Не удалось получить дескриптор окна")

        power_handler = PowerEventHandler(app_instance)

        WNDPROC = ctypes.WINFUNCTYPE(wintypes.LPARAM, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        
        old_proc_ptr = ctypes.windll.user32.SetWindowLongW(hwnd, win32con.GWL_WNDPROC, WNDPROC(power_handler.handle_power_event))
        
        if not old_proc_ptr:
            error_code = ctypes.get_last_error()
            if error_code != 0:
                raise Exception(f"SetWindowLongW не удалось. Код ошибки: {error_code}")
        
        ctypes.windll.user32.RegisterPowerSettingNotification(
            hwnd,
            ctypes.byref(GUID_SYSTEM_AWAYMODE),
            win32con.DEVICE_NOTIFY_WINDOW_HANDLE
        )
        
        app_instance.log_message("[СИСТЕМА] Обработчик событий питания установлен (только логирование)")
        return hwnd, power_handler
    except Exception as e:
        app_instance.log_message(f"[СИСТЕМА] Предупреждение: Не удалось установить обработчик питания: {e}")
        return None, None