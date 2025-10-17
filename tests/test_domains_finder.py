import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter
)
from PySide6.QtCore import QThread, Signal, Qt
import concurrent.futures
import time
import chardet

# === НАСТРОЙКИ ===
TIMEOUT = 5  # секунд на ожидание ответа от домена
MAX_WORKERS = 10  # потоков для проверки доменов

# === СПИСОК ТЕГОВ И АТРИБУТОВ ДЛЯ ПАРСИНГА ===
TAGS_ATTRS = {
    'script': 'src',
    'link': 'href',
    'img': 'src',
    'iframe': 'src',
    'embed': 'src',
    'source': 'src',
    'track': 'src',
    'video': 'src',
    'audio': 'src',
}

# === КЛАСС ДЛЯ ПРОВЕРКИ ДОМЕНОВ В ОТДЕЛЬНОМ ПОТОКЕ ===
class DomainCheckerThread(QThread):
    progress_updated = Signal(int)
    domain_checked = Signal(str, bool, str)
    finished = Signal()
    log_message = Signal(str)

    def __init__(self, domains):
        super().__init__()
        self.domains = domains

    def run(self):
        total = len(self.domains)
        self.log_message.emit(f"Начинаю проверку {total} доменов...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.check_domain, domain): domain for domain in self.domains}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                domain = futures[future]
                try:
                    accessible, error = future.result()
                    self.domain_checked.emit(domain, accessible, error)
                    status = "доступен" if accessible else "недоступен"
                    self.log_message.emit(f"Проверен: {domain} - {status}")
                except Exception as e:
                    self.domain_checked.emit(domain, False, str(e))
                    self.log_message.emit(f"Ошибка при проверке {domain}: {str(e)}")
                self.progress_updated.emit(int((i + 1) / total * 100))
        self.log_message.emit("Проверка доменов завершена!")
        self.finished.emit()

    def check_domain(self, domain):
        """Проверяет доступность домена (по HTTPS и HTTP)."""
        protocols = ['https', 'http']
        for protocol in protocols:
            try:
                response = requests.head(
                    f"{protocol}://{domain}",
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                if response.status_code < 400:
                    return True, None
            except requests.exceptions.RequestException:
                continue
        return False, "Timeout or connection error"

# === ОСНОВНОЕ ОКНО ПРИЛОЖЕНИЯ ===
class DomainAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анализатор доменов сайта")
        self.setGeometry(100, 100, 1200, 800)
        
        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        # Центральный виджет и основной layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Поле ввода URL/файла
        input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Введите URL сайта или выберите HTML файл...")
        input_layout.addWidget(self.url_input)
        
        self.browse_button = QPushButton("Обзор...")
        input_layout.addWidget(self.browse_button)
        
        self.analyze_button = QPushButton("Анализировать")
        self.analyze_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        input_layout.addWidget(self.analyze_button)
        
        self.cache_button = QPushButton("Из кэша Google")
        self.cache_button.setStyleSheet("QPushButton { background-color: #2196F3; color: white; }")
        input_layout.addWidget(self.cache_button)

        self.wayback_button = QPushButton("Из Wayback Machine")
        self.wayback_button.setStyleSheet("QPushButton { background-color: #FF9800; color: white; }")
        input_layout.addWidget(self.wayback_button)
        
        main_layout.addLayout(input_layout)

        # Прогресс-бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Создаем сплиттер для разделения таблиц и логов
        splitter = QSplitter(Qt.Vertical)
        
        # Табы для результатов
        self.tabs = QTabWidget()
        
        # Таб со всеми доменами
        self.all_domains_table = QTableWidget()
        self.all_domains_table.setColumnCount(2)
        self.all_domains_table.setHorizontalHeaderLabels(["Домен", "Статус"])
        self.all_domains_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tabs.addTab(self.all_domains_table, "Все домены")

        # Таб с недоступными доменами
        self.inaccessible_table = QTableWidget()
        self.inaccessible_table.setColumnCount(3)
        self.inaccessible_table.setHorizontalHeaderLabels(["Домен", "Статус", "Ошибка"])
        self.inaccessible_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tabs.addTab(self.inaccessible_table, "Недоступные домены")

        # Таб с доступными доменами
        self.accessible_table = QTableWidget()
        self.accessible_table.setColumnCount(2)
        self.accessible_table.setHorizontalHeaderLabels(["Домен", "Статус"])
        self.accessible_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tabs.addTab(self.accessible_table, "Доступные домены")
        
        splitter.addWidget(self.tabs)

        # Поле для логов
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.addWidget(QLabel("Лог выполнения:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        splitter.addWidget(log_widget)

        # Устанавливаем пропорции сплиттера
        splitter.setSizes([600, 200])
        main_layout.addWidget(splitter)

    def setup_connections(self):
        self.browse_button.clicked.connect(self.browse_file)
        self.analyze_button.clicked.connect(self.start_analysis)
        self.cache_button.clicked.connect(self.load_from_cache)
        self.wayback_button.clicked.connect(self.load_from_wayback)

    def log(self, message):
        """Выводит сообщение в лог и в консоль"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.append(formatted_message)
        print(formatted_message)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите HTML файл", "", "HTML files (*.html *.htm);;All files (*.*)"
        )
        if file_path:
            self.url_input.setText(file_path)
            self.log(f"Выбран файл: {file_path}")

    def start_analysis(self):
        source = self.url_input.text().strip()
        if not source:
            self.log("Ошибка: Введите URL или выберите HTML файл!")
            return

        # Очищаем таблицы и лог
        self.all_domains_table.setRowCount(0)
        self.inaccessible_table.setRowCount(0)
        self.accessible_table.setRowCount(0)
        self.log_text.clear()

        # Показываем прогресс-бар
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_button.setEnabled(False)

        # Запускаем анализ в отдельном потоке
        self.analysis_thread = AnalysisThread(source)
        self.analysis_thread.domains_found.connect(self.on_domains_found)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.log_message.connect(self.log)
        self.analysis_thread.start()

    def load_from_cache(self):
        url = self.url_input.text().strip()
        if not url.startswith(('http://', 'https://')):
            self.log("Ошибка: Для загрузки из кэша нужен URL, а не файл!")
            return
        
        # Очищаем таблицы и лог
        self.all_domains_table.setRowCount(0)
        self.inaccessible_table.setRowCount(0)
        self.accessible_table.setRowCount(0)
        self.log_text.clear()
        
        # Показываем прогресс-бар
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_button.setEnabled(False)
        
        html = self.get_from_google_cache(url)
        if html:
            self.process_html(html, url)
        else:
            self.progress_bar.setVisible(False)
            self.analyze_button.setEnabled(True)

    def load_from_wayback(self):
        url = self.url_input.text().strip()
        if not url.startswith(('http://', 'https://')):
            self.log("Ошибка: Для загрузки из Wayback нужен URL, а не файл!")
            return
        
        # Очищаем таблицы и лог
        self.all_domains_table.setRowCount(0)
        self.inaccessible_table.setRowCount(0)
        self.accessible_table.setRowCount(0)
        self.log_text.clear()
        
        # Показываем прогресс-бар
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_button.setEnabled(False)
        
        html = self.get_from_wayback(url)
        if html:
            self.process_html(html, url)
        else:
            self.progress_bar.setVisible(False)
            self.analyze_button.setEnabled(True)

    def get_from_google_cache(self, url):
        """Получает страницу из кэша Google"""
        try:
            cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{url}"
            self.log(f"Пытаюсь загрузить из кэша Google: {cache_url}")
            response = requests.get(cache_url, timeout=TIMEOUT)
            if response.status_code == 200 and "cache" in response.text.lower():
                return response.text
            else:
                self.log("Не удалось получить страницу из кэша Google")
                return None
        except Exception as e:
            self.log(f"Ошибка при загрузке из кэша Google: {str(e)}")
            return None

    def get_from_wayback(self, url):
        """Получает последнюю сохраненную версию из Wayback Machine"""
        try:
            api_url = f"http://archive.org/wayback/available?url={url}"
            self.log(f"Проверяю наличие копии в Wayback Machine...")
            response = requests.get(api_url, timeout=TIMEOUT)
            data = response.json()
            if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
                archive_url = data['archived_snapshots']['closest']['url']
                self.log(f"Найдена копия в Wayback Machine: {archive_url}")
                response = requests.get(archive_url, timeout=TIMEOUT)
                return response.text
            else:
                self.log("Не найдено сохраненных копий в Wayback Machine")
                return None
        except Exception as e:
            self.log(f"Ошибка при загрузке из Wayback Machine: {str(e)}")
            return None

    def process_html(self, html, source_url):
        """Обрабатывает HTML и запускает анализ доменов"""
        # Получаем домен из URL
        parsed_url = urlparse(source_url)
        base_domain = parsed_url.netloc
        
        # Извлекаем домены
        domains = self.get_domains_from_html(html, base_domain)
        
        # Запускаем проверку
        self.on_domains_found(domains)

    def on_domains_found(self, domains):
        self.log(f"Найдено доменов: {len(domains)}")
        for domain in domains:
            self.log(f"  - {domain}")
        
        # Создаем и запускаем поток для проверки доменов
        self.checker_thread = DomainCheckerThread(domains)
        self.checker_thread.progress_updated.connect(self.progress_bar.setValue)
        self.checker_thread.domain_checked.connect(self.on_domain_checked)
        self.checker_thread.finished.connect(self.on_checking_finished)
        self.checker_thread.log_message.connect(self.log)
        self.checker_thread.start()

    def on_domain_checked(self, domain, accessible, error):
        # Добавляем в таблицу всех доменов
        row = self.all_domains_table.rowCount()
        self.all_domains_table.insertRow(row)
        self.all_domains_table.setItem(row, 0, QTableWidgetItem(domain))
        self.all_domains_table.setItem(row, 1, QTableWidgetItem("Доступен" if accessible else "Недоступен"))

        # Добавляем в соответствующую таблицу
        if accessible:
            row = self.accessible_table.rowCount()
            self.accessible_table.insertRow(row)
            self.accessible_table.setItem(row, 0, QTableWidgetItem(domain))
            self.accessible_table.setItem(row, 1, QTableWidgetItem("Доступен"))
        else:
            row = self.inaccessible_table.rowCount()
            self.inaccessible_table.insertRow(row)
            self.inaccessible_table.setItem(row, 0, QTableWidgetItem(domain))
            self.inaccessible_table.setItem(row, 1, QTableWidgetItem("Недоступен"))
            self.inaccessible_table.setItem(row, 2, QTableWidgetItem(error))

    def on_checking_finished(self):
        self.progress_bar.setVisible(False)
        self.analyze_button.setEnabled(True)
        self.log("Анализ доменов завершен!")
        
        # Выводим статистику
        total = self.all_domains_table.rowCount()
        accessible = self.accessible_table.rowCount()
        inaccessible = self.inaccessible_table.rowCount()
        self.log(f"Статистика: Всего {total}, Доступно {accessible}, Недоступно {inaccessible}")

    def on_analysis_finished(self):
        pass

    def on_analysis_error(self, error):
        self.log(f"Ошибка при анализе: {error}")
        self.progress_bar.setVisible(False)
        self.analyze_button.setEnabled(True)

    def get_domains_from_html(self, html, base_domain=None):
        """Извлекает все уникальные домены из HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        domains = set()
        
        for tag, attr in TAGS_ATTRS.items():
            for element in soup.find_all(tag):
                url = element.get(attr)
                if url:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    if domain:
                        domains.add(domain)
        
        if base_domain:
            domains.add(base_domain)
        
        return sorted(domains)

# === ПОТОК ДЛЯ АНАЛИЗА HTML ===
class AnalysisThread(QThread):
    domains_found = Signal(list)
    finished = Signal()
    error = Signal(str)
    log_message = Signal(str)

    def __init__(self, source):
        super().__init__()
        self.source = source

    def run(self):
        try:
            html = ""
            base_domain = None

            if self.source.startswith(('http://', 'https://')):
                self.log_message.emit(f"Загружаю страницу: {self.source}")
                response = requests.get(self.source, timeout=TIMEOUT)
                response.raise_for_status()
                html = response.text
                parsed_url = urlparse(self.source)
                base_domain = parsed_url.netloc
                self.log_message.emit(f"Основной домен: {base_domain}")
            else:
                self.log_message.emit(f"Читаю HTML из файла: {self.source}")
                html = self.read_file_with_encoding(self.source)

            domains = self.get_domains_from_html(html, base_domain)
            self.domains_found.emit(domains)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def read_file_with_encoding(self, file_path):
        """Читает файл с автоматическим определением кодировки"""
        # Сначала пробуем определить кодировку
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                self.log_message.emit(f"Обнаружена кодировка: {encoding}")
                return raw_data.decode(encoding)
        except Exception as e:
            self.log_message.emit(f"Ошибка при определении кодировки: {str(e)}")
        
        # Если не удалось, пробуем распространенные кодировки
        encodings = ['utf-8', 'windows-1251', 'iso-8859-1', 'cp1251']
        for enc in encodings:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    self.log_message.emit(f"Использую кодировку: {enc}")
                    return f.read()
            except UnicodeDecodeError:
                continue
        
        raise Exception("Не удалось прочитать файл: не поддерживаемая кодировка")

    def get_domains_from_html(self, html, base_domain=None):
        """Извлекает все уникальные домены из HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        domains = set()
        
        for tag, attr in TAGS_ATTRS.items():
            for element in soup.find_all(tag):
                url = element.get(attr)
                if url:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    if domain:
                        domains.add(domain)
        
        if base_domain:
            domains.add(base_domain)
        
        return sorted(domains)

# === ЗАПУСК ПРИЛОЖЕНИЯ ===
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DomainAnalyzerApp()
    window.show()
    sys.exit(app.exec())