import time
import json
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException

def find_domains(url: str):
    """
    Запускает браузер Chrome, переходит на указанный URL,
    собирает все домены, к которым были сетевые запросы, и возвращает их список.
    """
    print("Запускаю браузер для анализа...")
    
    # Настройки для Chrome, чтобы включить логирование сети
    chrome_options = Options()
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    # Запуск в "безголовом" режиме, чтобы не открывалось видимое окно браузера
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=3") # Подавляем лишние сообщения в консоли

    driver = None
    try:
        # Selenium 4+ сам управляет драйверами, это упрощает запуск
        driver = webdriver.Chrome(options=chrome_options)
        
        print(f"Перехожу на {url}...")
        driver.get(url)
        
        # Даем странице время на полную прогрузку динамических элементов
        print("Жду 7 секунд для прогрузки всех ресурсов...")
        time.sleep(7)
        
        print("Собираю сетевые логи...")
        logs = driver.get_log('performance')
        
        domains = set()
        
        for entry in logs:
            log = json.loads(entry['message'])['message']
            if log['method'] == 'Network.requestWillBeSent':
                request_url = log['params']['request']['url']
                domain = urlparse(request_url).netloc
                if domain:
                    domains.add(domain)
                    
        return sorted(list(domains))

    except WebDriverException as e:
        print("\n" + "="*50)
        print("!!! ОШИБКА SELENIUM !!!")
        print("Не удалось запустить Chrome. Возможные причины:")
        print("1. Убедитесь, что Google Chrome установлен на вашем компьютере.")
        print("2. Ваша версия Chrome может быть несовместима с драйвером.")
        print(f"Текст ошибки: {e}")
        print("="*50)
        return None
    finally:
        if driver:
            driver.quit()
            print("Анализ завершен, браузер закрыт.")


if __name__ == "__main__":
    print("--- Анализатор доменов для сайтов ---")
    target_url = input("Введите полный URL сайта для анализа (например, https://glama.ai): ")
    
    if not target_url.lower().startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        print(f"URL исправлен на: {target_url}")

    found_domains = find_domains(target_url)
    
    if found_domains:
        print("\n" + "="*50)
        print("Найдены следующие домены (готовы для копирования в custom_list.txt):")
        print("="*50)
        for domain in found_domains:
            print(domain)
        print("="*50)
