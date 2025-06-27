import requests
import time

def check_zapret_version(log_callback):
    """Проверяет последнюю версию утилиты Zapret на GitHub и выводит в лог."""
    time.sleep(1) # Небольшая задержка, чтобы дать GUI прогрузиться
    log_callback("\n--- Проверка последней версии Zapret на GitHub ---")
    version_url = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/version.txt"
    release_url_base = "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/"
    try:
        response = requests.get(version_url, timeout=10, headers={"Cache-Control": "no-cache"})
        response.raise_for_status()
        github_version = response.text.strip()
        if github_version:
            log_callback(f"-> Последняя доступная версия: {github_version}")
            log_callback(f"-> Страница релиза: {release_url_base}{github_version}")
        else:
            log_callback("-> Не удалось определить последнюю версию (пустой ответ).")
    except requests.exceptions.RequestException:
        log_callback("!!! ОШИБКА: Не удалось проверить версию. Проверьте подключение к интернету.")
    except Exception as e:
        log_callback(f"!!! Непредвиденная ошибка при проверке версии: {e}")
    log_callback("--------------------------------------------------\n")