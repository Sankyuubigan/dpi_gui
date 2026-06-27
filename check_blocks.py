import asyncio
from urllib.parse import urlparse
try:
    from playwright.async_api import async_playwright
except ImportError:
    pass

async def _check_site_domains_async(url: str, log_callback):
    if not url.startswith('http'):
        url = 'https://' + url
        
    domains_all = set()
    domains_success = set()
    domains_failed = {}

    def get_hostname(req_url):
        try:
            return urlparse(req_url).hostname or "unknown"
        except:
            return "unknown"

    def on_request(request):
        domains_all.add(get_hostname(request.url))

    def on_request_finished(request):
        domains_success.add(get_hostname(request.url))

    def on_request_failed(request):
        domain = get_hostname(request.url)
        error_msg = request.failure
        error_text = error_msg.error_text if hasattr(error_msg, "error_text") else str(error_msg)
        if domain not in domains_failed:
            domains_failed[domain] = set()
        domains_failed[domain].add(error_text)

    log_callback(f"Запуск браузера для глубокой проверки: {url}", "status")
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
                ignore_https_errors=True 
            )
            page = await context.new_page()
            page.on("request", on_request)
            page.on("requestfinished", on_request_finished)
            page.on("requestfailed", on_request_failed)

            log_callback("Ожидаем загрузки элементов сайта (до 20 сек)...", "status")
            
            try:
                await page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception as e:
                # Если ошибка DNS и мы еще не пробовали www.
                if "ERR_NAME_NOT_RESOLVED" in str(e) and "://www." not in url:
                    log_callback(f"[!] Ошибка DNS (ERR_NAME_NOT_RESOLVED). Пробуем добавить www...", "status")
                    url = url.replace("https://", "https://www.").replace("http://", "http://www.")
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=20000)
                    except Exception as e2:
                        log_callback(f"[!] Ошибка загрузки страницы после добавления www: {e2}", "error")
                elif "Timeout" in str(e):
                    log_callback("[!] Таймаут. Анализируем то, что успело собраться...", "error")
                else:
                    log_callback(f"[!] Ошибка загрузки страницы: {e}", "error")

            await page.wait_for_timeout(2000)
            await browser.close()
    except Exception as e:
        log_callback(f"Ошибка Playwright: {e}", "error")
        log_callback("Подсказка: Откройте консоль (cmd) и введите команду: playwright install", "status")
        return

    accessible = []
    blocked = []
    partial = []

    for domain in domains_all:
        has_success = domain in domains_success
        has_failure = domain in domains_failed

        if has_success and not has_failure:
            accessible.append(domain)
        elif has_success and has_failure:
            partial.append(domain)
        elif has_failure and not has_success:
            blocked.append(domain)

    log_callback("="*60, "main")
    log_callback(f"РЕЗУЛЬТАТЫ ГЛУБОКОГО АНАЛИЗА: {url}", "status")
    
    if partial:
        log_callback("⚠️ ЧАСТИЧНО ДОСТУПНЫЕ (часть скриптов сайта отвалилась):", "error")
        for d in sorted(partial):
            errs = " | ".join(domains_failed[d])
            log_callback(f"  - {d} (Ошибки: {errs})", "error")

    log_callback("❌ НЕДОСТУПНЫЕ ДОМЕНЫ (сломались из-за блокировки РФ ИЛИ из-за включенного обхода):", "error")
    if not blocked:
        log_callback("  - Все загрузилось без фатальных ошибок", "success")
    for d in sorted(blocked):
        errs = " | ".join(domains_failed[d])
        log_callback(f"  - {d}", "error")
        log_callback(f"      * Причина: {errs}", "error")
        
    log_callback("="*60, "main")
    log_callback("СОВЕТ: Если при ВКЛЮЧЕННОМ обходе домен из списка ❌ выдает ERR_CONNECTION_CLOSED или RESET, значит обход его ломает.", "status")
    log_callback("Добавьте его в исключения: 'Настройки' -> 'Указать кастомный список' -> 'Открыть/Редактировать'.", "status")

def run_deep_analysis_sync(url, log_callback):
    # Запускает асинхронный цикл в синхронной обертке для работы в потоке
    asyncio.run(_check_site_domains_async(url, log_callback))