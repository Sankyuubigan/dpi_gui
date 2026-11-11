use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use std::thread;
use url::Url;
use headless_chrome::{Browser, LaunchOptions};
use headless_chrome::protocol::cdp::types::Event;
use headless_chrome::protocol::cdp::Network;
use sysinfo::System;
use tauri::AppHandle;
use crate::process;
use crate::analyzer_probe::{self, Probe};
use crate::analyzer_report::{self, ReportMeta};
use crate::bypass_lists;
use crate::bypass_toggle;
use crate::cancel;
use crate::ip_probe;
use crate::analyzer_ip_report;
use crate::ip_target;
use crate::probe_budget::StageBudget;
use crate::site_probe;
use crate::site_solution;

// Скрывает КОНСОЛЬНЫЕ окна, которые порождает headless Chrome на Windows.
// headless_chrome ставит CREATE_NO_WINDOW главному процессу, но Chrome сам внутри
// спавнит дочерние процессы (renderer/GPU/crashpad) без этого флага, и у них
// появляется чёрное консольное окно. Перебираем окна напрямую через Win32 API
// (быстро, без тяжёлого опроса процессов) и прячем именно консольные окна Chrome,
// не трогая реальный браузер пользователя (у него окна класса Chrome_WidgetWin_*).
#[cfg(windows)]
mod win_hide {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use windows_sys::Win32::Foundation::{BOOL, FALSE, HWND, TRUE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, QueryFullProcessImageNameW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, ShowWindow, SW_HIDE,
    };

    pub struct Ctx {
        pub known: Arc<Mutex<HashSet<u32>>>,
    }

    unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: isize) -> BOOL {
        let ctx = &*(lparam as *const Ctx);

        // Не трогаем окна уже запущенного браузера пользователя (его вкладки).
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if ctx.known.lock().unwrap().contains(&pid) {
            return TRUE;
        }

        // Проверяем, что окно принадлежит chrome.exe. Используем только
        // PROCESS_QUERY_INFORMATION — PROCESS_VM_READ может не пройти для
        // дочерних процессов Chrome (crashpad-handler и т.е.), и тогда окно
        // останется видимым.
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        let mut is_chrome = false;
        if handle != 0 {
            let mut buf = [0u16; 1024];
            let mut size: u32 = buf.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) != 0 {
                let path = String::from_utf16_lossy(&buf[..size as usize]);
                let name = path.rsplit(['\\', '/']).next().unwrap_or("");
                is_chrome = name.eq_ignore_ascii_case("chrome.exe");
            }
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        if is_chrome {
            // Прячем ЛЮБОЕ окно дочернего процесса Chrome (в т.С‡. чёрную
            // консоль), чтобы юзер не видел ни мгновенного мелькания.
            ShowWindow(hwnd, SW_HIDE);
        }

        TRUE
    }

    // Один быстрый проход: прячет все консольные окна Chrome, кроме известных PID юзера.
    pub fn hide_chrome_consoles(known: &Arc<Mutex<HashSet<u32>>>) {
        let ctx = Ctx { known: known.clone() };
        unsafe {
            EnumWindows(Some(enum_cb), &ctx as *const Ctx as isize);
        }
    }
}

fn chrome_pids() -> Vec<u32> {
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    sys.processes()
        .values()
        .filter(|p| p.name().to_string_lossy().eq_ignore_ascii_case("chrome.exe"))
        .map(|p| p.pid().as_u32())
        .collect()
}

// Парсинг значения из отладочной строки события CDP.
// Ищем ` key: "..."` (С ВЕДУЩИМ ПРОБЕЛОМ), чтобы не перепутать document_url с реальным request.url.
// Без ведущего пробела подстрока "url: " совпадает с "document_url: " — и тогда все
// под-ресурсы (CDN/API/скрипты) записывались бы как главный домен страницы.
fn extract_value(s: &str, key: &str) -> Option<String> {
    let search = format!(" {}: ", key);
    let idx = s.find(&search)?;
    let rest = &s[idx + search.len()..];
    let mut in_quotes = false;
    let mut val = String::new();
    for c in rest.chars() {
        if c == '"' {
            if in_quotes {
                return Some(val);
            } else {
                in_quotes = true;
            }
        } else if in_quotes {
            val.push(c);
        } else if c == ',' || c == ' ' || c == '}' || c == ')' {
            if !val.is_empty() { break; }
        }
    }
    None
}

/// Итог анализа: текстовый отчёт + структурированное решение
/// (для кнопки «Починить сайт» на фронтенде).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainAnalysisOutcome {
    pub report: String,
    /// Готовое решение: что применит кнопка «Починить сайт» (или честная
    /// причина, почему решения нет). Данные и текст блока «ИТОГ АНАЛИЗА» —
    /// один источник (site_solution).
    pub solution: site_solution::SiteSolution,
}

/// Контрольная точка кнопки «Стоп» анализа (флаг site_analysis, cancel.rs).
/// Ранний Err безопасен: в off-window фазе обход восстановит
/// OffWindowGuard::Drop, worker пошлёт честный «failed» и фронту, и бейджу
/// «Ошибок сети».
fn ensure_active() -> Result<(), String> {
    if cancel::is_cancelled(cancel::SITE_ANALYSIS) {
        return Err("Анализ остановлен пользователем".into());
    }
    Ok(())
}

pub fn analyze_url(app: &AppHandle, url: &str) -> Result<DomainAnalysisOutcome, String> {
    // Единая точка распознавания цели (SSOT в ip_target).
    // IP/IP:port уходит в собственный IP-режим: браузер и сбор доменов
    // для IP-цели бессмысленны (сайту к IP нечего открывать).
    match ip_target::parse_target(url) {
        ip_target::AnalysisTarget::Ip { ip, port } => {
            let facts = ip_probe::analyze_ip(app, ip, port);
            let report = analyzer_ip_report::build_ip_report(ip, port, &facts);
            // Автоматических действий для IP-цели не подбираем: советы отчёта
            // вручную (профили, списки) — честный ответ вместо выдумки.
            let solution = site_solution::SiteSolution {
                found: false,
                actions: Vec::new(),
                summary: String::new(),
                none_reason: Some(
                    "для IP-цели автоматическое решение не подбирается — примените советы отчёта вручную"
                        .to_string(),
                ),
            };
            let mut report = report;
            report.push_str(&site_solution::report_block(&solution));
            // Отчёт IP-анализа в лог — как у доменного: SSOT бэкенда
            // (фронт-эхо убрано, см. analyze_domain).
            crate::events::app_log(app, report.clone());
            Ok(DomainAnalysisOutcome { report, solution })
        }
        ip_target::AnalysisTarget::Domain { host } => analyze_domain(app, url, host),
    }
}

/// Chrome-этап анализа: открыть страницу в headless-браузере, собрать все
/// домены, которые сайт реально запрашивает (CDN, API, скрипты, шрифты), и
/// домены, упавшие прямо в браузере. Вынесен целиком в отдельную функцию,
/// чтобы жить в собственном потоке под жёстким бюджетом (см. analyze_domain):
/// в прогонах 09.11.26 браузер не отдавал НИ ОДНОГО сетевого события и мог
/// блокировать ~35 с на navigate_to, съедая весь анализ.
fn analyze_chrome_stage(target_url: String) -> Result<(Vec<String>, HashSet<String>), String> {
    // Используем НОВЫЙ headless-режим (--headless=new). В отличие от старого
    // --headless, в новом режиме Chrome не спавнит отдельные консольные дочерние
    // процессы (renderer/GPU/crashpad), поэтому чёрное консольное окно вообще
    // не появляется. headless_chrome сам добавляет старый --headless, поэтому
    // ставим headless=false и передаём --headless=new явно через args.
    let options = LaunchOptions::default_builder()
        .headless(false)
        .args(vec![std::ffi::OsStr::new("--headless=new")])
        .build()
        .map_err(|e| format!("Ошибка опций запуска Chrome: {}", e))?;

    // Запоминаем уже запущенные chrome-С‹ (свои вкладки юзера), чтобы не трогать их окна.
    let known_chrome: Arc<Mutex<HashSet<u32>>> =
        Arc::new(Mutex::new(chrome_pids().into_iter().collect()));

    // Фоновый поток СКРЫТИЯ окон. Запускаем ЕГО ДО старта Chrome, иначе консольные
    // окна дочерних процессов Chrome (renderer/GPU/crashpad) успевают нарисоваться
    // во время Browser::new и мелькают перед юзером. Прячем их по PID в реальном времени.
    #[cfg(windows)]
    let hide_stop = Arc::new(AtomicBool::new(false));
    #[cfg(windows)]
    let hide_handle = {
        let known = known_chrome.clone();
        let stop = hide_stop.clone();
        // Быстрый цикл: прячем консольные окна Chrome каждые ~10 мс, начиная ДО
        // старта браузера, чтобы юзер не видел даже мгновенного мелькания.
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                win_hide::hide_chrome_consoles(&known);
                thread::sleep(Duration::from_millis(10));
            }
        })
    };

    let browser = Browser::new(options).map_err(|e| format!("Ошибка запуска Chrome (установлен ли он?): {}", e))?;
    let tab = browser.new_tab().map_err(|e| format!("Ошибка создания вкладки: {}", e))?;

    // Своё компактное логирование lifecycle браузера: INFO-шум крейта
    // headless_chrome (~13 строк Launching/Started/Navigating/Killing на
    // анализ) глушится фильтром плагина. PID отдаёт API крейта (Option —
    // connect-режим без процесса даёт None: честно пишем без PID).
    log::info!(
        "[Анализ] Chrome-этап: браузер запущен{}",
        browser
            .get_process_id()
            .map(|p| format!(" (PID {p})"))
            .unwrap_or_default()
    );

    // ВАЖНО: без явного включения Network-домена события RequestWillBeSent/LoadingFailed
    // вообще не приходят (navigate_to их не включает).
    let _ = tab.call_method(Network::Enable {
        max_total_buffer_size: None,
        max_resource_buffer_size: None,
        max_post_data_size: None,
        report_direct_socket_traffic: None,
        enable_durable_messages: None,
    });

    // Все домены, которые сайт реально запрашивает (включая под-ресурсы: CDN, API, скрипты, шрифты)
    let discovered_domains: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    // request_id -> url, чтобы по событию ошибки понять, какой домен сломался
    let request_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    // Домены, упавшие прямо в браузере (обрыв соединения)
    let browser_failed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // Счётчик числа запросов — растёт при каждом новом RequestWillBeSent.
    // По его «замиранию» определяем network-idle (страница догрузилась).
    let req_counter: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let dd = discovered_domains.clone();
    let rm = request_map.clone();
    let fb = browser_failed.clone();
    let rc = req_counter.clone();

    let _ = tab.add_event_listener(Arc::new(move |event: &Event| {
        let debug_str = format!("{:?}", event);

        if debug_str.contains("RequestWillBeSent") {
            let req_id = extract_value(&debug_str, "request_id");
            let u = extract_value(&debug_str, "url");
            if let (Some(id), Some(u)) = (req_id, u) {
                if u.starts_with("http") {
                    rc.fetch_add(1, Ordering::Relaxed);
                    rm.lock().unwrap().insert(id, u.clone());
                    if let Ok(parsed) = Url::parse(&u) {
                        if let Some(host) = parsed.host_str() {
                            dd.lock().unwrap().insert(host.to_string());
                        }
                    }
                }
            }
        } else if debug_str.contains("LoadingFailed") {
            let err_text = extract_value(&debug_str, "error_text").unwrap_or_default();
            // Нас интересуют только реальные обрывы соединения (то, что ломает обход)
            let is_conn_error = err_text.contains("ERR_CONNECTION")
                || err_text.contains("RESET")
                || err_text.contains("CLOSED")
                || err_text.contains("TIMED")
                || err_text.contains("net::ERR");
            if is_conn_error {
                if let Some(id) = extract_value(&debug_str, "request_id") {
                    if let Some(u) = rm.lock().unwrap().get(&id) {
                        if let Ok(parsed) = Url::parse(u) {
                            if let Some(host) = parsed.host_str() {
                                fb.lock().unwrap().insert(host.to_string());
                            }
                        }
                    }
                }
            }
        }
    }));

    let _ = tab.navigate_to(&target_url);

    // Универсальное ожидание по «network idle»: ждём, пока новые запросы перестанут
    // появляться (окно тишины IDLE_WINDOW), с общим потолком MAX_WAIT. Это ловит
    // поздние домены SPA / lazy-load / редиректов для любого сайта, а не фиксированные 15 с.
    // Скрытие окон/консолей Chrome выполняет фоновый поток (запущен до старта браузера).
    {
        const IDLE_WINDOW: Duration = Duration::from_secs(3);
        const MAX_WAIT: Duration = Duration::from_secs(30);
        const MIN_WAIT: Duration = Duration::from_secs(4);
        let start = std::time::Instant::now();
        let mut last_count = req_counter.load(Ordering::Relaxed);
        let mut last_change = std::time::Instant::now();
        loop {
            thread::sleep(Duration::from_millis(250));
            let now_count = req_counter.load(Ordering::Relaxed);
            if now_count != last_count {
                last_count = now_count;
                last_change = std::time::Instant::now();
            }
            let elapsed = start.elapsed();
            if elapsed >= MAX_WAIT {
                break;
            }
            if elapsed >= MIN_WAIT && last_change.elapsed() >= IDLE_WINDOW {
                break;
            }
        }
    }

    // Останавливаем фоновый поток скрытия окон.
    #[cfg(windows)]
    {
        hide_stop.store(true, Ordering::Relaxed);
        let _ = hide_handle.join();
    }

    // Явный drop ДО строки остановки: крейтный Drop гасит процесс Chrome
    // (Killing Chrome — глушится фильтром плагина как шум), наша строка —
    // честный итог этапа в одну запись.
    drop(browser);
    log::info!("[Анализ] Chrome-этап: браузер остановлен");

    let mut discovered: Vec<String> =
        discovered_domains.lock().unwrap().iter().cloned().collect();
    discovered.sort();
    let browser_failed_set: HashSet<String> =
        browser_failed.lock().unwrap().iter().cloned().collect();
    Ok((discovered, browser_failed_set))
}

/// Бюджет Chrome-этапа анализа (запуск/навигация/idle-ожидание, теминг «chrome»).
pub(crate) const CHROME_BUDGET: Duration = Duration::from_secs(10);

/// Окно «обход выключен» (OFF-фаза): все фактовые пробы чистого окна — проба
/// #2, DoH-резолв главного домена, подмена DNS, CIDR-скан, фоновые подмены.
/// Гарантия дедлайна очереди (ANALYSIS_DEADLINE 90 с, инцидент 09.11.26):
/// Chrome 10 + OFF 35 + restore 2 + ON 30 = 77 с < 90 с, запас 13 с. Окно
/// живёт max(DoH-резолв, probe, подмена, скан): probe подчинён бюджету
/// частично (факт 34.9 с при бюджете 20 с в прогоне 01:33 11.11.26), поэтому
/// подмена DNS и CIDR-скан стартуют СРАЗУ после DoH-резолва — параллельно
/// probe — и успевают при любом probe. Сумму защищает тест
/// window_budgets_fit_analysis_deadline.
pub(crate) const WINDOW_BUDGET: Duration = Duration::from_secs(35);

/// Фаза ON (DoH-резолв + подмена DNS С активным обходом): отдельный бюджет —
/// resolve_doh_all_within ограничен 9 с, на подмену остаётся ~21 с (в прогоне
/// 01:33 вся фаза шла 17.9 с при прежних 20 — впритык).
pub(crate) const ON_WINDOW_BUDGET: Duration = Duration::from_secs(30);


fn analyze_domain(app: &AppHandle, url: &str, main_host: String) -> Result<DomainAnalysisOutcome, String> {
    let target_url = ip_target::target_url_of(url);

    // Тайминги этапов: пользователь видит, где анализ проводит время,
    // а мы — где его стоит ускорять (логирование до/после оптимизаций).
    let mut timings: Vec<(&'static str, std::time::Duration)> = Vec::new();
    let t_total = std::time::Instant::now();

    // Chrome-этап — под жёстким бюджетом: запуск/навигация/idle-ожидание
    // живут в отдельном потоке, результат ждём recv_timeout. Таймаут →
    // продолжаем с пустым списком (домены вкладки не собраны — это честно
    // отражено в отчёте как пустой discovered); брошенный поток сам дошлёт
    // idle-ожидание и умрёт вместе с Browser. 10 с хватает с запасом: старт
    // Chrome ~3-5 с + выход idle-цикла по MIN_WAIT 4 с, когда событий нет.
    let t_chrome = std::time::Instant::now();
    let (chrome_tx, chrome_rx) = std::sync::mpsc::channel();
    let chrome_target = target_url.clone();
    thread::spawn(move || {
        let _ = chrome_tx.send(analyze_chrome_stage(chrome_target));
    });
    let (discovered, browser_failed_set) = match chrome_rx.recv_timeout(CHROME_BUDGET) {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(e), // Chrome не запустился — честная ошибка анализа
        Err(_) => {
            crate::events::app_log(
                app,
                format!(
                    "[Анализ] браузер не уложился в {} с — этап пропущен, домены вкладки не собраны",
                    CHROME_BUDGET.as_secs()
                ),
            );
            (Vec::new(), HashSet::new())
        }
    };
    // Метка в теминге держится вразумительной с константой CHROME_BUDGET выше.
    timings.push(("chrome: загрузка страницы (бюджет 10 с)", t_chrome.elapsed()));

    // Контрольная точка «Стоп» — сразу после Chrome-этапа.
    ensure_active()?;

    let had_browser_failures = !browser_failed_set.is_empty();

    // === Этап проверки доступности ===
    // Независимо «простукиваем» каждый найденный домен через сетевой стек ОС.
    // Так как winws (WinDivert) работает на уровне драйвера, он перехватывает ВЕСЬ
    // трафик, включая этот запрос. Если обход ломает домен — получим обрыв соединения.
    let bypass_on = process::is_winws_running();

    // Проба #1: домены как есть (обход в текущем состоянии).
    let t_probe1 = std::time::Instant::now();
    let results_on = analyzer_probe::probe_all(&discovered);
    timings.push((
        if bypass_on {
            "probe_all #1 (с обходом)"
        } else {
            "probe_all #1 (без обхода)"
        },
        t_probe1.elapsed(),
    ));

    // Собираем домены, оборвавшиеся с включённым обходом — их надо перепроверить БЕЗ обхода,
    // чтобы отличить «заблокирован сам» (в обход) от «обход его ломает» (в исключения).
    let broken_on: Vec<String> = results_on
        .iter()
        .filter_map(|(h, p)| match p {
            Probe::Broken(_) | Probe::DeadIp => Some(h.clone()),
            _ => None,
        })
        .collect();

    // Контрольная точка после probe_all #1: до окна «обход выключен» —
    // ранний Err здесь обход ещё не трогал (winws в исходном состоянии).
    ensure_active()?;

    let mut bypass_toggled = false;
    let mut restore_note: Option<String> = None;

    // Общий бюджет чистого окна на ВСЕ фактовые пробы (обе ветки ниже):
    // раньше переборы DoH-сервисов и IP жили своими внутренними таймаутами и
    // на сайтах с тихим дропом TLS горели 300+ с (инцидент 09.11.26). Бюджет
    // кончился → пробы останавливаются, отчёт строится из собранного с
    // честными пометками «не проверено: не хватило бюджета». Кнопка «Стоп»
    // останавливает переборы немедленно (без ожидания контрольной точки).
    let window_budget =
        StageBudget::new_with_cancel(WINDOW_BUDGET, || cancel::is_cancelled(cancel::SITE_ANALYSIS));

    // === Окно «обход выключен» ===
    // Все фактовые пробы (диагностика главного домена, подмена DNS, разбор блока)
    // обязаны идти БЕЗ активного winws: обход перехватывает ВЕСЬ трафик процесса,
    // и при включённом профиле, который ломает сайт, отчёт получал ложные
    // «IP не отвечает / фильтрация маршрута» вместо правды (кейс sostav.ru).
    let (classification, main_probe, main_dns_sub, main_dns_sub_on, dns_fail_sub, block_scan, bypass_on_http) =
        if bypass_on {
        // Окно без обхода с гарантией восстановления: паника внутри ветки
        // больше не оставляет обход выключенным (OffWindowGuard::Drop).
        let off_window = bypass_toggle::OffWindowGuard::open(app);
        bypass_toggled = true;
        let t_off = std::time::Instant::now();

        // === Две параллельные цепочки под общим бюджетом окна ===
        // Кейс googlevideo.com 00:40: последовательный хвост окна (подмена DNS,
        // CIDR-скан, фоновые подмены) входил с исчерпанным бюджетом и целиком
        // превращался в «не проверено: не хватило бюджета окна». Теперь цепь A
        // (проба #2 + классификация + фоновые подмены) и цепь B (главный домен:
        // DoH-резолв → параллельно диагностика ∥ подмена DNS ∥ CIDR-скан) идут
        // ОДНОВРЕМЕННО и делят один бюджет — фаза больше не тушит другую.
        // Все бюджеты — new_with_cancel: «Стоп» останавливает всё немедленно.
        let chain_a = {
            let broken_on = broken_on.clone();
            let results_on = results_on.clone();
            let browser_failed_set = browser_failed_set.clone();
            let budget = window_budget;
            thread::spawn(move || {
                let mut broken_off: HashSet<String> = HashSet::new();
                let mut dns_off: HashSet<String> = HashSet::new();
                let mut dead_off: HashSet<String> = HashSet::new();
                for (h, off) in analyzer_probe::probe_off(&broken_on) {
                    match off {
                        analyzer_probe::OffProbe::Ok => {}
                        analyzer_probe::OffProbe::Dns => {
                            dns_off.insert(h);
                        }
                        analyzer_probe::OffProbe::Broken => {
                            broken_off.insert(h);
                        }
                        // Без обхода сервер вообще не отвечает: домен недоступен
                        // сам по себе, ни обход, ни исключения тут не при чём.
                        analyzer_probe::OffProbe::Dead => {
                            dead_off.insert(h);
                        }
                    }
                }

                // Контрольная точка отмены (поток не может выйти через `?`
                // наружу — Err уедет в join и честно упадёт анализ).
                ensure_active()?;
                let classification = analyzer_probe::classify_dual(
                    results_on,
                    &broken_off,
                    &dns_off,
                    &dead_off,
                    &browser_failed_set,
                );

                // Лёгкая подмена DNS для «не резолвящихся» (до 5) — из остатка
                // бюджета (низкий приоритет: фоновые домены).
                let t_dnsfail = std::time::Instant::now();
                let dns_fail_sub = dns_fail_sub_parallel(&classification.dns_fail, 5, budget);
                Ok::<_, String>((classification, dns_fail_sub, t_dnsfail.elapsed()))
            })
        };
        let chain_b = {
            let main_host = main_host.clone();
            let app = app.clone();
            let budget = window_budget;
            thread::spawn(move || {
                // DoH-ответы главного домена: бюджетированный резолв (дедлайн
                // min(9 с, остаток окна)) — фаза больше не перерасходует окно
                // через «свой» 9-с таймаут резолва (кейс googlevideo 00:40).
                let t_probe = std::time::Instant::now();
                let main_doh_answers =
                    crate::diagnostics_probe::resolve_doh_all_within(&main_host, budget);
                // ВСЁ параллельно, СРАЗУ после DoH-резолва: диагностика
                // главного домена, подмена DNS и CIDR-скан — три потока на
                // общем бюджете окна. Прежний порядок «probe → потом подмена»
                // сожрал бюджет пробой (34.9 с probe при бюджете 20 с; probe
                // сам бюджет уважает частично) — подмена всегда получала
                // обрезок «не проверено» (кейс googlevideo 01:33 11.11.26).
                // Айпишник ищем всегда: подмена — отдельные пробы по адресам
                // DoH-канала, её результат не зависит от вердикта probe.
                let main_probe_handle = {
                    let host = main_host.clone();
                    let answers = main_doh_answers.clone();
                    thread::spawn(move || {
                        site_probe::probe_domain_with_doh(&host, &answers, budget)
                    })
                };
                let sub_handle = {
                    let host = main_host.clone();
                    let answers = main_doh_answers.clone();
                    thread::spawn(move || {
                        site_probe::dns_substitutions_from(&host, &answers, true, budget)
                    })
                };
                let block_handle = {
                    let host = main_host.clone();
                    thread::spawn(move || {
                        crate::ip_range_scan::block_diagnose(&app, &host, budget)
                    })
                };
                let main_probe = main_probe_handle
                    .join()
                    .map_err(|_| "поток диагностики главного домена упал".to_string())?;
                let main_dns_sub = sub_handle
                    .join()
                    .map_err(|_| "поток подмены DNS упал".to_string())?;
                let block_scan_raw = block_handle
                    .join()
                    .map_err(|_| "поток CIDR-скана (block_diagnose) упал".to_string())?;
                // CIDR-скан осмыслен только для сломанного сайта: при открытом
                // сайте или WwwOnly-вердикте результат скана не показываем
                // (гейт использования; запуск всегда — иначе скан, стартующий
                // после probe, входил с исчерпанным бюджетом и целиком
                // превращался в «не проверено»).
                let block_scan = if main_probe.verdict.site_broken()
                    && main_probe.verdict != crate::site_verdict::Verdict::WwwOnly
                {
                    Some(block_scan_raw)
                } else {
                    None
                };
                let t_probe_elapsed = t_probe.elapsed();

                Ok::<_, String>((
                    main_probe,
                    main_doh_answers,
                    main_dns_sub,
                    block_scan,
                    t_probe_elapsed,
                ))
            })
        };

        // Join цепочек: паника потока = честная ошибка анализа (обход
        // восстановит OffWindowGuard::Drop при выходе из области).
        let res_a = chain_a
            .join()
            .map_err(|_| "поток пробы #2 (чистое окно) упал".to_string())?;
        let (mut classification, dns_fail_sub, t_dnsfail) = res_a?;
        let res_b = chain_b
            .join()
            .map_err(|_| "поток диагностики главного домена упал".to_string())?;
        let (main_probe, main_doh_answers, main_dns_sub, block_scan, t_probe_elapsed) = res_b?;

        ensure_active()?;
        timings.push(("главный домен (DoH-резолв ∥ проба ∥ подмена ∥ CIDR-скан)", t_probe_elapsed));
        timings.push(("dns_fail_sub (фоновые DoH-проверки)", t_dnsfail));

        // Арбитраж (кейс eu.aptabase.com): если сайт доказанно открывается без
        // обхода, а классификация зовёт его в обход — верен вывод «обход его
        // ломает» (в исключения), а не «добавьте в обход».
        analyzer_probe::arbitrate_open_main_host(
            &mut classification,
            results_on
                .iter()
                .find(|(h, _)| h == &main_host)
                .map(|(_, p)| p),
            &main_host,
            main_probe.verdict == crate::site_verdict::Verdict::Open,
        );

        timings.push((
            "окно без обхода (проба #2 + ретраи + главный домен)",
            t_off.elapsed(),
        ));

        restore_note = off_window.close();

        // === Фаза ON: DoH-резолв и подмена DNS С ОБХОДОМ ===
        // РКН блокирует сами DoH-сервисы: в чистом окне часть списка горит
        // таймаутами, с обходом отвечает (как у браузера юзера). Поэтому список
        // резолвится ещё раз С активным обходом, ответы сливаются с OFF-фазой
        // (merge_doh_answers), и полная подмена DNS идёт по объединению — каждый
        // сервис SSOT-файла проверен в ОБОИХ состояниях обхода. Условие запуска —
        // прежняя контрольная проба: GeoBlocked/ServiceRestricted пропускаем
        // (отказ сайта уже виден в чистом окне, повторять нечего).
        ensure_active()?;
        let main_dns_sub_on = if main_probe.verdict.site_broken()
            && main_probe.verdict != crate::site_verdict::Verdict::WwwOnly
            && main_probe.verdict != crate::site_verdict::Verdict::GeoBlocked
            && main_probe.verdict != crate::site_verdict::Verdict::ServiceRestricted
        {
            let t_on = std::time::Instant::now();
            let budget_on = StageBudget::new_with_cancel(
                ON_WINDOW_BUDGET,
                || cancel::is_cancelled(cancel::SITE_ANALYSIS),
            );
            let answers_on =
                crate::diagnostics_probe::resolve_doh_all_within(&main_host, budget_on);
            let merged =
                crate::diagnostics_probe::merge_doh_answers(&main_doh_answers, &answers_on);
            let subs_on = site_probe::dns_substitutions_from(&main_host, &merged, true, budget_on);
            timings.push(("фаза с обходом (DoH-резолв + подмена DNS)", t_on.elapsed()));
            subs_on
        } else {
            Vec::new()
        };

        // Рабочий IP из ON-колонки — роль прежней контрольной пробы с обходом,
        // но из полного перебора всех сервисов, а не одного первого IP:
        // предпочитаем подтверждённый Ok/Unverified, иначе первый типизированный
        // отказ (Forbidden/BlockPage — «сайт сам ограничивает», кейс Patreon).
        let bypass_on_http = {
            let mut chosen: Option<(IpAddr, crate::diagnostics_probe::HttpResult)> = None;
            let mut fallback: Option<(IpAddr, crate::diagnostics_probe::HttpResult)> = None;
            for s in &main_dns_sub_on {
                let Some(http) = &s.http else { continue };
                let Some(ip_str) = &s.working_ip else { continue };
                let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
                if s.http_ok {
                    chosen = Some((ip, http.clone()));
                    break;
                }
                if fallback.is_none() {
                    fallback = Some((ip, http.clone()));
                }
            }
            chosen.or(fallback)
        };

        (classification, Some(main_probe), main_dns_sub, main_dns_sub_on, dns_fail_sub, block_scan, bypass_on_http)
    } else {
        // Обход был выключен изначально — весь анализ и так шёл в чистом окне.
        let classification =
            analyzer_probe::classify_single(results_on, &browser_failed_set);

        // DoH-ответы грузятся ОДИН раз (см. ветку обхода выше).
        ensure_active()?;
        let t_probe = std::time::Instant::now();
        let main_doh_answers =
            crate::diagnostics_probe::resolve_doh_all_within(&main_host, window_budget);
        let main_probe = site_probe::probe_domain_with_doh(&main_host, &main_doh_answers, window_budget);
        timings.push(("probe_domain (диагностика главного домена)", t_probe.elapsed()));
        let main_dns_sub = if main_probe.verdict.site_broken()
            && main_probe.verdict != crate::site_verdict::Verdict::WwwOnly
        {
            site_probe::dns_substitutions_from(&main_host, &main_doh_answers, true, window_budget)
        } else {
            Vec::new()
        };
        ensure_active()?;
        let t_block = std::time::Instant::now();
        let block_scan = if main_probe.verdict.site_broken()
            && main_probe.verdict != crate::site_verdict::Verdict::WwwOnly
        {
            Some(crate::ip_range_scan::block_diagnose(app, &main_host, window_budget))
        } else {
            None
        };
        timings.push(("block_diagnose (CIDR-скан)", t_block.elapsed()));

        ensure_active()?;
        let t_dnsfail = std::time::Instant::now();
        let dns_fail_sub = dns_fail_sub_parallel(&classification.dns_fail, 5, window_budget);
        timings.push(("dns_fail_sub (фоновые DoH-проверки)", t_dnsfail.elapsed()));

        (classification, Some(main_probe), main_dns_sub, Vec::new(), dns_fail_sub, block_scan, None)
    };

    // SSOT: карта списков обхода загружается РАЗ на анализ и едет в meta —
    // отчёт и решение (`site_solution::decide`) потребляют одни данные.
    let bypass_map = bypass_lists::load_bypass_domains();

    // Факт «закреплено в hosts» для главного домена (кейс 30.10.26: прописали
    // IP — он умер, а анализ резолвит мимо hosts, браузер — по hosts). Пробы
    // закреплённых адресов — в рабочем состоянии обхода (окно уже закрыто),
    // как по ним ходит браузер юзера.
    ensure_active()?;
    let t_pins = std::time::Instant::now();
    let hosts_pins = {
        let map = match crate::hosts::load_hosts_map() {
            Ok(m) => m,
            Err(e) => {
                crate::events::app_log(
                    app,
                    format!("[Анализ] hosts не прочитан — закреплённые записи не проверены: {}", e),
                );
                std::collections::HashMap::new()
            }
        };
        let ips = map.get(&main_host).cloned().unwrap_or_default();
        if ips.is_empty() {
            Vec::new()
        } else {
            // Метки DPI_GUI читаются отдельным проходом: ошибка — это НЕ «все
            // записи ручные» (так решение соврало бы), а пропуск пинов с логом.
            site_probe::probe_hosts_pins(&main_host, &ips).unwrap_or_else(|e| {
                crate::events::app_log(
                    app,
                    format!(
                        "[Анализ] метки DPI_GUI в hosts не прочитаны — закреплённые записи не проверены: {}",
                        e
                    ),
                );
                Vec::new()
            })
        }
    };
    timings.push(("hosts_pins (пробы закреплённых адресов)", t_pins.elapsed()));

    let meta = ReportMeta {
        target_url,
        discovered,
        bypass_on,
        bypass_toggled,
        restore_note,
        had_browser_failures,
        main_probe,
        main_dns_sub,
        main_dns_sub_on,
        dns_fail_sub,
        block_scan,
        bypass_map,
        exclude_set: bypass_lists::load_exclude_domains(),
        user_exclude_entries: bypass_lists::user_exclude_entries(),
        hosts_pins,
        bypass_on_http,
    };

    let mut report = analyzer_report::build_report(&meta, &classification);
    // «Найденное решение» — из тех же фактов, что и отчёт (SSOT):
    // decide() читает meta/classification, report_block печатает тот же итог.
    let solution = site_solution::decide(&meta, &classification);
    report.push_str(&site_solution::report_block(&solution));
    // Тайминги этапов: где анализ провёл время (видно пользователю в логе).
    report.push_str(&timing_block(&timings, t_total.elapsed()));

    // Отчёт анализа в лог — единожды отсюда (SSOT бэкенда). Фронт-эхо
    // (SiteFixTab appendLog) убрано: мультистроку плагин сам разрежет на
    // записи (контракт «одна строка = одна запись»), хвост больше не режется.
    crate::events::app_log(app, report.clone());

    Ok(DomainAnalysisOutcome { report, solution })
}

/// Подмена DNS для доменов из списка «не резолвится» (до `limit`): проверка
/// параллельна — последовательный `.map` тянул дедлайн DoH (~9 с) на каждый
/// домен (до 45 с на пятерку). Порядок результатов — исходный. Неуспевшие
/// по бюджету/отмене домены опускаются (их подмена и так не проверена).
pub(crate) fn dns_fail_sub_parallel(
    hosts: &[String],
    limit: usize,
    budget: StageBudget,
) -> Vec<(String, Vec<site_probe::DnsSubstitution>)> {
    use std::sync::mpsc;
    let targets: Vec<String> = hosts.iter().take(limit).cloned().collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let (tx, rx) =
        mpsc::channel::<(usize, (String, Vec<site_probe::DnsSubstitution>))>();
    for (idx, h) in targets.iter().enumerate() {
        let tx = tx.clone();
        let h = h.clone();
        std::thread::spawn(move || {
            let subs = site_probe::check_dns_substitution(&h, false, budget);
            let _ = tx.send((idx, (h, subs)));
        });
    }
    drop(tx);
    let mut slots: Vec<Option<(String, Vec<site_probe::DnsSubstitution>)>> =
        (0..targets.len()).map(|_| None).collect();
    let deadline = std::time::Instant::now() + budget.left();
    for _ in 0..targets.len() {
        if budget.stopped() {
            break;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((idx, item)) => slots[idx] = Some(item),
            Err(_) => break,
        }
    }
    slots.into_iter().flatten().collect()
}

/// Текстовый блок таймингов анализа: по этапам и суммарно.
fn timing_block(timings: &[(&str, std::time::Duration)], total: std::time::Duration) -> String {
    let mut s = String::from("\n⏱ ТЕМИНГ АНАЛИЗА (где прошло время):\n");
    for (name, dt) in timings {
        s.push_str(&format!("  • {}: {:.1} с\n", name, dt.as_secs_f64()));
    }
    s.push_str(&format!("  ИТОГО: {:.1} с\n", total.as_secs_f64()));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Восстановление обхода после окна (sc stop WinDivert + пауза выгрузки
    /// драйвера) — в дедлайне очереди учтено константой теста.
    const RESTORE_GRACE: Duration = Duration::from_secs(2);

    /// Дедлайн очереди (инцидент 09.11.26: анализ горел 300+ с и умирал без
    /// отчёта): сумма бюджетов фаз обязана влезать в ANALYSIS_DEADLINE с
    /// запасом на перерасход probe (окно живёт max(потоки), probe частично
    /// вне бюджета) и на контрольные точки между фазами.
    #[test]
    fn window_budgets_fit_analysis_deadline() {
        let total = CHROME_BUDGET + WINDOW_BUDGET + RESTORE_GRACE + ON_WINDOW_BUDGET;
        let deadline = crate::analysis_queue::ANALYSIS_DEADLINE;
        assert!(
            total < deadline,
            "сумма бюджетов {:?} должна быть меньше дедлайна {:?}",
            total,
            deadline
        );
        assert!(
            deadline - total >= Duration::from_secs(10),
            "запас после бюджета {} с — меньше 10 с на перерасход probe",
            (deadline - total).as_secs()
        );
    }
}
