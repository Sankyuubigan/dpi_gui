use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::thread;
use url::Url;
use headless_chrome::{Browser, LaunchOptions};
use headless_chrome::protocol::cdp::types::Event;
use headless_chrome::protocol::cdp::Network;
use sysinfo::System;
use tauri::AppHandle;
use crate::process;
use crate::config;
use crate::analyzer_probe::{self, Probe};
use crate::analyzer_report::{self, ReportMeta};
use crate::site_probe;

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

pub fn analyze_url(app: &AppHandle, url: &str) -> Result<String, String> {
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    // Диагностика главного домена: DNS + поиск рабочего IP + первопричина.
    // Делаем сразу, чтобы отчёт начинался с главного: «сайт не открывается, вот почему».
    let main_host = url::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| target_url.clone())
        .trim_end_matches('/')
        .to_string();
    let main_probe = site_probe::probe_domain(&main_host);

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

    let discovered: Vec<String> = {
        let mut v: Vec<String> = discovered_domains.lock().unwrap().iter().cloned().collect();
        v.sort();
        v
    };
    let browser_failed_set: HashSet<String> = browser_failed.lock().unwrap().iter().cloned().collect();
    let had_browser_failures = !browser_failed_set.is_empty();

    // === Этап проверки доступности ===
    // Независимо «простукиваем» каждый найденный домен через сетевой стек ОС.
    // Так как winws (WinDivert) работает на уровне драйвера, он перехватывает ВЕСЬ
    // трафик, включая этот запрос. Если обход ломает домен — получим обрыв соединения.
    let bypass_on = process::is_winws_running();

    // Проба #1: домены как есть (обход в текущем состоянии).
    let results_on = analyzer_probe::probe_all(&discovered);

    // Собираем домены, оборвавшиеся с включённым обходом — их надо перепроверить БЕЗ обхода,
    // чтобы отличить «заблокирован сам» (в обход) от «обход его ломает» (в исключения).
    let broken_on: Vec<String> = results_on
        .iter()
        .filter_map(|(h, p)| match p {
            Probe::Broken(_) | Probe::DeadIp => Some(h.clone()),
            _ => None,
        })
        .collect();

    let mut bypass_toggled = false;
    let mut restore_note: Option<String> = None;

    let classification = if bypass_on && !broken_on.is_empty() {
        // Запоминаем активный профиль, чтобы восстановить обход после проверки.
        let (saved_profile, saved_game_filter) = read_active_profile();

        // Выключаем обход и перепроверяем сломанные домены без него.
        let _ = process::stop_winws();
        bypass_toggled = true;
        // Пауза на выгрузку драйвера WinDivert (см. docs 4.7).
        thread::sleep(Duration::from_millis(1200));

        let results_off = analyzer_probe::probe_all(&broken_on);
        let mut broken_off: HashSet<String> = HashSet::new();
        let mut dns_off: HashSet<String> = HashSet::new();
        let mut dead_off: HashSet<String> = HashSet::new();
        for (h, p) in results_off {
            match p {
                Probe::Broken(_) => {
                    broken_off.insert(h);
                }
                Probe::Dns => {
                    dns_off.insert(h);
                }
                // Без обхода сервер вообще не отвечает: домен недоступен сам по
                // себе, ни обход, ни исключения тут не при чём.
                Probe::DeadIp => {
                    dead_off.insert(h);
                }
                Probe::Ok => {}
            }
        }

        // Авто-восстановление обхода прежним профилем.
        if let Some(profile) = saved_profile {
            match process::start_winws(app.clone(), &profile, saved_game_filter) {
                Ok(_) => {
                    restore_note = Some(format!(
                        "✅ Обход восстановлен (профиль «{}»).",
                        profile
                    ));
                }
                Err(e) => {
                    restore_note = Some(format!(
                        "⚠️ Не удалось восстановить обход автоматически ({}). Включите профиль вручную.",
                        e
                    ));
                }
            }
        } else {
            restore_note = Some(
                "⚠️ Активный профиль не определён — включите обход вручную.".to_string(),
            );
        }

        analyzer_probe::classify_dual(
            results_on,
            &broken_off,
            &dns_off,
            &dead_off,
            &browser_failed_set,
        )
    } else {
        // Обход был выключен изначально (или обрывов нет) — одиночная классификация.
        analyzer_probe::classify_single(results_on, &browser_failed_set)
    };

    // Автопроверка «подмены DNS». Обычный DNS (системный/публичные UDP:53) может
    // быть отравлен или перехвачен, и тогда сайт не открывается, хотя сам не
    // заблокирован. Если главный домен не открывается — резолвим его через
    // DoH-сервисы xbox-dns.ru/geohide.ru и ищем рабочий IP для подмены.
    // При WwwOnly проверка бессмысленна: рабочее имя уже найдено.
    let main_dns_sub = if main_probe.verdict.site_broken()
        && main_probe.verdict != site_probe::Verdict::WwwOnly
    {
        site_probe::check_dns_substitution(&main_host, true)
    } else {
        Vec::new()
    };

    // Домены, «не резолвящиеся» по классификации, тоже прогоняем через подмену
    // (до 5 штук, лёгкая проверка — без полного HTTPS-прогона).
    let dns_fail_sub: Vec<(String, Vec<site_probe::DnsSubstitution>)> = classification
        .dns_fail
        .iter()
        .take(5)
        .map(|h| (h.clone(), site_probe::check_dns_substitution(h, false)))
        .collect();

    let meta = ReportMeta {
        target_url,
        discovered,
        bypass_on,
        bypass_toggled,
        restore_note,
        had_browser_failures,
        main_probe: Some(main_probe),
        main_dns_sub,
        dns_fail_sub,
    };

    Ok(analyzer_report::build_report(&meta, &classification))
}

/// Читает активный профиль обхода и флаг game_filter из config.json.
fn read_active_profile() -> (Option<String>, bool) {
    match config::read_config() {
        Ok(cfg) => {
            let profile = cfg
                .get("selected_profile")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let game_filter = cfg
                .get("game_filter")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            (profile, game_filter)
        }
        Err(_) => (None, false),
    }
}

