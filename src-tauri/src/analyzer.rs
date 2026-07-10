use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::thread;
use std::path::PathBuf;
use url::Url;
use headless_chrome::{Browser, LaunchOptions};
use headless_chrome::protocol::cdp::types::Event;
use headless_chrome::protocol::cdp::Network;
use reqwest::blocking::Client as HttpClient;
use sysinfo::System;
use crate::process;
use crate::bypass_lists;

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
        // дочерних процессов Chrome (crashpad-handler и т.п.), и тогда окно
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
            // Прячем ЛЮБОЕ окно дочернего процесса Chrome (в т.ч. чёрную
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

pub fn analyze_url(url: &str) -> Result<String, String> {
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

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

    // Запоминаем уже запущенные chrome-ы (свои вкладки юзера), чтобы не трогать их окна.
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

    let dd = discovered_domains.clone();
    let rm = request_map.clone();
    let fb = browser_failed.clone();

    let _ = tab.add_event_listener(Arc::new(move |event: &Event| {
        let debug_str = format!("{:?}", event);

        if debug_str.contains("RequestWillBeSent") {
            let req_id = extract_value(&debug_str, "request_id");
            let u = extract_value(&debug_str, "url");
            if let (Some(id), Some(u)) = (req_id, u) {
                if u.starts_with("http") {
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

    // Даем странице время подгрузить под-ресурсы (скрипты, API, CDN и т.д.).
    // Скрытие окон/консолей, которые порождает Chrome, выполняет фоновый поток,
    // запущенный выше (до старта браузера). Здесь только ждем загрузку.
    // known_chrome — chrome-ы, запущенные ДО анализа (свои вкладки юзера), трогать не будем.
    thread::sleep(Duration::from_secs(15));

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

    // === Этап проверки доступности ===
    // Независимо «простукиваем» каждый найденный домен через сетевой стек ОС.
    // Так как winws (WinDivert) работает на уровне драйвера, он перехватывает ВЕСЬ трафик,
    // включая этот запрос. Если обход ломает домен — получим обрыв соединения.
    let bypass_on = process::is_winws_running();

    // Проверяем домены параллельно (пачками), чтобы не ждать минуты при большом числе под-ресурсов.
    #[derive(Clone)]
    enum Probe {
        Ok,
        Dns,
        Broken(String),
    }

    const CHUNK: usize = 16;
    let mut results: Vec<(String, Probe)> = Vec::new();
    for chunk in discovered.chunks(CHUNK) {
        let mut handles = Vec::new();
        for host in chunk {
            let host = host.clone();
            handles.push(thread::spawn(move || {
                let client = HttpClient::builder()
                    .timeout(Duration::from_secs(5))
                    .danger_accept_invalid_certs(true)
                    .build();
                let test_url = format!("https://{}/", host);
                match client.and_then(|c| c.get(&test_url).send()) {
                    // Любой HTTP-ответ (даже 403/404) значит, что связь установилась — обход его не ломает
                    Ok(_) => (host, Probe::Ok),
                    Err(e) => {
                        let m = e.to_string().to_lowercase();
                        if m.contains("dns")
                            || m.contains("resolve")
                            || m.contains("name or service not known")
                            || m.contains("no address")
                        {
                            (host, Probe::Dns)
                        } else {
                            (host, Probe::Broken(e.to_string()))
                        }
                    }
                }
            }));
        }
        for h in handles {
            if let Ok(r) = h.join() {
                results.push(r);
            }
        }
    }

    let mut broken: Vec<(String, String)> = Vec::new();   // обрыв соединения -> кандидат в исключения
    let mut dns_fail: Vec<String> = Vec::new();           // похоже на блок РФ на уровне DNS
    let mut ok: Vec<String> = Vec::new();

    for (host, probe) in results {
        match probe {
            Probe::Ok => ok.push(host),
            Probe::Dns => dns_fail.push(host),
            Probe::Broken(err) => broken.push((host, err)),
        }
    }

    // Домены, упавшие прямо в браузере, но «прошедшие» простую проверку, тоже считаем сломанными
    for host in &browser_failed_set {
        if !ok.contains(host) && !broken.iter().any(|(h, _)| h == host) {
            broken.push((host.clone(), "обрыв соединения в браузере (LoadingFailed)".to_string()));
        }
    }

    broken.sort_by(|a, b| a.0.cmp(&b.0));
    dns_fail.sort();
    ok.sort();

    // === Кросс-чек с списками обхода ===
    // Ищем домены сайта, которые УЖЕ внесены в списки обхода (hostlist). Если такой домен
    // там по ошибке — обход его «мучает» и может ломать сайт. Советуем убрать из списка.
    let bypass_map = bypass_lists::load_bypass_domains();
    let bypass_matches = bypass_lists::find_bypass_matches(&discovered, &bypass_map);
    // Домены, которые одновременно сломаны обходом И присутствуют в списке обхода
    let broken_set: HashSet<String> = broken.iter().map(|(h, _)| h.clone()).collect();
    // Текущие исключения юзера (чтобы не советовать добавлять уже добавленное)
    let exclude_set = bypass_lists::load_exclude_domains();

    // === Формируем отчет ===
    let mut log = String::new();
    log.push_str(&format!("=== АНАЛИЗ ДОМЕНОВ: {} ===\n\n", target_url));

    log.push_str(&format!(
        "Обход (winws) активен: {}\n",
        if bypass_on { "ДА" } else { "НЕТ" }
    ));
    if !bypass_on {
        log.push_str("⚠️ Обход ВЫКЛЮЧЕН. Чтобы найти домены, которые ломает обход, ВКЛЮЧИТЕ профиль обхода и запустите анализ снова.\n");
    }
    log.push_str(&format!("🔎 Обнаружено доменов: {}\n\n", discovered.len()));

    log.push_str("❌ ДОМЕНЫ, КОТОРЫЕ ЛОМАЕТ ОБХОД (добавьте в исключения):\n");
    if broken.is_empty() {
        log.push_str("  - (пусто) все домены доступны через обход\n");
    } else {
        // Родительские домены среди сломанных (не покрытых исключениями) — для сокращения
        let mut parent_suggestions: Vec<String> = Vec::new();
        for (h, err) in &broken {
            let reason = err.lines().next().unwrap_or(err);
            let parent = bypass_lists::parent_domain(h);
            let kind = if parent == h.to_lowercase() {
                "[корневой домен]".to_string()
            } else {
                format!("[субдомен, родитель: {}]", parent)
            };
            let covered = bypass_lists::is_excluded(h, &exclude_set);
            let action = match covered {
                Some(entry) => format!("уже в исключениях: {} — не дублируйте", entry),
                None => {
                    if parent != h.to_lowercase() && !parent_suggestions.contains(&parent) {
                        parent_suggestions.push(parent.clone());
                    }
                    "добавьте в исключения".to_string()
                }
            };
            log.push_str(&format!(
                "  - {}   (причина: {})   {}   {}\n",
                h, reason, kind, action
            ));
        }
        if !parent_suggestions.is_empty() {
            parent_suggestions.sort();
            log.push_str(&format!(
                "  💡 Родительские домены (winws матчит поддомены, можно сократить список): {}\n",
                parent_suggestions.join(", ")
            ));
        }
    }
    log.push('\n');

    // === Домены сайта, уже внесённые в обход ===
    let is_builtin = |p: &PathBuf| -> bool {
        p.to_string_lossy().replace("\\", "/").contains("default-bypass/")
    };
    log.push_str("🗑️ ДОМЕНЫ САЙТА, УЖЕ ВНЕСЁННЫЕ В ОБХОД (проверьте, не ломают ли они сайт):\n");
    if bypass_matches.is_empty() {
        log.push_str("  - (пусто) ни один домен сайта не найден в списках обхода\n");
    } else {
        for (domain, files) in &bypass_matches {
            let also_broken = broken_set.contains(domain);
            let mut labels: Vec<String> = Vec::new();
            for f in files {
                let path = f.to_string_lossy().replace("\\", "/");
                if is_builtin(f) {
                    labels.push(format!("встроенный список {}", path));
                } else {
                    labels.push(format!("список обхода {}", path));
                }
            }
            if also_broken {
                // Совет удалить — ТОЛЬКО если домен реально ломается обходом
                log.push_str(&format!(
                    "  - {}   (в {} — ЛОМАЕТ САЙТ, удалите из обхода в приоритете!)\n",
                    domain, labels.join(", ")
                ));
            } else if is_builtin(files.first().unwrap()) {
                log.push_str(&format!(
                    "  - {}   (в {} — встроенный, перезаписывается при запуске; работает, трогать не обязательно)\n",
                    domain, labels.join(", ")
                ));
            } else {
                log.push_str(&format!(
                    "  - {}   (в {} — работает, трогать не обязательно)\n",
                    domain, labels.join(", ")
                ));
            }
        }
    }
    log.push('\n');

    if !dns_fail.is_empty() {
        log.push_str("⚠️ ВОЗМОЖНО ЗАБЛОКИРОВАНЫ НА УРОВНЕ РФ (ошибка DNS):\n");
        for h in &dns_fail {
            log.push_str(&format!("  - {}\n", h));
        }
        log.push('\n');
    }

    log.push_str(&format!("✅ Доступные (не требуют исключений): {}\n\n", ok.len()));

    log.push_str("📋 Полный список обнаруженных доменов:\n");
    if discovered.is_empty() {
        log.push_str("  - (не удалось обнаружить ни одного домена — возможно, сайт недоступен целиком)\n");
    } else {
        for h in &discovered {
            log.push_str(&format!("  - {}\n", h));
        }
    }

    log.push_str("\n💡 СОВЕТ: домены из списка ❌ (помеченные «добавьте в исключения») внесите в список исключений (кнопка открытия списка исключений на другой вкладке). Домены из списка 🗑️ удаляйте из обхода только если они помечены «ЛОМАЕТ САЙТ».");

    Ok(log)
}
