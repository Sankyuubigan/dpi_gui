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

// РЎРєСЂС‹РІР°РµС‚ РљРћРќРЎРћР›Р¬РќР«Р• РѕРєРЅР°, РєРѕС‚РѕСЂС‹Рµ РїРѕСЂРѕР¶РґР°РµС‚ headless Chrome РЅР° Windows.
// headless_chrome СЃС‚Р°РІРёС‚ CREATE_NO_WINDOW РіР»Р°РІРЅРѕРјСѓ РїСЂРѕС†РµСЃСЃСѓ, РЅРѕ Chrome СЃР°Рј РІРЅСѓС‚СЂРё
// СЃРїР°РІРЅРёС‚ РґРѕС‡РµСЂРЅРёРµ РїСЂРѕС†РµСЃСЃС‹ (renderer/GPU/crashpad) Р±РµР· СЌС‚РѕРіРѕ С„Р»Р°РіР°, Рё Сѓ РЅРёС…
// РїРѕСЏРІР»СЏРµС‚СЃСЏ С‡С‘СЂРЅРѕРµ РєРѕРЅСЃРѕР»СЊРЅРѕРµ РѕРєРЅРѕ. РџРµСЂРµР±РёСЂР°РµРј РѕРєРЅР° РЅР°РїСЂСЏРјСѓСЋ С‡РµСЂРµР· Win32 API
// (Р±С‹СЃС‚СЂРѕ, Р±РµР· С‚СЏР¶С‘Р»РѕРіРѕ РѕРїСЂРѕСЃР° РїСЂРѕС†РµСЃСЃРѕРІ) Рё РїСЂСЏС‡РµРј РёРјРµРЅРЅРѕ РєРѕРЅСЃРѕР»СЊРЅС‹Рµ РѕРєРЅР° Chrome,
// РЅРµ С‚СЂРѕРіР°СЏ СЂРµР°Р»СЊРЅС‹Р№ Р±СЂР°СѓР·РµСЂ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ (Сѓ РЅРµРіРѕ РѕРєРЅР° РєР»Р°СЃСЃР° Chrome_WidgetWin_*).
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

        // РќРµ С‚СЂРѕРіР°РµРј РѕРєРЅР° СѓР¶Рµ Р·Р°РїСѓС‰РµРЅРЅРѕРіРѕ Р±СЂР°СѓР·РµСЂР° РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ (РµРіРѕ РІРєР»Р°РґРєРё).
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if ctx.known.lock().unwrap().contains(&pid) {
            return TRUE;
        }

        // РџСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ РѕРєРЅРѕ РїСЂРёРЅР°РґР»РµР¶РёС‚ chrome.exe. РСЃРїРѕР»СЊР·СѓРµРј С‚РѕР»СЊРєРѕ
        // PROCESS_QUERY_INFORMATION вЂ” PROCESS_VM_READ РјРѕР¶РµС‚ РЅРµ РїСЂРѕР№С‚Рё РґР»СЏ
        // РґРѕС‡РµСЂРЅРёС… РїСЂРѕС†РµСЃСЃРѕРІ Chrome (crashpad-handler Рё С‚.Рї.), Рё С‚РѕРіРґР° РѕРєРЅРѕ
        // РѕСЃС‚Р°РЅРµС‚СЃСЏ РІРёРґРёРјС‹Рј.
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
            // РџСЂСЏС‡РµРј Р›Р®Р‘РћР• РѕРєРЅРѕ РґРѕС‡РµСЂРЅРµРіРѕ РїСЂРѕС†РµСЃСЃР° Chrome (РІ С‚.С‡. С‡С‘СЂРЅСѓСЋ
            // РєРѕРЅСЃРѕР»СЊ), С‡С‚РѕР±С‹ СЋР·РµСЂ РЅРµ РІРёРґРµР» РЅРё РјРіРЅРѕРІРµРЅРЅРѕРіРѕ РјРµР»СЊРєР°РЅРёСЏ.
            ShowWindow(hwnd, SW_HIDE);
        }

        TRUE
    }

    // РћРґРёРЅ Р±С‹СЃС‚СЂС‹Р№ РїСЂРѕС…РѕРґ: РїСЂСЏС‡РµС‚ РІСЃРµ РєРѕРЅСЃРѕР»СЊРЅС‹Рµ РѕРєРЅР° Chrome, РєСЂРѕРјРµ РёР·РІРµСЃС‚РЅС‹С… PID СЋР·РµСЂР°.
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

// РџР°СЂСЃРёРЅРі Р·РЅР°С‡РµРЅРёСЏ РёР· РѕС‚Р»Р°РґРѕС‡РЅРѕР№ СЃС‚СЂРѕРєРё СЃРѕР±С‹С‚РёСЏ CDP.
// РС‰РµРј ` key: "..."` (РЎ Р’Р•Р”РЈР©РРњ РџР РћР‘Р•Р›РћРњ), С‡С‚РѕР±С‹ РЅРµ РїРµСЂРµРїСѓС‚Р°С‚СЊ document_url СЃ СЂРµР°Р»СЊРЅС‹Рј request.url.
// Р‘РµР· РІРµРґСѓС‰РµРіРѕ РїСЂРѕР±РµР»Р° РїРѕРґСЃС‚СЂРѕРєР° "url: " СЃРѕРІРїР°РґР°РµС‚ СЃ "document_url: " вЂ” Рё С‚РѕРіРґР° РІСЃРµ
// РїРѕРґ-СЂРµСЃСѓСЂСЃС‹ (CDN/API/СЃРєСЂРёРїС‚С‹) Р·Р°РїРёСЃС‹РІР°Р»РёСЃСЊ Р±С‹ РєР°Рє РіР»Р°РІРЅС‹Р№ РґРѕРјРµРЅ СЃС‚СЂР°РЅРёС†С‹.
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

    // РСЃРїРѕР»СЊР·СѓРµРј РќРћР’Р«Р™ headless-СЂРµР¶РёРј (--headless=new). Р’ РѕС‚Р»РёС‡РёРµ РѕС‚ СЃС‚Р°СЂРѕРіРѕ
    // --headless, РІ РЅРѕРІРѕРј СЂРµР¶РёРјРµ Chrome РЅРµ СЃРїР°РІРЅРёС‚ РѕС‚РґРµР»СЊРЅС‹Рµ РєРѕРЅСЃРѕР»СЊРЅС‹Рµ РґРѕС‡РµСЂРЅРёРµ
    // РїСЂРѕС†РµСЃСЃС‹ (renderer/GPU/crashpad), РїРѕСЌС‚РѕРјСѓ С‡С‘СЂРЅРѕРµ РєРѕРЅСЃРѕР»СЊРЅРѕРµ РѕРєРЅРѕ РІРѕРѕР±С‰Рµ
    // РЅРµ РїРѕСЏРІР»СЏРµС‚СЃСЏ. headless_chrome СЃР°Рј РґРѕР±Р°РІР»СЏРµС‚ СЃС‚Р°СЂС‹Р№ --headless, РїРѕСЌС‚РѕРјСѓ
    // СЃС‚Р°РІРёРј headless=false Рё РїРµСЂРµРґР°С‘Рј --headless=new СЏРІРЅРѕ С‡РµСЂРµР· args.
    let options = LaunchOptions::default_builder()
        .headless(false)
        .args(vec![std::ffi::OsStr::new("--headless=new")])
        .build()
        .map_err(|e| format!("РћС€РёР±РєР° РѕРїС†РёР№ Р·Р°РїСѓСЃРєР° Chrome: {}", e))?;

    // Р—Р°РїРѕРјРёРЅР°РµРј СѓР¶Рµ Р·Р°РїСѓС‰РµРЅРЅС‹Рµ chrome-С‹ (СЃРІРѕРё РІРєР»Р°РґРєРё СЋР·РµСЂР°), С‡С‚РѕР±С‹ РЅРµ С‚СЂРѕРіР°С‚СЊ РёС… РѕРєРЅР°.
    let known_chrome: Arc<Mutex<HashSet<u32>>> =
        Arc::new(Mutex::new(chrome_pids().into_iter().collect()));

    // Р¤РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє РЎРљР Р«РўРРЇ РѕРєРѕРЅ. Р—Р°РїСѓСЃРєР°РµРј Р•Р“Рћ Р”Рћ СЃС‚Р°СЂС‚Р° Chrome, РёРЅР°С‡Рµ РєРѕРЅСЃРѕР»СЊРЅС‹Рµ
    // РѕРєРЅР° РґРѕС‡РµСЂРЅРёС… РїСЂРѕС†РµСЃСЃРѕРІ Chrome (renderer/GPU/crashpad) СѓСЃРїРµРІР°СЋС‚ РЅР°СЂРёСЃРѕРІР°С‚СЊСЃСЏ
    // РІРѕ РІСЂРµРјСЏ Browser::new Рё РјРµР»СЊРєР°СЋС‚ РїРµСЂРµРґ СЋР·РµСЂРѕРј. РџСЂСЏС‡РµРј РёС… РїРѕ PID РІ СЂРµР°Р»СЊРЅРѕРј РІСЂРµРјРµРЅРё.
    #[cfg(windows)]
    let hide_stop = Arc::new(AtomicBool::new(false));
    #[cfg(windows)]
    let hide_handle = {
        let known = known_chrome.clone();
        let stop = hide_stop.clone();
        // Р‘С‹СЃС‚СЂС‹Р№ С†РёРєР»: РїСЂСЏС‡РµРј РєРѕРЅСЃРѕР»СЊРЅС‹Рµ РѕРєРЅР° Chrome РєР°Р¶РґС‹Рµ ~10 РјСЃ, РЅР°С‡РёРЅР°СЏ Р”Рћ
        // СЃС‚Р°СЂС‚Р° Р±СЂР°СѓР·РµСЂР°, С‡С‚РѕР±С‹ СЋР·РµСЂ РЅРµ РІРёРґРµР» РґР°Р¶Рµ РјРіРЅРѕРІРµРЅРЅРѕРіРѕ РјРµР»СЊРєР°РЅРёСЏ.
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                win_hide::hide_chrome_consoles(&known);
                thread::sleep(Duration::from_millis(10));
            }
        })
    };

    let browser = Browser::new(options).map_err(|e| format!("РћС€РёР±РєР° Р·Р°РїСѓСЃРєР° Chrome (СѓСЃС‚Р°РЅРѕРІР»РµРЅ Р»Рё РѕРЅ?): {}", e))?;
    let tab = browser.new_tab().map_err(|e| format!("РћС€РёР±РєР° СЃРѕР·РґР°РЅРёСЏ РІРєР»Р°РґРєРё: {}", e))?;

    // Р’РђР–РќРћ: Р±РµР· СЏРІРЅРѕРіРѕ РІРєР»СЋС‡РµРЅРёСЏ Network-РґРѕРјРµРЅР° СЃРѕР±С‹С‚РёСЏ RequestWillBeSent/LoadingFailed
    // РІРѕРѕР±С‰Рµ РЅРµ РїСЂРёС…РѕРґСЏС‚ (navigate_to РёС… РЅРµ РІРєР»СЋС‡Р°РµС‚).
    let _ = tab.call_method(Network::Enable {
        max_total_buffer_size: None,
        max_resource_buffer_size: None,
        max_post_data_size: None,
        report_direct_socket_traffic: None,
        enable_durable_messages: None,
    });

    // Р’СЃРµ РґРѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ СЃР°Р№С‚ СЂРµР°Р»СЊРЅРѕ Р·Р°РїСЂР°С€РёРІР°РµС‚ (РІРєР»СЋС‡Р°СЏ РїРѕРґ-СЂРµСЃСѓСЂСЃС‹: CDN, API, СЃРєСЂРёРїС‚С‹, С€СЂРёС„С‚С‹)
    let discovered_domains: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    // request_id -> url, С‡С‚РѕР±С‹ РїРѕ СЃРѕР±С‹С‚РёСЋ РѕС€РёР±РєРё РїРѕРЅСЏС‚СЊ, РєР°РєРѕР№ РґРѕРјРµРЅ СЃР»РѕРјР°Р»СЃСЏ
    let request_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    // Р”РѕРјРµРЅС‹, СѓРїР°РІС€РёРµ РїСЂСЏРјРѕ РІ Р±СЂР°СѓР·РµСЂРµ (РѕР±СЂС‹РІ СЃРѕРµРґРёРЅРµРЅРёСЏ)
    let browser_failed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // РЎС‡С‘С‚С‡РёРє С‡РёСЃР»Р° Р·Р°РїСЂРѕСЃРѕРІ вЂ” СЂР°СЃС‚С‘С‚ РїСЂРё РєР°Р¶РґРѕРј РЅРѕРІРѕРј RequestWillBeSent.
    // РџРѕ РµРіРѕ В«Р·Р°РјРёСЂР°РЅРёСЋВ» РѕРїСЂРµРґРµР»СЏРµРј network-idle (СЃС‚СЂР°РЅРёС†Р° РґРѕРіСЂСѓР·РёР»Р°СЃСЊ).
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
            // РќР°СЃ РёРЅС‚РµСЂРµСЃСѓСЋС‚ С‚РѕР»СЊРєРѕ СЂРµР°Р»СЊРЅС‹Рµ РѕР±СЂС‹РІС‹ СЃРѕРµРґРёРЅРµРЅРёСЏ (С‚Рѕ, С‡С‚Рѕ Р»РѕРјР°РµС‚ РѕР±С…РѕРґ)
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

    // РЈРЅРёРІРµСЂСЃР°Р»СЊРЅРѕРµ РѕР¶РёРґР°РЅРёРµ РїРѕ В«network idleВ»: Р¶РґС‘Рј, РїРѕРєР° РЅРѕРІС‹Рµ Р·Р°РїСЂРѕСЃС‹ РїРµСЂРµСЃС‚Р°РЅСѓС‚
    // РїРѕСЏРІР»СЏС‚СЊСЃСЏ (РѕРєРЅРѕ С‚РёС€РёРЅС‹ IDLE_WINDOW), СЃ РѕР±С‰РёРј РїРѕС‚РѕР»РєРѕРј MAX_WAIT. Р­С‚Рѕ Р»РѕРІРёС‚
    // РїРѕР·РґРЅРёРµ РґРѕРјРµРЅС‹ SPA / lazy-load / СЂРµРґРёСЂРµРєС‚РѕРІ РґР»СЏ Р»СЋР±РѕРіРѕ СЃР°Р№С‚Р°, Р° РЅРµ С„РёРєСЃРёСЂРѕРІР°РЅРЅС‹Рµ 15 СЃ.
    // РЎРєСЂС‹С‚РёРµ РѕРєРѕРЅ/РєРѕРЅСЃРѕР»РµР№ Chrome РІС‹РїРѕР»РЅСЏРµС‚ С„РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє (Р·Р°РїСѓС‰РµРЅ РґРѕ СЃС‚Р°СЂС‚Р° Р±СЂР°СѓР·РµСЂР°).
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

    // РћСЃС‚Р°РЅР°РІР»РёРІР°РµРј С„РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє СЃРєСЂС‹С‚РёСЏ РѕРєРѕРЅ.
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
            Probe::Broken(_) => Some(h.clone()),
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
        for (h, p) in results_off {
            match p {
                Probe::Broken(_) => {
                    broken_off.insert(h);
                }
                Probe::Dns => {
                    dns_off.insert(h);
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

        analyzer_probe::classify_dual(results_on, &broken_off, &dns_off, &browser_failed_set)
    } else {
        // Обход был выключен изначально (или обрывов нет) — одиночная классификация.
        analyzer_probe::classify_single(results_on, &browser_failed_set)
    };

    let meta = ReportMeta {
        target_url,
        discovered,
        bypass_on,
        bypass_toggled,
        restore_note,
        had_browser_failures,
        main_probe: Some(main_probe),
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

