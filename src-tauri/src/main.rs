#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod process;
mod analyzer;
mod analyzer_probe;
mod analyzer_report;
mod site_probe;
mod testing;
mod bypass_lists;
mod diagnostics;
mod diagnostics_probe;
mod diagnostics_techniques;
mod diagnostics_report;
mod hosts;

use tauri::AppHandle;

#[tauri::command]
fn init_app() -> Result<(), String> {
    config::ensure_directories_and_files().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config() -> Result<serde_json::Value, String> {
    config::read_config().map_err(|e| e.to_string())
}

#[tauri::command]
fn save_config(config: serde_json::Value) -> Result<(), String> {
    config::write_config(&config).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_profiles() -> Result<Vec<serde_json::Value>, String> {
    config::read_profiles().map_err(|e| e.to_string())
}

#[tauri::command]
fn open_file(file_type: String) -> Result<(), String> {
    config::open_file_in_editor(&file_type).map_err(|e| e.to_string())
}

#[tauri::command]
fn start_bypass(app: AppHandle, profile_name: String, game_filter: bool) -> Result<String, String> {
    process::start_winws(app, &profile_name, game_filter).map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_bypass() -> Result<String, String> {
    process::stop_winws().map_err(|e| e.to_string())
}

#[tauri::command]
fn check_status() -> bool {
    process::is_winws_running()
}

// РћР±РѕСЂР°С‡РёРІР°РµРј РґРѕР»РіРёРµ РєРѕРјР°РЅРґС‹ РІ Р°СЃРёРЅС…СЂРѕРЅРЅС‹Рµ С‚Р°СЃРєРё, С‡С‚РѕР±С‹ РЅРµ РІРµС€Р°С‚СЊ UI-РїРѕС‚РѕРє
#[tauri::command]
async fn run_domain_analysis(app: AppHandle, url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        analyzer::analyze_url(&app, &url)
    }).await.unwrap_or_else(|e| Err(format!("РћС€РёР±РєР° РїРѕС‚РѕРєР°: {}", e)))
}

#[tauri::command]
async fn test_profile(app: AppHandle, profile_name: String, url: String, game_filter: bool) -> Result<testing::ProfileTestOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_single_profile(app, &profile_name, &url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("РћС€РёР±РєР° РїРѕС‚РѕРєР°: {}", e)))
}

#[tauri::command]
async fn test_dns(url: String, dns_ip: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_dns(&url, &dns_ip)
    }).await.unwrap_or_else(|e| Err(format!("РћС€РёР±РєР° РїРѕС‚РѕРєР°: {}", e)))
}

#[tauri::command]
async fn run_diagnostics(app: AppHandle, url: String, game_filter: bool) -> Result<diagnostics::DiagnosticsReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        diagnostics::run_diagnostics(app, url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("РћС€РёР±РєР° РїРѕС‚РѕРєР°: {}", e)))
}

#[tauri::command]
fn apply_hosts_entry(ip: String, domain: String) -> Result<String, String> {
    hosts::apply_hosts_entry(&ip, &domain)
}

#[tauri::command]
fn remove_hosts_entry(domain: String) -> Result<String, String> {
    hosts::remove_hosts_entry(&domain)
}

#[tauri::command]
fn read_hosts() -> Result<String, String> {
    hosts::read_hosts()
}

/// РђРІС‚Рѕ-РїСЂРѕРІРµСЂРєР° РїРѕСЃР»Рµ Р·Р°РїРёСЃРё РІ hosts: СЂРµР°Р»СЊРЅРѕ Р»Рё СЃР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С‡РµСЂРµР· СЌС‚РѕС‚ IP.
#[tauri::command]
fn verify_site_via_ip(host: String, ip: String) -> Result<String, String> {
    use std::net::IpAddr;
    use std::str::FromStr;
    let ip = IpAddr::from_str(ip.trim())
        .map_err(|_| format!("В«{}В» вЂ” РЅРµ РїРѕС…РѕР¶Рµ РЅР° IP-Р°РґСЂРµСЃ", ip))?;
    let host = hosts::normalize_domain_public(&host)?;
    match site_probe::probe_https_by_ip(&host, ip) {
        crate::diagnostics_probe::HttpResult::Ok(code) => {
            Ok(format!("вњ… РЎР°Р№С‚ {} РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С‡РµСЂРµР· {} (HTTP {})", host, ip, code))
        }
        crate::diagnostics_probe::HttpResult::BlockPage => {
            Ok(format!("вљ пёЏ {} С‡РµСЂРµР· {} вЂ” СЃС‚СЂР°РЅРёС†Р° Р±Р»РѕРєРёСЂРѕРІРєРё (403/451/Р·Р°РіР»СѓС€РєР°)", ip, host))
        }
        crate::diagnostics_probe::HttpResult::Rst => {
            Ok(format!("рџљ« {} вЂ” HTTPS СЃР±СЂРѕС€РµРЅ (RST). Р‘Р»РѕРє РїРѕ SNI/IP: РїРѕРґРјРµРЅР° РІ hosts РЅРµ РїРѕРјРѕР¶РµС‚, РЅСѓР¶РµРЅ РѕР±С…РѕРґ (winws).", ip))
        }
        crate::diagnostics_probe::HttpResult::Tls => {
            Ok(format!("рџ”ђ {} вЂ” TLS-СЂСѓРєРѕРїРѕР¶Р°С‚РёРµ СЃР»РѕРјР°Р»РѕСЃСЊ", ip))
        }
        crate::diagnostics_probe::HttpResult::BadCert => {
            Ok(format!("вљ пёЏ {} вЂ” СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ РґР»СЏ {}", ip, host))
        }
        crate::diagnostics_probe::HttpResult::Timeout => {
            Ok(format!("вЏі {} вЂ” С‚Р°Р№РјР°СѓС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ", ip))
        }
        crate::diagnostics_probe::HttpResult::Dns => {
            Ok(format!("в„№пёЏ {} вЂ” DNS-РѕС€РёР±РєР°", ip))
        }
        crate::diagnostics_probe::HttpResult::Other(m) => {
            Ok(format!("в„№пёЏ {} вЂ” {}", ip, m))
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            init_app,
            get_config,
            save_config,
            get_profiles,
            open_file,
            start_bypass,
            stop_bypass,
            check_status,
            run_domain_analysis,
            test_profile,
            test_dns,
            run_diagnostics,
            apply_hosts_entry,
            remove_hosts_entry,
            read_hosts,
            verify_site_via_ip
        ])
        .on_window_event(|_window, event| {
            // РџСЂРё Р·Р°РєСЂС‹С‚РёРё РѕРєРЅР° РіР°СЃРёРј РѕР±С…РѕРґ Рё РІС‹РіСЂСѓР¶Р°РµРј РґСЂР°Р№РІРµСЂ WinDivert,
            // С‡С‚РѕР±С‹ РѕРЅ РЅРµ РѕСЃС‚Р°РІР°Р»СЃСЏ РІ РїР°РјСЏС‚Рё Рё РЅРµ Р±Р»РѕРєРёСЂРѕРІР°Р» С„Р°Р№Р»С‹ РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let _ = process::stop_winws();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}