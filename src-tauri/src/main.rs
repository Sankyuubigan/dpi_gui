#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod process;
mod analyzer;
mod testing;
mod bypass_lists;
mod diagnostics;
mod diagnostics_probe;
mod diagnostics_techniques;
mod diagnostics_report;

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

// Оборачиваем долгие команды в асинхронные таски, чтобы не вешать UI-поток
#[tauri::command]
async fn run_domain_analysis(url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        analyzer::analyze_url(&url)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn test_profile(app: AppHandle, profile_name: String, url: String, game_filter: bool) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_single_profile(app, &profile_name, &url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn test_dns(url: String, dns_ip: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_dns(&url, &dns_ip)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn run_diagnostics(app: AppHandle, url: String, game_filter: bool) -> Result<diagnostics::DiagnosticsReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        diagnostics::run_diagnostics(app, url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
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
            run_diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}