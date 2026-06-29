#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod process;
mod analyzer;
mod testing;

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
fn start_bypass(profile_name: String, game_filter: bool) -> Result<String, String> {
    process::start_winws(&profile_name, game_filter).map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_bypass() -> Result<String, String> {
    process::stop_winws().map_err(|e| e.to_string())
}

#[tauri::command]
fn check_status() -> bool {
    process::is_winws_running()
}

#[tauri::command]
fn run_deep_analysis(url: String) -> Result<String, String> {
    analyzer::analyze_url(&url).map_err(|e| e.to_string())
}

#[tauri::command]
fn test_profile(profile_name: String, url: String, game_filter: bool) -> Result<String, String> {
    testing::test_single_profile(&profile_name, &url, game_filter).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            init_app,
            get_config,
            save_config,
            get_profiles,
            open_file,
            start_bypass,
            stop_bypass,
            check_status,
            run_deep_analysis,
            test_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}