use crate::process;
use std::thread;
use std::time::Duration;
use reqwest::blocking::Client;
use tauri::AppHandle;

pub fn test_single_profile(app: AppHandle, profile_name: &str, url: &str, game_filter: bool) -> Result<String, String> {
    let target_url = if !url.starts_with("http") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    // Запускаем
    if let Err(e) = process::start_winws(app.clone(), profile_name, game_filter) {
        return Err(format!("Ошибка запуска {}: {}", profile_name, e));
    }

    // Даем WinDivert время на перехват трафика
    thread::sleep(Duration::from_secs(3));

    // Проверяем доступность
    let client = Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();

    let result = match client.get(&target_url).send() {
        Ok(res) if res.status().is_success() => Ok("УСПЕХ (200 OK)".to_string()),
        Ok(res) => Ok(format!("Доступно, но статус: {}", res.status())),
        Err(e) => Ok(format!("Неудача: {}", e))
    };

    // Останавливаем
    let _ = process::stop_winws();
    thread::sleep(Duration::from_secs(1));

    result
}