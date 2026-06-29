use std::process::Command;
use std::env;
use std::path::PathBuf;
use sysinfo::System;
use crate::config;

const WINWS_EXE: &str = "winws.exe";

pub fn get_bin_dir() -> PathBuf {
    // Ищем bin рядом с экзешником (релиз) или в текущей директории (дев)
    if let Ok(mut path) = env::current_exe() {
        path.pop(); // убираем .exe
        path.push("bin");
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("bin")
}

pub fn start_winws(profile_name: &str, game_filter: bool) -> Result<String, String> {
    let profiles = config::read_profiles().map_err(|e| e.to_string())?;
    
    let profile = profiles.iter().find(|p| p["name"] == profile_name)
        .ok_or("Профиль не найден")?;
        
    let args_template = profile["args"].as_str().unwrap_or("");
    
    let app_dir = config::get_app_dir();
    let lists_dir = app_dir.join("lists").to_string_lossy().replace("\\", "/");
    let bin_dir = get_bin_dir().to_string_lossy().replace("\\", "/");
    let game_ports = if game_filter { "1024-65535" } else { "12" };

    // Форматируем строку (заменяем плейсхолдеры)
    let raw_args = args_template
        .replace("{LISTS_DIR}", &lists_dir)
        .replace("{BIN_DIR}", &bin_dir)
        .replace("{EXCLUDE_DIR}", &lists_dir)
        .replace("{GAME_FILTER}", game_ports);

    // Парсим аргументы через shlex, чтобы не ломались пути с пробелами в кавычках (как в python)
    let parsed_args = match shlex::split(&raw_args) {
        Some(a) => a,
        None => return Err("Ошибка парсинга аргументов. Проверьте правильность кавычек в профиле.".to_string()),
    };

    let mut final_args = Vec::new();
    
    for arg in parsed_args {
        // Мы жестко вырезаем логику IPSet, чтобы не мусорить и не зависеть от лишних файлов
        if arg.starts_with("--ipset=") || arg.starts_with("--ipset-exclude=") {
            continue;
        }
        final_args.push(arg);
    }

    let winws_path = get_bin_dir().join(WINWS_EXE);

    if !winws_path.exists() {
        return Err(format!("Файл не найден: {}", winws_path.display()));
    }

    // Убиваем старый процесс перед запуском нового
    let _ = stop_winws();

    match Command::new(&winws_path)
        .args(&final_args)
        .current_dir(get_bin_dir())
        .spawn() {
            Ok(child) => Ok(format!("Запущено успешно. PID: {}", child.id())),
            Err(e) => Err(format!("Ошибка запуска: {}", e))
        }
}

pub fn stop_winws() -> Result<String, String> {
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", WINWS_EXE])
        .output();
        
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "WinDivert.exe"]) // На всякий случай
        .output();

    Ok("Процессы остановлены".to_string())
}

pub fn is_winws_running() -> bool {
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    for (_, process) in sys.processes() {
        if process.name().to_string_lossy().to_lowercase().contains("winws") {
            return true;
        }
    }
    false
}