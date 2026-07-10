use std::process::{Command, Stdio};
use std::os::windows::process::CommandExt;
use std::env;
use std::path::PathBuf;
use std::io::{BufRead, BufReader};
use std::thread;
use sysinfo::System;
use tauri::{AppHandle, Emitter};
use crate::config;

const WINWS_EXE: &str = "winws.exe";
// Флаг для скрытия окна консоли в Windows
const CREATE_NO_WINDOW: u32 = 0x08000000;

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

/// Строит итоговый список аргументов winws из шаблона (с плейсхолдерами).
/// Вынесено отдельно, чтобы переиспользоваться и для запуска по имени профиля,
/// и для запуска произвольного шаблона (диагностика).
fn resolve_args(app: &AppHandle, raw_args_template: &str, game_filter: bool) -> Result<Vec<String>, String> {
    let app_dir = config::get_app_dir();
    let lists_dir = app_dir.join("lists").to_string_lossy().replace("\\", "/");
    let bin_dir = get_bin_dir().to_string_lossy().replace("\\", "/");
    let game_ports = if game_filter { "1024-65535" } else { "12" };

    let raw_args = raw_args_template
        .replace("{LISTS_DIR}", &lists_dir)
        .replace("{BIN_DIR}", &bin_dir)
        .replace("{EXCLUDE_DIR}", &lists_dir)
        .replace("{GAME_FILTER}", game_ports);

    let parsed_args = match shlex::split(&raw_args) {
        Some(a) => a,
        None => return Err("Ошибка парсинга аргументов. Проверьте правильность кавычек в профиле.".to_string()),
    };

    let mut final_args = Vec::new();
    let default_exclude_arg = format!("--hostlist-exclude={}/default-exclude.txt", lists_dir);
    let default_bypass_general_arg = format!("--hostlist={}/default-bypass/list-general.txt", lists_dir);
    let default_bypass_google_arg = format!("--hostlist={}/default-bypass/list-google.txt", lists_dir);

    for arg in parsed_args {
        // Мы жестко вырезаем логику IPSet, чтобы не зависеть от лишних файлов
        if arg.starts_with("--ipset=") || arg.starts_with("--ipset-exclude=") {
            let _ = app.emit("log", format!("[ПРОПУСК АРГУМЕНТА] {}", arg));
            continue;
        }
        final_args.push(arg.clone());
        // После каждого --hostlist-exclude пользователя добавляем дефолтный список исключений
        if arg.starts_with("--hostlist-exclude=") && arg.contains("list-exclude.txt") {
            final_args.push(default_exclude_arg.clone());
        }
        // После каждого --hostlist пользователя добавляем дефолтные списки обхода
        if arg.starts_with("--hostlist=") {
            if arg.contains("list-general.txt") {
                final_args.push(default_bypass_general_arg.clone());
            } else if arg.contains("list-google.txt") {
                final_args.push(default_bypass_google_arg.clone());
            }
        }
    }

    let _ = app.emit("log", format!("Итоговые аргументы запуска ({} шт.)", final_args.len()));

    Ok(final_args)
}

/// Собственно запуск winws с готовым списком аргументов.
fn spawn_winws(app: &AppHandle, final_args: Vec<String>) -> Result<String, String> {
    let winws_path = get_bin_dir().join(WINWS_EXE);

    if !winws_path.exists() {
        return Err(format!("Файл не найден: {}", winws_path.display()));
    }

    // Убиваем старый процесс перед запуском нового
    let _ = stop_winws();
    let _ = app.emit("log", "Старые процессы остановлены. Запускаем новый...".to_string());

    let mut child = Command::new(&winws_path)
        .args(&final_args)
        .current_dir(get_bin_dir())
        .creation_flags(CREATE_NO_WINDOW) // Не показывать консоль!
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Ошибка запуска: {}", e))?;

    let pid = child.id();
    let _ = app.emit("log", format!("Процесс запущен успешно. PID: {}", pid));

    // Перехват stdout
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let app_clone = app.clone();
    if let Some(out) = stdout {
        thread::spawn(move || {
            let reader = BufReader::new(out);
            for line in reader.lines().flatten() {
                let _ = app_clone.emit("log", format!("[winws] {}", line));
            }
        });
    }

    // Перехват stderr
    let app_clone_err = app.clone();
    if let Some(err) = stderr {
        thread::spawn(move || {
            let reader = BufReader::new(err);
            for line in reader.lines().flatten() {
                let _ = app_clone_err.emit("log", format!("[winws ERROR] {}", line));
            }
        });
    }

    Ok(format!("Запущено успешно. PID: {}", pid))
}

pub fn start_winws(app: AppHandle, profile_name: &str, game_filter: bool) -> Result<String, String> {
    let profiles = config::read_profiles().map_err(|e| e.to_string())?;

    let profile = profiles.iter().find(|p| p["name"] == profile_name)
        .ok_or("Профиль не найден")?;

    let args_template = profile["args"].as_str().unwrap_or("");
    let final_args = resolve_args(&app, args_template, game_filter)?;
    spawn_winws(&app, final_args)
}

/// Запуск winws с произвольным шаблоном аргументов (используется диагностикой).
pub fn start_winws_custom(app: AppHandle, raw_args_template: &str, game_filter: bool) -> Result<String, String> {
    let final_args = resolve_args(&app, raw_args_template, game_filter)?;
    spawn_winws(&app, final_args)
}

pub fn stop_winws() -> Result<String, String> {
    // Останавливаем скрыто, без моргания окон консоли
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", WINWS_EXE])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "WinDivert.exe"]) // На всякий случай
        .creation_flags(CREATE_NO_WINDOW)
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
