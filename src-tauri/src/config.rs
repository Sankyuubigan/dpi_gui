use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use serde_json::json;

pub fn get_app_dir() -> PathBuf {
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("DPI_GUI");
    path
}

pub fn ensure_directories_and_files() -> Result<(), std::io::Error> {
    let app_dir = get_app_dir();
    let lists_dir = app_dir.join("lists");

    if !app_dir.exists() {
        fs::create_dir_all(&app_dir)?;
    }
    if !lists_dir.exists() {
        fs::create_dir_all(&lists_dir)?;
    }

    let config_path = app_dir.join("config.json");
    if !config_path.exists() {
        let default_config = json!({
            "selected_profile": "",
            "game_filter": false
        });
        fs::write(&config_path, serde_json::to_string_pretty(&default_config).unwrap())?;
    }

    // Генерация базовых списков. IPSet списки убраны за ненадобностью.
    let files_to_create = vec![
        ("list-general.txt", "# General domains to bypass\n"),
        ("list-google.txt", "# Google domains to bypass\n"),
        ("list-exclude.txt", "# Domains to EXCLUDE from bypass\n"),
    ];

    for (filename, content) in files_to_create {
        let file_path = lists_dir.join(filename);
        if !file_path.exists() {
            fs::write(&file_path, content)?;
        }
    }

    // Дефолтный список исключений — встроен в бинарник, перезаписывается при каждом запуске
    let default_exclude = include_str!("../default-exclude.txt");
    fs::write(lists_dir.join("default-exclude.txt"), default_exclude)?;

    // Дефолтные списки обхода — встроены в бинарник, перезаписываются при каждом запуске
    let default_bypass_dir = lists_dir.join("default-bypass");
    if !default_bypass_dir.exists() {
        fs::create_dir_all(&default_bypass_dir)?;
    }
    let default_bypass_files = vec![
        ("list-general.txt", include_str!("../default-bypass/list-general.txt")),
        ("list-google.txt", include_str!("../default-bypass/list-google.txt")),
    ];
    for (filename, content) in default_bypass_files {
        fs::write(default_bypass_dir.join(filename), content)?;
    }

    // Проверка и инициализация профилей вынесена в read_profiles() для надежности
    let _ = read_profiles(); 

    Ok(())
}

pub fn read_config() -> Result<serde_json::Value, std::io::Error> {
    let path = get_app_dir().join("config.json");
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data).unwrap_or(json!({})))
}

pub fn write_config(config: &serde_json::Value) -> Result<(), std::io::Error> {
    let path = get_app_dir().join("config.json");
    fs::write(path, serde_json::to_string_pretty(config).unwrap())
}

pub fn read_profiles() -> Result<Vec<serde_json::Value>, std::io::Error> {
    let path = get_app_dir().join("profiles.json");
    
    // Пытаемся прочесть текущий файл
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            // Защита от бага: если файл пустой массив - восстанавливаем
            if !parsed.is_empty() {
                return Ok(parsed);
            }
        }
    }
    
    // Если файла нет или он поврежден (пустой/невалидный), восстанавливаем из дефолтных
    let default_profiles_str = include_str!("../profiles_default.json");
    let parsed_profiles: Vec<serde_json::Value> = serde_json::from_str(default_profiles_str)
        .expect("Invalid default profiles JSON schema!");
        
    // Сохраняем восстановленный профиль
    let _ = fs::write(&path, serde_json::to_string_pretty(&parsed_profiles).unwrap());
    
    Ok(parsed_profiles)
}

/// Добавляет (или заменяет, если имя совпадает) профиль в profiles.json.
/// Используется диагностикой для сохранения авто-сгенерированного профиля.
pub fn append_profile(profile: serde_json::Value) -> Result<(), String> {
    let mut profiles = read_profiles().map_err(|e| e.to_string())?;

    let name = profile["name"].as_str().unwrap_or("");
    if let Some(idx) = profiles.iter().position(|p| p["name"] == name) {
        profiles[idx] = profile;
    } else {
        profiles.push(profile);
    }

    let path = get_app_dir().join("profiles.json");
    fs::write(&path, serde_json::to_string_pretty(&profiles).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn open_file_in_editor(file_type: &str) -> Result<(), std::io::Error> {
    let app_dir = get_app_dir();
    let path = match file_type {
        "list_general" => app_dir.join("lists").join("list-general.txt"),
        "list_exclude" => app_dir.join("lists").join("list-exclude.txt"),
        "profiles" => app_dir.join("profiles.json"),
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unknown file type")),
    };

    Command::new("cmd")
        .args(["/C", "start", "", "notepad", path.to_str().unwrap()])
        .creation_flags(0x08000000)
        .spawn()?;

    Ok(())
}