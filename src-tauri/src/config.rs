use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use serde_json::json;

pub fn get_app_dir() -> PathBuf {
    // Тест/дев-оверрайд: вместо реального AppData — своя папка (sandbox для
    // юнит-тестов ensure_directories_and_files; в проде переменная не задана).
    if let Ok(custom) = std::env::var("DPI_GUI_APP_DIR") {
        if !custom.is_empty() {
            return PathBuf::from(custom);
        }
    }
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("DPI_GUI");
    path
}

/// Папка дефолтных списков в AppData: все четыре дефолта перезаписываются
/// сюда из встроенных исходников при каждом запуске (контракт владельца).
pub fn defaults_dir() -> PathBuf {
    get_app_dir().join("lists").join("defaults")
}

/// Путь к дефолтному файлу DoH-сервисов подмены DNS (lists/defaults/).
/// Файл перезаписывается при каждом запуске из src-tauri/defaults/, правки
/// вручную живут только до перезапуска.
pub fn doh_services_path() -> PathBuf {
    defaults_dir().join("doh-services.txt")
}

/// Результат чтения doh-services.txt. `hosts` — нормализованные хосты
/// (только имена, без схемы и пути), `warnings` — читаемые причины
/// проигнорированных строк (core rules §2.2: молчаливых ошибок нет).
#[derive(Debug, PartialEq)]
pub struct DohServicesRead {
    pub file_found: bool,
    pub hosts: Vec<String>,
    pub warnings: Vec<String>,
}

/// Парсинг текста doh-services.txt: по одному DoH-серверу на строку.
/// Допускается полный URL (`https://host/dns-query`) или только хост.
/// Пустые строки и `#` — комментарии. Валидный хост: ≥ 1 точка, символы
/// только `[a-z0-9.-]`. Дубли убираются с сохранением порядка.
/// Чистая функция — покрыта юнит-тестами.
pub fn parse_doh_services(text: &str) -> (Vec<String>, Vec<String>) {
    let mut hosts: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut host = line.to_lowercase();
        if host.starts_with("http://") {
            warnings.push(format!(
                "строка {}: «{}» — DoH-серверы работают только по https://, строка проигнорирована",
                line_no, raw.trim()
            ));
            continue;
        }
        if let Some(rest) = host.strip_prefix("https://") {
            host = rest.to_string();
        }
        // Хост = всё до первого слеша (путь, если указан, отбрасываем —
        // запрос всё равно выполняем по собственному пути /dns-query).
        if let Some(pos) = host.find('/') {
            host.truncate(pos);
        }
        let host = host.trim_end_matches('.').to_string();
        if host.is_empty() {
            warnings.push(format!("строка {}: «{}» — пустое имя хоста, строка проигнорирована", line_no, raw.trim()));
            continue;
        }
        let valid = host.contains('.')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !valid {
            warnings.push(format!(
                "строка {}: «{}» — не похоже на имя DoH-сервера (нужен хост вида dns.example.com), строка проигнорирована",
                line_no, raw.trim()
            ));
            continue;
        }
        if seen.insert(host.clone()) {
            hosts.push(host);
        }
    }

    (hosts, warnings)
}

/// Читает doh-services.txt. Файл не найден/нечитаем → hosts пуст, file_found=false
/// и warning с реальной причиной; решение о fallback принимает вызывающий код.
pub fn read_doh_services() -> DohServicesRead {
    let path = doh_services_path();
    match fs::read_to_string(&path) {
        Ok(text) => {
            let (hosts, warnings) = parse_doh_services(&text);
            DohServicesRead {
                file_found: true,
                hosts,
                warnings,
            }
        }
        Err(e) => DohServicesRead {
            file_found: false,
            hosts: Vec::new(),
            warnings: vec![format!(
                "не удалось прочитать список DoH-серверов {}: {}",
                path.display(),
                e
            )],
        },
    }
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

    // ДЕФОЛТНЫЕ СПИСКИ — единая папка lists/defaults/, жёсткая перезапись
    // из встроенных исходников при КАЖДОМ запуске (контракт владельца):
    // правки дефолтов сначала меняются в repo (src-tauri/defaults/) и едут
    // релизами ко всем юзерам; правки в AppData живут до перезапуска.
    let defaults_dir = defaults_dir();
    if !defaults_dir.exists() {
        fs::create_dir_all(&defaults_dir)?;
    }
    let default_files: &[(&str, &str)] = &[
        ("list-general.txt", include_str!("../defaults/list-general.txt")),
        ("list-google.txt", include_str!("../defaults/list-google.txt")),
        ("default-exclude.txt", include_str!("../defaults/default-exclude.txt")),
        ("doh-services.txt", include_str!("../defaults/doh-services.txt")),
    ];
    for (filename, content) in default_files {
        fs::write(defaults_dir.join(filename), content)?;
    }

    // Миграция со старых мест дефолтов (версии до папки defaults/):
    // удаляем best-effort, ошибки удаления не фатальны.
    let _ = fs::remove_file(lists_dir.join("default-exclude.txt"));
    let _ = fs::remove_file(lists_dir.join("doh-services.txt"));
    let _ = fs::remove_dir_all(lists_dir.join("default-bypass"));

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
        "doh_services" => defaults_dir().join("doh-services.txt"),
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unknown file type")),
    };

    Command::new("cmd")
        .args(["/C", "start", "", "notepad", path.to_str().unwrap()])
        .creation_flags(0x08000000)
        .spawn()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_url_and_bare_host() {
        // Полный URL и bare host одного сервера нормализуются к одному хосту
        // и схлопываются дедупом в единственную запись.
        let (hosts, warnings) =
            parse_doh_services("https://dns.dagami.ru/dns-query\nDns.Dagami.Ru\n");
        assert_eq!(hosts, vec!["dns.dagami.ru".to_string()]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let text = "\n# comment\n   \n  # с пробелом\nhttps://xbox-dns.ru/dns-query\n";
        let (hosts, warnings) = parse_doh_services(text);
        assert_eq!(hosts, vec!["xbox-dns.ru".to_string()]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn http_scheme_is_rejected_with_warning() {
        let (hosts, warnings) = parse_doh_services("http://dns.example.com/dns-query\n");
        assert!(hosts.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("https"));
    }

    #[test]
    fn garbage_line_produces_warning() {
        let (hosts, warnings) = parse_doh_services("https://not a host here\n");
        assert!(hosts.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("строка 1"));
    }

    #[test]
    fn path_and_trailing_dot_are_trimmed() {
        let (hosts, warnings) = parse_doh_services("https://geohide.ru/dns-query\nEu.Geohide.Ru.\n");
        assert_eq!(hosts, vec!["geohide.ru".to_string(), "eu.geohide.ru".to_string()]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn duplicates_kept_once_in_order() {
        let text = "a.example.ru\nb.example.ru\na.example.ru\n";
        let (hosts, warnings) = parse_doh_services(text);
        assert_eq!(hosts, vec!["a.example.ru".to_string(), "b.example.ru".to_string()]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn empty_text_yields_nothing() {
        let (hosts, warnings) = parse_doh_services("");
        assert!(hosts.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn default_embedded_file_parses_clean() {
        // Встроенный дефолт всегда обязан парситься без единого warning —
        // защита от опечаток при будущих правках defaults/doh-services.txt.
        let (hosts, warnings) = parse_doh_services(include_str!("../defaults/doh-services.txt"));
        assert!(warnings.is_empty(), "warnings: {:?}", warnings);
        assert_eq!(
            hosts,
            vec![
                "xbox-dns.ru",
                "geohide.ru",
                "eu.geohide.ru",
                "dns.comss.one",
                "dns.bezmezhau.com",
                "dns.dns-ai.ru",
                "dns.dagami.ru",
                "dns.magicdns.ru",
                "unfiltered.adguard-dns.com",
                "cloudflare-dns.com",
                "dns.google",
                "doh.sandbox.opendns.com",
                "doh.dns.sb",
                "dns10.quad9.net",
                "wikimedia-dns.org",
                "doh.libredns.gr",
                "unfiltered.joindns4.eu",
                "dns.digitale-gesellschaft.ch",
                "dns.decloudus.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ensure_writes_defaults_and_migrates_old_layout() {
        // Полный smoke-контракт ensure_directories_and_files на временной папке:
        // 1) lists/defaults/ получает все 4 дефолта (жёсткая перезапись);
        // 2) старые места дефолтов удаляются;
        // 3) юзерские списки в корне lists/ не трогаются.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("время системное")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dpi_gui_ensure_{}", unique));
        // Стартовая раскладка «до папки defaults/»:
        std::fs::create_dir_all(dir.join("lists").join("default-bypass"))
            .expect("создание старой раскладки");
        std::fs::write(dir.join("lists").join("default-exclude.txt"), "old.content\n")
            .expect("запись старого дефолта");
        std::fs::write(dir.join("lists").join("doh-services.txt"), "https://old.example/dns-query\n")
            .expect("запись старого doh");
        std::fs::write(dir.join("lists").join("default-bypass").join("list-google.txt"), "old\n")
            .expect("запись старого bypass");
        std::fs::write(dir.join("lists").join("list-general.txt"), "example.com\n")
            .expect("запись юзерского списка");

        std::env::set_var("DPI_GUI_APP_DIR", &dir);
        let ensured = ensure_directories_and_files();
        std::env::remove_var("DPI_GUI_APP_DIR");
        ensured.expect("ensure завершается без ошибок");

        let defaults = dir.join("lists").join("defaults");
        for (name, src) in [
            ("list-general.txt", include_str!("../defaults/list-general.txt")),
            ("list-google.txt", include_str!("../defaults/list-google.txt")),
            ("default-exclude.txt", include_str!("../defaults/default-exclude.txt")),
            ("doh-services.txt", include_str!("../defaults/doh-services.txt")),
        ] {
            let text = std::fs::read_to_string(defaults.join(name))
                .unwrap_or_else(|e| panic!("{} не создан: {}", name, e));
            assert_eq!(text, src, "{} обязан равняться встроенному дефолту", name);
        }

        assert!(!dir.join("lists").join("default-exclude.txt").exists(), "старый exclude удалён");
        assert!(!dir.join("lists").join("default-bypass").exists(), "старая папка bypass удалена");
        assert!(!dir.join("lists").join("doh-services.txt").exists(), "старый doh удалён");

        let user_list = std::fs::read_to_string(dir.join("lists").join("list-general.txt"))
            .expect("юзерский список на месте");
        assert_eq!(user_list, "example.com\n", "юзерские списки ensure не перезаписывает");

        let _ = std::fs::remove_dir_all(&dir);
    }
}