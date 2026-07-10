use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::config;

/// Домен (lowercase) -> список файлов обхода, в которых он встречается.
pub type BypassMap = HashMap<String, Vec<PathBuf>>;

/// Собирает ВСЕ эффективные списки обхода (hostlist), которые реально читает winws
/// для текущего состояния приложения, и возвращает карту "домен -> файлы".
///
/// Учитываются:
/// - `--hostlist=` файлы из аргументов активного профиля (пользовательские списки)
/// - встроенные списки `default-bypass/list-general.txt` и `default-bypass/list-google.txt`
///   (всегда подключаются в process.rs независимо от профиля)
///
/// Матчинг домена: точное совпадение либо суффикс (домен является субдоменом списка),
/// т.е. `sub.example.com` найдётся по записи `example.com`.
pub fn load_bypass_domains() -> BypassMap {
    let app_dir = config::get_app_dir();
    let lists_dir = app_dir.join("lists");

    let mut candidate_files: Vec<PathBuf> = Vec::new();

    // 1. --hostlist= файлы из активного профиля
    if let Ok(cfg) = config::read_config() {
        if let Some(selected) = cfg.get("selected_profile").and_then(|v| v.as_str()) {
            if !selected.is_empty() {
                if let Ok(profiles) = config::read_profiles() {
                    if let Some(profile) = profiles.iter().find(|p| p["name"] == selected) {
                        if let Some(args) = profile.get("args").and_then(|v| v.as_str()) {
                            if let Some(parsed) = shlex::split(args) {
                                for arg in parsed {
                                    if let Some(path) = arg.strip_prefix("--hostlist=") {
                                        // Аргументы профиля содержат плейсхолдеры ({LISTS_DIR} и т.п.)
                                        let resolved = path
                                            .replace("{LISTS_DIR}", &lists_dir.to_string_lossy())
                                            .replace("{EXCLUDE_DIR}", &lists_dir.to_string_lossy());
                                        candidate_files.push(PathBuf::from(resolved));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Встроенные списки обхода (всегда подключаются в process.rs)
    candidate_files.push(lists_dir.join("default-bypass").join("list-general.txt"));
    candidate_files.push(lists_dir.join("default-bypass").join("list-google.txt"));

    // Убираем дубли (если профиль ссылается на те же файлы)
    candidate_files.sort();
    candidate_files.dedup();

    let mut map: BypassMap = HashMap::new();

    for file in candidate_files {
        let content = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue, // файла нет — пропускаем
        };
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let domain = line.to_lowercase();
            map.entry(domain).or_default().push(file.clone());
        }
    }

    map
}

/// Собирает домены из пользовательского и встроенного списков ИСКЛЮЧЕНИЙ
/// (list-exclude.txt и default-exclude.txt). Используется, чтобы не советовать
/// добавлять в исключения то, что юзер уже и так исключил.
pub fn load_exclude_domains() -> HashSet<String> {
    let lists_dir = config::get_app_dir().join("lists");
    let files = [
        lists_dir.join("list-exclude.txt"),
        lists_dir.join("default-exclude.txt"),
    ];
    let mut set = HashSet::new();
    for file in files {
        if let Ok(content) = fs::read_to_string(&file) {
            for raw in content.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                set.insert(line.to_lowercase());
            }
        }
    }
    set
}

/// Проверяет, покрыт ли домен какой-либо записью списка исключений
/// (точное совпадение либо домен — субдомен записи). Возвращает саму запись.
pub fn is_excluded(host: &str, excludes: &HashSet<String>) -> Option<String> {
    let host_lc = host.to_lowercase();
    for entry in excludes {
        if &host_lc == entry || host_lc.ends_with(&format!(".{}", entry)) {
            return Some(entry.clone());
        }
    }
    None
}

/// Возвращает родительский домен (последние 2 метки), например
/// `sdk.rum.aliyuncs.com` -> `aliyuncs.com`. Для домена из одной метки вернёт его как есть.
pub fn parent_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 2 {
        host.to_lowercase()
    } else {
        parts[parts.len() - 2..].join(".").to_lowercase()
    }
}

/// Проверяет, внесён ли обнаруженный домен в какой-либо список обхода.
/// Учитывает как точное совпадение, так и субдомены (суффикс).
pub fn find_bypass_matches(discovered: &[String], bypass: &BypassMap) -> Vec<(String, Vec<PathBuf>)> {
    let mut matches: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for host in discovered {
        let host_lc = host.to_lowercase();
        let mut sources: Vec<PathBuf> = Vec::new();
        for (listed, files) in bypass {
            let exact = host_lc == *listed;
            let suffix = host_lc.ends_with(&format!(".{}", listed));
            if exact || suffix {
                for f in files {
                    if !sources.contains(f) {
                        sources.push(f.clone());
                    }
                }
            }
        }
        if !sources.is_empty() {
            matches.push((host.clone(), sources));
        }
    }
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches
}
