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
/// - встроенные списки `defaults/list-general.txt` и `defaults/list-google.txt`
///   (всегда подключаются в process.rs независимо от профиля, папка lists/defaults/)
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

    // 2. Встроенные списки обхода (всегда подключаются в process.rs; папка defaults/)
    candidate_files.push(config::defaults_dir().join("list-general.txt"));
    candidate_files.push(config::defaults_dir().join("list-google.txt"));

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

/// Собирает домены из пользовательского и дефолтного списков ИСКЛЮЧЕНИЙ
/// (list-exclude.txt и defaults/default-exclude.txt). Используется, чтобы не советовать
/// добавлять в исключения то, что юзер уже и так исключил.
pub fn load_exclude_domains() -> HashSet<String> {
    let lists_dir = config::get_app_dir().join("lists");
    let files = [
        lists_dir.join("list-exclude.txt"),
        config::defaults_dir().join("default-exclude.txt"),
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

/// Делит кандидатов на «можно советовать добавить в обход» и «уже покрыт».
///
/// Единый источник правды для отчёта и решения (`site_solution::decide`):
/// оба слоя получают одни и те же данные, поэтому отчёт больше не может
/// напечатать «уже покрыт — не дублируйте», а итог — «добавьте в обход»
/// (кейс vercel 27.10.26). Чистая функция: карта приходит аргументом,
/// файловая система не читается.
pub fn split_bypass_candidates(
    hosts: &[String],
    bypass: &BypassMap,
) -> (Vec<String>, Vec<String>) {
    let mut uncovered: Vec<String> = Vec::new();
    let mut covered: Vec<String> = Vec::new();
    for host in hosts {
        if find_bypass_matches(std::slice::from_ref(host), bypass).is_empty() {
            uncovered.push(host.clone());
        } else {
            covered.push(host.clone());
        }
    }
    (uncovered, covered)
}

/// Какой юзерский список правит [`add_domains`]. Дефолтные файлы (defaults/)
/// здесь не участвуют: они перезаписываются при каждом старте (контракт
/// владельца), правки туда терялись бы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetList {
    /// lists/list-general.txt — домены для обхода.
    Bypass,
    /// lists/list-exclude.txt — домены, исключённые из обхода.
    Exclude,
}

impl TargetList {
    fn user_file(&self) -> PathBuf {
        let lists_dir = config::get_app_dir().join("lists");
        match self {
            TargetList::Bypass => lists_dir.join("list-general.txt"),
            TargetList::Exclude => lists_dir.join("list-exclude.txt"),
        }
    }

    /// Что уже есть в списке (lowercase-записи, только юзерский файл).
    fn existing_entries(&self) -> HashSet<String> {
        let mut set = HashSet::new();
        if let Ok(content) = fs::read_to_string(self.user_file()) {
            for raw in content.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                set.insert(line.to_lowercase());
            }
        }
        set
    }
}

/// Нормализация домена для списка: lowercase, без схемы/пути/порта/
/// завершающей точки. Пустая строка — домен не распознан.
fn normalize_for_list(raw: &str) -> Option<String> {
    let mut d = raw.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = d.strip_prefix(prefix) {
            d = rest.to_string();
        }
    }
    if let Some(pos) = d.find('/') {
        d.truncate(pos);
    }
    if let Some(pos) = d.find(':') {
        d.truncate(pos);
    }
    let d = d.trim_end_matches('.').to_string();
    if d.is_empty() || !d.contains('.') {
        return None;
    }
    d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-').then_some(d)
}

/// Добавляет домены в юзерский список (обход или исключения). Каждый домен
/// нормализуется; уже покрытые записи (точное совпадение или субдомен
/// существующей записи) не дублируются. Возвращает прочитанный отчёт:
/// что добавлено, что уже было, что отброшено как мусор — без молчаливых
/// пропусков (core rules §2.2).
pub fn add_domains(target: TargetList, domains: &[String]) -> Result<String, String> {
    if domains.is_empty() {
        return Err("список доменов пуст — добавлять нечего".to_string());
    }
    let path = target.user_file();
    let mut existing = target.existing_entries();

    let mut added: Vec<String> = Vec::new();
    let mut skipped_present: Vec<String> = Vec::new();
    let mut skipped_invalid: Vec<String> = Vec::new();
    for raw in domains {
        let Some(d) = normalize_for_list(raw) else {
            skipped_invalid.push(raw.clone());
            continue;
        };
        if is_excluded(&d, &existing).is_some() {
            skipped_present.push(d);
            continue;
        }
        added.push(d.clone());
        existing.insert(d);
    }

    if !added.is_empty() {
        let mut content = fs::read_to_string(&path).unwrap_or_default();
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        // Пометка-маркер, чтобы юзер видел, что дописано автоматически.
        content.push_str("# DPI_GUI auto-added\n");
        for d in &added {
            content.push_str(d);
            content.push('\n');
        }
        // Атомарная запись: temp + rename, как в hosts.rs.
        let tmp = path.with_extension("txt.tmp");
        fs::write(&tmp, content)
            .map_err(|e| format!("не удалось записать {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .map_err(|e| format!("не удалось заменить {}: {e}", path.display()))?;
    }

    let mut report = format!("Добавлено {} домен(ов) в {}", added.len(), list_name(target));
    if !added.is_empty() {
        report.push_str(&format!(": {}", added.join(", ")));
    }
    if !skipped_present.is_empty() {
        report.push_str(&format!(
            "; уже покрыты списком (не дублируются): {}",
            skipped_present.join(", ")
        ));
    }
    if !skipped_invalid.is_empty() {
        report.push_str(&format!(
            "; отброшены как не домены: {}",
            skipped_invalid.join(", ")
        ));
    }
    Ok(report)
}

fn list_name(t: TargetList) -> &'static str {
    match t {
        TargetList::Bypass => "список обхода (list-general.txt)",
        TargetList::Exclude => "список исключений (list-exclude.txt)",
    }
}

/// Записи ТОЛЬКО юзерского списка исключений (без дефолтов) — множество
/// редактируемых записей для решений (SSOT с [`remove_domains`]: убираем
/// то, что реально есть в файле). Записи дефолтного default-exclude.txt
/// сюда не попадают: он перегенерируется при каждом старте (контракт
/// владельца), удалять из него бессмысленно.
pub fn user_exclude_entries() -> HashSet<String> {
    TargetList::Exclude.existing_entries()
}

/// Убирает записи из юзерского списка (обход или исключения). Сравнение —
/// по точной строке (lowercase): убираем именно ту запись, которую вернул
/// [`is_excluded`]; суффикс-матч здесь опасен — снёс бы чужие строки.
/// Комментарии и пустые строки не трогаются. Возвращает честный отчёт:
/// что убрано, чего в списке не было.
pub fn remove_domains(target: TargetList, entries: &[String]) -> Result<String, String> {
    if entries.is_empty() {
        return Err("список доменов пуст — убирать нечего".to_string());
    }
    let path = target.user_file();
    let content = fs::read_to_string(&path).unwrap_or_default();
    let want: HashSet<String> = entries.iter().map(|e| e.trim().to_lowercase()).collect();
    let mut removed: Vec<String> = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        let drop_it =
            !line.is_empty() && !line.starts_with('#') && want.contains(&line.to_lowercase());
        if drop_it {
            removed.push(line.to_string());
        } else {
            kept.push(raw);
        }
    }
    if removed.is_empty() {
        return Err(format!(
            "в {} нет записей {}: убирать нечего",
            list_name(target),
            entries.join(", ")
        ));
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    // Атомарная запись: temp + rename, как в add_domains/hosts.rs.
    let tmp = path.with_extension("txt.tmp");
    fs::write(&tmp, out).map_err(|e| format!("не удалось записать {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("не удалось заменить {}: {e}", path.display()))?;

    let mut report = format!(
        "Убрано {} записей из {}: {}",
        removed.len(),
        list_name(target),
        removed.join(", ")
    );
    let missing: Vec<&str> = entries
        .iter()
        .filter(|e| {
            let el = e.trim().to_lowercase();
            !removed.iter().any(|r| r == &el)
        })
        .map(|e| e.as_str())
        .collect();
    if !missing.is_empty() {
        report.push_str(&format!(
            "; в списке не найдены (оставлены как есть): {}",
            missing.join(", ")
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Тонкая обёртка над is_excluded для читаемости тестов.
    fn is_excluded_by_entries(host: &str, entries: &HashSet<String>) -> bool {
        is_excluded(host, entries).is_some()
    }

    /// Нормализация: схема, путь, порт, точка в конце, регистр.
    #[test]
    fn normalize_for_list_strips_noise() {
        assert_eq!(
            normalize_for_list("HTTPS://Sub.Example.COM/path?q=1:80"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(normalize_for_list("Example.RU."), Some("example.ru".to_string()));
        assert_eq!(normalize_for_list("  дуршлаг  "), None);
        assert_eq!(normalize_for_list("localhost"), None, "без точки — не домен списка");
        assert_eq!(normalize_for_list(""), None);
    }

    /// Субдомен уже покрытой записи не дублируется.
    #[test]
    fn is_excluded_by_entries_matches_suffix() {
        let entries = set(&["example.com"]);
        assert!(is_excluded_by_entries("example.com", &entries));
        assert!(is_excluded_by_entries("sub.example.com", &entries));
        assert!(!is_excluded_by_entries("notexample.com", &entries));
    }

    fn bypass_map(entries: &[&str]) -> BypassMap {
        entries
            .iter()
            .map(|e| (e.to_string(), vec![PathBuf::from("list-general.txt")]))
            .collect()
    }

    /// Покрытый родителем домен уходит в covered, непокрытый — в uncovered.
    /// Единый фильтр отчёта и решения (кейс vercel 27.10.26).
    #[test]
    fn split_bypass_candidates_divides_covered_and_uncovered() {
        let map = bypass_map(&["vercel.app"]);
        let hosts = vec![
            "sub.vercel.app".to_string(),
            "example.org".to_string(),
        ];
        let (uncovered, covered) = split_bypass_candidates(&hosts, &map);
        assert_eq!(uncovered, vec!["example.org".to_string()]);
        assert_eq!(covered, vec!["sub.vercel.app".to_string()]);
    }

    /// Точное совпадение тоже считается покрытием.
    #[test]
    fn split_bypass_candidates_exact_match_is_covered() {
        let map = bypass_map(&["example.org"]);
        let (uncovered, covered) =
            split_bypass_candidates(&["example.org".to_string()], &map);
        assert!(uncovered.is_empty());
        assert_eq!(covered, vec!["example.org".to_string()]);
    }

    /// Пустая карта — всё непокрыто; пустой список — обе стороны пусты.
    #[test]
    fn split_bypass_candidates_empty_inputs() {
        let map = bypass_map(&[]);
        let (uncovered, covered) =
            split_bypass_candidates(&["example.org".to_string()], &map);
        assert_eq!(uncovered, vec!["example.org".to_string()]);
        assert!(covered.is_empty());

        let (uncovered, covered) = split_bypass_candidates(&[], &bypass_map(&["a.ru"]));
        assert!(uncovered.is_empty());
        assert!(covered.is_empty());
    }

    /// Регистр не влияет: домены списков в нижнем регистре.
    #[test]
    fn split_bypass_candidates_case_insensitive() {
        let map = bypass_map(&["vercel.app"]);
        let (uncovered, covered) =
            split_bypass_candidates(&["Sub.VERCEL.app".to_string()], &map);
        assert!(uncovered.is_empty());
        assert_eq!(covered, vec!["Sub.VERCEL.app".to_string()]);
    }
}
