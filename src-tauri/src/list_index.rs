//! Индекс доменных списков (PRP ревизия 4 §7.5, ШАГ D).
//!
//! Отвечает на вопрос юзера «этот домен есть в каком-то списке или нету?»:
//! при подозрении показываем названия списков, где домен нашёлся, либо явное
//! «в списках отсутствует».
//!
//! SSOT матчинга — здесь; на фронт уходит ТОЛЬКО готовый список лейблов
//! (поле `lists` события `domain_discovery`), списки на фронт не копируются.
//!
//! Состав списков — факт из кода (`config.rs::ensure_directories_and_files`):
//! ровно 6 файлов в `AppData/.../lists/` (3 юзерских в корне + 3 дефолтных в
//! `lists/defaults/`, которые перезаписываются при каждом запуске), профили
//! winws подключают только их, поэтому директорию не сканируем — фиксируем
//! состав таблицей ниже.

use std::collections::HashMap;
use std::path::Path;

/// Файл списка (относительно lists_dir) → человеческий лейбл.
/// Порядок в таблице = порядок лейблов в результате find() (стабильный вывод).
const LIST_FILES: [(&str, &str); 6] = [
    ("list-general.txt", "General List"),
    ("list-exclude.txt", "Exclude List"),
    ("list-google.txt", "Google List"),
    // Дефолтные списки — единая папка lists/defaults/, перезапись при каждом старте.
    ("defaults/default-exclude.txt", "Дефолтные исключения"),
    ("defaults/list-general.txt", "Дефолтный bypass (General)"),
    ("defaults/list-google.txt", "Дефолтный bypass (Google)"),
];

/// Лейблы списков по битовой маске.
fn labels(mask: u64) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (idx, (_, label)) in LIST_FILES.iter().enumerate() {
        if mask & (1u64 << idx) != 0 {
            out.push(*label);
        }
    }
    out
}

/// Индекс доменов списков: точные совпадения + суффиксы.
#[derive(Debug, Default)]
pub struct ListIndex {
    /// Точный домен (lowercase, без лид-точки) -> биты списков.
    exact: HashMap<String, u64>,
    /// Суффикс с ведущей точкой (".example.com") -> биты списков.
    suffix: HashMap<String, u64>,
}

impl ListIndex {
    /// Читать все 6 файлов. Ошибки чтения НЕ фатальны: файл пропускается,
    /// его причина попадает в warnings (показать в лог один раз при старте).
    pub fn load(lists_dir: &Path) -> (ListIndex, Vec<String>) {
        let mut exact: HashMap<String, u64> = HashMap::new();
        let mut suffix: HashMap<String, u64> = HashMap::new();
        let mut warnings = Vec::new();

        for (idx, (rel, _)) in LIST_FILES.iter().enumerate() {
            let bit = 1u64 << idx;
            let path = lists_dir.join(rel);
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(err) => {
                    warnings.push(format!("{}: {}", rel, err));
                    continue;
                }
            };
            for raw in text.lines() {
                let line = raw.trim().to_lowercase();
                // Комментарии (winws hostlist: строки с #) и пустые — пропустить.
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Формат записи:
                //   "example.com"      — точное совпадение + его поддомены (suffix);
                //   ".example.com"     — ТОЛЬКО поддомены (суффикс);
                //   "*.example.com"    — ТОЛЬКО поддомены (суффикс, звездочка отпадает).
                if let Some(rest) = line.strip_prefix("*.") {
                    let key = format!(".{}", rest.trim_start_matches('.'));
                    if key.len() > 1 {
                        *suffix.entry(key).or_insert(0) |= bit;
                    }
                } else if let Some(rest) = line.strip_prefix('.') {
                    let key = format!(".{}", rest);
                    if key.len() > 1 {
                        *suffix.entry(key).or_insert(0) |= bit;
                    }
                } else {
                    *exact.entry(line.clone()).or_insert(0) |= bit;
                    let key = format!(".{}", line);
                    *suffix.entry(key).or_insert(0) |= bit;
                }
            }
        }

        (ListIndex { exact, suffix }, warnings)
    }

    /// В каких списках нашёлся домен (дедуп, стабильный порядок таблицы).
    /// Суффиксный обход: максимум 5 меток вверх от запрошенного домена
    /// (практика: FQDN длиннее практически не встречаются).
    pub fn find(&self, domain: &str) -> Vec<&'static str> {
        let lower = domain.trim().to_lowercase();
        if lower.is_empty() {
            return Vec::new();
        }
        let mut mask = 0u64;
        if let Some(m) = self.exact.get(&lower) {
            mask |= *m;
        }
        let parts: Vec<&str> = lower.split('.').collect();
        let start_max = parts.len().min(5);
        for start in 1..start_max {
            let cand = format!(".{}", parts[start..].join("."));
            if let Some(m) = self.suffix.get(&cand) {
                mask |= *m;
            }
        }
        labels(mask)
    }
}

// ---------------------------------------------------------------------------
// Тесты (unit, без драйвера).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_subdir(tag: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("время системное настоящий")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dpi_gui_list_index_{}_{}", tag, unique));
        fs::create_dir_all(dir.join("defaults")).expect("создание temp-поддерева");
        dir
    }

    #[test]
    fn exact_domain_and_subdomains() {
        let dir = temp_subdir("exact");
        fs::write(dir.join("list-general.txt"), "example.com\n").expect("запись temp");
        let (idx, warns) = ListIndex::load(&dir);
        // Только list-general.txt создан — остальные 5 обязаны дать предупреждения.
        assert_eq!(warns.len(), 5, "неожиданный состав warnings: {:?}", warns);
        assert_eq!(idx.find("example.com"), vec!["General List"]);
        // bare-запись в списке покрывает и поддомены (юзерская интуиция
        // «google.com в списке => maps.google.com тоже из списка»).
        assert_eq!(idx.find("maps.example.com"), vec!["General List"]);
        assert!(idx.find("example.org").is_empty());
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let dir = temp_subdir("comments");
        fs::write(
            dir.join("list-general.txt"),
            "# комментарий\n.blocked.com\n\n   \nempty.ru\n",
        )
        .expect("запись temp");
        let (idx, _) = ListIndex::load(&dir);
        // ".blocked.com" — сугубо суффикс: ловит ТОЛЬКО поддомены.
        assert_eq!(idx.find("sub.blocked.com"), vec!["General List"]);
        assert!(
            idx.find("blocked.com").is_empty(),
            "лид-точка = ТОЛЬКО суффикс: сам домен НЕ ловится"
        );
        assert_eq!(idx.find("empty.ru"), vec!["General List"]);
    }

    #[test]
    fn leading_dot_and_star_starct_suffix_only() {
        let dir = temp_subdir("suffixonly");
        fs::write(dir.join("list-exclude.txt"), ".private.net\n*.secret.net\n").expect("запись temp");
        let (idx, _) = ListIndex::load(&dir);
        assert_eq!(idx.find("host.private.net"), vec!["Exclude List"]);
        assert!(idx.find("private.net").is_empty());
        assert_eq!(idx.find("a.b.secret.net"), vec!["Exclude List"]);
        assert!(idx.find("secret.net").is_empty());
    }

    #[test]
    fn domain_found_in_two_lists_dedup_and_order() {
        let dir = temp_subdir("twolists");
        fs::write(dir.join("list-general.txt"), "google.com\n").expect("запись temp");
        fs::write(dir.join("list-google.txt"), "google.com\n").expect("запись temp");
        let (idx, _) = ListIndex::load(&dir);
        // Порядок лейблов стабилен по таблице LIST_FILES (general раньше google).
        assert_eq!(
            idx.find("maps.google.com"),
            vec!["General List", "Google List"]
        );
    }

    #[test]
    fn missing_files_produce_warnings() {
        let dir = temp_subdir("missing");
        let (idx, warns) = ListIndex::load(&dir);
        assert_eq!(warns.len(), LIST_FILES.len(), "все файлы отсутствуют");
        assert!(idx.find("anything.com").is_empty());
    }

    #[test]
    fn suffix_walk_limited_to_5_levels() {
        let dir = temp_subdir("depth");
        fs::write(dir.join("list-general.txt"), "deep.example.jp\n").expect("запись temp");
        let (idx, _) = ListIndex::load(&dir);
        // 5 уровней от «tag1.deep.example.jp» — внутри; глубже — за границей.
        assert_eq!(idx.find("tag1.deep.example.jp"), vec!["General List"]);
        assert!(idx.find("a.b.c.d.e.f.g.deep.example.jp").is_empty());
    }

    #[test]
    fn wildcard_read_from_real_generated_file() {
        // Состав полный: предупреждения про отсутствующие файлы в лог — ручная
        // проверка на живой машине; здесь только честный подход через файлы.
        let dir = temp_subdir("realf");
        fs::write(
            dir.join("defaults").join("list-google.txt"),
            "*.googlevideo.com\n",
        )
        .expect("запись temp");
        let (idx, _) = ListIndex::load(&dir);
        assert_eq!(idx.find("rr3---sn-abcd.googlevideo.com"), vec!["Дефолтный bypass (Google)"]);
    }
}

