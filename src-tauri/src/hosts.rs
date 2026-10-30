use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";
const BACKUP_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts.dpigui.bak";
/// Метка, которой приложение помечает СВОИ строки в hosts. Удаляются только они.
const MARKER: &str = "# DPI_GUI";

/// Единственная точка знания пути к hosts (SSOT): используется и правкой
/// файла, и кнопкой «Открыть файл hosts» на вкладке «Настройки».
pub fn hosts_path() -> PathBuf {
    PathBuf::from(HOSTS_PATH)
}

/// Валидация домена: латинские буквы/цифры/дефис/точка, без пробелов и слешей.
pub fn normalize_domain_public(domain: &str) -> Result<String, String> {
    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Result<String, String> {
    let d = domain.trim().to_lowercase();
    if d.is_empty() {
        return Err("Домен пустой".to_string());
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("Домен «{}» содержит недопустимые символы", domain));
    }
    if d.contains("..") {
        return Err(format!("Домен «{}» некорректен", domain));
    }
    Ok(d.trim_end_matches('.').to_string())
}

/// Чтение текущего содержимого hosts (сырые строки).
fn read_hosts_raw() -> Result<Vec<String>, String> {
    fs::read_to_string(hosts_path())
        .map_err(|e| format!("Не удалось прочитать hosts: {}", e))
        .map(|s| s.lines().map(|l| l.to_string()).collect())
}

/// Бэкап делается один раз (первое редактирование), не затирает старую копию.
fn ensure_backup() -> Result<(), String> {
    if !PathBuf::from(BACKUP_PATH).exists() {
        fs::copy(hosts_path(), BACKUP_PATH)
            .map_err(|e| format!("Не удалось создать бэкап hosts: {}", e))?;
    }
    Ok(())
}

/// Добавляет (или заменяет) строки `ip domain` и `ip www.domain` в hosts.
/// * удаляет прежние строки, маппящие этот домен (или www) на любой IP;
/// * дописывает свежие строки с меткой DPI_GUI;
/// * записывает атомарно (tmp + rename) и сбрасывает DNS-кэш.
pub fn apply_hosts_entry(ip: &str, domain: &str) -> Result<String, String> {
    let parsed = IpAddr::from_str(ip.trim())
        .map_err(|_| format!("«{}» — не похоже на IP-адрес (нужен IPv4/IPv6)", ip))?;
    let domain = normalize_domain(domain)?;
    let www = if domain.starts_with("www.") {
        domain.clone()
    } else {
        format!("www.{}", domain)
    };

    ensure_backup()?;
    let mut lines = read_hosts_raw()?;

    // Убираем прежние упоминания домена и www (чтобы не было конфликтов/дублей,
    // в т.ч. блокирующих строк вида `0.0.0.0 domain`).
    lines.retain(|l| !maps_domain(l, &domain) && !maps_domain(l, &www));

    // Всегда дописываем наши свежие строки.
    lines.push(format!("{} {} {}", parsed, domain, MARKER));
    lines.push(format!("{} {} {}", parsed, www, MARKER));

    write_hosts(&lines)?;
    let _ = flush_dns();

    Ok(format!(
        "✅ В hosts записано:\n  {} {}\n  {} {}\nDNS-кэш сброшен.",
        parsed, domain, parsed, www
    ))
}

/// Удаляет строки, которые приложение ПОМЕТИЛО DPI_GUI для этого домена.
pub fn remove_hosts_entry(domain: &str) -> Result<String, String> {
    let domain = normalize_domain(domain)?;
    let www = if domain.starts_with("www.") {
        domain.clone()
    } else {
        format!("www.{}", domain)
    };

    ensure_backup()?;
    let mut lines = read_hosts_raw()?;
    let before = lines.len();
    lines.retain(|l| {
        !(l.contains(MARKER) && (maps_domain(l, &domain) || maps_domain(l, &www)))
    });
    let removed = before - lines.len();
    write_hosts(&lines)?;
    let _ = flush_dns();

    if removed == 0 {
        Ok(format!("ℹ️ В hosts не нашлось записей DPI_GUI для «{}» — ничего не удалено.", domain))
    } else {
        Ok(format!("✅ Из hosts удалено {} строк(и) DPI_GUI для «{}».\nDNS-кэш сброшен.", removed, domain))
    }
}

/// Маппит ли строка hosts домен на IP (т.е. в строке есть токен, равный домену).
/// Не трогаем строки-комментарии (начинающиеся с `#`).
fn maps_domain(line: &str, domain: &str) -> bool {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return false;
    }
    t.split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case(domain))
}

/// Разобрать строки hosts в карту «домен (lowercase) → список IP» (без дублей).
/// Чистая функция: комментарии (`#` — и в начале строки, и инлайном) пропускаются,
/// строка вида `IP домен [домен2 …]` маппит каждый домен на IP; строка с невалидным
/// первым токеном (не IP) пропускается целиком. Пустые домены и точки на конце
/// (FQDN-форма `domain.`) нормализуются.
fn parse_hosts_lines(lines: &[&str]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in lines {
        // Всё после `#` — комментарий: и полные строки, и инлайновые метки
        // (наши записи выглядят как `1.2.3.4 domain # DPI_GUI`).
        let t = line.split('#').next().unwrap_or("").trim();
        let mut tokens = t.split_whitespace();
        let Some(ip_tok) = tokens.next() else { continue };
        let Ok(ip) = IpAddr::from_str(ip_tok) else { continue };
        for dom in tokens {
            let dom = dom.trim_end_matches('.').to_lowercase();
            if dom.is_empty() {
                continue;
            }
            let ips = map.entry(dom).or_default();
            let ip_s = ip.to_string();
            if !ips.contains(&ip_s) {
                ips.push(ip_s);
            }
        }
    }
    map
}

/// Прочитать системный hosts и вернуть карту «домен → список IP». ЕДИНСТВЕННАЯ
/// точка чтения существующих записей (SSOT): чип «в hosts: …» в списке «Ошибки
/// сети» показывает юзеру его же закреплённые адреса — сценарий «прописали IP,
/// он умер, домен падает» виден прямо в строке ошибки.
pub fn load_hosts_map() -> Result<HashMap<String, Vec<String>>, String> {
    let raw = read_hosts_raw()?;
    let refs: Vec<&str> = raw.iter().map(|s| s.as_str()).collect();
    Ok(parse_hosts_lines(&refs))
}

/// Атомарная запись: во временный файл в той же папке, затем rename поверх.
fn write_hosts(lines: &[String]) -> Result<(), String> {
    let path = hosts_path();
    let parent = path
        .parent()
        .ok_or("Не удалось определить папку hosts")?
        .to_path_buf();
    let content = lines.join("\r\n") + "\r\n";
    let tmp = parent.join(format!(
        ".hosts.tmp.{}",
        std::process::id()
    ));
    fs::write(&tmp, &content)
        .map_err(|e| format!("Не удалось записать временный файл hosts: {}", e))?;
    fs::rename(&tmp, &path).map_err(|e| format!("Не удалось заменить hosts: {}", e))?;
    Ok(())
}

/// Сброс DNS-кэша Windows. Ошибка не фатальна — только предупреждение.
fn flush_dns() -> Result<String, String> {
    let out = Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("ipconfig /flushdns не запустился: {}", e))?;
    if out.status.success() {
        Ok("DNS-кэш сброшен".to_string())
    } else {
        Ok("DNS-кэш не сброшен (ipconfig /flushdns вернул ошибку)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Базовый разбор: IP + домены, инлайновый комментарий-метка, дубль IP.
    #[test]
    fn parse_basic_and_marker_comment() {
        let lines = vec![
            "127.0.0.1 localhost",
            "1.2.3.4 example.com www.example.com # DPI_GUI",
            "1.2.3.4 example.com # DPI_GUI", // дубль IP — не должен задвоиться
            "5.6.7.8 example.com",           // второй IP того же домена — копится
        ];
        let m = parse_hosts_lines(&lines);
        assert_eq!(
            m.get("example.com").map(|v| v.as_slice()),
            Some(&["1.2.3.4".to_string(), "5.6.7.8".to_string()][..])
        );
        assert_eq!(
            m.get("www.example.com").map(|v| v.as_slice()),
            Some(&["1.2.3.4".to_string()][..])
        );
        assert_eq!(m.get("localhost").map(|v| v.as_slice()), Some(&["127.0.0.1".to_string()][..]));
    }

    /// Комментарии, мусорные строки, IPv6 и FQDN-точка на конце.
    #[test]
    fn parse_skips_comments_and_junk_keeps_ipv6() {
        let lines = vec![
            "# комментарий целиком",
            "   ",
            "not-an-ip example.com", // первый токен не IP — строка пропущена
            "0.0.0.0 blocked.example # блокировка",
            "::1 v6.example",
            "9.9.9.9 fqdn.example.",
        ];
        let m = parse_hosts_lines(&lines);
        assert!(m.get("example.com").is_none(), "строка с мусором вместо IP не маппится");
        assert_eq!(
            m.get("blocked.example").map(|v| v.as_slice()),
            Some(&["0.0.0.0".to_string()][..])
        );
        assert_eq!(m.get("v6.example").map(|v| v.as_slice()), Some(&["::1".to_string()][..]));
        assert_eq!(m.get("fqdn.example").map(|v| v.as_slice()), Some(&["9.9.9.9".to_string()][..]));
        assert!(m.get("fqdn.example.").is_none(), "точка на конце нормализуется");
    }

    /// Регистр домена в hosts не важен — ключ всегда lowercase.
    #[test]
    fn parse_is_case_insensitive() {
        let lines = vec!["1.1.1.1 Example.COM"];
        let m = parse_hosts_lines(&lines);
        assert!(m.contains_key("example.com"));
        assert!(!m.contains_key("Example.COM"));
    }
}