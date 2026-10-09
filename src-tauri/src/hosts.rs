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

fn hosts_path() -> PathBuf {
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

/// Возвращает содержимое hosts (для отображения в UI).
pub fn read_hosts() -> Result<String, String> {
    fs::read_to_string(hosts_path()).map_err(|e| format!("Не удалось прочитать hosts: {}", e))
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