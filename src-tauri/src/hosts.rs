use std::fs;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";
const BACKUP_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts.dpigui.bak";
/// РњРµС‚РєР°, РєРѕС‚РѕСЂРѕР№ РїСЂРёР»РѕР¶РµРЅРёРµ РїРѕРјРµС‡Р°РµС‚ РЎР’РћР СЃС‚СЂРѕРєРё РІ hosts. РЈРґР°Р»СЏСЋС‚СЃСЏ С‚РѕР»СЊРєРѕ РѕРЅРё.
const MARKER: &str = "# DPI_GUI";

fn hosts_path() -> PathBuf {
    PathBuf::from(HOSTS_PATH)
}

/// Р’Р°Р»РёРґР°С†РёСЏ РґРѕРјРµРЅР°: Р»Р°С‚РёРЅСЃРєРёРµ Р±СѓРєРІС‹/С†РёС„СЂС‹/РґРµС„РёСЃ/С‚РѕС‡РєР°, Р±РµР· РїСЂРѕР±РµР»РѕРІ Рё СЃР»РµС€РµР№.
pub fn normalize_domain_public(domain: &str) -> Result<String, String> {
    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Result<String, String> {
    let d = domain.trim().to_lowercase();
    if d.is_empty() {
        return Err("Р”РѕРјРµРЅ РїСѓСЃС‚РѕР№".to_string());
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("Р”РѕРјРµРЅ В«{}В» СЃРѕРґРµСЂР¶РёС‚ РЅРµРґРѕРїСѓСЃС‚РёРјС‹Рµ СЃРёРјРІРѕР»С‹", domain));
    }
    if d.contains("..") {
        return Err(format!("Р”РѕРјРµРЅ В«{}В» РЅРµРєРѕСЂСЂРµРєС‚РµРЅ", domain));
    }
    Ok(d.trim_end_matches('.').to_string())
}

/// Р§С‚РµРЅРёРµ С‚РµРєСѓС‰РµРіРѕ СЃРѕРґРµСЂР¶РёРјРѕРіРѕ hosts (СЃС‹СЂС‹Рµ СЃС‚СЂРѕРєРё).
fn read_hosts_raw() -> Result<Vec<String>, String> {
    fs::read_to_string(hosts_path())
        .map_err(|e| format!("РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РёС‚Р°С‚СЊ hosts: {}", e))
        .map(|s| s.lines().map(|l| l.to_string()).collect())
}

/// Р‘СЌРєР°Рї РґРµР»Р°РµС‚СЃСЏ РѕРґРёРЅ СЂР°Р· (РїРµСЂРІРѕРµ СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ), РЅРµ Р·Р°С‚РёСЂР°РµС‚ СЃС‚Р°СЂСѓСЋ РєРѕРїРёСЋ.
fn ensure_backup() -> Result<(), String> {
    if !PathBuf::from(BACKUP_PATH).exists() {
        fs::copy(hosts_path(), BACKUP_PATH)
            .map_err(|e| format!("РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ Р±СЌРєР°Рї hosts: {}", e))?;
    }
    Ok(())
}

/// Р”РѕР±Р°РІР»СЏРµС‚ (РёР»Рё Р·Р°РјРµРЅСЏРµС‚) СЃС‚СЂРѕРєРё `ip domain` Рё `ip www.domain` РІ hosts.
/// * СѓРґР°Р»СЏРµС‚ РїСЂРµР¶РЅРёРµ СЃС‚СЂРѕРєРё, РјР°РїРїСЏС‰РёРµ СЌС‚РѕС‚ РґРѕРјРµРЅ (РёР»Рё www) РЅР° Р»СЋР±РѕР№ IP;
/// * РґРѕРїРёСЃС‹РІР°РµС‚ СЃРІРµР¶РёРµ СЃС‚СЂРѕРєРё СЃ РјРµС‚РєРѕР№ DPI_GUI;
/// * Р·Р°РїРёСЃС‹РІР°РµС‚ Р°С‚РѕРјР°СЂРЅРѕ (tmp + rename) Рё СЃР±СЂР°СЃС‹РІР°РµС‚ DNS-РєСЌС€.
pub fn apply_hosts_entry(ip: &str, domain: &str) -> Result<String, String> {
    let parsed = IpAddr::from_str(ip.trim())
        .map_err(|_| format!("В«{}В» вЂ” РЅРµ РїРѕС…РѕР¶Рµ РЅР° IP-Р°РґСЂРµСЃ (РЅСѓР¶РµРЅ IPv4/IPv6)", ip))?;
    let domain = normalize_domain(domain)?;
    let www = if domain.starts_with("www.") {
        domain.clone()
    } else {
        format!("www.{}", domain)
    };

    ensure_backup()?;
    let mut lines = read_hosts_raw()?;

    // РЈР±РёСЂР°РµРј РїСЂРµР¶РЅРёРµ СѓРїРѕРјРёРЅР°РЅРёСЏ РґРѕРјРµРЅР° Рё www (С‡С‚РѕР±С‹ РЅРµ Р±С‹Р»Рѕ РєРѕРЅС„Р»РёРєС‚РѕРІ/РґСѓР±Р»РµР№,
    // РІ С‚.С‡. Р±Р»РѕРєРёСЂСѓСЋС‰РёС… СЃС‚СЂРѕРє РІРёРґР° `0.0.0.0 domain`).
    lines.retain(|l| !maps_domain(l, &domain) && !maps_domain(l, &www));

    // Р’СЃРµРіРґР° РґРѕРїРёСЃС‹РІР°РµРј РЅР°С€Рё СЃРІРµР¶РёРµ СЃС‚СЂРѕРєРё.
    lines.push(format!("{} {} {}", parsed, domain, MARKER));
    lines.push(format!("{} {} {}", parsed, www, MARKER));

    write_hosts(&lines)?;
    let _ = flush_dns();

    Ok(format!(
        "вњ… Р’ hosts Р·Р°РїРёСЃР°РЅРѕ:\n  {} {}\n  {} {}\nDNS-РєСЌС€ СЃР±СЂРѕС€РµРЅ.",
        parsed, domain, parsed, www
    ))
}

/// РЈРґР°Р»СЏРµС‚ СЃС‚СЂРѕРєРё, РєРѕС‚РѕСЂС‹Рµ РїСЂРёР»РѕР¶РµРЅРёРµ РџРћРњР•РўРР›Рћ DPI_GUI РґР»СЏ СЌС‚РѕРіРѕ РґРѕРјРµРЅР°.
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
        Ok(format!("в„№пёЏ Р’ hosts РЅРµ РЅР°С€Р»РѕСЃСЊ Р·Р°РїРёСЃРµР№ DPI_GUI РґР»СЏ В«{}В» вЂ” РЅРёС‡РµРіРѕ РЅРµ СѓРґР°Р»РµРЅРѕ.", domain))
    } else {
        Ok(format!("вњ… РР· hosts СѓРґР°Р»РµРЅРѕ {} СЃС‚СЂРѕРє(Рё) DPI_GUI РґР»СЏ В«{}В».\nDNS-РєСЌС€ СЃР±СЂРѕС€РµРЅ.", removed, domain))
    }
}

/// РњР°РїРїРёС‚ Р»Рё СЃС‚СЂРѕРєР° hosts РґРѕРјРµРЅ РЅР° IP (С‚.Рµ. РІ СЃС‚СЂРѕРєРµ РµСЃС‚СЊ С‚РѕРєРµРЅ, СЂР°РІРЅС‹Р№ РґРѕРјРµРЅСѓ).
/// РќРµ С‚СЂРѕРіР°РµРј СЃС‚СЂРѕРєРё-РєРѕРјРјРµРЅС‚Р°СЂРёРё (РЅР°С‡РёРЅР°СЋС‰РёРµСЃСЏ СЃ `#`).
fn maps_domain(line: &str, domain: &str) -> bool {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return false;
    }
    t.split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case(domain))
}

/// Р’РѕР·РІСЂР°С‰Р°РµС‚ СЃРѕРґРµСЂР¶РёРјРѕРµ hosts (РґР»СЏ РѕС‚РѕР±СЂР°Р¶РµРЅРёСЏ РІ UI).
pub fn read_hosts() -> Result<String, String> {
    fs::read_to_string(hosts_path()).map_err(|e| format!("РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РёС‚Р°С‚СЊ hosts: {}", e))
}

/// РђС‚РѕРјР°СЂРЅР°СЏ Р·Р°РїРёСЃСЊ: РІРѕ РІСЂРµРјРµРЅРЅС‹Р№ С„Р°Р№Р» РІ С‚РѕР№ Р¶Рµ РїР°РїРєРµ, Р·Р°С‚РµРј rename РїРѕРІРµСЂС….
fn write_hosts(lines: &[String]) -> Result<(), String> {
    let path = hosts_path();
    let parent = path
        .parent()
        .ok_or("РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ РїР°РїРєСѓ hosts")?
        .to_path_buf();
    let content = lines.join("\r\n") + "\r\n";
    let tmp = parent.join(format!(
        ".hosts.tmp.{}",
        std::process::id()
    ));
    fs::write(&tmp, &content)
        .map_err(|e| format!("РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РїРёСЃР°С‚СЊ РІСЂРµРјРµРЅРЅС‹Р№ С„Р°Р№Р» hosts: {}", e))?;
    fs::rename(&tmp, &path).map_err(|e| format!("РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РјРµРЅРёС‚СЊ hosts: {}", e))?;
    Ok(())
}

/// РЎР±СЂРѕСЃ DNS-РєСЌС€Р° Windows. РћС€РёР±РєР° РЅРµ С„Р°С‚Р°Р»СЊРЅР° вЂ” С‚РѕР»СЊРєРѕ РїСЂРµРґСѓРїСЂРµР¶РґРµРЅРёРµ.
fn flush_dns() -> Result<String, String> {
    let out = Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("ipconfig /flushdns РЅРµ Р·Р°РїСѓСЃС‚РёР»СЃСЏ: {}", e))?;
    if out.status.success() {
        Ok("DNS-РєСЌС€ СЃР±СЂРѕС€РµРЅ".to_string())
    } else {
        Ok("DNS-РєСЌС€ РЅРµ СЃР±СЂРѕС€РµРЅ (ipconfig /flushdns РІРµСЂРЅСѓР» РѕС€РёР±РєСѓ)".to_string())
    }
}