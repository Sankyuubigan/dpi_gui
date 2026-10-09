use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::config;

/// Р”РѕРјРµРЅ (lowercase) -> СЃРїРёСЃРѕРє С„Р°Р№Р»РѕРІ РѕР±С…РѕРґР°, РІ РєРѕС‚РѕСЂС‹С… РѕРЅ РІСЃС‚СЂРµС‡Р°РµС‚СЃСЏ.
pub type BypassMap = HashMap<String, Vec<PathBuf>>;

/// РЎРѕР±РёСЂР°РµС‚ Р’РЎР• СЌС„С„РµРєС‚РёРІРЅС‹Рµ СЃРїРёСЃРєРё РѕР±С…РѕРґР° (hostlist), РєРѕС‚РѕСЂС‹Рµ СЂРµР°Р»СЊРЅРѕ С‡РёС‚Р°РµС‚ winws
/// РґР»СЏ С‚РµРєСѓС‰РµРіРѕ СЃРѕСЃС‚РѕСЏРЅРёСЏ РїСЂРёР»РѕР¶РµРЅРёСЏ, Рё РІРѕР·РІСЂР°С‰Р°РµС‚ РєР°СЂС‚Сѓ "РґРѕРјРµРЅ -> С„Р°Р№Р»С‹".
///
/// РЈС‡РёС‚С‹РІР°СЋС‚СЃСЏ:
/// - `--hostlist=` С„Р°Р№Р»С‹ РёР· Р°СЂРіСѓРјРµРЅС‚РѕРІ Р°РєС‚РёРІРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ (РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРёРµ СЃРїРёСЃРєРё)
/// - РІСЃС‚СЂРѕРµРЅРЅС‹Рµ СЃРїРёСЃРєРё `default-bypass/list-general.txt` Рё `default-bypass/list-google.txt`
///   (РІСЃРµРіРґР° РїРѕРґРєР»СЋС‡Р°СЋС‚СЃСЏ РІ process.rs РЅРµР·Р°РІРёСЃРёРјРѕ РѕС‚ РїСЂРѕС„РёР»СЏ)
///
/// РњР°С‚С‡РёРЅРі РґРѕРјРµРЅР°: С‚РѕС‡РЅРѕРµ СЃРѕРІРїР°РґРµРЅРёРµ Р»РёР±Рѕ СЃСѓС„С„РёРєСЃ (РґРѕРјРµРЅ СЏРІР»СЏРµС‚СЃСЏ СЃСѓР±РґРѕРјРµРЅРѕРј СЃРїРёСЃРєР°),
/// С‚.Рµ. `sub.example.com` РЅР°Р№РґС‘С‚СЃСЏ РїРѕ Р·Р°РїРёСЃРё `example.com`.
pub fn load_bypass_domains() -> BypassMap {
    let app_dir = config::get_app_dir();
    let lists_dir = app_dir.join("lists");

    let mut candidate_files: Vec<PathBuf> = Vec::new();

    // 1. --hostlist= С„Р°Р№Р»С‹ РёР· Р°РєС‚РёРІРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ
    if let Ok(cfg) = config::read_config() {
        if let Some(selected) = cfg.get("selected_profile").and_then(|v| v.as_str()) {
            if !selected.is_empty() {
                if let Ok(profiles) = config::read_profiles() {
                    if let Some(profile) = profiles.iter().find(|p| p["name"] == selected) {
                        if let Some(args) = profile.get("args").and_then(|v| v.as_str()) {
                            if let Some(parsed) = shlex::split(args) {
                                for arg in parsed {
                                    if let Some(path) = arg.strip_prefix("--hostlist=") {
                                        // РђСЂРіСѓРјРµРЅС‚С‹ РїСЂРѕС„РёР»СЏ СЃРѕРґРµСЂР¶Р°С‚ РїР»РµР№СЃС…РѕР»РґРµСЂС‹ ({LISTS_DIR} Рё С‚.Рї.)
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

    // 2. Р’СЃС‚СЂРѕРµРЅРЅС‹Рµ СЃРїРёСЃРєРё РѕР±С…РѕРґР° (РІСЃРµРіРґР° РїРѕРґРєР»СЋС‡Р°СЋС‚СЃСЏ РІ process.rs)
    candidate_files.push(lists_dir.join("default-bypass").join("list-general.txt"));
    candidate_files.push(lists_dir.join("default-bypass").join("list-google.txt"));

    // РЈР±РёСЂР°РµРј РґСѓР±Р»Рё (РµСЃР»Рё РїСЂРѕС„РёР»СЊ СЃСЃС‹Р»Р°РµС‚СЃСЏ РЅР° С‚Рµ Р¶Рµ С„Р°Р№Р»С‹)
    candidate_files.sort();
    candidate_files.dedup();

    let mut map: BypassMap = HashMap::new();

    for file in candidate_files {
        let content = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue, // С„Р°Р№Р»Р° РЅРµС‚ вЂ” РїСЂРѕРїСѓСЃРєР°РµРј
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

/// РЎРѕР±РёСЂР°РµС‚ РґРѕРјРµРЅС‹ РёР· РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРѕРіРѕ Рё РІСЃС‚СЂРѕРµРЅРЅРѕРіРѕ СЃРїРёСЃРєРѕРІ РРЎРљР›Р®Р§Р•РќРР™
/// (list-exclude.txt Рё default-exclude.txt). РСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ, С‡С‚РѕР±С‹ РЅРµ СЃРѕРІРµС‚РѕРІР°С‚СЊ
/// РґРѕР±Р°РІР»СЏС‚СЊ РІ РёСЃРєР»СЋС‡РµРЅРёСЏ С‚Рѕ, С‡С‚Рѕ СЋР·РµСЂ СѓР¶Рµ Рё С‚Р°Рє РёСЃРєР»СЋС‡РёР».
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

/// РџСЂРѕРІРµСЂСЏРµС‚, РїРѕРєСЂС‹С‚ Р»Рё РґРѕРјРµРЅ РєР°РєРѕР№-Р»РёР±Рѕ Р·Р°РїРёСЃСЊСЋ СЃРїРёСЃРєР° РёСЃРєР»СЋС‡РµРЅРёР№
/// (С‚РѕС‡РЅРѕРµ СЃРѕРІРїР°РґРµРЅРёРµ Р»РёР±Рѕ РґРѕРјРµРЅ вЂ” СЃСѓР±РґРѕРјРµРЅ Р·Р°РїРёСЃРё). Р’РѕР·РІСЂР°С‰Р°РµС‚ СЃР°РјСѓ Р·Р°РїРёСЃСЊ.
pub fn is_excluded(host: &str, excludes: &HashSet<String>) -> Option<String> {
    let host_lc = host.to_lowercase();
    for entry in excludes {
        if &host_lc == entry || host_lc.ends_with(&format!(".{}", entry)) {
            return Some(entry.clone());
        }
    }
    None
}

/// Р’РѕР·РІСЂР°С‰Р°РµС‚ СЂРѕРґРёС‚РµР»СЊСЃРєРёР№ РґРѕРјРµРЅ (РїРѕСЃР»РµРґРЅРёРµ 2 РјРµС‚РєРё), РЅР°РїСЂРёРјРµСЂ
/// `sdk.rum.aliyuncs.com` -> `aliyuncs.com`. Р”Р»СЏ РґРѕРјРµРЅР° РёР· РѕРґРЅРѕР№ РјРµС‚РєРё РІРµСЂРЅС‘С‚ РµРіРѕ РєР°Рє РµСЃС‚СЊ.
pub fn parent_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 2 {
        host.to_lowercase()
    } else {
        parts[parts.len() - 2..].join(".").to_lowercase()
    }
}

/// РџСЂРѕРІРµСЂСЏРµС‚, РІРЅРµСЃС‘РЅ Р»Рё РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹Р№ РґРѕРјРµРЅ РІ РєР°РєРѕР№-Р»РёР±Рѕ СЃРїРёСЃРѕРє РѕР±С…РѕРґР°.
/// РЈС‡РёС‚С‹РІР°РµС‚ РєР°Рє С‚РѕС‡РЅРѕРµ СЃРѕРІРїР°РґРµРЅРёРµ, С‚Р°Рє Рё СЃСѓР±РґРѕРјРµРЅС‹ (СЃСѓС„С„РёРєСЃ).
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
