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
// Р¤Р»Р°Рі РґР»СЏ СЃРєСЂС‹С‚РёСЏ РѕРєРЅР° РєРѕРЅСЃРѕР»Рё РІ Windows
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn get_bin_dir() -> PathBuf {
    // РС‰РµРј bin СЂСЏРґРѕРј СЃ СЌРєР·РµС€РЅРёРєРѕРј (СЂРµР»РёР·) РёР»Рё РІ С‚РµРєСѓС‰РµР№ РґРёСЂРµРєС‚РѕСЂРёРё (РґРµРІ)
    if let Ok(mut path) = env::current_exe() {
        path.pop(); // СѓР±РёСЂР°РµРј .exe
        path.push("bin");
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("bin")
}

/// РЎС‚СЂРѕРёС‚ РёС‚РѕРіРѕРІС‹Р№ СЃРїРёСЃРѕРє Р°СЂРіСѓРјРµРЅС‚РѕРІ winws РёР· С€Р°Р±Р»РѕРЅР° (СЃ РїР»РµР№СЃС…РѕР»РґРµСЂР°РјРё).
/// Р’С‹РЅРµСЃРµРЅРѕ РѕС‚РґРµР»СЊРЅРѕ, С‡С‚РѕР±С‹ РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°С‚СЊСЃСЏ Рё РґР»СЏ Р·Р°РїСѓСЃРєР° РїРѕ РёРјРµРЅРё РїСЂРѕС„РёР»СЏ,
/// Рё РґР»СЏ Р·Р°РїСѓСЃРєР° РїСЂРѕРёР·РІРѕР»СЊРЅРѕРіРѕ С€Р°Р±Р»РѕРЅР° (РґРёР°РіРЅРѕСЃС‚РёРєР°).
///
/// Р’ С‚РёС…РѕРј СЂРµР¶РёРјРµ (`quiet`) РЅРµ СЃС‹РїРµРј СЃР»СѓР¶РµР±РЅС‹Рµ СЃС‚СЂРѕРєРё В«РџР РћРџРЈРЎРљ РђР Р“РЈРњР•РќРўРђВ» Рё
/// В«РС‚РѕРіРѕРІС‹Рµ Р°СЂРіСѓРјРµРЅС‚С‹В», С‡С‚РѕР±С‹ Р»РѕРіРё С‚РµСЃС‚РѕРІ/РґРёР°РіРЅРѕСЃС‚РёРєРё РѕСЃС‚Р°РІР°Р»РёСЃСЊ С‡РёСЃС‚С‹РјРё.
fn resolve_args(app: &AppHandle, raw_args_template: &str, game_filter: bool, quiet: bool) -> Result<Vec<String>, String> {
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
        None => return Err("РћС€РёР±РєР° РїР°СЂСЃРёРЅРіР° Р°СЂРіСѓРјРµРЅС‚РѕРІ. РџСЂРѕРІРµСЂСЊС‚Рµ РїСЂР°РІРёР»СЊРЅРѕСЃС‚СЊ РєР°РІС‹С‡РµРє РІ РїСЂРѕС„РёР»Рµ.".to_string()),
    };

    let mut final_args = Vec::new();
    let default_exclude_arg = format!("--hostlist-exclude={}/default-exclude.txt", lists_dir);
    let default_bypass_general_arg = format!("--hostlist={}/default-bypass/list-general.txt", lists_dir);
    let default_bypass_google_arg = format!("--hostlist={}/default-bypass/list-google.txt", lists_dir);

    for arg in parsed_args {
        // РњС‹ Р¶РµСЃС‚РєРѕ РІС‹СЂРµР·Р°РµРј Р»РѕРіРёРєСѓ IPSet, С‡С‚РѕР±С‹ РЅРµ Р·Р°РІРёСЃРµС‚СЊ РѕС‚ Р»РёС€РЅРёС… С„Р°Р№Р»РѕРІ
        if arg.starts_with("--ipset=") || arg.starts_with("--ipset-exclude=") {
            if !quiet {
                let _ = app.emit("log", format!("[РџР РћРџРЈРЎРљ РђР Р“РЈРњР•РќРўРђ] {}", arg));
            }
            continue;
        }
        final_args.push(arg.clone());
        // РџРѕСЃР»Рµ РєР°Р¶РґРѕРіРѕ --hostlist-exclude РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РґРѕР±Р°РІР»СЏРµРј РґРµС„РѕР»С‚РЅС‹Р№ СЃРїРёСЃРѕРє РёСЃРєР»СЋС‡РµРЅРёР№
        if arg.starts_with("--hostlist-exclude=") && arg.contains("list-exclude.txt") {
            final_args.push(default_exclude_arg.clone());
        }
        // РџРѕСЃР»Рµ РєР°Р¶РґРѕРіРѕ --hostlist РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РґРѕР±Р°РІР»СЏРµРј РґРµС„РѕР»С‚РЅС‹Рµ СЃРїРёСЃРєРё РѕР±С…РѕРґР°
        if arg.starts_with("--hostlist=") {
            if arg.contains("list-general.txt") {
                final_args.push(default_bypass_general_arg.clone());
            } else if arg.contains("list-google.txt") {
                final_args.push(default_bypass_google_arg.clone());
            }
        }
    }

    if !quiet {
        let _ = app.emit("log", format!("РС‚РѕРіРѕРІС‹Рµ Р°СЂРіСѓРјРµРЅС‚С‹ Р·Р°РїСѓСЃРєР° ({} С€С‚.)", final_args.len()));
    }

    Ok(final_args)
}

/// РЎРѕР±СЃС‚РІРµРЅРЅРѕ Р·Р°РїСѓСЃРє winws СЃ РіРѕС‚РѕРІС‹Рј СЃРїРёСЃРєРѕРј Р°СЂРіСѓРјРµРЅС‚РѕРІ.
fn spawn_winws(app: &AppHandle, final_args: Vec<String>, quiet: bool) -> Result<String, String> {
    let winws_path = get_bin_dir().join(WINWS_EXE);

    if !winws_path.exists() {
        return Err(format!("Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ: {}", winws_path.display()));
    }

    // РЈР±РёРІР°РµРј СЃС‚Р°СЂС‹Р№ РїСЂРѕС†РµСЃСЃ РїРµСЂРµРґ Р·Р°РїСѓСЃРєРѕРј РЅРѕРІРѕРіРѕ
    let _ = stop_winws();
    let _ = app.emit("log", "РЎС‚Р°СЂС‹Рµ РїСЂРѕС†РµСЃСЃС‹ РѕСЃС‚Р°РЅРѕРІР»РµРЅС‹. Р—Р°РїСѓСЃРєР°РµРј РЅРѕРІС‹Р№...".to_string());

    let mut child = Command::new(&winws_path)
        .args(&final_args)
        .current_dir(get_bin_dir())
        .creation_flags(CREATE_NO_WINDOW) // РќРµ РїРѕРєР°Р·С‹РІР°С‚СЊ РєРѕРЅСЃРѕР»СЊ!
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("РћС€РёР±РєР° Р·Р°РїСѓСЃРєР°: {}", e))?;

    let pid = child.id();
    let _ = app.emit("log", format!("РџСЂРѕС†РµСЃСЃ Р·Р°РїСѓС‰РµРЅ СѓСЃРїРµС€РЅРѕ. PID: {}", pid));

    // РџРµСЂРµС…РІР°С‚ stdout. Р’ С‚РёС…РѕРј СЂРµР¶РёРјРµ РєСѓС…РЅСЋ РїСЂРѕС†РµСЃСЃР° РІ Р»РѕРі РЅРµ Р»СЊС‘Рј вЂ”
    // winws РІС‹РІРѕРґРёС‚ РґРµСЃСЏС‚РєРё СЃР»СѓР¶РµР±РЅС‹С… СЃС‚СЂРѕРє, Р±РµСЃРїРѕР»РµР·РЅС‹С… РїРѕР»СЊР·РѕРІР°С‚РµР»СЋ.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let app_clone = app.clone();
    if let Some(out) = stdout {
        thread::spawn(move || {
            let reader = BufReader::new(out);
            for line in reader.lines().flatten() {
                if !quiet {
                    let _ = app_clone.emit("log", format!("[winws] {}", line));
                }
            }
        });
    }

    // РџРµСЂРµС…РІР°С‚ stderr
    let app_clone_err = app.clone();
    if let Some(err) = stderr {
        thread::spawn(move || {
            let reader = BufReader::new(err);
            for line in reader.lines().flatten() {
                let _ = app_clone_err.emit("log", format!("[winws ERROR] {}", line));
            }
        });
    }

    Ok(format!("Р—Р°РїСѓС‰РµРЅРѕ СѓСЃРїРµС€РЅРѕ. PID: {}", pid))
}

pub fn start_winws(app: AppHandle, profile_name: &str, game_filter: bool) -> Result<String, String> {
    start_winws_inner(app, profile_name, game_filter, false)
}

/// РўРёС…РёР№ Р·Р°РїСѓСЃРє: Р±РµР· СЃР»СѓР¶РµР±РЅРѕР№ РєСѓС…РЅРё winws РІ Р»РѕРіР°С… (С‚РµСЃС‚С‹ РїСЂРѕС„РёР»РµР№, РґРёР°РіРЅРѕСЃС‚РёРєР°).
pub fn start_winws_quiet(app: AppHandle, profile_name: &str, game_filter: bool) -> Result<String, String> {
    start_winws_inner(app, profile_name, game_filter, true)
}

fn start_winws_inner(app: AppHandle, profile_name: &str, game_filter: bool, quiet: bool) -> Result<String, String> {
    let profiles = config::read_profiles().map_err(|e| e.to_string())?;

    let profile = profiles.iter().find(|p| p["name"] == profile_name)
        .ok_or("РџСЂРѕС„РёР»СЊ РЅРµ РЅР°Р№РґРµРЅ")?;

    let args_template = profile["args"].as_str().unwrap_or("");
    let final_args = resolve_args(&app, args_template, game_filter, quiet)?;
    spawn_winws(&app, final_args, quiet)
}

/// РўРёС…РёР№ Р·Р°РїСѓСЃРє РїСЂРѕРёР·РІРѕР»СЊРЅРѕРіРѕ С€Р°Р±Р»РѕРЅР° Р°СЂРіСѓРјРµРЅС‚РѕРІ (РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РґРёР°РіРЅРѕСЃС‚РёРєРѕР№).
pub fn start_winws_custom_quiet(app: AppHandle, raw_args_template: &str, game_filter: bool) -> Result<String, String> {
    let final_args = resolve_args(&app, raw_args_template, game_filter, true)?;
    spawn_winws(&app, final_args, true)
}

pub fn stop_winws() -> Result<String, String> {
    // РћСЃС‚Р°РЅР°РІР»РёРІР°РµРј СЃРєСЂС‹С‚Рѕ, Р±РµР· РјРѕСЂРіР°РЅРёСЏ РѕРєРѕРЅ РєРѕРЅСЃРѕР»Рё
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", WINWS_EXE])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "WinDivert.exe"]) // РќР° РІСЃСЏРєРёР№ СЃР»СѓС‡Р°Р№
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // Р–С‘СЃС‚РєРѕРµ СѓР±РёР№СЃС‚РІРѕ winws.exe РЅРµ РІС‹РіСЂСѓР¶Р°РµС‚ РґСЂР°Р№РІРµСЂ-СЃР»СѓР¶Р±Сѓ WinDivert РёР· СЏРґСЂР°,
    // Рё С„Р°Р№Р» WinDivert64.sys РѕСЃС‚Р°С‘С‚СЃСЏ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅРЅС‹Рј. РћСЃС‚Р°РЅР°РІР»РёРІР°РµРј СЃР»СѓР¶Р±Сѓ СЏРІРЅРѕ,
    // РёРЅР°С‡Рµ СѓСЃС‚Р°РЅРѕРІС‰РёРє/РѕР±РЅРѕРІР»РµРЅРёРµ РЅРµ СЃРјРѕРіСѓС‚ РїРµСЂРµР·Р°РїРёСЃР°С‚СЊ .sys.
    // РРјСЏ СЃР»СѓР¶Р±С‹ Р·Р°РІРёСЃРёС‚ РѕС‚ РІРµСЂСЃРёРё winws вЂ” РіР°СЃРёРј РІСЃРµ РёР·РІРµСЃС‚РЅС‹Рµ РІР°СЂРёР°РЅС‚С‹.
    for svc in ["WinDivert", "WinDivert1.4", "windivert"] {
        let _ = Command::new("sc")
            .args(["stop", svc])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    // Р”Р°С‘Рј СЏРґСЂСѓ РІСЂРµРјСЏ РІС‹РіСЂСѓР·РёС‚СЊ РґСЂР°Р№РІРµСЂ Рё РѕСЃРІРѕР±РѕРґРёС‚СЊ .sys
    thread::sleep(std::time::Duration::from_millis(800));

    Ok("РџСЂРѕС†РµСЃСЃС‹ РѕСЃС‚Р°РЅРѕРІР»РµРЅС‹".to_string())
}

/// Р—Р°РіСЂСѓР¶РµРЅР° Р»Рё РґСЂР°Р№РІРµСЂ-СЃР»СѓР¶Р±Р° WinDivert (РјРѕР¶РµС‚ Р¶РёС‚СЊ РґР°Р¶Рµ РїРѕСЃР»Рµ СЃРјРµСЂС‚Рё winws.exe).
fn is_windivert_service_running() -> bool {
    for svc in ["WinDivert", "WinDivert1.4", "windivert"] {
        if let Ok(out) = Command::new("sc")
            .args(["query", svc])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("RUNNING") {
                return true;
            }
        }
    }
    false
}

pub fn is_winws_running() -> bool {
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    for (_, process) in sys.processes() {
        if process.name().to_string_lossy().to_lowercase().contains("winws") {
            return true;
        }
    }
    // РџСЂРѕС†РµСЃСЃ winws РјРѕРі Р±С‹С‚СЊ СѓР±РёС‚, РЅРѕ РґСЂР°Р№РІРµСЂ WinDivert РµС‰С‘ Р·Р°РіСЂСѓР¶РµРЅ вЂ”
    // СЃС‡РёС‚Р°РµРј РѕР±С…РѕРґ Р°РєС‚РёРІРЅС‹Рј, С‡С‚РѕР±С‹ СЃС‚Р°С‚СѓСЃ РІ UI РЅРµ РІРІРѕРґРёР» РІ Р·Р°Р±Р»СѓР¶РґРµРЅРёРµ.
    is_windivert_service_running()
}
