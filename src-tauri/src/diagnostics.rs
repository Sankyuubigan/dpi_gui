use std::thread;
use std::time::Duration;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use crate::{config, process};
use crate::diagnostics_probe::{self, DnsInfo, HttpResult};
use crate::diagnostics_techniques::{self, TechniqueSpec};
use crate::diagnostics_report;

/// Р РµР·СѓР»СЊС‚Р°С‚ РѕРґРЅРѕР№ С‚РµС…РЅРёРєРё РґР»СЏ С„СЂРѕРЅС‚РµРЅРґР°.
#[derive(Serialize)]
pub struct TechniqueOutcome {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// РС‚РѕРіРѕРІС‹Р№ РѕС‚С‡С‘С‚ РґРёР°РіРЅРѕСЃС‚РёРєРё (РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ РЅР° С„СЂРѕРЅС‚РµРЅРґ).
#[derive(Serialize)]
pub struct DiagnosticsReport {
    pub admin_ok: bool,
    pub winws_present: bool,
    pub windivert_ok: bool,
    pub windivert_detail: String,
    pub ipv6_available: bool,
    pub dns_summary: String,
    pub connect_443: String,
    pub tls_sni: String,
    pub quic: String,
    pub techniques: Vec<TechniqueOutcome>,
    pub existing_profiles: Vec<TechniqueOutcome>,
    pub fingerprint: String,
    pub recommendation: String,
    pub generated_profile_name: Option<String>,
    pub generated_profile_args: Option<String>,
    pub generated_profile_verified: Option<bool>,
}

/// РЈРЅРёРІРµСЂСЃР°Р»СЊРЅС‹Р№ РїРµСЂРµС…РІР°С‚ РїР°РЅРёРєРё: РµСЃР»Рё РїСЂРѕР±Р° СѓРїР°Р»Р° вЂ” Р»РѕРіРёСЂСѓРµРј Рё РІРѕР·РІСЂР°С‰Р°РµРј None,
/// РґРёР°РіРЅРѕСЃС‚РёРєР° РїСЂРѕРґРѕР»Р¶Р°РµС‚СЃСЏ РґР°Р»СЊС€Рµ (РѕС‚РєР°Р·РѕСѓСЃС‚РѕР№С‡РёРІРѕСЃС‚СЊ).
fn try_catch<T>(label: &str, app: &AppHandle, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            let _ = app.emit("log", format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РРЅСЃС‚СЂСѓРјРµРЅС‚ '{}' РЅРµ СЃСЂР°Р±РѕС‚Р°Р», РїСЂРѕРїСѓСЃРєР°РµРј.", label));
            None
        }
    }
}

/// РџСЂРѕРІРµСЂРєР° РєРѕРЅРєСЂРµС‚РЅРѕРіРѕ РїСЂРѕС„РёР»СЏ (РїРѕ РёРјРµРЅРё) РїСЂРѕС‚РёРІ С‚РµСЃС‚РѕРІРѕРіРѕ РґРѕРјРµРЅР°.
fn test_profile_against(app: &AppHandle, name: &str, domain: &str, game_filter: bool) -> (bool, String) {
    match process::start_winws_quiet(app.clone(), name, game_filter) {
        Ok(_) => {
            thread::sleep(Duration::from_secs(3));
            let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
            let _ = process::stop_winws();
            let ok = matches!(r, diagnostics_probe::HttpResult::Ok(_));
            let detail = match r {
                diagnostics_probe::HttpResult::Ok(s) => format!("OK ({})", s),
                diagnostics_probe::HttpResult::BadCert => "SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ (NET::ERR_CERT_*)".to_string(),
                other => format!("{:?}", other),
            };
            (ok, detail)
        }
        Err(e) => (false, format!("Р·Р°РїСѓСЃРє: {}", e)),
    }
}

/// РћСЃРЅРѕРІРЅР°СЏ РґРёР°РіРЅРѕСЃС‚РёРєР° СЃРѕРµРґРёРЅРµРЅРёСЏ + РїРѕРґР±РѕСЂ Рё РїСЂРѕРІРµСЂРєР° Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЏ.
pub fn run_diagnostics(app: AppHandle, blocked_url: String, game_filter: bool) -> Result<DiagnosticsReport, String> {
    let log = |msg: String| {
        let _ = app.emit("log", msg);
    };

    let domain = diagnostics_techniques::norm(&blocked_url);
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] === Р—Р°РїСѓСЃРє РґРёР°РіРЅРѕСЃС‚РёРєРё РґР»СЏ: {} ===", domain));

    // РћСЃС‚Р°РЅР°РІР»РёРІР°РµРј Р°РєС‚РёРІРЅС‹Р№ РѕР±С…РѕРґ, С‡С‚РѕР±С‹ РїСЂРѕР±С‹ Р±С‹Р»Рё С‡РёСЃС‚С‹РјРё
    let _ = process::stop_winws();
    thread::sleep(Duration::from_millis(500));

    // 1. РџСЂР°РІР° Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° (С‚РѕС‡РЅРѕРµ Р·РЅР°С‡РµРЅРёРµ РґРѕРѕРїСЂРµРґРµР»РёРј РїРѕСЃР»Рµ РїСЂРѕРІРµСЂРєРё WinDivert)
    let admin_check = try_catch("admin", &app, || diagnostics_probe::check_admin()).unwrap_or_else(|| {
        log("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РїСЂРѕРІРµСЂРєР° РїСЂР°РІ Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° РЅРµ СѓРґР°Р»Р°СЃСЊ".into());
        false
    });
    let mut admin = admin_check;
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РџСЂР°РІР° Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° (РїСЂРµРґРІ.): {}", if admin { "Р”Рђ" } else { "РќР•Рў" }));

    // 2. РќР°Р»РёС‡РёРµ winws
    let present = try_catch("winws_present", &app, || diagnostics_probe::winws_present()).unwrap_or(false);
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] winws.exe РЅР°Р№РґРµРЅ: {}", if present { "Р”Рђ" } else { "РќР•Рў" }));

    // 3. WinDivert
    let (windivert_ok, windivert_detail) =
        try_catch("windivert", &app, || diagnostics_probe::test_windivert(&app)).unwrap_or_else(|| {
            (false, "РїСЂРѕРІРµСЂРєР° WinDivert РЅРµ СѓРґР°Р»Р°СЃСЊ".to_string())
        });
    // WinDivert С‚СЂРµР±СѓРµС‚ РїСЂР°РІ Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° вЂ” РµСЃР»Рё РѕРЅ РїРѕРґРЅСЏР»СЃСЏ, РїСЂР°РІ С‚РѕС‡РЅРѕ С…РІР°С‚Р°РµС‚
    if windivert_ok {
        admin = true;
    }
    log(format!(
        "[Р”РёР°РіРЅРѕСЃС‚РёРєР°] WinDivert: {} ({})",
        if windivert_ok { "OK" } else { "FAIL" },
        windivert_detail
    ));

    // 4. DNS (СЃРёСЃС‚РµРјРЅС‹Р№ + РїСѓР±Р»РёС‡РЅС‹Рµ)
    let dns: DnsInfo = try_catch("dns", &app, || diagnostics_probe::dns_multi(&domain)).unwrap_or_else(DnsInfo::new);
    let dns_summary = format!(
        "РЎРёСЃС‚РµРјРЅС‹Р№: [{}]\nCloudflare 1.1.1.1: [{}]\nGoogle 8.8.8.8: [{}]{}",
        dns.system.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        dns.cloudflare.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        dns.google.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        if dns.err.is_empty() { String::new() } else { format!("\nРћС€РёР±РєР°: {}", dns.err) }
    );
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] DNS:\n{}", dns_summary));

    // Р’С‹Р±РёСЂР°РµРј IP РґР»СЏ connect/UDP-РїСЂРѕР± (РїСѓР±Р»РёС‡РЅС‹Р№ DNS РЅР°РґС‘Р¶РЅРµРµ РїСЂРё С†РµРЅР·СѓСЂРµ)
    let target_ip = dns
        .cloudflare
        .first()
        .copied()
        .or_else(|| dns.system.first().copied())
        .or_else(|| dns.google.first().copied());

    // 5. IPv6
    let ipv6 = try_catch("ipv6", &app, || diagnostics_probe::has_ipv6(&domain)).unwrap_or(false);
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] IPv6 РґРѕ СЃР°Р№С‚Р°: {}", if ipv6 { "РµСЃС‚СЊ" } else { "РЅРµС‚" }));

    // 6. РЎС‹СЂРѕРµ TCP-СЃРѕРµРґРёРЅРµРЅРёРµ Рє 443 (Р±РµР· РѕР±С…РѕРґР°)
    let connect = match target_ip {
        Some(ip) => try_catch("tcp_connect", &app, || diagnostics_probe::tcp_connect(ip, 443)).unwrap_or_else(|| "РѕС€РёР±РєР°".into()),
        None => "no-ip".to_string(),
    };
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] CONNECT 443 (Р±РµР· РѕР±С…РѕРґР°): {}", connect));

    // 7. HTTPS Рє Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅРЅРѕРјСѓ СЃР°Р№С‚Сѓ (Р±РµР· РѕР±С…РѕРґР°) вЂ” РєР»Р°СЃСЃРёС„РёРєР°С†РёСЏ Р±Р»РѕРєР°
    let tls = try_catch("http_block", &app, || {
        let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
        format!("{:?}", r)
    })
    .unwrap_or_else(|| "РѕС€РёР±РєР°".into());
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] HTTPS (Р±РµР· РѕР±С…РѕРґР°): {}", tls));

    // 8. UDP/QUIC Р·РѕРЅРґ
    let quic = match target_ip {
        Some(ip) => try_catch("quic", &app, || diagnostics_probe::quic_probe(ip)).unwrap_or_else(|| "РѕС€РёР±РєР°".into()),
        None => "no-ip".to_string(),
    };
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] QUIC/UDP 443: {}", quic));

    // 9. РџСЂРѕРіРѕРЅ desync-С‚РµС…РЅРёРє (РєР°Р¶РґР°СЏ РёР·РѕР»РёСЂРѕРІР°РЅРЅРѕ)
    let techniques: Vec<TechniqueSpec> = diagnostics_techniques::all_techniques();
    let mut outcomes: Vec<TechniqueOutcome> = Vec::new();
    let mut passed: Vec<String> = Vec::new();

    for spec in &techniques {
        log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] -> РўРµСЃС‚ С‚РµС…РЅРёРєРё: {}", spec.name));
        let (p, d) = try_catch("technique", &app, || {
            diagnostics_techniques::test_technique(&app, spec, &domain, game_filter)
        })
        .unwrap_or_else(|| (false, "РїСЂРѕР±Р° СѓРїР°Р»Р°".into()));
        log(format!(
            "   {}: {}",
            spec.name,
            if p { "РџР РћРҐРћР”РРў".to_string() } else { d.clone() }
        ));
        outcomes.push(TechniqueOutcome {
            name: spec.name.clone(),
            passed: p,
            detail: d,
        });
        if p {
            passed.push(spec.name.clone());
        }
    }

    // 9b. РџСЂРѕРІРµСЂРєР° РЎРЈР©Р•РЎРўР’РЈР®Р©РРҐ РїСЂРѕС„РёР»РµР№ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ (С‡С‚РѕР±С‹ РЅРµ РіРѕРІРѕСЂРёС‚СЊ
    // "РЅРё РѕРґРЅР° С‚РµС…РЅРёРєР° РЅРµ СЂР°Р±РѕС‚Р°РµС‚", РєРѕРіРґР° Сѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ СѓР¶Рµ РµСЃС‚СЊ СЂР°Р±РѕС‡РёР№).
    let user_profiles = config::read_profiles().unwrap_or_default();
    let mut existing_outcomes: Vec<TechniqueOutcome> = Vec::new();
    for p in &user_profiles {
        let pname = p["name"].as_str().unwrap_or("").to_string();
        if pname.is_empty() || pname.starts_with("РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ") {
            continue;
        }
        log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] -> РўРµСЃС‚ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РµРіРѕ РїСЂРѕС„РёР»СЏ: {}", pname));
        let (ok, detail) = try_catch("existing_profile", &app, || {
            test_profile_against(&app, &pname, &domain, game_filter)
        })
        .unwrap_or_else(|| (false, "РїСЂРѕР±Р° СѓРїР°Р»Р°".into()));
        log(format!(
            "   {}: {}",
            pname,
            if ok { "РџР РћРҐРћР”РРў".to_string() } else { detail.clone() }
        ));
        existing_outcomes.push(TechniqueOutcome {
            name: pname,
            passed: ok,
            detail,
        });
    }

    // 10. Р“РµРЅРµСЂР°С†РёСЏ Рё РїСЂРѕРІРµСЂРєР° Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЏ
    let app_dir = config::get_app_dir();
    let lists_dir = app_dir.join("lists").to_string_lossy().replace("\\", "/");
    let bin_dir = process::get_bin_dir().to_string_lossy().replace("\\", "/");

    let mut gen_name: Option<String> = None;
    let mut gen_args: Option<String> = None;
    let mut verified: Option<bool> = None;
    let mut profile_saved = false;

    if let Some((name, args)) =
        diagnostics_report::generate_profile(&domain, &techniques, &passed, &lists_dir, &bin_dir)
    {
        // РџРёС€РµРј РґРѕРјРµРЅРЅРѕ-СЃРїРµС†РёС„РёС‡РЅС‹Р№ С…РѕСЃС‚Р»РёСЃС‚, РЅР° РєРѕС‚РѕСЂС‹Р№ СЃСЃС‹Р»Р°РµС‚СЃСЏ РїСЂРѕС„РёР»СЊ
        let _ = std::fs::write(app_dir.join("lists").join("diag-autoprofile.txt"), format!("{}\n", domain));

        match config::append_profile(serde_json::json!({ "name": name, "args": args })) {
            Ok(_) => {
                profile_saved = true;
                log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ '{}' СЃРѕС…СЂР°РЅС‘РЅ.", name));
            }
            Err(e) => {
                log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕС…СЂР°РЅРёС‚СЊ РїСЂРѕС„РёР»СЊ: {}", e));
            }
        }

        // РџСЂРѕРІРµСЂСЏРµРј СЃРѕС…СЂР°РЅС‘РЅРЅС‹Р№ РїСЂРѕС„РёР»СЊ РїРѕ С„Р°РєС‚Сѓ
        let _ = process::stop_winws();
        thread::sleep(Duration::from_millis(500));
        verified = try_catch("verify_profile", &app, || {
            match process::start_winws_custom_quiet(app.clone(), &args, game_filter) {
                Ok(_) => {
                    thread::sleep(Duration::from_secs(3));
                    let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
                    let ok = matches!(r, HttpResult::Ok(_));
                    let _ = process::stop_winws();
                    log(format!(
                        "[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РџСЂРѕРІРµСЂРєР° Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЏ: {}",
                        if ok { "Р РђР‘РћРўРђР•Рў" } else { "РЅРµ РїСЂРѕС€Р»Р°" }
                    ));
                    ok
                }
                Err(e) => {
                    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РїСѓСЃС‚РёС‚СЊ Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЊ: {}", e));
                    false
                }
            }
        });

        gen_name = Some(name);
        gen_args = Some(args);
    } else if let Some(work) = existing_outcomes.iter().find(|o| o.passed) {
        // РќРё РѕРґРЅР° РёР·РѕР»РёСЂРѕРІР°РЅРЅР°СЏ С‚РµС…РЅРёРєР° РЅРµ РїСЂРѕС€Р»Р°, РЅРѕ Сѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РµСЃС‚СЊ
        // СЂР°Р±РѕС‡РёР№ РїСЂРѕС„РёР»СЊ вЂ” РєР»РѕРЅРёСЂСѓРµРј РµРіРѕ РєР°Рє Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЊ.
        let src = user_profiles.iter().find(|p| p["name"] == work.name);
        if let Some(src) = src {
            let src_args = src["args"].as_str().unwrap_or("").to_string();
            if let Some((cname, cargs)) =
                diagnostics_report::clone_profile(&work.name, &src_args, &lists_dir, &bin_dir)
            {
                let _ = std::fs::write(
                    app_dir.join("lists").join("diag-autoprofile.txt"),
                    format!("{}\n", domain),
                );
                if config::append_profile(serde_json::json!({ "name": cname, "args": cargs })).is_ok() {
                    profile_saved = true;
                    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ (РєР»РѕРЅ '{}') СЃРѕС…СЂР°РЅС‘РЅ.", work.name));
                }
                let _ = process::stop_winws();
                thread::sleep(Duration::from_millis(500));
                verified = try_catch("verify_clone", &app, || {
                    match process::start_winws_custom_quiet(app.clone(), &cargs, game_filter) {
                        Ok(_) => {
                            thread::sleep(Duration::from_secs(3));
                            let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
                            let ok = matches!(r, HttpResult::Ok(_));
                            let _ = process::stop_winws();
                            log(format!(
                                "[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РџСЂРѕРІРµСЂРєР° РєР»РѕРЅР°: {}",
                                if ok { "Р РђР‘РћРўРђР•Рў" } else { "РЅРµ РїСЂРѕС€Р»Р°" }
                            ));
                            ok
                        }
                        Err(e) => {
                            log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РїСѓСЃС‚РёС‚СЊ РєР»РѕРЅ: {}", e));
                            false
                        }
                    }
                });
                gen_name = Some(cname);
                gen_args = Some(cargs);
            }
        }
    } else {
        log("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] Р Р°Р±РѕС‡РёС… С‚РµС…РЅРёРє Рё РїСЂРѕС„РёР»РµР№ РЅРµ РЅР°Р№РґРµРЅРѕ вЂ” Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЊ РЅРµ СЃРѕР·РґР°С‘С‚СЃСЏ.".into());
    }

    // РќР° РІСЃСЏРєРёР№ СЃР»СѓС‡Р°Р№ РіР»СѓС€РёРј РѕР±С…РѕРґ РІ РєРѕРЅС†Рµ
    let _ = process::stop_winws();

    // 11. РћС‚РїРµС‡Р°С‚РѕРє Рё СЂРµРєРѕРјРµРЅРґР°С†РёСЏ
    let fingerprint = diagnostics_report::build_fingerprint(
        admin, windivert_ok, ipv6, &dns, &connect, &tls, &quic, &passed,
    );
    let recommendation = diagnostics_report::build_recommendation(
        admin,
        present,
        windivert_ok,
        &windivert_detail,
        ipv6,
        &dns,
        &connect,
        &tls,
        &passed,
        profile_saved,
        verified,
    );

    log("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] === РћРўР§РЃРў ===".into());
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] РћС‚РїРµС‡Р°С‚РѕРє: {}", fingerprint));
    log(format!("[Р”РёР°РіРЅРѕСЃС‚РёРєР°] Р РµРєРѕРјРµРЅРґР°С†РёСЏ:\n{}", recommendation));

    Ok(DiagnosticsReport {
        admin_ok: admin,
        winws_present: present,
        windivert_ok,
        windivert_detail,
        ipv6_available: ipv6,
        dns_summary,
        connect_443: connect,
        tls_sni: tls,
        quic,
        techniques: outcomes,
        existing_profiles: existing_outcomes,
        fingerprint,
        recommendation,
        generated_profile_name: gen_name,
        generated_profile_args: gen_args,
        generated_profile_verified: verified,
    })
}
