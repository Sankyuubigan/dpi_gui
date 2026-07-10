use std::thread;
use std::time::Duration;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use crate::{config, process};
use crate::diagnostics_probe::{self, DnsInfo, HttpResult};
use crate::diagnostics_techniques::{self, TechniqueSpec};
use crate::diagnostics_report;

/// Результат одной техники для фронтенда.
#[derive(Serialize)]
pub struct TechniqueOutcome {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Итоговый отчёт диагностики (возвращается на фронтенд).
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

/// Универсальный перехват паники: если проба упала — логируем и возвращаем None,
/// диагностика продолжается дальше (отказоустойчивость).
fn try_catch<T>(label: &str, app: &AppHandle, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            let _ = app.emit("log", format!("[Диагностика] Инструмент '{}' не сработал, пропускаем.", label));
            None
        }
    }
}

/// Проверка конкретного профиля (по имени) против тестового домена.
fn test_profile_against(app: &AppHandle, name: &str, domain: &str, game_filter: bool) -> (bool, String) {
    match process::start_winws(app.clone(), name, game_filter) {
        Ok(_) => {
            thread::sleep(Duration::from_secs(3));
            let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
            let _ = process::stop_winws();
            let ok = matches!(r, diagnostics_probe::HttpResult::Ok(_));
            let detail = match r {
                diagnostics_probe::HttpResult::Ok(s) => format!("OK ({})", s),
                other => format!("{:?}", other),
            };
            (ok, detail)
        }
        Err(e) => (false, format!("запуск: {}", e)),
    }
}

/// Основная диагностика соединения + подбор и проверка авто-профиля.
pub fn run_diagnostics(app: AppHandle, blocked_url: String, game_filter: bool) -> Result<DiagnosticsReport, String> {
    let log = |msg: String| {
        let _ = app.emit("log", msg);
    };

    let domain = diagnostics_techniques::norm(&blocked_url);
    log(format!("[Диагностика] === Запуск диагностики для: {} ===", domain));

    // Останавливаем активный обход, чтобы пробы были чистыми
    let _ = process::stop_winws();
    thread::sleep(Duration::from_millis(500));

    // 1. Права администратора (точное значение доопределим после проверки WinDivert)
    let admin_check = try_catch("admin", &app, || diagnostics_probe::check_admin()).unwrap_or_else(|| {
        log("[Диагностика] проверка прав администратора не удалась".into());
        false
    });
    let mut admin = admin_check;
    log(format!("[Диагностика] Права администратора (предв.): {}", if admin { "ДА" } else { "НЕТ" }));

    // 2. Наличие winws
    let present = try_catch("winws_present", &app, || diagnostics_probe::winws_present()).unwrap_or(false);
    log(format!("[Диагностика] winws.exe найден: {}", if present { "ДА" } else { "НЕТ" }));

    // 3. WinDivert
    let (windivert_ok, windivert_detail) =
        try_catch("windivert", &app, || diagnostics_probe::test_windivert(&app)).unwrap_or_else(|| {
            (false, "проверка WinDivert не удалась".to_string())
        });
    // WinDivert требует прав администратора — если он поднялся, прав точно хватает
    if windivert_ok {
        admin = true;
    }
    log(format!(
        "[Диагностика] WinDivert: {} ({})",
        if windivert_ok { "OK" } else { "FAIL" },
        windivert_detail
    ));

    // 4. DNS (системный + публичные)
    let dns: DnsInfo = try_catch("dns", &app, || diagnostics_probe::dns_multi(&domain)).unwrap_or_else(DnsInfo::new);
    let dns_summary = format!(
        "Системный: [{}]\nCloudflare 1.1.1.1: [{}]\nGoogle 8.8.8.8: [{}]{}",
        dns.system.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        dns.cloudflare.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        dns.google.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        if dns.err.is_empty() { String::new() } else { format!("\nОшибка: {}", dns.err) }
    );
    log(format!("[Диагностика] DNS:\n{}", dns_summary));

    // Выбираем IP для connect/UDP-проб (публичный DNS надёжнее при цензуре)
    let target_ip = dns
        .cloudflare
        .first()
        .copied()
        .or_else(|| dns.system.first().copied())
        .or_else(|| dns.google.first().copied());

    // 5. IPv6
    let ipv6 = try_catch("ipv6", &app, || diagnostics_probe::has_ipv6(&domain)).unwrap_or(false);
    log(format!("[Диагностика] IPv6 до сайта: {}", if ipv6 { "есть" } else { "нет" }));

    // 6. Сырое TCP-соединение к 443 (без обхода)
    let connect = match target_ip {
        Some(ip) => try_catch("tcp_connect", &app, || diagnostics_probe::tcp_connect(ip, 443)).unwrap_or_else(|| "ошибка".into()),
        None => "no-ip".to_string(),
    };
    log(format!("[Диагностика] CONNECT 443 (без обхода): {}", connect));

    // 7. HTTPS к заблокированному сайту (без обхода) — классификация блока
    let tls = try_catch("http_block", &app, || {
        let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
        format!("{:?}", r)
    })
    .unwrap_or_else(|| "ошибка".into());
    log(format!("[Диагностика] HTTPS (без обхода): {}", tls));

    // 8. UDP/QUIC зонд
    let quic = match target_ip {
        Some(ip) => try_catch("quic", &app, || diagnostics_probe::quic_probe(ip)).unwrap_or_else(|| "ошибка".into()),
        None => "no-ip".to_string(),
    };
    log(format!("[Диагностика] QUIC/UDP 443: {}", quic));

    // 9. Прогон desync-техник (каждая изолированно)
    let techniques: Vec<TechniqueSpec> = diagnostics_techniques::all_techniques();
    let mut outcomes: Vec<TechniqueOutcome> = Vec::new();
    let mut passed: Vec<String> = Vec::new();

    for spec in &techniques {
        log(format!("[Диагностика] -> Тест техники: {}", spec.name));
        let (p, d) = try_catch("technique", &app, || {
            diagnostics_techniques::test_technique(&app, spec, &domain, game_filter)
        })
        .unwrap_or_else(|| (false, "проба упала".into()));
        log(format!(
            "   {}: {}",
            spec.name,
            if p { "ПРОХОДИТ".to_string() } else { d.clone() }
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

    // 9b. Проверка СУЩЕСТВУЮЩИХ профилей пользователя (чтобы не говорить
    // "ни одна техника не работает", когда у пользователя уже есть рабочий).
    let user_profiles = config::read_profiles().unwrap_or_default();
    let mut existing_outcomes: Vec<TechniqueOutcome> = Vec::new();
    for p in &user_profiles {
        let pname = p["name"].as_str().unwrap_or("").to_string();
        if pname.is_empty() || pname.starts_with("Авто-профиль") {
            continue;
        }
        log(format!("[Диагностика] -> Тест существующего профиля: {}", pname));
        let (ok, detail) = try_catch("existing_profile", &app, || {
            test_profile_against(&app, &pname, &domain, game_filter)
        })
        .unwrap_or_else(|| (false, "проба упала".into()));
        log(format!(
            "   {}: {}",
            pname,
            if ok { "ПРОХОДИТ".to_string() } else { detail.clone() }
        ));
        existing_outcomes.push(TechniqueOutcome {
            name: pname,
            passed: ok,
            detail,
        });
    }

    // 10. Генерация и проверка авто-профиля
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
        // Пишем доменно-специфичный хостлист, на который ссылается профиль
        let _ = std::fs::write(app_dir.join("lists").join("diag-autoprofile.txt"), format!("{}\n", domain));

        match config::append_profile(serde_json::json!({ "name": name, "args": args })) {
            Ok(_) => {
                profile_saved = true;
                log(format!("[Диагностика] Авто-профиль '{}' сохранён.", name));
            }
            Err(e) => {
                log(format!("[Диагностика] Не удалось сохранить профиль: {}", e));
            }
        }

        // Проверяем сохранённый профиль по факту
        let _ = process::stop_winws();
        thread::sleep(Duration::from_millis(500));
        verified = try_catch("verify_profile", &app, || {
            match process::start_winws_custom(app.clone(), &args, game_filter) {
                Ok(_) => {
                    thread::sleep(Duration::from_secs(3));
                    let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
                    let ok = matches!(r, HttpResult::Ok(_));
                    let _ = process::stop_winws();
                    log(format!(
                        "[Диагностика] Проверка авто-профиля: {}",
                        if ok { "РАБОТАЕТ" } else { "не прошла" }
                    ));
                    ok
                }
                Err(e) => {
                    log(format!("[Диагностика] Не удалось запустить авто-профиль: {}", e));
                    false
                }
            }
        });

        gen_name = Some(name);
        gen_args = Some(args);
    } else if let Some(work) = existing_outcomes.iter().find(|o| o.passed) {
        // Ни одна изолированная техника не прошла, но у пользователя есть
        // рабочий профиль — клонируем его как авто-профиль.
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
                    log(format!("[Диагностика] Авто-профиль (клон '{}') сохранён.", work.name));
                }
                let _ = process::stop_winws();
                thread::sleep(Duration::from_millis(500));
                verified = try_catch("verify_clone", &app, || {
                    match process::start_winws_custom(app.clone(), &cargs, game_filter) {
                        Ok(_) => {
                            thread::sleep(Duration::from_secs(3));
                            let r = diagnostics_probe::http_classify(&format!("https://{}/", domain));
                            let ok = matches!(r, HttpResult::Ok(_));
                            let _ = process::stop_winws();
                            log(format!(
                                "[Диагностика] Проверка клона: {}",
                                if ok { "РАБОТАЕТ" } else { "не прошла" }
                            ));
                            ok
                        }
                        Err(e) => {
                            log(format!("[Диагностика] Не удалось запустить клон: {}", e));
                            false
                        }
                    }
                });
                gen_name = Some(cname);
                gen_args = Some(cargs);
            }
        }
    } else {
        log("[Диагностика] Рабочих техник и профилей не найдено — авто-профиль не создаётся.".into());
    }

    // На всякий случай глушим обход в конце
    let _ = process::stop_winws();

    // 11. Отпечаток и рекомендация
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

    log("[Диагностика] === ОТЧЁТ ===".into());
    log(format!("[Диагностика] Отпечаток: {}", fingerprint));
    log(format!("[Диагностика] Рекомендация:\n{}", recommendation));

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
