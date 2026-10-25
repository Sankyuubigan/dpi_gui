#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod process;
mod analyzer;
mod analyzer_probe;
mod analyzer_report;
mod analyzer_ip_report;
mod bypass_toggle;
mod ip_candidates;
 mod ip_probe;

 mod ip_range_scan;
mod ip_target;
mod site_probe;
mod site_solution;
mod site_verdict;
mod testing;
mod bypass_lists;
mod diagnostics;
mod diagnostics_probe;
mod diagnostics_techniques;
mod diagnostics_report;
mod hosts;
mod events;
mod win_divert;
mod domain_monitor;
mod tls_sni;
mod quic_sniff;
mod list_index;
mod process_owner;

use tauri::AppHandle;

#[tauri::command]
fn init_app(app: AppHandle) -> Result<(), String> {
    // Порядок важен: чистим грязное состояние прошлого сеанса (остаточную
    // службу WinDivert) ДО первого check_status из фронтенда, чтобы индикатор
    // не показывал «ПРОЦЕСС АКТИВЕН» на мёртвом обходе.
    process::cleanup_stale_windivert(&app);
    config::ensure_directories_and_files().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config() -> Result<serde_json::Value, String> {
    config::read_config().map_err(|e| e.to_string())
}

#[tauri::command]
fn save_config(config: serde_json::Value) -> Result<(), String> {
    config::write_config(&config).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_profiles() -> Result<Vec<serde_json::Value>, String> {
    config::read_profiles().map_err(|e| e.to_string())
}

#[tauri::command]
fn open_file(file_type: String) -> Result<(), String> {
    config::open_file_in_editor(&file_type).map_err(|e| e.to_string())
}

/// Список DoH-сервисов подмены DNS для UI-дропдауна — из дефолт-файла
/// lists/defaults/doh-services.txt (переписывается при каждом старте).
/// При сбое чтения файла — встроенный дефолт
/// (fallback-логика ровно одна, в diagnostics_probe::load_doh_resolvers).
#[tauri::command]
fn get_doh_services() -> Vec<String> {
    let (services, _warnings, _config_error) = diagnostics_probe::load_doh_resolvers();
    services
        .iter()
        .map(|host| format!("https://{}/dns-query", host))
        .collect()
}

#[tauri::command]
fn start_bypass(app: AppHandle, profile_name: String, game_filter: bool) -> Result<String, String> {
    process::start_winws(app, &profile_name, game_filter).map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_bypass() -> Result<String, String> {
    process::stop_winws().map_err(|e| e.to_string())
}

#[tauri::command]
fn check_status() -> bool {
    process::is_winws_running()
}

// Оборачиваем долгие команды в асинхронные таски, чтобы не вешать UI-поток
#[tauri::command]
async fn run_domain_analysis(app: AppHandle, url: String) -> Result<analyzer::DomainAnalysisOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        analyzer::analyze_url(&app, &url)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

/// Применяет найденное решение (кнопка «Починить сайт»): правит списки
/// обхода/исключений и/или hosts. При работающем обходе правка списков
/// требует перезапуска winws — списки читаются процессом только на старте.
#[tauri::command]
async fn apply_solution(app: AppHandle, solution: site_solution::SiteSolution) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut report_lines: Vec<String> = Vec::new();
        let mut lists_changed: bool = false;

        for action in &solution.actions {
            match action {
                site_solution::SolutionAction::AddToBypassList { domains } => {
                    let r = bypass_lists::add_domains(bypass_lists::TargetList::Bypass, domains)?;
                    report_lines.push(format!("🛡️ {}", r));
                    lists_changed = true;
                }
                site_solution::SolutionAction::AddToExcludeList { domains } => {
                    let r = bypass_lists::add_domains(bypass_lists::TargetList::Exclude, domains)?;
                    report_lines.push(format!("⛔ {}", r));
                    lists_changed = true;
                }
                site_solution::SolutionAction::WriteHosts { ip, domain } => {
                    let r = hosts::apply_hosts_entry(ip, domain)?;
                    report_lines.push(format!("📄 {}", r));
                }
            }
        }

        if lists_changed {
            // winws читает hostlist-файлы только при старте: чтобы решение
            // заработало сразу, перезапускаем обход тем же профилем
            // (логика SSOT — bypass_toggle, как в анализе).
            if process::is_winws_running() {
                let saved = bypass_toggle::capture_active();
                bypass_toggle::stop_bypass();
                let note = bypass_toggle::restore_bypass(&app, &saved)
                    .unwrap_or_else(|| "Обход не перезапускался: профиль не был активен.".to_string());
                report_lines.push(format!("♻️ Правки списков применены; {}", note));
            } else {
                report_lines.push("ℹ️ Обход сейчас выключен: правки вступят в силу при следующем старте профиля.".to_string());
            }
        }

        if report_lines.is_empty() {
            return Err("в решении нет ни одного действия — применять нечего".to_string());
        }
        Ok(report_lines.join("\n"))
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn test_profile(app: AppHandle, profile_name: String, url: String, game_filter: bool) -> Result<testing::ProfileTestOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_single_profile(app, &profile_name, &url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn test_dns(url: String, dns_ip: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        testing::test_dns(&url, &dns_ip)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
async fn run_diagnostics(app: AppHandle, url: String, game_filter: bool) -> Result<diagnostics::DiagnosticsReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        diagnostics::run_diagnostics(app, url, game_filter)
    }).await.unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

#[tauri::command]
fn apply_hosts_entry(ip: String, domain: String) -> Result<String, String> {
    hosts::apply_hosts_entry(&ip, &domain)
}

#[tauri::command]
fn remove_hosts_entry(domain: String) -> Result<String, String> {
    hosts::remove_hosts_entry(&domain)
}

/// Чей это собственный IP-шлюз среди DoH-сервисов (для предупреждения перед
/// записью в hosts). `None` — адрес не принадлежит инфраструктуре сервисов.
fn doh_gateway_owner_of(ip: &std::net::IpAddr) -> Option<String> {
    let (services, _, _) = diagnostics_probe::load_doh_resolvers();
    diagnostics_probe::doh_own_ips(&services)
        .into_iter()
        .find(|(_, ips)| ips.contains(ip))
        .map(|(svc, _)| svc)
}

/// Авто-проверка после записи в hosts: реально ли сайт открывается через этот IP.
#[tauri::command]
fn verify_site_via_ip(host: String, ip: String) -> Result<String, String> {
    use std::net::IpAddr;
    use std::str::FromStr;
    let ip = IpAddr::from_str(ip.trim())
        .map_err(|_| format!("«{}» — не похоже на IP-адрес", ip))?;
    let host = hosts::normalize_domain_public(&host)?;
    // Честность (core §2.2): проба через SNI-прокси DoH-сервиса реально даёт
    // HTTP 200, а сайт в браузере по такому адресу не открывается (кейс
    // openrouter.ai). Молча проверять шлюз — значит выдать ложный «успех».
    let gateway_note = match doh_gateway_owner_of(&ip) {
        Some(svc) => format!(
            "⚠️ ВНИМАНИЕ: {} — собственный IP DoH-сервиса «{}» (прокси-шлюз), а не адрес сайта. Проба через него может пройти, но браузер по нему сайт НЕ откроет.\n",
            ip, svc
        ),
        None => String::new(),
    };
    let text = match site_probe::probe_https_by_ip(&host, ip) {
        crate::diagnostics_probe::HttpResult::Ok(code) => {
            format!("✅ Сайт {} открывается через {} (HTTP {})", host, ip, code)
        }
        crate::diagnostics_probe::HttpResult::BlockPage => {
            format!("⚠️ {} через {} — страница блокировки (подставил оператор)", ip, host)
        }
        crate::diagnostics_probe::HttpResult::Forbidden(code) => {
            format!("🌍 {} через {} — отказ сервера HTTP {} без признаков подмены (возможно, региональное ограничение — проверьте через VPN)", ip, host, code)
        }
        crate::diagnostics_probe::HttpResult::ServiceRestrict => {
            format!("⚠️ {} через {} — сайт отдался, но сервис сам сообщает об ограничении (регион источника): сеть здесь не при чём, нужен VPN", ip, host)
        }
        crate::diagnostics_probe::HttpResult::Rst => {
            format!("🚫 {} — HTTPS сброшен (RST). Блок по SNI/IP: подмена в hosts не поможет, нужен обход (winws).", ip)
        }
        crate::diagnostics_probe::HttpResult::Tls => {
            format!("🔐 {} — TLS-рукопожатие сломалось", ip)
        }
        crate::diagnostics_probe::HttpResult::BadCert => {
            format!("⚠️ {} — сертификат невалиден для {}", ip, host)
        }
        crate::diagnostics_probe::HttpResult::Timeout => {
            format!("⏳ {} — таймаут соединения", ip)
        }
        crate::diagnostics_probe::HttpResult::Dns => {
            format!("ℹ️ {} — DNS-ошибка", ip)
        }
        crate::diagnostics_probe::HttpResult::Other(m) => {
            format!("ℹ️ {} — {}", ip, m)
        }
    };
    if gateway_note.is_empty() {
        Ok(text)
    } else {
        Ok(format!("{}{}", gateway_note, text))
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_about_updates::init())
        .invoke_handler(tauri::generate_handler![
            init_app,
            get_config,
            save_config,
            get_profiles,
            open_file,
            get_doh_services,
            start_bypass,
            stop_bypass,
            check_status,
            run_domain_analysis,
            apply_solution,
            test_profile,
            test_dns,
            run_diagnostics,
            apply_hosts_entry,
            remove_hosts_entry,
            verify_site_via_ip
        ])
        .on_window_event(|_window, event| {
            // При закрытии окна гасим обход и выгружаем драйвер WinDivert,
            // чтобы он не оставался в памяти и не блокировал файлы при обновлении.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let _ = process::stop_winws();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}