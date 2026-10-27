//! Массовый анализ списка «Ошибки сети» за ОДНО окно «обход выключен».
//!
//! Мотивация (инцидент 27.10.26): авто-анализ по одному домену глушал обход
//! чаще, чем он был включён — фича сделала обход бесполезным. Массовый анализ
//! меняет форму (core §1.10): факты для ВСЕХ доменов пачки собираются в одном
//! окне — одно выключение/включение на прогон вместо N.
//!
//! Порядок фаз:
//! 1. Проба #1 всех доменов (обход в текущем состоянии), параллельно.
//! 2. Если обход был включён — ОДНО окно без обхода: проба #2 сломанных +
//!    ретраи, DoH-факты всех доменов (параллельно), диагностика, CIDR-скан
//!    сломанных. Если обход был выключен — окно не открывается вовсе.
//! 3. Восстановление обхода — гарантировано [`OffWindowGuard`] (даже паника
//!    вернёт обход).
//! 4. Отчёт + решение по каждому домену (те же SSOT: build_report, decide),
//!    событие `analysis_progress` на каждый домен.
//!
//! Отличие от одиночного анализа: без headless Chrome — пачка работает только
//! с самими доменами из списка (под-ресурсы не собираются); глубокий разбор
//! одного сайта остаётся на вкладке «Починка сайтов».

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use tauri::AppHandle;

use crate::analyzer::DomainAnalysisOutcome;
use crate::analyzer_probe::{self, Probe};
use crate::analyzer_report::{self, ReportMeta};
use crate::bypass_lists;
use crate::bypass_toggle::OffWindowGuard;
use crate::events::app_log;
use crate::ip_range_scan;
use crate::ip_target::{self, AnalysisTarget};
use crate::process;
use crate::site_probe;
use crate::site_solution;
use crate::site_verdict::Verdict;

/// Потолок доменов на один прогон: каждый домен добавляет окну секунды
/// (DoH + диагностика), потолок держит окно в разумных пределах.
pub const MASS_MAX: usize = 20;

/// Чем закончилась проба #2 (без обхода) для домена.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OffResult {
    /// Проба #2 не требовалась (домен работал с обходом).
    Untested,
    /// Без обхода работает — обход его ломает.
    Ok,
    /// Без обхода DNS-ошибка.
    Dns,
    /// Сломан и без обхода — заблокирован сам.
    Broken,
    /// Без обхода сервер не отвечает вообще.
    Dead,
}

/// Факты одного домена, собранные в чистом окне.
struct HostFacts {
    off: OffResult,
    main_probe: Option<site_probe::DomainProbe>,
    main_dns_sub: Vec<site_probe::DnsSubstitution>,
    dns_fail_sub: Vec<(String, Vec<site_probe::DnsSubstitution>)>,
    block_scan: Option<ip_range_scan::BlockScanReport>,
}

/// Точка входа массового анализа. Возвращает человеческую сводку прогона;
/// по-доменные отчёты/решения уходят в UI событиями `analysis_progress`.
pub fn run_mass(app: &AppHandle, requested: Vec<String>) -> Result<String, String> {
    let t_total = Instant::now();

    // Нормализация: домены — в общий батч, IP-цели — индивидуально после окна
    // (их путь ip_probe сам рулит обходом, и он не собирает под-ресурсы).
    let mut hosts: Vec<String> = Vec::new();
    let mut ip_rows: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for row in requested {
        let row = row.trim().to_string();
        if row.is_empty() {
            continue;
        }
        match ip_target::parse_target(&row) {
            AnalysisTarget::Domain { host } => {
                if seen.insert(host.clone()) {
                    hosts.push(host);
                }
            }
            AnalysisTarget::Ip { .. } => {
                if seen.insert(row.clone()) {
                    ip_rows.push(row);
                }
            }
        }
    }
    if hosts.len() > MASS_MAX {
        app_log(
            app,
            format!(
                "[Массовый анализ] доменов {} — беру первые {}, остальные — следующим прогоном",
                hosts.len(),
                MASS_MAX
            ),
        );
        hosts.truncate(MASS_MAX);
    }
    if hosts.is_empty() && ip_rows.is_empty() {
        return Err("нет доменов для анализа".to_string());
    }

    for h in &hosts {
        crate::analysis_queue::emit_progress(app, h, "running", None, None);
    }
    for r in &ip_rows {
        crate::analysis_queue::emit_progress(app, r, "running", None, None);
    }

    let bypass_on = process::is_winws_running();
    app_log(
        app,
        format!(
            "[Массовый анализ] старт: {} дом. + {} IP-целей; обход {}",
            hosts.len(),
            ip_rows.len(),
            if bypass_on {
                "включён — будет ОДНО окно без обхода"
            } else {
                "выключен — окно не нужно"
            }
        ),
    );

    // === Фаза 1: проба #1 всех доменов (обход как есть), параллельно ===
    let results_on = analyzer_probe::probe_all(&hosts);
    let on_map: HashMap<String, Probe> = results_on.into_iter().collect();
    let broken_on: Vec<String> = on_map
        .iter()
        .filter_map(|(h, p)| match p {
            Probe::Broken(_) | Probe::DeadIp => Some(h.clone()),
            _ => None,
        })
        .collect();

    // === Фаза 2: чистое окно — ОДНО на всю пачку ===
    let mut facts: HashMap<String, HostFacts> = HashMap::new();
    let mut restore_note: Option<String> = None;
    let bypass_toggled = bypass_on;

    // Итоги пробы #2: заполняются только при включённом обходе.
    let mut off_map: HashMap<String, OffResult> =
        hosts.iter().map(|h| (h.clone(), OffResult::Untested)).collect();

    if bypass_on {
        let off_window = OffWindowGuard::open(app);
        let t_off = Instant::now();

        // Проба #2 сломанных + ретрай (защита от ложных обрывов сразу после
        // выгрузки драйвера — кейс eu.aptabase.com: засчитывается обрыв,
        // увиденный ДВАЖДЫ; Ok/Dns на ретрае перебивают первый обрыв).
        if !broken_on.is_empty() {
            let first_pass: HashMap<String, Probe> =
                analyzer_probe::probe_all(&broken_on).into_iter().collect();
            let to_retry: Vec<String> = first_pass
                .iter()
                .filter_map(|(h, p)| match p {
                    Probe::Broken(_) | Probe::DeadIp => Some(h.clone()),
                    _ => None,
                })
                .collect();
            thread::sleep(std::time::Duration::from_secs(1));
            let retry_pass: HashMap<String, Probe> = if to_retry.is_empty() {
                HashMap::new()
            } else {
                analyzer_probe::probe_all(&to_retry).into_iter().collect()
            };
            for (h, first) in &first_pass {
                let final_res = match first {
                    Probe::Ok => OffResult::Ok,
                    Probe::Dns => OffResult::Dns,
                    Probe::Broken(_) | Probe::DeadIp => match retry_pass.get(h) {
                        Some(Probe::Ok) => OffResult::Ok,
                        Some(Probe::Dns) => OffResult::Dns,
                        Some(Probe::DeadIp) => OffResult::Dead,
                        Some(Probe::Broken(_)) => OffResult::Broken,
                        // Ретрай не вернулся (поток упал) — честнее считать
                        // первый обрыв, чем придумывать результат.
                        None => match first {
                            Probe::DeadIp => OffResult::Dead,
                            _ => OffResult::Broken,
                        },
                    },
                };
                off_map.insert(h.clone(), final_res);
            }
        }

        // DoH-ответы всех доменов пачки — параллельно (по одному потоку на
        // домен; последовательный прогон тянул бы дедлайн DoH на каждый).
        let doh_map = resolve_doh_parallel(&hosts);

        // Диагностика каждого домена — в чистом окне (те же условия, что в
        // одиночном анализе: подмена DNS и CIDR-скан только для сломанных).
        for h in &hosts {
            let main_probe = doh_map
                .get(h)
                .map(|a| site_probe::probe_domain_with_doh(h, a));
            let (main_dns_sub, block_scan) = match &main_probe {
                Some(p) if p.verdict.site_broken() && p.verdict != Verdict::WwwOnly => (
                    doh_map
                        .get(h)
                        .map(|a| site_probe::dns_substitutions_from(h, a, true))
                        .unwrap_or_default(),
                    Some(ip_range_scan::block_diagnose(app, h)),
                ),
                _ => (Vec::new(), None),
            };
            facts.insert(
                h.clone(),
                HostFacts {
                    off: *off_map.get(h).unwrap_or(&OffResult::Untested),
                    main_probe,
                    main_dns_sub,
                    dns_fail_sub: Vec::new(), // заполним после классификации
                    block_scan,
                },
            );
        }

        app_log(
            app,
            format!(
                "[Массовый анализ] окно без обхода заняло {:.1} с",
                t_off.elapsed().as_secs_f64()
            ),
        );
        restore_note = off_window.close();
    } else {
        // Обход и так был выключен: чистое окно не нужно, но фактовая
        // диагностика (DoH/проба домена/CIDR) всё равно нужна.
        let doh_map = resolve_doh_parallel(&hosts);
        for h in &hosts {
            let main_probe = doh_map
                .get(h)
                .map(|a| site_probe::probe_domain_with_doh(h, a));
            let (main_dns_sub, block_scan) = match &main_probe {
                Some(p) if p.verdict.site_broken() && p.verdict != Verdict::WwwOnly => (
                    doh_map
                        .get(h)
                        .map(|a| site_probe::dns_substitutions_from(h, a, true))
                        .unwrap_or_default(),
                    Some(ip_range_scan::block_diagnose(app, h)),
                ),
                _ => (Vec::new(), None),
            };
            facts.insert(
                h.clone(),
                HostFacts {
                    off: OffResult::Untested,
                    main_probe,
                    main_dns_sub,
                    dns_fail_sub: Vec::new(),
                    block_scan,
                },
            );
        }
    }

    // === Фаза 3: классификация + отчёт + решение по каждому домену ===
    // Классификация и подмена DNS для «не резолвящихся» — вне окна: это
    // чистые вычисления и параллельные DoH-пробы (как dns_fail_sub_parallel
    // в одиночном анализе, который тоже идёт после восстановления).
    let mut found = 0usize;
    let mut none = 0usize;
    let mut failed = 0usize;

    // dns_fail всех доменов — одна параллельная проверка подмены DNS.
    let dns_fail_hosts: Vec<String> = hosts
        .iter()
        .filter(|h| match on_map.get(*h) {
            Some(Probe::Dns) => true,
            _ => facts.get(*h).map(|f| f.off == OffResult::Dns).unwrap_or(false),
        })
        .cloned()
        .collect();
    let mut dns_subs: HashMap<String, Vec<site_probe::DnsSubstitution>> = if dns_fail_hosts
        .is_empty()
    {
        HashMap::new()
    } else {
        crate::analyzer::dns_fail_sub_parallel(&dns_fail_hosts, dns_fail_hosts.len())
            .into_iter()
            .collect()
    };

    for h in &hosts {
        let Some(mut f) = facts.remove(h) else {
            failed += 1;
            crate::analysis_queue::emit_progress(
                app,
                h,
                "failed",
                None,
                Some("факты домена не собрались (внутренняя ошибка прогона)".into()),
            );
            continue;
        };
        // Классификация: одна и та же пара проб, что в одиночном анализе.
        let on_probe = on_map.get(h).cloned();
        let mut classification = match f.off {
            OffResult::Untested => {
                analyzer_probe::classify_single(on_probe.into_iter().map(|p| (h.clone(), p)).collect(), &HashSet::new())
            }
            _ => analyzer_probe::classify_dual(
                on_probe.into_iter().map(|p| (h.clone(), p)).collect(),
                &set_if(f.off == OffResult::Broken, h),
                &set_if(f.off == OffResult::Dns, h),
                &set_if(f.off == OffResult::Dead, h),
                &HashSet::new(),
            ),
        };
        // Арбитраж «открытый без обхода главный домен» (кейс eu.aptabase.com).
        let open = f
            .main_probe
            .as_ref()
            .map(|p| p.verdict == Verdict::Open)
            .unwrap_or(false);
        analyzer_probe::arbitrate_open_main_host(&mut classification, on_map.get(h), h, open);
        // Подмена DNS для домена из «не резолвится» — его собственная запись
        // из общей пачки (remove: каждому домену нужна только его).
        f.dns_fail_sub = dns_subs
            .remove(h)
            .map(|subs| vec![(h.clone(), subs)])
            .unwrap_or_default();

        let meta = ReportMeta {
            target_url: ip_target::target_url_of(h),
            discovered: vec![h.clone()],
            bypass_on,
            bypass_toggled,
            restore_note: restore_note.clone(),
            had_browser_failures: false,
            main_probe: f.main_probe,
            main_dns_sub: f.main_dns_sub,
            dns_fail_sub: f.dns_fail_sub,
            block_scan: f.block_scan,
            bypass_map: bypass_lists::load_bypass_domains(),
        };
        let mut report = analyzer_report::build_report(&meta, &classification);
        let solution = site_solution::decide(&meta, &classification);
        report.push_str(&site_solution::report_block(&solution));
        if solution.found {
            found += 1;
        } else {
            none += 1;
        }
        let outcome = DomainAnalysisOutcome { report, solution };
        crate::analysis_queue::emit_progress(app, h, "done", Some(&outcome), None);
    }

    // IP-цели — индивидуально после окна (их путь сам рулит обходом).
    for row in &ip_rows {
        match crate::analyzer::analyze_url(app, row) {
            Ok(o) => {
                if o.solution.found {
                    found += 1;
                } else {
                    none += 1;
                }
                crate::analysis_queue::emit_progress(app, row, "done", Some(&o), None);
            }
            Err(e) => {
                failed += 1;
                crate::analysis_queue::emit_progress(app, row, "failed", None, Some(e));
            }
        }
    }

    Ok(format!(
        "Массовый анализ завершён за {:.1} с: доменов {}, решение найдено для {}, без решения {}, ошибок {}.{}",
        t_total.elapsed().as_secs_f64(),
        hosts.len() + ip_rows.len(),
        found,
        none,
        failed,
        match &restore_note {
            Some(n) => format!(" {}", n),
            None => String::new(),
        }
    ))
}

fn set_if(cond: bool, host: &str) -> HashSet<String> {
    if cond {
        HashSet::from([host.to_string()])
    } else {
        HashSet::new()
    }
}

/// DoH-ответы всех доменов пачки — параллельно (тот же паттерн, что
/// dns_fail_sub_parallel: поток на домен, результат собирается в канал).
fn resolve_doh_parallel(hosts: &[String]) -> HashMap<String, crate::diagnostics_probe::DohAnswers> {
    let (tx, rx) = mpsc::channel::<(usize, (String, crate::diagnostics_probe::DohAnswers))>();
    for (idx, h) in hosts.iter().enumerate() {
        let tx = tx.clone();
        let h = h.clone();
        thread::spawn(move || {
            let answers = site_probe::resolve_doh_answers(&h);
            let _ = tx.send((idx, (h, answers)));
        });
    }
    drop(tx);
    let mut out: HashMap<String, crate::diagnostics_probe::DohAnswers> = HashMap::new();
    for _ in 0..hosts.len() {
        if let Ok((_, (h, answers))) = rx.recv() {
            out.insert(h, answers);
        }
    }
    out
}
