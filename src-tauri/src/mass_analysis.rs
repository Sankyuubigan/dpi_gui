//! Массовый анализ списка «Ошибки сети» за ОДНО окно «обход выключен».
//!
//! Мотивация (инцидент 27.10.26): авто-анализ по одному домену глушал обход
//! чаще, чем он был включён — фича сделала обход бесполезным. Массовый анализ
//! меняет форму (core §1.10): факты для ВСЕХ доменов пачки собираются в одном
//! окне — одно выключение/включение на прогон вместо N.
//!
//! Порядок фаз:
//! 1. Проба #1 всех доменов (обход в текущем состоянии), параллельно.
//! 2. Если обход был включён — ОДНО окно без обхода, и ТОЛЬКО для сломанных:
//!    проба #2 + ретраи, проверка подмены DNS «не резолвящихся», полная
//!    диагностика сломанных (DoH-проба, CIDR-скан) — параллельно, поток на
//!    домен. Остальные домены получают лёгкую пробу ПОСЛЕ восстановления
//!    обхода: их вердикт («сайт открывается») от чистого окна не зависит.
//!    Если обход был выключен — окно не открывается вовсе.
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

/// Потолок доменов на один прогон: каждый сломанный домен добавляет окну
/// секунды (DoH + диагностика), потолок держит окно в разумных пределах.
pub const MASS_MAX: usize = 20;

/// Факты одного домена, собранные в чистом окне.
struct HostFacts {
    /// Итог пробы #2 (без обхода). None — проба не требовалась: домен
    /// работал уже с обходом, чистый замер ему не нужен.
    off: Option<analyzer_probe::OffProbe>,
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

    // === Фаза 2: чистое окно — ОДНО на всю пачку, и ТОЛЬКО для сломанных ===
    let bypass_toggled = bypass_on;

    // Лёгкие домены (открывшиеся с обходом / не резолвящиеся): их вердикт
    // («сайт открывается», «DNS не отвечает») от чистого окна не зависит —
    // им хватает лёгкой пробы в рабочем режиме после восстановления обхода.
    // Чистый замер нужен только сломанным, поэтому окно в разы короче.
    let light_hosts: Vec<String> = hosts
        .iter()
        .filter(|h| !broken_on.contains(h))
        .cloned()
        .collect();

    let (facts_broken, mut dns_subs, restore_note) = if bypass_on {
        let off_window = OffWindowGuard::open(app);
        let t_off = Instant::now();

        // Итоги пробы #2 (без обхода): запись есть только у доменов,
        // сломанных с обходом; отсутствие записи = проба не требовалась.
        let mut off_map: HashMap<String, analyzer_probe::OffProbe> = HashMap::new();

        // Проба #2 сломанных + ретрай — общий рецепт с одиночным анализом
        // (analyzer_probe::probe_off, SSOT): обрыв засчитывается, только
        // если увиден ДВАЖДЫ (кейс eu.aptabase.com).
        off_map.extend(analyzer_probe::probe_off(&broken_on));

        // Проверка подмены DNS — внутри окна (как в одиночном анализе:
        // их TCP-пробы не должны идти через активный обход).
        let dns_fail_hosts = dns_fail_hosts_of(&hosts, &on_map, &off_map);
        let dns_subs = dns_fail_subs(&dns_fail_hosts);

        // Полная диагностика сломанных — в чистом окне, параллельно
        // (поток на домен: CIDR-скан одного домена не задерживает остальных).
        let facts_broken = collect_facts_off(app, &broken_on, &off_map);

        app_log(
            app,
            format!(
                "[Массовый анализ] окно без обхода заняло {:.1} с",
                t_off.elapsed().as_secs_f64()
            ),
        );
        let restore_note = off_window.close();
        (facts_broken, dns_subs, restore_note)
    } else {
        // Обход и так был выключен: чистые условия есть без окна.
        let facts_broken = collect_facts_off(app, &broken_on, &HashMap::new());

        let dns_fail_hosts = dns_fail_hosts_of(&hosts, &on_map, &HashMap::new());
        let dns_subs = dns_fail_subs(&dns_fail_hosts);
        (facts_broken, dns_subs, None)
    };

    // Лёгкие факты остальных доменов — в рабочем режиме (обход как был).
    let mut facts = facts_broken;
    facts.extend(collect_facts_on(&light_hosts));

    // === Фаза 3: классификация + отчёт + решение по каждому домену ===
    // Классификация — вне окна: это чистые вычисления над уже собранными
    // фактами (те же classify_single/classify_dual, что в одиночном анализе).
    let mut found = 0usize;
    let mut none = 0usize;
    let mut failed = 0usize;

    // SSOT: карты списков загружаются РАЗ на прогон — решение по каждому
    // домену потребляет одни данные (как в одиночном анализе).
    let bypass_map = bypass_lists::load_bypass_domains();
    let exclude_set = bypass_lists::load_exclude_domains();

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
            None => {
                analyzer_probe::classify_single(on_probe.into_iter().map(|p| (h.clone(), p)).collect(), &HashSet::new())
            }
            Some(off) => analyzer_probe::classify_dual(
                on_probe.into_iter().map(|p| (h.clone(), p)).collect(),
                &set_if(off == analyzer_probe::OffProbe::Broken, h),
                &set_if(off == analyzer_probe::OffProbe::Dns, h),
                &set_if(off == analyzer_probe::OffProbe::Dead, h),
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
            bypass_map: bypass_map.clone(),
            exclude_set: exclude_set.clone(),
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

/// Домены из «не резолвится»: DNS-ошибка в пробе #1 (с обходом) или в
/// пробе #2 (без обхода).
fn dns_fail_hosts_of(
    hosts: &[String],
    on_map: &HashMap<String, Probe>,
    off_map: &HashMap<String, analyzer_probe::OffProbe>,
) -> Vec<String> {
    hosts
        .iter()
        .filter(|h| match on_map.get(*h) {
            Some(Probe::Dns) => true,
            _ => off_map.get(*h) == Some(&analyzer_probe::OffProbe::Dns),
        })
        .cloned()
        .collect()
}

/// Одна параллельная проверка подмены DNS для всех dns_fail доменов пачки.
fn dns_fail_subs(
    dns_fail_hosts: &[String],
) -> HashMap<String, Vec<site_probe::DnsSubstitution>> {
    if dns_fail_hosts.is_empty() {
        HashMap::new()
    } else {
        crate::analyzer::dns_fail_sub_parallel(dns_fail_hosts, dns_fail_hosts.len())
            .into_iter()
            .collect()
    }
}

/// Полная диагностика СЛОМАННЫХ доменов из «чистых» условий (вызывать только
/// там, где обход гарантированно не работает: в реальном окне после
/// `OffWindowGuard::open` либо когда обход и так был выключен). Параллельно,
/// поток на домен: CIDR-скан одного домена не задерживает остальных.
fn collect_facts_off(
    app: &AppHandle,
    broken_on: &[String],
    off_map: &HashMap<String, analyzer_probe::OffProbe>,
) -> HashMap<String, HostFacts> {
    let (tx, rx) = mpsc::channel::<(String, HostFacts)>();
    for h in broken_on {
        let off = off_map.get(h).copied();
        let tx = tx.clone();
        let h = h.clone();
        let app = app.clone();
        thread::spawn(move || {
            let answers = site_probe::resolve_doh_answers(&h);
            let main_probe = site_probe::probe_domain_with_doh(&h, &answers);
            let (main_dns_sub, block_scan) =
                if main_probe.verdict.site_broken() && main_probe.verdict != Verdict::WwwOnly {
                    (
                        site_probe::dns_substitutions_from(&h, &answers, true),
                        Some(ip_range_scan::block_diagnose(&app, &h)),
                    )
                } else {
                    (Vec::new(), None)
                };
            let _ = tx.send((
                h,
                HostFacts {
                    off,
                    main_probe: Some(main_probe),
                    main_dns_sub,
                    dns_fail_sub: Vec::new(), // заполним после классификации
                    block_scan,
                },
            ));
        });
    }
    drop(tx);
    let mut facts: HashMap<String, HostFacts> = HashMap::new();
    for _ in 0..broken_on.len() {
        if let Ok((h, f)) = rx.recv() {
            facts.insert(h, f);
        }
    }
    facts
}

/// Лёгкие факты доменов, которым чистый замер не нужен (открывшиеся с
/// обходом / не резолвящиеся): одна DoH-проба в рабочем режиме — том же,
/// в котором домен реально используется. Параллельно, после окна.
fn collect_facts_on(light_hosts: &[String]) -> HashMap<String, HostFacts> {
    let (tx, rx) = mpsc::channel::<(String, site_probe::DomainProbe)>();
    for h in light_hosts {
        let tx = tx.clone();
        let h = h.clone();
        thread::spawn(move || {
            let answers = site_probe::resolve_doh_answers(&h);
            let probe = site_probe::probe_domain_with_doh(&h, &answers);
            let _ = tx.send((h, probe));
        });
    }
    drop(tx);
    let mut facts: HashMap<String, HostFacts> = HashMap::new();
    for _ in 0..light_hosts.len() {
        if let Ok((h, probe)) = rx.recv() {
            facts.insert(
                h,
                HostFacts {
                    off: None,
                    main_probe: Some(probe),
                    main_dns_sub: Vec::new(),
                    dns_fail_sub: Vec::new(),
                    block_scan: None,
                },
            );
        }
    }
    facts
}
