//! Поиск кандидатов-виновников среди доменов списков обхода.
//!
//! Выделен из ip_probe (правило §2.3: файлы ≤500 строк). Чистая механика
//! матчинга: домены списков, чьи DNS-адреса включают целевой IP.
//! Резолвер передаётся параметром ради тестов без сети.
//!
//! Честность подсчёта (core rules §2.2): таймаут резолва — НЕ «резолва нет»,
//! а «не проверено»; такие записи уходят в отдельный счётчик и попадают
//! в отчёт, иначе «проверено X из Y» врёт.
//!
//! IP-литералы в списках резолвить бессмысленно: winws hostlist матчит
//! только имена, поэтому литералы собираются отдельно (категория
//! «записи, по которым матч невозможен»).

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::AppHandle;

use crate::bypass_lists;
use crate::ip_probe::app_log;

/// Размер пачки параллельных резолвов.
const CHUNK: usize = 48;
/// Общий бюджет фазы резолва списков.
const RESOLVE_BUDGET: Duration = Duration::from_secs(90);
/// Таймаут одного системного резолва.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Итог одного резолва: готовый список адресов или «не проверено»
/// (таймаут/ошибка). Замолчавший таймаут НЕ равен «резолва нет».
#[derive(Clone, Debug)]
pub enum ResolveOutcome {
    Ready(Vec<IpAddr>),
    Failed,
}

/// Кандидат-виновник: домен из списков обхода, чьи DNS-адреса
/// включают целевой IP.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub domain: String,
    pub files: Vec<PathBuf>,
    pub ips: Vec<String>,
    /// Запись list-exclude.txt, покрывающая домен (если есть). Совет
    /// «добавьте в exclude» для покрытого домена был бы дезинформацией.
    pub already_excluded: Option<String>,
    /// SNI-проба домена, прибитая сокетом к целевому IP, БЕЗ обхода.
    pub sni_off: Option<crate::analyzer_probe::Probe>,
    /// Та же проба С обходом (выполняется, если обход возвращён).
    pub sni_on: Option<crate::analyzer_probe::Probe>,
}

/// Итог фазы поиска кандидатов.
pub struct ScanOutcome {
    pub candidates: Vec<Candidate>,
    pub ip_literals: Vec<(String, Vec<PathBuf>)>,
    /// Доменных записей проверено (резолв удался).
    pub done: usize,
    /// Доменных записей всего (IP-литералы сюда не входят — они не резолвятся).
    pub total: usize,
    /// Записей с не удавшимся резолвом (таймаут) — НЕ считаются проверенными.
    pub failed: usize,
    pub budget_hit: bool,
}

impl ScanOutcome {
    pub fn empty() -> Self {
        ScanOutcome {
            candidates: Vec::new(),
            ip_literals: Vec::new(),
            done: 0,
            total: 0,
            failed: 0,
            budget_hit: false,
        }
    }
}

/// Ядро поиска кандидатов; резолвер передаётся параметром ради тестов
/// без сети. Не мутирует списки, логирует прогресс по пачкам CHUNK.
/// Честность подсчёта: `total` — только доменные записи; в `done` попадают
/// лишь резолвы, вернувшие `Ready`; таймауты уходят в `failed`.
pub fn scan_candidates<F, P>(
    entries: &[(String, Vec<PathBuf>)],
    target: IpAddr,
    resolve: F,
    mut progress: P,
) -> ScanOutcome
where
    F: Fn(&str) -> ResolveOutcome + Sync + Send + 'static,
    P: FnMut(usize, usize),
{
    let resolve = Arc::new(resolve);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut ip_literals: Vec<(String, Vec<PathBuf>)> = Vec::new();
    let mut seen_lit: HashSet<String> = HashSet::new();

    let mut resolvable: Vec<&(String, Vec<PathBuf>)> = Vec::new();
    for entry in entries {
        // IP-литералы резолвить бессмысленно — откладываем отдельно.
        if entry.0.parse::<IpAddr>().is_ok() {
            if seen_lit.insert(entry.0.clone()) {
                ip_literals.push((entry.0.clone(), entry.1.clone()));
            }
            continue;
        }
        resolvable.push(entry);
    }
    let total = resolvable.len();

    let mut done = 0usize;
    let mut failed = 0usize;
    let mut budget_hit = false;

    let deadline = Instant::now() + RESOLVE_BUDGET;

    for chunk in resolvable.chunks(CHUNK) {
        if Instant::now() >= deadline {
            budget_hit = true;
            break;
        }
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for (domain, files) in chunk {
                let domain = domain.clone();
                let files = files.clone();
                let r = Arc::clone(&resolve);
                handles.push(scope.spawn(move || {
                    let ips = r(&domain);
                    (domain, files, ips)
                }));
            }
            for h in handles {
                if let Ok((domain, files, outcome)) = h.join() {
                    match outcome {
                        ResolveOutcome::Ready(ips) => {
                            done += 1;
                            if ips.contains(&target) {
                                let ips: Vec<String> =
                                    ips.iter().map(|i| i.to_string()).collect();
                                candidates.push(Candidate {
                                    domain,
                                    files,
                                    ips,
                                    already_excluded: None,
                                    sni_off: None,
                                    sni_on: None,
                                });
                            }
                        }
                        ResolveOutcome::Failed => {
                            failed += 1;
                        }
                    }
                }
            }
        });
        progress(done, total);
    }
    if budget_hit {
        // Честно доносим, что бюджет кончился не на пустом месте.
        progress(done, total);
    }

    candidates.sort_by(|a, b| a.domain.cmp(&b.domain));

    ScanOutcome {
        candidates,
        ip_literals,
        done,
        total,
        failed,
        budget_hit,
    }
}

/// Обёртка кандидатов над системным резолвером с жёстким таймаутом.
pub fn scan_candidates_with_system_dns(
    app: &AppHandle,
    map: &bypass_lists::BypassMap,
    target: IpAddr,
) -> ScanOutcome {
    use std::sync::mpsc;
    use std::thread;

    const ECHO_EVERY: usize = 64;

    let resolve = |domain: &str| -> ResolveOutcome {
        let (tx, rx) = mpsc::channel();
        let d = domain.to_string();
        thread::spawn(move || {
            let _ = tx.send(crate::diagnostics_probe::resolve_system(&d));
        });
        rx.recv_timeout(RESOLVE_TIMEOUT)
            .map(ResolveOutcome::Ready)
            .unwrap_or(ResolveOutcome::Failed)
    };

    let progress_cb = {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        move |done: usize, total: usize| {
            let cur = counter.load(std::sync::atomic::Ordering::Relaxed);
            if done >= cur + ECHO_EVERY || done == total {
                counter.store(done, std::sync::atomic::Ordering::Relaxed);
                app_log(app, format!("[Анализ IP] Резолвим списки: {}/{}...", done, total));
            }
        }
    };

    let mut entries: Vec<(String, Vec<PathBuf>)> = map
        .iter()
        .map(|(domain, files)| (domain.clone(), files.clone()))
        .collect();
    entries.sort();

    scan_candidates(&entries, target, resolve, progress_cb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn target() -> IpAddr {
        "172.65.90.21".parse().unwrap()
    }

    fn entry(d: &str) -> (String, Vec<PathBuf>) {
        (d.to_string(), vec![PathBuf::from("lists/list-general.txt")])
    }

    fn with_resolver(
        entries: Vec<(String, Vec<PathBuf>)>,
        target: IpAddr,
        resolve: impl Fn(&str) -> ResolveOutcome + Sync + Send + 'static,
    ) -> ScanOutcome {
        scan_candidates(&entries, target, resolve, |_, _| {})
    }

    #[test]
    fn only_matching_domain_becomes_candidate() {
        let t = target();
        let entries = vec![entry("a.org"), entry("b.org"), entry("1.2.3.4")];
        let out = with_resolver(entries, t, move |d| {
            if d == "a.org" {
                ResolveOutcome::Ready(vec![t])
            } else if d == "b.org" {
                ResolveOutcome::Ready(vec!["93.184.216.34".parse().unwrap()])
            } else {
                ResolveOutcome::Ready(vec![])
            }
        });
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].domain, "a.org");
        assert_eq!(out.done, out.total);
        assert_eq!(out.total, 2);
        assert!(!out.budget_hit);
    }

    #[test]
    fn ip_literals_are_collected_not_resolved() {
        let t = target();
        let entries = vec![entry("1.2.3.4"), entry("site.com")];
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        let out = with_resolver(entries, t, move |d: &str| {
            seen2.lock().unwrap().push(d.to_string());
            ResolveOutcome::Ready(vec![])
        });
        assert_eq!(out.ip_literals.len(), 1);
        assert_eq!(out.ip_literals[0].0, "1.2.3.4");
        // IP-литерал не должен идти в резолвер.
        let seen = seen.lock().unwrap();
        assert!(!seen.contains(&"1.2.3.4".to_string()));
        assert!(seen.contains(&"site.com".to_string()));
    }

    #[test]
    fn duplicate_ip_literal_deduplicated() {
        let t = target();
        let entries = vec![entry("1.2.3.4"), entry("1.2.3.4")];
        let out = with_resolver(entries, t, |_| ResolveOutcome::Ready(vec![]));
        assert_eq!(out.ip_literals.len(), 1);
    }

    #[test]
    fn full_progress_reported() {
        // Прогон без бюджета: все записи посчитаны, budget_hit не поднят
        // (бюджетная ветка проверяется чтением кода — в тесте бюджет
        // константный и её гонять не будем).
        let t = target();
        let entries: Vec<_> = (0..10).map(|i| entry(&format!("d{}.org", i))).collect();
        let out = with_resolver(entries, t, |_| ResolveOutcome::Ready(vec![]));
        assert_eq!(out.done, out.total);
        assert_eq!(out.failed, 0);
        assert!(!out.budget_hit);
    }

    #[test]
    fn resolve_timeout_is_counted_as_not_checked() {
        // Честность подсчёта: не удавшийся резолв не считается «проверено»,
        // иначе «проверено X из Y» врёт (core rules §2.2).
        let t = target();
        let entries = vec![entry("ok.org"), entry("slow.org")];
        let out = with_resolver(entries, t, |d| {
            if d == "ok.org" {
                ResolveOutcome::Ready(vec![])
            } else {
                ResolveOutcome::Failed
            }
        });
        assert_eq!(out.done, 1);
        assert_eq!(out.failed, 1);
        assert_eq!(out.total, 2);
        assert_eq!(out.candidates.len(), 0);
    }

    #[test]
    fn candidate_carries_sni_slots_and_exclusion() {
        // Поля sni_off/sni_on/already_excluded рождаются пустыми — их
        // заполняет оркестрация фаз в ip_probe, не матчинг.
        let t = target();
        let entries = vec![entry("a.org")];
        let out = with_resolver(entries, t, move |d| {
            if d == "a.org" {
                ResolveOutcome::Ready(vec![t])
            } else {
                ResolveOutcome::Ready(vec![])
            }
        });
        assert_eq!(out.candidates.len(), 1);
        assert!(out.candidates[0].sni_off.is_none());
        assert!(out.candidates[0].sni_on.is_none());
        assert!(out.candidates[0].already_excluded.is_none());
    }
}
