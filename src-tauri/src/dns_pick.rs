//! Скрипт подбора рабочего DNS (кнопка «Подбор рабочего DNS»).
//!
//! Универсальная архитектура (переработка 01.11.26 после кейса Patreon —
//! НЕ возвращаться к эвристике по диапазонам Google):
//!
//! 1. Слой DNS: `resolve_doh_all` опрашивает все DoH-сервисы.
//! 2. Классификация ответов БЕЗ угадывания по ownership IP:
//!    - `Dead` — не ответил / только заглушки;
//!    - `Gateway` — отдал СВОИ адреса (`DohAnswers::gateway_owner`):
//!      фронтинг-шлюзы, браузер пойдёт через сервис (кейс eu.geohide.ru);
//!    - `Resolves` — консенсус большинства (если повторяющихся сетов нет
//!      вообще — GeoDNS-норма «у каждого свои», все считаются Resolves);
//!    - `Diverges` — расходится с консенсусом большинства.
//!    Прежняя эвристика «IP вне диапазонов Google = проксирует» была
//!    хардкодом под один кейс: для сайтов не на Google (Patreon на
//!    Cloudflare) «ПРОКСИРУЕТ (РАБОЧИЙ)» получал даже dns.google, который
//!    ничего не проксирует — он просто честно резолвит.
//! 3. Сквозная проверка (слой «открывается ли сайт»):
//!    - не-шлюзовые сеты — HTTP-проба `site_probe::probe_https_by_ip`
//!      (SSOT): `Open` / `SiteBlocked` (403/блок-страница/«регион» — отказ
//!      самого сайта; у Cloudflare это в т.ч. ошибка 1009 — страна
//!      забанена владельцем) / `DpiBlocked` (RST/TLS — лечится обходом
//!      winws) / `Unreachable`;
//!    - шлюзовые сеты HTTP-пробой проверять НЕЛЬЗЯ: шлюз может отдать
//!      свой 200, не являющийся страницей сайта (документировано в доке
//!      `DohAnswers::own_ips`, кейс openrouter.ai/80.74.30.162) — им
//!      только TCP-живость `site_probe::tcp_scan_parallel`.
//!
//! Посессионный гео-блок (кейс aistudio.google.com, пробы 28.10.26): проба
//! с исходного IP видит страницу (часто с «регион ограничен» —
//! ServiceRestrict), блок срабатывает после логина и привязан к ИСХОДНОМУ
//! IP клиента. Поэтому живой Gateway остаётся единственным DNS-фиксом и
//! рекомендуется даже при «не-Open» пробе честных адресов.

use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config;
use crate::diagnostics_probe::{self, is_stub_ip, DohAnswers, HttpResult};
use crate::ip_target;
use crate::site_probe::{probe_https_by_ip, substitution_note, tcp_scan_parallel};

/// Лимит HTTP-проб: уникальных сетов адресов и адресов внутри сета.
const MAX_PROBE_SETS: usize = 4;
const MAX_PROBE_IPS: usize = 2;
/// Дедлайн сбора HTTP-проб (клиентский таймаут одной пробы — 6 с).
const PROBE_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResolverKind {
    /// Отдал собственные адреса-шлюзы (фронтинг): браузер пойдёт через сервис.
    Gateway,
    /// Адреса совпадают с консенсусом большинства (или большинства нет —
    /// GeoDNS-норма «у каждого свои»).
    Resolves,
    /// Адреса расходятся с консенсусом большинства.
    Diverges,
    /// Сервис не ответил / не дал адресов.
    Dead,
}

/// Сквозная проверка адресов резолвера (слой «открывается ли сайт»).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProbeVerdict {
    /// Сайт открылся (HTTP 2xx/3xx без маркеров ограничения).
    Open,
    /// Отказ самого сайта: 403/451, блок-страница, «регион ограничен».
    /// У Cloudflare это в т.ч. ошибка 1009 — страну забанил владелец.
    SiteBlocked,
    /// Транспорт/TLS сломан (RST/TLS/BadCert) — лечится обходом winws.
    DpiBlocked,
    /// Адрес не отвечает (таймаут/прочее).
    Unreachable,
    /// Шлюз DoH-сервиса отвечает по TCP:443. HTTP-проба шлюзам запрещена:
    /// их 200 не является страницей сайта (дока DohAnswers::own_ips).
    GatewayAlive,
    /// Шлюз не отвечает даже по TCP.
    GatewayDead,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickEntry {
    pub service: String,
    pub resolved: Vec<String>,
    pub kind: ResolverKind,
    pub note: String,
    /// Результат сквозной проверки (None — Dead: проверять нечего).
    pub probe: Option<ProbeVerdict>,
    pub probe_note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickOutcome {
    pub domain: String,
    pub entries: Vec<DnsPickEntry>,
    /// Итоговая строка — единый текст для лог-панели (SSOT).
    pub summary: String,
    /// "ok" | "warn" | "fail" — уровень итога; фронт рендерит по нему,
    /// не снифая текст summary.
    pub verdict_level: String,
}

/// Результат чистой классификации ответов: entries + что и как проверять.
#[derive(Debug)]
pub struct Classification {
    pub entries: Vec<DnsPickEntry>,
    /// Уникальные не-шлюзовые сеты адресов для HTTP-проб: (ключ, адреса).
    /// Консенсус-сет первым. Ключ — нормализованный (отсортированный) список.
    pub site_sets: Vec<(String, Vec<IpAddr>)>,
    /// entry[i] → ключ его сета (None — Dead/Gateway).
    pub entry_set: Vec<Option<String>>,
    /// entry[i] → адреса сайта из его ответа (наследование пробы по IP,
    /// когда свой сет не попал в лимит проб).
    pub entry_site_ips: Vec<Option<Vec<IpAddr>>>,
    /// entry[i] → собственные шлюзы сервиса (чистые Gateway) для TCP-пробы.
    pub entry_gateways: Vec<Option<Vec<IpAddr>>>,
}

/// Ключ сета адресов: сортировка + склейка — одинаковые наборы дают равные
/// ключи независимо от порядка в ответе.
fn set_key(ips: &[IpAddr]) -> String {
    ips.iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Строка адресов для заметок: не больше 3, дальше «…» с количеством.
fn ips_str(ips: &[IpAddr]) -> String {
    let all: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    if all.len() <= 3 {
        all.join(", ")
    } else {
        format!("{}, … (всего {})", all[..3].join(", "), all.len())
    }
}

/// Чистая классификация ответов DoH-сервисов (без сети) — покрыта тестами.
pub fn pick_resolvers(answers: &DohAnswers) -> Classification {
    // 1) Черновик: раскладка каждого ответа на «свои шлюзы» и «адреса сайта».
    struct Draft {
        service: String,
        resolved: Vec<String>,
        gateway_ips: Vec<IpAddr>,
        site_ips: Vec<IpAddr>,
        key: String,
        error: Option<String>,
    }
    let mut drafts: Vec<Draft> = Vec::new();
    for a in &answers.answers {
        let (service, error) = match &a.error {
            Some(err) => (a.service.clone(), Some(err.clone())),
            None => (a.service.clone(), None),
        };
        let real: Vec<IpAddr> = a.ips.iter().copied().filter(|ip| !is_stub_ip(ip)).collect();
        let (gateway_ips, site_ips): (Vec<_>, Vec<_>) = real
            .iter()
            .copied()
            .partition(|ip| answers.gateway_owner(ip).is_some());
        let key = if site_ips.is_empty() {
            String::new()
        } else {
            set_key(&site_ips)
        };
        drafts.push(Draft {
            resolved: real.iter().map(|i| i.to_string()).collect(),
            service,
            gateway_ips,
            site_ips,
            key,
            error,
        });
    }

    // 2) Консенсус: самый частый не-пустой сет (ничья по частоте — больший
    // сет, затем более раннее появление). Повторяющихся сетов нет вообще —
    // консенсуса нет (GeoDNS-норма, все считаются Resolves).
    let mut freq: Vec<(String, usize, usize, usize)> = Vec::new(); // key, count, size, first
    for (idx, d) in drafts.iter().enumerate() {
        if d.key.is_empty() {
            continue;
        }
        match freq.iter_mut().find(|f| f.0 == d.key) {
            Some(f) => f.1 += 1,
            None => freq.push((d.key.clone(), 1, d.site_ips.len(), idx)),
        }
    }
    let consensus = freq
        .iter()
        .filter(|f| f.1 > 1)
        .max_by_key(|f| (f.1, f.2, std::cmp::Reverse(f.3)))
        .map(|f| f.0.clone());

    // 3) Пул «подтверждено большинством»: адреса, возвращённые ≥2 сервисами
    // (не-шлюзовыми). Резолвер с подмножеством пула честен (ответ из одного
    // A — норма DNS); подозрительно только то, чего в пуле нет вовсе.
    // Пула нет (у всех свои адреса) — GeoDNS-норма, все считаются Resolves.
    let mut ip_freq: HashMap<&IpAddr, usize> = HashMap::new();
    for d in &drafts {
        if d.key.is_empty() {
            continue;
        }
        for ip in &d.site_ips {
            *ip_freq.entry(ip).or_insert(0) += 1;
        }
    }
    let pool: BTreeSet<IpAddr> = ip_freq
        .into_iter()
        .filter(|(_, cnt)| *cnt >= 2)
        .map(|(ip, _)| *ip)
        .collect();

    // 4) Записи по сервисам.
    let mut entries = Vec::new();
    let mut entry_set: Vec<Option<String>> = Vec::new();
    let mut entry_site_ips: Vec<Option<Vec<IpAddr>>> = Vec::new();
    let mut entry_gateways: Vec<Option<Vec<IpAddr>>> = Vec::new();
    for d in &drafts {
        match &d.error {
            Some(err) => {
                entries.push(DnsPickEntry {
                    service: d.service.clone(),
                    resolved: Vec::new(),
                    kind: ResolverKind::Dead,
                    note: err.clone(),
                    probe: None,
                    probe_note: String::new(),
                });
                entry_set.push(None);
                entry_site_ips.push(None);
                entry_gateways.push(None);
            }
            None => {
                if d.gateway_ips.is_empty() && d.site_ips.is_empty() {
                    // Только заглушки (0.0.0.0 и т.п.) — проверять нечего.
                    entries.push(DnsPickEntry {
                        service: d.service.clone(),
                        resolved: Vec::new(),
                        kind: ResolverKind::Dead,
                        note: "не вернул адресов (или только заглушки)".to_string(),
                        probe: None,
                        probe_note: String::new(),
                    });
                    entry_set.push(None);
                    entry_site_ips.push(None);
                    entry_gateways.push(None);
                    continue;
                }
                let note_gw = if d.gateway_ips.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; частично отдаёт свои шлюзы ({})",
                        ips_str(&d.gateway_ips)
                    )
                };
                let (kind, note, key) = if d.site_ips.is_empty() {
                    (
                        ResolverKind::Gateway,
                        format!(
                            "отдаёт собственные шлюзы ({}) — трафик пойдёт через сервис (фронтинг)",
                            ips_str(&d.gateway_ips)
                        ),
                        None,
                    )
                } else {
                    let base = if pool.is_empty() {
                        (
                            ResolverKind::Resolves,
                            format!(
                                "у каждого сервиса свои адреса (GeoDNS-норма): {}",
                                ips_str(&d.site_ips)
                            ),
                        )
                    } else {
                        let outside: Vec<IpAddr> = d
                            .site_ips
                            .iter()
                            .copied()
                            .filter(|ip| !pool.contains(ip))
                            .collect();
                        if outside.is_empty() {
                            (
                                ResolverKind::Resolves,
                                "резолвит верно: все адреса подтверждены большинством сервисов"
                                    .to_string(),
                            )
                        } else {
                            let pool_str =
                                ips_str(&pool.iter().copied().collect::<Vec<_>>());
                            (
                                ResolverKind::Diverges,
                                format!(
                                    "адреса ({}) расходятся с большинством (пул: {}); для GeoDNS-доменов это норма — подмену отсечёт проба",
                                    ips_str(&outside),
                                    pool_str
                                ),
                            )
                        }
                    };
                    (base.0, format!("{}{}", base.1, note_gw), Some(d.key.clone()))
                };
                entries.push(DnsPickEntry {
                    service: d.service.clone(),
                    resolved: d.resolved.clone(),
                    kind,
                    note,
                    probe: None,
                    probe_note: String::new(),
                });
                entry_set.push(key);
                entry_site_ips.push(Some(d.site_ips.clone()));
                entry_gateways.push(
                    (!d.gateway_ips.is_empty() && d.site_ips.is_empty())
                        .then(|| d.gateway_ips.clone()),
                );
            }
        }
    }

    // 5) Сеты для HTTP-проб: консенсус первым, остальные по появлению.
    let ip_by_key = |key: &str| {
        drafts
            .iter()
            .find(|d| d.key == key)
            .map(|d| d.site_ips.clone())
            .unwrap_or_default()
    };
    let mut site_sets: Vec<(String, Vec<IpAddr>)> = Vec::new();
    if let Some(c) = &consensus {
        site_sets.push((c.clone(), ip_by_key(c)));
    }
    for f in &freq {
        if Some(&f.0) != consensus.as_ref() {
            site_sets.push((f.0.clone(), ip_by_key(&f.0)));
        }
    }

    Classification {
        entries,
        site_sets,
        entry_set,
        entry_site_ips,
        entry_gateways,
    }
}

/// Агрегат HTTP-проб одного сета: самая информативная проба решает
/// (Open > отказ сайта > сломанный TLS > не отвечает). Чистая функция.
fn aggregate_site_set(results: &[(IpAddr, HttpResult)]) -> (ProbeVerdict, String) {
    let prio = |r: &HttpResult| match r {
        HttpResult::Ok(_) => 0,
        HttpResult::Forbidden(_) | HttpResult::BlockPage | HttpResult::ServiceRestrict => 1,
        HttpResult::Rst | HttpResult::Tls | HttpResult::BadCert => 2,
        _ => 3,
    };
    let (ip, best) = results
        .iter()
        .min_by_key(|(_, r)| prio(r))
        .expect("агрегат пустого сета");
    let verdict = match best {
        HttpResult::Ok(_) => ProbeVerdict::Open,
        HttpResult::Forbidden(_) | HttpResult::BlockPage | HttpResult::ServiceRestrict => {
            ProbeVerdict::SiteBlocked
        }
        HttpResult::Rst | HttpResult::Tls | HttpResult::BadCert => ProbeVerdict::DpiBlocked,
        _ => ProbeVerdict::Unreachable,
    };
    (verdict, format!("{} ({})", substitution_note(best), ip))
}

/// TCP-живость шлюзового сета (HTTP-проба шлюзам запрещена — их 200 не
/// является страницей сайта).
fn gateway_tcp_probe(ips: &[IpAddr]) -> (ProbeVerdict, String) {
    let res = tcp_scan_parallel(ips);
    let alive: Vec<&IpAddr> = ips.iter().zip(res.iter()).filter(|(_, s)| s.as_str() == "Success").map(|(ip, _)| ip).collect();
    if let Some(first) = alive.first() {
        (
            ProbeVerdict::GatewayAlive,
            format!("шлюз {} отвечает на :443", first),
        )
    } else {
        (
            ProbeVerdict::GatewayDead,
            "шлюз не отвечает даже по TCP:443".to_string(),
        )
    }
}

/// HTTP-пробы не-шлюзовых сетов, параллельно (до MAX_PROBE_SETS сетов,
/// до MAX_PROBE_IPS адресов в каждом). Возврат: агрегаты по ключам сетов +
/// сырые результаты по каждому IP (для наследования проб записями, чей сет
/// не попал в лимит, но адреса проверялись в составе других сетов).
fn run_site_probes(
    host: &str,
    site_sets: &[(String, Vec<IpAddr>)],
) -> (
    HashMap<String, (ProbeVerdict, String)>,
    HashMap<IpAddr, HttpResult>,
) {
    let (tx, rx) = mpsc::channel::<(String, IpAddr, HttpResult)>();
    let mut jobs = 0usize;
    for (key, ips) in site_sets.iter().take(MAX_PROBE_SETS) {
        for ip in ips.iter().take(MAX_PROBE_IPS) {
            let tx = tx.clone();
            let key = key.clone();
            let host = host.to_string();
            let ip = *ip;
            thread::spawn(move || {
                let r = probe_https_by_ip(&host, ip);
                let _ = tx.send((key, ip, r));
            });
            jobs += 1;
        }
    }
    drop(tx);

    let mut per_set: HashMap<String, Vec<(IpAddr, HttpResult)>> = HashMap::new();
    let deadline = Instant::now() + PROBE_DEADLINE;
    let mut got = 0usize;
    while got < jobs {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((key, ip, r)) => {
                per_set.entry(key).or_default().push((ip, r));
                got += 1;
            }
            Err(_) => break,
        }
    }
    let mut per_ip: HashMap<IpAddr, HttpResult> = HashMap::new();
    for results in per_set.values() {
        for (ip, r) in results {
            // На каждый адрес — ровно одна проба, перезапись невозможна.
            per_ip.insert(*ip, r.clone());
        }
    }
    let site = per_set
        .into_iter()
        .map(|(k, v)| (k, aggregate_site_set(&v)))
        .collect();
    (site, per_ip)
}

/// Прикрутка результатов проб к записям. Чистая функция — покрыта тестами.
fn attach_probes(
    mut class: Classification,
    site: &HashMap<String, (ProbeVerdict, String)>,
    per_ip: &HashMap<IpAddr, HttpResult>,
    gateways: &HashMap<String, (ProbeVerdict, String)>,
) -> Vec<DnsPickEntry> {
    for (i, e) in class.entries.iter_mut().enumerate() {
        if let Some(key) = &class.entry_set[i] {
            if let Some((v, n)) = site.get(key) {
                e.probe = Some(*v);
                e.probe_note = n.clone();
                continue;
            }
            // Свой сет не попал в лимит проб — но его адреса могли быть
            // проверены в составе других сетов: наследуем по IP.
            let inherited: Vec<(IpAddr, HttpResult)> = class.entry_site_ips[i]
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|ip| per_ip.get(ip).map(|r| (*ip, r.clone())))
                .collect();
            if inherited.is_empty() {
                e.probe_note = "HTTP-проба не выполнялась (лимит сетов)".to_string();
            } else {
                let (v, n) = aggregate_site_set(&inherited);
                e.probe = Some(v);
                e.probe_note = format!("{} — по адресам из других сетов", n);
            }
        } else if let Some(gips) = &class.entry_gateways[i] {
            if let Some((v, n)) = gateways.get(&set_key(gips)) {
                e.probe = Some(*v);
                e.probe_note = n.clone();
            }
        }
    }
    class.entries
}

/// Итоговая строка + уровень по приоритету честных исходов:
/// открылся пробой > живой фронтинг-шлюз > отказ сайта (VPN) > DPI > ничего.
/// Чистая функция — покрыта тестами.
fn build_summary(host: &str, entries: &[DnsPickEntry]) -> (String, &'static str) {
    if let Some(e) = entries.iter().find(|e| e.probe == Some(ProbeVerdict::Open)) {
        return (
            format!(
                "Рабочий DNS: {} — проверено пробой ({}): {} открывается через адреса этого резолвера. Включите его как Secure DNS в браузере: https://{}/dns-query",
                e.service, e.probe_note, host, e.service
            ),
            "ok",
        );
    }
    if let Some(e) = entries
        .iter()
        .find(|e| e.kind == ResolverKind::Gateway && e.probe == Some(ProbeVerdict::GatewayAlive))
    {
        return (
            format!(
                "Рабочий DNS: {} — отдаёт собственные шлюзы для {}: трафик пойдёт через сервис, сайт будет видеть IP шлюза, а не ваш (кейс посессионного гео-блока). Включите его как Secure DNS в браузере: https://{}/dns-query",
                e.service, host, e.service
            ),
            "ok",
        );
    }
    if let Some(e) = entries
        .iter()
        .find(|e| e.probe == Some(ProbeVerdict::SiteBlocked))
    {
        return (
            format!(
                "DNS-резолверы исправны и отдают настоящие адреса {}, но сайт сам отказывает: {}. Это гео-блок/WAF на стороне сайта (у Cloudflare — в т.ч. ошибка 1009 «Access denied»): поможет только VPN/прокси — смена DNS и запись в hosts бессильны",
                host, e.probe_note
            ),
            "fail",
        );
    }
    if let Some(e) = entries
        .iter()
        .find(|e| e.probe == Some(ProbeVerdict::DpiBlocked))
    {
        return (
            format!(
                "Резолверы отдают настоящие адреса {}, но TLS до сайта режется (DPI): {}. Включите обход (winws) — смена DNS сама по себе сайт не откроет",
                host, e.probe_note
            ),
            "warn",
        );
    }
    let causes: Vec<String> = entries
        .iter()
        .filter(|e| e.kind == ResolverKind::Dead)
        .map(|e| format!("{} — {}", e.service, e.note))
        .chain(entries.iter().filter(|e| e.kind != ResolverKind::Dead && e.probe_note.contains("лимит сетов")).map(|e| format!("{} — {}", e.service, e.probe_note)))
        .take(3)
        .collect();
    let causes = if causes.is_empty() {
        String::new()
    } else {
        format!(": {}", causes.join("; "))
    };
    (
        format!(
            "Рабочего адреса не найдено{} — запустите «Анализ сайта» для полной картины",
            causes
        ),
        "fail",
    )
}

/// Запуск скрипта: домен из поля → перебор doh-services.txt → классификация
/// → сквозные пробы адресов. Никаких угадываний по ownership IP: вердикт
/// только по факту «сайт открывается через адреса резолвера».
pub fn run_pick(url: &str) -> Result<DnsPickOutcome, String> {
    let host = match ip_target::parse_target(url) {
        ip_target::AnalysisTarget::Domain { host } => host,
        ip_target::AnalysisTarget::Ip { .. } => {
            return Err("нужен домен, а не IP-адрес: у IP-цели нет DNS-подмены".to_string())
        }
    };
    let read = config::read_doh_services();
    if !read.file_found {
        return Err(format!(
            "список DoH-сервисов недоступен: {}",
            read.warnings.join("; ")
        ));
    }
    if read.hosts.is_empty() {
        return Err(format!(
            "список DoH-сервисов пуст ({}); добавьте сервисы в файл (Настройки → DoH-серверы)",
            read.warnings.join("; ")
        ));
    }

    let answers = diagnostics_probe::resolve_doh_all(&host);
    if answers.answers.is_empty() {
        return Err(format!(
            "ни один DoH-сервис не ответил для {}{}",
            host,
            answers
                .config_error
                .as_deref()
                .map(|e| format!(" ({})", e))
                .unwrap_or_default()
        ));
    }

    let class = pick_resolvers(&answers);

    // Шлюзовые сеты — только TCP-живость (HTTP-проба шлюза лжёт 200-м).
    let mut gateway_sets: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for gips in class.entry_gateways.iter().flatten() {
        let key = set_key(gips);
        if !gateway_sets.iter().any(|(k, _)| *k == key) {
            gateway_sets.push((key, gips.clone()));
        }
    }
    let gateways: HashMap<String, (ProbeVerdict, String)> = gateway_sets
        .iter()
        .map(|(k, ips)| (k.clone(), gateway_tcp_probe(ips)))
        .collect();

    let (site, per_ip) = run_site_probes(&host, &class.site_sets);
    let entries = attach_probes(class, &site, &per_ip, &gateways);
    let (summary, level) = build_summary(&host, &entries);

    Ok(DnsPickOutcome {
        domain: host,
        entries,
        summary,
        verdict_level: level.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics_probe::DohAnswer;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ans(service: &str, ips: &[&str]) -> DohAnswer {
        DohAnswer {
            service: service.to_string(),
            ips: ips.iter().map(|s| ip(s)).collect(),
            error: None,
        }
    }

    fn dead(service: &str, err: &str) -> DohAnswer {
        DohAnswer {
            service: service.to_string(),
            ips: vec![],
            error: Some(err.to_string()),
        }
    }

    fn answers(list: Vec<DohAnswer>, own_ips: Vec<(String, Vec<IpAddr>)>) -> DohAnswers {
        DohAnswers {
            answers: list,
            config_error: None,
            warnings: vec![],
            own_ips,
        }
    }

    #[test]
    fn wire_query_matches_rfc8484_fixture() {
        // Живой запрос, подтверждённый curl'ом 28.10.26 (ID 0x1234 → у нас
        // ID=0; остальное байт-в-байт).
        let q = diagnostics_probe::build_doh_wire_query("aistudio.google.com").unwrap();
        let expect_id0 = "AAABAAABAAAAAAAACGFpc3R1ZGlvBmdvb2dsZQNjb20AAAEAAQ";
        assert_eq!(diagnostics_probe::b64url(&q), expect_id0);
    }

    #[test]
    fn wire_query_rejects_empty_and_long_labels() {
        assert!(diagnostics_probe::build_doh_wire_query("").is_err());
        assert!(diagnostics_probe::build_doh_wire_query("a..b").is_err());
        let long = "a".repeat(64);
        assert!(diagnostics_probe::build_doh_wire_query(&long).is_err());
    }

    /// Живой ответ eu.geohide.ru (захвачен curl'ом 28.10.26, 160 байт,
    /// 7 A-записей — собственные шлюзы сервиса).
    const GEOHIDE_RESPONSE_HEX: &str = "12348180000100070000000108616973747564696f06676f6f676c6503636f6d0000010001c00c000100010000003c000405afa128c00c000100010000003c00041f19ef84c00c000100010000003c00042d0dedd5c00c000100010000003c000405afa103c00c000100010000003c00048f1440c0c00c000100010000003c000425dd5d80c00c000100010000003c000425dd5d8d0000291000000000000000";

    #[test]
    fn parse_doh_wire_response_reads_all_answers() {
        let bytes: Vec<u8> = (0..GEOHIDE_RESPONSE_HEX.len() / 2)
            .map(|i| u8::from_str_radix(&GEOHIDE_RESPONSE_HEX[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let ips = diagnostics_probe::parse_doh_wire_response(&bytes);
        assert_eq!(ips.len(), 7, "{:?}", ips);
        assert!(ips.contains(&ip("5.175.161.40")));
        assert!(ips.contains(&ip("37.221.93.141")));
    }

    #[test]
    fn parse_doh_wire_response_garbage_is_empty() {
        assert!(diagnostics_probe::parse_doh_wire_response(&[]).is_empty());
        assert!(diagnostics_probe::parse_doh_wire_response(&[0u8; 5]).is_empty());
        // rcode != 0 (NXDOMAIN)
        assert!(diagnostics_probe::parse_doh_wire_response(&[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]).is_empty());
    }

    /// Консенсус большинства: честные резолверы → Resolves, одиночка,
    /// расходящаяся с большинством → Diverges (кейс Patreon: честные
    /// резолверы отдают одни и те же Cloudflare-адреса).
    #[test]
    fn consensus_majority_resolves_and_divergent_marks() {
        let a = answers(
            vec![
                ans("svc-a", &["104.16.24.14", "104.16.25.14"]),
                ans("svc-b", &["104.16.25.14", "104.16.24.14"]), // порядок другой — сет тот же
                ans("svc-c", &["104.16.24.14"]),
                ans("svc-d", &["188.186.154.88"]),
            ],
            vec![],
        );
        let c = pick_resolvers(&a);
        for svc in ["svc-a", "svc-b", "svc-c"] {
            let e = c.entries.iter().find(|e| e.service == svc).unwrap();
            assert_eq!(e.kind, ResolverKind::Resolves, "{}: {:?}", svc, e.note);
        }
        let d = c.entries.iter().find(|e| e.service == "svc-d").unwrap();
        assert_eq!(d.kind, ResolverKind::Diverges);
        // Подозрительный адрес называет по имени, а не пул большинства.
        assert!(d.note.contains("188.186.154.88"), "{}", d.note);
    }

    /// Собственные шлюзы сервиса (answers.gateway_owner) → Gateway,
    /// независимо от того, в каких они диапазонах. Эталон eu.geohide.ru.
    #[test]
    fn own_gateways_are_gateway_kind() {
        let a = answers(
            vec![ans("eu.geohide.ru", &["5.175.161.40", "37.221.93.128"])],
            vec![(
                "eu.geohide.ru".to_string(),
                vec![ip("5.175.161.40"), ip("37.221.93.128")],
            )],
        );
        let c = pick_resolvers(&a);
        let e = &c.entries[0];
        assert_eq!(e.kind, ResolverKind::Gateway);
        assert!(e.note.contains("фронтинг"), "{}", e.note);
        assert!(c.site_sets.is_empty(), "шлюзовый сет не должен идти в HTTP-пробы");
    }

    /// Смешанный ответ (шлюз + адрес сайта): классификация по не-шлюзовой
    /// части, шлюзовая часть — в примечании.
    #[test]
    fn mixed_answer_judged_by_site_part() {
        let a = answers(
            vec![
                ans("svc-honest", &["104.16.24.14"]),
                ans("svc-mixed", &["104.16.24.14", "5.175.161.40"]),
            ],
            vec![("svc-mixed".to_string(), vec![ip("5.175.161.40")])],
        );
        let c = pick_resolvers(&a);
        let e = c.entries.iter().find(|e| e.service == "svc-mixed").unwrap();
        assert_eq!(e.kind, ResolverKind::Resolves, "{}", e.note);
        assert!(e.note.contains("частично отдаёт свои шлюзы"), "{}", e.note);
    }

    /// Повторяющихся сетов нет вообще (GeoDNS-норма) — все Resolves,
    /// никакого «расходится» для легитимной разницы эджей.
    #[test]
    fn no_majority_geodns_all_resolves() {
        let a = answers(
            vec![
                ans("svc-a", &["142.251.155.2"]),
                ans("svc-b", &["64.233.162.101"]),
            ],
            vec![],
        );
        let c = pick_resolvers(&a);
        assert!(c
            .entries
            .iter()
            .all(|e| e.kind == ResolverKind::Resolves), "{:?}", c.entries);
    }

    #[test]
    fn stub_only_and_error_are_dead() {
        let a = answers(
            vec![
                ans("svc-stub", &["0.0.0.0"]),
                dead("svc-err", "не ответил за 9 с (таймаут)"),
            ],
            vec![],
        );
        let c = pick_resolvers(&a);
        for e in &c.entries {
            assert_eq!(e.kind, ResolverKind::Dead, "{}", e.service);
        }
        assert!(c.entries[1].note.contains("таймаут"));
    }

    /// Консенсус-сет идёт в пробы первым.
    #[test]
    fn consensus_set_is_probed_first() {
        let a = answers(
            vec![
                ans("svc-rare", &["9.9.9.9"]),
                ans("svc-m1", &["104.16.24.14"]),
                ans("svc-m2", &["104.16.24.14"]),
            ],
            vec![],
        );
        let c = pick_resolvers(&a);
        assert_eq!(c.site_sets[0].0, set_key(&[ip("104.16.24.14")]));
    }

    /// Агрегат пробы сета: приоритет Open > отказ сайта > сломанный TLS > не отвечает.
    #[test]
    fn aggregate_priorities() {
        let f = |rs: &[(IpAddr, HttpResult)]| aggregate_site_set(rs).0;
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Ok(200)), (ip("1.1.1.2"), HttpResult::Rst)]), ProbeVerdict::Open);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Forbidden(403))]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::BlockPage)]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::ServiceRestrict)]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Rst), (ip("1.1.1.2"), HttpResult::Timeout)]), ProbeVerdict::DpiBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Timeout)]), ProbeVerdict::Unreachable);
        // Заметка несёт и текст, и адрес.
        let (v, note) = aggregate_site_set(&[(ip("104.16.24.14"), HttpResult::Forbidden(403))]);
        assert_eq!(v, ProbeVerdict::SiteBlocked);
        assert!(note.contains("403") && note.contains("104.16.24.14"), "{}", note);
    }

    /// Итог «проба открыла сайт» → ok, рекомендация с Secure DNS.
    #[test]
    fn summary_open_is_ok() {
        let entries = vec![DnsPickEntry {
            service: "svc-a".into(),
            resolved: vec!["1.2.3.4".into()],
            kind: ResolverKind::Resolves,
            note: "резолвит верно".into(),
            probe: Some(ProbeVerdict::Open),
            probe_note: "HTTP 200 (1.2.3.4)".into(),
        }];
        let (s, level) = build_summary("example.com", &entries);
        assert_eq!(level, "ok");
        assert!(s.contains("Рабочий DNS: svc-a") && s.contains("https://svc-a/dns-query"), "{}", s);
    }

    /// Итог «живой фронтинг-шлюз» → ok (кейс aistudio).
    #[test]
    fn summary_gateway_is_ok() {
        let entries = vec![
            DnsPickEntry {
                service: "eu.geohide.ru".into(),
                resolved: vec!["5.175.161.40".into()],
                kind: ResolverKind::Gateway,
                note: "отдаёт собственные шлюзы".into(),
                probe: Some(ProbeVerdict::GatewayAlive),
                probe_note: "шлюз 5.175.161.40 отвечает на :443".into(),
            },
            DnsPickEntry {
                service: "dns.google".into(),
                resolved: vec!["142.251.155.2".into()],
                kind: ResolverKind::Resolves,
                note: "резолвит верно".into(),
                probe: Some(ProbeVerdict::SiteBlocked),
                probe_note: "страница отдалась, но сервис сообщает об ограничении (регион) (142.251.155.2)".into(),
            },
        ];
        let (s, level) = build_summary("aistudio.google.com", &entries);
        assert_eq!(level, "ok");
        assert!(s.contains("eu.geohide.ru") && s.contains("собственные шлюзы"), "{}", s);
    }

    /// Итог «сайт сам отказывает» → fail с честным «нужен VPN» (кейс
    /// Patreon: 403/1009 от Cloudflare при честных резолверах).
    #[test]
    fn summary_site_blocked_is_fail_vpn() {
        let entries = vec![DnsPickEntry {
            service: "dns.google".into(),
            resolved: vec!["104.16.24.14".into()],
            kind: ResolverKind::Resolves,
            note: "резолвит верно".into(),
            probe: Some(ProbeVerdict::SiteBlocked),
            probe_note: "отказ сервера HTTP 403 (104.16.24.14)".into(),
        }];
        let (s, level) = build_summary("www.patreon.com", &entries);
        assert_eq!(level, "fail");
        assert!(s.contains("сайт сам отказывает") && s.contains("VPN"), "{}", s);
        assert!(s.contains("1009"), "{}", s);
    }

    /// Итог «TLS режется» → warn с советом включить обход.
    #[test]
    fn summary_dpi_is_warn() {
        let entries = vec![DnsPickEntry {
            service: "dns.google".into(),
            resolved: vec!["104.16.24.14".into()],
            kind: ResolverKind::Resolves,
            note: "резолвит верно".into(),
            probe: Some(ProbeVerdict::DpiBlocked),
            probe_note: "RST — TCP:443 открыт, но HTTPS рвётся (DPI по SNI) (104.16.24.14)".into(),
        }];
        let (s, level) = build_summary("example.com", &entries);
        assert_eq!(level, "warn");
        assert!(s.contains("DPI") && s.contains("winws"), "{}", s);
    }

    /// Нечего показать (все мёртвые) → fail c причинами.
    #[test]
    fn summary_nothing_is_fail() {
        let entries = vec![DnsPickEntry {
            service: "svc-a".into(),
            resolved: vec![],
            kind: ResolverKind::Dead,
            note: "не ответил за 9 с (таймаут)".into(),
            probe: None,
            probe_note: String::new(),
        }];
        let (s, level) = build_summary("example.com", &entries);
        assert_eq!(level, "fail");
        assert!(s.contains("Рабочего адреса не найдено") && s.contains("svc-a"), "{}", s);
    }

    /// attach_probes: сет без результата (лимит проб) получает честную
    /// пометку, а не молчаливый «нет данных».
    #[test]
    fn attach_probes_marks_unprobed_sets() {
        let key = set_key(&[ip("1.2.3.4")]);
        let class = Classification {
            entries: vec![DnsPickEntry {
                service: "svc-a".into(),
                resolved: vec!["1.2.3.4".into()],
                kind: ResolverKind::Resolves,
                note: "резолвит верно".into(),
                probe: None,
                probe_note: String::new(),
            }],
            site_sets: vec![(key.clone(), vec![ip("1.2.3.4")])],
            entry_set: vec![Some(key.clone())],
            entry_site_ips: vec![Some(vec![ip("1.2.3.4")])],
            entry_gateways: vec![None],
        };
        let entries = attach_probes(class, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(entries[0].probe.is_none());
        assert!(entries[0].probe_note.contains("лимит сетов"), "{}", entries[0].probe_note);
    }

    /// Наследование пробы по IP: резолвер с подмножеством адресов (свой сет
    /// не попал в лимит проб) получает вердикт по пробам своих адресов в
    /// составе других сетов — а не «нет данных».
    #[test]
    fn attach_probes_inherits_by_ip() {
        let class = Classification {
            entries: vec![DnsPickEntry {
                service: "svc-subset".into(),
                resolved: vec!["104.16.24.14".into()],
                kind: ResolverKind::Resolves,
                note: "резолвит верно".into(),
                probe: None,
                probe_note: String::new(),
            }],
            site_sets: vec![],
            entry_set: vec![Some("104.16.24.14".to_string())],
            entry_site_ips: vec![Some(vec![ip("104.16.24.14")])],
            entry_gateways: vec![None],
        };
        let mut per_ip = HashMap::new();
        per_ip.insert(ip("104.16.24.14"), HttpResult::Forbidden(403));
        let entries = attach_probes(class, &HashMap::new(), &per_ip, &HashMap::new());
        assert_eq!(entries[0].probe, Some(ProbeVerdict::SiteBlocked));
        assert!(entries[0].probe_note.contains("из других сетов"), "{}", entries[0].probe_note);
    }

    /// Живой эталон классификации (ground truth юзера 28.10.26: браузер с
    /// eu.geohide.ru не редиректит, с прямыми адресами — редиректит).
    /// Запуск вручную при включённом обходе (docs/blocks.md §2):
    /// `cargo test live_pick_aistudio -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network + включённый обход (docs/blocks.md §2)"]
    fn live_pick_aistudio() {
        let out = run_pick("https://aistudio.google.com").expect("run_pick");
        for e in &out.entries {
            println!("[{:?} / {:?}] {}: {} | {}", e.kind, e.probe, e.service, e.note, e.probe_note);
        }
        println!("ИТОГ ({}): {}", out.verdict_level, out.summary);
        let geohide = out
            .entries
            .iter()
            .find(|e| e.service == "eu.geohide.ru")
            .expect("eu.geohide.ru не в списке doh-services.txt");
        assert_eq!(geohide.kind, ResolverKind::Gateway, "эталон: geohide отдаёт свои шлюзы ({:?})", geohide);
        assert_eq!(geohide.probe, Some(ProbeVerdict::GatewayAlive), "шлюз geohide должен отвечать при включённом обходе");
        for svc in ["dns.google", "cloudflare-dns.com", "dns.comss.one"] {
            if let Some(e) = out.entries.iter().find(|e| e.service == svc) {
                assert_eq!(e.kind, ResolverKind::Resolves, "эталон: {} — честный резолвер ({:?})", svc, e);
            }
        }
    }
}
