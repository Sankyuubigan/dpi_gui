//! Скрипт подбора рабочего DNS (кнопка «Подбор рабочего DNS»).
//!
//! Универсальная архитектура (переработка 01.11.26 после кейса Patreon —
//! НЕ возвращаться к эвристике по диапазонам Google):
//!
//! 1. Слой DNS: `resolve_doh_all` опрашивает все DoH-сервисы.
//! 2. Классификация ответов БЕЗ угадывания по ownership IP:
//!    - `Dead` — не ответил / только заглушки;
//!    - `Gateway` — отдал СВОИ адреса (`DohAnswers::gateway_owner`):
//!      фронтинг-шлюзы сервиса (кейс eu.geohide.ru); вердикт фронтинга
//!      ставит только сквозная проба (ниже);
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
//!    - шлюзовые сеты — сквозная HTTP-проба `site_probe::http_via_ip` по
//!      каждому IP пула: мина «свой 200» обезврежена валидацией TLS-
//!      сертификата имени сайта (чужой 200 → честный `BadCert`; кейс
//!      openrouter.ai 09.11.26: сайт открывался только через 2 из 7
//!      шлюзов пула — TCP-вердикт удалён как источник лжи).
//!
//! Посессионный гео-блок (кейс aistudio.google.com, пробы 28.10.26): проба
//! с исходного IP видит страницу (часто с «регион ограничен» —
//! ServiceRestrict), блок срабатывает после логина и привязан к ИСХОДНОМУ
//! IP клиента. Поэтому живой Gateway остаётся единственным DNS-фиксом и
//! рекомендуется даже при «не-Open» пробе честных адресов.

use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tauri::AppHandle;

use crate::bypass_toggle::OffWindowGuard;
use crate::cancel;
use crate::config;
use crate::diagnostics_probe::{self, is_stub_ip, DohAnswers, HttpResult};
use crate::events::app_log;
use crate::ip_target;
use crate::site_probe::{http_via_ip, probe_https_by_ip, substitution_note};

/// Лимит HTTP-проб: уникальных сетов адресов и адресов внутри сета.
const MAX_PROBE_SETS: usize = 4;
const MAX_PROBE_IPS: usize = 2;
/// Дедлайн сбора HTTP-проб (клиентский таймаут одной пробы — 6 с).
const PROBE_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResolverKind {
    /// Отдал собственные адреса-шлюзы (фронтинг): вердикт ставит сквозная проба.
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
    /// Транспорт до сайта работает, но страница — JS-оболочка без видимого
    /// контента: проба анонимная и не видит ограничений, отрисованных после
    /// входа в аккаунт (кейс aistudio 08.11.26). Это «не подтверждено»,
    /// а не «открывается» — вывод от отсутствия доказательств запрещён
    /// (core rules §2.2).
    Unverified,
    /// Отказ самого сайта: 403/451, блок-страница, «регион ограничен».
    /// У Cloudflare это в т.ч. ошибка 1009 — страну забанил владелец.
    SiteBlocked,
    /// Транспорт/TLS сломан (RST/TLS/BadCert) — лечится обходом winws.
    DpiBlocked,
    /// Адрес не отвечает (таймаут/прочее).
    Unreachable,
    /// Фронтинг подтверждён сквозной пробой (`http_via_ip` с валидацией
    /// сертификата): сайт открывается через не меньше половины шлюзов пула.
    /// TCP-живость вердиктом не считается — она лгала на openrouter.ai
    /// (09.11.26: сайт открывался только через 2 из 7 шлюзов пула).
    GatewayAlive,
    /// Фронтинг подтверждён пробой, но меньше чем на половине шлюзов пула:
    /// браузер получает весь пул и может попадать на нерабочие IP.
    GatewayPartial,
    /// Ни один шлюз пула не открыл сайт (сквозная проба) — фронтинг не
    /// подтверждён; TCP-живость при этом ничего не доказывает.
    GatewayDead,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickEntry {
    pub service: String,
    pub resolved: Vec<String>,
    pub kind: ResolverKind,
    pub note: String,
    /// Результат сквозной проверки (None — Dead: проверять нечего).
    pub probe: Option<ProbeVerdict>,
    pub probe_note: String,
    /// Шлюзы, через которые сайт РЕАЛЬНО открылся сквозной пробой — SSOT
    /// для «Применить» (маппинг берёт проверенный IP, а не resolved[0],
    /// который в кейсе 09.11.26 был мёртвым). Пусто у не-шлюзовых записей.
    pub fronting_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickOutcome {
    pub domain: String,
    pub entries: Vec<DnsPickEntry>,
    /// Итоговая строка — единый текст для лог-панели (SSOT).
    pub summary: String,
    /// "ok" | "warn" | "fail" — уровень итога; фронт рендер по нему,
    /// не снифая текст summary.
    pub verdict_level: String,
}

/// Последний результат подбора — SSOT для «Применить» во вкладке Браузер
/// (PRP-3): команда принимает только force, outcome берёт отсюда, чтобы
/// не протаскивать DnsPickOutcome через invoke (CommandArg не реализуется
/// для сложных структур без Deserialize). Обновляется ТОЛЬКО при Some(app)
/// — живой эталон-тест (app = None) не должен подменять продуктовый
/// результат подбора.
pub static LAST_PICK: std::sync::Mutex<Option<DnsPickOutcome>> = std::sync::Mutex::new(None);

pub fn set_last_pick(o: DnsPickOutcome) {
    if let Ok(mut g) = LAST_PICK.lock() {
        *g = Some(o);
    }
}

pub fn last_pick() -> Option<DnsPickOutcome> {
    LAST_PICK
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|o| o.clone()))
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
    /// entry[i] → собственные шлюзы сервиса (чистые Gateway) для сквозной
    /// пробы фронтинга.
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
                    fronting_ips: Vec::new(),
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
                        fronting_ips: Vec::new(),
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
                            "отдаёт собственные шлюзы ({}) — вердикт фронтинга ставит сквозная проба",
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
                    fronting_ips: Vec::new(),
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
/// (Open > отказ сайта > не подтверждено > сломанный TLS > не отвечает).
/// Верифицированный отказ сайта важнее неопределённости: один IP даёт 403,
/// другой — оболочку → сёт SiteBlocked, а не Unverified. Чистая функция.
fn aggregate_site_set(results: &[(IpAddr, HttpResult)]) -> (ProbeVerdict, String) {
    let prio = |r: &HttpResult| match r {
        HttpResult::Ok(_) => 0,
        HttpResult::Forbidden(_) | HttpResult::BlockPage | HttpResult::ServiceRestrict => 1,
        HttpResult::Unverified => 2,
        HttpResult::Rst | HttpResult::Tls | HttpResult::BadCert => 3,
        _ => 4,
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
        HttpResult::Unverified => ProbeVerdict::Unverified,
        HttpResult::Rst | HttpResult::Tls | HttpResult::BadCert => ProbeVerdict::DpiBlocked,
        _ => ProbeVerdict::Unreachable,
    };
    (verdict, format!("{} ({})", substitution_note(best), ip))
}

/// Результат сквозной пробы шлюзового пула.
#[derive(Debug, Clone)]
pub struct GatewayProbe {
    pub verdict: ProbeVerdict,
    pub note: String,
    /// Шлюзы, через которые сайт реально открылся (или транспорт до сайта
    /// работает — JS-оболочка): подтверждено пробой, не догадкой.
    pub fronting: Vec<IpAddr>,
}

/// Строка «IP 0.6с, IP 0.7с» для подтверждённых шлюзов (≤3, как ips_str).
fn ips_times_str(items: &[(IpAddr, Duration)]) -> String {
    let all: Vec<String> = items
        .iter()
        .map(|(ip, d)| format!("{} {:.1}с", ip, d.as_secs_f64()))
        .collect();
    if all.len() <= 3 {
        all.join(", ")
    } else {
        format!("{}, … (всего {})", all[..3].join(", "), all.len())
    }
}

/// Агрегат сквозных проб шлюзового пула (чистая функция — покрыта тестами).
/// Фронтинг подтверждает только `Ok` (настоящая страница через валидный
/// сертификат сайта) или `Unverified` (транспорт работает, страница —
/// оболочка). Отказ сайта и через шлюз (Forbidden/ServiceRestrict) —
/// транспорт доходит, но сайт отказывает и IP шлюза (VPN-кейс). Всё
/// остальное (BadCert/Tls/Rst/Timeout/BlockPage/Other) — этот шлюз сайт
/// не фронтит: «свой 200» шлюза без валидного сертификата отфильтрован
/// как `BadCert` (blocks.md §3), TCP-живость подтверждением не считается.
fn aggregate_gateway_set(results: &[(IpAddr, HttpResult, Duration)]) -> GatewayProbe {
    let total = results.len();
    let ok: Vec<(IpAddr, Duration)> = results
        .iter()
        .filter(|(_, r, _)| matches!(r, HttpResult::Ok(_)))
        .map(|(ip, _, d)| (*ip, *d))
        .collect();
    let unverified: Vec<(IpAddr, Duration)> = results
        .iter()
        .filter(|(_, r, _)| matches!(r, HttpResult::Unverified))
        .map(|(ip, _, d)| (*ip, *d))
        .collect();
    let refused: Vec<&(IpAddr, HttpResult, Duration)> = results
        .iter()
        .filter(|(_, r, _)| matches!(r, HttpResult::Forbidden(_) | HttpResult::ServiceRestrict))
        .collect();
    let confirmed_cnt = ok.len() + unverified.len();
    let fronting: Vec<IpAddr> = ok
        .iter()
        .chain(unverified.iter())
        .map(|(ip, _)| *ip)
        .collect();

    if confirmed_cnt == 0 {
        if !refused.is_empty() {
            return GatewayProbe {
                verdict: ProbeVerdict::SiteBlocked,
                note: format!(
                    "транспорт до сайта через шлюзы работает, но сайт отказывает и IP шлюзов ({} из {}): поможет только VPN",
                    refused.len(),
                    total
                ),
                fronting: Vec::new(),
            };
        }
        return GatewayProbe {
            verdict: ProbeVerdict::GatewayDead,
            note: format!(
                "сайт не открывается ни через один из {} шлюзов — фронтинг не подтверждён",
                total
            ),
            fronting: Vec::new(),
        };
    }

    let fronting_items: Vec<(IpAddr, Duration)> = ok
        .iter()
        .chain(unverified.iter())
        .cloned()
        .collect();
    let front_list = ips_times_str(&fronting_items);
    let dead_cnt = total - confirmed_cnt - refused.len();
    let mut note = if ok.is_empty() {
        format!(
            "фронтинг подтверждён пробой: транспорт до сайта работает через {} из {} шлюзов ({}), но страница — JS-оболочка: доступность не подтверждена",
            confirmed_cnt,
            total,
            front_list
        )
    } else {
        let times: Vec<f64> = ok.iter().map(|(_, d)| d.as_secs_f64()).collect();
        format!(
            "фронтинг подтверждён пробой: сайт открывается через {} из {} шлюзов ({}, время {:.1}–{:.1} с)",
            confirmed_cnt,
            total,
            front_list,
            times.iter().cloned().fold(f64::INFINITY, f64::min),
            times.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
        )
    };
    if dead_cnt > 0 {
        note.push_str(&format!(
            "; {} из {} шлюзов не фронтят сайт — браузер может попасть на нерабочий IP",
            dead_cnt,
            total
        ));
    }
    if !refused.is_empty() {
        note.push_str(&format!(
            "; {} — сайт отказывает и IP шлюза (VPN-кейс)",
            refused.len()
        ));
    }
    let verdict = if confirmed_cnt * 2 >= total {
        ProbeVerdict::GatewayAlive
    } else {
        note.push_str(" — сайт может открываться не с первой попытки");
        ProbeVerdict::GatewayPartial
    };
    GatewayProbe {
        verdict,
        note,
        fronting,
    }
}

/// Сквозная проба шлюзового сета: сайт должен открыться через шлюз.
/// `http_via_ip` валидирует TLS-сертификат имени сайта — «свой 200» шлюза
/// без валидного сертификата отфильтруется как BadCert и успехом не
/// притворится (blocks.md §3). Пробы параллельны (по одной на IP);
/// не ответившие в бюджет считаются нерабочими — так их видит браузер.
fn gateway_fronting_probe(host: &str, ips: &[IpAddr]) -> GatewayProbe {
    let (tx, rx) = mpsc::channel();
    for ip in ips {
        let tx = tx.clone();
        let host = host.to_string();
        let ip = *ip;
        thread::spawn(move || {
            let start = Instant::now();
            let r = http_via_ip(&host, ip, 443);
            let _ = tx.send((ip, r, start.elapsed()));
        });
    }
    drop(tx);
    let deadline = Instant::now() + PROBE_DEADLINE;
    let mut results: Vec<(IpAddr, HttpResult, Duration)> = Vec::new();
    while results.len() < ips.len() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(res) => results.push(res),
            Err(_) => break,
        }
    }
    // Не ответившие в бюджет — честный Timeout (в агрегате «не фронтят»).
    let answered: HashSet<IpAddr> = results.iter().map(|(ip, _, _)| *ip).collect();
    for ip in ips {
        if !answered.contains(ip) {
            results.push((*ip, HttpResult::Timeout, PROBE_DEADLINE));
        }
    }
    aggregate_gateway_set(&results)
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
    gateways: &HashMap<String, GatewayProbe>,
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
            if let Some(gp) = gateways.get(&set_key(gips)) {
                e.probe = Some(gp.verdict);
                e.probe_note = gp.note.clone();
                e.fronting_ips = gp.fronting.clone();
            }
        }
    }
    class.entries
}

/// Итоговая строка + уровень по приоритету честных исходов:
/// открылся пробой > фронтинг подтверждён (≥ половины пула) > фронтинг
/// частичный (warn) > оболочка (не подтверждено) > отказ сайта (VPN) >
/// DPI > ничего. Чистая функция — покрыта тестами.
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
                "Рабочий DNS: {} — отдаёт собственные шлюзы для {}; {}. Сайт будет видеть IP шлюза, а не ваш (кейс посессионного гео-блока). Включите его как Secure DNS в браузере: https://{}/dns-query",
                e.service, host, e.probe_note, e.service
            ),
            "ok",
        );
    }
    // Частичный фронтинг (кейс openrouter.ai 09.11.26: сайт открывался
    // только через 2 из 7 шлюзов пула): «Рабочий DNS» без оговорок — ложь.
    if let Some(e) = entries
        .iter()
        .find(|e| e.kind == ResolverKind::Gateway && e.probe == Some(ProbeVerdict::GatewayPartial))
    {
        return (
            format!(
                "Шлюзы {} для {} фронтят сайт только частично ({}): браузер получает весь пул и может попадать на нерабочие IP — смена DNS может не открыть сайт с первой попытки, надёжнее VPN",
                e.service, host, e.probe_note
            ),
            "warn",
        );
    }
    // Посессионный гео-блок (кейс aistudio 08.11.26): транспорт работает,
    // но страница — JS-оболочка; анонимная проба доступность НЕ подтверждает.
    // Слово «открывается» здесь запрещено (core rules §2.2).
    if let Some(e) = entries
        .iter()
        .find(|e| e.probe == Some(ProbeVerdict::Unverified))
    {
        return (
            format!(
                "Резолвер {} отдаёт адреса {}, транспорт до сайта работает, но страница — JS-оболочка без видимого контента: анонимная проба доступность НЕ подтверждает. Если сайт ограничивает по региону после входа в аккаунт — смена DNS бессильна (нужен VPN или фронтинг-шлюз — строки 🛰); {}",
                e.service, host, e.probe_note
            ),
            "warn",
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
        .filter(|e| e.kind == ResolverKind::Dead || e.probe == Some(ProbeVerdict::GatewayDead))
        .map(|e| {
            if e.probe == Some(ProbeVerdict::GatewayDead) {
                format!("{} — {}", e.service, e.probe_note)
            } else {
                format!("{} — {}", e.service, e.note)
            }
        })
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
///
/// `app = Some` (продуктовый путь): HTTP-пробы сайта идут в чистом окне
/// (blocks.md §3 — с обходом проба видит только RST и приписывает DNS то,
/// что чинит winws); живость DoH/шлюзов мерится С обходом (blocks.md §2),
/// поэтому глушится обход только здесь. `app = None` — ТОЛЬКО живой
/// эталон-тест: он мерит классификацию DoH-ответов, а не окно.
pub fn run_pick(app: Option<&AppHandle>, url: &str) -> Result<DnsPickOutcome, String> {
    let host = match ip_target::parse_target(url) {
        ip_target::AnalysisTarget::Domain { host } => host,
        ip_target::AnalysisTarget::Ip { .. } => {
            return Err("нужен домен, а не IP-адрес: у IP-цели нет DNS-подмены".to_string())
        }
    };
    // Честная видимость (PRP 08.11.26): если юзер забрал кукисы из браузера,
    // пробы подбора идут с ними — сказать в логе ОДИН раз, не на каждый
    // запрос (шум). Кукисы держатся в памяти (browser_cookies.rs).
    if crate::browser_cookies::count_for(&host) > 0 {
        if let Some(app) = app {
            app_log(
                app,
                format!(
                    "[Подбор DNS] Пробы идут с кукисами из браузера ({} шт.)",
                    crate::browser_cookies::count_for(&host)
                ),
            );
        }
    }
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

    // Контрольная точка «Стоп»: перебор DoH-сервисов — самая долгая фаза.
    // winws здесь не рулится, финализации не требуется — честный Err.
    if cancel::is_cancelled(cancel::DNS_PICK) {
        return Err("Подбор DNS остановлен пользователем".into());
    }

    let class = pick_resolvers(&answers);

    // Шлюзовые сеты — сквозная проба: «фронтинг подтверждён» только когда
    // сайт реально открывается через шлюз (валидный сертификат + контент).
    // TCP-живость была ложью (кейс openrouter.ai 09.11.26: сайт открывался
    // только через 2 из 7 шлюзов пула). Мера с обходом (blocks.md §2) —
    // состояние «браузер + обход ВКЛ».
    let mut gateway_sets: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for gips in class.entry_gateways.iter().flatten() {
        let key = set_key(gips);
        if !gateway_sets.iter().any(|(k, _)| *k == key) {
            gateway_sets.push((key, gips.clone()));
        }
    }
    let gateways: HashMap<String, GatewayProbe> = {
        if let Some(app) = app {
            let total: usize = gateway_sets.iter().map(|(_, ips)| ips.len()).sum();
            app_log(
                app,
                format!(
                    "[Подбор DNS] Сквозная проба шлюзов: {} шт. — сайт должен реально открываться через каждый (валидный сертификат)",
                    total
                ),
            );
        }
        let started = Instant::now();
        let res: HashMap<String, GatewayProbe> = gateway_sets
            .iter()
            .map(|(k, ips)| (k.clone(), gateway_fronting_probe(&host, ips)))
            .collect();
        if let Some(app) = app {
            for gp in res.values() {
                app_log(
                    app,
                    format!(
                        "[Подбор DNS] Проба шлюзов за {:.1} с: {:?} — {}",
                        started.elapsed().as_secs_f64(),
                        gp.verdict,
                        gp.note
                    ),
                );
            }
        }
        res
    };

    // Контрольная точка после сквозных проб шлюзов, перед HTTP-пробами сайта.
    if cancel::is_cancelled(cancel::DNS_PICK) {
        return Err("Подбор DNS остановлен пользователем".into());
    }

    // HTTP-пробы сайта — в чистом окне (blocks.md §3). OffWindowGuard
    // восстанавливает обход даже при панике (Drop); факт restore — в лог.
    let (site, per_ip) = match app {
        Some(app) => {
            app_log(
                app,
                "[Подбор DNS] HTTP-пробы идут в чистом окне: обход на время проб отключается и восстановится."
                    .to_string(),
            );
            let guard = OffWindowGuard::open(app);
            let res = run_site_probes(&host, &class.site_sets);
            if let Some(note) = guard.close() {
                app_log(app, format!("[Подбор DNS] {}", note));
            }
            res
        }
        None => run_site_probes(&host, &class.site_sets),
    };
    let entries = attach_probes(class, &site, &per_ip, &gateways);
    let (summary, level) = build_summary(&host, &entries);

    let outcome = DnsPickOutcome {
        domain: host,
        entries,
        summary,
        verdict_level: level.to_string(),
    };
    // SSOT для «Применить» во вкладке Браузер (PRP-3): запоминаем только
    // продуктовый запуск (Some(app)); эталон-тест None не трогает состояние.
    if app.is_some() {
        set_last_pick(outcome.clone());
    }
    Ok(outcome)
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

    /// Агрегат пробы сета: приоритет Open > отказ сайта > не подтверждено > сломанный TLS > не отвечает.
    #[test]
    fn aggregate_priorities() {
        let f = |rs: &[(IpAddr, HttpResult)]| aggregate_site_set(rs).0;
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Ok(200)), (ip("1.1.1.2"), HttpResult::Rst)]), ProbeVerdict::Open);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Forbidden(403))]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::BlockPage)]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::ServiceRestrict)]), ProbeVerdict::SiteBlocked);
        assert_eq!(f(&[(ip("1.1.1.1"), HttpResult::Unverified)]), ProbeVerdict::Unverified);
        // Верифицированный отказ сайта важнее неопределённости (PRP-1 §3.2).
        assert_eq!(
            f(&[(ip("1.1.1.1"), HttpResult::Unverified), (ip("1.1.1.2"), HttpResult::Forbidden(403))]),
            ProbeVerdict::SiteBlocked
        );
        // Оболочка информативнее DPI-сбоя: транспорт через адрес работает.
        assert_eq!(
            f(&[(ip("1.1.1.1"), HttpResult::Unverified), (ip("1.1.1.2"), HttpResult::Rst)]),
            ProbeVerdict::Unverified
        );
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
            fronting_ips: Vec::new(),
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
                probe_note: "фронтинг подтверждён пробой: сайт открывается через 7 из 7 шлюзов (5.175.161.40 0.6с, … (всего 7), время 0.6–0.7 с)".into(),
                fronting_ips: vec![ip("5.175.161.40")],
            },
            DnsPickEntry {
                service: "dns.google".into(),
                resolved: vec!["142.251.155.2".into()],
                kind: ResolverKind::Resolves,
                note: "резолвит верно".into(),
                probe: Some(ProbeVerdict::SiteBlocked),
                probe_note: "страница отдалась, но сервис сообщает об ограничении (регион) (142.251.155.2)".into(),
                fronting_ips: Vec::new(),
            },
        ];
        let (s, level) = build_summary("aistudio.google.com", &entries);
        assert_eq!(level, "ok");
        assert!(s.contains("eu.geohide.ru") && s.contains("собственные шлюзы"), "{}", s);
        assert!(s.contains("фронтинг подтверждён"), "{}", s);
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
            fronting_ips: Vec::new(),
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
            fronting_ips: Vec::new(),
        }];
        let (s, level) = build_summary("example.com", &entries);
        assert_eq!(level, "warn");
        assert!(s.contains("DPI") && s.contains("winws"), "{}", s);
    }

    /// Итог «страница — JS-оболочка» → warn БЕЗ слова «открывается»
    /// (кейс aistudio 08.11.26: анонимная проба не подтверждает доступность).
    #[test]
    fn summary_unverified_is_warn_without_open_claim() {
        let entries = vec![DnsPickEntry {
            service: "dns.comss.one".into(),
            resolved: vec!["142.250.65.100".into()],
            kind: ResolverKind::Resolves,
            note: "резолвит верно".into(),
            probe: Some(ProbeVerdict::Unverified),
            probe_note: "страница без видимого контента (JS-оболочка) — доступность после входа не подтверждена (142.250.65.100)".into(),
            fronting_ips: Vec::new(),
        }];
        let (s, level) = build_summary("aistudio.google.com", &entries);
        assert_eq!(level, "warn");
        assert!(!s.contains("открывается"), "ложь в итоге: {}", s);
        assert!(s.contains("JS-оболочка") && s.contains("НЕ подтверждает"), "{}", s);
    }

    /// Порядок честных исходов: живой фронтинг-шлюз важнее оболочки
    /// (кейс aistudio: итог — рекомендация eu.geohide.ru, не warn).
    #[test]
    fn summary_gateway_alive_outranks_unverified() {
        let entries = vec![
            DnsPickEntry {
                service: "dns.comss.one".into(),
                resolved: vec!["142.250.65.100".into()],
                kind: ResolverKind::Resolves,
                note: "резолвит верно".into(),
                probe: Some(ProbeVerdict::Unverified),
                probe_note: "оболочка".into(),
                fronting_ips: Vec::new(),
            },
            DnsPickEntry {
                service: "eu.geohide.ru".into(),
                resolved: vec!["5.175.161.40".into()],
                kind: ResolverKind::Gateway,
                note: "отдаёт собственные шлюзы".into(),
                probe: Some(ProbeVerdict::GatewayAlive),
                probe_note: "фронтинг подтверждён пробой: сайт открывается через 7 из 7 шлюзов (5.175.161.40 0.6с, … (всего 7), время 0.6–0.7 с)".into(),
                fronting_ips: vec![ip("5.175.161.40")],
            },
        ];
        let (s, level) = build_summary("aistudio.google.com", &entries);
        assert_eq!(level, "ok");
        assert!(s.contains("eu.geohide.ru"), "{}", s);
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
            fronting_ips: Vec::new(),
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
                fronting_ips: Vec::new(),
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
                fronting_ips: Vec::new(),
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

    /// PRP-1 гейт: контентные сайты остаются Open — порог оболочки (200 байт
    /// видимого текста) не должен задевать нормальные страницы (замер
    /// 08.11.26: google.com=827, github.com=6800 видимых байт).
    #[test]
    #[ignore = "requires network"]
    fn live_content_sites_remain_open() {
        for url in ["https://google.com", "https://github.com"] {
            let out = run_pick(None, url).expect("run_pick");
            println!("ИТОГ ({}): {}", out.verdict_level, out.summary);
            let opened = out
                .entries
                .iter()
                .any(|e| e.probe == Some(ProbeVerdict::Open));
            assert!(
                opened,
                "{}: ни одной пробы Open — порог оболочки задевает контентные сайты",
                url
            );
        }
    }

    /// Живой эталон классификации (ground truth юзера 28.10.26: браузер с
    /// eu.geohide.ru не редиректит, с прямыми адресами — редиректит).
    /// Запуск вручную при включённом обходе (docs/blocks.md §2):
    /// `cargo test live_pick_aistudio -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network + включённый обход (docs/blocks.md §2)"]
    fn live_pick_aistudio() {
        let out = run_pick(None, "https://aistudio.google.com").expect("run_pick");
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
        assert!(
            matches!(
                geohide.probe,
                Some(ProbeVerdict::GatewayAlive) | Some(ProbeVerdict::GatewayPartial)
            ),
            "фронтинг geohide обязан подтверждаться сквозной пробой (сайт реально открывается через шлюз), а не TCP-живостью: {:?}",
            geohide
        );
        // PRP-1 гейт: aistudio анонимно — JS-оболочка, честные резолверы НЕ
        // могут иметь пробу Open («открывается») — это была главная ложь.
        // Проверка НЕ зависит от GeoDNS-дрейфа: любой сервис с ответом.
        for e in &out.entries {
            assert_ne!(
                e.probe,
                Some(ProbeVerdict::Open),
                "ложь PRP-1: {} с пробой Open («открывается») на JS-оболочке aistudio ({:?})",
                e.service,
                e
            );
        }
        // Стабильный инвариант шлюзовых сервисов (gateway_owner — не зависит
        // от дрейфа консенсуса). Kind (Resolves/Diverges) и исход пробы
        // честных резолверов ЖИВОЙ ДРЕЙФУЕТ между прогонами (GeoDNS отдаёт
        // разные сеты эджей; проба может честно дать Unreachable/Timeout на
        // конкретном эдже), поэтому эталон НЕ фиксирует их ни kind, ни probe:
        // единственный анти-ложь инвариант — НЕ Open (главная ложь PRP-1).
        for svc in ["dns.google", "cloudflare-dns.com", "dns.comss.one"] {
            if let Some(e) = out.entries.iter().find(|e| e.service == svc) {
                assert_ne!(e.kind, ResolverKind::Dead, "эталон: {} живой, не Dead ({:?})", svc, e);
            }
        }
    }

    /// Фикстура результата сквозной пробы одного шлюза.
    fn gp(ip_s: &str, r: HttpResult, secs: u64) -> (IpAddr, HttpResult, Duration) {
        (ip(ip_s), r, Duration::from_secs(secs))
    }

    /// Весь пул фронтит → GatewayAlive с подтверждёнными IP и временем.
    #[test]
    fn gateway_probe_all_front_is_alive() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Ok(200), 1),
            gp("2.2.2.2", HttpResult::Ok(200), 2),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::GatewayAlive);
        assert_eq!(g.fronting, vec![ip("1.1.1.1"), ip("2.2.2.2")]);
        assert!(g.note.contains("2 из 2") && g.note.contains("время 1.0–2.0 с"), "{}", g.note);
    }

    /// Меньше половины пула → GatewayPartial: «Рабочий DNS» без оговорок —
    /// ложь (кейс openrouter.ai 09.11.26: фронтинг только на 2 из 7).
    #[test]
    fn gateway_probe_minority_is_partial() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Ok(200), 1),
            gp("2.2.2.2", HttpResult::Ok(200), 2),
            gp("3.3.3.3", HttpResult::Timeout, 6),
            gp("4.4.4.4", HttpResult::BadCert, 1),
            gp("5.5.5.5", HttpResult::Tls, 1),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::GatewayPartial);
        assert_eq!(g.fronting.len(), 2);
        assert!(g.note.contains("2 из 5"), "{}", g.note);
        assert!(g.note.contains("не фронтят сайт"), "{}", g.note);
    }

    /// Ровно половина — уже GatewayAlive (граница включена).
    #[test]
    fn gateway_probe_half_counts_as_alive() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Ok(200), 1),
            gp("2.2.2.2", HttpResult::Timeout, 6),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::GatewayAlive);
    }

    /// Оболочка на шлюзе: транспорт работает, но честно «не подтверждена»,
    /// а не «открывается» (инвариант PRP-1).
    #[test]
    fn gateway_probe_unverified_is_alive_with_shell_note() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Unverified, 1),
            gp("2.2.2.2", HttpResult::Unverified, 2),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::GatewayAlive);
        assert!(
            g.note.contains("оболочка") && g.note.contains("не подтверждена"),
            "{}",
            g.note
        );
    }

    /// Ни один шлюз не открыл сайт → GatewayDead, не Alive: TCP-живость и
    /// «свой 200» без валидного сертификата подтверждением не считаются
    /// (мина blocks.md §3; кейс openrouter 09.11.26).
    #[test]
    fn gateway_probe_none_fronting_is_dead() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Timeout, 6),
            gp("2.2.2.2", HttpResult::BadCert, 1),
            gp("3.3.3.3", HttpResult::Tls, 1),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::GatewayDead);
        assert!(g.fronting.is_empty());
        assert!(g.note.contains("не подтверждён"), "{}", g.note);
    }

    /// Сайт отказывает и IP шлюзов (403 сквозь фронтинг) → SiteBlocked:
    /// транспорт работает, виноват сайт — VPN-кейс (Patreon).
    #[test]
    fn gateway_probe_site_refuses_gateway_is_site_blocked() {
        let g = aggregate_gateway_set(&[
            gp("1.1.1.1", HttpResult::Forbidden(403), 1),
            gp("2.2.2.2", HttpResult::Forbidden(403), 2),
        ]);
        assert_eq!(g.verdict, ProbeVerdict::SiteBlocked);
        assert!(g.note.contains("VPN"), "{}", g.note);
    }

    /// Частичный фронтинг → warn с честной оговоркой (не «Рабочий DNS»).
    #[test]
    fn summary_gateway_partial_is_warn() {
        let entries = vec![DnsPickEntry {
            service: "eu.geohide.ru".into(),
            resolved: vec![],
            kind: ResolverKind::Gateway,
            note: "отдаёт собственные шлюзы".into(),
            probe: Some(ProbeVerdict::GatewayPartial),
            probe_note: "фронтинг подтверждён пробой: сайт открывается через 2 из 7 шлюзов (143.20.64.192 0.6с, 37.221.93.141 0.7с, время 0.6–0.7 с); 4 из 7 шлюзов не фронтят сайт — браузер может попасть на нерабочий IP — сайт может открываться не с первой попытки".into(),
            fronting_ips: vec![ip("143.20.64.192")],
        }];
        let (s, level) = build_summary("openrouter.ai", &entries);
        assert_eq!(level, "warn");
        assert!(s.contains("частично") && s.contains("VPN"), "{}", s);
        assert!(
            !s.contains("Рабочий DNS"),
            "ложь: частичный фронтинг назван рабочим: {}",
            s
        );
    }

    /// Мёртвый фронтинг попадает в причины честного «ничего не найдено».
    #[test]
    fn summary_gateway_dead_in_causes() {
        let entries = vec![DnsPickEntry {
            service: "eu.geohide.ru".into(),
            resolved: vec![],
            kind: ResolverKind::Gateway,
            note: "отдаёт собственные шлюзы".into(),
            probe: Some(ProbeVerdict::GatewayDead),
            probe_note: "сайт не открывается ни через один из 7 шлюзов — фронтинг не подтверждён".into(),
            fronting_ips: vec![],
        }];
        let (s, level) = build_summary("openrouter.ai", &entries);
        assert_eq!(level, "fail");
        assert!(
            s.contains("Рабочего адреса не найдено") && s.contains("eu.geohide.ru"),
            "{}",
            s
        );
    }

    /// Живой эталон кейса лжи 09.11.26 (юзер: «Рабочий DNS», сайт не пашет):
    /// geohide отдаёт для openrouter.ai свой пул, где фронтит только часть
    /// шлюзов. Инвариант честности: вердикт шлюза подтверждается РЕАЛЬНЫМ
    /// открытием сайта сквозной пробой; частичный пул → warn (не безусловное
    /// «Рабочий DNS»). Пул дрейфует — фиксируем класс вердикта, не долю.
    #[test]
    #[ignore = "requires network + включённый обход (docs/blocks.md §2)"]
    fn live_pick_openrouter_honest_gateway() {
        let out = run_pick(None, "https://openrouter.ai").expect("run_pick");
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
        assert!(
            matches!(
                geohide.probe,
                Some(ProbeVerdict::GatewayAlive) | Some(ProbeVerdict::GatewayPartial)
            ),
            "фронтинг geohide должен подтверждаться сквозной пробой, а не TCP: {:?}",
            geohide
        );
        if geohide.probe == Some(ProbeVerdict::GatewayPartial) {
            assert_eq!(
                out.verdict_level, "warn",
                "частичный фронтинг — не безусловный «Рабочий DNS»: {}",
                out.summary
            );
        }
    }
}
