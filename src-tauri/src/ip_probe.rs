//! Механика анализа IP-цели во вкладке «Анализ сайта / IP».
//!
//! Урок фазы 1 (tasks/…Фаза 2 — честные пробы…): HTTPS-проба к IP-литералу
//! с SNI=IP ничего не доказывает — фронт (Cloudflare и т.п.) по такому SNI
//! может не давать рукопожатие и в здоровой сети. Поэтому вердикты строятся
//! ТОЛЬКО на: TCP-пробах двух фаз и SNI-эксперименте по кандидатам
//! (HTTPS к `https://домен/`, прибитый сокетом к целевому IP, реюз
//! `site_probe::http_via_ip`).
//!
//! Порядок фаз (важен для честности DNS: DPI может ломать/медлить UDP:53,
//! поэтому резолв списков идёт ПРИ выключенном обходе):
//! 1) TCP с ходом (если обход был включён);
//! 2) обход останавливается (`bypass_toggle`, пауза на выгрузку WinDivert);
//! 3) TCP без обхода;
//! 4) резолв списков (чистый DNS) + сбор IP-литералов — `ip_candidates`;
//! 5) SNI-проба кандидатов без обхода;
//! 6) обход возвращается (`restore_bypass`);
//! 7) SNI-проба кандидатов с обходом.
//!
//! Фазы логируются в UI единым каналом `emit("log")`; провалы не глотаются.
//! Паники фаз 4–5 не оставляют юзера без обхода: зеркало restore обязательное.

use std::net::IpAddr;
use std::time::Duration;

use tauri::{AppHandle, Emitter};

use crate::analyzer_probe::Probe;
use crate::diagnostics_probe::{HttpResult, tcp_connect};
use crate::ip_candidates::{self, ScanOutcome};
use crate::process;

/// Малая пауза после TCP-пробы без обхода — DNS-кэш и состояние сети
/// устаканиваются перед фазой резолва (тяжёлые паузы живут в bypass_toggle).
const PROBE_GAP: Duration = Duration::from_millis(200);

pub(crate) fn app_log(app: &AppHandle, msg: impl Into<String>) {
    let _ = app.emit("log", msg.into());
}

/// Результат пробы TCP к ip:port.
///
/// Семантика нарочито узкая (TCP сам по себе верно различает только
/// «принял/рвёт/молчит»); HTTPS живёт в SNI-эксперименте по кандидатам,
/// где она доказательна (SNI=домен), а не по IP (SNI=IP — недоказательно).
#[derive(Clone, Debug, PartialEq)]
pub enum TcpProbeResult {
    Ok,
    Broken(String),
    DeadIp,
}

/// Сведение сырой строки tcp_connect к результату пробы.
/// Таймаут — это молчащий сервер (DeadIp: см. analyzer_probe::is_dead_ip_error),
/// RST/REFUSED и прочее — обрыв (Broken).
pub fn classify_tcp(raw: &str) -> TcpProbeResult {
    if raw == "Success" {
        return TcpProbeResult::Ok;
    }
    if crate::analyzer_probe::is_dead_ip_error(&raw.to_lowercase()) {
        TcpProbeResult::DeadIp
    } else {
        TcpProbeResult::Broken(raw.to_string())
    }
}

/// Снимок одной TCP-пробы.
#[derive(Clone)]
pub struct IpProbe {
    pub tcp: TcpProbeResult,
}

/// Считается ли TCP-проба живой (порт принял соединение).
pub fn probe_is_ok(p: &IpProbe) -> bool {
    p.tcp == TcpProbeResult::Ok
}

/// Одна TCP-проба к ip:port.
pub fn probe_ip(ip: IpAddr, port: u16) -> IpProbe {
    IpProbe {
        tcp: classify_tcp(&tcp_connect(ip, port)),
    }
}

fn report_probe(p: &IpProbe) -> String {
    match &p.tcp {
        TcpProbeResult::Ok => "TCP: OK".to_string(),
        TcpProbeResult::Broken(e) => format!("TCP: обрыв ({})", first_line(e)),
        TcpProbeResult::DeadIp => "TCP: сервер молчит (таймаут)".to_string(),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

/// Конвертация результата HTTPS-пробы (`site_probe::http_via_ip`) в словарь
/// Probe. Проба меряет ТРАНСПОРТ: любой ответ сервера (200, 403, страница-эхо)
/// означает «TLS-рукопожатие прошло, путь цел»; сломанными считаются
/// RST/ошибка рукопожатия/молчание. BadCert тоже «транспорт цел»: рукопожатие
/// прошло (DPI в наших профилях не подделывает сертификаты), странности
/// сертификата — вопрос сервера, не канала.
pub fn http_result_to_probe(h: &HttpResult) -> Probe {
    match h {
        HttpResult::Ok(_) | HttpResult::BlockPage | HttpResult::Forbidden(_) => Probe::Ok,
        HttpResult::BadCert => Probe::Ok, // рукопожатие прошло — DPI не рвал канал
        HttpResult::Rst => Probe::Broken("соединение сброшено (RST)".to_string()),
        HttpResult::Tls => Probe::Broken("ошибка TLS-рукопожатия".to_string()),
        HttpResult::Timeout => Probe::DeadIp,
        HttpResult::Dns => Probe::Dns,
        HttpResult::Other(e) => Probe::Broken(e.clone()),
    }
}

/// SNI-проба одного домена-кандидата: HTTPS к `https://домен/` (SNI и проверка
/// сертификата доменные), а соединение прибито сокетом к целевому ip:port.
/// Реюз site_probe::http_via_ip — дубль reqwest-клиента запрещён (SSOT).
fn sni_probe(domain: &str, ip: IpAddr, port: u16) -> Probe {
    http_result_to_probe(&crate::site_probe::http_via_ip(domain, ip, port))
}

/// Прогон SNI-проб по всем кандидатам; слот (off/on) заполняется по фазе.
fn sni_probe_candidates(
    app: &AppHandle,
    cands: &mut [crate::ip_candidates::Candidate],
    ip: IpAddr,
    port: u16,
    on: bool,
) {
    for c in cands.iter_mut() {
        let r = sni_probe(&c.domain, ip, port);
        if on {
            c.sni_on = Some(r);
        } else {
            c.sni_off = Some(r);
        }
    }
    app_log(
        app,
        format!(
            "[Анализ IP] SNI-проба кандидатов ({}): {} шт.",
            if on { "с обходом" } else { "без обхода" },
            cands.len()
        ),
    );
}

/// Факты IP-анализа: всё, из чего собирается отчёт.
#[derive(Default)]
pub struct IpFacts {
    pub bypass_was_running: bool,
    pub probe_on: Option<IpProbe>,
    pub probe_off: Option<IpProbe>,
    pub toggled: bool,
    pub restore_note: Option<String>,
    pub candidates: Vec<crate::ip_candidates::Candidate>,
    pub ip_literals: Vec<(String, Vec<std::path::PathBuf>)>,
    /// Записи списков, чей резолв успел провериться в бюджет.
    pub resolve_done: usize,
    /// Всего доменных записей в списках (не IP-литералов).
    pub resolve_total: usize,
    /// Записи, резолв которых не выполнился (таймаут) — не проверены.
    pub resolve_failed: usize,
    pub resolve_budget_hit: bool,
}

pub fn analyze_ip(app: &AppHandle, ip: IpAddr, port: u16) -> IpFacts {
    let bypass_was_running = process::is_winws_running();
    let mut facts = IpFacts {
        bypass_was_running,
        ..Default::default()
    };

    app_log(
        app,
        format!(
            "[Анализ IP] Проверяем {}:{}, обход: {}. Во время анализа обход будет временно выключен (для честных проб и чистого DNS).",
            ip,
            port,
            if facts.bypass_was_running { "ВКЛЮЧЁН" } else { "выключен" }
        ),
    );

    // Фаза A: TCP с живым обходом.
    let mut saved: Option<crate::bypass_toggle::SavedBypass> = None;
    if bypass_was_running {
        let on = probe_ip(ip, port);
        app_log(app, format!("[Анализ IP] TCP-проба с обходом: {}.", report_probe(&on)));
        facts.probe_on = Some(on);

        // Обход выключаем СРАЗУ: все дальнейшие фазы (TCP-контроль, резолв,
        // SNI-проба off) требуют честного канала.
        saved = Some(crate::bypass_toggle::capture_active());
        app_log(app, "[Анализ IP] Останавливаю обход (нужен чистый DNS и контрольная проба; пауза ~1.2 с на выгрузку драйвера)...");
        crate::bypass_toggle::stop_bypass();
        facts.toggled = true;
    }

    // Фаза B: TCP без обхода (контроль).
    let off = probe_ip(ip, port);
    app_log(app, format!("[Анализ IP] TCP-проба без обхода: {}.", report_probe(&off)));
    facts.probe_off = Some(off);
    std::thread::sleep(PROBE_GAP);

    // Фаза C+D: резолв и SNI-проба off — при выключенном обходе. Паники
    // здесь не оставляют юзера без обхода: после них mirror-восстановление.
    app_log(app, "[Анализ IP] Ищу в списках обхода домены, чьи адреса резолвятся в этот IP (DNS сейчас чистый)...");
    let map = crate::bypass_lists::load_bypass_domains();
    let outcome = catch_phase(
        app,
        "[Анализ IP] Фаза резолва упала",
        ip_candidates::ScanOutcome::empty,
        || ip_candidates::scan_candidates_with_system_dns(app, &map, ip),
    );
    let ScanOutcome { candidates, ip_literals, done, total, failed, budget_hit } = outcome;

    let mut candidates = candidates;
    if !candidates.is_empty() {
        catch_phase(
            app,
            "[Анализ IP] Фаза SNI-пробы (без обхода) упала",
            || (),
            || sni_probe_candidates(app, &mut candidates, ip, port, false),
        );
    }

    facts.candidates = candidates;
    facts.ip_literals = ip_literals;
    facts.resolve_done = done;
    facts.resolve_total = total;
    facts.resolve_failed = failed;
    facts.resolve_budget_hit = budget_hit;
    // Пометка «уже в list-exclude»: реюз bypass_lists::is_excluded,
    // чтобы отчёт не советовал дубль для уже исключённого домена.
    let exclude_set = crate::bypass_lists::load_exclude_domains();
    for c in &mut facts.candidates {
        c.already_excluded = crate::bypass_lists::is_excluded(&c.domain, &exclude_set);
    }
    app_log(
        app,
        format!(
            "[Анализ IP] Резолв списков: проверено {} из {} записей{}, кандидатов {}.",
            facts.resolve_done,
            facts.resolve_total,
            if facts.resolve_failed > 0 {
                format!(" (не резолвнулось: {})", facts.resolve_failed)
            } else {
                String::new()
            },
            facts.candidates.len()
        ),
    );

    // Восстановление обхода ВСЕГДА, если сами останавливали.
    if let (true, Some(s)) = (facts.toggled, saved.as_ref()) {
        facts.restore_note = crate::bypass_toggle::restore_bypass(app, s);
    }

    // Фаза E: SNI-проба с включённым обходом (тот же путь, что у браузера).
    if facts.toggled && !facts.candidates.is_empty() {
        catch_phase(
            app,
            "[Анализ IP] Фаза SNI-пробы (с обходом) упала",
            || (),
            || sni_probe_candidates(app, &mut facts.candidates, ip, port, true),
        );
    }

    facts
}

/// Панель панических фаз: ошибка не остаётся молчаливой (лог), что бы ни
/// случилось — анализ продолжается на fallback-значении, а restore-фаза
/// гарантированно дойдёт (юзер не остаётся без обхода).
fn catch_phase<T>(
    app: &AppHandle,
    msg: &str,
    fallback: impl FnOnce() -> T,
    f: impl FnOnce() -> T,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            app_log(app, format!("{} — продолжаю анализ, обход будет восстановлен.", msg));
            fallback()
        }
    }
}
