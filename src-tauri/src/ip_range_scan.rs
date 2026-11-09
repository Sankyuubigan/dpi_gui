//! Диагностика блока сервера/IP/CDN для главного домена + поиск рабочего IP.
//!
//! Подход (после разбора профессионала): 403 от Cloudflare бывает разным, поэтому
//! сначала пробуются «родные» IP домена, полученные через нейтральный DoH JSON
//! (запрос прямо на IP — 1.1.1.1/8.8.8.8, без SNI-домена). По ответам выносится
//! вердикт; скан опубликованных CIDR Cloudflare запускается только когда
//! транспорт к родным IP не работает (RST/TLS/таймаут) — т.е. вероятна блокировка
//! цензором IP/подсети, и есть смысл искать живой альтернативный IP.
//!
//! Классификация 403:
//! - `error code: 1034/1003/1000` в теле → «чужой VIP» (edge не обслуживает
//!   зону; защита от domain fronting) — НЕ доказательство гео-блока;
//! - маркеры WAF («Attention Required! | Cloudflare», «Sorry, you have been
//!   blocked», «Access denied», заголовок cf-mitigated) → WAF/гео/капча;
//! - прочее → «голый» отказ (причина не распознана).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::ACCEPT;
use tauri::AppHandle;

use crate::diagnostics_probe::{classify_reqwest_err, run_with_timeout, HttpResult};
use crate::ip_probe::app_log;
use crate::probe_budget::StageBudget;

/// «Родных» адресов домена достаточно проверить по первым нескольким.
const NATIVE_PROBE_LIMIT: usize = 3;
/// Сколько случайных IP берём из каждого CIDR при скане.
const PER_CIDR: usize = 4;
/// Пачка параллельных проб.
const CHUNK: usize = 12;
/// Таймаут одной HTTP-пробы (IP закреплён).
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
/// Внешний дедлайн этапа `ClientBuilder::build()` внутри probe(). У reqwest
/// blocking build запускает runtime-поток и ждёт его БЕЗ внутреннего дедлайна
/// (инцидент 03.11.26: воркер анализа заклинил в probe() второй итерации) —
/// поэтому построчный этап дополнительно страхуется снаружи.
const BUILD_TIMEOUT: Duration = Duration::from_secs(3);
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// Штатный бюджет скана диапазонов.
const SCAN_BUDGET: Duration = Duration::from_secs(90);

/// Скан собственной сети сайта (соседние /24): максимум диапазонов и адресов
/// из каждого. Для сайтов не на Cloudflare скан CF-пула неприменим (кейс
/// sostav.ru) — честный пул это /24 вокруг родных адресов сайта: у сайтов
/// на своей инфраструктуре пул фронтендов живёт в одной /24 (GeoDNS,
/// кейс 05.11.26 web.telegram.org — 149.154.167.0/24).
const NEIGHBORHOOD_MAX_RANGES: usize = 3;
const NEIGHBORHOOD_PER_RANGE: usize = 96;

const CIDR_GITHUB: &str =
    "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ip.txt";
const CIDR_JSON: &str = "https://api.cloudflare.com/client/v4/ips";
const CIDR_TEXT: &str = "https://www.cloudflare.com/ips-v4";

/// Классификация HTTP-отказа (только для 403/451).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// Edge не обслуживает эту зону (защита от domain fronting).
    GuestVip,
    /// WAF/гео/капча-маркеры (cf-mitigated, Attention Required, ...).
    WafChallenge,
    /// «Голый» отказ без узнаваемых маркеров.
    Plain,
}

/// Результат HTTP-пробы одного IP (с телом для классификации 403).
#[derive(Debug, Clone)]
pub enum HttpOutcome {
    Http { status: u16, body_head: String, cf_mitigated: bool },
    Rst,
    Tls,
    Timeout,
    Other(String),
}

impl HttpOutcome {
    pub fn is_transport_dead(&self) -> bool {
        matches!(self, HttpOutcome::Rst | HttpOutcome::Tls | HttpOutcome::Timeout)
    }
}

/// Откуда взяты диапазоны скана (единый источник правды для логов и отчёта).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanSource {
    /// Официальный список CIDR Cloudflare (число диапазонов скачанного списка).
    Cloudflare { ranges_count: usize },
    /// Собственная сеть сайта: /24 вокруг её родных публичных IPv4.
    /// `cf_note` — почему скан шёл мимо списка CF (список не скачался).
    Neighborhood { ranges: Vec<String>, cf_note: Option<String> },
}

/// Итог разбора блока главного домена (то, что попадает в отчёт).
#[derive(Debug, Clone)]
pub enum BlockScanReport {
    /// Транспорт до родного IP прошёл, сайт отвечает нормально.
    Accessible { http: u16 },
    /// Отказ от сервера с WAF-маркерами (гео/капча) — смена IP не поможет.
    WafRefusal { status: u16, evidence: Vec<String> },
    /// 403/451 без узнаваемых маркеров (причина точно не распознана, но
    /// соединение до сервера прошло — подбор IP не поможет).
    PlainRefusal { status: u16, evidence: Vec<String> },
    /// Сервер отвечает 5xx — ошибка приложения, это НЕ блокировка.
    ServerFault { status: u16 },
    /// Транспорт к родным IP не работал — выполнен скан диапазонов
    /// (Cloudflare или собственная сеть сайта — см. ScanSource).
    RangesScanned(RangeScanOutcome),
    /// Разбор не состоялся (нет адресов/не классифицировался ответ).
    NoPath { why: String },
}

/// Итог скана диапазонов (Cloudflare или собственная сеть сайта) с поиском
/// рабочего IP.
#[derive(Debug, Clone)]
pub struct RangeScanOutcome {
    /// Источник пула — определяет заголовок и строку источника в отчёте.
    pub source: ScanSource,
    /// Размер пула проверяемых IP.
    pub pool_size: usize,
    /// Сколько из пула реально проверено (могли не успеть по бюджету).
    pub probed: usize,
    /// Живые HTTP-ответы (любой статус).
    pub alive_count: usize,
    /// 403 «чужой VIP» (error code 1034/1003/1000).
    pub guest_refusal_count: usize,
    /// 403/451 с WAF-маркерами (гео/капча).
    pub waf_refusal_count: usize,
    /// Прочие 403/451 без маркеров.
    pub other_status_count: usize,
    /// Рабочие адреса с позитивным ответом (2xx/3xx).
    pub working: Vec<(IpAddr, u16)>,
}

/// Чистая классификация 403/451 по телу (и флагу заголовка cf-mitigated).
pub fn classify_refusal(status: u16, cf_mitigated: bool, body_head: &str) -> RefusalKind {
    if status != 403 && status != 451 {
        return RefusalKind::Plain; // вызов имеет смысл только для 403/451
    }
    let low = body_head.to_lowercase();
    if low.contains("error code: 1034")
        || low.contains("error code: 1003")
        || low.contains("error code: 1000")
    {
        return RefusalKind::GuestVip;
    }
    if cf_mitigated
        || low.contains("attention required")
        || low.contains("sorry, you have been blocked")
        || low.contains("access denied")
    {
        return RefusalKind::WafChallenge;
    }
    RefusalKind::Plain
}

// --- CIDR ----------------------------------------------------------------

struct Cidr {
    base: u32,
    bits: u32,
}

fn parse_cidr(s: &str) -> Result<Cidr, String> {
    let (addr, bits_str) = s
        .split_once('/')
        .ok_or_else(|| format!("CIDR без '/': {s}"))?;
    let bits: u32 = bits_str
        .trim()
        .parse()
        .map_err(|_| format!("маска не число: {bits_str}"))?;
    if bits > 32 {
        return Err(format!("маска больше 32 (это не IPv4): {bits}"));
    }
    let base: Ipv4Addr = addr
        .trim()
        .parse()
        .map_err(|_| format!("адрес не IPv4: {addr}"))?;
    Ok(Cidr {
        base: u32::from(base),
        bits,
    })
}

/// Входит ли IPv4-адрес хотя бы в один из диапазонов. Чистая функция.
fn ip_in_cidrs(ip: &IpAddr, cidrs: &[Cidr]) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let num = u32::from(*v4);
            cidrs.iter().any(|c| {
                let host_bits = 32 - c.bits;
                num >> host_bits == c.base >> host_bits
            })
        }
        // Скан CF-пула только по IPv4.
        IpAddr::V6(_) => false,
    }
}

fn now_seed() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut z = t;
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut r = z;
    r = (r ^ (r >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    r = (r ^ (r >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    r ^ (r >> 31)
}

fn next_u32(seed: &mut u64) -> u32 {
    *seed = seed
        .wrapping_add(0x9E37_79B9_7F4A_7C15)
        .wrapping_mul(0x94D0_49BB_1331_11EB)
        | 1;
    (*seed ^ (*seed >> 33)) as u32
}

/// Из каждого CIDR — `per_range` случайных адресов (по одному на случайный
/// /24-блок диапазона; для самой /24 — случайные адреса её подсети).
fn sample_pool(cidrs: &[Cidr], per_range: usize, seed: &mut u64) -> Vec<IpAddr> {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut pool = Vec::new();
    for c in cidrs {
        let host_bits = (32 - c.bits).min(32);
        let blocks: u32 = if host_bits >= 8 {
            1u32 << (host_bits - 8).min(24)
        } else {
            1
        };
        for _ in 0..per_range {
            let mut ip_num = c.base;
            if host_bits >= 8 {
                let idx = if blocks > 1 { next_u32(seed) % blocks } else { 0 };
                ip_num = c.base.wrapping_add(idx << 8);
            }
            let last = next_u32(seed) % 254 + 1; // 1..=254, без .0/.255
            ip_num = (ip_num & !0xFF) | last;
            if seen.insert(ip_num) {
                pool.push(IpAddr::V4(Ipv4Addr::from(ip_num)));
            }
        }
    }
    pool
}

/// Соседние /24-диапазоны сайта: для каждого публичного IPv4 — его подсеть
/// a.b.c.0/24. Чистая функция: приватные/служебные адреса и дубли отбрасываются,
/// диапазонов не больше NEIGHBORHOOD_MAX_RANGES (порядок — как пришли адреса).
fn neighborhood_ranges(native: &[IpAddr]) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for ip in native {
        let v4 = match ip {
            // resolve_neutral отдаёт только A-записи; IPv6 сюда не дойдёт,
            // а сканировать соседей /64 в разумный бюджет нереализуемо.
            IpAddr::V4(v4) => *v4,
            IpAddr::V6(_) => continue,
        };
        // Приватные/служебные сети не сканируем: родные адреса публичного
        // сайта не бывают такими, а мусор в пуле дал бы бессмысленные пробы.
        let junk = v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_unspecified()
            || v4.is_documentation();
        if junk {
            continue;
        }
        let [o1, o2, o3, _] = v4.octets();
        let cidr = Cidr { base: u32::from(Ipv4Addr::new(o1, o2, o3, 0)), bits: 24 };
        if !out.iter().any(|c| c.base == cidr.base) {
            out.push(cidr);
            if out.len() >= NEIGHBORHOOD_MAX_RANGES {
                break;
            }
        }
    }
    out
}

/// Строка CIDR для логов и отчёта (neighborhood всегда /24).
fn cidr_to_string(c: &Cidr) -> String {
    format!("{}/{}", Ipv4Addr::from(c.base), c.bits)
}

// --- Официальный список CIDR ---------------------------------------------

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| format!("HTTP-клиент: {e}"))
}

fn lines_with_cidr(body: &str) -> Vec<String> {
    body.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.contains('/') && parse_cidr(l).is_ok())
        .collect()
}

fn fetch_github(client: &Client) -> Result<Vec<String>, String> {
    let body = client
        .get(CIDR_GITHUB)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
        .map_err(|e| format!("{CIDR_GITHUB}: {e}"))?;
    let v = lines_with_cidr(&body);
    if v.is_empty() {
        return Err("файл диапазонов пуст".to_string());
    }
    Ok(v)
}

fn fetch_cf_json(client: &Client) -> Result<Vec<String>, String> {
    let body = client
        .get(CIDR_JSON)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
        .map_err(|e| format!("{CIDR_JSON}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("JSON разбора: {e}"))?;
    let arr = v
        .get("result")
        .and_then(|r| r.get("ipv4_cidrs"))
        .and_then(|x| x.as_array())
        .ok_or_else(|| "JSON без result.ipv4_cidrs".to_string())?;
    let mut out = Vec::new();
    for it in arr {
        if let Some(s) = it.as_str() {
            out.push(s.to_string());
        }
    }
    if out.is_empty() {
        return Err("JSON вернул пустой список".to_string());
    }
    Ok(out)
}

fn fetch_cf_text(client: &Client) -> Result<Vec<String>, String> {
    let body = client
        .get(CIDR_TEXT)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
        .map_err(|e| format!("{CIDR_TEXT}: {e}"))?;
    let v = lines_with_cidr(&body);
    if v.is_empty() {
        return Err("текстовый список пуст".to_string());
    }
    Ok(v)
}

/// Официальный список CIDR Cloudflare: GitHub raw → CF JSON API → CF текст.
/// Возвращает (список, имя источника). Все три ошибки — честная причина.
fn fetch_cidrs() -> Result<(Vec<String>, &'static str), String> {
    let client = http_client()?;
    let mut errors = Vec::new();
    match fetch_github(&client) {
        Ok(v) => return Ok((v, "GitHub raw (XIU2/CloudflareSpeedTest)")),
        Err(e) => errors.push(format!("GitHub: {e}")),
    }
    match fetch_cf_json(&client) {
        Ok(v) => return Ok((v, "api.cloudflare.com")),
        Err(e) => errors.push(format!("CF API: {e}")),
    }
    match fetch_cf_text(&client) {
        Ok(v) => return Ok((v, "cloudflare.com/ips-v4")),
        Err(e) => errors.push(format!("CF text: {e}")),
    }
    Err(errors.join("; "))
}

// --- Нейтральный DoH JSON -------------------------------------------------

/// DoH JSON прямо на IP-адрес (TLS без SNI-имени; сертификат проверяется по IP).
const NEUTRAL_DOH: &[(&str, &str)] = &[("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve")];

/// Резолв домена через нейтральные DoH JSON. Порядок: 1.1.1.1 → 8.8.8.8 →
/// системный DNS (последний фолбэк, честно помечается).
fn resolve_neutral(host: &str) -> Result<(Vec<IpAddr>, String), String> {
    let client = http_client()?;
    let mut errors = Vec::new();
    for (ip, path) in NEUTRAL_DOH {
        let url = format!("https://{ip}{path}?name={host}&type=A");
        let body = client
            .get(&url)
            .header(ACCEPT, "application/dns-json")
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.text())
            .map_err(|e| format!("DoH {ip}: {e}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("DoH {ip}: JSON разбора: {e}"))?;
        let answer = v
            .get("Answer")
            .and_then(|a| a.as_array())
            .ok_or_else(|| format!("DoH {ip}: ответ без Answer"))?;
        let mut ips = Vec::new();
        for a in answer {
            let is_a = a.get("type").and_then(|t| t.as_i64()) == Some(1);
            if let (true, Some(data)) = (is_a, a.get("data").and_then(|d| d.as_str())) {
                if let Ok(x) = data.parse::<IpAddr>() {
                    // Заглушки (0.0.0.0 и т.п.) — это отказ резолвера, а не адрес.
                    if x != IpAddr::from([0, 0, 0, 0]) {
                        ips.push(x);
                    }
                }
            }
        }
        if !ips.is_empty() {
            return Ok((ips, format!("DoH {ip} (запрос по IP, без SNI-имени)")));
        }
        errors.push(format!("DoH {ip}: Answer без A-записей"));
    }
    // Системный DNS — только как последний фолбэк (может быть отравлен).
    use std::net::ToSocketAddrs;
    let sock: Vec<_> = format!("{host}:0")
        .to_socket_addrs()
        .map_err(|e| format!("системный DNS: {e}"))?
        .collect();
    let ips: Vec<IpAddr> = sock.iter().map(|a| a.ip()).filter(|i| i.is_ipv4()).collect();
    if ips.is_empty() {
        return Err(format!(
            "нейтральные DoH молчали ({}), системный DNS пуст",
            errors.join("; ")
        ));
    }
    Ok((
        ips,
        "системный DNS (нейтральные DoH молчали — адрес не могли проверить)".to_string(),
    ))
}

// --- HTTP-проба с телом ---------------------------------------------------

/// Создание reqwest-клиента пробы (IP закреплён через `.resolve`). Вынесено,
/// чтобы этап build обёртываться в run_with_timeout отдельно от send: у build
/// внутреннего дедлайна нет совсем.
fn build_probe_client(host: &str, ip: IpAddr) -> Result<Client, String> {
    Client::builder()
        .resolve(host, std::net::SocketAddr::new(ip, 443))
        .timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|e| format!("клиент[{ip}]: {e}"))
}

/// send+чтение тела пробы (этап с внутренним total-таймаутом PROBE_TIMEOUT).
fn send_probe(client: &Client, host: &str) -> HttpOutcome {
    let url = format!("https://{host}/");
    match client.get(&url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let cf_mitigated = resp
                .headers()
                .get("cf-mitigated")
                .and_then(|v| v.to_str().ok())
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            let mut body_head = resp.text().unwrap_or_default();
            if body_head.len() > 512 {
                body_head.truncate(512);
            }
            HttpOutcome::Http { status, body_head, cf_mitigated }
        }
        Err(e) => {
            // SSOT (core rules): причина ошибки разбирается ЕДИНСТВЕННОЙ
            // функцией classify_reqwest_err — она ходит по цепочке error.source()
            // reqwest, поэтому HttpOutcome::Other несёт КОНКРЕТНУЮ причину
            // («соединение сброшено», «истёк таймаут», «ошибка сертификата»),
            // а не голое «error sending request for url».
            match classify_reqwest_err(&e) {
                HttpResult::Rst => HttpOutcome::Rst,
                HttpResult::Timeout => HttpOutcome::Timeout,
                // Для скана чужой сертификат и TLS-обрыв равнозначны: сайт
                // HTTP-ответом не ответил.
                HttpResult::Tls | HttpResult::BadCert => HttpOutcome::Tls,
                HttpResult::Dns => {
                    HttpOutcome::Other(
                        "ошибка резолва имени, хотя IP закреплён за клиентом напрямую".to_string(),
                    )
                }
                HttpResult::Other(t) => HttpOutcome::Other(t),
                // Классификатор причин здесь иное не возвращает; не паникуем —
                // честный текст вместо выдуманного статуса.
                other => {
                    HttpOutcome::Other(format!("неожиданный итог классификации: {other:?}"))
                }
            }
        }
    }
}

/// Проба без внешних логов (используется параллельным сканом).
fn probe(host: &str, ip: IpAddr) -> HttpOutcome {
    match build_probe_client(host, ip) {
        Ok(c) => send_probe(&c, host),
        Err(e) => HttpOutcome::Other(e),
    }
}

/// Проба родного IP с внешними дедлайнами на КАЖДЫЙ этап (build/send) и
/// логом-дискриминатором. По инциденту 03.11.26 .timeout() reqwest'а не
/// гарантирует возврат URL-вызова: build ждёт bootstrap runtime-потока без
/// дедлайна, а внутренний таймер не прерывает заклинивший syscall уровне ОС.
/// Здесь каждый этап ограничен извне SSOT-обёрткой
/// `diagnostics_probe::run_with_timeout`: заклинивший поток оставляется
/// зомби (это дешевле вечного зависания воркера), пробе возвращается
/// честный Outcome.
fn probe_with_app(app: &AppHandle, host: &str, ip: IpAddr) -> HttpOutcome {
    // Этап 1: build (внутреннего дедлайна нет — внешний обязателен).
    let t_build = Instant::now();
    let h = host.to_string();
    let stage_client =
        run_with_timeout(move || build_probe_client(&h, ip), BUILD_TIMEOUT.as_millis() as u64);
    let client = match stage_client {
        Some(Ok(c)) => {
            app_log(
                app,
                format!("[IPSCAN] клиент[{ip}]: build ok {} мс", t_build.elapsed().as_millis()),
            );
            c
        }
        Some(Err(e)) => {
            let msg = format!("{e} (build {} мс)", t_build.elapsed().as_millis());
            app_log(app, format!("[IPSCAN] клиент[{ip}]: build fail: {msg}"));
            return HttpOutcome::Other(msg);
        }
        None => {
            let msg = format!(
                "клиент[{ip}]: build заклинил — внешний дедлайн {} мс, поток брошен",
                BUILD_TIMEOUT.as_millis()
            );
            app_log(app, format!("[IPSCAN] {msg}"));
            return HttpOutcome::Other(msg);
        }
    };

    // Этап 2: send+чтение (внутренний total-таймаут PROBE_TIMEOUT, внешний —
    // с запасом +2 c, чтобы внутренний успел сработать первым).
    let stage_deadline = PROBE_TIMEOUT + Duration::from_secs(2);
    let t_send = Instant::now();
    let h = host.to_string();
    match run_with_timeout(
        move || send_probe(&client, &h),
        stage_deadline.as_millis() as u64,
    ) {
        Some(o) => {
            app_log(
                app,
                format!("[IPSCAN] клиент[{ip}]: send ok {} мс", t_send.elapsed().as_millis()),
            );
            o
        }
        None => {
            let msg = format!(
                "клиент[{ip}]: send заклинил — внешний дедлайн {} мс, поток брошен",
                stage_deadline.as_millis()
            );
            app_log(app, format!("[IPSCAN] {msg}"));
            HttpOutcome::Timeout
        }
    }
}

fn describe_outcome(o: &HttpOutcome) -> String {
    match o {
        HttpOutcome::Http { status, body_head, cf_mitigated } => {
            let marker = match classify_refusal(*status, *cf_mitigated, body_head) {
                RefusalKind::GuestVip => " — «чужой VIP» (error code 1034/1003/1000)",
                RefusalKind::WafChallenge => " — маркеры WAF/гео/капчи",
                RefusalKind::Plain => " — без WAF-маркеров",
            };
            format!("HTTP {status}{marker}")
        }
        HttpOutcome::Rst => "RST (сброс соединения)".to_string(),
        HttpOutcome::Tls => "TLS-ошибка (рукопожатие не прошло)".to_string(),
        HttpOutcome::Timeout => "таймаут".to_string(),
        HttpOutcome::Other(t) => {
            let mut t = t.clone();
            if t.len() > 160 {
                t.truncate(160);
            }
            t
        }
    }
}

// --- Дерево решений -------------------------------------------------------

/// Разбор блока главного домена: нейтральный DoH → пробы родных IP → вердикт.
/// Скан CIDR-диапазонов запускается только если транспорт к родным IP умер.
///
/// `budget` — остаток общего бюджета чистого окна анализа: скану достаётся
/// `min(остаток, SCAN_BUDGET)`, по исчерпанию часть пула честно помечается
/// непроверенной.
pub fn block_diagnose(app: &AppHandle, host: &str, budget: StageBudget) -> BlockScanReport {
    if budget.stopped() {
        return BlockScanReport::NoPath {
            why: "не проверено: не хватило бюджета окна".to_string(),
        };
    }
    let t0 = Instant::now();
    app_log(app, format!("[IPSCAN] разбор блока для {host}..."));

    let (native_ips, resolver_note) = {
        // Внешний дедлайн резолва: 2 DoH по FETCH_TIMEOUT + запас на системный
        // фолбэк (иначе зависший DoH-вызов вечен прямо при старте разбора).
        let resolver_ceiling = FETCH_TIMEOUT * 2 + Duration::from_secs(10);
        let h = host.to_string();
        match run_with_timeout(
            move || resolve_neutral(&h),
            resolver_ceiling.as_millis() as u64,
        ) {
            Some(Ok(res)) => res,
            Some(Err(e)) => {
                let why = format!("не удалось получить адреса домена: {e}");
                app_log(app, format!("[IPSCAN] {why}"));
                return BlockScanReport::NoPath { why };
            }
            None => {
                let why = format!(
                    "не удалось получить адреса домена: резолв не уложился во внешний дедлайн {} мс",
                    resolver_ceiling.as_millis()
                );
                app_log(app, format!("[IPSCAN] {why}"));
                return BlockScanReport::NoPath { why };
            }
        }
    };
    app_log(
        app,
        format!(
            "[IPSCAN] адреса ({}): {} | {} сек",
            resolver_note,
            native_ips
                .iter()
                .take(NATIVE_PROBE_LIMIT)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            t0.elapsed().as_secs()
        ),
    );

    // Проба родных IP. Каждый этап с внешним дедлайном (probe_with_app):
    // заклинившая проба больше не стопорит весь анализ (инцидент 03.11.26).
    let mut outcomes: Vec<HttpOutcome> = Vec::new();
    // Честные описания всех непроизошедших HTTP-ответов (для итогового лога,
    // core §2.2): «чужой VIP» мы не имеем права называть, если ответов не было.
    let mut native_notes: Vec<String> = Vec::new();
    let mut last_err = String::from("без ответа");
    for ip in native_ips.iter().take(NATIVE_PROBE_LIMIT) {
        let t_ip = Instant::now();
        let o = probe_with_app(app, host, *ip);
        let note =
            format!("{} ({} мс)", describe_outcome(&o), t_ip.elapsed().as_millis());
        if o.is_transport_dead() {
            last_err = note.clone();
            app_log(app, format!("[IPSCAN] родной {ip}: {note}"));
        } else {
            app_log(app, format!("[IPSCAN] родной {ip}: {note}"));
            native_notes.push(note);
            outcomes.push(o);
        }
    }

    if outcomes.is_empty() {
        app_log(
            app,
            format!(
                "[IPSCAN] родные IP не отвечают ({last_err}) — проверяю принадлежность Cloudflare"
            ),
        );
        return decide_range_scan(app, host, &native_ips, budget);
    }

    let mut working: Option<u16> = None;
    let mut waf_refusal: Option<u16> = None;
    let mut plain_refusal: Option<u16> = None;
    let mut guest_only = true;
    let mut server_fault: Option<u16> = None;
    let mut evidence: Vec<String> = Vec::new();
    for o in &outcomes {
        if let HttpOutcome::Http { status, body_head, cf_mitigated } = o {
            if (200..=399).contains(status) {
                working = Some(*status);
            } else if (500..=599).contains(status) {
                server_fault = Some(*status);
                guest_only = false;
            } else if *status == 403 || *status == 451 {
                match classify_refusal(*status, *cf_mitigated, body_head) {
                    RefusalKind::WafChallenge => {
                        guest_only = false;
                        if waf_refusal.is_none() {
                            waf_refusal = Some(*status);
                            evidence.push(describe_outcome(o));
                        }
                    }
                    RefusalKind::GuestVip => {
                        // Аномалия на родном IP; не доказательство гео-блока.
                        evidence.push(describe_outcome(o));
                    }
                    RefusalKind::Plain => {
                        guest_only = false;
                        if plain_refusal.is_none() {
                            plain_refusal = Some(*status);
                            evidence.push(describe_outcome(o));
                        }
                    }
                }
            } else {
                // Прочие 4xx: зона дожила до приложения.
                guest_only = false;
                if server_fault.is_none() {
                    server_fault = Some(*status);
                }
            }
        }
    }

    if let Some(http) = working {
        return BlockScanReport::Accessible { http };
    }
    if let Some(s) = waf_refusal {
        return BlockScanReport::WafRefusal { status: s, evidence };
    }
    if let Some(s) = plain_refusal {
        return BlockScanReport::PlainRefusal { status: s, evidence };
    }
    if let Some(s) = server_fault {
        return BlockScanReport::ServerFault { status: s };
    }
    if guest_only {
        // Честность (core §2.2): «чужой VIP» — про HTTP-ответ 403 с маркером
        // 1034/1003/1000. Если HTTP-ответов не было вовсе (только прочие
        // ошибки клиента) — называть VIP ложь; но скан CIDR уместен и тут.
        let any_http = outcomes
            .iter()
            .any(|o| matches!(o, HttpOutcome::Http { .. }));
        if any_http {
            app_log(
                app,
                "[IPSCAN] родные IP отдали только «чужой VIP» 403 — уточняю сканом CF-пула",
            );
        } else {
            app_log(
                app,
                format!(
                    "[IPSCAN] родные IP не классифицированы ({}) — уточняю сканом CF-пула",
                    native_notes.join("; ")
                ),
            );
        }
        return decide_range_scan(app, host, &native_ips, budget);
    }
    BlockScanReport::NoPath { why: "не удалось классифицировать ответ родных IP".to_string() }
}

// --- Скан CIDR-диапазонов --------------------------------------------------

/// Решает, откуда взять пул для скана, и выполняет его.
///
/// Ложь «цензор закрывает весь пул» для сайта не на Cloudflare (кейс
/// sostav.ru — сайт на 185.71.x.x, а сканировались адреса CF) исключена
/// разделением источников: для CF-сайтов сканируется официальный список
/// диапазонов CF, для всех остальных — СОБСТВЕННАЯ сеть сайта (соседние /24
/// вокруг его родных адресов). Если список CF не скачался, принадлежность
/// сайта неизвестна — но скан собственной сети честен и без списка.
fn decide_range_scan(
    app: &AppHandle,
    host: &str,
    native_ips: &[IpAddr],
    budget: StageBudget,
) -> BlockScanReport {
    // Внешний дедлайн получения списка CIDR: 3 источника по FETCH_TIMEOUT
    // (плюс build клиента) + запас; иначе зависший запрос к raw.githubusercontent
    // держит разбор вечнее воркера (см. инцидент 03.11.26).
    let fetch_ceiling = FETCH_TIMEOUT * 3 + Duration::from_secs(10);
    let cf_list: Result<(Vec<Cidr>, usize, &'static str), String> =
        match run_with_timeout(fetch_cidrs, fetch_ceiling.as_millis() as u64) {
            Some(Ok((cidr_text, source))) => {
                let mut parsed = Vec::new();
                for c in &cidr_text {
                    match parse_cidr(c) {
                        Ok(x) => parsed.push(x),
                        Err(e) => app_log(app, format!("[IPSCAN] CIDR пропущен ({e}): {c}")),
                    }
                }
                Ok((parsed, cidr_text.len(), source))
            }
            Some(Err(e)) => Err(e),
            None => Err(format!(
                "скачивание CIDR не уложилось во внешний дедлайн {} мс",
                fetch_ceiling.as_millis()
            )),
        };

    match cf_list {
        Ok((parsed, ranges_count, source)) => {
            if native_ips.iter().any(|ip| ip_in_cidrs(ip, &parsed)) {
                app_log(
                    app,
                    format!("[IPSCAN] сайт на Cloudflare ({source}) — скан диапазонов"),
                );
                BlockScanReport::RangesScanned(scan_ranges(
                    app,
                    host,
                    &parsed,
                    ScanSource::Cloudflare { ranges_count },
                    PER_CIDR,
                    budget,
                ))
            } else {
                app_log(
                    app,
                    "[IPSCAN] родные IP вне диапазонов Cloudflare — скан соседних /24 сети сайта",
                );
                neighborhood_scan(app, host, native_ips, None, budget)
            }
        }
        Err(e) => {
            app_log(
                app,
                format!("[IPSCAN] список CIDR не получен ({e}) — скан соседних /24 сети сайта"),
            );
            neighborhood_scan(app, host, native_ips, Some(e), budget)
        }
    }
}

/// Скан собственной сети сайта: /24 вокруг родных публичных IPv4.
/// `cf_note` — причина, по которой скан идёт мимо списка CF (список не скачался).
fn neighborhood_scan(
    app: &AppHandle,
    host: &str,
    native_ips: &[IpAddr],
    cf_note: Option<String>,
    budget: StageBudget,
) -> BlockScanReport {
    let ranges = neighborhood_ranges(native_ips);
    if ranges.is_empty() {
        let why = "родные адреса не годятся для скана соседей (публичных IPv4 нет)".to_string();
        app_log(app, format!("[IPSCAN] {why}"));
        return BlockScanReport::NoPath { why };
    }
    let range_strs: Vec<String> = ranges.iter().map(cidr_to_string).collect();
    BlockScanReport::RangesScanned(scan_ranges(
        app,
        host,
        &ranges,
        ScanSource::Neighborhood { ranges: range_strs, cf_note },
        NEIGHBORHOOD_PER_RANGE,
        budget,
    ))
}

fn scan_ranges(
    app: &AppHandle,
    host: &str,
    parsed: &[Cidr],
    source: ScanSource,
    per_range: usize,
    budget: StageBudget,
) -> RangeScanOutcome {
    let t0 = Instant::now();
    app_log(app, format!("[IPSCAN] CIDR: {} шт", parsed.len()));

    let mut seed = now_seed();
    let pool = sample_pool(parsed, per_range, &mut seed);
    let scan_budget = budget.left().min(SCAN_BUDGET);
    app_log(
        app,
        format!("[IPSCAN] пул: {} IP (по {per_range} из каждого), бюджет {} сек", pool.len(), scan_budget.as_secs()),
    );

    let mut res = RangeScanOutcome {
        source,
        pool_size: pool.len(),
        probed: 0,
        alive_count: 0,
        guest_refusal_count: 0,
        waf_refusal_count: 0,
        other_status_count: 0,
        working: Vec::new(),
    };
    let deadline = Instant::now() + scan_budget;
    // Внешний дедлайн одной пробы пула (send 6 с + запас на build/OS-клин;
    // инцидент 03.11.26: проба без внешнего дедлайна заклинила воркер).
    let probe_ceiling = (PROBE_TIMEOUT + Duration::from_secs(2)).as_millis() as u64;
    for chunk in pool.chunks(CHUNK) {
        if Instant::now() > deadline {
            app_log(
                app,
                "[IPSCAN] бюджет скана исчерпан; часть пула не проверена".to_string(),
            );
            break;
        }
        // Пачка параллельных проб с ОГРАНИЧЕННЫМ ожиданием: старый вариант
        // (std::thread::scope + join) ждал зависший поток вечно. Теперь каждый
        // поток шлёт результат в канал, а главный поток собирает пачку по
        // одному recv_timeout со дедлайном чанка; неуспевшие пробы честно
        // помечаются брошенными.
        let (tx, rx) = std::sync::mpsc::channel::<(IpAddr, HttpOutcome)>();
        let mut spawned = 0usize;
        for ip in chunk {
            let ip = *ip;
            let h = host.to_string();
            let tx = tx.clone();
            spawned += 1;
            std::thread::spawn(move || {
                let out = run_with_timeout(move || probe(&h, ip), probe_ceiling);
                let o = out.unwrap_or_else(|| {
                    HttpOutcome::Other(
                        "проба не уложилась во внешний дедлайн (поток брошен)".to_string(),
                    )
                });
                let _ = tx.send((ip, o));
            });
        }
        drop(tx); // не держим копию отправителя — канал закроется после всех проб
        let chunk_deadline = deadline.min(Instant::now() + PROBE_TIMEOUT + Duration::from_secs(4));
        let got: Vec<(IpAddr, HttpOutcome)> = {
            let mut acc = Vec::with_capacity(spawned);
            loop {
                // Ждём результат или дедлайн чанка
                let remaining = chunk_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match rx.recv_timeout(remaining) {
                    Ok((ip, o)) => acc.push((ip, o)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            acc
        };
        if got.len() < spawned {
            let abandoned = spawned - got.len();
            app_log(
                app,
                format!("[IPSCAN] проб(ы) брошены по внешнему дедлайну чанка: {abandoned}"),
            );
        }
        for (ip, o) in got {
            res.probed += 1;
            match &o {
                HttpOutcome::Http { status, body_head, cf_mitigated } => {
                    res.alive_count += 1;
                    let is_refusal = *status == 403 || *status == 451;
                    match classify_refusal(*status, *cf_mitigated, body_head) {
                        RefusalKind::GuestVip => res.guest_refusal_count += 1,
                        RefusalKind::WafChallenge => res.waf_refusal_count += 1,
                        RefusalKind::Plain => {
                            if is_refusal {
                                res.other_status_count += 1;
                            } else {
                                res.working.push((ip, *status));
                                app_log(app, format!("[IPSCAN] РАБОЧИЙ IP: {ip} (HTTP {status})"));
                            }
                        }
                    }
                }
                _ => { /* транспорт умер — учитываем только в probed */ }
            }
        }
        app_log(
            app,
            format!(
                "[IPSCAN] проверено {}/{} | живых {} | чужих VIP {} | WAF {} | рабочих {}",
                res.probed, pool.len(), res.alive_count, res.guest_refusal_count,
                res.waf_refusal_count, res.working.len()
            ),
        );
    }
    app_log(app, format!("[IPSCAN] скан завершён за {} сек", t0.elapsed().as_secs()));
    res
}

// --- Отчётная секция (SSOT текстов) ----------------------------------------

/// Строки секции отчёта «анализа». Тексты здесь, в модуле скана (SSOT).
pub fn build_report_lines(host: &str, r: &BlockScanReport) -> Vec<String> {
    let mut lines = vec![format!("🌐 РАЗБОР БЛОКА СЕРВЕРА/IP «{host}»")];

    match r {
        BlockScanReport::Accessible { http } => {
            lines.push(format!(
                "✅ Родной адрес отвечает HTTPS {http} — блок на уровне сервера не обнаружен."
            ));
        }
        BlockScanReport::WafRefusal { status, evidence } => {
            lines.push(format!(
                "❌ Сервер/Cloudflare WAF отказал (HTTP {status}) С МАРКЕРАМИ WAF/гео/капчи:"
            ));
            for e in evidence {
                lines.push(format!("    ↳ {e}"));
            }
            lines.push(
                "    Транспорт до сервера пройден — отказ идёт от самого сайта.".to_string(),
            );
            lines.push(
                "    Смена DNS, hosts и подбор IP НЕ помогут: любой IP того же сервиса".to_string(),
            );
            lines.push(
                "    применит то же правило страны. Нужен VPN/прокси (смена исходного IP).".to_string(),
            );
        }
        BlockScanReport::PlainRefusal { status, evidence } => {
            lines.push(format!(
                "⚠️ Сервер вернул отказ HTTP {status} без WAF-маркеров (WAF/бот-защита/регион — точно не распознать):"
            ));
            for e in evidence {
                lines.push(format!("    ↳ {e}"));
            }
            lines.push(
                "    Соединение до сервера прошло — дело в самом сервисе, а не в DNS/обходе.".to_string(),
            );
            lines.push(
                "    Подбор IP и hosts не изменят исход. Нужен VPN/прокси (смена исходного IP).".to_string(),
            );
        }
        BlockScanReport::ServerFault { status } => {
            lines.push(format!(
                "⚠️ Сервер отвечает HTTP {status} (ошибка приложения). Это НЕ блокировка; сайт частично жив."
            ));
        }
        BlockScanReport::RangesScanned(outcome) => {
            match &outcome.source {
                ScanSource::Cloudflare { ranges_count } => {
                    lines.push(
                        "🔎 Транспорт к родным IP не работал — выполнен скан CIDR-диапазонов Cloudflare:"
                            .to_string(),
                    );
                    lines.push(format!("    источник CIDR: {ranges_count} диапазонов"));
                }
                ScanSource::Neighborhood { ranges, cf_note } => {
                    lines.push(format!(
                        "🔎 Транспорт к родным IP не работал — выполнен скан СОБСТВЕННОЙ сети сайта (соседние /24): {}",
                        ranges.join(", ")
                    ));
                    if let Some(note) = cf_note {
                        lines.push(format!(
                            "    ℹ️ список Cloudflare не получен ({note}) — скан идёт по диапазону самого сайта"
                        ));
                    }
                }
            }
            lines.push(format!(
                "    пробовано: {} из {} | живых: {} | «чужой VIP» (1034/1003/1000): {} | WAF-маркеры: {} | прочие отказы: {}",
                outcome.probed, outcome.pool_size, outcome.alive_count,
                outcome.guest_refusal_count, outcome.waf_refusal_count,
                outcome.other_status_count
            ));
            if outcome.working.is_empty() {
                if outcome.alive_count == 0 {
                    lines.push(
                        "    ❌ Ни один проверенный IP не ответил живым HTTP-соединением.".to_string(),
                    );
                    lines.push(
                        "    Похоже, цензор закрывает весь проанализированный пул по IP.".to_string(),
                    );
            } else if outcome.waf_refusal_count > 0 {
                lines.push(
                    "    ❌ Региональный блок ПОДТВЕРЖДЁН сканом: живые IP отвечают с WAF-маркерами."
                        .to_string(),
                );
                lines.push(
                    "    Обход тут бесполезен. Нужен VPN/прокси (смена исходного IP).".to_string(),
                );
            } else if outcome.guest_refusal_count > 0 && outcome.other_status_count == 0 {
                // «Строгий пул» — сильный вывод: ставим его ТОЛЬКО когда каждый
                // живой HTTP-ответ был именно «чужим VIP» (403 с 1034/1003/1000),
                // без примеси прочих отказов. Иначе выборка хрупкая.
                lines.push(
                    "    ⚠️ Все живые IP ответили «чужой VIP»: похоже, домен привязан к строгому пулу Cloudflare."
                        .to_string(),
                );
                lines.push(
                    "    Подменить IP через hosts на соседний CF-адрес может не получиться."
                        .to_string(),
                );
            } else {
                // Честная формулировка вместо сильного вывода (кейс
                // turboimagehost: 4 VIP в выборке, а соседний диапазон рабочий).
                if outcome.guest_refusal_count > 0 {
                    lines.push(
                        "    ❌ Скан не показал рабочего IP; часть живых IP ответила прочими отказами, поэтому вывод о строгом пуле на этих данных не основан."
                            .to_string(),
                    );
                } else {
                    lines.push(
                        "    ❌ Рабочих IP не найдено (живые IP отвечают прочими отказами)."
                            .to_string(),
                    );
                }
                lines.push(
                    "    Анализ выбирает лишь несколько адресов из каждого диапазона — можно повторить позже."
                        .to_string(),
                );
            }
            } else {
                let (ip, status) = outcome.working[0];
                lines.push(format!(
                    "    ✅ РАБОЧИЙ IP НАЙДЕН: {ip} (HTTP {status}). Можно попробовать записать в hosts:"
                ));
                lines.push(format!("        {ip}  {host}"));
                lines.push(
                    "    ℹ️ Адрес может смениться со временем — при пропадании запустите анализ заново.".to_string(),
                );
                if outcome.working.len() > 1 {
                    let extra: Vec<String> = outcome.working[1..]
                        .iter()
                        .take(3)
                        .map(|(i, _)| i.to_string())
                        .collect();
                    lines.push(format!(
                        "    (и ещё {} шт: {})",
                        outcome.working.len() - 1,
                        extra.join(", ")
                    ));
                }
            }
        }
        BlockScanReport::NoPath { why } => {
            lines.push(format!("⚠️ Разбор блока не состоялся: {why}"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_known_cf_prefixes() {
        let c = parse_cidr("173.245.48.0/20").unwrap();
        assert_eq!(c.bits, 20);
        assert_eq!(u32::from(Ipv4Addr::from(c.base)), 0xAD_F5_30_00);
        let c = parse_cidr("172.64.229.0/24").unwrap();
        assert_eq!(c.bits, 24);
        assert!(parse_cidr("104.16.0.0/40").is_err());
        assert!(parse_cidr("172.64.0.0").is_err());
        assert!(parse_cidr("1.2.3.p/24").is_err());
    }

    /// Кейс sostav.ru: сайт 185.71.67.130 не на Cloudflare — скан CF-пула
    /// к нему неприменим (раньше давал ложь «цензор закрывает весь пул»).
    #[test]
    fn cf_membership_check() {
        let cf = ["104.16.0.0/12", "172.64.0.0/16"]
            .iter()
            .map(|s| parse_cidr(s).unwrap())
            .collect::<Vec<_>>();
        // Границы диапазона 104.16/12: 104.16.0.0 — 104.31.255.255.
        assert!(ip_in_cidrs(&"104.18.2.115".parse().unwrap(), &cf));
        assert!(ip_in_cidrs(&"104.16.0.1".parse().unwrap(), &cf));
        assert!(ip_in_cidrs(&"104.31.255.254".parse().unwrap(), &cf));
        assert!(!ip_in_cidrs(&"104.32.0.1".parse().unwrap(), &cf));
        // Кейс sostav.ru.
        assert!(!ip_in_cidrs(&"185.71.67.130".parse().unwrap(), &cf));
        assert!(!ip_in_cidrs(&"8.8.8.8".parse().unwrap(), &cf));
        // IPv6 в IPv4-скан не входит.
        assert!(!ip_in_cidrs(&"2606:4700::1111".parse().unwrap(), &cf));
    }

    /// Соседние /24 сайта: только публичные IPv4, дубли схлопнуты, порядок
    /// сохранён; кап NEIGHBORHOOD_MAX_RANGES. Кейс 05.11.26: фронтенды
    /// web.telegram.org живут в 149.154.167.0/24.
    #[test]
    fn neighborhood_ranges_filters_and_caps() {
        let native: Vec<IpAddr> = [
            "149.154.167.99",
            "149.154.167.220", // та же /24 — дубликат диапазона
            "149.154.166.51",
            "192.168.1.10", // приватная — мимо
            "127.0.0.1",    // loopback — мимо
            "169.254.1.1",  // link-local — мимо
            "2606:4700::1111",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let strs: Vec<String> = neighborhood_ranges(&native)
            .iter()
            .map(cidr_to_string)
            .collect();
        assert_eq!(strs, vec!["149.154.167.0/24", "149.154.166.0/24"]);

        // Кап: пять публичных /24 — вернутся первые три.
        let many: Vec<IpAddr> = ["1.0.1.1", "1.0.2.1", "1.0.3.1", "1.0.4.1", "1.0.5.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(neighborhood_ranges(&many).len(), NEIGHBORHOOD_MAX_RANGES);
    }

    /// Отчёт скана собственной сети: заголовок с диапазонами сайта, честный
    /// итог мёртвого пула (кейс 05.11.26: весь /24 Telegram не отвечает —
    /// нужен VPN), никаких «CF-диапазонов».
    #[test]
    fn report_lines_neighborhood_dead_pool() {
        let host = "web.telegram.org";
        let scanned = BlockScanReport::RangesScanned(RangeScanOutcome {
            source: ScanSource::Neighborhood {
                ranges: vec!["149.154.167.0/24".to_string()],
                cf_note: None,
            },
            pool_size: 96,
            probed: 96,
            alive_count: 0,
            guest_refusal_count: 0,
            waf_refusal_count: 0,
            other_status_count: 0,
            working: Vec::new(),
        });
        let all = build_report_lines(host, &scanned).join("\n");
        assert!(all.contains("СОБСТВЕННОЙ сети сайта"), "{all}");
        assert!(all.contains("149.154.167.0/24"), "{all}");
        assert!(!all.contains("Cloudflare:"), "{all}");
        assert!(!all.contains("РАБОЧИЙ IP НАЙДЕН"), "{all}");
    }

    #[test]
    fn classify_refusal_kinds() {
        assert_eq!(
            classify_refusal(403, false, "<html>error code: 1034</html>"),
            RefusalKind::GuestVip
        );
        assert_eq!(
            classify_refusal(403, true, "какой-то текст"),
            RefusalKind::WafChallenge
        );
        assert_eq!(
            classify_refusal(403, false, "Attention Required! | Cloudflare"),
            RefusalKind::WafChallenge
        );
        assert_eq!(
            classify_refusal(451, false, "ничего узнаваемого"),
            RefusalKind::Plain
        );
        assert_eq!(
            classify_refusal(200, true, "не имеет значения"),
            RefusalKind::Plain, // классификация определена только для 403/451
        );
    }

    #[test]
    fn sample_pool_has_expected_size_without_duplicates() {
        let cidrs = ["104.16.0.0/12", "172.64.0.0/16", "173.245.48.0/20"];
        let parsed: Vec<Cidr> = cidrs.iter().map(|s| parse_cidr(s).unwrap()).collect();
        let mut seed = 42u64;
        let pool = sample_pool(&parsed, PER_CIDR, &mut seed);
        let set: HashSet<IpAddr> = pool.iter().copied().collect();
        assert_eq!(pool.len(), 3 * PER_CIDR);
        assert_eq!(set.len(), pool.len());
        for ip in &pool {
            let num = match ip {
                IpAddr::V4(v4) => u32::from(*v4),
                IpAddr::V6(_) => panic!("IPv6 не должно попадать в IPv4-скан"),
            };
            // 104.16.0.0/12 = 104.16–104.31; 172.64.0.0/16; 173.245.48.0/20.
            // 104=0x68, 172=0xAC, 173=0xAD.
            let inside =
                (0x6810_0000..0x6820_0000).contains(&num)      // 104.16–104.32
                    || (0xAC40_0000..0xAC41_0000).contains(&num) // 172.64
                    || (0xADF5_3000..=0xADF5_3FFF).contains(&num); // 173.245.48/20
            assert!(inside, "IP {ip} вне заявленных диапазонов");
        }
    }

    #[test]
    fn report_lines_mention_verdicts() {
        let host = "example.org";
        let waf = BlockScanReport::WafRefusal {
            status: 403,
            evidence: vec!["HTTP 403 — маркеры WAF/гео/капчи".to_string()],
        };
        let all = build_report_lines(host, &waf).join("\n");
        assert!(all.contains("WAF"));
        assert!(all.contains("VPN"));

        let scanned = BlockScanReport::RangesScanned(RangeScanOutcome {
            source: ScanSource::Cloudflare { ranges_count: 25 },
            pool_size: 100,
            probed: 100,
            alive_count: 40,
            guest_refusal_count: 30,
            waf_refusal_count: 10,
            other_status_count: 0,
            working: vec![(IpAddr::from([104, 18, 6, 160]), 200)],
        });
        let all = build_report_lines(host, &scanned).join("\n");
        assert!(all.contains("РАБОЧИЙ IP НАЙДЕН"));
        assert!(all.contains("104.18.6.160"));
        assert!(all.contains(host));
    }

    #[test]
    fn report_lines_guest_vip_case() {
        let host = "example.org";
        let scanned = BlockScanReport::RangesScanned(RangeScanOutcome {
            source: ScanSource::Cloudflare { ranges_count: 25 },
            pool_size: 100,
            probed: 100,
            alive_count: 40,
            guest_refusal_count: 40,
            waf_refusal_count: 0,
            other_status_count: 0,
            working: Vec::new(),
        });
        let all = build_report_lines(host, &scanned).join("\n");
        assert!(all.contains("чужой VIP"));
        assert!(all.contains("строго пул") || all.contains("строгому пулу"));
        assert!(!all.contains("РАБОЧИЙ IP НАЙДЕН"));
    }

    /// «Строгий пул» — запрещён, если HTTP-данных мало или они смешаны:
    /// только-Other случай и смесь VIP с прочими отказами не дают права
    /// на этот вывод (кейс turboimagehost).
    #[test]
    fn strict_pool_claim_needs_guest_only_http() {
        let host = "example.org";
        // Случай «только транспортные смерти»: HTTP-ответов не было вовсе.
        let no_http = BlockScanReport::RangesScanned(RangeScanOutcome {
            source: ScanSource::Cloudflare { ranges_count: 25 },
            pool_size: 100,
            probed: 40,
            alive_count: 0,
            guest_refusal_count: 0,
            waf_refusal_count: 0,
            other_status_count: 0,
            working: Vec::new(),
        });
        let all = build_report_lines(host, &no_http).join("\n");
        assert!(!all.contains("привязан к строгому пулу"), "{all}");
        assert!(!all.contains("Подменить IP через hosts"), "{all}");

        // Смесь: и «чужой VIP», и прочие отказы — сильный вывод запрещён.
        let mixed = BlockScanReport::RangesScanned(RangeScanOutcome {
            source: ScanSource::Cloudflare { ranges_count: 25 },
            pool_size: 100,
            probed: 40,
            alive_count: 8,
            guest_refusal_count: 3,
            waf_refusal_count: 0,
            other_status_count: 5,
            working: Vec::new(),
        });
        let all = build_report_lines(host, &mixed).join("\n");
        assert!(!all.contains("привязан к строгому пулу"), "{all}");
        assert!(!all.contains("Подменить IP через hosts"), "{all}");
        assert!(all.contains("не основан"), "{all}");
    }

    /// Причина Other-ошибки обязана попасть в описание и быть короткой
    /// (проверка форматирования describe_outcome).
    #[test]
    fn describe_outcome_other_keeps_honest_cause_and_truncates() {
        let o = HttpOutcome::Other("io error: соединение сброшено удалённым хостом".to_string());
        assert!(describe_outcome(&o).contains("соединение сброшено"), "{}", describe_outcome(&o));

        let long = "x".repeat(500);
        let o = HttpOutcome::Other(long);
        assert!(describe_outcome(&o).chars().count() <= 170, "{}", describe_outcome(&o));
    }

    #[test]
    fn describe_outcome_has_markers() {
        let o = HttpOutcome::Http {
            status: 403,
            body_head: "error code: 1034".to_string(),
            cf_mitigated: false,
        };
        assert!(describe_outcome(&o).contains("чужой VIP"));
        let o = HttpOutcome::Rst;
        assert!(describe_outcome(&o).contains("RST"));
    }
}
