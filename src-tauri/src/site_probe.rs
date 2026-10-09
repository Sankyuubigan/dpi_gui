use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::blocking::Client;

use crate::diagnostics_probe::{
    classify_reqwest_err, dns_multi, resolve_via_doh, tcp_connect, DnsInfo, HttpResult,
    DOH_RESOLVERS,
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    Open,
    /// Домен открывается только по имени с префиксом `www.`, без него не отвечает.
    WwwOnly,
    IpUnreachable,
    IpReset,
    TlsBroken,
    /// Сайт отвечает по TCP/TLS, но сертификат невалиден для имени домена
    /// (браузер: NET::ERR_CERT_COMMON_NAME_INVALID и т.п.).
    BadCert,
    DnsBlocked,
    BlockPage,
    NoPath,
    Unknown,
}

impl Verdict {
    /// Реально недоступен пользователю — нужна диагностика и подсказка.
    pub fn site_broken(self) -> bool {
        !matches!(self, Verdict::Open)
    }

    /// Короткое техническое имя вердикта для заголовка отчёта.
    pub fn verdict_name(self) -> &'static str {
        match self {
            Verdict::Open => "САЙТ ОТКРЫВАЕТСЯ",
            Verdict::WwwOnly => "РАБОТАЕТ ТОЛЬКО С WWW",
            Verdict::IpUnreachable => "IP НЕ ОТВЕЧАЕТ",
            Verdict::IpReset => "СБРОС СОЕДИНЕНИЯ (DPI)",
            Verdict::TlsBroken => "TLS СЛОМАН",
            Verdict::BadCert => "НЕВАЛИДНЫЙ СЕРТИФИКАТ",
            Verdict::DnsBlocked => "DNS-ПОДМЕНА",
            Verdict::BlockPage => "СТРАНИЦА БЛОКИРОВКИ",
            Verdict::NoPath => "НЕТ ПУТИ",
            Verdict::Unknown => "ПРИЧИНА НЕ ЯСНА",
        }
    }
}

#[derive(Debug)]
pub struct DomainProbe {
    pub host: String,
    pub dns: DnsInfo,
    pub dns_consistent: bool,
    pub primary_ips: Vec<String>,
    pub working_ip: Option<String>,
    pub http_note: String,
    pub verdict: Verdict,
    /// Рабочее имя с префиксом `www.`, если apex не отвечает, а `www` отвечает.
    pub www_host: Option<String>,
    pub www_ips: Vec<String>,
    /// Готовый URL, который точно открывается (только при `Verdict::WwwOnly`).
    pub www_url: Option<String>,
    /// Разбор причины и подсказки; `None`, если сайт доступен.
    pub diagnosis: Option<Diagnosis>,
}

fn dedup_ips(addrs: impl Iterator<Item = IpAddr>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for a in addrs {
        let s = a.to_string();
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

fn http_via_ip(host: &str, ip: IpAddr) -> HttpResult {
    let client = match Client::builder()
        .resolve(host, SocketAddr::new(ip, 443))
        .timeout(Duration::from_secs(6))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResult::Other(format!("не удалось создать клиент: {}", e)),
    };
    match client.get(format!("https://{}/", host)).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 403 || status == 451 {
                return HttpResult::BlockPage;
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if low.contains("роскомнадзор")
                    || low.contains("заблокир")
                    || low.contains("this site is blocked")
                    || low.contains("access denied: by order")
                    || low.contains("страница не может быть отображена")
                {
                    HttpResult::BlockPage
                } else {
                    HttpResult::Ok(status)
                }
            } else {
                HttpResult::Ok(status)
            }
        }
        Err(e) => classify_reqwest_err(&e),
    }
}

/// Чистая логика классификации первопричины — отделена от I/O, чтобы её можно
/// было покрыть юнит-тестами без сети.
///
/// * `dns_consistent` — системный DNS совпадает с публичными резолверами.
/// * `primary_ok` — хотя бы один IP системного DNS ответил на TCP:443.
/// * `alt_ok` — хотя бы один «альтернативный» IP (www + DoH) ответил на TCP:443.
/// * `any_reset` — среди всех попыток было RST.
/// * `http` — результат HTTPS-запроса через первый рабочий IP.
pub fn classify(
    dns_consistent: bool,
    primary_ok: bool,
    alt_ok: bool,
    any_reset: bool,
    http: Option<&HttpResult>,
    www_ok: bool,
) -> Verdict {
    // Сначала — фактическая работоспособность сайта. Даже если DNS-списки
    // разных резолверов отличаются (нормальный anycast у крупных CDN), сайт
/// * `www_ok` — домен открывается только под именем с префиксом `www.`.
    match http {
        Some(HttpResult::Ok(_)) => {
            return if primary_ok {
                Verdict::Open
            } else {
                Verdict::IpUnreachable
            };
        }
        Some(HttpResult::BlockPage) => return Verdict::BlockPage,
        Some(HttpResult::BadCert) => return Verdict::BadCert,
        Some(HttpResult::Tls) => return Verdict::TlsBroken,
        Some(HttpResult::Rst) => return Verdict::IpReset,
        _ => {}
    }

/// Сначала — фактическая работоспособность сайта. Даже если DNS-списки
/// разных резолверов отличаются (нормальный anycast у крупных CDN), сайт
/// может открываться — это не цензура.
    if www_ok {
        return Verdict::WwwOnly;
    }

    if !dns_consistent {
        return Verdict::DnsBlocked;
    }
    match http {
        Some(HttpResult::Dns) => Verdict::DnsBlocked,
        Some(HttpResult::Timeout) => {
            if alt_ok {
                Verdict::IpUnreachable
            } else if any_reset {
                Verdict::IpReset
            } else {
                Verdict::IpUnreachable
            }
        }
        Some(HttpResult::Other(_)) => Verdict::Unknown,
        None => {
            if alt_ok {
                Verdict::IpUnreachable
            } else if any_reset {
                Verdict::IpReset
            } else if !primary_ok && !alt_ok {
                Verdict::IpUnreachable
            } else {
                Verdict::NoPath
            }
        }
        _ => Verdict::Unknown,
    }
}

pub fn probe_domain(host: &str) -> DomainProbe {
    let dns = dns_multi(host);

    let mut dns_consistent = true;
    if dns.system.is_empty() {
    // Системный DNS не резолвит домен, но публичные резолверы отвечают —
    // признак сбоя/цензуры локального DNS. Расхождение самих IP-адресов
    // (anycast крупных CDN) цензурой НЕ считается.
        if !dns.cloudflare.is_empty() || !dns.google.is_empty() {
            dns_consistent = false;
        }
    }

    let is_www = host.starts_with("www.");
    let www_host = if is_www {
        host.to_string()
    } else {
        format!("www.{}", host)
    };

    let primary_ips = dedup_ips(dns.system.iter().copied());
    // Первичные адреса берём из системного DNS. Этого достаточно,
    // чтобы отличить «заблокирован сам» от «обход его ломает».
    let doh_ips = dedup_ips(dns.cloudflare.iter().chain(dns.google.iter()).copied());

    let mut any_reset = false;
    let (primary_tcp_ok, mut working_ip, http, mut http_note) =
        probe_host_at(host, &primary_ips, &mut any_reset);

    // Если по системному DNS не дотянулись, пробуем адреса публичных DoH-резолверов.
    let mut alt_tcp_ok = false;
    let mut same_host_alt_ip_works = false;
    if working_ip.is_none() && !doh_ips.is_empty() {
        let (tcp_ok, ip, _http2, note) = probe_host_at(host, &doh_ips, &mut any_reset);
        alt_tcp_ok = tcp_ok;
        if ip.is_some() {
            same_host_alt_ip_works = true;
            working_ip = ip;
            http_note = note;
        }
    }

    // Пробуем вариант с `www.`: у сайта может быть рабочее имя только с этим
    // префиксом, а apex без него не отвечает.
    let (www_ips, www_url, www_ok) = if is_www {
        let ok = matches!(http, Some(HttpResult::Ok(_)));
        (primary_ips.clone(), None, ok)
    } else {
        let www_dns = dns_multi(&www_host);
        let ips = dedup_ips(www_dns.system.iter().copied());
        let mut ignored = false;
        let (_, _, w_http, _w_note) = probe_host_at(&www_host, &ips, &mut ignored);
        let ok = matches!(w_http, Some(HttpResult::Ok(_)));
        let url = ok.then(|| format!("https://{}/", www_host));
        (ips, url, ok)
    };
    if is_www && www_ok {
        http_note = format!("HTTPS через {} не прошёл: {}", www_host, http_result_note(&http.as_ref().unwrap()));
    }

    let verdict = classify(
        dns_consistent,
        primary_tcp_ok,
        alt_tcp_ok,
        any_reset,
        http.as_ref(),
        www_ok,
    );

    let apex_ip = primary_ips.first().cloned();
    let diagnosis = explain(
        verdict,
        &CauseContext {
            host,
            www_url: www_url.as_deref(),
            apex_ip: apex_ip.as_deref(),
            dns_consistent,
            same_host_alt_ip_works,
        },
    );

    DomainProbe {
        host: host.to_string(),
        dns,
        dns_consistent,
        primary_ips,
        working_ip,
        http_note,
        verdict,
        www_host: if is_www { None } else { Some(www_host) },
        www_ips,
        www_url,
        diagnosis: Some(diagnosis),
    }
}

/// Результат проверки «подмены DNS» через один DoH-сервис.
/// Сервис пытается вернуть настоящий рабочий IP в обход отравленного DNS.
#[derive(Debug)]
pub struct DnsSubstitution {
    pub service: String,
    pub resolved: Vec<String>,
    /// Реально «рабочий» IP — HTTPS через него открылся (`http_ok == true`).
    /// Если `http_ok == false`, тут может лежать кандидат, прошедший только TCP:443.
    pub working_ip: Option<String>,
    pub http_note: String,
    /// HTTPS-проба через `working_ip` реально вернула OK. От этого зависит,
    /// можно ли советовать подмену в hosts (иначе RST — hosts бесполезен).
    pub http_ok: bool,
}

/// Экспорт HTTPS-пробы по конкретному IP (для hosts-фичи: проверяем, что
/// сайт реально открывается через выбранный адрес после записи в hosts).
pub fn probe_https_by_ip(host: &str, ip: IpAddr) -> HttpResult {
    http_via_ip(host, ip)
}

/// Проверка «подмены DNS»: резолв домена через DoH-сервисы (xbox-dns.ru,
/// geohide.ru) и поиск рабочего IP. Если системный/публичный UDP-DNS отравлен,
/// эти сервисы могут вернуть настоящий адрес, и сайт откроется через подмену.
///
/// * `probe_http` — делать ли полную HTTPS-пробу первого рабочего IP
///   (для главного домена да/для долгого перебора — нет).
pub fn check_dns_substitution(host: &str, probe_http: bool) -> Vec<DnsSubstitution> {
    let mut out = Vec::new();
    for service in DOH_RESOLVERS {
        let ips = resolve_via_doh(host, service);
        if ips.is_empty() {
            out.push(DnsSubstitution {
                service: service.to_string(),
                resolved: vec![],
                working_ip: None,
                http_note: "не вернул IP-адресов (DoH недоступен или не резолвит)".to_string(),
                http_ok: false,
            });
            continue;
        }
        let display: Vec<String> = ips.iter().take(4).map(|i| i.to_string()).collect();

        let mut working: Option<IpAddr> = None;
        for ip in ips.iter().take(6) {
            if tcp_connect(*ip, 443) == "Success" {
                working = Some(*ip);
                break;
            }
        }

        let mut http_ok = false;
        let mut http_note;
        if let Some(ip) = working {
            match http_via_ip(host, ip) {
                HttpResult::Ok(code) => {
                    http_ok = true;
                    http_note = format!("HTTPS {} через {}", code, ip);
                }
                HttpResult::BlockPage => {
                    http_note = format!("страница блокировки через {}", ip);
                }
                HttpResult::Tls => {
                    http_note = format!("TLS сломан через {}", ip);
                }
                HttpResult::BadCert => {
                    http_note = format!("SSL-сертификат невалиден через {}", ip);
                }
                HttpResult::Rst => {
                    http_note = format!("RST через {} — TCP:443 открыт, но HTTPS рвётся (DPI по SNI)", ip);
                }
                HttpResult::Timeout => {
                    http_note = format!("таймаут через {}", ip);
                }
                HttpResult::Dns => {
                    http_note = format!("DNS-ошибка через {}", ip);
                }
                HttpResult::Other(m) => {
                    http_note = m;
                }
            }
        } else {
            http_note = "ни один IP из подмены не ответил на TCP:443".to_string();
        }
        if !probe_http {
            // Лёгкий прогон (список dns_fail): HTTPS не гоняем, но и не называем
            // IP «рабочим» — только кандидатом.
            let res = working.is_some();
            http_ok = res;
            if let Some(ip) = working {
                http_note = format!("TCP:443 отвечает ({})", ip);
            }
            out.push(DnsSubstitution {
                service: service.to_string(),
                resolved: display,
                working_ip: working.map(|i| i.to_string()),
                http_note,
                http_ok,
            });
            continue;
        }

        out.push(DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: working.map(|i| i.to_string()),
            http_note,
            http_ok,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> HttpResult {
        HttpResult::Ok(200)
    }

    fn ctx<'a>(
        host: &'a str,
        www: Option<&'a str>,
        apex_ip: Option<&'a str>,
    ) -> CauseContext<'a> {
        CauseContext {
            host,
            www_url: www,
            apex_ip,
            dns_consistent: true,
            same_host_alt_ip_works: false,
        }
    }

    #[test]
    fn open_when_primary_reachable() {
        assert_eq!(
            classify(true, true, true, false, Some(&ok()), false),
            Verdict::Open
        );
    }

    #[test]
    fn ip_unreachable_but_alt_works() {
        assert_eq!(
            classify(true, false, true, false, Some(&ok()), false),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn ip_unreachable_all_timeout() {
        assert_eq!(
            classify(true, false, false, false, None, false),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn dns_censorship_when_inconsistent() {
        assert_eq!(
            classify(false, true, true, false, None, false),
            Verdict::DnsBlocked
        );
    }

    #[test]
    fn dns_mismatch_but_site_ok() {
        assert_eq!(
            classify(false, true, true, false, Some(&ok()), false),
            Verdict::Open
        );
    }

    #[test]
    fn rst_is_dpi_block() {
        assert_eq!(
            classify(true, false, false, true, None, false),
            Verdict::IpReset
        );
    }

    #[test]
    fn tls_broken_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::Tls), false),
            Verdict::TlsBroken
        );
    }

    #[test]
    fn block_page_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BlockPage), false),
            Verdict::BlockPage
        );
    }

    #[test]
    fn bad_cert_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BadCert), false),
            Verdict::BadCert
        );
    }

    // --- Regression: apex dead, site alive only under www. ---

    #[test]
    fn apex_dead_but_www_ok_is_www_only() {
        assert_eq!(
            classify(
                true,
                false,
                true,
                false,
                Some(&HttpResult::Timeout),
                true
            ),
            Verdict::WwwOnly
        );
    }

    #[test]
    fn www_ok_does_not_mask_block_page() {
        // A block page on apex is a block, not "works with www".
        assert_eq!(
            classify(
                true,
                true,
                true,
                false,
                Some(&HttpResult::BlockPage),
                true
            ),
            Verdict::BlockPage
        );
    }

    #[test]
    fn www_ok_does_not_mask_bad_cert() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BadCert), true),
            Verdict::BadCert
        );
    }

    #[test]
    fn www_only_diagnosis_points_to_www_url() {
        let d = explain(
            Verdict::WwwOnly,
            &ctx(
                "cactuscompute.com",
                Some("https://www.cactuscompute.com/"),
                Some("216.150.1.1"),
            ),
        );
        assert!(d.probable_cause.contains("216.150.1.1"), "{}", d.probable_cause);
        assert!(
            d.do_this
                .iter()
                .any(|a| a.contains("https://www.cactuscompute.com/")),
            "{:?}",
            d.do_this
        );
        // Useless actions must be called out, otherwise the user retries blind.
        assert!(!d.wont_help.is_empty(), "wont_help must not be empty");
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
    }

    #[test]
    fn www_only_reason_differs_when_dns_poisoned() {
        let clean = explain(
            Verdict::WwwOnly,
            &ctx("example.com", Some("https://www.example.com/"), Some("1.2.3.4")),
        );
        let mut poisoned = ctx(
            "example.com",
            Some("https://www.example.com/"),
            Some("127.0.0.1"),
        );
        poisoned.dns_consistent = false;
        let dirty = explain(Verdict::WwwOnly, &poisoned);
        // Poisoned DNS and a broken site record must be reported differently.
        assert_ne!(clean.probable_cause, dirty.probable_cause);
    }

    #[test]
    fn unreachable_ip_says_bypass_wont_help() {
        let d = explain(Verdict::IpUnreachable, &ctx("example.com", None, Some("1.2.3.4")));
        assert!(
            d.wont_help.iter().any(|a| a.contains("winws")),
            "{:?}",
            d.wont_help
        );
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts")),
            "hosts must not be advised for a dead IP: {:?}",
            d.do_this
        );
    }

    #[test]
    fn open_has_no_action_noise() {
        let d = explain(Verdict::Open, &ctx("example.com", None, None));
        assert!(d.do_this.is_empty(), "{:?}", d.do_this);
        assert!(d.wont_help.is_empty(), "{:?}", d.wont_help);
    }

    #[test]
    fn verdict_names_are_unique() {
        let all = [
            Verdict::Open,
            Verdict::WwwOnly,
            Verdict::IpUnreachable,
            Verdict::IpReset,
            Verdict::TlsBroken,
            Verdict::BadCert,
            Verdict::DnsBlocked,
            Verdict::BlockPage,
            Verdict::NoPath,
            Verdict::Unknown,
        ];
        let mut names: Vec<&str> = all.iter().map(|v| v.verdict_name()).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "duplicated verdict names: {:?}", names);
    }

    #[test]
    fn site_broken_flag() {
        assert!(!Verdict::Open.site_broken());
        assert!(Verdict::WwwOnly.site_broken());
        assert!(Verdict::IpReset.site_broken());
    }

    #[test]
    #[ignore = "requires network"]
    fn live_probe_google() {
        let p = probe_domain("google.com");
        assert_eq!(p.verdict, Verdict::Open, "probe: {:?}", p);
    }

    /// Real user case: apex DNS returns a dead IP, `www` serves the site.
    #[test]
    #[ignore = "requires network"]
    fn live_probe_cactuscompute() {
        let p = probe_domain("cactuscompute.com");
        println!("verdict: {:?}", p.verdict);
        println!("apex: {:?}", p.primary_ips);
        println!("www: {:?}", p.www_ips);
        println!("www_url: {:?}", p.www_url);
        println!("diagnosis: {:#?}", p.diagnosis);
        assert_eq!(p.verdict, Verdict::WwwOnly, "probe: {:?}", p);
    }
}

/// Контекст для разбора причины: всё, что известно о домене на момент проверки.
#[derive(Debug)]
pub struct CauseContext<'a> {
    pub host: &'a str,
    /// Рабочий адрес с префиксом www., если он найден.
    pub www_url: Option<&'a str>,
    /// Первый IP, который вернул системный DNS для apex-имени.
    pub apex_ip: Option<&'a str>,
    /// Системный DNS совпадает с публичными резолверами.
    pub dns_consistent: bool,
    /// Для того же домена нашёлся рабочий IP через DoH.
    pub same_host_alt_ip_works: bool,
}

/// Разбор причины: что, скорее всего, произошло и что с этим делать.
#[derive(Debug)]
pub struct Diagnosis {
    pub probable_cause: String,
    pub do_this: Vec<String>,
    pub wont_help: Vec<String>,
}

/// Короткое описание результата HTTPS-запроса — для строки в отчёте.
pub fn http_result_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::Tls => "TLS сломан".to_string(),
        HttpResult::BadCert => "SSL-сертификат невалиден".to_string(),
        HttpResult::Rst => "RST".to_string(),
        HttpResult::Timeout => "таймаут".to_string(),
        HttpResult::Dns => "DNS-ошибка".to_string(),
        HttpResult::BlockPage => "страница блокировки".to_string(),
        HttpResult::Other(m) => m.clone(),
    }
}

/// Сколько адресов одного хоста пробуем подряд.
const MAX_IPS: usize = 3;

/// Пробует TCP:443 по списку адресов и делает HTTPS-запрос по первому ответившему.
/// Возвращает (дошёл ли TCP, рабочий IP, результат HTTPS, описание).
fn probe_host_at(
    host: &str,
    ips: &[String],
    any_reset: &mut bool,
) -> (bool, Option<String>, Option<HttpResult>, String) {
    let mut tcp_only: Option<(String, HttpResult)> = None;

    for ip in ips.iter().take(MAX_IPS) {
        let Ok(addr) = ip.parse::<IpAddr>() else { continue };
        match tcp_connect(addr, 443).as_str() {
            "RST/REFUSED" => {
                *any_reset = true;
                continue;
            }
            "Success" => {}
            _ => continue,
        }
        let r = http_via_ip(host, ip.parse().unwrap());
        if let HttpResult::Ok(code) = r {
            return (
                true,
                Some(ip.clone()),
                Some(r),
                format!("HTTPS через {}: HTTP {}", ip, code),
            );
        }
        if tcp_only.is_none() {
            tcp_only = Some((ip.clone(), r));
        }
    }

    match tcp_only {
        Some((ip, r)) => {
            let note = format!("HTTPS через {}: {}", ip, http_result_note(&r));
            (true, Some(ip), Some(r), note)
        }
        None => (false, None, None, "ни один IP не ответил на TCP:443".to_string()),
    }
}

/// Разбор первопричины по вердикту. Только логика, без обращения к сети.
pub fn explain(verdict: Verdict, ctx: &CauseContext) -> Diagnosis {
    let mut do_this = Vec::new();
    let mut wont_help = Vec::new();

    let probable_cause = match verdict {
        Verdict::Open =>
            "Сайт открывается по тому же адресу, по которому он и должен работать.".to_string(),

        Verdict::WwwOnly => {
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.dns_consistent {
                format!(
                    "Домен «{}» без префикса www. не отвечает, хотя DNS отдаёт для него адрес {}. Сайт открывается только по имени с www.",
                    ctx.host, apex
                )
            } else {
                format!(
                    "Для «{}» системный DNS и публичные резолверы отдают разные адреса, и без префикса www. домен не открывается ({}).",
                    ctx.host, apex
                )
            }
        }

        Verdict::IpReset => {
            wont_help.push(
                "Правка hosts здесь не поможет: соединение обрывается ещё до обмена данными.".to_string(),
            );
            "Соединение сбрасывается (RST) прямо во время TLS-рукопожатия — так выглядит блокировка по IP или по SNI."
                .to_string()
        }

        Verdict::TlsBroken => {
            wont_help.push(
                "Ни смена DNS, ни запись в hosts: TCP проходит, обрыв происходит уже на уровне TLS.".to_string(),
            );
            "TCP-соединение устанавливается, но TLS-рукопожатие обрывается на шифровании. Сервер не принимает сертификат, который предъявляет браузер, либо сервер сам не готов работать с шифрованием."
                .to_string()
        }

        Verdict::BadCert => {
            wont_help.push("Обход тут не поможет: блокировки на уровне сети нет, TCP/TLS работают.".to_string());
            wont_help.push(
                "Ни смена DNS, ни hosts: сначала нужно устранить неверный сертификат на стороне сервера."
                    .to_string(),
            );
            "Имя домена не совпадает с тем, что записано в сертификате, выданном сервером. Обход по IP без передачи SNI не поможет."
                .to_string()
        }

        Verdict::DnsBlocked => {
            "Системный DNS отдаёт для домена не те адреса, что публичные резолверы — такое расхождение бывает при подмене DNS."
                .to_string()
        }

        Verdict::BlockPage => {
            "Сервер отдаёт страницу блокировки вместо сайта — обычно это ответ с кодом 403 или 451.".to_string()
        }

        Verdict::IpUnreachable => {
            wont_help.push(
                "Обход winws тут не поможет: до сервера доходит RST, ответ не возвращается.".to_string(),
            );
            wont_help.push(
                "Ни смена DNS, ни запись в hosts: DNS отдаёт верный адрес, но до него невозможно дойти."
                    .to_string(),
            );
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.same_host_alt_ip_works {
                format!(
                    "DNS не подменялся, но до адреса {} не доходит. Тот же домен открывается по другому адресу — похоже на фильтрацию маршрута.",
                    apex
                )
            } else {
                format!(
                    "DNS не подменялся, но до адреса {} не доходит. Похоже на фильтрацию маршрута оператором связи.",
                    apex
                )
            }
        }

        Verdict::NoPath => {
            wont_help.push(
                "Обход тут не поможет: маршрут до адреса потерян не из-за блокировки.".to_string(),
            );
            "Ни по одному из адресов связаться с сайтом не удалось. Проверьте общее подключение к интернету."
                .to_string()
        }

        Verdict::Unknown =>
            "Не удалось однозначно определить причину по результатам одной проверки.".to_string(),
    };

    if verdict == Verdict::WwwOnly {
        if let Some(url) = ctx.www_url {
            do_this.insert(0, format!("Откройте сайт по адресу {} — он точно работает.", url));
        }
        do_this.push(
            "Проверьте, какой из вариантов открывается у вас: с префиксом www. или без него.".to_string(),
        );
        wont_help.push(
            "Проверка через hosts не даёт верного результата — включите системный DoH и повторите замер."
                .to_string(),
        );
        wont_help.push(
            "Добавление домена в список обхода тут не поможет: apex-адрес недоступен независимо от обхода."
                .to_string(),
        );
    }

    if verdict == Verdict::Open {
        return Diagnosis {
            probable_cause,
            do_this,
            wont_help,
        };
    }

    if verdict == Verdict::BlockPage || verdict == Verdict::DnsBlocked {
        do_this.push(
            "Добавьте домен в список исключений для профиля обхода и перезапустите обход.".to_string(),
        );
        wont_help.push(
            "Смена DNS не поможет: страницу блокировки отдаёт сам провайдер, и адрес у неё тот же."
                .to_string(),
        );
    } else if do_this.is_empty() && verdict != Verdict::WwwOnly {
        do_this.push("Попробуйте включить VPN или сменить сеть.".to_string());
    }

    Diagnosis {
        probable_cause,
        do_this,
        wont_help,
    }
}