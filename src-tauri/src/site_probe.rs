use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::blocking::Client;

use crate::diagnostics_probe::{classify_reqwest_err, dns_multi, tcp_connect, DnsInfo, HttpResult};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    Open,
    IpUnreachable,
    IpReset,
    TlsBroken,
    DnsBlocked,
    BlockPage,
    NoPath,
    Unknown,
}

#[derive(Debug)]
pub struct DomainProbe {
    pub host: String,
    pub dns: DnsInfo,
    pub dns_consistent: bool,
    pub primary_ips: Vec<String>,
    pub alt_ips: Vec<String>,
    pub working_ip: Option<String>,
    pub working_from_alt: bool,
    pub http_note: String,
    pub verdict: Verdict,
    pub recommendation: Vec<String>,
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
        .danger_accept_invalid_certs(true)
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
) -> Verdict {
    // Сначала — фактическая работоспособность сайта. Даже если DNS-списки
    // разных резолверов отличаются (нормальный anycast у крупных CDN), сайт
    // может открываться — это не цензура.
    match http {
        Some(HttpResult::Ok(_)) => {
            return if primary_ok {
                Verdict::Open
            } else {
                Verdict::IpUnreachable
            };
        }
        Some(HttpResult::BlockPage) => return Verdict::BlockPage,
        Some(HttpResult::Tls) => return Verdict::TlsBroken,
        Some(HttpResult::Rst) => return Verdict::IpReset,
        _ => {}
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
    let www_dns = dns_multi(&www_host);

    let primary_ips = dedup_ips(dns.system.iter().copied());
    let alt_ips = dedup_ips(
        www_dns
            .system
            .iter()
            .chain(dns.cloudflare.iter())
            .chain(dns.google.iter())
            .copied(),
    );

    let mut primary_tcp_ok = false;
    let mut alt_tcp_ok = false;
    let mut any_reset = false;
    let mut working: Option<(String, bool)> = None;

    // Первичные IP (системный DNS). Достаточно первого успешного.
    for ip in primary_ips.iter() {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            let r = tcp_connect(addr, 443);
            if r == "RST/REFUSED" {
                any_reset = true;
            }
            if r == "Success" {
                primary_tcp_ok = true;
                working = Some((ip.clone(), true));
                break;
            }
        }
    }

    // Если primary не добрался — пробуем альтернативные (www + DoH).
    if working.is_none() {
        for ip in alt_ips.iter() {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                let r = tcp_connect(addr, 443);
                if r == "RST/REFUSED" {
                    any_reset = true;
                }
                if r == "Success" {
                    alt_tcp_ok = true;
                    working = Some((ip.clone(), false));
                    break;
                }
            }
        }
    }
    let mut http: Option<HttpResult> = None;
    let mut http_note = "ни один IP не ответил на TCP:443".to_string();
    let mut working_from_alt = false;

    if let Some((ip, is_primary)) = &working {
        let r = http_via_ip(host, ip.parse().unwrap());
        working_from_alt = !*is_primary;
        http = Some(r.clone());
        http_note = format!(
            "HTTPS через {} ({}): {}",
            ip,
            if working_from_alt { "alt-IP" } else { "primary-IP" },
            match &r {
                HttpResult::Ok(code) => format!("HTTP {}", code),
                HttpResult::Tls => "TLS сломан".to_string(),
                HttpResult::Rst => "RST".to_string(),
                HttpResult::Timeout => "таймаут".to_string(),
                HttpResult::Dns => "DNS-ошибка".to_string(),
                HttpResult::BlockPage => "страница блокировки".to_string(),
                HttpResult::Other(m) => m.clone(),
            }
        );
    }

    let verdict = classify(dns_consistent, primary_tcp_ok, alt_tcp_ok, any_reset, http.as_ref());

    let mut rec: Vec<String> = Vec::new();
    match verdict {
        Verdict::Open => rec.push("Сайт открывается штатно: системный DNS и его IP доступны.".to_string()),
        Verdict::IpUnreachable => {
            rec.push(
                "Системный DNS-адрес сайта недоступен из вашей сети (маршрут провайдера / «чёрная дыра»). Обход и списки здесь не помогут.".to_string(),
            );
            if let Some((ip, _)) = &working {
                rec.push(format!(
                    "Но сайт отвечает на рабочем IP {}. Добавьте в hosts (C:\\Windows\\System32\\drivers\\etc\\hosts):",
                    ip
                ));
                rec.push(format!("    {} {}", ip, host));
                rec.push(format!("    {} {}", ip, www_host));
                rec.push("Затем выполните: ipconfig /flushdns".to_string());
                rec.push(
                    "Важно: браузеры с включённым Secure DNS (DoH) игнорируют файл hosts — отключите DoH или выберите один из системных DNS.".to_string(),
                );
            } else {
                rec.push(
                    "Рабочий альтернативный IP не найден. Решения: VPN/прокси, повторить позже, сменить DNS на публичный (1.1.1.1/8.8.8.8).".to_string(),
                );
            }
        }
        Verdict::IpReset => rec.push(
            "Соединение сбрасывается (RST) — похоже на DPI-блок на уровне IP. Используйте обход (winws) и добавьте домен в general-лист (или поддомены).".to_string(),
        ),
        Verdict::TlsBroken => rec.push(
            "TCP-порт открыт, но TLS-рукопожатие рвётся. Если обход активен — его десинк может ломать TLS: добавьте домен в исключения. Если обход выключен — проблема на стороне сервера/CDN.".to_string(),
        ),
        Verdict::DnsBlocked => rec.push(
            "DNS-ответы системного и публичных резолверов расходятся (или не резолвится) — возможна DNS-цензура. Смените DNS на 1.1.1.1/8.8.8.8 или включите DoH.".to_string(),
        ),
        Verdict::BlockPage => rec.push(
            "Сервер возвращает страницу блокировки (403/451/заглушку). Добавьте домен в обход.".to_string(),
        ),
        Verdict::NoPath => rec.push(
            "К сайту не удалось установить связь ни по одному адресу. Проверьте общее соединение с интернетом.".to_string(),
        ),
        Verdict::Unknown => rec.push("Не удалось однозначно определить причину.".to_string()),
    }

    DomainProbe {
        host: host.to_string(),
        dns,
        dns_consistent,
        primary_ips,
        alt_ips,
        working_ip: working.map(|(i, _)| i),
        working_from_alt,
        http_note,
        verdict,
        recommendation: rec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> HttpResult {
        HttpResult::Ok(200)
    }

    #[test]
    fn open_when_primary_reachable() {
        assert_eq!(
            classify(true, true, true, false, Some(&ok())),
            Verdict::Open
        );
    }

    #[test]
    fn ip_unreachable_but_alt_works() {
        assert_eq!(
            classify(true, false, true, false, Some(&ok())),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn ip_unreachable_all_timeout() {
        assert_eq!(
            classify(true, false, false, false, None),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn dns_censorship_when_inconsistent() {
        // DNS-списки расходятся и HTTP не открылся — цензура.
        assert_eq!(
            classify(false, true, true, false, None),
            Verdict::DnsBlocked
        );
    }

    #[test]
    fn dns_mismatch_but_site_ok() {
        // anycast: списки разных резолверов отличаются, но сайт отвечает — НЕ цензура.
        assert_eq!(
            classify(false, true, true, false, Some(&ok())),
            Verdict::Open
        );
    }

    #[test]
    fn rst_is_dpi_block() {
        assert_eq!(
            classify(true, false, false, true, None),
            Verdict::IpReset
        );
    }

    #[test]
    fn tls_broken_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::Tls)),
            Verdict::TlsBroken
        );
    }

    #[test]
    fn block_page_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BlockPage)),
            Verdict::BlockPage
        );
    }

    #[test]
    #[ignore = "требует сеть"]
    fn live_probe_google() {
        let p = probe_domain("google.com");
        assert_eq!(p.verdict, Verdict::Open, "probe: {:?}", p);
    }

    #[test]
    #[ignore = "требует сеть"]
    fn live_probe_artificialanalysis() {
        let p = probe_domain("artificialanalysis.ai");
        println!("verdict: {:?}", p.verdict);
        println!("dns_consistent: {}", p.dns_consistent);
        println!("primary: {:?}", p.primary_ips);
        println!("alt: {:?}", p.alt_ips);
        println!("working_ip: {:?}", p.working_ip);
        println!("http_note: {}", p.http_note);
        println!("rec: {:#?}", p.recommendation);
    }
}