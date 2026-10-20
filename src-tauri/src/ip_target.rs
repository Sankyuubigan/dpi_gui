//! Контракт цели «Анализ доменов»: домен или IP(-порт).
//!
//! Единая точка распознавания ввода. До этого модуля фича считала
//! любой ввод доменом: IP-адрес прогонялся через DNS-пробы, отчёт печатал
//! имена `www.<ip>` и «родительские домены» из фрагментов адреса (`90.21`).
//! Ничто больше не разбирает ввод на домен/IP — только эти функции (SSOT).

use std::net::IpAddr;

/// Порт по умолчанию для IP-цели, если пользователь его не указал.
pub const DEFAULT_IP_PORT: u16 = 443;

#[derive(Clone, Debug, PartialEq)]
pub enum AnalysisTarget {
    Domain { host: String },
    Ip { ip: IpAddr, port: u16 },
}

/// URL с «https://» так, как его строила доменная ветка analyzer.rs:
/// без «http» — просто добавляет схему. Тримы нет — поведение сохранено.
pub fn target_url_of(input: &str) -> String {
    if !input.starts_with("http") {
        format!("https://{}", input)
    } else {
        input.to_string()
    }
}

/// Главный хост доменной ветки ровно той же формулой, что была в
/// analyzer.rs: host_str из URL, а при невозможности парса — вся строка.
pub fn domain_host_of(input: &str) -> String {
    let target_url = target_url_of(input);
    url::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| target_url.clone())
        .trim_end_matches('/')
        .to_string()
}

/// Разбор ввода в цель анализа.
///
/// Формы: голый IPv4/IPv6, `ip:port`, `[v6]:port`, URL (`https://1.2.3.4:8443/`).
/// Для IP без порта дефолт 443. Всё, что не распозналось как IP — домен.
///
/// Фиксация для IPv6 без скобок с «двоеточие+число» на конце
/// (например `::1:443`): это валидный IPv6-адрес, поэтому трактуем ввод
/// как IP с портом по умолчанию 443. Порт там однозначно отделить нельзя,
/// иного разумного разбора не существует.
pub fn parse_target(input: &str) -> AnalysisTarget {
    let s = input.trim();

    // 1. URL-формы: хост и порт берём прямо из URL.
    if s.starts_with("http://") || s.starts_with("https://") {
        if let Ok(u) = url::Url::parse(s) {
            if let Some(host) = u.host_str() {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    let port = u.port().unwrap_or(DEFAULT_IP_PORT);
                    return AnalysisTarget::Ip { ip, port };
                }
            }
        }
        return AnalysisTarget::Domain { host: domain_host_of(s) };
    }

    // 2. Скобочная IPv6 (возможно с портом): [::1]:443, [::1].
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let inner = &s[1..close];
            let rest = &s[close + 1..];
            let port_opt = match rest.strip_prefix(':') {
                Some(p) => p.parse::<u16>().ok(),
                None if rest.is_empty() => Some(DEFAULT_IP_PORT),
                None => None,
            };
            if let (Ok(ip), Some(port)) = (inner.parse::<IpAddr>(), port_opt) {
                return AnalysisTarget::Ip { ip, port };
            }
            // Невалидная скобочная форма — общий разбор ниже, который
            // трактовал её как домен (старое поведение).
        }
    }

    // 3. Голый IP (IPv4 и IPv6 без скобок).
    if let Ok(ip) = s.parse::<IpAddr>() {
        return AnalysisTarget::Ip { ip, port: DEFAULT_IP_PORT };
    }

    // 4. IPv4 с портом: ip:port.
    if let Some((host, port_s)) = s.rsplit_once(':') {
        if let Ok(port) = port_s.parse::<u16>() {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return AnalysisTarget::Ip { ip, port };
            }
        }
    }

    // 5. Домен — старое поведение (см. domain_host_of).
    AnalysisTarget::Domain { host: domain_host_of(s) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ip6(s: &str) -> IpAddr {
        s.parse::<Ipv6Addr>().unwrap().into()
    }

    fn dom(host: &str) -> AnalysisTarget {
        AnalysisTarget::Domain { host: host.to_string() }
    }

    #[test]
    fn ipv4_without_port_gets_default_443() {
        let t = parse_target("172.65.90.21");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip4(172, 65, 90, 21), port: 443 });
    }

    #[test]
    fn ipv4_with_port() {
        let t = parse_target("172.65.90.21:443");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip4(172, 65, 90, 21), port: 443 });
    }

    #[test]
    fn ipv4_with_nonstandard_port() {
        let t = parse_target("1.2.3.4:8443");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip4(1, 2, 3, 4), port: 8443 });
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        let t = parse_target("[::1]:443");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip6("::1"), port: 443 });
    }

    #[test]
    fn bracketed_ipv6_without_port() {
        let t = parse_target("[::1]");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip6("::1"), port: 443 });
    }

    #[test]
    fn bare_ipv6_is_target_with_default_port() {
        // Фиксация: число с двоеточием на конце (например `::1:443`) —
        // валидный IPv6, трактуем как IP, порт по умолчанию.
        let t = parse_target("::1");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip6("::1"), port: 443 });

        let t2 = parse_target("fe80::1:443");
        assert_eq!(t2, AnalysisTarget::Ip { ip: ip6("fe80::1:443"), port: 443 });
    }

    #[test]
    fn https_url_to_ip_with_port() {
        let t = parse_target("https://1.2.3.4:8443/some/path");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip4(1, 2, 3, 4), port: 8443 });
    }

    #[test]
    fn https_url_to_ip_without_port() {
        let t = parse_target("https://1.2.3.4/");
        assert_eq!(t, AnalysisTarget::Ip { ip: ip4(1, 2, 3, 4), port: 443 });
    }

    #[test]
    fn plain_domain() {
        assert_eq!(parse_target("twitter.com"), dom("twitter.com"));
    }

    #[test]
    fn domain_with_trailing_slash() {
        assert_eq!(parse_target("twitter.com/"), dom("twitter.com"));
    }

    #[test]
    fn https_url_to_domain() {
        assert_eq!(parse_target("https://site.com/x"), dom("site.com"));
    }

    #[test]
    fn invalid_port_falls_back_to_domain() {
        // «1.2.3.4:99999» — порт не влезает в u16: не IP-цель. Доменное
        // поведение сохраняется: старая формула при отказе парса отдавала
        // всю построенную ссылку целиком.
        assert_eq!(parse_target("1.2.3.4:99999"), dom("https://1.2.3.4:99999"));
    }

    #[test]
    fn domain_with_port_is_domain_as_before() {
        // Доменный путь раньше всегда терял порт (host_str без порта) —
        // поведение не меняем в этой задаче.
        assert_eq!(parse_target("site.com:8443"), dom("site.com"));
    }
}
