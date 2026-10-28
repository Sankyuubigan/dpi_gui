//! Скрипт подбора рабочего DNS (кнопка «Подбор рабочего DNS»).
//!
//! Для сайтов с посессионным гео-блоком (кейс aistudio.google.com: до входа
//! в аккаунт страница отдаётся всем, проверка региона происходит после
//! логина и привязана к ИСХОДНОМУ IP клиента) проба страницы бессмысленна —
//! она всегда видит «открыт» (доказано пробами 28.10.26: curl с обоих эджей
//! и свежий браузер получают одинаковый 200). Единственный сетевой фикс —
//! проксирующий DoH-резолвер: кейс eu.geohide.ru отдаёт СВОИ шлюзы, трафик
//! идёт через сервис, Google видит не клиентский IP (живое подтверждение).
//!
//! Классификация ответов: адрес из официальных диапазонов Google (goog.json)
//! = прямой эдж — такой DNS посессионный блок не чинит (доказано
//! hosts-тестом 28.10.26: запись настоящего Google-эджа в hosts не сняла
//! редирект); адрес вне диапазонов = проксирует. Критерий «отличается от
//! ответов dns.google» ЗАПРЕЩЁН: GeoDNS легитимно раздаёт разным резолверам
//! разные эджи (контрпример: dns.comss.one → 142.251.155.2 — прямой эдж).

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::config;
use crate::diagnostics_probe::{self, is_stub_ip, run_with_timeout, DohAnswers};
use crate::ip_target;

/// Снапшот официальных диапазонов Google (www.gstatic.com/ipranges/goog.json,
/// снят 28.10.26) — фолбэк, если живая загрузка не удалась.
const GOOG_SNAPSHOT: &str = include_str!("dns_pick_goog_ranges.txt");
const GOOG_JSON_URL: &str = "https://www.gstatic.com/ipranges/goog.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResolverKind {
    /// Проксирует: отдаёт свои шлюзы, трафик идёт через сервис — рабочий DNS.
    Proxy,
    /// Прямые адреса Google: соединение идёт напрямую, посессионый
    /// гео-блок остаётся (доказано hosts-тестом 28.10.26).
    Direct,
    /// Сервис не ответил / не дал адресов.
    Dead,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickEntry {
    pub service: String,
    pub resolved: Vec<String>,
    pub kind: ResolverKind,
    pub note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsPickOutcome {
    pub domain: String,
    pub entries: Vec<DnsPickEntry>,
    /// Итоговая строка — единый текст для лог-панели (SSOT).
    pub summary: String,
}

// --- диапазоны Google ---

#[derive(Deserialize)]
struct GoogJson {
    #[serde(default)]
    prefixes: Vec<GoogPrefix>,
}

#[derive(Deserialize)]
struct GoogPrefix {
    #[serde(rename = "ipv4Prefix", default)]
    ipv4_prefix: Option<String>,
    #[serde(rename = "ipv6Prefix", default)]
    ipv6_prefix: Option<String>,
}

/// Диапазоны Google: (адрес, маска). v4 и v6 раздельно.
struct Nets {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    /// Диапазоны взяты из живой загрузки (true) или из снапшота (false) —
    /// для честности в примечании отчёта.
    source_live: bool,
}

/// Парсинг текста «CIDR на строку». Чистая функция — покрыта юнит-тестами.
fn parse_ranges(text: &str) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (addr_str, bits_str) = match line.split_once('/') {
            Some((a, b)) => (a, b),
            None => continue,
        };
        let bits: u8 = match bits_str.trim().parse() {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(ip) = addr_str.trim().parse::<Ipv4Addr>() {
            if bits > 32 {
                continue;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            v4.push((u32::from(ip) & mask, mask));
        } else if let Ok(ip) = addr_str.trim().parse::<Ipv6Addr>() {
            if bits > 128 {
                continue;
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            v6.push((u128::from(ip) & mask, mask));
        }
    }
    (v4, v6)
}

/// Диапазоны Google: живая загрузка goog.json, при сбое — вшитый снапшот
/// (спроектированный фолбэк, не молчаливая ошибка: источник фиксируется
/// в `Nets.source_live` и попадает в примечание отчёта).
fn google_nets() -> &'static Nets {
    static NETS: OnceLock<Nets> = OnceLock::new();
    NETS.get_or_init(|| {
        let live = run_with_timeout(
            || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(6))
                    .build()
                    .map_err(|e| e.to_string())?;
                let body = client
                    .get(GOOG_JSON_URL)
                    .send()
                    .map_err(|e| e.to_string())?
                    .error_for_status()
                    .map_err(|e| e.to_string())?
                    .text()
                    .map_err(|e| e.to_string())?;
                let parsed: GoogJson = serde_json::from_str(&body).map_err(|e| e.to_string())?;
                let mut text = String::new();
                for p in parsed.prefixes {
                    if let Some(v4) = p.ipv4_prefix {
                        text.push_str(&v4);
                        text.push('\n');
                    }
                    if let Some(v6) = p.ipv6_prefix {
                        text.push_str(&v6);
                        text.push('\n');
                    }
                }
                if text.trim().is_empty() {
                    return Err("пустой список диапазонов".to_string());
                }
                Ok(text)
            },
            8000,
        );
        match live {
            Some(Ok(text)) => {
                let (v4, v6) = parse_ranges(&text);
                if !v4.is_empty() || !v6.is_empty() {
                    return Nets { v4, v6, source_live: true };
                }
            }
            _ => {}
        }
        let (v4, v6) = parse_ranges(GOOG_SNAPSHOT);
        Nets { v4, v6, source_live: false }
    })
}

/// Принадлежит ли IP диапазонам Google. Чистая функция — покрыта тестами.
fn in_google_ranges(ip: &IpAddr, nets: &Nets) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let i = u32::from(*v4);
            nets.v4.iter().any(|(net, mask)| i & mask == *net)
        }
        IpAddr::V6(v6) => {
            let i = u128::from(*v6);
            nets.v6.iter().any(|(net, mask)| i & mask == *net)
        }
    }
}

/// Классификация одного ответа сервиса. Чистая функция (диапазоны берёт
/// параметром) — покрыта юнит-тестами.
fn classify_answer(service: &str, ips: &[IpAddr], nets: &Nets) -> DnsPickEntry {
    let real: Vec<IpAddr> = ips.iter().copied().filter(|ip| !is_stub_ip(ip)).collect();
    let resolved: Vec<String> = real.iter().map(|i| i.to_string()).collect();
    let entry = |kind: ResolverKind, note: String| DnsPickEntry {
        service: service.to_string(),
        resolved: resolved.clone(),
        kind,
        note,
    };
    if real.is_empty() {
        return entry(
            ResolverKind::Dead,
            "не вернул адресов (или только заглушки)".to_string(),
        );
    }
    let outside: Vec<String> = real
        .iter()
        .filter(|ip| !in_google_ranges(ip, nets))
        .map(|i| i.to_string())
        .collect();
    if outside.is_empty() {
        entry(
            ResolverKind::Direct,
            format!(
                "прямые адреса Google ({}) — редирект в сессии останется (доказано hosts-тестом 28.10.26)",
                resolved.join(", ")
            ),
        )
    } else {
        entry(
            ResolverKind::Proxy,
            format!(
                "проксирует: отдаёт свои адреса ({}) — трафик пойдёт через сервис",
                outside.join(", ")
            ),
        )
    }
}

/// Классификация всех ответов (чистая относительно сети: диапазоны — параметр).
pub fn pick_resolvers(answers: &DohAnswers) -> Vec<DnsPickEntry> {
    let nets = google_nets();
    answers
        .answers
        .iter()
        .map(|a| match &a.error {
            Some(err) => DnsPickEntry {
                service: a.service.clone(),
                resolved: Vec::new(),
                kind: ResolverKind::Dead,
                note: err.clone(),
            },
            None => classify_answer(&a.service, &a.ips, nets),
        })
        .collect()
}

/// Запуск скрипта: домен из поля → перебор doh-services.txt → классификация.
/// Никаких проб страницы и очереди анализа — только DoH-опрос.
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

    let entries = pick_resolvers(&answers);
    let working = entries
        .iter()
        .find(|e| e.kind == ResolverKind::Proxy)
        .map(|e| e.service.clone());
    // Честность (core §2.2): если диапазоны Google взяты из вшитого снапшота
    // (живая загрузка не удалась), юзер обязан это видеть — снапшот мог
    // устареть, и классификация «прямой/прокси» могла быть неточной.
    let nets = google_nets();
    let nets_note = if nets.source_live {
        String::new()
    } else {
        " (диапазоны Google — вшитый снапшот: живая загрузка goog.json не удалась)".to_string()
    };
    let summary = match working {
        Some(svc) => format!(
            "Рабочий DNS: {} (проксирует {}) — включите его как Secure DNS в браузере, адрес: https://{}/dns-query{}",
            svc, host, svc, nets_note
        ),
        None => format!(
            "ни один сервис из списка ({} шт.) не проксирует {} — DNS-подмена не поможет, нужен VPN/прокси{}",
            entries.len(),
            host,
            nets_note
        ),
    };

    Ok(DnsPickOutcome {
        domain: host,
        entries,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// 7 A-записей — все вне диапазонов Google, см. тест ниже).
    const GEOHIDE_RESPONSE_HEX: &str = "12348180000100070000000108616973747564696f06676f6f676c6503636f6d0000010001c00c000100010000003c000405afa128c00c000100010000003c00041f19ef84c00c000100010000003c00042d0dedd5c00c000100010000003c000405afa103c00c000100010000003c00048f1440c0c00c000100010000003c000425dd5d80c00c000100010000003c000425dd5d8d0000291000000000000000";

    #[test]
    fn parse_doh_wire_response_reads_all_answers() {
        let bytes: Vec<u8> = (0..GEOHIDE_RESPONSE_HEX.len() / 2)
            .map(|i| u8::from_str_radix(&GEOHIDE_RESPONSE_HEX[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let ips = diagnostics_probe::parse_doh_wire_response(&bytes);
        assert_eq!(ips.len(), 7, "{:?}", ips);
        assert!(ips.contains(&"5.175.161.40".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"37.221.93.141".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_doh_wire_response_garbage_is_empty() {
        assert!(diagnostics_probe::parse_doh_wire_response(&[]).is_empty());
        assert!(diagnostics_probe::parse_doh_wire_response(&[0u8; 5]).is_empty());
        // rcode != 0 (NXDOMAIN)
        assert!(diagnostics_probe::parse_doh_wire_response(&[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]).is_empty());
    }

    #[test]
    fn parse_ranges_v4_and_v6() {
        let text = "142.251.0.0/16\n8.8.8.0/24\n2001:4860::/32\nмусор\n\n5.175.161.40/32";
        let (v4, v6) = parse_ranges(text);
        assert_eq!(v4.len(), 3, "{:?}", v4);
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn in_google_ranges_truth_table() {
        let (v4, v6) = parse_ranges(GOOG_SNAPSHOT);
        let nets = Nets { v4, v6, source_live: false };
        // Прямые Google-эджи (из живых ответов comss/dns.google 28.10.26).
        assert!(in_google_ranges(&"142.251.155.2".parse().unwrap(), &nets));
        assert!(in_google_ranges(&"64.233.162.101".parse().unwrap(), &nets));
        assert!(in_google_ranges(&"142.250.178.46".parse().unwrap(), &nets));
        // Прокси-шлюзы geohide (живой ответ 28.10.26) — вне диапазонов.
        assert!(!in_google_ranges(&"5.175.161.40".parse().unwrap(), &nets));
        assert!(!in_google_ranges(&"37.221.93.128".parse().unwrap(), &nets));
        assert!(!in_google_ranges(&"31.25.239.132".parse().unwrap(), &nets));
    }

    fn nets() -> Nets {
        let (v4, v6) = parse_ranges(GOOG_SNAPSHOT);
        Nets { v4, v6, source_live: false }
    }

    #[test]
    fn classify_google_ips_is_direct() {
        let e = classify_answer(
            "dns.comss.one",
            &["142.251.155.2".parse().unwrap()],
            &nets(),
        );
        assert_eq!(e.kind, ResolverKind::Direct);
        assert!(e.note.contains("hosts-тестом"), "{}", e.note);
    }

    #[test]
    fn classify_own_gateways_is_proxy() {
        let e = classify_answer(
            "eu.geohide.ru",
            &["5.175.161.40".parse().unwrap(), "37.221.93.128".parse().unwrap()],
            &nets(),
        );
        assert_eq!(e.kind, ResolverKind::Proxy);
        assert!(e.note.contains("проксирует"), "{}", e.note);
    }

    /// Смешанный ответ: хоть один не-Google адрес — сервис проксирует
    /// (браузер может пойти через шлюз), прямые адреса перечисляются рядом.
    #[test]
    fn classify_mixed_answer_is_proxy() {
        let e = classify_answer(
            "svc.example",
            &["142.251.155.2".parse().unwrap(), "5.175.161.40".parse().unwrap()],
            &nets(),
        );
        assert_eq!(e.kind, ResolverKind::Proxy);
        assert!(e.note.contains("5.175.161.40"), "{}", e.note);
    }

    #[test]
    fn classify_stub_only_is_dead() {
        let e = classify_answer("svc.example", &["0.0.0.0".parse().unwrap()], &nets());
        assert_eq!(e.kind, ResolverKind::Dead);
    }

    /// Вшитый снапшот обязан парситься и содержать диапазоны, покрывающие
    /// живые Google-эджи (защита от порчи файла при будущих правках).
    #[test]
    fn goog_snapshot_is_parsable_and_covers_edges() {
        let (v4, v6) = parse_ranges(GOOG_SNAPSHOT);
        assert!(v4.len() >= 100, "v4: {}", v4.len());
        assert!(!v6.is_empty(), "v6 пуст");
        assert!(in_google_ranges(&"142.251.155.2".parse().unwrap(), &Nets { v4, v6, source_live: false }));
    }

    /// Живой эталон классификации (ground truth юзера 28.10.26: браузер с
    /// eu.geohide.ru не редиректит, с прямыми адресами — редиректит).
    /// Запуск вручную: `cargo test live_pick_aistudio -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network"]
    fn live_pick_aistudio() {
        let out = run_pick("https://aistudio.google.com").expect("run_pick");
        for e in &out.entries {
            println!("{:?} — {}: {}", e.kind, e.service, e.note);
        }
        println!("ИТОГ: {}", out.summary);
        let geohide = out.entries.iter().find(|e| e.service == "eu.geohide.ru");
        let geohide = match geohide {
            Some(e) => e,
            None => panic!("eu.geohide.ru не в списке doh-services.txt"),
        };
        assert_eq!(geohide.kind, ResolverKind::Proxy, "эталон: geohide проксирует ({:?})", geohide);
        for svc in ["dns.google", "cloudflare-dns.com", "dns.comss.one"] {
            if let Some(e) = out.entries.iter().find(|e| e.service == svc) {
                assert_eq!(e.kind, ResolverKind::Direct, "эталон: {} — прямой резолвер ({:?})", svc, e);
            }
        }
    }
}
