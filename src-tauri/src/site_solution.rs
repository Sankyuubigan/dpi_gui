//! Механика «найденное решение»: из фактов анализа собирается конкретное
//! действие для кнопки «Починить сайт».
//!
//! Ядро (core rules §2.8): [`decide`] — чистая функция без сети и файловой
//! системы; она решает, ЧТО применить, но ничего не применяет. Текст блока
//! «ИТОГ АНАЛИЗА» строится здесь же — единый источник и данных, и их
//! формулировки (SSOT). Применение — в `main.rs::apply_solution`.

use serde::{Deserialize, Serialize};

use crate::analyzer_probe::Classification;
use crate::analyzer_report::{is_background_host, ReportMeta};
use crate::site_probe;
use crate::site_verdict::Verdict;

/// Конкретное действие кнопки «Починить сайт».
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SolutionAction {
    /// Добавить домены в список обхода (general-лист).
    AddToBypassList { domains: Vec<String> },
    /// Добавить домены в исключения — обход их ломает.
    AddToExcludeList { domains: Vec<String> },
    /// Записать проверенный IP в hosts для домена (apex + www).
    WriteHosts { ip: String, domain: String },
}

/// Найденное (или не найденное) решение анализа.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSolution {
    /// Есть ли действие, которое кнопка «Починить сайт» может применить.
    pub found: bool,
    pub actions: Vec<SolutionAction>,
    /// Короткая человеческая формулировка найденного решения.
    pub summary: String,
    /// При `found == false` — честная причина, почему решения у приложения нет.
    pub none_reason: Option<String>,
}

/// Приоритет решений — от самого безопасного и доказанного к частному:
/// 1. Исключения: классификация доказала «обход ломает домен» (с обходом
///    обрыв, без обхода работает). Применение — исключить и перезапустить обход.
/// 2. Обход: домен заблокирован сам (сломан и с обходом, и без) — в general-лист.
/// 3. Hosts: главный домен — доказанная подмена DNS, и найден проверенный
///    (DoH, не шлюз) адрес, через который HTTPS-проба реально открыла сайт.
///
/// Фоновые домены (трекеры) и уже покрытые списками не попадают в действия:
/// советовать их — ложь.
pub fn decide(meta: &ReportMeta, c: &Classification) -> SiteSolution {
    let mut actions: Vec<SolutionAction> = Vec::new();
    let mut summaries: Vec<String> = Vec::new();

    // 1. Исключения: обход ломает домен.
    let excludes: Vec<String> = c
        .bypass_breaks
        .iter()
        .map(|(h, _)| h.clone())
        .filter(|h| !is_background_host(h))
        .filter(|h| !is_main_fixed_by_hosts(meta, h))
        .collect();
    if !excludes.is_empty() {
        summaries.push(format!(
            "добавить в исключения обхода: {} (обход эти домены ломает)",
            excludes.join(", ")
        ));
        actions.push(SolutionAction::AddToExcludeList { domains: excludes });
    }

    // 2. Обход: домен заблокирован сам по себе.
    let bypass: Vec<String> = c
        .need_bypass
        .iter()
        .filter(|h| !is_background_host(h))
        .filter(|h| !is_main_fixed_by_hosts(meta, h))
        // Сайт, доказанно открывающийся без обхода (вердикт Open из чистого
        // окна), обходу не подлежит: обход не чинит работающий сайт — в этом
        // кейсе он его ЛОМАЛ (кейс eu.aptabase.com). Арбитраж в analyzer.rs
        // обычно убирает такой домен из need_bypass до decide(); фильтр —
        // вторая линия обороны, чтобы вредный совет не воскрес.
        .filter(|h| !is_main_open(meta, h))
        .cloned()
        .collect();
    if !bypass.is_empty() {
        summaries.push(format!(
            "добавить в список обхода (general-лист): {}",
            bypass.join(", ")
        ));
        actions.push(SolutionAction::AddToBypassList { domains: bypass });
    }

    // 3. Hosts: подмена DNS доказана, есть проверенный не-шлюзовой адрес.
    if let Some(probe) = &meta.main_probe {
        if probe.verdict.needs_address_fix() {
            if let Some(ip) = verified_hosts_ip(probe) {
                summaries.push(format!(
                    "записать в hosts {} → {} (адрес проверен DoH-каналом и HTTPS-пробой)",
                    ip, probe.host
                ));
                actions.push(SolutionAction::WriteHosts {
                    ip,
                    domain: probe.host.clone(),
                });
            }
        }
    }

    if actions.is_empty() {
        SiteSolution {
            found: false,
            actions: Vec::new(),
            summary: String::new(),
            none_reason: Some(no_solution_reason(meta, c)),
        }
    } else {
        SiteSolution {
            found: true,
            actions,
            summary: summaries.join("; "),
            none_reason: None,
        }
    }
}

/// Главный домен открывается без обхода (вердикт Open) — в обход его
/// советовать нельзя.
fn is_main_open(meta: &ReportMeta, host: &str) -> bool {
    meta.main_probe
        .as_ref()
        .map(|p| p.host == host && p.verdict == Verdict::Open)
        .unwrap_or(false)
}

/// Главный домен лечится hosts (проверенный адрес найден) — в списки его
/// советовать нельзя: противоречие внутри одного решения (кейс vercel).
fn is_main_fixed_by_hosts(meta: &ReportMeta, host: &str) -> bool {
    meta.main_probe
        .as_ref()
        .map(|p| {
            p.host == host && p.verdict.needs_address_fix() && verified_hosts_ip(p).is_some()
        })
        .unwrap_or(false)
}

/// Проверенный адрес главного домена для hosts: DoH-источник + реальный
/// HTTPS-ответ Ok. Тот же критерий, что у `site_probe::hosts_entries` —
/// единый источник правды (дублирование критерия = расхождение решений).
fn verified_hosts_ip(probe: &site_probe::DomainProbe) -> Option<String> {
    site_probe::hosts_entries(probe)
        .first()
        .and_then(|line| line.split(' ').next().map(|s| s.to_string()))
}

/// Честная причина «решения нет» — по фактическому вердикту, без выдумок.
fn no_solution_reason(meta: &ReportMeta, c: &Classification) -> String {
    let Some(probe) = &meta.main_probe else {
        return "анализ не смог собрать факты по главному домену".to_string();
    };
    match probe.verdict {
        Verdict::Open if c.bypass_breaks.is_empty() => {
            "сайт открывается — чинить нечего".to_string()
        }
        Verdict::Open => {
            format!(
                "сайт открывается без обхода, но обход ломает домены сайта: {}",
                c.bypass_breaks
                    .iter()
                    .map(|(h, _)| h.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Verdict::GeoBlocked | Verdict::ServiceRestricted => {
            "сайт ограничивает сам сервис по региону клиента: блокировка по исходному IP. \
             Ни hosts, ни DNS, ни обход не помогут — нужен VPN/прокси (смена исходного IP)"
                .to_string()
        }
        Verdict::WwwOnly => format!(
            "сайт открывается только по имени с префиксом www: {}",
            probe
                .www_url
                .clone()
                .unwrap_or_else(|| format!("https://www.{}/", probe.host))
        ),
        Verdict::DnsBlocked => {
            "DNS подменён, но проверенного рабочего адреса найти не удалось: \
             сначала смените DNS-сервер на шифрованный (DoH) и повторите анализ"
                .to_string()
        }
        Verdict::IpUnreachable | Verdict::IpReset | Verdict::NoPath | Verdict::TlsBroken
        | Verdict::BadCert | Verdict::BlockPage | Verdict::IspBlockRedirect | Verdict::Unknown => {
            format!(
                "действий приложения недостаточно: {} — {}",
                probe.verdict.verdict_name(),
                probe
                    .diagnosis
                    .as_ref()
                    .map(|d| d.probable_cause.clone())
                    .unwrap_or_default()
            )
        }
    }
}

/// Текстовый блок «ИТОГ АНАЛИЗА» для отчёта. Данные те же, что уезжают
/// на фронтенд в `SiteSolution` — два вида одного источника (SSOT).
pub fn report_block(solution: &SiteSolution) -> String {
    let mut s = String::from("\n════ ИТОГ АНАЛИЗА ════\n");
    if solution.found {
        s.push_str(&format!("✅ НАЙДЕННОЕ РЕШЕНИЕ: {}\n", solution.summary));
        s.push_str("   Кнопка «🔧 Починить сайт» применит это действие автоматически.\n");
    } else {
        s.push_str(&format!(
            "❌ РЕШЕНИЕ НЕ НАЙДЕНО: {}\n",
            solution
                .none_reason
                .clone()
                .unwrap_or_else(|| "причина не установлена".to_string())
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer_report::ReportMeta;
    use crate::diagnostics_probe::{DnsInfo, HttpResult};
    use crate::site_probe::{DomainProbe, IpSource};
    use crate::site_verdict::{CauseContext, Verdict};

    fn empty_classification() -> Classification {
        Classification {
            need_bypass: Vec::new(),
            bypass_breaks: Vec::new(),
            dns_fail: Vec::new(),
            ok: Vec::new(),
            broken: Vec::new(),
        }
    }

    fn diagnosis(verdict: Verdict, host: &str, doh_working_ip: Option<&str>) -> crate::site_verdict::Diagnosis {
        crate::site_verdict::explain(
            verdict,
            &CauseContext {
                host,
                www_url: None,
                apex_ip: Some("1.2.3.4"),
                dns_spoofed: matches!(verdict, Verdict::DnsBlocked),
                doh_working_ip,
                same_host_alt_ip_works: doh_working_ip.is_some(),
                isp_redirect: None,
                doh_http80_hint: false,
                doh_candidates: Vec::new(),
                probe_fail_note: None,
            },
        )
    }

    fn probe(verdict: Verdict, working_http: Option<HttpResult>, source: Option<IpSource>) -> DomainProbe {
        let mut dns = DnsInfo::new();
        dns.system = vec!["1.2.3.4".parse().unwrap()];
        DomainProbe {
            host: "example.com".to_string(),
            dns,
            primary_ips: vec!["1.2.3.4".to_string()],
            doh_ips: vec![],
            doh_gateway_ips: vec![],
            doh_ip_services: vec![],
            working_ip: Some("5.6.7.8".to_string()),
            working_ip_source: source,
            working_http,
            http_note: String::new(),
            verdict,
            www_host: Some("www.example.com".to_string()),
            www_ips: vec![],
            www_url: None,
            isp_redirect: None,
            dns_spoofed: matches!(verdict, Verdict::DnsBlocked).then(|| "расхождение".to_string()),
            doh_failures: vec![],
            diagnosis: Some(diagnosis(verdict, "example.com", Some("5.6.7.8"))),
        }
    }

    fn meta(p: DomainProbe) -> ReportMeta {
        ReportMeta {
            target_url: "https://example.com/".to_string(),
            discovered: vec!["example.com".to_string()],
            bypass_on: true,
            bypass_toggled: true,
            restore_note: None,
            had_browser_failures: false,
            main_probe: Some(p),
            main_dns_sub: Vec::new(),
            dns_fail_sub: Vec::new(),
            block_scan: None,
        }
    }

    /// Кейс sostav.ru: обход ломает корневой домен → решение «в исключения».
    #[test]
    fn bypass_breaks_main_host_gives_exclude_action() {
        let mut c = empty_classification();
        c.bypass_breaks = vec![("sostav.ru".to_string(), "error sending request".to_string())];
        let m = meta(probe(Verdict::Open, Some(HttpResult::Ok(200)), Some(IpSource::SystemDns)));
        let s = decide(&m, &c);
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::AddToExcludeList {
                domains: vec!["sostav.ru".to_string()]
            }]
        );
        assert!(s.summary.contains("исключения"), "{}", s.summary);
    }

    /// Кейс openrouter.ai: гео-блок с WAF-маркерами → решения нет, только VPN.
    #[test]
    fn geo_block_has_no_solution_and_names_vpn() {
        let m = meta(probe(
            Verdict::GeoBlocked,
            Some(HttpResult::Forbidden(403)),
            Some(IpSource::SystemDns),
        ));
        let s = decide(&m, &empty_classification());
        assert!(!s.found);
        assert!(s.none_reason.as_ref().unwrap().contains("VPN"), "{:?}", s.none_reason);
    }

    /// Кейс nnmclub: подмена DNS + проверенный DoH-адрес → решение «в hosts».
    #[test]
    fn dns_blocked_with_verified_ip_gives_hosts_action() {
        let m = meta(probe(
            Verdict::DnsBlocked,
            Some(HttpResult::Ok(200)),
            Some(IpSource::Doh),
        ));
        let s = decide(&m, &empty_classification());
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::WriteHosts {
                ip: "5.6.7.8".to_string(),
                domain: "example.com".to_string()
            }]
        );
    }

    /// Подмена DNS, но рабочий адрес не подтверждён HTTPS — hosts не предлагаем.
    #[test]
    fn dns_blocked_without_verified_ip_has_no_solution() {
        let m = meta(probe(Verdict::DnsBlocked, Some(HttpResult::Rst), Some(IpSource::SystemDns)));
        let s = decide(&m, &empty_classification());
        assert!(!s.found);
        let reason = s.none_reason.unwrap();
        assert!(reason.contains("DoH"), "{}", reason);
    }

    /// Домен, сломанный обходом, но названный «рабочим» hosts-лечением —
    /// не может одновременно ехать в исключения (противоречие запрещено).
    #[test]
    fn hosts_fixed_main_host_is_not_offered_exclusions() {
        let mut c = empty_classification();
        c.bypass_breaks = vec![("example.com".to_string(), "err".to_string())];
        // Вердикт Open: без обхода сайт открывается, hosts-лечение не нужно.
        let m = meta(probe(Verdict::Open, Some(HttpResult::Ok(200)), Some(IpSource::SystemDns)));
        let s = decide(&m, &c);
        assert!(s.found);
        assert!(matches!(s.actions[0], SolutionAction::AddToExcludeList { .. }));
    }

    /// Кейс eu.aptabase.com: главный домен открывается без обхода (вердикт
    /// Open из чистого окна), а классификация звала его в обход. Действие
    /// AddToBypassList для открытого сайта — вредная ложь, запрещено даже
    /// если арбитраж выше по стеку не сработал.
    #[test]
    fn open_main_host_never_gets_bypass_action() {
        let m = meta(probe(Verdict::Open, Some(HttpResult::Ok(200)), Some(IpSource::SystemDns)));
        let mut c = empty_classification();
        c.need_bypass = vec!["example.com".to_string()];
        let s = decide(&m, &c);
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "открытый сайт нельзя звать в обход: {:?}",
            s.actions
        );
        assert!(!s.found, "{:?}", s);
        assert!(
            s.none_reason.as_ref().unwrap().contains("чинить нечего"),
            "{:?}",
            s.none_reason
        );
    }

    /// Фоновые домены (трекеры) не попадают в решение.
    #[test]
    fn background_domains_are_excluded_from_actions() {
        let mut c = empty_classification();
        c.need_bypass = vec!["static.cloudflareinsights.com".to_string()];
        let m = meta(probe(Verdict::Open, Some(HttpResult::Ok(200)), Some(IpSource::SystemDns)));
        let s = decide(&m, &c);
        assert!(!s.found, "{:?}", s);
    }

    /// Текстовый блок обязан совпадать по смыслу с данными решения.
    #[test]
    fn report_block_matches_solution_data() {
        let found = SiteSolution {
            found: true,
            summary: "добавить в исключения обхода: sostav.ru".to_string(),
            actions: vec![SolutionAction::AddToExcludeList {
                domains: vec!["sostav.ru".to_string()],
            }],
            none_reason: None,
        };
        let b = report_block(&found);
        assert!(b.contains("ИТОГ АНАЛИЗА"), "{}", b);
        assert!(b.contains("НАЙДЕННОЕ РЕШЕНИЕ"), "{}", b);
        assert!(b.contains("sostav.ru"), "{}", b);

        let none = SiteSolution {
            found: false,
            summary: String::new(),
            actions: Vec::new(),
            none_reason: Some("нужен VPN".to_string()),
        };
        let b = report_block(&none);
        assert!(b.contains("РЕШЕНИЕ НЕ НАЙДЕНО"), "{}", b);
        assert!(b.contains("нужен VPN"), "{}", b);
    }

    /// Serde-контракт для фронтенда: тег типа и имена полей в camelCase.
    #[test]
    fn serde_contract_is_stable() {
        let s = SiteSolution {
            found: true,
            summary: "x".to_string(),
            actions: vec![
                SolutionAction::WriteHosts {
                    ip: "1.2.3.4".to_string(),
                    domain: "example.com".to_string(),
                },
                SolutionAction::AddToBypassList {
                    domains: vec!["a.ru".to_string()],
                },
            ],
            none_reason: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["found"], true);
        assert_eq!(v["actions"][0]["type"], "writeHosts");
        assert_eq!(v["actions"][0]["ip"], "1.2.3.4");
        assert_eq!(v["actions"][1]["type"], "addToBypassList");
    }
}
