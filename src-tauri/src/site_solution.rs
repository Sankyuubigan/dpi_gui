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
use crate::bypass_lists;
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
    /// Убрать записи DPI_GUI для домена из hosts (мёртвая закреплённая запись —
    /// кейс 30.10.26 «прописали IP, он умер»). Чужие (непомеченные) записи
    /// приложение не трогает — remove_hosts_entry честно отчитается.
    RemoveHosts { domain: String },
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
///    Только если домен ЕЩЁ НЕ покрыт списками (добавлять покрытое — нулевой
///    эффект, кейс vercel 27.10.26), НЕ покрыт исключениями (в winws
///    исключения проверяются раньше include-листов — nfq/hostlist.c: добавление
///    в general-лист не изменит ничего, кейс api.messenger.yandex.net 27.10.26)
///    и вердикт главного домена вообще допускает лечение обходом
///    ([`Verdict::bypass_relevant`]).
/// 3. Hosts по пробе главного домена: доказанная подмена DNS, найден проверенный
///    (DoH, не шлюз) адрес, через который HTTPS-проба открыла сайт.
/// 4. Hosts по DoH-подмене: сайт не открылся нигде, но подменные DoH-сервисы
///    отдали адрес, на котором HTTPS дал живой ответ (кейс vercel: системный
///    DNS отдал мёртвые адреса, живой был только у DoH — пользователь чинил
///    именно ручной записью в hosts).
///
/// Фоновые домены (трекеры) и уже покрытые списками (включая исключения)
/// не попадают в действия: советовать их — ложь. Карты списков берутся из
/// `meta.bypass_map` / `meta.exclude_set` (SSOT: отчёт и решение потребляют
/// одну загрузку).
pub fn decide(meta: &ReportMeta, c: &Classification) -> SiteSolution {
    // 0. Мёртвая запись hosts (кейс 30.10.26 «прописали IP — он умер»):
    //    браузер ходит по закреплённому адресу НАПРЯМУЮ, минуя DNS, поэтому
    //    починка записи — приоритет над всеми действиями про DNS-путь. Другие
    //    действия при раннем возврате не добавляются: состояние DNS-пути
    //    (обход/VPN/исключения) после починки записи честно описано в отчёте,
    //    а совет «в списки» рядом с hosts-фиксом — противоречие (кейс vercel).
    if let Some(pin) = meta
        .hosts_pins
        .iter()
        .find(|p| site_probe::hosts_pin_is_broken(&p.http))
    {
        return hosts_pin_solution(meta, pin);
    }

    let mut actions: Vec<SolutionAction> = Vec::new();
    let mut summaries: Vec<String> = Vec::new();

    let main_verdict = meta.main_probe.as_ref().map(|p| p.verdict);
    let main_host = meta.main_probe.as_ref().map(|p| p.host.clone());

    // 1. Исключения: обход ломает домен. Уже покрытые исключениями не
    //    советуем: повторное добавление — нулевой эффект (совет-дубликат).
    let mut already_excluded: Vec<String> = Vec::new();
    let excludes: Vec<String> = c
        .bypass_breaks
        .iter()
        .map(|(h, _)| h.clone())
        .filter(|h| !is_background_host(h))
        .filter(|h| !is_main_fixed_by_hosts(meta, h))
        .filter(|h| match bypass_lists::is_excluded(h, &meta.exclude_set) {
            Some(_) => {
                already_excluded.push(h.clone());
                false
            }
            None => true,
        })
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
        // Главный домен звать в обход можно только при вердикте DPI-класса:
        // «IP не отвечает» и прочее обходом не лечится (кейс vercel 27.10.26).
        .filter(|h| {
            if Some(*h) == main_host.as_ref() {
                main_verdict.map(|v| v.bypass_relevant()).unwrap_or(false)
            } else {
                true
            }
        })
        .cloned()
        .collect();
    // Уже покрытые списками домены не советуем: добавление ничего не изменит.
    let (bypass, covered) =
        bypass_lists::split_bypass_candidates(&bypass, &meta.bypass_map);
    // Домен, покрытый списком ИСКЛЮЧЕНИЙ, в обход звать нельзя: в winws
    // исключения проверяются раньше include-листов (nfq/hostlist.c,
    // HostlistCheck_), так что «добавить в general-лист» не изменит ничего —
    // кнопка «Починить» отчиталась бы об успехе, а сайт остался бы сломан
    // (кейс api.messenger.yandex.net 27.10.26: домен накрыт записью
    // yandex.net в дефолтных исключениях). Ложный совет запрещён.
    let mut blocked_by_exclude: Vec<(String, String)> = Vec::new();
    let bypass: Vec<String> = bypass
        .into_iter()
        .filter(|h| match bypass_lists::is_excluded(h, &meta.exclude_set) {
            Some(entry) => {
                blocked_by_exclude.push((h.clone(), entry));
                false
            }
            None => true,
        })
        .collect();
    if !bypass.is_empty() {
        summaries.push(format!(
            "добавить в список обхода (general-лист): {}",
            bypass.join(", ")
        ));
        actions.push(SolutionAction::AddToBypassList { domains: bypass });
    }

    // 3. Hosts по пробе главного домена: подмена DNS доказана, есть
    //    проверенный не-шлюзовой адрес.
    let mut hosts_from_probe: Option<(String, String)> = None;
    if let Some(probe) = &meta.main_probe {
        if probe.verdict.needs_address_fix() {
            if let Some(ip) = verified_hosts_ip(probe) {
                hosts_from_probe = Some((ip, probe.host.clone()));
            }
        }
    }

    // 4. Hosts по DoH-подмене: проба главного домена живого адреса не нашла,
    //    но DoH-сервисы отдали адрес с живым HTTPS-ответом. Меняет исход
    //    только когда обход главному домену НЕ предлагается (иначе обход —
    //    приоритетное лечение, и hosts «подменять правильный адрес» не нужен).
    let mut hosts_from_sub: Option<(String, String)> = None;
    if hosts_from_probe.is_none()
        && !matches!(main_verdict, Some(v) if v.bypass_relevant())
    {
        if let Some(verdict) = main_verdict {
            if verdict.site_broken() {
                if let Some(sub) = meta
                    .main_dns_sub
                    .iter()
                    .find(|s| s.http_ok && s.working_ip.is_some())
                {
                    if let (Some(ip), Some(host)) = (sub.working_ip.clone(), main_host.clone()) {
                        hosts_from_sub = Some((ip, host));
                    }
                }
            }
        }
    }
    for (ip, host) in hosts_from_probe.into_iter().chain(hosts_from_sub) {
        // Код ответа виден пользователю: «живой ответ» бывает и 404 (адрес
        // живой, страницу могли не отдать) — молчать об этом была бы ложь.
        let http_ctx = meta
            .main_dns_sub
            .iter()
            .find(|s| s.working_ip.as_deref() == Some(ip.as_str()))
            .map(|s| format!(" ({})", s.http_note))
            .unwrap_or_default();
        summaries.push(format!(
            "записать в hosts {} → {} (адрес проверен DoH-каналом и HTTPS-пробой){}",
            ip, host, http_ctx
        ));
        actions.push(SolutionAction::WriteHosts { ip, domain: host });
    }

    // Честные оговорки о доменах, которым решение не досталось из-за
    // исключений: молчание здесь снова превратилось бы в ложь
    // («починено», а домен остался сломан).
    let mut caveats: Vec<String> = Vec::new();
    if !already_excluded.is_empty() {
        caveats.push(format!(
            "уже в исключениях — повторное добавление ничего не изменит: {}",
            already_excluded.join(", ")
        ));
    }
    if !blocked_by_exclude.is_empty() {
        caveats.push(format!(
            "покрыты исключениями обхода — winws к ним трюки не применяет \
             (исключения сильнее general-листа), в обход звать бессмысленно: {}",
            blocked_by_exclude
                .iter()
                .map(|(h, e)| format!("{} («{}»)", h, e))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if actions.is_empty() {
        SiteSolution {
            found: false,
            actions: Vec::new(),
            summary: String::new(),
            none_reason: Some(no_solution_reason(meta, c, &covered, &caveats)),
        }
    } else {
        if !caveats.is_empty() {
            summaries.push(format!("⚠️ {}", caveats.join("; ")));
        }
        SiteSolution {
            found: true,
            actions,
            summary: summaries.join("; "),
            none_reason: None,
        }
    }
}

/// Решение при мёртвой записи hosts. Приоритеты:
/// 1. Замена на проверенный живой адрес — когда DNS-путь сломан, но анализ
///    нашёл рабочий адрес (та же проверка, что у обычного hosts-совета:
///    DoH-источник + живой HTTPS, либо DoH-подмена с HTTP-пробой). Замена
///    имеет смысл только на адрес, отличный от мёртвого закреплённого.
/// 2. Убрать запись — когда DNS-путь открывается (запись только мешает) либо
///    рабочего адреса найти не удалось. В summary честно называется вердикт
///    DNS-пути: удаление записи возвращает браузер на DNS-путь, чьё состояние
///    описано в отчёте, — «починено и открыто» здесь не обещается.
fn hosts_pin_solution(meta: &ReportMeta, pin: &site_probe::HostsPin) -> SiteSolution {
    let host = pin.domain.clone();
    let replacement = meta.main_probe.as_ref().and_then(|probe| {
        let from_probe = verified_hosts_ip(probe);
        let from_sub = meta
            .main_dns_sub
            .iter()
            .find(|s| s.http_ok)
            .and_then(|s| s.working_ip.clone());
        from_probe.or(from_sub)
    });

    let dns_path_open = meta
        .main_probe
        .as_ref()
        .map(|p| p.verdict == Verdict::Open)
        .unwrap_or(false);

    match replacement {
        // Замена: живой проверенный адрес, отличный от мёртвого закреплённого.
        Some(ip) if ip != pin.ip && !dns_path_open => SiteSolution {
            found: true,
            actions: vec![SolutionAction::WriteHosts { ip: ip.clone(), domain: host.clone() }],
            summary: format!(
                "заменить мёртвую запись hosts ({} → {}) на проверенный живой адрес {} (адрес проверен DoH-каналом и HTTPS-пробой)",
                pin.ip, host, ip
            ),
            none_reason: None,
        },
        _ => {
            let dns_note = match meta.main_probe.as_ref().map(|p| p.verdict) {
                Some(v) => format!("путь по DNS после удаления: {}", v.verdict_name()),
                None => "состояние DNS-пути — в отчёте".to_string(),
            };
            SiteSolution {
                found: true,
                actions: vec![SolutionAction::RemoveHosts { domain: host.clone() }],
                summary: format!(
                    "убрать мёртвую запись hosts ({} → {}); {}; {}",
                    pin.ip,
                    host,
                    dns_note,
                    if dns_path_open {
                        "без записи сайт открывается по DNS".to_string()
                    } else {
                        "дальнейшие шаги — в отчёте анализа".to_string()
                    }
                ),
                none_reason: None,
            }
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
fn no_solution_reason(
    meta: &ReportMeta,
    c: &Classification,
    covered: &[String],
    caveats: &[String],
) -> String {
    let Some(probe) = &meta.main_probe else {
        return "анализ не смог собрать факты по главному домену".to_string();
    };
    // Домены, которые обход уже матчит: «добавьте в обход» для них — нулевой
    // эффект, и причина отсутствия решения обязана это назвать честно
    // (кейс vercel 27.10.26: итог предлагал добавлять уже покрытый домен).
    let covered_note = (!covered.is_empty()).then(|| {
        format!(
            "{} уже покрыт обходом — добавление в списки ничего не изменит",
            covered.join(", ")
        )
    });
    let mut reason = match probe.verdict {
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
    };
    if let Some(note) = covered_note {
        reason.push_str("; ");
        reason.push_str(&note);
    }
    for caveat in caveats {
        reason.push_str("; ");
        reason.push_str(caveat);
    }
    reason
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

/// Слить несколько решений в ОДНО для кнопки «Починить все»: действия
/// собираются по типам в порядке приоритета `decide` (исключения → обход →
/// hosts), домены/IP дедуплицируются — повторная запись того же значения
/// была бы ложным «успехом» поверх уже применённого. Найденные, но пустые
/// по действиям решения отбрасываются: применять нечего — не pretending.
pub fn merge_solutions(solutions: &[SiteSolution]) -> SiteSolution {
    let mut excludes: Vec<String> = Vec::new();
    let mut bypass: Vec<String> = Vec::new();
    let mut hosts: Vec<(String, String)> = Vec::new();
    let mut removes: Vec<String> = Vec::new();
    let mut summaries: Vec<String> = Vec::new();

    for s in solutions {
        if !s.found {
            continue;
        }
        for a in &s.actions {
            match a {
                SolutionAction::AddToExcludeList { domains } => {
                    for d in domains {
                        if !excludes.contains(d) {
                            excludes.push(d.clone());
                        }
                    }
                }
                SolutionAction::AddToBypassList { domains } => {
                    for d in domains {
                        if !bypass.contains(d) {
                            bypass.push(d.clone());
                        }
                    }
                }
                SolutionAction::WriteHosts { ip, domain } => {
                    if !hosts.iter().any(|(i, h)| i == ip && h == domain) {
                        hosts.push((ip.clone(), domain.clone()));
                    }
                }
                SolutionAction::RemoveHosts { domain } => {
                    if !removes.contains(domain) {
                        removes.push(domain.clone());
                    }
                }
            }
        }
        if !s.summary.is_empty() && !summaries.contains(&s.summary) {
            summaries.push(s.summary.clone());
        }
    }

    let mut actions: Vec<SolutionAction> = Vec::new();
    if !excludes.is_empty() {
        actions.push(SolutionAction::AddToExcludeList { domains: excludes });
    }
    // Домен, попавший и в исключения, и в обход (противоречивые решения пачки),
    // остаётся только в исключениях: в winws исключения проверяются раньше
    // include-листов, так что обходная запись для него — нулевой эффект.
    let bypass: Vec<String> = bypass
        .into_iter()
        .filter(|d| !actions.iter().any(|a| matches!(a,
            SolutionAction::AddToExcludeList { domains } if domains.contains(d))))
        .collect();
    if !bypass.is_empty() {
        actions.push(SolutionAction::AddToBypassList { domains: bypass });
    }
    for (ip, domain) in hosts {
        actions.push(SolutionAction::WriteHosts { ip, domain });
    }
    // Удаление записи для домена, который в этой же пачке получают новую живую
    // запись (WriteHosts), лишнее: apply_hosts_entry сам заменяет прежние
    // строки — «убрать, чтобы тут же записать» — лишняя перезапись hosts.
    let removes: Vec<String> = removes
        .into_iter()
        .filter(|d| !actions.iter().any(|a| matches!(a,
            SolutionAction::WriteHosts { domain, .. } if domain == d)))
        .collect();
    for domain in removes {
        actions.push(SolutionAction::RemoveHosts { domain });
    }

    if actions.is_empty() {
        SiteSolution {
            found: false,
            actions: Vec::new(),
            summary: String::new(),
            none_reason: Some("ни одно из переданных решений не содержит действий".to_string()),
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
            geo_dns_note: None,
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
            bypass_map: std::collections::HashMap::new(),
            exclude_set: std::collections::HashSet::new(),
            hosts_pins: Vec::new(),
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

    // ---- Кейс vercel 27.10.26: ложь «добавьте в обход» уже-покрытого домена ----

    fn bypass_meta(p: DomainProbe, entries: &[&str]) -> ReportMeta {
        let mut m = meta(p);
        m.bypass_map = entries
            .iter()
            .map(|e| {
                (
                    e.to_string(),
                    vec![std::path::PathBuf::from("list-general.txt")],
                )
            })
            .collect();
        m
    }

    fn dns_sub(ip: Option<&str>, note: &str, ok: bool) -> site_probe::DnsSubstitution {
        site_probe::DnsSubstitution {
            service: "doh-test".to_string(),
            resolved: Vec::new(),
            working_ip: ip.map(|i| i.to_string()),
            http_note: note.to_string(),
            http_ok: ok,
        }
    }

    /// Главный домен уже покрыт обходом (родитель vercel.app), вердикт
    /// «IP не отвечает»: bypass-совет запрещён, причина честно называет и
    /// покрытость, и невозможность обхода. Регресс на ложь итога.
    #[test]
    fn covered_main_host_ip_unreachable_never_gets_bypass_action() {
        let mut c = empty_classification();
        c.need_bypass = vec!["sub.vercel.app".to_string()];
        let m = bypass_meta(probe(Verdict::IpUnreachable, Some(HttpResult::Timeout), None), &["vercel.app"]);
        let s = decide(&m, &c);
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "покрытый домен нельзя звать в обход: {:?}",
            s.actions
        );
        assert!(!s.found, "{:?}", s);
        let reason = s.none_reason.unwrap();
        assert!(reason.contains("уже покрыт"), "{:?}", reason);
        assert!(reason.contains("IP НЕ ОТВЕЧАЕТ"), "{:?}", reason);
    }

    /// «IP не отвечает», но DoH-подмена нашла живой адрес — решение «в hosts».
    /// Кейс vercel: пользователь чинил именно ручной записью IP.
    #[test]
    fn ip_unreachable_with_doh_sub_gives_hosts_action() {
        let mut c = empty_classification();
        c.need_bypass = vec!["sub.vercel.app".to_string()];
        let mut m = bypass_meta(probe(Verdict::IpUnreachable, Some(HttpResult::Timeout), None), &["vercel.app"]);
        m.main_dns_sub = vec![
            dns_sub(None, "ошибка DoH: не ответил", false),
            dns_sub(Some("203.0.113.7"), "HTTPS через 203.0.113.7: HTTP 404", true),
        ];
        let s = decide(&m, &c);
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::WriteHosts {
                ip: "203.0.113.7".to_string(),
                domain: "example.com".to_string()
            }]
        );
        // Честный код ответа виден пользователю (404 ≠ открытая страница).
        assert!(s.summary.contains("203.0.113.7"), "{}", s.summary);
        assert!(s.summary.contains("404"), "{}", s.summary);
        // И никакого «добавить в обход» рядом.
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "{:?}",
            s.actions
        );
    }

    /// «IP не отвечает», живого адреса никто не дал — решения нет, причина
    /// называет вердикт и причину, а не выдуманное действие.
    #[test]
    fn ip_unreachable_without_doh_sub_is_honest_none() {
        let mut c = empty_classification();
        c.need_bypass = vec!["example.com".to_string()];
        let mut m = meta(probe(Verdict::IpUnreachable, Some(HttpResult::Timeout), None));
        m.main_dns_sub = vec![dns_sub(Some("198.51.100.1"), "TCP:443 отвечает — HTTPS не проверен", false)];
        let s = decide(&m, &c);
        assert!(!s.found, "{:?}", s);
        let reason = s.none_reason.unwrap();
        assert!(reason.contains("IP НЕ ОТВЕЧАЕТ"), "{:?}", reason);
    }

    /// DPI-вереск (RST) сохраняет легитимный bypass-совет для главного домена.
    #[test]
    fn ip_reset_main_host_keeps_bypass_action() {
        let mut c = empty_classification();
        c.need_bypass = vec!["example.com".to_string()];
        let m = meta(probe(Verdict::IpReset, Some(HttpResult::Rst), None));
        let s = decide(&m, &c);
        assert!(s.found, "{:?}", s);
        assert!(
            s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "DPI-блокировка — легитимный случай обхода: {:?}",
            s.actions
        );
    }

    /// DoH-подмена нашла живой IP при IpReset (DPI-вереск): hosts НЕ предлагаем,
    /// обход — приоритетное лечение (адрес правильный, его просто рвут).
    #[test]
    fn dpi_verdict_prefers_bypass_over_hosts_sub() {
        let mut c = empty_classification();
        c.need_bypass = vec!["example.com".to_string()];
        let mut m = meta(probe(Verdict::IpReset, Some(HttpResult::Rst), None));
        m.main_dns_sub = vec![dns_sub(Some("203.0.113.7"), "HTTPS через 203.0.113.7: HTTP 200", true)];
        let s = decide(&m, &c);
        assert!(
            s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "{:?}",
            s.actions
        );
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::WriteHosts { .. })),
            "при DPI-вереске hosts-совет из подмены уводит в сторону: {:?}",
            s.actions
        );
    }

    /// Hosts-решение из DoH-подмены не берёт адрес из системного DNS-канала:
    /// подменный сервис обязан быть DoH-каналом (текст/факт только от него).
    #[test]
    fn hosts_sub_requires_verified_ok() {
        let mut c = empty_classification();
        c.need_bypass = vec!["sub.vercel.app".to_string()];
        let mut m = meta(probe(Verdict::IpUnreachable, Some(HttpResult::Timeout), None));
        m.main_dns_sub = vec![dns_sub(Some("198.51.100.9"), "TCP:443 отвечает — HTTPS не проверен", false)];
        let s = decide(&m, &c);
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::WriteHosts { .. })),
            "TCP-ответ без HTTPS-пробы — не основание для hosts: {:?}",
            s.actions
        );
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

    // ---- Кейс api.messenger.yandex.net 27.10.26: домен накрыт исключениями ----

    fn excluded_meta(p: DomainProbe, entries: &[&str]) -> ReportMeta {
        let mut m = meta(p);
        m.exclude_set = entries.iter().map(|e| e.to_string()).collect();
        m
    }

    /// Домен «заблокирован сам» (нужен обход), но накрыт записью исключений
    /// (yandex.net накрывает api.messenger.yandex.net): в winws исключения
    /// проверяются раньше include-листов, так что совет «добавить в
    /// general-лист» — ложь: кнопка «Починить» отчиталась бы об успехе,
    /// а сайт остался бы сломан. Регресс на ложь итога.
    #[test]
    fn exclude_covered_domain_never_gets_bypass_action() {
        let mut c = empty_classification();
        c.need_bypass = vec!["api.messenger.yandex.net".to_string()];
        let m = excluded_meta(
            probe(Verdict::IpReset, Some(HttpResult::Rst), None),
            &["yandex.net"],
        );
        let s = decide(&m, &c);
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToBypassList { .. })),
            "покрытый исключениями домен нельзя звать в обход: {:?}",
            s.actions
        );
        assert!(!s.found, "{:?}", s);
        let reason = s.none_reason.unwrap();
        assert!(reason.contains("исключени"), "{:?}", reason);
        assert!(reason.contains("yandex.net"), "{:?}", reason);
    }

    /// Домен, уже сидящий в исключениях, не получает повторный совет
    /// «добавить в исключения» — это совет-дубликат (нулевая польза).
    #[test]
    fn already_excluded_domain_never_gets_exclude_action() {
        let mut c = empty_classification();
        c.bypass_breaks = vec![("example.com".to_string(), "err".to_string())];
        let m = excluded_meta(
            probe(Verdict::Open, Some(HttpResult::Ok(200)), Some(IpSource::SystemDns)),
            &["example.com"],
        );
        let s = decide(&m, &c);
        assert!(
            !s.actions
                .iter()
                .any(|a| matches!(a, SolutionAction::AddToExcludeList { .. })),
            "повторное «в исключения» — нулевой эффект: {:?}",
            s.actions
        );
        assert!(!s.found, "{:?}", s);
        assert!(
            s.none_reason.as_ref().unwrap().contains("уже в исключениях"),
            "{:?}",
            s.none_reason
        );
    }

    /// Исключённый домен среди нескольких кандидатов: рабочая часть решения
    /// сохраняется, исключённый — только честной оговоркой в summary.
    #[test]
    fn mixed_bypass_candidates_keep_action_and_caveat() {
        let mut c = empty_classification();
        c.need_bypass = vec!["blocked.example".to_string(), "api.messenger.yandex.net".to_string()];
        let m = excluded_meta(
            probe(Verdict::IpReset, Some(HttpResult::Rst), None),
            &["yandex.net"],
        );
        let s = decide(&m, &c);
        assert!(s.found, "{:?}", s);
        assert!(
            s.actions.iter().any(|a| matches!(a,
                SolutionAction::AddToBypassList { domains } if domains == &vec!["blocked.example".to_string()])),
            "рабочий кандидат должен остаться в решении: {:?}",
            s.actions
        );
        assert!(
            s.summary.contains("исключени") && s.summary.contains("yandex.net"),
            "оговорка обязана попасть в итог: {}",
            s.summary
        );
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

    // ---- «Починить все»: слияние пачки решений в одно ----

    fn sol(
        summary: &str,
        actions: Vec<SolutionAction>,
    ) -> SiteSolution {
        SiteSolution {
            found: true,
            actions,
            summary: summary.to_string(),
            none_reason: None,
        }
    }

    /// Действия собираются по типам в порядке приоритета decide, домены и
    /// пары (ip, домен) дедуплицируются.
    #[test]
    fn merge_dedups_and_keeps_priority_order() {
        let batch = vec![
            sol(
                "s1",
                vec![
                    SolutionAction::WriteHosts {
                        ip: "1.2.3.4".to_string(),
                        domain: "a.com".to_string(),
                    },
                    SolutionAction::AddToBypassList {
                        domains: vec!["b.com".to_string()],
                    },
                ],
            ),
            sol(
                "s2",
                vec![
                    SolutionAction::AddToExcludeList {
                        domains: vec!["c.com".to_string(), "b.com".to_string()],
                    },
                    SolutionAction::AddToBypassList {
                        domains: vec!["b.com".to_string(), "d.com".to_string()],
                    },
                    SolutionAction::WriteHosts {
                        ip: "1.2.3.4".to_string(),
                        domain: "a.com".to_string(),
                    },
                    SolutionAction::WriteHosts {
                        ip: "5.6.7.8".to_string(),
                        domain: "a.com".to_string(),
                    },
                ],
            ),
        ];
        let m = merge_solutions(&batch);
        assert!(m.found);
        // b.com был и в исключениях, и в обходе: остаётся ТОЛЬКО в исключениях —
        // в winws они проверяются раньше include-листов, обходная запись
        // для исключённого домена не действует.
        assert_eq!(
            m.actions,
            vec![
                SolutionAction::AddToExcludeList {
                    domains: vec!["c.com".to_string(), "b.com".to_string()]
                },
                SolutionAction::AddToBypassList {
                    domains: vec!["d.com".to_string()]
                },
                SolutionAction::WriteHosts {
                    ip: "1.2.3.4".to_string(),
                    domain: "a.com".to_string()
                },
                SolutionAction::WriteHosts {
                    ip: "5.6.7.8".to_string(),
                    domain: "a.com".to_string()
                },
            ],
            "порядок: исключения → обход → hosts, дубликаты и противоречия убраны: {:?}",
            m.actions
        );
        assert_eq!(m.summary, "s1; s2");
    }

    /// Пустая/безрешительная пачка — честное «решения нет», не found=true
    /// с пустым списком действий.
    #[test]
    fn merge_empty_batch_is_honest_none() {
        let none = SiteSolution {
            found: false,
            actions: Vec::new(),
            summary: String::new(),
            none_reason: Some("x".to_string()),
        };
        let m = merge_solutions(&[none.clone(), none]);
        assert!(!m.found, "{:?}", m);
        assert!(m.none_reason.is_some());
    }

    /// Удаление записи для домена, получающего в той же пачке новую живую
    /// запись, отбрасывается: WriteHosts сам заменяет прежние строки.
    #[test]
    fn merge_write_hosts_beats_remove_hosts() {
        let batch = vec![
            sol(
                "s1",
                vec![SolutionAction::RemoveHosts { domain: "a.com".to_string() }],
            ),
            sol(
                "s2",
                vec![SolutionAction::WriteHosts {
                    ip: "1.2.3.4".to_string(),
                    domain: "a.com".to_string(),
                }],
            ),
        ];
        let m = merge_solutions(&batch);
        assert_eq!(
            m.actions,
            vec![SolutionAction::WriteHosts {
                ip: "1.2.3.4".to_string(),
                domain: "a.com".to_string()
            }],
            "{:?}",
            m.actions
        );
    }

    // ---- Мёртвая запись hosts (кейс 30.10.26 «прописали IP — он умер») ----

    fn pin(ip: &str, http: HttpResult) -> crate::site_probe::HostsPin {
        crate::site_probe::HostsPin {
            domain: "example.com".to_string(),
            ip: ip.to_string(),
            http,
        }
    }

    /// DNS-путь сломан (подмена), но DoH нашёл живой адрес — мёртвая запись
    /// заменяется живой, а не удаляется.
    #[test]
    fn dead_pin_with_doh_working_ip_gives_replacement() {
        let mut m = meta(probe(
            Verdict::DnsBlocked,
            Some(HttpResult::Ok(200)),
            Some(IpSource::Doh),
        ));
        m.hosts_pins = vec![pin("1.2.3.4", HttpResult::Rst)];
        let s = decide(&m, &empty_classification());
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::WriteHosts {
                ip: "5.6.7.8".to_string(),
                domain: "example.com".to_string()
            }],
            "{:?}",
            s.actions
        );
        assert!(s.summary.contains("заменить"), "{}", s.summary);
        assert!(s.summary.contains("1.2.3.4"), "{}", s.summary);
    }

    /// DNS-путь открыт — мёртвая запись только мешает: убрать, не заменять.
    #[test]
    fn dead_pin_with_open_dns_path_gives_remove() {
        let mut m = meta(probe(
            Verdict::Open,
            Some(HttpResult::Ok(200)),
            Some(IpSource::SystemDns),
        ));
        m.hosts_pins = vec![pin("1.2.3.4", HttpResult::Timeout)];
        let s = decide(&m, &empty_classification());
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::RemoveHosts { domain: "example.com".to_string() }],
            "{:?}",
            s.actions
        );
        assert!(s.summary.contains("убрать"), "{}", s.summary);
        assert!(s.summary.contains("открывается по DNS"), "{}", s.summary);
    }

    /// DNS-путь сломан, рабочего адреса нет — запись убирается, в summary
    /// честно назван вердикт DNS-пути (удаление ≠ «сайт починен»).
    #[test]
    fn dead_pin_broken_path_no_replacement_gives_remove_with_verdict() {
        let mut m = meta(probe(Verdict::IpReset, Some(HttpResult::Rst), None));
        m.hosts_pins = vec![pin("1.2.3.4", HttpResult::Rst)];
        let s = decide(&m, &empty_classification());
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::RemoveHosts { domain: "example.com".to_string() }],
            "{:?}",
            s.actions
        );
        assert!(s.summary.contains("СБРОС СОЕДИНЕНИЯ"), "{}", s.summary);
    }

    /// Живая запись hosts обычный ход решения не меняет (hosts не при чём).
    #[test]
    fn alive_pin_keeps_regular_flow() {
        let mut m = meta(probe(
            Verdict::DnsBlocked,
            Some(HttpResult::Ok(200)),
            Some(IpSource::Doh),
        ));
        m.hosts_pins = vec![pin("1.2.3.4", HttpResult::Ok(200))];
        let s = decide(&m, &empty_classification());
        assert!(s.found, "{:?}", s);
        assert_eq!(
            s.actions,
            vec![SolutionAction::WriteHosts {
                ip: "5.6.7.8".to_string(),
                domain: "example.com".to_string()
            }],
            "обычный hosts-совет по подмене DNS: {:?}",
            s.actions
        );
    }

    /// Сломанность записи: живой HTTP — единственный «не сломан» ответ.
    #[test]
    fn hosts_pin_broken_criterion() {
        use crate::site_probe::hosts_pin_is_broken;
        assert!(!hosts_pin_is_broken(&HttpResult::Ok(200)));
        assert!(hosts_pin_is_broken(&HttpResult::Rst));
        assert!(hosts_pin_is_broken(&HttpResult::Timeout));
        assert!(hosts_pin_is_broken(&HttpResult::Forbidden(403)));
        assert!(hosts_pin_is_broken(&HttpResult::BlockPage));
    }

    /// Serde-контракт нового действия: тег removeHosts.
    #[test]
    fn serde_remove_hosts_tag() {
        let s = SiteSolution {
            found: true,
            summary: "x".to_string(),
            actions: vec![SolutionAction::RemoveHosts { domain: "a.com".to_string() }],
            none_reason: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["actions"][0]["type"], "removeHosts");
        assert_eq!(v["actions"][0]["domain"], "a.com");
    }
}
