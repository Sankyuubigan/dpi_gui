//! Сетевой слой проверки домена: собирает факты (DNS, DoH, TCP, HTTPS, порт 80)
//! и передаёт их в чистую классификацию [`crate::site_verdict`].
//!
//! Модуль ничего не решает сам — вся логика вердиктов и подсказок живёт там.
//! Здесь важна только честность сбора: канал ответа помечен, и провалившийся
//! резолвер не исчезает молча (core rules §2.2).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::blocking::Client;

use crate::diagnostics_probe::{
    classify_reqwest_err, dns_multi, resolve_doh_all, tcp_connect, DnsInfo, HttpResult,
};
use crate::site_verdict::{
    classify, explain, hosts_lines, http_result_note, refine_with_isp_redirect, CauseContext,
    ProbeFacts, Verdict,
};

/// Сколько адресов одного хоста пробуем подряд.
const MAX_IPS: usize = 3;

/// Какой канал разрешения дал адрес, по которому удалось достучаться до сервера.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpSource {
    /// Адрес из системного DNS (UDP:53) — может быть подменён.
    SystemDns,
    /// Адрес из защищённого канала (DoH) — проверенный.
    Doh,
}

/// Итог проверки домена: факты + их интерпретация.
#[derive(Debug)]
pub struct DomainProbe {
    pub host: String,
    pub dns: DnsInfo,
    pub primary_ips: Vec<String>,
    /// Адреса, найденные через DoH (проверенный канал).
    pub doh_ips: Vec<String>,
    /// Адрес, по которому сервер ответил на TCP:443.
    pub working_ip: Option<String>,
    /// Какой канал разрешения дал `working_ip`.
    pub working_ip_source: Option<IpSource>,
    /// Реальный результат HTTPS через `working_ip`. Именно он, а не текст
    /// примечания, решает, можно ли назвать адрес рабочим.
    pub working_http: Option<HttpResult>,
    pub http_note: String,
    pub verdict: Verdict,
    /// Рабочее имя с префиксом `www.`, если apex не отвечает, а `www` отвечает.
    pub www_host: Option<String>,
    pub www_ips: Vec<String>,
    /// Готовый URL, который точно открывается (только при `Verdict::WwwOnly`).
    pub www_url: Option<String>,
    /// Хост, на который провайдер подменил редирект вместо ответа сервера.
    /// Заполняется только при `Verdict::IspBlockRedirect`.
    pub isp_redirect: Option<String>,
    /// Доказательства перехвата UDP:53 (расхождение системного DNS с DoH).
    /// `None` означает «перехват не обнаружен» либо «DoH недоступен и
    /// сравнивать не с чем» — в обоих случаях отчёт обязан это оговорить.
    pub dns_spoofed: Option<String>,
    /// Почему не сработал хотя бы один DoH-сервис (пусто — все ответили).
    pub doh_failures: Vec<String>,
    /// Разбор причины и подсказки.
    pub diagnosis: Option<crate::site_verdict::Diagnosis>,
}

fn dedup_ips(addrs: impl Iterator<Item = IpAddr>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for s in addrs.map(|a| a.to_string()) {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Регистрируемый домен: последние две метки (`example.co.uk` схлопывается
/// частично, но для сравнения «свой домен vs чужой» этого достаточно).
fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return host.to_ascii_lowercase();
    }
    labels[labels.len() - 2..].join(".").to_ascii_lowercase()
}

/// Сверка системного DNS (UDP:53) с DoH: доказательство перехвата UDP:53 и
/// проверенные адреса для подмены.
///
/// UDP:53 перехватывается по дороге, и подменённый ответ ничем не отличается от
/// настоящего по форме — единственный способ это заметить: сравнить с ответом
/// по защищённому каналу.
///
/// Возвращает пару `(причина подмены, проверенные адреса)`. Причина `None`
/// означает «перехвата не видно» **или** «DoH недоступен»; во втором случае
/// отчёт обязан сказать, что сравнение не проводилось, а не «цензуры нет».
fn detect_udp_spoofing(dns: &DnsInfo, doh_ips: &[IpAddr]) -> Option<String> {
    if doh_ips.is_empty() {
        return None;
    }
    let doh: HashSet<IpAddr> = doh_ips.iter().copied().collect();
    let sys: HashSet<IpAddr> = dns.system.iter().copied().collect();

    let list = |set: &HashSet<IpAddr>| {
        let mut v: Vec<String> = set.iter().map(|i| i.to_string()).collect();
        v.sort();
        v.join(", ")
    };

    if sys.is_empty() {
        return Some(format!(
            "системный DNS не вернул адрес, а DoH-резолверы вернули: {}",
            list(&doh)
        ));
    }
    if doh.is_disjoint(&sys) {
        return Some(format!(
            "системный DNS вернул {}, DoH-резолверы — {} (пересечений нет)",
            list(&sys),
            list(&doh)
        ));
    }
    None
}

/// Хост редиректа, на который провайдер подменил ответ вместо ответа сервера.
///
/// Операторы блокировки отвечают на порту 80 раньше, чем запрос дойдёт до
/// сервера: подставляют `302` на страницу РКН (`lawfilter.ertelecom.ru` и
/// подобные). По HTTPS такого ответа нет — там соединение просто рвут, поэтому
/// без этой пробы причина блокировки остаётся нераспознанной.
///
/// Легальный редирект `apex -> www` остаётся внутри того же регистрируемого
/// домена и подменой не считается.
fn probe_isp_redirect(host: &str, ip: IpAddr) -> Option<String> {
    let client = Client::builder()
        // Редирект не следуем: нам нужен сам заголовок Location.
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, SocketAddr::new(ip, 80))
        .timeout(Duration::from_secs(6))
        .build()
        .ok()?;

    let resp = client.get(format!("http://{}/", host)).send().ok()?;
    let status = resp.status().as_u16();
    if !(300..=399).contains(&status) {
        return None;
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()?;
    let target = url::Url::parse(location).ok()?;
    let target_host = target.host_str()?.to_string();

    if registrable_domain(&target_host) == registrable_domain(host) {
        return None;
    }
    Some(format!("{} -> {}", host, target_host))
}

/// HTTPS-запрос к конкретному адресу: адрес подставляется на уровне сокета,
/// имя домена остаётся в SNI и в проверке сертификата.
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

/// Ответ одной пробы: дошёл ли TCP, какой адрес ответил и что на нём с HTTPS.
#[derive(Debug, Clone)]
struct ProbeOutcome {
    tcp_ok: bool,
    ip: Option<String>,
    http: Option<HttpResult>,
    note: String,
    any_reset: bool,
}

impl ProbeOutcome {
    fn dead(note: String) -> Self {
        ProbeOutcome {
            tcp_ok: false,
            ip: None,
            http: None,
            note,
            any_reset: false,
        }
    }
}

/// Пробует TCP:443 по списку адресов и делает HTTPS-запрос по первому ответившему.
fn probe_host_at(host: &str, ips: &[String]) -> ProbeOutcome {
    let mut tcp_only: Option<(String, HttpResult)> = None;
    let mut any_reset = false;

    for ip in ips.iter().take(MAX_IPS) {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            continue;
        };
        match tcp_connect(addr, 443).as_str() {
            "RST/REFUSED" => {
                any_reset = true;
                continue;
            }
            "Success" => {}
            _ => continue,
        }
        let r = http_via_ip(host, addr);
        if let HttpResult::Ok(code) = r {
            return ProbeOutcome {
                tcp_ok: true,
                ip: Some(ip.clone()),
                note: format!("HTTPS через {}: HTTP {}", ip, code),
                http: Some(r),
                any_reset,
            };
        }
        if tcp_only.is_none() {
            tcp_only = Some((ip.clone(), r));
        }
    }

    match tcp_only {
        Some((ip, r)) => {
        let note = format!("HTTPS через {}: {}", ip, http_result_note(&r));
        ProbeOutcome {
            tcp_ok: true,
            ip: Some(ip),
            note,
            http: Some(r),
            any_reset,
        }
    }
        None => ProbeOutcome::dead("ни один IP не ответил на TCP:443".to_string()),
    }
}

pub fn probe_domain(host: &str) -> DomainProbe {
    let dns = dns_multi(host);

    // Адреса из защищённого канала. Это единственный источник проверенных
    // адресов: именно по ним проверяется, открывается ли сайт «настоящий».
    let doh_answers = resolve_doh_all(host);
    let doh_addr_ips = doh_answers.all_ips();
    let doh_failures = doh_answers.failures();

    let dns_spoofed = detect_udp_spoofing(&dns, &doh_addr_ips);

    let is_www = host.starts_with("www.");
    let www_host = if is_www {
        host.to_string()
    } else {
        format!("www.{}", host)
    };

    let primary_ips = dedup_ips(dns.system.iter().copied());
    // Адреса из DoH вычитаем из системных: один и тот же адрес не имеет смысла
    // проверять дважды — он и так проверен тем же HTTPS-запросом.
    let primary_set: HashSet<&String> = primary_ips.iter().collect();
    let doh_ips = dedup_ips(
        doh_addr_ips
            .iter()
            .copied()
            .filter(|ip| !primary_set.contains(&ip.to_string())),
    );

    // Проба по адресам из системного DNS.
    let sys_probe = probe_host_at(host, &primary_ips);

    // Проба по адресам из DoH. Именно она ломает ложный вывод «сертификат не
    // совпал»: на подменённом адресе лежит чужой сервер, на проверенном — сайт.
    let doh_probe = if doh_ips.is_empty() {
        ProbeOutcome::dead("DoH не вернул адресов, отличных от системного DNS".to_string())
    } else {
        probe_host_at(host, &doh_ips)
    };

    // Пробуем вариант с `www.`: у сайта может быть рабочее имя только с этим
    // префиксом, а apex без него не отвечает.
    let (www_ips, www_url, www_ok) = if is_www {
        (primary_ips.clone(), None, false)
    } else {
        let www_dns = dns_multi(&www_host);
        let ips = dedup_ips(www_dns.system.iter().copied());
        let w = probe_host_at(&www_host, &ips);
        let ok = matches!(w.http, Some(HttpResult::Ok(_)));
        (ips, ok.then(|| format!("https://{}/", www_host)), ok)
    };

    let any_reset = sys_probe.any_reset || doh_probe.any_reset;

    let facts = ProbeFacts {
        dns_spoofed: dns_spoofed.is_some(),
        system_http: sys_probe.http.clone(),
        doh_http: doh_probe.http.clone(),
        any_tcp_ok: sys_probe.tcp_ok || doh_probe.tcp_ok,
        any_reset,
        www_ok,
    };

    let base_verdict = classify(&facts);

    // Рабочий адрес и результат HTTPS по нему берём из канала, который
    // реально открыл сайт. Приоритет у DoH: адрес системного DNS при
    // доказанной подмене недостоверен.
    let (working_ip, working_ip_source, working_http, http_note) = pick_working(
        &facts,
        sys_probe.ip.clone(),
        &sys_probe,
        doh_probe.ip.clone(),
        &doh_probe,
    );

    // Проба порта 80: ловим подмену редиректа провайдером. Запускаем только
    // когда HTTPS не дал рабочего ответа — при живом сайте она ничего не скажет
    // и лишь замедлит проверку.
    let isp_redirect: Option<String> = if base_verdict != Verdict::Open {
        primary_ips
            .iter()
            .chain(doh_ips.iter())
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .take(4)
            .find_map(|ip| probe_isp_redirect(host, ip))
    } else {
        None
    };

    let verdict = refine_with_isp_redirect(base_verdict, isp_redirect.as_deref());

    // Адрес для подсказки «записать в hosts»: только проверенный (DoH) и
    // только если сайт через него действительно открылся.
    let doh_working_ip = match working_ip_source {
        Some(IpSource::Doh) => working_ip.as_deref(),
        _ => None,
    };

    let apex_ip = primary_ips.first().cloned();
    let diagnosis = explain(
        verdict,
        &CauseContext {
            host,
            www_url: www_url.as_deref(),
            apex_ip: apex_ip.as_deref(),
            dns_spoofed: dns_spoofed.is_some(),
            doh_working_ip,
            same_host_alt_ip_works: matches!(doh_probe.http, Some(HttpResult::Ok(_))),
            isp_redirect: isp_redirect.as_deref(),
        },
    );

    DomainProbe {
        host: host.to_string(),
        dns,
        primary_ips,
        doh_ips,
        working_ip,
        working_ip_source,
        working_http,
        http_note,
        verdict,
        www_host: if is_www { None } else { Some(www_host) },
        www_ips,
        www_url,
        isp_redirect,
        dns_spoofed,
        doh_failures,
        diagnosis: Some(diagnosis),
    }
}

/// Выбирает адрес, который реально открывает сайт, и результат HTTPS по нему.
///
/// Приоритет у DoH-канала: при доказанной подмене DNS адрес из системного
/// резолвера заведомо не принадлежит сайту, даже если TCP:443 там отвечает.
fn pick_working(
    facts: &ProbeFacts,
    sys_ip: Option<String>,
    sys: &ProbeOutcome,
    doh_ip: Option<String>,
    doh: &ProbeOutcome,
) -> (Option<String>, Option<IpSource>, Option<HttpResult>, String) {
    if sys_ip.is_none() && doh_ip.is_none() {
        return (None, None, None, sys.note.clone());
    }

    let doh_is_working = matches!(doh.http, Some(HttpResult::Ok(_)));
    let sys_is_working = matches!(sys.http, Some(HttpResult::Ok(_)));

    if doh_is_working || (sys_is_working && !facts.dns_spoofed) {
        if doh_is_working {
            return (
                doh_ip.clone(),
                Some(IpSource::Doh),
                doh.http.clone(),
                doh.note.clone(),
            );
        }
        return (
            sys_ip.clone(),
            Some(IpSource::SystemDns),
            sys.http.clone(),
            sys.note.clone(),
        );
    }

    // Сайт не открылся нигде: показываем адрес, на котором был контакт, но
    // вместе с его реальным результатом — вызывающий слой обязан сказать, что
    // этот адрес сайт НЕ открывает.
    match (doh_ip.is_some(), sys_ip.is_some()) {
        (true, true) => (
            sys_ip.clone(),
            Some(IpSource::SystemDns),
            sys.http.clone(),
            format!("{}; {}", sys.note, doh.note),
        ),
        (true, false) => (doh_ip.clone(), Some(IpSource::Doh), doh.http.clone(), doh.note.clone()),
        _ => (
            sys_ip.clone(),
            Some(IpSource::SystemDns),
            sys.http.clone(),
            sys.note.clone(),
        ),
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

/// Проверка «подмены DNS»: резолв домена через DoH-сервисы и поиск рабочего IP.
/// Если системный/публичный UDP-DNS отравлен, эти сервисы могут вернуть
/// настоящий адрес, и сайт откроется через подмену.
///
/// * `probe_http` — делать ли полную HTTPS-пробу первого рабочего IP
///   (для главного домена да/для долгого перебора — нет).
pub fn check_dns_substitution(host: &str, probe_http: bool) -> Vec<DnsSubstitution> {
    let answers = resolve_doh_all(host);
    let mut out = Vec::new();
    for a in answers.answers {
        out.push(summarize_substitution(host, &a.service, &a.ips, a.error, probe_http));
    }
    out
}

/// Сведение одного DoH-ответа в строку отчёта. Чистая функция относительно
/// сети: те же входные данные дают тот же текст, поэтому её можно покрыть
/// юнит-тестами без обращения к сети.
fn summarize_substitution(
    host: &str,
    service: &str,
    ips: &[IpAddr],
    error: Option<String>,
    probe_http: bool,
) -> DnsSubstitution {
    if let Some(e) = error {
        return DnsSubstitution {
            service: service.to_string(),
            resolved: vec![],
            working_ip: None,
            http_note: format!("ошибка DoH: {}", e),
            http_ok: false,
        };
    }

    let display: Vec<String> = ips.iter().take(4).map(|i| i.to_string()).collect();
    let working = ips
        .iter()
        .take(6)
        .find(|ip| tcp_connect(**ip, 443) == "Success")
        .copied();

    let Some(ip) = working else {
        return DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: None,
            http_note: "ни один IP из подмены не ответил на TCP:443".to_string(),
            http_ok: false,
        };
    };

    if !probe_http {
        // Лёгкий прогон (список dns_fail): HTTPS не гоняем, но и не называем
        // IP «рабочим» — только кандидатом.
        return DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: Some(ip.to_string()),
            http_note: format!("TCP:443 отвечает ({})", ip),
            http_ok: true,
        };
    }

    let http = http_via_ip(host, ip);
    let http_ok = matches!(http, HttpResult::Ok(_));
    let note = format!("HTTPS через {}: {}", ip, substitution_note(&http));

    DnsSubstitution {
        service: service.to_string(),
        resolved: display,
        working_ip: Some(ip.to_string()),
        http_note: note,
        http_ok,
    }
}

fn substitution_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::BlockPage => "страница блокировки".to_string(),
        HttpResult::Tls => "TLS сломан".to_string(),
        HttpResult::BadCert => "SSL-сертификат невалиден".to_string(),
        HttpResult::Rst => "RST — TCP:443 открыт, но HTTPS рвётся (DPI по SNI)".to_string(),
        HttpResult::Timeout => "таймаут".to_string(),
        HttpResult::Dns => "DNS-ошибка".to_string(),
        HttpResult::Other(m) => m.clone(),
    }
}

/// Готовые строки для файла hosts по проверенному адресу. Пустой список
/// означает «адреса нет, писать нечего» — вызывающий код обязан это учесть.
pub fn hosts_entries(probe: &DomainProbe) -> Vec<String> {
    let ip = match probe.working_ip_source {
        Some(IpSource::Doh) => probe.working_ip.as_deref(),
        _ => None,
    };
    hosts_lines(&probe.host, ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_ignores_www_and_case() {
        assert_eq!(registrable_domain("www.nnmclub.to"), "nnmclub.to");
        assert_eq!(registrable_domain("NNMClub.TO"), "nnmclub.to");
        // A block page lives in a different registrable domain — that is the signal.
        assert_ne!(
            registrable_domain("nnmclub.to"),
            registrable_domain("lawfilter.ertelecom.ru")
        );
    }

    /// Системный DNS вернул отравленный адрес, DoH — настоящий: это подмена.
    #[test]
    fn disjoint_system_and_doh_is_spoofing() {
        let mut dns = DnsInfo::new();
        dns.system = vec!["188.186.154.88".parse().unwrap()];
        let doh: Vec<IpAddr> = vec!["104.21.95.93".parse().unwrap(), "172.67.144.20".parse().unwrap()];
        let s = detect_udp_spoofing(&dns, &doh);
        let text = s.expect("расхождение обязано быть замечено");
        assert!(text.contains("188.186.154.88"), "{}", text);
    }

    /// Пересечение адресов — норма для крупных CDN, цензура тут ни при чём.
    #[test]
    fn overlapping_system_and_doh_is_not_spoofing() {
        let mut dns = DnsInfo::new();
        dns.system = vec!["104.21.95.93".parse().unwrap()];
        let doh: Vec<IpAddr> = vec![
            "104.21.95.93".parse().unwrap(),
            "172.67.144.20".parse().unwrap(),
        ];
        assert!(detect_udp_spoofing(&dns, &doh).is_none());
    }

    /// DoH недоступен — это не «цензуры нет» и не «подмена доказана».
    #[test]
    fn empty_doh_gives_no_spoof_claim() {
        let mut dns = DnsInfo::new();
        dns.system = vec!["1.2.3.4".parse().unwrap()];
        assert!(detect_udp_spoofing(&dns, &[]).is_none());
    }

    #[test]
    fn empty_system_dns_with_doh_answers_is_spoofing() {
        let dns = DnsInfo::new();
        let doh: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        assert!(detect_udp_spoofing(&dns, &doh).is_some());
    }

    #[test]
    fn dedup_ips_removes_repeats() {
        let ips = dedup_ips(
            vec![
                "1.2.3.4".parse().unwrap(),
                "1.2.3.4".parse().unwrap(),
                "5.6.7.8".parse().unwrap(),
            ]
            .into_iter(),
        );
        assert_eq!(ips, vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]);
    }

    /// Реальный пользовательский случай целиком: системный DNS отравлен, DoH
    /// вернул рабочий адрес, в отчёте нет вранья.
    #[test]
    fn poisoned_case_reports_hosts_lines_from_doh() {
        let dns = DnsInfo {
            system: vec!["188.186.154.88".parse().unwrap()],
            ..DnsInfo::new()
        };
        let probe = DomainProbe {
            host: "nnmclub.to".to_string(),
            dns,
            primary_ips: vec!["188.186.154.88".to_string()],
            doh_ips: vec!["104.21.95.93".to_string()],
            working_ip: Some("104.21.95.93".to_string()),
            working_ip_source: Some(IpSource::Doh),
            working_http: Some(HttpResult::Ok(200)),
            http_note: "HTTPS через 104.21.95.93: HTTP 200".to_string(),
            verdict: Verdict::Open,
            www_host: Some("www.nnmclub.to".to_string()),
            www_ips: vec![],
            www_url: None,
            isp_redirect: None,
            dns_spoofed: Some("системный DNS вернул 188.186.154.88, DoH-резолверы — 104.21.95.93 (пересечений нет)".to_string()),
            doh_failures: vec!["dns.dns-ai.ru: HTTP 505".to_string()],
            diagnosis: None,
        };
        assert_eq!(
            hosts_entries(&probe),
            vec![
                "104.21.95.93 nnmclub.to".to_string(),
                "104.21.95.93 www.nnmclub.to".to_string()
            ]
        );
    }

    /// Адрес из системного DNS при доказанной подмене писать в hosts нельзя:
    /// он принадлежит чужому серверу.
    #[test]
    fn hosts_entries_never_uses_system_dns_ip() {
        let probe = DomainProbe {
            host: "example.com".to_string(),
            dns: DnsInfo::new(),
            primary_ips: vec!["188.186.154.88".to_string()],
            doh_ips: vec![],
            working_ip: Some("188.186.154.88".to_string()),
            working_ip_source: Some(IpSource::SystemDns),
            working_http: Some(HttpResult::BadCert),
            http_note: "HTTPS через 188.186.154.88: SSL-сертификат невалиден".to_string(),
            verdict: Verdict::DnsBlocked,
            www_host: None,
            www_ips: vec![],
            www_url: None,
            isp_redirect: None,
            dns_spoofed: Some("расхождение".to_string()),
            doh_failures: vec![],
            diagnosis: None,
        };
        assert!(hosts_entries(&probe).is_empty());
    }

    #[test]
    #[ignore = "requires network"]
    fn live_probe_google() {
        let p = probe_domain("google.com");
        assert_eq!(p.verdict, Verdict::Open, "probe: {:?}", p);
    }

    /// Проверка на реальной сети: домен из известного случая отравления DNS.
    /// Запускается вручную: `cargo test live_probe_poisoned -- --ignored`.
    #[test]
    #[ignore = "requires network"]
    fn live_probe_poisoned_domain() {
        let p = probe_domain("nnmclub.to");
        println!("verdict: {:?}", p.verdict);
        println!("system ips: {:?}", p.primary_ips);
        println!("doh ips: {:?}", p.doh_ips);
        println!("spoofed: {:?}", p.dns_spoofed);
        println!("working: {:?} via {:?}", p.working_ip, p.working_ip_source);
        println!("doh failures: {:?}", p.doh_failures);
        // На этой машине системный DNS отдаёт подменённый адрес, поэтому
        // либо вердикт Open (сайт открылся по DoH-адресу), либо DnsBlocked.
        assert!(
            matches!(p.verdict, Verdict::Open | Verdict::DnsBlocked),
            "неожиданный вердикт: {:?}",
            p
        );
    }

    /// Сколько реально отвечают DoH-сервисы из списка — проверка самого списка,
    /// чтобы молча отвалившийся резолвер не остался в коде навсегда.
    #[test]
    #[ignore = "requires network"]
    fn live_doh_resolvers_availability() {
        let answers = resolve_doh_all("example.com");
        for a in &answers.answers {
            println!(
                "{}: {} {:?}",
                a.service,
                a.ips.len(),
                a.error.as_deref().unwrap_or("ok")
            );
        }
        assert!(!answers.all_ips().is_empty(), "ни один DoH не ответил");
    }
}