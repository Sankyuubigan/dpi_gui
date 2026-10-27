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
    body_looks_like_blockpage, body_looks_region_restricted, classify_reqwest_err, dns_multi,
    is_stub_ip, resolve_doh_all, tcp_connect, DnsInfo, DohAnswers, HttpResult,
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
    /// Адреса, найденные через DoH (проверенный канал). Адреса-прокси-шлюзы
    /// самих DoH-сервисов сюда НЕ попадают — они в `doh_gateway_ips`.
    pub doh_ips: Vec<String>,
    /// Собственные адреса DoH-сервисов, отданные в ответе вместо адреса сайта.
    /// Не участвуют ни в пробах, ни в вердикте, ни в hosts-советах: проба через
    /// такой SNI-прокси может дать HTTP 200, а браузер пользователя по нему
    /// сайт не откроет (кейс openrouter.ai / dns.comss.one).
    pub doh_gateway_ips: Vec<(String, String)>,
    /// Карта «адрес из `doh_ips` → сервисы DoH, которые его вернули».
    /// Пусто при пустом `doh_ips`. Нужна отчёту: адрес, который отдал
    /// только один сервис и которого нет у системного DNS, — кандидат
    /// «прокси-шлюз» этого сервиса, а не адрес самого сайта.
    pub doh_ip_services: Vec<(String, Vec<String>)>,
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

/// Разделяет адреса DoH на «адреса сайта» и «адреса-прокси-шлюзы сервисов».
///
/// Шлюз — адрес из ответа DoH, совпавший с собственной A-записью какого-то
/// DoH-сервиса: проба через такой SNI-прокси может вернуть HTTP 200, а браузер
/// пользователя по нему сайт не откроет (кейс openrouter.ai: 80.74.30.162 —
/// инфраструктура dns.comss.one). Чистая функция — покрыта юнит-тестами.
fn split_doh_ips(
    doh_addr_ips: &[IpAddr],
    primary_ips: &[String],
    gateway_owner: &dyn Fn(&IpAddr) -> Option<String>,
) -> (Vec<String>, Vec<(String, String)>) {
    let primary_set: HashSet<&String> = primary_ips.iter().collect();
    let mut site_ips: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut gateways: Vec<(String, String)> = Vec::new();
    let mut gw_seen: HashSet<String> = HashSet::new();

    for ip in doh_addr_ips {
        let s = ip.to_string();
        if let Some(owner) = gateway_owner(ip) {
            if primary_set.contains(&s) {
                // Шлюз совпал с системным адресом — отдельной строкой не дублируем.
                continue;
            }
            if gw_seen.insert(s.clone()) {
                gateways.push((s, owner));
            }
            continue;
        }
        if seen.insert(s.clone()) {
            site_ips.push(s);
        }
    }
    (site_ips, gateways)
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

/// Параллельная проба ISP-редиректа по всем кандидатам сразу (последовательный
/// перебор мёртвых адресов тянул до 6 с на каждый). Выбирается первый по
/// порядку адресов найденный редирект — как у прежнего `find_map`.
fn isp_redirect_parallel(host: &str, primary: &[String], doh: &[String]) -> Option<String> {
    use std::sync::mpsc;
    let ips: Vec<IpAddr> = primary
        .iter()
        .chain(doh.iter())
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .filter(|i| !is_stub_ip(i))
        .take(4)
        .collect();
    let (tx, rx) = mpsc::channel::<(usize, Option<String>)>();
    for (idx, ip) in ips.iter().enumerate() {
        let tx = tx.clone();
        let host = host.to_string();
        let ip = *ip;
        std::thread::spawn(move || {
            let _ = tx.send((idx, probe_isp_redirect(&host, ip)));
        });
    }
    drop(tx);
    let mut slots: Vec<Option<Option<String>>> = (0..ips.len()).map(|_| None).collect();
    for _ in 0..ips.len() {
        if let Ok((idx, r)) = rx.recv() {
            slots[idx] = Some(r);
        }
    }
    slots.into_iter().flatten().flatten().next()
}

/// Фолбэк-проба обычного HTTP (порт 80) по проверенным DoH-адресам: жив ли
/// транспорт до настоящего адреса, когда HTTPS/TLS из приложения не открыл
/// сайт. Достаточно самого факта осмысленного HTTP-ответа (1xx–4xx):
/// редиректы ищет отдельно [`probe_isp_redirect`], здесь это не дублируется.
/// Любой 5xx считаем «ответили, но ошибка» — подсказку «транспорт жив» такое
/// не даёт (заглушки ТСПУ тоже умеют отвечать 503).
fn probe_alive_over_http80(host: &str, ips: &[String]) -> bool {
    use std::sync::mpsc;
    // Пробы параллельны: важен только факт «транспорт жив», а не порядок —
    // последовательный скан мёртвых адресов тянул до 5 с на каждый.
    // rx.recv() не зависает: каждый HTTP-клиент ограничен своим таймаутом 5 с.
    let (tx, rx) = mpsc::channel::<bool>();
    let mut spawned = 0usize;
    for ip in ips.iter().filter_map(|s| s.parse::<IpAddr>().ok()) {
        if is_stub_ip(&ip) {
            continue;
        }
        let tx = tx.clone();
        let host = host.to_string();
        std::thread::spawn(move || {
            let alive = (|| {
                let Ok(client) = Client::builder()
                    .resolve(&host, SocketAddr::new(ip, 80))
                    .timeout(Duration::from_secs(5))
                    .build()
                else {
                    return false;
                };
                match client.get(format!("http://{}/", host)).send() {
                    Ok(resp) => (100..=499).contains(&resp.status().as_u16()),
                    Err(_) => false,
                }
            })();
            let _ = tx.send(alive);
        });
        spawned += 1;
    }
    drop(tx);
    for _ in 0..spawned {
        match rx.recv() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => break,
        }
    }
    false
}

/// HTTPS-запрос к конкретному адресу: адрес подставляется на уровне сокета,
/// имя домена остаётся в SNI и в проверке сертификата. Публично и с явным
/// портом: используется также IP-режимом анализа (ip_probe SNI-эксперимент) —
/// дубль reqwest-клиента для него запрещён (SSOT).
pub fn http_via_ip(host: &str, ip: IpAddr, port: u16) -> HttpResult {
    let url = if port == 443 {
        format!("https://{}/", host)
    } else {
        format!("https://{}:{}/", host, port)
    };
    let client = match Client::builder()
        .resolve(host, SocketAddr::new(ip, port))
        .timeout(Duration::from_secs(6))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResult::Other(format!("не удалось создать клиент: {}", e)),
    };
    match client.get(&url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Голый 403/451 — отказ самого сервера (часто гео-блок),
            // страница блокировки — только при маркерах подмены в теле.
            if status == 403 || status == 451 {
                return HttpResult::Forbidden(status);
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if body_looks_like_blockpage(&low) {
                    HttpResult::BlockPage
                } else if body_looks_region_restricted(&low) {
                    // Живой HTTP-ответ, но сам сервис сообщает об ограничении
                    // (регион источника). Сеть в порядке — вердикт «открыт»
                    // тут был бы ложью (кейс AI-студий).
                    HttpResult::ServiceRestrict
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

/// Пробует TCP:443 по списку адресов и делает HTTPS-запрос по каждому
/// ответившему — до первого открывшего сайт. Адреса-заглушки (0.0.0.0 и т.п.)
/// пропускаются до счётчика `MAX_IPS`: пробовать их — ложь в отчёте.
fn probe_host_at(host: &str, ips: &[String]) -> ProbeOutcome {
    let mut tcp_only: Option<(String, HttpResult)> = None;
    let mut any_reset = false;

    // Кандидаты: валидные адреса без заглушек, лимит MAX_IPS.
    let candidates: Vec<IpAddr> = ips
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .filter(|a| !is_stub_ip(a))
        .take(MAX_IPS)
        .collect();

    // TCP-пробы параллельно: последовательный скан мёртвых адресов съедал
    // до 3.5 с на каждый (worst ~10 с на канал). HTTP-пробы — по-прежнему
    // последовательно до первого Ok: порядок «первого рабочего IP» сохранён.
    let tcp = tcp_scan_parallel(&candidates);
    for (ip, res) in candidates.iter().zip(tcp.iter()) {
        match res.as_str() {
            "RST/REFUSED" => {
                any_reset = true;
            }
            "Success" => {
                let r = http_via_ip(host, *ip, 443);
                if let HttpResult::Ok(code) = r {
                    return ProbeOutcome {
                        tcp_ok: true,
                        ip: Some(ip.to_string()),
                        note: format!("HTTPS через {}: HTTP {}", ip, code),
                        http: Some(r),
                        any_reset,
                    };
                }
                if tcp_only.is_none() {
                    tcp_only = Some((ip.to_string(), r));
                }
            }
            _ => {}
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

/// Параллельный TCP-скан: результат в том же порядке, что и входные адреса.
/// Каждый поток гарантированно завершается (`tcp_connect` ограничен таймаутом),
/// поэтому `rx.recv()` не может зависнуть.
pub fn tcp_scan_parallel(ips: &[IpAddr]) -> Vec<String> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<(usize, String)>();
    for (idx, ip) in ips.iter().enumerate() {
        let tx = tx.clone();
        let ip = *ip;
        std::thread::spawn(move || {
            let _ = tx.send((idx, tcp_connect(ip, 443)));
        });
    }
    drop(tx);
    let mut slots: Vec<Option<String>> = (0..ips.len()).map(|_| None).collect();
    for _ in 0..ips.len() {
        if let Ok((idx, res)) = rx.recv() {
            slots[idx] = Some(res);
        }
    }
    slots
        .into_iter()
        .map(|s| s.unwrap_or_else(|| "Timeout".to_string()))
        .collect()
}

/// Обёртка для интеграционных тестов: одна DoH-загрузка + проба. В проде не
/// используется — `analyzer.rs` зовёт `resolve_doh_answers` + `probe_domain_with_doh`
/// ради SSOT одной загрузки, поэтому функция живёт только под cfg(test)
/// (иначе — dead_code warning в release-сборке).
#[cfg(test)]
pub fn probe_domain(host: &str) -> DomainProbe {
    let doh_answers = resolve_doh_all(host);
    probe_domain_with_doh(host, &doh_answers)
}

/// Единая точка загрузки DoH-ответов для анализа (дверь модуля): одна
/// загрузка расходуется и на пробу домена, и на «подмену DNS».
pub fn resolve_doh_answers(host: &str) -> DohAnswers {
    resolve_doh_all(host)
}

/// Вариант [`probe_domain`] с уже загруженными DoH-ответами: одна загрузка
/// на анализ расходуется и на пробу домена, и на «подмену DNS» (SSOT,
/// минус лишний DoH-проход с его 9-секундным дедлайном).
pub fn probe_domain_with_doh(host: &str, doh_answers: &DohAnswers) -> DomainProbe {
    let dns = dns_multi(host);

    // Адреса из защищённого канала. Это единственный источник проверенных
    // адресов: именно по ним проверяется, открывается ли сайт «настоящий».
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
    let (doh_ips, doh_gateway_ips) = split_doh_ips(
        &doh_addr_ips,
        &primary_ips,
        &|ip| doh_answers.gateway_owner(ip),
    );
    // Карта «адрес → сервисы» — строится из фактических ответов сервисов
    // (без повторных запросов), для честной адресной таблицы отчёта.
    let doh_ip_services = doh_answers.services_map(&doh_ips);

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

    // DoH вернул только те же адреса, что системный DNS: проверять отдельно
    // нечего, а системный адрес тем самым проверен защищённым каналом.
    // Без этого флага одинаковый 403 с единственного адреса было бы не с чем
    // сравнить — и гео-блок снова выдавался бы за «страницу провайдера».
    let doh_agrees = !doh_addr_ips.is_empty() && doh_ips.is_empty();

    let facts = ProbeFacts {
        dns_spoofed: dns_spoofed.is_some(),
        system_http: sys_probe.http.clone(),
        doh_http: doh_probe.http.clone(),
        doh_agrees,
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
    // и лишь замедлит проверку. Пробы параллельны, выбирается первый по
    // порядку адресов редирект (семантика прежнего find_map сохранена).
    let isp_redirect: Option<String> = if base_verdict != Verdict::Open {
        isp_redirect_parallel(host, &primary_ips, &doh_ips)
    } else {
        None
    };

    let verdict = refine_with_isp_redirect(base_verdict, isp_redirect.as_deref());

    // Фолбэк HTTP:80 (кейс turboimagehost: подмена доказана, но HTTPS по
    // DoH-адресам из приложения не прошёл): проверяем по порту 80 те же
    // DoH-адреса. Осмысленный ответ — доказательство «транспорт до
    // настоящего адреса жив, режется TLS/SNI»; вердикт это не меняет
    // (остаётся DnsBlocked), но текст честно называет лечение через обход.
    let doh_opened = matches!(doh_probe.http, Some(HttpResult::Ok(_)));
    let doh_http80_hint =
        dns_spoofed.is_some() && !doh_opened && probe_alive_over_http80(host, &doh_ips);

    // DoH-адреса, которые нельзя спрятать (core §2.2), если приложение их
    // HTTPS-пробой не подтвердило: уходят в отчёт как КАНДИДАТЫ с причиной.
    let doh_candidates: Vec<String> = if doh_opened { Vec::new() } else { doh_ips.clone() };
    let probe_fail_note: Option<String> = if doh_opened {
        None
    } else {
        match &doh_probe.http {
            Some(r) => Some(http_result_note(r)),
            // TCP до DoH-адресов не дошёл: причина — исход из сетевых проб.
            None => (!doh_probe.note.is_empty()).then(|| doh_probe.note.clone()),
        }
    };

    // Адрес для подсказки «записать в hosts»: только проверенный (DoH) и
    // только если сайт через него действительно открылся (HTTP Ok).
    // Без проверки Ok сюда попадал адрес с отказом/RST — и отчёт советовал
    // hosts, по которому сайт не открывается.
    let doh_working_ip = match (working_ip_source, &working_http) {
        (Some(IpSource::Doh), Some(HttpResult::Ok(_))) => working_ip.as_deref(),
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
            doh_http80_hint,
            doh_candidates,
            probe_fail_note,
        },
    );

    DomainProbe {
        host: host.to_string(),
        dns,
        primary_ips,
        doh_ips,
        doh_gateway_ips,
        doh_ip_services,
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
    http_via_ip(host, ip, 443)
}

/// Проверка «подмены DNS»: резолв домена через DoH-сервисы и поиск рабочего IP.
/// Если системный/публичный UDP-DNS отравлен, эти сервисы могут вернуть
/// настоящий адрес, и сайт откроется через подмену.
///
/// * `probe_http` — делать ли полную HTTPS-пробу первого рабочего IP
///   (для главного домена да/для долгого перебора — нет).
pub fn check_dns_substitution(host: &str, probe_http: bool) -> Vec<DnsSubstitution> {
    let answers = resolve_doh_all(host);
    dns_substitutions_from(host, &answers, probe_http)
}

/// Разбор «подмены DNS» от уже загруженных DoH-ответов: чистая функция без
/// сети. Переиспользуется с пробой главного домена (одна загрузка на анализ).
pub fn dns_substitutions_from(
    host: &str,
    answers: &DohAnswers,
    probe_http: bool,
) -> Vec<DnsSubstitution> {
    let mut out = Vec::new();
    for a in &answers.answers {
        // Собственный адрес сервиса (SNI-прокси) — не решение: проба через него
        // может дать 200, а сайт в браузере по нему не откроется.
        let only_gateway = !a.ips.is_empty()
            && a.ips.iter().all(|ip| answers.gateway_owner(ip).is_some());
        if only_gateway {
            out.push(DnsSubstitution {
                service: a.service.clone(),
                resolved: vec![],
                working_ip: None,
                http_note: format!(
                    "сервис отдал собственный адрес-шлюз ({}) — это не адрес сайта",
                    a.ips
                        .iter()
                        .take(3)
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                http_ok: false,
            });
            continue;
        }
        let real_ips: Vec<IpAddr> = a
            .ips
            .iter()
            .copied()
            .filter(|ip| answers.gateway_owner(ip).is_none())
            .collect();
        out.push(summarize_substitution(host, &a.service, &real_ips, a.error.clone(), probe_http));
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

    let display: Vec<String> = ips
        .iter()
        .filter(|ip| !is_stub_ip(ip))
        .take(4)
        .map(|i| i.to_string())
        .collect();
    // TCP-живые адреса (без заглушек): HTTPS пробуем по КАЖДОМУ до первого
    // открывшего сайт. Раньше проверялся только первый TCP-ответивший —
    // и если им оказывалась заглушка/битый IP, отчёт врал «не помогла»,
    // хотя следующий адрес сайт открывал (кейс openrouter.ai).
    // TCP-скан параллельный, порядок живых адресов — исходный.
    let candidates: Vec<IpAddr> = ips
        .iter()
        .filter(|ip| !is_stub_ip(ip))
        .take(6)
        .copied()
        .collect();
    let tcp = tcp_scan_parallel(&candidates);
    let mut live: Vec<IpAddr> = Vec::new();
    for (ip, res) in candidates.iter().zip(tcp.iter()) {
        if res == "Success" {
            live.push(*ip);
        }
    }

    let Some(first) = live.first().copied() else {
        return DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: None,
            http_note: "ни один IP из подмены не ответил на TCP:443".to_string(),
            http_ok: false,
        };
    };

    if !probe_http {
        // Лёгкий прогон (список dns_fail): HTTPS не гоняем, поэтому честно
        // помечаем как непроверенный — http_ok=true тут была ложью
        // (core rules §2.2): TCP:443 отвечает и у заглушек цензора.
        return DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: Some(first.to_string()),
            http_note: format!("TCP:443 отвечает ({}) — HTTPS не проверен", first),
            http_ok: false,
        };
    }

    let mut last_note = String::new();
    for (n, ip) in live.iter().copied().enumerate() {
        let http = http_via_ip(host, ip, 443);
        if matches!(http, HttpResult::Ok(_)) {
            let mut note = format!("HTTPS через {}: {}", ip, substitution_note(&http));
            if n > 0 {
                note.push_str(&format!(" (перебрано адресов: {})", n + 1));
            }
            return DnsSubstitution {
                service: service.to_string(),
                resolved: display,
                working_ip: Some(ip.to_string()),
                http_note: note,
                http_ok: true,
            };
        }
        last_note = format!("HTTPS через {}: {}", ip, substitution_note(&http));
    }

    DnsSubstitution {
        service: service.to_string(),
        resolved: display,
        working_ip: Some(first.to_string()),
        http_note: last_note,
        http_ok: false,
    }
}

fn substitution_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::BlockPage => "страница блокировки".to_string(),
        HttpResult::Forbidden(code) => format!("отказ сервера HTTP {}", code),
        HttpResult::ServiceRestrict => {
            "страница отдалась, но сервис сообщает об ограничении (регион)".to_string()
        }
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
/// Адрес отдаётся только если сайт через него реально открылся (HTTP Ok):
/// hosts для адреса с отказом/RST — ложь.
pub fn hosts_entries(probe: &DomainProbe) -> Vec<String> {
    let ip = match (probe.working_ip_source, &probe.working_http) {
        (Some(IpSource::Doh), Some(HttpResult::Ok(_))) => probe.working_ip.as_deref(),
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

    /// Кейс openrouter.ai: адрес dns.comss.one (80.74.30.162) уходит в шлюзы,
    /// адреса сайта остаются в основном списке.
    #[test]
    fn split_doh_ips_separates_gateway_from_site() {
        let doh_addrs: Vec<IpAddr> = vec![
            "80.74.30.162".parse().unwrap(),
            "104.18.2.115".parse().unwrap(),
            "80.74.30.162".parse().unwrap(), // дубль шлюза
        ];
        let primary = vec!["104.18.3.115".to_string()];
        let owner = |ip: &IpAddr| {
            if ip.to_string() == "80.74.30.162" {
                Some("dns.comss.one".to_string())
            } else {
                None
            }
        };
        let (site, gateways) = split_doh_ips(&doh_addrs, &primary, &owner);
        assert_eq!(site, vec!["104.18.2.115".to_string()]);
        assert_eq!(
            gateways,
            vec![("80.74.30.162".to_string(), "dns.comss.one".to_string())],
            "дубль шлюза не дублируется"
        );
    }

    /// Шлюз, совпавший с системным адресом, не дублируется отдельной строкой:
    /// он уже показан в списке системных.
    #[test]
    fn split_doh_ips_gateway_matching_system_is_not_duplicated() {
        let doh_addrs: Vec<IpAddr> = vec!["80.74.30.162".parse().unwrap()];
        let primary = vec!["80.74.30.162".to_string()];
        let owner =
            |ip: &IpAddr| (ip.to_string() == "80.74.30.162").then(|| "dns.comss.one".to_string());
        let (site, gateways) = split_doh_ips(&doh_addrs, &primary, &owner);
        assert!(site.is_empty());
        assert!(gateways.is_empty());
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
            doh_gateway_ips: vec![],
            doh_ip_services: vec![(
                "104.21.95.93".to_string(),
                vec!["dns.comss.one".to_string()],
            )],
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
            doh_gateway_ips: vec![],
            doh_ip_services: vec![],
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