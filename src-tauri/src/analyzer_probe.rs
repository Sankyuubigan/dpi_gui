use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::thread;
use reqwest::blocking::Client as HttpClient;

/// Результат «простукивания» одного домена через сетевой стек ОС.
/// Так как winws (WinDivert) работает на уровне драйвера, он перехватывает ВЕСЬ
/// трафик, включая этот запрос. Если обход ломает домен — получим обрыв соединения.
#[derive(Clone, Debug)]
pub enum Probe {
    Ok,
    Dns,
    Broken(String),
    /// TCP до адреса домена не устанавливается вообще: сервер не отвечает даже на
    /// SYN. Такой домен обход не спасёт — он не принимает соединения.
    DeadIp,
}

/// Проба одного домена: любой HTTP-ответ (даже 403/404) значит, что связь
/// установилась. Обрыв соединения различаем на DNS-ошибку и прочие (RST/TLS/timeout).
pub fn probe_host(host: &str) -> Probe {
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build();
    let test_url = format!("https://{}/", host);
    match client.and_then(|c| c.get(&test_url).send()) {
        Ok(_) => Probe::Ok,
        Err(e) => {
            let m = e.to_string().to_lowercase();
            if m.contains("dns")
                || m.contains("resolve")
                || m.contains("name or service not known")
                || m.contains("no address")
            {
                Probe::Dns
            } else if is_dead_ip_error(&m) {
                Probe::DeadIp
            } else {
                Probe::Broken(e.to_string())
            }
        }
    }
}

/// Таймаут соединения без RST — типичный признак того, что сервер не слушает
/// этот адрес (а не DPI: DPI обычно сбрасывает соединение или подменяет ответ).
pub fn is_dead_ip_error(msg: &str) -> bool {
    (msg.contains("timed out") || msg.contains("timeout") || msg.contains("10060"))
        && !msg.contains("reset")
        && !msg.contains("10061")
        && !msg.contains("10054")
}

/// Параллельно (пачками) простукивает список доменов, чтобы не ждать минуты при
/// большом числе под-ресурсов.
pub fn probe_all(hosts: &[String]) -> Vec<(String, Probe)> {
    const CHUNK: usize = 16;
    let mut results: Vec<(String, Probe)> = Vec::new();
    for chunk in hosts.chunks(CHUNK) {
        let mut handles = Vec::new();
        for host in chunk {
            let host = host.clone();
            handles.push(thread::spawn(move || {
                let p = probe_host(&host);
                (host, p)
            }));
        }
        for h in handles {
            if let Ok(r) = h.join() {
                results.push(r);
            }
        }
    }
    results
}

/// Итог пробы «без обхода» для одного домена — класс без деталей обрыва:
/// для классификации важен тип результата, а не текст ошибки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffProbe {
    /// Без обхода работает — обход его ломает.
    Ok,
    /// Без обхода DNS-ошибка.
    Dns,
    /// Сломан и без обхода — заблокирован сам.
    Broken,
    /// Без обхода сервер не отвечает вообще (TCP не устанавливается).
    Dead,
}

/// Слияние первой пробы «без обхода» и ретрая по правилу «обрыв
/// засчитывается, только если увиден ДВАЖДЫ»: Ok или DNS-ошибка на ретрае
/// перебивают первый обрыв (он был ложным — сразу после остановки winws
/// часть соединений ещё ловит до-зачистку драйвера/стека, кейс
/// eu.aptabase.com). Выпавший ретрай (поток пробы умер) — честнее засчитать
/// первый обрыв, чем переклеивать его в «обход ломает» без чистого
/// подтверждения.
fn merge_off_pass(first: Probe, retry: Option<&Probe>) -> OffProbe {
    match first {
        Probe::Ok => OffProbe::Ok,
        Probe::Dns => OffProbe::Dns,
        Probe::Broken(_) | Probe::DeadIp => match retry {
            Some(Probe::Ok) => OffProbe::Ok,
            Some(Probe::Dns) => OffProbe::Dns,
            Some(Probe::DeadIp) => OffProbe::Dead,
            Some(Probe::Broken(_)) => OffProbe::Broken,
            None => match first {
                Probe::DeadIp => OffProbe::Dead,
                _ => OffProbe::Broken,
            },
        },
    }
}

/// Проба «без обхода» для доменов, сломанных при обходе: первая проба,
/// пауза, ретрай обрывов. Единый источник правды для одиночного (analyzer.rs)
/// и массового (mass_analysis.rs) анализа — политика «обрыв виден дважды»
/// живёт здесь в одном экземпляре.
pub fn probe_off(broken_on: &[String]) -> HashMap<String, OffProbe> {
    if broken_on.is_empty() {
        return HashMap::new();
    }
    let first_pass: HashMap<String, Probe> = probe_all(broken_on).into_iter().collect();
    let to_retry: Vec<String> = first_pass
        .iter()
        .filter_map(|(h, p)| match p {
            Probe::Broken(_) | Probe::DeadIp => Some(h.clone()),
            _ => None,
        })
        .collect();
    // Пауза перед ретраем: соединениям нужно время, чтобы кончилась
    // до-зачистка драйвера после остановки winws.
    thread::sleep(Duration::from_secs(1));
    let retry_pass: HashMap<String, Probe> = if to_retry.is_empty() {
        HashMap::new()
    } else {
        probe_all(&to_retry).into_iter().collect()
    };
    first_pass
        .into_iter()
        .map(|(h, first)| {
            let off = merge_off_pass(first, retry_pass.get(&h));
            (h, off)
        })
        .collect()
}

/// Итоговая классификация домена после сравнения двух проб (обход ВКЛ / ВЫКЛ).
pub struct Classification {
    /// Заблокирован сам по себе (сломан и с обходом, и без него) — кандидат в обход (general-лист).
    pub need_bypass: Vec<String>,
    /// Обход ломает рабочий домен (сломан только с обходом) — кандидат в исключения.
    pub bypass_breaks: Vec<(String, String)>,
    /// Похоже на блок РФ на уровне DNS.
    pub dns_fail: Vec<String>,
    /// Доступен через обход, ничего не требует.
    pub ok: Vec<String>,
    /// Недоступен, но причина не установлена (обход был выключен — нельзя
    /// отличить «заблокирован сам» от «обход его ломает»). Требуется прогон
    /// с включённым обходом для честного вывода.
    pub broken: Vec<String>,
}

/// Разбирает результаты первой пробы (обход как есть). Используется, когда
/// вторую пробу (без обхода) сделать нельзя (обход был выключен изначально).
/// В этом случае обрывы — НЕ «обход ломает домен»: обход просто не работал.
/// Поэтому недоступные домены складываем в честный слот `broken` (причина не
/// установлена), а не в `bypass_breaks` (иначе отчёт врёт, что обход ломает сайт).
pub fn classify_single(
    results: Vec<(String, Probe)>,
    browser_failed: &HashSet<String>,
) -> Classification {
    let mut c = Classification {
        need_bypass: Vec::new(),
        bypass_breaks: Vec::new(),
        dns_fail: Vec::new(),
        ok: Vec::new(),
        broken: Vec::new(),
    };
    for (host, probe) in results {
        match probe {
            Probe::Ok => c.ok.push(host),
            Probe::Dns => c.dns_fail.push(host),
            Probe::Broken(_) => c.broken.push(host),
            Probe::DeadIp => c.broken.push(host),
        }
    }
    // Домены, упавшие в браузере, при выключенном обходе тоже «неизвестны»,
    // а не «сломаны обходом».
    for host in browser_failed {
        let known = c.ok.contains(host)
            || c.dns_fail.contains(host)
            || c.broken.contains(host)
            || c.need_bypass.contains(host)
            || c.bypass_breaks.iter().any(|(h, _)| h == host);
        if !known {
            c.broken.push(host.clone());
        }
    }
    finalize(&mut c);
    c
}

/// Разбирает результаты ДВУХ проб. `broken_off` — множество доменов, которые
/// оказались сломаны И без обхода (проба #2). Если домен сломан с обходом, но:
///  - сломан и без обхода  -> заблокирован сам -> need_bypass (в обход);
///  - работает без обхода   -> обход его ломает -> bypass_breaks (в исключения).
/// `dead_off` — домены, которые и без обхода не принимают соединение (сервер
/// не отвечает). Для них обход не поможет, поэтому они никуда не рекомендуются.
pub fn classify_dual(
    results_on: Vec<(String, Probe)>,
    broken_off: &HashSet<String>,
    dns_off: &HashSet<String>,
    dead_off: &HashSet<String>,
    browser_failed: &HashSet<String>,
) -> Classification {
    let mut c = Classification {
        need_bypass: Vec::new(),
        bypass_breaks: Vec::new(),
        dns_fail: Vec::new(),
        ok: Vec::new(),
        broken: Vec::new(),
    };
    for (host, probe) in results_on {
        if dead_off.contains(&host) {
            // Сервер не отвечает даже без обхода — домен недоступен сам по себе.
            c.broken.push(host);
            continue;
        }
        match probe {
            Probe::Ok => c.ok.push(host),
            Probe::Dns => c.dns_fail.push(host),
            // Сервер не принимает соединение вообще — ни обход, ни исключения
            // тут не помогут, домен уходит в «недоступные», а не в обход.
            Probe::DeadIp => c.broken.push(host),
            Probe::Broken(err) => {
                if dns_off.contains(&host) {
                    c.dns_fail.push(host);
                } else if broken_off.contains(&host) {
                    c.need_bypass.push(host);
                } else {
                    c.bypass_breaks.push((host, err));
                }
            }
        }
    }
    add_browser_failed(&mut c, browser_failed);
    finalize(&mut c);
    c
}

/// Домены, упавшие прямо в браузере (LoadingFailed), но не попавшие ни в один
/// список, считаем сломанными обходом (кандидаты в исключения).
fn add_browser_failed(c: &mut Classification, browser_failed: &HashSet<String>) {
    for host in browser_failed {
        let known = c.ok.contains(host)
            || c.dns_fail.contains(host)
            || c.need_bypass.contains(host)
            || c.bypass_breaks.iter().any(|(h, _)| h == host);
        if !known {
            c.bypass_breaks
                .push((host.clone(), "обрыв соединения в браузере (LoadingFailed)".to_string()));
        }
    }
}

/// Арбитраж противоречия: классификация требует обхода для главного домена
/// (`need_bypass`), но факт-диагностика [`crate::site_probe::probe_domain`],
/// проведённая в чистом окне без обхода, доказала, что сайт ОТКРЫВАЕТСЯ.
/// Обход не чинит сайт, который работает без него, — значит «добавьте в
/// обход» здесь ложь, и верен противоположный вывод: если проба #1 (с
/// обходом) домен обрывала, его ломает сам обход → `bypass_breaks`
/// (в исключения). Классифицировать «открытый без обхода» домен в обход
/// уходил и вредный совет «Починить сайт» (кейс eu.aptabase.com: профиль
/// ALT11 рвал bunny CDN, а анализ звал этот домен в general-лист).
pub fn arbitrate_open_main_host(
    c: &mut Classification,
    main_on_probe: Option<&Probe>,
    main_host: &str,
    main_verdict_open: bool,
) {
    if !main_verdict_open || !c.need_bypass.iter().any(|h| h == main_host) {
        return;
    }
    c.need_bypass.retain(|h| h != main_host);
    match main_on_probe {
        // Проба #1 (с обходом) обрывала домен, который без обхода открыт, —
        // ломает именно обход; причина честная, из факта пробы.
        Some(Probe::Broken(err)) => c.bypass_breaks.push((main_host.to_string(), err.clone())),
        Some(Probe::DeadIp) => c.bypass_breaks.push((
            main_host.to_string(),
            "TCP:443 с включённым обходом не отвечает (без обхода — отвечает)".to_string(),
        )),
        // Проба #1 домен тоже открывала: он просто доступен, ничего не советуем.
        _ => {}
    }
    finalize(c);
}

fn finalize(c: &mut Classification) {
    c.need_bypass.sort();
    c.need_bypass.dedup();
    c.bypass_breaks.sort_by(|a, b| a.0.cmp(&b.0));
    c.dns_fail.sort();
    c.dns_fail.dedup();
    c.ok.sort();
    c.ok.dedup();
    c.broken.sort();
    c.broken.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn results(v: &[(&str, Probe)]) -> Vec<(String, Probe)> {
        v.iter().map(|(h, p)| (h.to_string(), p.clone())).collect()
    }

    /// Правило «обрыв засчитывается, только если увиден ДВАЖДЫ» (SSOT
    /// для одиночного и массового анализа): Ok/Dns на ретрае перебивают
    /// первый обрыв, выпавший ретрай — первый обрыв остаётся.
    #[test]
    fn off_retry_requires_two_sightings() {
        assert_eq!(merge_off_pass(Probe::Ok, None), OffProbe::Ok);
        assert_eq!(merge_off_pass(Probe::Dns, None), OffProbe::Dns);
        // Один обрыв, ретрай открыл — первый был ложным.
        assert_eq!(
            merge_off_pass(Probe::Broken("x".into()), Some(&Probe::Ok)),
            OffProbe::Ok
        );
        // DNS-ошибка на ретрае тоже перебивает обрыв.
        assert_eq!(
            merge_off_pass(Probe::Broken("x".into()), Some(&Probe::Dns)),
            OffProbe::Dns
        );
        // Обрыв виден дважды — засчитан.
        assert_eq!(
            merge_off_pass(Probe::Broken("x".into()), Some(&Probe::Broken("y".into()))),
            OffProbe::Broken
        );
        assert_eq!(
            merge_off_pass(Probe::DeadIp, Some(&Probe::DeadIp)),
            OffProbe::Dead
        );
        // Обрыв → мёртвый IP на ретрае: класс уточняется в Dead.
        assert_eq!(
            merge_off_pass(Probe::Broken("x".into()), Some(&Probe::DeadIp)),
            OffProbe::Dead
        );
        // Ретрай не вернулся (поток умер) — честнее первый обрыв, чем «обход ломает».
        assert_eq!(merge_off_pass(Probe::Broken("x".into()), None), OffProbe::Broken);
        assert_eq!(merge_off_pass(Probe::DeadIp, None), OffProbe::Dead);
    }

    #[test]
    fn single_bypass_off_broken_goes_to_broken_not_bypass_breaks() {
        let c = classify_single(
            results(&[
                ("ok.example", Probe::Ok),
                ("broken.example", Probe::Broken("err".to_string())),
                ("dns.example", Probe::Dns),
            ]),
            &set(&["br.failed.example"]),
        );
        assert_eq!(c.ok, vec!["ok.example"]);
        assert_eq!(c.dns_fail, vec!["dns.example"]);
        assert_eq!(c.broken, vec!["br.failed.example", "broken.example"]);
        assert!(c.bypass_breaks.is_empty(), "обход выключен — не может «ломать»");
    }

    #[test]
    fn single_browser_failed_not_duplicated() {
        let c = classify_single(
            results(&[("dup.example", Probe::Broken("err".to_string()))]),
            &set(&["dup.example"]),
        );
        assert_eq!(c.broken, vec!["dup.example"]);
        assert!(c.bypass_breaks.is_empty());
    }

    #[test]
    fn dual_broken_both_ways_is_need_bypass() {
        let c = classify_dual(
            results(&[("blocked.example", Probe::Broken("err".to_string()))]),
            &set(&["blocked.example"]),
            &set(&[]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(c.need_bypass, vec!["blocked.example"]);
        assert!(c.broken.is_empty());
    }

    #[test]
    fn dual_broken_with_bypass_works_without_is_bypass_breaks() {
        let c = classify_dual(
            results(&[("fine.example", Probe::Broken("err".to_string()))]),
            &set(&[]), // без обхода работает
            &set(&[]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(c.bypass_breaks, vec![("fine.example".to_string(), "err".to_string())]);
        assert!(c.broken.is_empty());
    }

    #[test]
    fn dual_dns_broken_both_ways_is_dns_fail() {
        let c = classify_dual(
            results(&[("dns.example", Probe::Dns)]),
            &set(&["dns.example"]),
            &set(&["dns.example"]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(c.dns_fail, vec!["dns.example"]);
    }

    #[test]
    fn dual_ok_untouched() {
        let c = classify_dual(
            results(&[("ok.example", Probe::Ok)]),
            &set(&[]),
            &set(&[]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(c.ok, vec!["ok.example"]);
        assert!(c.need_bypass.is_empty());
        assert!(c.bypass_breaks.is_empty());
    }

    /// Сервер не отвечает даже без обхода — обход тут бессилен, домен не рекомендуем.
    #[test]
    fn dead_ip_never_recommended_for_bypass() {
        let c = classify_dual(
            results(&[("dead.example", Probe::DeadIp)]),
            &set(&["dead.example"]),
            &set(&[]),
            &set(&["dead.example"]),
            &HashSet::new(),
        );
        assert_eq!(c.broken, vec!["dead.example"]);
        assert!(c.need_bypass.is_empty());
        assert!(c.bypass_breaks.is_empty());
    }

    #[test]
    fn dead_ip_without_bypass_pass_goes_to_broken() {
        let c = classify_single(results(&[("dead.example", Probe::DeadIp)]), &HashSet::new());
        assert_eq!(c.broken, vec!["dead.example"]);
        assert!(c.need_bypass.is_empty());
    }

    #[test]
    fn timeout_is_dead_ip_but_reset_is_not() {
        assert!(is_dead_ip_error("error sending request: operation timed out"));
        assert!(is_dead_ip_error("read tcp: i/o timeout (os error 10060)"));
        // RST — это DPI, а не мёртвый сервер.
        assert!(!is_dead_ip_error("connection reset by peer (os error 10054)"));
        assert!(!is_dead_ip_error("connection refused (os error 10061)"));
    }

    // --- арбитраж «открытый без обхода главный домен» (кейс eu.aptabase.com) ---

    /// Классификация позвала главный домен в обход, но probe_domain доказал,
    /// что сайт открывается без обхода, а проба #1 (с обходом) его обрывала:
    /// домен уходит в bypass_breaks («обход ломает»), не в need_bypass.
    #[test]
    fn open_main_host_with_broken_probe_moves_to_bypass_breaks() {
        let mut c = empty_classification();
        c.need_bypass = vec!["eu.aptabase.com".to_string()];
        arbitrate_open_main_host(
            &mut c,
            Some(&Probe::Broken("error sending request".to_string())),
            "eu.aptabase.com",
            true,
        );
        assert!(c.need_bypass.is_empty(), "{:?}", c.need_bypass);
        assert_eq!(
            c.bypass_breaks,
            vec![("eu.aptabase.com".to_string(), "error sending request".to_string())]
        );
    }

    /// Проба #1 тоже открывала домен: он просто доступен — не советуем ничего.
    #[test]
    fn open_main_host_with_ok_probe_drops_bypass_advice() {
        let mut c = empty_classification();
        c.need_bypass = vec!["eu.aptabase.com".to_string()];
        arbitrate_open_main_host(&mut c, Some(&Probe::Ok), "eu.aptabase.com", true);
        assert!(c.need_bypass.is_empty(), "{:?}", c.need_bypass);
        assert!(c.bypass_breaks.is_empty(), "{:?}", c.bypass_breaks);
    }

    /// Вердикт не Open (сайт и без обхода сломан) — классификацию не трогаем.
    #[test]
    fn non_open_verdict_keeps_need_bypass() {
        let mut c = empty_classification();
        c.need_bypass = vec!["blocked.example".to_string()];
        arbitrate_open_main_host(
            &mut c,
            Some(&Probe::Broken("err".to_string())),
            "blocked.example",
            false,
        );
        assert_eq!(c.need_bypass, vec!["blocked.example".to_string()]);
        assert!(c.bypass_breaks.is_empty());
    }

    /// Главный домен не в need_bypass — арбитраж ничего не меняет.
    #[test]
    fn main_host_not_in_need_bypass_is_untouched() {
        let mut c = empty_classification();
        c.need_bypass = vec!["other.example".to_string()];
        c.bypass_breaks = vec![("already.example".to_string(), "e".to_string())];
        arbitrate_open_main_host(
            &mut c,
            Some(&Probe::Broken("err".to_string())),
            "main.example",
            true,
        );
        assert_eq!(c.need_bypass, vec!["other.example".to_string()]);
        assert_eq!(c.bypass_breaks.len(), 1);
    }

    fn empty_classification() -> Classification {
        Classification {
            need_bypass: Vec::new(),
            bypass_breaks: Vec::new(),
            dns_fail: Vec::new(),
            ok: Vec::new(),
            broken: Vec::new(),
        }
    }
}
