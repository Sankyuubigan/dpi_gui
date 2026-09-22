use std::collections::HashSet;
use std::time::Duration;
use std::thread;
use reqwest::blocking::Client as HttpClient;

/// Результат «простукивания» одного домена через сетевой стек ОС.
/// Так как winws (WinDivert) работает на уровне драйвера, он перехватывает ВЕСЬ
/// трафик, включая этот запрос. Если обход ломает домен — получим обрыв соединения.
#[derive(Clone)]
pub enum Probe {
    Ok,
    Dns,
    Broken(String),
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
            } else {
                Probe::Broken(e.to_string())
            }
        }
    }
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
pub fn classify_dual(
    results_on: Vec<(String, Probe)>,
    broken_off: &HashSet<String>,
    dns_off: &HashSet<String>,
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
        match probe {
            Probe::Ok => c.ok.push(host),
            Probe::Dns => c.dns_fail.push(host),
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
        );
        assert_eq!(c.ok, vec!["ok.example"]);
        assert!(c.need_bypass.is_empty());
        assert!(c.bypass_breaks.is_empty());
    }
}
