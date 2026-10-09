use std::collections::HashSet;
use std::time::Duration;
use std::thread;
use reqwest::blocking::Client as HttpClient;

/// Р РµР·СѓР»СЊС‚Р°С‚ В«РїСЂРѕСЃС‚СѓРєРёРІР°РЅРёСЏВ» РѕРґРЅРѕРіРѕ РґРѕРјРµРЅР° С‡РµСЂРµР· СЃРµС‚РµРІРѕР№ СЃС‚РµРє РћРЎ.
/// РўР°Рє РєР°Рє winws (WinDivert) СЂР°Р±РѕС‚Р°РµС‚ РЅР° СѓСЂРѕРІРЅРµ РґСЂР°Р№РІРµСЂР°, РѕРЅ РїРµСЂРµС…РІР°С‚С‹РІР°РµС‚ Р’Р•РЎР¬
/// С‚СЂР°С„РёРє, РІРєР»СЋС‡Р°СЏ СЌС‚РѕС‚ Р·Р°РїСЂРѕСЃ. Р•СЃР»Рё РѕР±С…РѕРґ Р»РѕРјР°РµС‚ РґРѕРјРµРЅ вЂ” РїРѕР»СѓС‡РёРј РѕР±СЂС‹РІ СЃРѕРµРґРёРЅРµРЅРёСЏ.
#[derive(Clone)]
pub enum Probe {
    Ok,
    Dns,
    Broken(String),
    /// TCP РґРѕ Р°РґСЂРµСЃР° РґРѕРјРµРЅР° РЅРµ СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РІРѕРѕР±С‰Рµ: СЃРµСЂРІРµСЂ РЅРµ РѕС‚РІРµС‡Р°РµС‚ РґР°Р¶Рµ РЅР°
    /// SYN. РўР°РєРѕР№ РґРѕРјРµРЅ РѕР±С…РѕРґ РЅРµ СЃРїР°СЃС‘С‚ вЂ” РѕРЅ РЅРµ РїСЂРёРЅРёРјР°РµС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ.
    DeadIp,
}

/// РџСЂРѕР±Р° РѕРґРЅРѕРіРѕ РґРѕРјРµРЅР°: Р»СЋР±РѕР№ HTTP-РѕС‚РІРµС‚ (РґР°Р¶Рµ 403/404) Р·РЅР°С‡РёС‚, С‡С‚Рѕ СЃРІСЏР·СЊ
/// СѓСЃС‚Р°РЅРѕРІРёР»Р°СЃСЊ. РћР±СЂС‹РІ СЃРѕРµРґРёРЅРµРЅРёСЏ СЂР°Р·Р»РёС‡Р°РµРј РЅР° DNS-РѕС€РёР±РєСѓ Рё РїСЂРѕС‡РёРµ (RST/TLS/timeout).
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

/// РўР°Р№РјР°СѓС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ Р±РµР· RST вЂ” С‚РёРїРёС‡РЅС‹Р№ РїСЂРёР·РЅР°Рє С‚РѕРіРѕ, С‡С‚Рѕ СЃРµСЂРІРµСЂ РЅРµ СЃР»СѓС€Р°РµС‚
/// СЌС‚РѕС‚ Р°РґСЂРµСЃ (Р° РЅРµ DPI: DPI РѕР±С‹С‡РЅРѕ СЃР±СЂР°СЃС‹РІР°РµС‚ СЃРѕРµРґРёРЅРµРЅРёРµ РёР»Рё РїРѕРґРјРµРЅСЏРµС‚ РѕС‚РІРµС‚).
pub fn is_dead_ip_error(msg: &str) -> bool {
    (msg.contains("timed out") || msg.contains("timeout") || msg.contains("10060"))
        && !msg.contains("reset")
        && !msg.contains("10061")
        && !msg.contains("10054")
}

/// РџР°СЂР°Р»Р»РµР»СЊРЅРѕ (РїР°С‡РєР°РјРё) РїСЂРѕСЃС‚СѓРєРёРІР°РµС‚ СЃРїРёСЃРѕРє РґРѕРјРµРЅРѕРІ, С‡С‚РѕР±С‹ РЅРµ Р¶РґР°С‚СЊ РјРёРЅСѓС‚С‹ РїСЂРё
/// Р±РѕР»СЊС€РѕРј С‡РёСЃР»Рµ РїРѕРґ-СЂРµСЃСѓСЂСЃРѕРІ.
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

/// РС‚РѕРіРѕРІР°СЏ РєР»Р°СЃСЃРёС„РёРєР°С†РёСЏ РґРѕРјРµРЅР° РїРѕСЃР»Рµ СЃСЂР°РІРЅРµРЅРёСЏ РґРІСѓС… РїСЂРѕР± (РѕР±С…РѕРґ Р’РљР› / Р’Р«РљР›).
pub struct Classification {
    /// Р—Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ СЃР°Рј РїРѕ СЃРµР±Рµ (СЃР»РѕРјР°РЅ Рё СЃ РѕР±С…РѕРґРѕРј, Рё Р±РµР· РЅРµРіРѕ) вЂ” РєР°РЅРґРёРґР°С‚ РІ РѕР±С…РѕРґ (general-Р»РёСЃС‚).
    pub need_bypass: Vec<String>,
    /// РћР±С…РѕРґ Р»РѕРјР°РµС‚ СЂР°Р±РѕС‡РёР№ РґРѕРјРµРЅ (СЃР»РѕРјР°РЅ С‚РѕР»СЊРєРѕ СЃ РѕР±С…РѕРґРѕРј) вЂ” РєР°РЅРґРёРґР°С‚ РІ РёСЃРєР»СЋС‡РµРЅРёСЏ.
    pub bypass_breaks: Vec<(String, String)>,
    /// РџРѕС…РѕР¶Рµ РЅР° Р±Р»РѕРє Р Р¤ РЅР° СѓСЂРѕРІРЅРµ DNS.
    pub dns_fail: Vec<String>,
    /// Р”РѕСЃС‚СѓРїРµРЅ С‡РµСЂРµР· РѕР±С…РѕРґ, РЅРёС‡РµРіРѕ РЅРµ С‚СЂРµР±СѓРµС‚.
    pub ok: Vec<String>,
    /// РќРµРґРѕСЃС‚СѓРїРµРЅ, РЅРѕ РїСЂРёС‡РёРЅР° РЅРµ СѓСЃС‚Р°РЅРѕРІР»РµРЅР° (РѕР±С…РѕРґ Р±С‹Р» РІС‹РєР»СЋС‡РµРЅ вЂ” РЅРµР»СЊР·СЏ
    /// РѕС‚Р»РёС‡РёС‚СЊ В«Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ СЃР°РјВ» РѕС‚ В«РѕР±С…РѕРґ РµРіРѕ Р»РѕРјР°РµС‚В»). РўСЂРµР±СѓРµС‚СЃСЏ РїСЂРѕРіРѕРЅ
    /// СЃ РІРєР»СЋС‡С‘РЅРЅС‹Рј РѕР±С…РѕРґРѕРј РґР»СЏ С‡РµСЃС‚РЅРѕРіРѕ РІС‹РІРѕРґР°.
    pub broken: Vec<String>,
}

/// Р Р°Р·Р±РёСЂР°РµС‚ СЂРµР·СѓР»СЊС‚Р°С‚С‹ РїРµСЂРІРѕР№ РїСЂРѕР±С‹ (РѕР±С…РѕРґ РєР°Рє РµСЃС‚СЊ). РСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ, РєРѕРіРґР°
/// РІС‚РѕСЂСѓСЋ РїСЂРѕР±Сѓ (Р±РµР· РѕР±С…РѕРґР°) СЃРґРµР»Р°С‚СЊ РЅРµР»СЊР·СЏ (РѕР±С…РѕРґ Р±С‹Р» РІС‹РєР»СЋС‡РµРЅ РёР·РЅР°С‡Р°Р»СЊРЅРѕ).
/// Р’ СЌС‚РѕРј СЃР»СѓС‡Р°Рµ РѕР±СЂС‹РІС‹ вЂ” РќР• В«РѕР±С…РѕРґ Р»РѕРјР°РµС‚ РґРѕРјРµРЅВ»: РѕР±С…РѕРґ РїСЂРѕСЃС‚Рѕ РЅРµ СЂР°Р±РѕС‚Р°Р».
/// РџРѕСЌС‚РѕРјСѓ РЅРµРґРѕСЃС‚СѓРїРЅС‹Рµ РґРѕРјРµРЅС‹ СЃРєР»Р°РґС‹РІР°РµРј РІ С‡РµСЃС‚РЅС‹Р№ СЃР»РѕС‚ `broken` (РїСЂРёС‡РёРЅР° РЅРµ
/// СѓСЃС‚Р°РЅРѕРІР»РµРЅР°), Р° РЅРµ РІ `bypass_breaks` (РёРЅР°С‡Рµ РѕС‚С‡С‘С‚ РІСЂС‘С‚, С‡С‚Рѕ РѕР±С…РѕРґ Р»РѕРјР°РµС‚ СЃР°Р№С‚).
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
    // Р”РѕРјРµРЅС‹, СѓРїР°РІС€РёРµ РІ Р±СЂР°СѓР·РµСЂРµ, РїСЂРё РІС‹РєР»СЋС‡РµРЅРЅРѕРј РѕР±С…РѕРґРµ С‚РѕР¶Рµ В«РЅРµРёР·РІРµСЃС‚РЅС‹В»,
    // Р° РЅРµ В«СЃР»РѕРјР°РЅС‹ РѕР±С…РѕРґРѕРјВ».
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

/// Р Р°Р·Р±РёСЂР°РµС‚ СЂРµР·СѓР»СЊС‚Р°С‚С‹ Р”Р’РЈРҐ РїСЂРѕР±. `broken_off` вЂ” РјРЅРѕР¶РµСЃС‚РІРѕ РґРѕРјРµРЅРѕРІ, РєРѕС‚РѕСЂС‹Рµ
/// РѕРєР°Р·Р°Р»РёСЃСЊ СЃР»РѕРјР°РЅС‹ Р Р±РµР· РѕР±С…РѕРґР° (РїСЂРѕР±Р° #2). Р•СЃР»Рё РґРѕРјРµРЅ СЃР»РѕРјР°РЅ СЃ РѕР±С…РѕРґРѕРј, РЅРѕ:
///  - СЃР»РѕРјР°РЅ Рё Р±РµР· РѕР±С…РѕРґР°  -> Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ СЃР°Рј -> need_bypass (РІ РѕР±С…РѕРґ);
///  - СЂР°Р±РѕС‚Р°РµС‚ Р±РµР· РѕР±С…РѕРґР°   -> РѕР±С…РѕРґ РµРіРѕ Р»РѕРјР°РµС‚ -> bypass_breaks (РІ РёСЃРєР»СЋС‡РµРЅРёСЏ).
/// `dead_off` вЂ” РґРѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ Рё Р±РµР· РѕР±С…РѕРґР° РЅРµ РїСЂРёРЅРёРјР°СЋС‚ СЃРѕРµРґРёРЅРµРЅРёРµ (СЃРµСЂРІРµСЂ
/// РЅРµ РѕС‚РІРµС‡Р°РµС‚). Р”Р»СЏ РЅРёС… РѕР±С…РѕРґ РЅРµ РїРѕРјРѕР¶РµС‚, РїРѕСЌС‚РѕРјСѓ РѕРЅРё РЅРёРєСѓРґР° РЅРµ СЂРµРєРѕРјРµРЅРґСѓСЋС‚СЃСЏ.
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
            // РЎРµСЂРІРµСЂ РЅРµ РѕС‚РІРµС‡Р°РµС‚ РґР°Р¶Рµ Р±РµР· РѕР±С…РѕРґР° вЂ” РґРѕРјРµРЅ РЅРµРґРѕСЃС‚СѓРїРµРЅ СЃР°Рј РїРѕ СЃРµР±Рµ.
            c.broken.push(host);
            continue;
        }
        match probe {
            Probe::Ok => c.ok.push(host),
            Probe::Dns => c.dns_fail.push(host),
            // РЎРµСЂРІРµСЂ РЅРµ РїСЂРёРЅРёРјР°РµС‚ СЃРѕРµРґРёРЅРµРЅРёРµ РІРѕРѕР±С‰Рµ вЂ” РЅРё РѕР±С…РѕРґ, РЅРё РёСЃРєР»СЋС‡РµРЅРёСЏ
            // С‚СѓС‚ РЅРµ РїРѕРјРѕРіСѓС‚, РґРѕРјРµРЅ СѓС…РѕРґРёС‚ РІ В«РЅРµРґРѕСЃС‚СѓРїРЅС‹РµВ», Р° РЅРµ РІ РѕР±С…РѕРґ.
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

/// Р”РѕРјРµРЅС‹, СѓРїР°РІС€РёРµ РїСЂСЏРјРѕ РІ Р±СЂР°СѓР·РµСЂРµ (LoadingFailed), РЅРѕ РЅРµ РїРѕРїР°РІС€РёРµ РЅРё РІ РѕРґРёРЅ
/// СЃРїРёСЃРѕРє, СЃС‡РёС‚Р°РµРј СЃР»РѕРјР°РЅРЅС‹РјРё РѕР±С…РѕРґРѕРј (РєР°РЅРґРёРґР°С‚С‹ РІ РёСЃРєР»СЋС‡РµРЅРёСЏ).
fn add_browser_failed(c: &mut Classification, browser_failed: &HashSet<String>) {
    for host in browser_failed {
        let known = c.ok.contains(host)
            || c.dns_fail.contains(host)
            || c.need_bypass.contains(host)
            || c.bypass_breaks.iter().any(|(h, _)| h == host);
        if !known {
            c.bypass_breaks
                .push((host.clone(), "РѕР±СЂС‹РІ СЃРѕРµРґРёРЅРµРЅРёСЏ РІ Р±СЂР°СѓР·РµСЂРµ (LoadingFailed)".to_string()));
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
        assert!(c.bypass_breaks.is_empty(), "РѕР±С…РѕРґ РІС‹РєР»СЋС‡РµРЅ вЂ” РЅРµ РјРѕР¶РµС‚ В«Р»РѕРјР°С‚СЊВ»");
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
            &set(&[]), // Р±РµР· РѕР±С…РѕРґР° СЂР°Р±РѕС‚Р°РµС‚
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

    /// РЎРµСЂРІРµСЂ РЅРµ РѕС‚РІРµС‡Р°РµС‚ РґР°Р¶Рµ Р±РµР· РѕР±С…РѕРґР° вЂ” РѕР±С…РѕРґ С‚СѓС‚ Р±РµСЃСЃРёР»РµРЅ, РґРѕРјРµРЅ РЅРµ СЂРµРєРѕРјРµРЅРґСѓРµРј.
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
        // RST вЂ” СЌС‚Рѕ DPI, Р° РЅРµ РјС‘СЂС‚РІС‹Р№ СЃРµСЂРІРµСЂ.
        assert!(!is_dead_ip_error("connection reset by peer (os error 10054)"));
        assert!(!is_dead_ip_error("connection refused (os error 10061)"));
    }
}
