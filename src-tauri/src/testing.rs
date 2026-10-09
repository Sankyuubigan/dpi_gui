use crate::{process, diagnostics_probe};
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::Serialize;
use tauri::AppHandle;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::Resolver;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;

/// Р РµР·СѓР»СЊС‚Р°С‚ С‚РµСЃС‚Р° РѕРґРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ вЂ” РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ РЅР° С„СЂРѕРЅС‚РµРЅРґ.
#[derive(Serialize, Debug)]
pub struct ProfileTestOutcome {
    pub name: String,
    pub ok: bool,
    /// Р§РµР»РѕРІРµРєРѕ-С‡РёС‚Р°РµРјС‹Р№ РІРµСЂРґРёРєС‚: В«РЈРЎРџР•РҐ (200 OK)В», В«РўР°Р№РјР°СѓС‚ СЃРѕРµРґРёРЅРµРЅРёСЏВ», В«RST вЂ” СЃР±СЂРѕСЃ (DPI)В» Рё С‚.Рї.
    pub verdict: String,
    /// Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅР°СЏ РґРµС‚Р°Р»СЊ (РґР»СЏ РїСЂРѕРІР°Р»Р°).
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Р§РµР»РѕРІРµРєРѕ-С‡РёС‚Р°РµРјРѕРµ РѕРїРёСЃР°РЅРёРµ РєР»Р°СЃСЃРёС„РёС†РёСЂРѕРІР°РЅРЅРѕРіРѕ СЂРµР·СѓР»СЊС‚Р°С‚Р° HTTP-РїСЂРѕР±С‹.
fn verdict_from_http(r: &diagnostics_probe::HttpResult) -> (bool, String) {
    match r {
        diagnostics_probe::HttpResult::Ok(s) => (true, format!("РЈРЎРџР•РҐ (HTTP {})", s)),
        diagnostics_probe::HttpResult::BlockPage => (false, "РЎС‚СЂР°РЅРёС†Р° Р±Р»РѕРєРёСЂРѕРІРєРё (403/451/Р·Р°РіР»СѓС€РєР°)".to_string()),
        diagnostics_probe::HttpResult::Dns => (false, "DNS РЅРµ СЂРµР·РѕР»РІРёС‚СЃСЏ (NXDOMAIN / DNS-С†РµРЅР·СѓСЂР°)".to_string()),
        diagnostics_probe::HttpResult::Rst => (false, "RST вЂ” СЃРѕРµРґРёРЅРµРЅРёРµ СЃР±СЂРѕС€РµРЅРѕ (С‚РёРїРёС‡РЅРѕ РґР»СЏ DPI)".to_string()),
        diagnostics_probe::HttpResult::Tls => (false, "TLS-СЂСѓРєРѕРїРѕР¶Р°С‚РёРµ СЂРІС‘С‚СЃСЏ".to_string()),
        diagnostics_probe::HttpResult::BadCert => (false, "SSL-СЃРµСЂС‚РёС„РёРєР°С‚ СЃР°Р№С‚Р° РЅРµРІР°Р»РёРґРµРЅ (NET::ERR_CERT_*)".to_string()),
        diagnostics_probe::HttpResult::Timeout => (false, "РўР°Р№РјР°СѓС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ".to_string()),
        diagnostics_probe::HttpResult::Other(msg) => (false, format!("РћС€РёР±РєР°: {}", msg)),
    }
}

pub fn test_single_profile(app: AppHandle, profile_name: &str, url: &str, game_filter: bool) -> Result<ProfileTestOutcome, String> {
    let started = Instant::now();
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    if let Err(e) = process::start_winws_quiet(app.clone(), profile_name, game_filter) {
        return Ok(ProfileTestOutcome {
            name: profile_name.to_string(),
            ok: false,
            verdict: "РћС€РёР±РєР° Р·Р°РїСѓСЃРєР°".to_string(),
            detail: e,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Р”Р°РµРј WinDivert РІСЂРµРјСЏ РЅР° РїРµСЂРµС…РІР°С‚ С‚СЂР°С„РёРєР°
    thread::sleep(Duration::from_secs(2));

    // Р”РµСЃРёРЅРє-РїСЂРѕС„РёР»Рё С‡Р°СЃС‚Рѕ РїСЂРѕР±РёРІР°СЋС‚ С‚РѕР»СЊРєРѕ СЃРѕ РІС‚РѕСЂРѕР№/С‚СЂРµС‚СЊРµР№ РїРѕРїС‹С‚РєРё
    // (РїРµСЂРІС‹Р№ РєРѕРЅРЅРµРєС‚ СЃСЉРµРґР°РµС‚СЃСЏ DPI, winws РїРµСЂРµСЃС‹Р»Р°РµС‚ РјРѕРґРёС„РёС†РёСЂРѕРІР°РЅРЅС‹Рµ РїР°РєРµС‚С‹).
    let mut result: diagnostics_probe::HttpResult = diagnostics_probe::HttpResult::Timeout;
    for attempt in 1..=2 {
        let r = diagnostics_probe::http_classify_with(&target_url, 5);
        if matches!(r, diagnostics_probe::HttpResult::Ok(_)) {
            result = r;
            break;
        }
        result = r;
        if attempt == 1 {
            thread::sleep(Duration::from_millis(800));
        }
    }

    let _ = process::stop_winws();
    thread::sleep(Duration::from_secs(1));

    let (ok, verdict) = verdict_from_http(&result);
    let detail = if ok {
        String::new()
    } else {
        match &result {
            diagnostics_probe::HttpResult::Other(m) => m.clone(),
            diagnostics_probe::HttpResult::BlockPage => "РїРѕР»СѓС‡РµРЅР° СЃС‚СЂР°РЅРёС†Р°-Р·Р°РіР»СѓС€РєР° РІРјРµСЃС‚Рѕ СЃР°Р№С‚Р°".to_string(),
            diagnostics_probe::HttpResult::Dns => "Р·Р°РїРёСЃСЊ РґРѕРјРµРЅР° РЅРµ РЅР°Р№РґРµРЅР° СЃРёСЃС‚РµРјРЅС‹Рј DNS".to_string(),
            diagnostics_probe::HttpResult::Rst => "СЃРѕРµРґРёРЅРµРЅРёРµ РѕР±РѕСЂРІР°РЅРѕ RST РїСЂРё СЂСѓРєРѕРїРѕР¶Р°С‚РёРё".to_string(),
            diagnostics_probe::HttpResult::Tls => "TLS-С…РµРЅРґС€РµР№Рє РЅРµ Р·Р°РІРµСЂС€РёР»СЃСЏ Р·Р° РІСЂРµРјСЏ РїСЂРѕР±С‹".to_string(),
            diagnostics_probe::HttpResult::BadCert => "СЃРµСЂРІРµСЂ РѕС‚РІРµС‚РёР», РЅРѕ РµРіРѕ SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ РґР»СЏ РґРѕРјРµРЅР° вЂ” РѕР±С…РѕРґ РЅРµ РїРѕС‡РёРЅРёС‚ СЌС‚Рѕ".to_string(),
            diagnostics_probe::HttpResult::Timeout => "СЃРµСЂРІРµСЂ РЅРµ РѕС‚РІРµС‚РёР» Р·Р° ~5 СЃРµРєСѓРЅРґ".to_string(),
            _ => format!("{:?}", result),
        }
    };

    Ok(ProfileTestOutcome {
        name: profile_name.to_string(),
        ok,
        verdict,
        detail,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

pub fn test_dns(url: &str, dns_ip: &str) -> Result<String, String> {
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    // Р’С‹С‚Р°СЃРєРёРІР°РµРј РґРѕРјРµРЅ РґР»СЏ СЂРµР·РѕР»РІРёРЅРіР°
    let parsed_url = url::Url::parse(&target_url).map_err(|e| format!("РќРµРІРµСЂРЅС‹Р№ URL: {}", e))?;
    let domain = parsed_url.host_str().ok_or("РќРµ СѓРґР°Р»РѕСЃСЊ РёР·РІР»РµС‡СЊ РґРѕРјРµРЅ")?.to_string();

    let dns_label = dns_ip.to_string();

    // Р”РІР° РІРёРґР° СЂРµР·РѕР»РІРµСЂРѕРІ: РїСЂРёРІС‹С‡РЅС‹Р№ IP (UDP:53) Рё DoH-СЃРµСЂРІРёСЃ (https://host/dns-query).
    let resolved_ip: IpAddr;
    if dns_ip.trim().starts_with("http") {
        let doh_url = url::Url::parse(dns_ip.trim())
            .map_err(|e| format!("РќРµРІРµСЂРЅС‹Р№ URL DoH-СЂРµР·РѕР»РІРµСЂР°: {}", e))?;
        let doh_host = doh_url.host_str()
            .ok_or("РќРµ СѓРґР°Р»РѕСЃСЊ РёР·РІР»РµС‡СЊ С…РѕСЃС‚ РёР· DoH-СЂРµР·РѕР»РІРµСЂР°")?
            .to_string();
        let ips = diagnostics_probe::resolve_via_doh(&domain, &doh_host);
        resolved_ip = ips.first().copied().ok_or_else(|| {
            format!("DoH-СЂРµР·РѕР»РІРµСЂ {} РЅРµ РІРµСЂРЅСѓР» IP РґР»СЏ {}. Р’РѕР·РјРѕР¶РЅРѕ DNS-С†РµРЅР·СѓСЂР° РёР»Рё СЃРµСЂРІРёСЃ РЅРµРґРѕСЃС‚СѓРїРµРЅ.", doh_host, domain)
        })?;
    } else {
        let dns_addr = IpAddr::from_str(dns_ip.trim()).map_err(|_| "РќРµРІРµСЂРЅС‹Р№ IP РєР°СЃС‚РѕРјРЅРѕРіРѕ DNS СЃРµСЂРІРµСЂР°")?;

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(dns_addr, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        });

        // Р”РµР»Р°РµРј Р·Р°РїСЂРѕСЃ Рє РєР°СЃС‚РѕРјРЅРѕРјСѓ DNS (РЅР°РїСЂРёРјРµСЂ, 1.1.1.1)
        let resolver = Resolver::new(config, ResolverOpts::default()).map_err(|e| format!("РћС€РёР±РєР° РёРЅРёС†РёР°Р»РёР·Р°С†РёРё DNS РєР»РёРµРЅС‚Р°: {}", e))?;
        let response = resolver.lookup_ip(&domain).map_err(|e| format!("РЎР±РѕР№ СЂРµР·РѕР»РІРёРЅРіР° (РІРѕР·РјРѕР¶РЅРѕ DNS РЅРµРґРѕСЃС‚СѓРїРµРЅ РёР»Рё РґРѕРјРµРЅ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ РЅР° СѓСЂРѕРІРЅРµ DNS): {}", e))?;
        let resolved = response.iter().next().ok_or("РљР°СЃС‚РѕРјРЅС‹Р№ DNS РЅРµ РІРµСЂРЅСѓР» IP Р°РґСЂРµСЃР°!")?;
        resolved_ip = resolved;
    }

    // РџРѕРґРјРµРЅСЏРµРј IP РІ Р·Р°РїСЂРѕСЃРµ Рє reqwest (СЌРјРёС‚РёСЂСѓРµРј Host Р·Р°РіРѕР»РѕРІРѕРє)
    let client = Client::builder()
        .resolve(&domain, SocketAddr::new(resolved_ip, 443))
        .resolve(&domain, SocketAddr::new(resolved_ip, 80))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get(&target_url).send() {
        Ok(res) if res.status().is_success() => Ok(format!("РЈРЎРџР•РҐ (200 OK)\n DNS: {}\n Р Р°Р·СЂРµС€РµРЅРЅС‹Р№ IP: {}", dns_label, resolved_ip)),
        Ok(res) => Ok(format!("Р”РѕСЃС‚СѓРїРЅРѕ, РЅРѕ СЃС‚Р°С‚СѓСЃ: {}\n DNS: {}\n IP: {}", res.status(), dns_label, resolved_ip)),
        Err(e) => Ok(format!("РћРЁРР‘РљРђ РїРѕРґРєР»СЋС‡РµРЅРёСЏ:\n DNS: {}\n IP: {}\n РџСЂРёС‡РёРЅР°: {}", dns_label, resolved_ip, e))
    }
}