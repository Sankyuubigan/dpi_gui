use std::net::{TcpStream, UdpSocket, SocketAddr, IpAddr};
use std::error::Error as StdError;
use std::time::Duration;
use std::sync::mpsc;
use std::thread;
use std::os::windows::process::CommandExt;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::Resolver;
use reqwest::blocking::Client;
use tauri::AppHandle;
use crate::process;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Р РµР·СѓР»СЊС‚Р°С‚ РєР»Р°СЃСЃРёС„РёРєР°С†РёРё HTTP-РїСЂРѕРІРµСЂРєРё СЃР°Р№С‚Р°.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpResult {
    Ok(u16),
    BlockPage,   // РћС‚РІРµС‚ РїРѕР»СѓС‡РµРЅ, РЅРѕ СЌС‚Рѕ СЃС‚СЂР°РЅРёС†Р°-Р·Р°РіР»СѓС€РєР° Р±Р»РѕРєРёСЂРѕРІРєРё
    Dns,         // РќРµ СЂРµР·РѕР»РІРёС‚СЃСЏ (DNS-С†РµРЅР·СѓСЂР° / NXDOMAIN)
    Rst,         // РЎР±СЂРѕСЃ СЃРѕРµРґРёРЅРµРЅРёСЏ (RST) вЂ” С‚РёРїРёС‡РЅРѕ РґР»СЏ DPI
    Tls,         // РћС€РёР±РєР° TLS/СЂСѓРєРѕРїРѕР¶Р°С‚РёСЏ
    BadCert,     // TLS РїСЂРѕС€С‘Р», РЅРѕ СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ РґР»СЏ РёРјРµРЅРё (NET::ERR_CERT_*)
    Timeout,     // РўР°Р№РјР°СѓС‚
    Other(String),
}

/// Р—Р°РїСѓСЃРє РїРѕС‚РµРЅС†РёР°Р»СЊРЅРѕ Р·Р°РІРёСЃР°СЋС‰РµР№ РѕРїРµСЂР°С†РёРё СЃ С‚Р°Р№РјР°СѓС‚РѕРј.
pub fn run_with_timeout<F, T>(f: F, ms: u64) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let r = f();
        let _ = tx.send(r);
    });
    match rx.recv_timeout(Duration::from_millis(ms)) {
        Ok(r) => Some(r),
        Err(_) => {
            let _ = handle.join();
            None
        }
    }
}

/// РџСЂРѕРІРµСЂРєР° РїСЂР°РІ Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° (WinDivert РёС… С‚СЂРµР±СѓРµС‚).
pub fn check_admin() -> bool {
    let res = run_with_timeout(
        || {
            std::process::Command::new("cmd")
                .args(["/C", "net", "session"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        },
        5000,
    );
    res.unwrap_or(false)
}

/// РќР°Р»РёС‡РёРµ winws.exe СЂСЏРґРѕРј СЃ РїСЂРёР»РѕР¶РµРЅРёРµРј.
pub fn winws_present() -> bool {
    process::get_bin_dir().join("winws.exe").exists()
}

/// РџСЂРѕРІРµСЂРєР°, С‡С‚Рѕ РґСЂР°Р№РІРµСЂ WinDivert СЂРµР°Р»СЊРЅРѕ Р·Р°РіСЂСѓР¶Р°РµС‚СЃСЏ.
/// Р—Р°РїСѓСЃРєР°РµРј winws СЃ СЂРµР°Р»СЊРЅС‹Рј С„РёР»СЊС‚СЂРѕРј РЅР° 443 + desync Рё РјСѓСЃРѕСЂРЅС‹Рј hostlist
/// (С‡С‚РѕР±С‹ РЅРµ С‚СЂРѕРіР°С‚СЊ СЂРµР°Р»СЊРЅС‹Р№ С‚СЂР°С„РёРє), Рё СЃРјРѕС‚СЂРёРј, РѕСЃС‚Р°Р»СЃСЏ Р»Рё РїСЂРѕС†РµСЃСЃ Р¶РёРІ вЂ”
/// СЌС‚Рѕ Рё РµСЃС‚СЊ РїСЂРёР·РЅР°Рє СѓСЃРїРµС€РЅРѕР№ Р·Р°РіСЂСѓР·РєРё РґСЂР°Р№РІРµСЂР°.
pub fn test_windivert(_app: &AppHandle) -> (bool, String) {
    let _ = process::stop_winws();
    let bin = process::get_bin_dir().join("winws.exe");
    if !bin.exists() {
        return (false, "winws.exe РЅРµ РЅР°Р№РґРµРЅ СЂСЏРґРѕРј СЃ РїСЂРёР»РѕР¶РµРЅРёРµРј".to_string());
    }

    // Р’СЂРµРјРµРЅРЅС‹Р№ hostlist СЃ РјСѓСЃРѕСЂРЅС‹Рј РґРѕРјРµРЅРѕРј вЂ” С„РёР»СЊС‚СЂ РЅРё Рє С‡РµРјСѓ РЅРµ РїСЂРёРјРµРЅРёС‚СЃСЏ,
    // РЅРѕ WinDivert РІСЃС‘ СЂР°РІРЅРѕ РґРѕР»Р¶РµРЅ РѕС‚РєСЂС‹С‚СЊСЃСЏ.
    let lists_dir = crate::config::get_app_dir().join("lists");
    let _ = std::fs::write(lists_dir.join("diag-windivert.txt"), "nonexistent.invalid\n");
    let lists_str = lists_dir.to_string_lossy().replace("\\", "/");

    let mut child = match std::process::Command::new(&bin)
        .args([
            "--filter-tcp=443",
            &format!("--hostlist={}/diag-windivert.txt", lists_str),
            "--dpi-desync=fake",
            "--dpi-desync-repeats=1",
        ])
        .current_dir(process::get_bin_dir())
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("РЅРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РїСѓСЃС‚РёС‚СЊ: {}", e)),
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let mut buf = String::new();
        use std::io::BufRead;
        if let Some(s) = stdout {
            for line in std::io::BufReader::new(s).lines().flatten() {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        if let Some(s) = stderr {
            for line in std::io::BufReader::new(s).lines().flatten() {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        let _ = tx.send(buf);
    });

    thread::sleep(Duration::from_millis(2500));

    let alive = matches!(child.try_wait(), Ok(None));
    let _ = child.kill();
    let captured = rx.try_recv().unwrap_or_default();

    let low = captured.to_lowercase();
    let windivert_error = low.contains("windivertopen")
        || low.contains("failed to open")
        || low.contains("access is denied")
        || low.contains("cannot open");

    if alive && !windivert_error {
        (true, "РґСЂР°Р№РІРµСЂ Р·Р°РіСЂСѓР·РёР»СЃСЏ, С„РёР»СЊС‚СЂР°С†РёСЏ СЂР°Р±РѕС‚Р°РµС‚".to_string())
    } else if windivert_error {
        (
            false,
            format!("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё WinDivert. Р’С‹РІРѕРґ: {}", captured.trim().lines().next().unwrap_or("")),
        )
    } else {
        (false, "winws Р·Р°РІРµСЂС€РёР»СЃСЏ СЃСЂР°Р·Сѓ РїСЂРё СЃС‚Р°СЂС‚Рµ (РґСЂР°Р№РІРµСЂ РЅРµ Р·Р°РіСЂСѓР·РёР»СЃСЏ?)".to_string())
    }
}

/// РС‚РѕРі РѕРґРЅРѕРіРѕ DNS-Р·Р°РїСЂРѕСЃР°. Р Р°Р·Р»РёС‡Р°РµРј В«РґРѕРјРµРЅ РЅРµ СЃСѓС‰РµСЃС‚РІСѓРµС‚В» Рё В«СЂРµР·РѕР»РІРµСЂ РЅРµ
/// РѕС‚РІРµС‚РёР»В»: РІ СЂРѕСЃСЃРёР№СЃРєРёС… СЃРµС‚СЏС… UDP:53 РґРѕ 1.1.1.1/8.8.8.8 С‡Р°СЃС‚Рѕ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ,
/// Рё СЂР°РЅСЊС€Рµ СЌС‚Рѕ РјРѕР»С‡Р° РїРѕРєР°Р·С‹РІР°Р»РѕСЃСЊ РєР°Рє В«(РїСѓСЃС‚Рѕ)В», С…РѕС‚СЏ РЅР° СЃР°РјРѕРј РґРµР»Рµ Р°РґСЂРµСЃР°
/// РјРѕРіР»Рё СЃСѓС‰РµСЃС‚РІРѕРІР°С‚СЊ вЂ” РїСЂРѕСЃС‚Рѕ СЂРµР·РѕР»РІРµСЂ РЅРµ Р±С‹Р» РґРѕСЃС‚РёР¶РёРј.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsState {
    #[default]
    Ok,
    /// NXDOMAIN вЂ” РґРѕРјРµРЅ РЅРµ СЃСѓС‰РµСЃС‚РІСѓРµС‚.
    Nxdomain,
    /// Р РµР·РѕР»РІРµСЂ РЅРµ РѕС‚РІРµС‚РёР» (С‚Р°Р№РјР°СѓС‚ / Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ / РѕР±СЂС‹РІ).
    Unreachable,
}

#[derive(Debug, Default)]
pub struct DnsLookup {
    pub ips: Vec<IpAddr>,
    pub state: DnsState,
}

#[derive(Debug)]
pub struct DnsInfo {
    pub system: Vec<IpAddr>,
    pub cloudflare: Vec<IpAddr>,
    pub google: Vec<IpAddr>,
    pub err: String,
    /// РЎРѕСЃС‚РѕСЏРЅРёРµ РєР°Р¶РґРѕРіРѕ СЂРµР·РѕР»РІРµСЂР°, С‡С‚РѕР±С‹ РѕС‚С‡С‘С‚ РЅРµ РїСѓС‚Р°Р» NXDOMAIN СЃ Р±Р»РѕРєРёСЂРѕРІРєРѕР№ UDP:53.
    pub system_state: DnsState,
    pub cloudflare_state: DnsState,
    pub google_state: DnsState,
}

impl DnsInfo {
    pub fn new() -> Self {
        DnsInfo {
            system: vec![],
            cloudflare: vec![],
            google: vec![],
            err: String::new(),
            system_state: DnsState::default(),
            cloudflare_state: DnsState::default(),
            google_state: DnsState::default(),
        }
    }
}

fn resolve_via_full(domain: &str, ns: &str) -> DnsLookup {
    let mut cfg = ResolverConfig::new();
    if let Ok(addr) = ns.parse::<IpAddr>() {
        cfg.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(addr, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        });
    }
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;
    match Resolver::new(cfg, opts) {
        Ok(r) => match r.lookup_ip(domain) {
            Ok(resp) => DnsLookup {
                ips: resp.iter().collect(),
                state: DnsState::Ok,
            },
            Err(e) => DnsLookup {
                ips: vec![],
                state: match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => DnsState::Nxdomain,
                    _ => DnsState::Unreachable,
                },
            },
        },
        Err(_) => DnsLookup {
            ips: vec![],
            state: DnsState::Unreachable,
        },
    }
}

fn resolve_system_full(domain: &str) -> DnsLookup {
    match Resolver::from_system_conf() {
        Ok(r) => match r.lookup_ip(domain) {
            Ok(resp) => DnsLookup {
                ips: resp.iter().collect(),
                state: DnsState::Ok,
            },
            Err(e) => DnsLookup {
                ips: vec![],
                state: match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => DnsState::Nxdomain,
                    _ => DnsState::Unreachable,
                },
            },
        },
        Err(_) => DnsLookup {
            ips: vec![],
            state: DnsState::Unreachable,
        },
    }
}

fn resolve_via(domain: &str, ns: &str) -> Vec<IpAddr> {
    resolve_via_full(domain, ns).ips
}

fn resolve_system(domain: &str) -> Vec<IpAddr> {
    resolve_system_full(domain).ips
}

/// Р РµР·РѕР»РІ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅРЅРѕРіРѕ РґРѕРјРµРЅР° С‡РµСЂРµР· СЃРёСЃС‚РµРјРЅС‹Р№ DNS Рё РґРІР° РїСѓР±Р»РёС‡РЅС‹С….
/// Р Р°Р·РЅРёС†Р° РјРµР¶РґСѓ РЅРёРјРё вЂ” РїСЂРёР·РЅР°Рє DNS-С†РµРЅР·СѓСЂС‹.
/// Р РµР·РѕР»РІС‹ РІС‹РїРѕР»РЅСЏСЋС‚СЃСЏ РїР°СЂР°Р»Р»РµР»СЊРЅРѕ, РєР°Р¶РґС‹Р№ вЂ” СЃ Р¶С‘СЃС‚РєРёРј С‚Р°Р№РјР°СѓС‚РѕРј, С‡С‚РѕР±С‹
/// РЅРµРґРѕСЃС‚СѓРїРЅС‹Р№ РїСѓР±Р»РёС‡РЅС‹Р№ DNS РЅРµ РІРµС€Р°Р» РґРёР°РіРЅРѕСЃС‚РёРєСѓ РЅР° РґРµСЃСЏС‚РєРё СЃРµРєСѓРЅРґ.
pub fn dns_multi(domain: &str) -> DnsInfo {
    let mut info = DnsInfo::new();

    let (tx, rx) = mpsc::channel();

    let d = domain.to_string();
    let t = tx.clone();
    thread::spawn(move || {
        let _ = t.send(("sys", resolve_system_full(&d)));
    });
    let d = domain.to_string();
    let t = tx.clone();
    thread::spawn(move || {
        let _ = t.send(("cf", resolve_via_full(&d, "1.1.1.1")));
    });
    let d = domain.to_string();
    thread::spawn(move || {
        let _ = tx.send(("gg", resolve_via_full(&d, "8.8.8.8")));
    });

    // Р–РґС‘Рј РєР°Р¶РґС‹Р№ СЂРµР·РѕР»РІ СЃ Р¶С‘СЃС‚РєРёРј С‚Р°Р№РјР°СѓС‚РѕРј. Р—Р°РІРёСЃС€РёР№ DNS Р¶РёРІС‘С‚ РІ С„РѕРЅРµ Рё РЅРµ
    // Р±Р»РѕРєРёСЂСѓРµС‚ РґРёР°РіРЅРѕСЃС‚РёРєСѓ.
    let mut got = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while got < 3 {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((kind, res)) => {
                match kind {
                    "sys" => {
                        info.system_state = res.state;
                        info.system = res.ips;
                    }
                    "cf" => {
                        info.cloudflare_state = res.state;
                        info.cloudflare = res.ips;
                    }
                    _ => {
                        info.google_state = res.state;
                        info.google = res.ips;
                    }
                }
                got += 1;
            }
            Err(_) => break,
        }
    }

    if info.system.is_empty() && info.cloudflare.is_empty() && info.google.is_empty() {
        info.err = "РЅРё СЃРёСЃС‚РµРјРЅС‹Р№, РЅРё РїСѓР±Р»РёС‡РЅС‹Рµ DNS РЅРµ РІРµСЂРЅСѓР»Рё Р°РґСЂРµСЃ".to_string();
    }

    info
}

/// DoH-СЃРµСЂРІРёСЃС‹ РґР»СЏ РїСЂРѕРІРµСЂРєРё В«РїРѕРґРјРµРЅС‹ DNSВ»: РІРѕР·РІСЂР°С‰Р°СЋС‚ РЅР°СЃС‚РѕСЏС‰РёРµ IP РІ РѕР±С…РѕРґ
/// РѕС‚СЂР°РІР»РµРЅРЅРѕРіРѕ/РїРµСЂРµС…РІР°С‡РµРЅРЅРѕРіРѕ DNS. РСЃРїРѕР»СЊР·СѓСЋС‚СЃСЏ Рё РІ С‚РµСЃС‚Рµ РїРѕРґРјРµРЅС‹ DNS, Рё РІ
/// Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРѕР№ РїСЂРѕРІРµСЂРєРµ РїСЂРё Р°РЅР°Р»РёР·Рµ РґРѕРјРµРЅРѕРІ.
pub const DOH_RESOLVERS: &[&str] = &["xbox-dns.ru", "geohide.ru"];

/// Р РµР·РѕР»РІРёС‚ С…РѕСЃС‚ DoH-СЃРµСЂРІРµСЂР° (Р±СѓС‚СЃС‚СЂР°Рї): СЃРЅР°С‡Р°Р»Р° СЃРёСЃС‚РµРјРЅС‹Р№ DNS, РїСЂРё РЅРµСѓРґР°С‡Рµ вЂ”
/// РїСѓР±Р»РёС‡РЅС‹Р№ 1.1.1.1 (UDP). Р‘РµР· РЅРµРіРѕ РЅРµР»СЊР·СЏ СѓР·РЅР°С‚СЊ IP, РЅР° РєРѕС‚РѕСЂС‹Р№ Https-РєР»РёРµРЅС‚
/// trust-dns РґРѕР»Р¶РµРЅ РёРґС‚Рё РїРѕ 443.
fn bootstrap_doh_host(host: &str) -> Vec<IpAddr> {
    let mut ips = resolve_system(host);
    if ips.is_empty() {
        ips = resolve_via(host, "1.1.1.1");
    }
    ips
}

/// Р РµР·РѕР»РІ РґРѕРјРµРЅР° С‡РµСЂРµР· DNS-over-HTTPS (RFC 8484, РїСѓС‚СЊ `/dns-query`).
/// `doh_host` вЂ” РёРјСЏ DoH-СЃРµСЂРІРёСЃР° (РЅР°РїСЂРёРјРµСЂ, "geohide.ru"). Р‘СѓС‚СЃС‚СЂР°Рї С…РѕСЃС‚Р°
/// РґРµР»Р°РµС‚СЃСЏ СЃРёСЃС‚РµРјРЅС‹Рј DNS (fallback 1.1.1.1), Р·Р°С‚РµРј Р·Р°РїСЂРѕСЃ СѓС…РѕРґРёС‚ РїРѕ HTTPS.
/// Р’С‹РїРѕР»РЅСЏРµС‚СЃСЏ СЃ Р¶С‘СЃС‚РєРёРј С‚Р°Р№РјР°СѓС‚РѕРј РІРЅСѓС‚СЂРё РїРѕС‚РѕРєР° вЂ” Р·Р°РІРёСЃС€РёР№ DoH РЅРµ РІРµС€Р°РµС‚ РІС‹Р·РѕРІ.
pub fn resolve_via_doh(domain: &str, doh_host: &str) -> Vec<IpAddr> {
    let bootstrap = bootstrap_doh_host(doh_host);
    if bootstrap.is_empty() {
        return vec![];
    }

    let mut cfg = ResolverConfig::new();
    for ip in bootstrap {
        cfg.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, 443),
            protocol: Protocol::Https,
            tls_dns_name: Some(doh_host.to_string()),
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        });
    }
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 1;

    let domain = domain.to_string();
    run_with_timeout(
        move || {
            if let Ok(r) = Resolver::new(cfg, opts) {
                if let Ok(resp) = r.lookup_ip(&domain) {
                    let ips: Vec<IpAddr> = resp.iter().collect();
                    if !ips.is_empty() {
                        return ips;
                    }
                }
            }
            vec![]
        },
        8000,
    )
    .unwrap_or_default()
}

/// Р•СЃС‚СЊ Р»Рё Сѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ СЂР°Р±РѕС‡РёР№ IPv6 РґРѕ С†РµР»РµРІРѕРіРѕ РґРѕРјРµРЅР° (winws С‚РѕР»СЊРєРѕ IPv4).
pub fn has_ipv6(domain: &str) -> bool {
    let addrs = resolve_via(domain, "2606:4700:4700::1111");
    if let Some(ip) = addrs.iter().find(|ip| ip.is_ipv6()).copied() {
        if TcpStream::connect_timeout(&SocketAddr::new(ip, 443), Duration::from_millis(3000)).is_ok() {
            return true;
        }
    }
    false
}

/// РљР»Р°СЃСЃРёС„РёРєР°С†РёСЏ РѕС€РёР±РєРё reqwest РІ РїРѕРЅСЏС‚РЅСѓСЋ РєР°С‚РµРіРѕСЂРёСЋ.
/// Р’Р°Р¶РЅРѕ: РІРµСЂС…РЅРёР№ С‚РµРєСЃС‚ РѕС€РёР±РєРё reqwest вЂ” СЌС‚Рѕ РїСЂРѕСЃС‚Рѕ "error sending request for url (...)",
/// Р° РЅР°СЃС‚РѕСЏС‰Р°СЏ РїСЂРёС‡РёРЅР° (RST / timeout / TLS) СЃРїСЂСЏС‚Р°РЅР° РІ e.source(). РџРѕСЌС‚РѕРјСѓ С…РѕРґРёРј
/// РїРѕ Р’РЎР•Р™ С†РµРїРѕС‡РєРµ РїСЂРёС‡РёРЅ С‡РµСЂРµР· source().
pub fn classify_reqwest_err(e: &reqwest::Error) -> HttpResult {
    let mut msg = e.to_string().to_lowercase();
    let mut src: Option<&dyn std::error::Error> = e.source();
    while let Some(s) = src {
        msg.push(' ');
        msg.push_str(&s.to_string().to_lowercase());
        src = s.source();
    }
    classify_err_text(&msg)
}

/// РљР»Р°СЃСЃРёС„РёРєР°С†РёСЏ РїРѕ С‚РµРєСЃС‚Сѓ РѕС€РёР±РєРё вЂ” С‡РёСЃС‚Р°СЏ С„СѓРЅРєС†РёСЏ, РїРѕРєСЂС‹С‚Р° СЋРЅРёС‚-С‚РµСЃС‚Р°РјРё.
/// РџРѕСЂСЏРґРѕРє РІР°Р¶РµРЅ: СЃРµСЂС‚РёС„РёРєР°С‚РЅС‹Рµ РѕС€РёР±РєРё Р»РѕРІРёРј Р”Рћ РѕР±С‰РёС… tls/ssl/handshake.
pub fn classify_err_text(msg: &str) -> HttpResult {
    if msg.contains("dns")
        || msg.contains("resolve")
        || msg.contains("name or service")
        || msg.contains("no address")
        || msg.contains("nxdomain")
    {
        HttpResult::Dns
    } else if msg.contains("reset")
        || msg.contains("connection closed")
        || msg.contains("connection reset")
        || msg.contains("10054")
        || msg.contains("10061")
    {
        HttpResult::Rst
    } else if msg.contains("certificate")
        || msg.contains("peer certificate")
        || msg.contains("not valid for")
        || msg.contains("issuer")
        || msg.contains("invalid peer")
        || msg.contains("x509")
        || msg.contains("common name")
        || msg.contains("cert")
        // Windows schannel РѕС‚РґР°С‘С‚ Р»РѕРєР°Р»РёР·РѕРІР°РЅРЅС‹Рµ С‚РµРєСЃС‚С‹ Рё CERT_E_* РєРѕРґС‹.
        || msg.contains("СЃРµСЂС‚РёС„РёРєР°С‚")
        || msg.contains("РЅРµ СЃРѕРІРїР°РґР°РµС‚")
        || msg.contains("0x800b010")
        || msg.contains("-21467624")
    {
        HttpResult::BadCert
    } else if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("handshake")
        || msg.contains("СЂСѓРєРѕРїРѕР¶Р°С‚РёРµ")
    {
        HttpResult::Tls
    } else if msg.contains("timed out") || msg.contains("timeout") || msg.contains("10060") {
        HttpResult::Timeout
    } else {
        HttpResult::Other(msg.to_string())
    }
}

/// HTTP/HTTPS-РїСЂРѕРІРµСЂРєР° СЃР°Р№С‚Р° СЃ РєР»Р°СЃСЃРёС„РёРєР°С†РёРµР№ СЂРµР·СѓР»СЊС‚Р°С‚Р°.
pub fn http_classify_with(url: &str, secs: u64) -> HttpResult {
    let client = match Client::builder()
        .timeout(Duration::from_secs(secs))
        .build()
    {
        Ok(c) => c,
        Err(_) => return HttpResult::Other("РЅРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ HTTP-РєР»РёРµРЅС‚".to_string()),
    };

    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 403 || status == 451 {
                return HttpResult::BlockPage;
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if low.contains("СЂРѕСЃРєРѕРјРЅР°РґР·РѕСЂ")
                    || low.contains("Р·Р°Р±Р»РѕРєРёСЂ")
                    || low.contains("this site is blocked")
                    || low.contains("access denied: by order")
                    || low.contains("СЃС‚СЂР°РЅРёС†Р° РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РѕС‚РѕР±СЂР°Р¶РµРЅР°")
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

pub fn http_classify(url: &str) -> HttpResult {
    http_classify_with(url, 6)
}

/// РЎС‹СЂРѕРµ TCP-СЃРѕРµРґРёРЅРµРЅРёРµ Рє IP:port Р±РµР· TLS вЂ” СЂР°Р·Р»РёС‡Р°РµС‚ RST / С‚Р°Р№РјР°СѓС‚ / СѓСЃРїРµС….
pub fn tcp_connect(ip: IpAddr, port: u16) -> String {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, Duration::from_millis(3500)) {
        Ok(_) => "Success".to_string(),
        Err(e) => match e.raw_os_error() {
            Some(10054) | Some(10061) | Some(10056) => "RST/REFUSED".to_string(),
            Some(10060) | Some(10053) => "Timeout".to_string(),
            _ => format!("Other({})", e),
        },
    }
}

/// Best-effort РїСЂРѕРІРµСЂРєР° С„РёР»СЊС‚СЂР°С†РёРё UDP/QUIC РЅР° РїРѕСЂС‚Сѓ 443.
pub fn quic_probe(ip: IpAddr) -> String {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => return format!("send-error: {}", e),
    };
    sock.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    // РњРёРЅРёРјР°Р»СЊРЅС‹Р№ QUIC Initial (С„Р»Р°Рі 0xC0 + version + DCID) вЂ” С‚РѕР»СЊРєРѕ С‡С‚РѕР±С‹
    // СЃРїСЂРѕРІРѕС†РёСЂРѕРІР°С‚СЊ РѕС‚РІРµС‚/С„РёР»СЊС‚СЂР°С†РёСЋ, С‚РѕС‡РЅС‹Р№ РїР°СЂСЃРёРЅРі РЅРµ РІР°Р¶РµРЅ.
    let payload: [u8; 21] = [
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, b't', b'e', b's', b't', 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let addr = SocketAddr::new(ip, 443);
    if sock.send_to(&payload, addr).is_err() {
        return "send-error".to_string();
    }
    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok(_) => "responded".to_string(),
        Err(_) => "no-response (С„РёР»СЊС‚СЂР°С†РёСЏ UDP/443 РІРѕР·РјРѕР¶РЅР°)".to_string(),
    }
}

/// РќРѕСЂРјР°Р»РёР·Р°С†РёСЏ URL/РґРѕРјРµРЅР° РІ С‡РёСЃС‚С‹Р№ С…РѕСЃС‚.
pub fn normalize_host(input: &str) -> String {
    let u = if input.starts_with("http") {
        input.to_string()
    } else {
        format!("https://{}", input)
    };
    match url::Url::parse(&u) {
        Ok(p) => p.host_str().unwrap_or(input).to_string(),
        Err(_) => input.trim_end_matches('/').to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_errors() {
        assert_eq!(classify_err_text("dns error"), HttpResult::Dns);
        assert_eq!(classify_err_text("unable to resolve host"), HttpResult::Dns);
        assert_eq!(classify_err_text("no address found"), HttpResult::Dns);
        assert_eq!(classify_err_text("nxdomain"), HttpResult::Dns);
    }

    #[test]
    fn rst_errors() {
        assert_eq!(classify_err_text("connection reset by peer"), HttpResult::Rst);
        assert_eq!(classify_err_text("connection closed before message completed"), HttpResult::Rst);
        assert_eq!(classify_err_text("os error 10054"), HttpResult::Rst);
        assert_eq!(classify_err_text("os error 10061"), HttpResult::Rst);
    }

    #[test]
    fn bad_cert_errors() {
        // РўРѕС‚ СЃР°РјС‹Р№ СЃР»СѓС‡Р°Р№: NET::ERR_CERT_COMMON_NAME_INVALID.
        assert_eq!(classify_err_text("invalid peer certificate: NotValidForName"), HttpResult::BadCert);
        assert_eq!(classify_err_text("certificate is not valid for 'pornolab.net'"), HttpResult::BadCert);
        assert_eq!(classify_err_text("the certificate doesn't match common name"), HttpResult::BadCert);
        assert_eq!(classify_err_text("unable to get local issuer certificate"), HttpResult::BadCert);
        assert_eq!(classify_err_text("x509: certificate signed by unknown authority"), HttpResult::BadCert);
        // Windows schannel: Р»РѕРєР°Р»РёР·РѕРІР°РЅРЅР°СЏ РїСЂРёС‡РёРЅР° + РєРѕРґ CERT_E_CN_NO_MATCH.
        assert_eq!(classify_err_text("client error (connect) cn-РёРјСЏ СЃРµСЂС‚РёС„РёРєР°С‚Р° РЅРµ СЃРѕРІРїР°РґР°РµС‚ СЃ РїРѕР»СѓС‡РµРЅРЅС‹Рј Р·РЅР°С‡РµРЅРёРµРј. (os error -2146762481)"), HttpResult::BadCert);
        // РћР±С‰Р°СЏ TLS-РѕС€РёР±РєР° Р‘Р•Р— СѓРїРѕРјРёРЅР°РЅРёСЏ СЃРµСЂС‚РёС„РёРєР°С‚Р° вЂ” РѕСЃС‚Р°С‘С‚СЃСЏ Tls.
        assert_eq!(classify_err_text("tls handshake failure"), HttpResult::Tls);
        assert_eq!(classify_err_text("ssl protocol error"), HttpResult::Tls);
    }

    #[test]
    fn timeout_and_other() {
        assert_eq!(classify_err_text("operation timed out"), HttpResult::Timeout);
        assert_eq!(classify_err_text("os error 10060"), HttpResult::Timeout);
        assert_eq!(classify_err_text("С‡С‚Рѕ-С‚Рѕ РЅРµРІРµРґРѕРјРѕРµ"), HttpResult::Other("С‡С‚Рѕ-С‚Рѕ РЅРµРІРµРґРѕРјРѕРµ".to_string()));
    }
}
