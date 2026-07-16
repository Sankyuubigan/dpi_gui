use std::net::{TcpStream, UdpSocket, SocketAddr, IpAddr};
use std::error::Error as StdError;
use std::time::Duration;
use std::sync::mpsc;
use std::thread;
use std::os::windows::process::CommandExt;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::Resolver;
use reqwest::blocking::Client;
use tauri::AppHandle;
use crate::process;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Результат классификации HTTP-проверки сайта.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HttpResult {
    Ok(u16),
    BlockPage,   // Ответ получен, но это страница-заглушка блокировки
    Dns,         // Не резолвится (DNS-цензура / NXDOMAIN)
    Rst,         // Сброс соединения (RST) — типично для DPI
    Tls,         // Ошибка TLS/рукопожатия
    Timeout,     // Таймаут
    Other(String),
}

/// Запуск потенциально зависающей операции с таймаутом.
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

/// Проверка прав администратора (WinDivert их требует).
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

/// Наличие winws.exe рядом с приложением.
pub fn winws_present() -> bool {
    process::get_bin_dir().join("winws.exe").exists()
}

/// Проверка, что драйвер WinDivert реально загружается.
/// Запускаем winws с реальным фильтром на 443 + desync и мусорным hostlist
/// (чтобы не трогать реальный трафик), и смотрим, остался ли процесс жив —
/// это и есть признак успешной загрузки драйвера.
pub fn test_windivert(_app: &AppHandle) -> (bool, String) {
    let _ = process::stop_winws();
    let bin = process::get_bin_dir().join("winws.exe");
    if !bin.exists() {
        return (false, "winws.exe не найден рядом с приложением".to_string());
    }

    // Временный hostlist с мусорным доменом — фильтр ни к чему не применится,
    // но WinDivert всё равно должен открыться.
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
        Err(e) => return (false, format!("не удалось запустить: {}", e)),
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
        (true, "драйвер загрузился, фильтрация работает".to_string())
    } else if windivert_error {
        (
            false,
            format!("ошибка загрузки WinDivert. Вывод: {}", captured.trim().lines().next().unwrap_or("")),
        )
    } else {
        (false, "winws завершился сразу при старте (драйвер не загрузился?)".to_string())
    }
}

pub struct DnsInfo {
    pub system: Vec<IpAddr>,
    pub cloudflare: Vec<IpAddr>,
    pub google: Vec<IpAddr>,
    pub err: String,
}

impl DnsInfo {
    pub fn new() -> Self {
        DnsInfo {
            system: vec![],
            cloudflare: vec![],
            google: vec![],
            err: String::new(),
        }
    }
}

fn resolve_via(domain: &str, ns: &str) -> Vec<IpAddr> {
    let mut cfg = ResolverConfig::new();
    if let Ok(addr) = ns.parse::<IpAddr>() {
        cfg.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(addr, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
    }
    if let Ok(r) = Resolver::new(cfg, ResolverOpts::default()) {
        if let Ok(resp) = r.lookup_ip(domain) {
            return resp.iter().collect();
        }
    }
    vec![]
}

/// Резолв заблокированного домена через системный DNS и два публичных.
/// Разница между ними — признак DNS-цензуры.
pub fn dns_multi(domain: &str) -> DnsInfo {
    let mut info = DnsInfo::new();

    if let Ok(r) = Resolver::from_system_conf() {
        if let Ok(resp) = r.lookup_ip(domain) {
            info.system = resp.iter().collect();
        }
    } else {
        info.err = "не удалось прочитать системный DNS".to_string();
    }

    info.cloudflare = resolve_via(domain, "1.1.1.1");
    info.google = resolve_via(domain, "8.8.8.8");
    info
}

/// Есть ли у пользователя рабочий IPv6 до целевого домена (winws только IPv4).
pub fn has_ipv6(domain: &str) -> bool {
    let addrs = resolve_via(domain, "2606:4700:4700::1111");
    if let Some(ip) = addrs.iter().find(|ip| ip.is_ipv6()).copied() {
        if TcpStream::connect_timeout(&SocketAddr::new(ip, 443), Duration::from_millis(3000)).is_ok() {
            return true;
        }
    }
    false
}

/// Классификация ошибки reqwest в понятную категорию.
/// Важно: верхний текст ошибки reqwest — это просто "error sending request for url (...)",
/// а настоящая причина (RST / timeout / TLS) спрятана в e.source(). Поэтому ходим
/// по ВСЕЙ цепочке причин через source().
pub fn classify_reqwest_err(e: &reqwest::Error) -> HttpResult {
    let mut msg = e.to_string().to_lowercase();
    let mut src: Option<&dyn std::error::Error> = e.source();
    while let Some(s) = src {
        msg.push(' ');
        msg.push_str(&s.to_string().to_lowercase());
        src = s.source();
    }
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
    } else if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("certificate")
        || msg.contains("handshake")
        || msg.contains("cert")
    {
        HttpResult::Tls
    } else if msg.contains("timed out") || msg.contains("timeout") || msg.contains("10060") {
        HttpResult::Timeout
    } else {
        HttpResult::Other(msg)
    }
}

/// HTTP/HTTPS-проверка сайта с классификацией результата.
pub fn http_classify_with(url: &str, secs: u64) -> HttpResult {
    let client = match Client::builder()
        .timeout(Duration::from_secs(secs))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return HttpResult::Other("не удалось создать HTTP-клиент".to_string()),
    };

    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..=399).contains(&status) {
                let body = resp.text().unwrap_or_default();
                let low = body.to_lowercase();
                if low.contains("роскомнадзор")
                    || low.contains("заблокир")
                    || low.contains("blocked")
                    || low.contains("access denied")
                    || low.contains("451")
                {
                    HttpResult::BlockPage
                } else {
                    HttpResult::Ok(status)
                }
            } else if status == 403 || status == 451 {
                HttpResult::BlockPage
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

/// Сырое TCP-соединение к IP:port без TLS — различает RST / таймаут / успех.
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

/// Best-effort проверка фильтрации UDP/QUIC на порту 443.
pub fn quic_probe(ip: IpAddr) -> String {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => return format!("send-error: {}", e),
    };
    sock.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    // Минимальный QUIC Initial (флаг 0xC0 + version + DCID) — только чтобы
    // спровоцировать ответ/фильтрацию, точный парсинг не важен.
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
        Err(_) => "no-response (фильтрация UDP/443 возможна)".to_string(),
    }
}

/// Нормализация URL/домена в чистый хост.
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
