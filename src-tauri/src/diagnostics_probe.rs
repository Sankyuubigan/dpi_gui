use std::collections::HashSet;
use std::net::{TcpStream, UdpSocket, SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
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
use crate::config;
use crate::process;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Результат классификации HTTP-проверки сайта.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpResult {
    Ok(u16),
    BlockPage,   // Ответ с явными маркерами блокировки в теле (подставил оператор)
    /// Голый отказ сервера (403/451 без маркеров блокировки в теле).
    /// Это НЕ обязательно цензура провайдера: так же отвечает сам сервер
    /// при региональном ограничении (гео-блок). Выдавать его за «страницу
    /// блокировки провайдера» было прямой ложью (кейс cohere: с VPN работает).
    Forbidden(u16),
    /// Сайт вернул живой HTTP-ответ (2xx/3xx), но в теле страницы сам сервис
    /// сообщает об ограничении доступа (регион источника, доступность).
    /// Сеть в порядке — ограничивает сам сервис; на вердикт «открыт» это
    /// смотреть нельзя (кейс AI-студий: 200 «открывается», пользы нет).
    ServiceRestrict,
    Dns,         // Не резолвится (DNS-цензура / NXDOMAIN)
    Rst,         // Сброс соединения (RST) — типично для DPI
    Tls,         // Ошибка TLS/рукопожатия
    BadCert,     // TLS прошёл, но сертификат невалиден для имени (NET::ERR_CERT_*)
    Timeout,     // Таймаут
    Other(String),
}

/// Адрес-заглушка в ответе резолвера: такой ответ означает «заблокировано»,
/// а не адрес сайта. Попадание заглушки в список «проверенных» и в TCP-пробы
/// давало ложь вида «IP через DoH (проверенные): 0.0.0.0».
pub fn is_stub_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_unspecified()
                || v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                // CGNAT 100.64/10 — в публичном DNS такому делать нечего.
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            v.is_unspecified() || v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Маркеры подставленной страницы блокировки в теле ответа.
/// Единственный источник правды (core rules §2.1): обе HTTP-классификации
/// (`http_classify_with` здесь и `http_via_ip` в site_probe) читают отсюда,
/// а не держат каждая свой список.
pub fn body_looks_like_blockpage(low_text: &str) -> bool {
    low_text.contains("роскомнадзор")
        || low_text.contains("заблокир")
        || low_text.contains("this site is blocked")
        || low_text.contains("access denied: by order")
        || low_text.contains("страница не может быть отображена")
}

/// Маркеры регионального ограничения В ТЕЛЕ живой 200-страницы.
/// Единственный источник правды (core rules §2.1), как и blockpage-маркеры:
/// сканер тела живёт здесь, потребители — site_probe и отчёт. Только общие
/// фразы (core §2.9): конкретные имена сервисов в движок не вписываются.
pub fn body_looks_region_restricted(low_text: &str) -> bool {
    low_text.contains("not available in your country")
        || low_text.contains("not available in your region")
        || low_text.contains("not available in your area")
        || low_text.contains("unavailable in your region")
        || low_text.contains("not supported in your region")
        || low_text.contains("location is not supported")
        || low_text.contains("your region is not supported")
        || low_text.contains("country is not supported")
        || low_text.contains("not available from your location")
        || low_text.contains("недоступен в вашем регионе")
        || low_text.contains("не поддерживается для вашего региона")
        || low_text.contains("ограничен для вашего региона")
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

/// Итог одного DNS-запроса. Различаем «домен не существует» и «резолвер не
/// ответил»: в российских сетях UDP:53 до 1.1.1.1/8.8.8.8 часто заблокирован,
/// и раньше это молча показывалось как «(пусто)», хотя на самом деле адреса
/// могли существовать — просто резолвер не был достижим.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsState {
    #[default]
    Ok,
    /// NXDOMAIN — домен не существует.
    Nxdomain,
    /// Резолвер не ответил (таймаут / заблокирован / обрыв).
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
    /// Состояние каждого резолвера, чтобы отчёт не путал NXDOMAIN с блокировкой UDP:53.
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

pub fn resolve_system(domain: &str) -> Vec<IpAddr> {
    resolve_system_full(domain).ips
}

/// Резолв заблокированного домена через системный DNS и два публичных.
/// Разница между ними — признак DNS-цензуры.
/// Резолвы выполняются параллельно, каждый — с жёстким таймаутом, чтобы
/// недоступный публичный DNS не вешал диагностику на десятки секунд.
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

    // Ждём каждый резолв с жёстким таймаутом. Зависший DNS живёт в фоне и не
    // блокирует диагностику.
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
        info.err = "ни системный, ни публичные DNS не вернули адрес".to_string();
    }

    info
}

/// DoH-сервисы для проверки «подмены DNS»: возвращают настоящие IP в обход
/// отравленного/перехваченного DNS. Используются и в тесте подмены DNS, и в
/// автоматической проверке при анализе доменов.
///
/// Право правды у файла `lists/defaults/doh-services.txt` (SSOT, перезаписывается
/// при каждом старте из src-tauri/defaults/, редактируется через UI/вручную) —
/// см. `load_doh_resolvers()`. Эта
/// константа остаётся только встроенным дефолтом: она используется, когда
/// файл отсутствует или не содержит ни одной валидной записи.
pub const DOH_RESOLVERS_FALLBACK: &[&str] = &[
    "xbox-dns.ru",
    "geohide.ru",
    "eu.geohide.ru",
    "dns.comss.one",
    "dns.bezmezhau.com",
    "dns.dns-ai.ru",
];

/// Читает дефолтный список DoH-сервисов из `lists/defaults/doh-services.txt`
/// (вызывается при КАЖДОМ проходе — правки применяются без перезапуска).
///
/// Возвращает `(сервисы, warnings, config_error)`:
/// - файл не найден/нечитаем → встроенный дефолт + warning с причиной;
/// - файл прочитан, но валидных записей нет → встроенный дефолт И
///   config_error в отчёт (не молчаливое «0 адресов», core rules §2.2);
/// - нормальный случай → содержимое файла + warnings с проигнорированными
///   мусорными строками, если были.
///
/// Публично и для Tauri-команды `get_doh_services` (UI-дропдаун) — чтобы
/// fallback-логика была ровно одна, а не копия в main.rs.
pub fn load_doh_resolvers() -> (Vec<String>, Vec<String>, Option<String>) {
    let fallback: Vec<String> = DOH_RESOLVERS_FALLBACK
        .iter()
        .map(|s| s.to_string())
        .collect();
    let read = config::read_doh_services();

    if !read.file_found {
        let mut warnings = read.warnings;
        let path = config::doh_services_path();
        warnings.push(format!(
            "файл списка DoH не найден ({}), используется встроенный список по умолчанию",
            path.display()
        ));
        return (fallback, warnings, None);
    }

    if read.hosts.is_empty() {
        let path = config::doh_services_path();
        let mut warnings = read.warnings;
        let error = format!(
            "файл списка DoH-серверов ({}) прочитан, но валидных записей в нём нет — \
             используется встроенный список по умолчанию. Добавьте хосты вида \
             «https://dns.example.ru/dns-query» в этот файл.",
            path.display()
        );
        warnings.push(format!("пустой список DoH-серверов → {}", error));
        return (fallback, warnings, Some(error));
    }

    (read.hosts, read.warnings, None)
}

/// Резолвит хост DoH-сервера (бутстрап): сначала системный DNS, при неудаче —
/// публичный 1.1.1.1 (UDP). Без него нельзя узнать IP, на который Https-клиент
/// trust-dns должен идти по 443.
fn bootstrap_doh_host(host: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = resolve_system(host);
    if ips.is_empty() {
        ips = resolve_via(host, "1.1.1.1");
    }
    if ips.is_empty() {
        return Err(format!(
            "не удалось разрешить имя DoH-сервера {} ни системным DNS, ни 1.1.1.1",
            host
        ));
    }
    Ok(ips)
}

/// Резолв домена через DNS-over-HTTPS (RFC 8484, путь `/dns-query`).
/// `doh_host` — имя DoH-сервиса (например, "geohide.ru"). Бутстрап хоста
/// делается системным DNS (fallback 1.1.1.1), затем запрос уходит по HTTPS.
///
/// Основной транспорт — reqwest GET (RFC 8484 §4.1): работает со всеми
/// сервисами списка, включая те, что не отвечают trust-dns-клиенту (кейс
/// eu.geohide.ru 28.10.26: trust-dns — таймаут 9 с, GET — 0.4 с). Фолбэк —
/// trust-dns; обе причины ошибки показываются (запрет молчаливых ошибок).
pub fn resolve_via_doh(domain: &str, doh_host: &str) -> Result<Vec<IpAddr>, String> {
    let bootstrap = bootstrap_doh_host(doh_host)?;

    let domain_owned = domain.to_string();
    let svc = doh_host.to_string();
    let boot = bootstrap.clone();
    // Бюджет растёт с числом бутстрап-IP: на каждый — попытка (клиент 5 с)
    // плюс запас. Один IP → 8 с, как раньше; перебор 7 адресов (eu.geohide.ru)
    // не обрезается общим потолком раньше времени.
    let wire_ms = 3000 + 5000 * bootstrap.len() as u64;
    let wire = run_with_timeout(
        move || doh_wire_get(&svc, &domain_owned, &boot),
        wire_ms,
    )
    .unwrap_or_else(|| {
        Err(format!(
            "сервис {} не ответил за {} с (таймаут)",
            doh_host,
            wire_ms / 1000
        ))
    });

    match wire {
        Ok(ips) => Ok(ips),
        Err(wire_err) => match trust_dns_doh(domain, doh_host, bootstrap) {
            Ok(ips) => Ok(ips),
            Err(td_err) => Err(format!(
                "{}; фолбэк trust-dns: {}",
                wire_err, td_err
            )),
        },
    }
}

/// Фолбэк-транспорт: trust-dns-resolver (Protocol::Https).
fn trust_dns_doh(
    domain: &str,
    doh_host: &str,
    bootstrap: Vec<IpAddr>,
) -> Result<Vec<IpAddr>, String> {
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
    let svc = doh_host.to_string();
    run_with_timeout(
        move || {
            let resolver = Resolver::new(cfg, opts)
                .map_err(|e| format!("не удалось создать DoH-клиент: {}", e))?;
            let resp = resolver
                .lookup_ip(&domain)
                .map_err(|e| format!("запрос не выполнен: {}", e))?;
            let ips: Vec<IpAddr> = resp.iter().collect();
            if ips.is_empty() {
                return Err("сервис вернул пустой ответ".to_string());
            }
            // Заглушки (0.0.0.0 и т.п.) — это отказ резолвера, а не адреса.
            let real: Vec<IpAddr> = ips.iter().copied().filter(|ip| !is_stub_ip(ip)).collect();
            if real.is_empty() {
                return Err(format!(
                    "сервис вернул только заглушки ({})",
                    ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                ));
            }
            Ok(real)
        },
        8000,
    )
    .unwrap_or_else(|| Err(format!("сервис {} не ответил за 8 с (таймаут)", svc)))
}

/// DoH-запрос через reqwest GET (RFC 8484 §4.1): wireformat в параметре
/// `?dns=` (base64url), accept: application/dns-message. IP подставляется
/// на уровне сокета (бутстрап), имя сервиса остаётся в SNI.
///
/// Перебирает ВСЕ бутстрап-IP до первого успеха: пробовать только первый
/// (`bootstrap.first()`) — попадание в недоступный адрес валило весь сервис
/// при живых остальных (кейс eu.geohide.ru 28.10.26: 7 A-записей, ответ
/// приходит не с каждого; curl и браузер тем временем работали). При неудаче —
/// построчный список «IP — причина» (запрет молчаливых ошибок).
fn doh_wire_get(host: &str, domain: &str, bootstrap: &[IpAddr]) -> Result<Vec<IpAddr>, String> {
    let query = build_doh_wire_query(domain)?;
    let q = b64url(&query);
    try_bootstrap_ips(bootstrap, |ip| doh_wire_get_via(host, &q, ip))
}

/// Одна попытка `GET /dns-query` через конкретный бутстрап-IP (клиент
/// создаётся на попытку: адрес подставляется в resolve при сборке).
fn doh_wire_get_via(host: &str, q: &str, ip: IpAddr) -> Result<Vec<IpAddr>, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .resolve(host, SocketAddr::new(ip, 443))
        .build()
        .map_err(|e| format!("не удалось создать HTTP-клиент: {}", e))?;
    let resp = client
        .get(format!("https://{}/dns-query?dns={}", host, q))
        .header("accept", "application/dns-message")
        .send()
        .map_err(|e| format!("GET /dns-query не выполнен: {:?}", classify_reqwest_err(&e)))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("сервер ответил HTTP {}", status.as_u16()));
    }
    let body = resp
        .bytes()
        .map_err(|e| format!("не удалось прочитать ответ: {}", e))?;
    let ips = parse_doh_wire_response(&body);
    if ips.is_empty() {
        return Err(format!(
            "ответ не содержит A/AAAA-записей (HTTP {}, {} байт)",
            status.as_u16(),
            body.len()
        ));
    }
    Ok(ips)
}

/// Перебор бутстрап-IP до первого успеха. Логика попыток — чистая функция,
/// сеть остаётся в замыкании; покрыта юнит-тестами.
fn try_bootstrap_ips<F>(bootstrap: &[IpAddr], mut attempt: F) -> Result<Vec<IpAddr>, String>
where
    F: FnMut(IpAddr) -> Result<Vec<IpAddr>, String>,
{
    if bootstrap.is_empty() {
        return Err("бутстрап пуст: нет IP для попыток".to_string());
    }
    let mut fails: Vec<String> = Vec::new();
    for ip in bootstrap {
        match attempt(*ip) {
            Ok(ips) => return Ok(ips),
            Err(e) => fails.push(format!("{} — {}", ip, e)),
        }
    }
    Err(format!("все IP бутстрапа недоступны: {}", fails.join("; ")))
}

/// Wireformat-запрос A/AAAA: заголовок (ID=0, флаг RD), QNAME, QTYPE=A,
/// QCLASS=IN. Чистая функция — покрыта юнит-тестами.
pub(crate) fn build_doh_wire_query(domain: &str) -> Result<Vec<u8>, String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Err("домен пустой".to_string());
    }
    let mut q = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(format!("домен «{}» содержит пустую метку", domain));
        }
        if label.len() > 63 {
            return Err(format!("метка «{}» длиннее 63 байт", label));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    Ok(q)
}

/// base64url без паддинга (RFC 4648 §5) — для параметра `?dns=`.
pub(crate) fn b64url(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[n as usize & 63] as char);
        }
    }
    out
}

/// Разбор wireformat-ответа: только A (тип 1) и AAAA (тип 28) из секции
/// ответов. Упрощения осознаны: rcode != 0 → пусто (вызывающий код честно
/// скажет «ответ не содержит записей»), сжатие имён обрабатывается по
/// указателю, защита от зацикливания указателей — счётчиком. Чистая
/// функция — покрыта юнит-тестами на живом ответе.
pub(crate) fn parse_doh_wire_response(bytes: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if bytes.len() < 12 {
        return ips;
    }
    if bytes[3] & 0x0F != 0 {
        return ips; // rcode != NOERROR
    }
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let mut guard = 0;
        loop {
            guard += 1;
            if pos >= bytes.len() || guard > 128 {
                return ips;
            }
            let len = bytes[pos];
            pos += 1;
            if len == 0 {
                break;
            }
            pos += len as usize;
        }
        pos += 4; // QTYPE + QCLASS
    }
    for _ in 0..ancount {
        let mut guard = 0;
        loop {
            guard += 1;
            if pos >= bytes.len() || guard > 128 {
                return ips;
            }
            let len = bytes[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len as usize;
        }
        if pos + 10 > bytes.len() {
            return ips;
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > bytes.len() {
            return ips;
        }
        let rd = &bytes[pos..pos + rdlen];
        if rtype == 1 && rdlen == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])));
        } else if rtype == 28 && rdlen == 16 {
            let mut o = [0u8; 16];
            o.copy_from_slice(rd);
            ips.push(IpAddr::V6(Ipv6Addr::from(o)));
        }
        pos += rdlen;
    }
    ips
}

/// Ответ одного DoH-сервиса по домену. Сервис, который не ответил, не
/// пропадает молча: его ошибка уезжает в отчёт, иначе «0 адресов» читается
/// как «домен не существует» (core rules §2.2).
#[derive(Debug, Clone)]
pub struct DohAnswer {
    pub service: String,
    pub ips: Vec<IpAddr>,
    /// Реальная причина, по которой сервис не дал адресов.
    pub error: Option<String>,
}

/// Все ответы DoH-сервисов по домену — один сетевой проход вместо N.
#[derive(Debug, Clone, Default)]
pub struct DohAnswers {
    pub answers: Vec<DohAnswer>,
    /// Проблема конфигурации списка DoH (файл есть, но пуст) — не мешает
    /// сетевому проходу, но обязана попасть в отчёт.
    pub config_error: Option<String>,
    /// Замечания о конфигурации (мусорные строки файла, отсутствие файла
    /// при использовании встроенного дефолта). Не ошибка прохода.
    pub warnings: Vec<String>,
    /// Собственные IP-адреса DoH-сервисов (их A-записи). Обходные DoH для
    /// заблокированных имён отдают адреса СВОИХ SNI-прокси-шлюзов: проба
    /// через такой адрес даёт HTTP 200, а браузер пользователя по нему сайт
    /// не открывает. Эти адреса обязаны отличаться от адресов сайта.
    pub own_ips: Vec<(String, Vec<IpAddr>)>,
}

impl DohAnswers {
    /// Какому DoH-сервису принадлежит адрес (его собственная инфраструктура).
    /// `None` — адрес не совпадает ни с одной A-записью сервисов.
    pub fn gateway_owner(&self, ip: &IpAddr) -> Option<String> {
        self.own_ips
            .iter()
            .filter(|(_, ips)| ips.contains(ip))
            .map(|(svc, _)| svc.clone())
            .next()
    }
}

impl DohAnswers {
    /// Все адреса, которые вернул хотя бы один сервис, без дублей, в порядке
    /// появления. Пустой список означает «ни один сервис не ответил».
    /// Заглушки сюда не попадают даже при прямом конструировании `DohAnswer`.
    pub fn all_ips(&self) -> Vec<IpAddr> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for a in &self.answers {
            for ip in &a.ips {
                if is_stub_ip(ip) {
                    continue;
                }
                if seen.insert(*ip) {
                    out.push(*ip);
                }
            }
        }
        out
    }

    /// Подробности по сервисам, которые не ответили, — одной строкой на сервис.
    /// Сюда же складываются config_error (первым) и warnings из конфигурации
    /// файла списка: отчёт обязан показывать реальные причины (core rules §2.2),
    /// а вызывающий код (site_probe) менять не нужно.
    pub fn failures(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(e) = &self.config_error {
            out.push(e.clone());
        }
        for a in &self.answers {
            if let Some(e) = a.error.as_ref() {
                out.push(format!("{}: {}", a.service, e));
            }
        }
        out.extend(self.warnings.iter().cloned());
        out
    }

    /// Какие сервисы вернули данный адрес. Нужен отчёту: адрес, всплывший
    /// только у одного DoH-сервиса (и не совпавший с системным DNS) — кандидат
    /// «прокси-шлюз» этого сервиса, а не адрес сайта (кейс обходных DoH,
    /// отдающих собственные шлюзы для AI-сервисов).
    pub fn services_for_ip(&self, ip: &IpAddr) -> Vec<String> {
        self.answers
            .iter()
            .filter(|a| a.ips.iter().any(|x| x == ip))
            .map(|a| a.service.clone())
            .collect()
    }

    /// Карта «адрес → сервисы» под порядок переданного списка адресов.
    /// Адреса без сервиса (не вернул никто) в карту не попадают.
    pub fn services_map(&self, ips: &[String]) -> Vec<(String, Vec<String>)> {
        ips.iter()
            .filter_map(|s| {
                let ip: IpAddr = s.parse().ok()?;
                let svcs = self.services_for_ip(&ip);
                (!svcs.is_empty()).then(|| (s.clone(), svcs))
            })
            .collect()
    }
}

/// Резолвит домен через ВСЕ доверенные DoH-сервисы параллельно, с общим
/// жёстким дедлайном: зависший сервис не должен держать проверку.
///
/// Это единственная точка обращения к DoH за списком сервисов — и детект
/// подмены DNS, и поиск рабочего IP для hosts берут адреса отсюда, а не
/// опрашивают сервисы повторно каждый сам по себе.
pub fn resolve_doh_all(domain: &str) -> DohAnswers {
    let (services, warnings, config_error) = load_doh_resolvers();
    let (tx, rx) = mpsc::channel::<(usize, DohAnswer)>();
    let total = services.len();

    for (idx, service) in services.iter().enumerate() {
        let tx = tx.clone();
        let domain = domain.to_string();
        let service = service.to_string();
        thread::spawn(move || {
            let answer = match resolve_via_doh(&domain, &service) {
                Ok(ips) => DohAnswer {
                    service,
                    ips,
                    error: None,
                },
                Err(e) => DohAnswer {
                    service,
                    ips: vec![],
                    error: Some(e),
                },
            };
            let _ = tx.send((idx, answer));
        });
    }
    drop(tx);

    let mut slots: Vec<Option<DohAnswer>> = (0..total).map(|_| None).collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(9);
    let mut got = 0usize;
    while got < total {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((idx, answer)) => {
                if slots[idx].is_none() {
                    got += 1;
                }
                slots[idx] = Some(answer);
            }
            Err(_) => break,
        }
    }

    let answers: Vec<DohAnswer> = slots
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| {
            slot.unwrap_or_else(|| DohAnswer {
                service: services[idx].clone(),
                ips: vec![],
                error: Some("не ответил за 9 с (таймаут)".to_string()),
            })
        })
        .collect();

    // Собственные адреса сервисов резолвим тем же бутстрапом, что и DoH-запрос:
    // это A-записи имён из списка (xbox-dns.ru и т.п.). С ними отчёт отличает
    // «адрес сайта» от «адрес прокси-шлюза DoH-сервиса» (кейс openrouter.ai:
    // 80.74.30.162 — инфраструктура dns.comss.one, а не сайта).
    let own_ips = doh_own_ips(&services);

    DohAnswers {
        answers,
        config_error,
        warnings,
        own_ips,
    }
}

/// Собственные IP всех DoH-сервисов (A-записи их имён) — параллельно, с общим
/// дедлайном. Единственный источник карты «сервис → его инфраструктура»:
/// её используют и анализ (отличать адрес сайта от SNI-шлюза сервиса),
/// и проверка hosts-IP перед ручной записью.
pub fn doh_own_ips(services: &[String]) -> Vec<(String, Vec<IpAddr>)> {
    let (tx, rx) = mpsc::channel::<(String, Vec<IpAddr>)>();
    for svc in services {
        let tx = tx.clone();
        let svc = svc.clone();
        thread::spawn(move || {
            let ips = resolve_system(&svc);
            let _ = tx.send((svc, ips));
        });
    }
    drop(tx);
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut out = Vec::new();
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(deadline - std::time::Instant::now()) {
            Ok((svc, ips)) if !ips.is_empty() => out.push((svc, ips)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
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
    // URL верхней ошибки выбрасываем из текста: адрес DoH-запроса сам несёт
    // «/dns-query», и ЛЮБОЙ сбой (connect/TLS/timeout) классифицировался как
    // Dns по подстроке в адресе (кейс eu.geohide.ru 28.10.26). Реальный этап
    // ищем по цепочке source(): там «dns» встречается только у настоящих
    // DNS-сбоев.
    if let Some(url) = e.url() {
        msg = strip_url(&msg, &url.as_str().to_lowercase());
    }
    let mut src: Option<&dyn std::error::Error> = e.source();
    while let Some(s) = src {
        msg.push(' ');
        msg.push_str(&s.to_string().to_lowercase());
        src = s.source();
    }
    classify_err_text(&msg)
}

/// Убирает текст URL из сообщения об ошибке (оба аргумента — в нижнем
/// регистре). Если URL в текст не попал — сообщение без изменений.
fn strip_url(msg: &str, url_lower: &str) -> String {
    if url_lower.is_empty() || !msg.contains(url_lower) {
        return msg.to_string();
    }
    msg.replace(url_lower, " ")
}

/// Классификация по тексту ошибки — чистая функция, покрыта юнит-тестами.
/// Порядок важен: сертификатные ошибки ловим ДО общих tls/ssl/handshake.
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
        // Windows schannel отдаёт локализованные тексты и CERT_E_* коды.
        || msg.contains("сертификат")
        || msg.contains("не совпадает")
        || msg.contains("0x800b010")
        || msg.contains("-21467624")
    {
        HttpResult::BadCert
    } else if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("handshake")
        || msg.contains("рукопожатие")
    {
        HttpResult::Tls
    } else if msg.contains("timed out") || msg.contains("timeout") || msg.contains("10060") {
        HttpResult::Timeout
    } else {
        HttpResult::Other(msg.to_string())
    }
}

/// HTTP/HTTPS-проверка сайта с классификацией результата.
pub fn http_classify_with(url: &str, secs: u64) -> HttpResult {
    let client = match Client::builder()
        .timeout(Duration::from_secs(secs))
        .build()
    {
        Ok(c) => c,
        Err(_) => return HttpResult::Other("не удалось создать HTTP-клиент".to_string()),
    };

    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Голый 403/451 БЕЗ маркеров блокировки — отказ самого сервера
            // (часто региональное ограничение), а не страница провайдера.
            if status == 403 || status == 451 {
                return HttpResult::Forbidden(status);
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if body_looks_like_blockpage(&low) {
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
        // Тот самый случай: NET::ERR_CERT_COMMON_NAME_INVALID.
        assert_eq!(classify_err_text("invalid peer certificate: NotValidForName"), HttpResult::BadCert);
        assert_eq!(classify_err_text("certificate is not valid for 'pornolab.net'"), HttpResult::BadCert);
        assert_eq!(classify_err_text("the certificate doesn't match common name"), HttpResult::BadCert);
        assert_eq!(classify_err_text("unable to get local issuer certificate"), HttpResult::BadCert);
        assert_eq!(classify_err_text("x509: certificate signed by unknown authority"), HttpResult::BadCert);
        // Windows schannel: локализованная причина + код CERT_E_CN_NO_MATCH.
        assert_eq!(classify_err_text("client error (connect) cn-имя сертификата не совпадает с полученным значением. (os error -2146762481)"), HttpResult::BadCert);
        // Общая TLS-ошибка БЕЗ упоминания сертификата — остаётся Tls.
        assert_eq!(classify_err_text("tls handshake failure"), HttpResult::Tls);
        assert_eq!(classify_err_text("ssl protocol error"), HttpResult::Tls);
    }

    #[test]
    fn timeout_and_other() {
        assert_eq!(classify_err_text("operation timed out"), HttpResult::Timeout);
        assert_eq!(classify_err_text("os error 10060"), HttpResult::Timeout);
        assert_eq!(classify_err_text("что-то неведомое"), HttpResult::Other("что-то неведомое".to_string()));
    }

    /// Заглушки резолвера — не адреса: 0.0.0.0, loopback, private, CGNAT.
    #[test]
    fn stub_ips_are_filtered() {
        for s in [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "::",
            "::1",
        ] {
            assert!(is_stub_ip(&s.parse().unwrap()), "{}", s);
        }
        for s in ["34.96.76.122", "104.18.2.115", "8.8.8.8", "1.1.1.1"] {
            assert!(!is_stub_ip(&s.parse().unwrap()), "{}", s);
        }
    }

    /// Заглушка в ответе DoH-сервиса не попадает в общий список адресов.
    #[test]
    fn all_ips_skips_stubs() {
        let answers = DohAnswers {
            answers: vec![DohAnswer {
                service: "test".to_string(),
                ips: vec!["0.0.0.0".parse().unwrap(), "104.18.2.115".parse().unwrap()],
                error: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            answers.all_ips(),
            vec!["104.18.2.115".parse::<IpAddr>().unwrap()]
        );
    }

    /// Карта «адрес → сервисы»: адрес, который отдал только один сервис,
    /// подписывается этим сервисом (кандидат «прокси-шлюз» в отчёте).
    #[test]
    fn services_map_labels_single_service_addresses() {
        let answers = DohAnswers {
            answers: vec![
                DohAnswer {
                    service: "svc-a".to_string(),
                    ips: vec!["74.125.205.105".parse().unwrap(), "199.189.249.126".parse().unwrap()],
                    error: None,
                },
                DohAnswer {
                    service: "svc-b".to_string(),
                    ips: vec!["74.125.205.105".parse().unwrap()],
                    error: None,
                },
                DohAnswer {
                    service: "svc-dead".to_string(),
                    ips: vec![],
                    error: Some("таймаут".to_string()),
                },
            ],
            ..Default::default()
        };
        let map = answers.services_map(&[
            "74.125.205.105".to_string(),
            "199.189.249.126".to_string(),
        ]);
        assert_eq!(map.len(), 2, "{:?}", map);
        // Оба сервиса отдали первый адрес.
        assert_eq!(
            map[0].1,
            vec!["svc-a".to_string(), "svc-b".to_string()],
            "{:?}",
            map
        );
        // Второй — только один сервис: в отчёте он попадёт под подозрение «шлюза».
        assert_eq!(map[1].1, vec!["svc-a".to_string()], "{:?}", map);
    }

    /// Маркеры регионального ограничения в теле живой 200-страницы.
    #[test]
    fn region_restricted_body_markers() {
        for body in [
            "The requested URL is not available in your region",
            "Location is not supported error 409",
            "сервис недоступен в вашем регионе",
        ] {
            assert!(body_looks_region_restricted(&body.to_lowercase()), "{}", body);
        }
        for body in ["Welcome to our site!", "Loading…", "error code: 1034"] {
            assert!(!body_looks_region_restricted(&body.to_lowercase()), "{}", body);
        }
    }

    /// Адрес собственной инфраструктуры DoH-сервиса опознаётся владельцем:
    /// кейс openrouter.ai — 80.74.30.162 это шлюз dns.comss.one, а не сайта.
    #[test]
    fn gateway_owner_recognizes_own_ips() {
        let answers = DohAnswers {
            own_ips: vec![(
                "dns.comss.one".to_string(),
                vec![
                    "80.74.30.162".parse().unwrap(),
                    "206.223.242.94".parse().unwrap(),
                ],
            )],
            ..Default::default()
        };
        assert_eq!(
            answers.gateway_owner(&"80.74.30.162".parse().unwrap()),
            Some("dns.comss.one".to_string())
        );
        assert_eq!(
            answers.gateway_owner(&"104.18.2.115".parse().unwrap()),
            None,
            "адрес сайта не должен считаться шлюзом"
        );
    }

    /// Пустая карта собственных адресов (ни один сервис не зарезолвился)
    /// не должна паниковать и ни на что не указывает.
    #[test]
    fn gateway_owner_empty_map_is_none() {
        let answers = DohAnswers::default();
        assert_eq!(answers.gateway_owner(&"1.2.3.4".parse().unwrap()), None);
    }

    /// Перебор бутстрап-IP: успех засчитывается на любом элементе, не только
    /// на первом (кейс eu.geohide.ru — первый IP мёртв, второй отвечает).
    #[test]
    fn try_bootstrap_ips_falls_through_dead_first() {
        let ips: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let mut tried: Vec<IpAddr> = Vec::new();
        let dead: IpAddr = "192.0.2.1".parse().unwrap();
        let res = try_bootstrap_ips(&ips, |ip| {
            tried.push(ip);
            if ip == dead {
                Err("GET /dns-query не выполнен: Rst".to_string())
            } else {
                Ok(vec!["1.2.3.4".parse().unwrap()])
            }
        });
        assert_eq!(res, Ok(vec!["1.2.3.4".parse().unwrap()]));
        assert_eq!(tried, ips, "попытки идут в порядке бутстрапа, до первого успеха");
    }

    /// Все попытки неудачны — ошибка перечисляет КАЖДЫЙ IP с его причиной.
    #[test]
    fn try_bootstrap_ips_lists_every_failure() {
        let ips: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let msg = try_bootstrap_ips(&ips, |ip| Err(format!("причина-{}", ip))).unwrap_err();
        assert!(msg.contains("192.0.2.1 — причина-192.0.2.1"), "{}", msg);
        assert!(msg.contains("192.0.2.2 — причина-192.0.2.2"), "{}", msg);
    }

    /// Пустой бутстрап — честная ошибка, а не «успех с нулём попыток».
    #[test]
    fn try_bootstrap_ips_empty_is_error() {
        let res = try_bootstrap_ips(&[], |_| Ok(vec!["1.2.3.4".parse().unwrap()]));
        assert!(res.is_err());
    }

    /// URL DoH-запроса выбрасывается из текста ошибки: подстрока «dns» в
    /// адресе не должна превращать connect-сбой в DNS-ошибку.
    #[test]
    fn strip_url_removes_doh_url_from_message() {
        let url = "https://eu.geohide.ru/dns-query?dns=aa";
        let msg = format!("error sending request for url ({}): tcp connect error", url)
            .to_lowercase();
        let stripped = strip_url(&msg, &url.to_lowercase());
        assert!(!stripped.contains("dns"), "{}", stripped);
        assert!(stripped.contains("tcp connect error"), "{}", stripped);
        // URL, которого нет в тексте (или пустая строка), ничего не меняет.
        assert_eq!(strip_url("ошибка без url", "https://x.test/dns-query"), "ошибка без url");
        assert_eq!(strip_url("ошибка", ""), "ошибка");
    }

    /// Остаток сообщения после выбрасывания URL классифицируется по реальному
    /// этапу: connect-сбой — Rst, а не Dns. Контроль подтверждает старую ложь.
    #[test]
    fn doh_url_does_not_force_dns_classification() {
        let url = "https://eu.geohide.ru/dns-query?dns=aa";
        let msg = format!(
            "error sending request for url ({}): client error (connect): tcp connect error (os error 10061)",
            url
        )
        .to_lowercase();
        assert_eq!(classify_err_text(&strip_url(&msg, &url)), HttpResult::Rst);
        // Без выбрасывания URL старый код ложно давал Dns по подстроке адреса.
        assert_eq!(classify_err_text(&msg), HttpResult::Dns);
    }

    /// Реальная ошибка reqwest (закрытый loopback-порт) на URL /dns-query
    /// НЕ классифицируется как Dns: URL выбрасывается из текста до
    /// классификации, итог называет реальный этап соединения. Rst или
    /// Timeout — зависит от того, отвергнут порт или дропнут файрволом.
    #[test]
    fn real_reqwest_doh_url_connect_fail_is_not_dns() {
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .expect("клиент собирается");
        let err = client
            .get("https://127.0.0.1:1/dns-query?dns=AA")
            .send()
            .expect_err("порт 1 на loopback закрыт — обязана быть ошибка");
        let res = classify_reqwest_err(&err);
        assert_ne!(res, HttpResult::Dns, "{:?}", res);
        assert!(
            matches!(res, HttpResult::Rst | HttpResult::Timeout),
            "connect-сбой обязан называться Rst/Timeout, а не {:?}",
            res
        );
    }
}
