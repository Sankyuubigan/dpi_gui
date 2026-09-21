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

/// Результат теста одного профиля — возвращается на фронтенд.
#[derive(Serialize, Debug)]
pub struct ProfileTestOutcome {
    pub name: String,
    pub ok: bool,
    /// Человеко-читаемый вердикт: «УСПЕХ (200 OK)», «Таймаут соединения», «RST — сброс (DPI)» и т.п.
    pub verdict: String,
    /// Дополнительная деталь (для провала).
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Человеко-читаемое описание классифицированного результата HTTP-пробы.
fn verdict_from_http(r: &diagnostics_probe::HttpResult) -> (bool, String) {
    match r {
        diagnostics_probe::HttpResult::Ok(s) => (true, format!("УСПЕХ (HTTP {})", s)),
        diagnostics_probe::HttpResult::BlockPage => (false, "Страница блокировки (403/451/заглушка)".to_string()),
        diagnostics_probe::HttpResult::Dns => (false, "DNS не резолвится (NXDOMAIN / DNS-цензура)".to_string()),
        diagnostics_probe::HttpResult::Rst => (false, "RST — соединение сброшено (типично для DPI)".to_string()),
        diagnostics_probe::HttpResult::Tls => (false, "TLS-рукопожатие рвётся".to_string()),
        diagnostics_probe::HttpResult::Timeout => (false, "Таймаут соединения".to_string()),
        diagnostics_probe::HttpResult::Other(msg) => (false, format!("Ошибка: {}", msg)),
    }
}

pub fn test_single_profile(app: AppHandle, profile_name: &str, url: &str, game_filter: bool) -> Result<ProfileTestOutcome, String> {
    let started = Instant::now();
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    if let Err(e) = process::start_winws_quiet(app.clone(), profile_name, game_filter) {
        return Ok(ProfileTestOutcome {
            name: profile_name.to_string(),
            ok: false,
            verdict: "Ошибка запуска".to_string(),
            detail: e,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Даем WinDivert время на перехват трафика
    thread::sleep(Duration::from_secs(2));

    // Десинк-профили часто пробивают только со второй/третьей попытки
    // (первый коннект съедается DPI, winws пересылает модифицированные пакеты).
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
            diagnostics_probe::HttpResult::BlockPage => "получена страница-заглушка вместо сайта".to_string(),
            diagnostics_probe::HttpResult::Dns => "запись домена не найдена системным DNS".to_string(),
            diagnostics_probe::HttpResult::Rst => "соединение оборвано RST при рукопожатии".to_string(),
            diagnostics_probe::HttpResult::Tls => "TLS-хендшейк не завершился за время пробы".to_string(),
            diagnostics_probe::HttpResult::Timeout => "сервер не ответил за ~5 секунд".to_string(),
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
    
    // Вытаскиваем домен для резолвинга
    let parsed_url = url::Url::parse(&target_url).map_err(|e| format!("Неверный URL: {}", e))?;
    let domain = parsed_url.host_str().ok_or("Не удалось извлечь домен")?.to_string();

    let dns_addr = IpAddr::from_str(dns_ip).map_err(|_| "Неверный IP кастомного DNS сервера")?;
    
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: SocketAddr::new(dns_addr, 53),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });

    // Делаем запрос к кастомному DNS (например, 1.1.1.1)
    let resolver = Resolver::new(config, ResolverOpts::default()).map_err(|e| format!("Ошибка инициализации DNS клиента: {}", e))?;
    let response = resolver.lookup_ip(&domain).map_err(|e| format!("Сбой резолвинга (возможно DNS недоступен или домен заблокирован на уровне DNS): {}", e))?;
    let resolved_ip = response.iter().next().ok_or("Кастомный DNS не вернул IP адреса!")?;

    // Подменяем IP в запросе к reqwest (эмитируем Host заголовок)
    let client = Client::builder()
        .resolve(&domain, SocketAddr::new(resolved_ip, 443))
        .resolve(&domain, SocketAddr::new(resolved_ip, 80))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get(&target_url).send() {
        Ok(res) if res.status().is_success() => Ok(format!("УСПЕХ (200 OK)\n DNS: {}\n Разрешенный IP: {}", dns_ip, resolved_ip)),
        Ok(res) => Ok(format!("Доступно, но статус: {}\n DNS: {}\n IP: {}", res.status(), dns_ip, resolved_ip)),
        Err(e) => Ok(format!("ОШИБКА подключения:\n DNS: {}\n IP: {}\n Причина: {}", dns_ip, resolved_ip, e))
    }
}