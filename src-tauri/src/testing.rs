use crate::process;
use std::thread;
use std::time::Duration;
use reqwest::blocking::Client;
use tauri::AppHandle;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::Resolver;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;

pub fn test_single_profile(app: AppHandle, profile_name: &str, url: &str, game_filter: bool) -> Result<String, String> {
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    if let Err(e) = process::start_winws(app.clone(), profile_name, game_filter) {
        return Err(format!("Ошибка запуска {}: {}", profile_name, e));
    }

    // Даем WinDivert время на перехват трафика
    thread::sleep(Duration::from_secs(3));

    let client = Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();

    let result = match client.get(&target_url).send() {
        Ok(res) if res.status().is_success() => Ok("УСПЕХ (200 OK)".to_string()),
        Ok(res) => Ok(format!("Доступно, но статус: {}", res.status())),
        Err(e) => Ok(format!("Неудача: {}", e))
    };

    let _ = process::stop_winws();
    thread::sleep(Duration::from_secs(1));

    result
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