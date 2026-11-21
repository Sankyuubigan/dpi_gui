// pac_server.rs — Этап A «Группы маршрутизации» (19.11.26, PRP tasks/261113_1838-7053fad3).
// Две роли:
//  1) Локальный HTTP-слушатель 127.0.0.1:7896 (SSOT порта — routing::PAC_PORT), отдающий
//     proxy.pac, скомпилированный routing.rs НА КАЖДЫЙ запрос: правка списков/режимов
//     подхватывается браузерами без дополнительных действий.
//  2) Command-слой маршрутизации: статус/смена режимов + системный PAC
//     (AutoConfigURL в HKCU\...\Internet Settings + refresh WinINet).
// routing.rs остаётся чистым (модель+компилятор), вся механика ОС — здесь.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::json;
use tauri::{AppHandle, Emitter};
use winreg::enums::{HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE};
use winreg::RegKey;
use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;

const AUTOCONFIG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
// InternetSetOptionW без именованных констант: 39 = INTERNET_OPTION_SETTINGS_CHANGED,
// 37 = INTERNET_OPTION_REFRESH — разбудить браузеры после правки реестра.
const OPT_SETTINGS_CHANGED: u32 = 39;
const OPT_REFRESH: u32 = 37;

// ---------- PAC-слушатель ----------

/// Стартует слушатель PAC в фоновом треде. Порт занят (второй экземпляр
/// приложения) → честный warn, включение PAC позже вернёт ошибку браузера 404.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", crate::routing::PAC_PORT)) {
            Ok(l) => l,
            Err(e) => {
                log::warn!(
                    "[PAC] 127.0.0.1:{} не открыт: {} — PAC-подхват браузеров недоступен",
                    crate::routing::PAC_PORT,
                    e
                );
                return;
            }
        };
        log::info!("[PAC] слушает http://127.0.0.1:{}/proxy.pac", crate::routing::PAC_PORT);
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let app2 = app.clone();
            std::thread::spawn(move || handle_conn(&mut stream, &app2));
        }
    });
}

fn handle_conn(stream: &mut TcpStream, _app: &AppHandle) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    // PAC-запросы крошечные; читаем до конца заголовков или лимита.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                    break;
                }
            }
        }
    }
    let req = String::from_utf8_lossy(&buf);
    // Единственный ресурс — наш proxy.pac; всё остальное честно 404.
    if req.starts_with("GET /proxy.pac") {
        let body = pac_body();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else {
        let _ = stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
}

/// Тело PAC на конкретный момент. Честный фолбэк при непрочитанных режимах:
/// всё-DIRECT (ничего через прокси не гоняем), причина — в лог.
fn pac_body() -> String {
    let active = crate::proxy_core::active_channel_id();
    match crate::routing::load_modes() {
        Ok(modes) => match crate::routing::compile_from_fs(
            &modes,
            active != "off",
            None,
            &[],
            crate::proxy_core::PROXY_PORT,
        ) {
            Ok(art) => art.pac_script,
            Err(e) => {
                log::warn!("[PAC] компиляция не удалась — отдаю всё-DIRECT: {}", e);
                all_direct()
            }
        },
        Err(e) => {
            log::warn!("[PAC] routing.json не прочитан — отдаю всё-DIRECT: {}", e);
            all_direct()
        }
    }
}

fn all_direct() -> String {
    String::from(
        "// Честный фолбэк DPI_GUI: режимы маршрутизации не прочитаны.\nfunction FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n",
    )
}

// ---------- Системный PAC (AutoConfigURL) ----------

/// Настроен ли системный PAC и на какой URL. None = не настроен/реестр не читается.
pub fn pac_configured() -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(AUTOCONFIG_KEY, KEY_QUERY_VALUE).ok()?;
    key.get_value::<String, _>("AutoConfigURL").ok()
}

fn set_autoconfig_url(url: Option<&str>) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(AUTOCONFIG_KEY, KEY_SET_VALUE | KEY_QUERY_VALUE)
        .map_err(|e| format!("реестр Internet Settings не открыт (права HKCU): {}", e))?;
    match url {
        Some(u) => key
            .set_value("AutoConfigURL", &u)
            .map_err(|e| format!("AutoConfigURL не записан: {}", e))?,
        None => match key.delete_value("AutoConfigURL") {
            Ok(_) => {}
            // Значения уже нет — цель достигнута, не ошибка.
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("AutoConfigURL не удалить: {}", e)),
        },
    }
    refresh_wininet()
}

/// Разбудить WinINet после правки реестра: без refresh браузеры увидят
/// изменение только после полного перезапуска.
fn refresh_wininet() -> Result<(), String> {
    // SAFETY: InternetSetOptionW с NULL-hwnd и пустым буфером — документированный
    // способ оповестить систему о смене настроек подключения.
    unsafe {
        if InternetSetOptionW(std::ptr::null_mut(), OPT_SETTINGS_CHANGED, std::ptr::null_mut(), 0) == 0
            || InternetSetOptionW(std::ptr::null_mut(), OPT_REFRESH, std::ptr::null_mut(), 0) == 0
        {
            return Err(format!(
                "InternetSetOptionW (refresh) не сработал: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Включение/выключение системного PAC. Честность: если юзер настроил свой
/// PAC — наш не перезаписываем и не удаляем.
pub fn pac_set(enabled: bool) -> Result<String, String> {
    if enabled {
        if let Some(url) = pac_configured() {
            if url != crate::routing::PAC_URL {
                return Err(format!(
                    "Система уже использует чужой PAC ({}). Наш не перезаписываю — сними его и повтори.",
                    url
                ));
            }
        }
        set_autoconfig_url(Some(crate::routing::PAC_URL))?;
        Ok(format!(
            "PAC включён: {} — браузеры подхватят домены групп «канал» автоматически (открытому браузеру может понадобиться перезапуск).",
            crate::routing::PAC_URL
        ))
    } else {
        if let Some(url) = pac_configured() {
            if url != crate::routing::PAC_URL {
                return Err(format!("Активен чужой PAC ({}), наш не трогаю.", url));
            }
        }
        set_autoconfig_url(None)?;
        Ok("PAC выключен — браузеры вернулись к обычным настройкам.".into())
    }
}

// ---------- Статус/смена режимов (command-слой) ----------

/// Полный статус маршрутизации для UI «Маршрутизатора».
pub fn routing_status_json() -> Result<serde_json::Value, String> {
    let modes = crate::routing::load_modes()?;
    let pac = pac_configured();
    Ok(json!({
        "dpi_mode": crate::routing::dpi_mode_str(modes.dpi_mode),
        "geo_mode": crate::routing::geo_mode_str(modes.geo_mode),
        "route_mode": crate::routing::route_mode_str(modes.route_mode),
        "dpi_count": crate::routing::dpi_domains().len(),
        "geo_count": crate::routing::geo_domains().len(),
        "trusted_count": crate::routing::trusted_domains().len(),
        "channel": crate::proxy_core::active_channel_id(),
        "pac_on": pac.as_deref() == Some(crate::routing::PAC_URL),
        "pac_url": pac.unwrap_or_default(),
        "proxy_port": crate::proxy_core::PROXY_PORT,
        "pac_port": crate::routing::PAC_PORT,
    }))
}

/// Смена режимов групп (dpi/geo/route) с пересборкой артефактов:
/// 1) routing.json сохранён (ошибки значений отловены ДО записи);
/// 2) channel-exclude.txt пересобран под текущий канал;
/// 3) живой запасной канал перезапущен (его rules зависят от режимов);
///    платный НЕ рестартуем — его yaml мы не патчим, а winws перечитывает
///    channel-exclude по изменению файла;
/// 4) PAC пересобирается сам на каждый запрос — действий не нужно.
pub fn routing_set_mode(
    app: &AppHandle,
    dpi_mode: &str,
    geo_mode: &str,
    route_mode: &str,
) -> Result<String, String> {
    let new_modes = crate::routing::RoutingModes {
        dpi_mode: crate::routing::parse_dpi_mode(dpi_mode)?,
        geo_mode: crate::routing::parse_geo_mode(geo_mode)?,
        route_mode: crate::routing::parse_route_mode(route_mode)?,
    };
    crate::routing::save_modes(&new_modes)?;
    app.emit(
        "log",
        format!("[ROUTING] режимы сохранены: dpi={}, geo={}, route={}", dpi_mode, geo_mode, route_mode),
    )
    .ok();

    let excluded = crate::proxy_core::refresh_channel_exclude()?;
    app.emit(
        "log",
        format!(
            "[ROUTING] channel-exclude пересобран: {} доменов (winws перечитывает hostlist по изменению файла).",
            excluded
        ),
    )
    .ok();

    // rules запасного канала генерируются из режимов → живой запасной
    // перезапускаем, чтобы применились. Платный не трогаем (см. доку выше).
    if crate::proxy_core::active_channel_id() == crate::proxy_core::WG_CHANNEL_ID {
        crate::proxy_core::channel_set(app, crate::proxy_core::WG_CHANNEL_ID)?;
    }

    let mut reply = format!(
        "Режимы применены: dpi={} ({} доменов), geo={} ({} доменов), route={}.",
        dpi_mode,
        crate::routing::dpi_domains().len(),
        geo_mode,
        crate::routing::geo_domains().len(),
        route_mode
    );
    // Честность: списки winws фиксируются на старте обхода — активный обход
    // примет новый dpi-режим только при следующем запуске (PAC и
    // channel-exclude применились уже сейчас).
    if crate::process::is_winws_running() {
        reply.push_str(
            " Обход сейчас активен: новый режим dpi применится при его следующем запуске.",
        );
    }
    Ok(reply)
}
