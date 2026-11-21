//! Psiphon-канал: sidecar aether.exe (сеть Psiphon) за внутренним listener'ом mihomo.
//! Цепочка проверена живьём 20.11.26 (temp/psiphon_chain): aether --psiphon-only
//! --upstream http://127.0.0.1:<listener> --bind 127.0.0.1:<socks> → loc=DE, yt204 0.5с.
//! Медленный (~0.2 МБ/с) — резервный канал с честной меткой в UI (§9).
//! Нюансы:
//!  - ДВА aether в одной папке не живут (datastore лочится) → cwd = AppData/psiphon/
//!    (своя папка данных, переживает обновления). Bootstrap-инстанс (регистрация AWG)
//!    живёт в AppData/psiphon_bootstrap/ и на ДРУГИХ портах (7910/9110/7911/10819),
//!    чтобы не конфликтовать с боевым (7901/10818).
//!  - udp: false у PSIPHON-socks: UDP через psiphon-socks не заявляем (v1 TCP-only).

use std::fs::OpenOptions;
use std::net::TcpStream;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::process;
use crate::proxy_core;

const AETHER_EXE: &str = "aether.exe";
/// Внутренний listener (→ WARP masque outbound): через него aether ходит в интернет.
pub const LISTENER_PORT: u16 = 7901;
/// Локальный socks5 aether — сюда mihomo PSIPHON-outbound сует трафик юзера.
pub const SOCKS_PORT: u16 = 10818;
/// Aether-регион — константа v1 (настраиваемость — потом).
const REGION: &str = "DE";
/// Ожидание готовности socks-порта aether при старте канала.
const READY_TIMEOUT: Duration = Duration::from_secs(40);
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Bootstrap-порты (регистрация AWG через aether): не пересекаются с боевыми
/// 7897/9097/7901/10818 и с тестовыми инстансами агента.
pub const BOOT_LISTEN_PORT: u16 = 7910;
pub const BOOT_API_PORT: u16 = 9110;
pub const BOOT_LISTENER_PORT: u16 = 7911;
pub const BOOT_SOCKS_PORT: u16 = 10819;

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn emit_log(app: &AppHandle, msg: String) {
    let _ = app.emit("log", msg);
}

fn sidecar_dir() -> PathBuf {
    config::get_app_dir().join("psiphon")
}

fn log_path() -> PathBuf {
    sidecar_dir().join("aether.log")
}

/// Путь регенерированного конфига Psiphon-канала.
pub fn profile_path() -> PathBuf {
    proxy_core::proxy_dir().join("psiphon_profile.yaml")
}

// ---------- Конфиг ----------

/// База psiphon-конфига: masque-outbound из warp-учётки (напрямую, без такси) +
/// listener c proxy: WARP. psiphon_out=false — bootstrap-вариант (без PSIPHON-
/// outbound, rules MATCH,DIRECT); true — боевой канал (+socks5-outbound).
pub(crate) fn build_psiphon_yaml(
    listen: u16,
    api: u16,
    listener: u16,
    psiphon_out: bool,
) -> Result<String, String> {
    let acct = crate::warp::load_account().ok_or_else(|| String::from(
        "Нет WARP masque-учётки — Psiphon-канал ходит через WARP; зарегистрируй WARP-канал (1 клик)",
    ))?;
    let tpl = include_str!("../defaults/psiphon_template.yaml");
    let psiphon_block = if psiphon_out {
        format!(
            "- name: \"PSIPHON\"\n    type: socks5\n    server: 127.0.0.1\n    port: {}\n    udp: false",
            SOCKS_PORT
        )
    } else {
        String::new()
    };
    let mut out = tpl
        .replace("__LISTEN_PORT__", &listen.to_string())
        .replace("__API_PORT__", &api.to_string())
        .replace("__LISTENER_PORT__", &listener.to_string())
        .replace("__SERVER__", &acct.server)
        .replace("__PRIVATE_KEY__", &acct.private_key)
        .replace("__PUBLIC_KEY__", &acct.peer_public_key)
        .replace("__IP__", &acct.ip)
        .replace("__PSIPHON_OUT__", &psiphon_block);
    // Учётка без ipv6: строка `ipv6: __IPV6__` удаляется целиком (пустой плейс-
    // холдер стал бы yaml-null — mihomo падает на парсинге; паттерн warp.rs).
    if acct.ipv6.trim().is_empty() {
        out = out
            .lines()
            .filter(|l| !l.contains("__IPV6__"))
            .collect::<Vec<_>>()
            .join("\n");
    }
    out = out.replace("__IPV6__", &acct.ipv6);
    Ok(out)
}

/// Чистый yaml bootstrap-конфига (регистрация AWG через aether; порты 7910/9110/7911).
pub(crate) fn generate_bootstrap_config() -> Result<String, String> {
    build_psiphon_yaml(BOOT_LISTEN_PORT, BOOT_API_PORT, BOOT_LISTENER_PORT, false)
}

/// Регенерация боевого конфига Psiphon-канала: подстановка учётки + правила
/// компилятора групп (channel-домены → PSIPHON, остальное DIRECT) + trace-правило
/// для гарда (первым, через PSIPHON-outbound — критерий гарда loc != RU).
pub fn generate_psiphon_config() -> Result<PathBuf, String> {
    let mut text = build_psiphon_yaml(
        proxy_core::PROXY_PORT,
        proxy_core::API_PORT,
        LISTENER_PORT,
        true,
    )?;
    let modes = crate::routing::load_modes()?;
    let art = crate::routing::compile_from_fs(
        &modes,
        true,
        Some("PSIPHON"),
        &[],
        proxy_core::PROXY_PORT,
    )?;
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let Some(ri) = lines.iter().position(|l| l.trim() == "rules:") else {
        return Err(String::from("Шаблон psiphon: не найдена секция rules"));
    };
    lines.truncate(ri);
    lines.push(String::from("rules:"));
    lines.push(String::from("  - DOMAIN,www.cloudflare.com,PSIPHON"));
    lines.extend(art.mihomo_rules.iter().map(|r| format!("  {}", r)));
    text = lines.join("\n") + "\n";

    let path = profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не создать {}: {}", parent.display(), e))?;
    }
    std::fs::write(&path, &text).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(path)
}

/// Текстовый гейт перед стартом mihomo (образец — validate_reserve_config):
/// порты SSOT, masque + socks5-outbound + listener на месте, плейсхолдеров нет.
pub fn validate_psiphon_config() -> Result<PathBuf, String> {
    let path = profile_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Нет psiphon-профиля {} — сгенерируй конфиг канала", path.display()))?;
    if !text.contains(&format!("mixed-port: {}", proxy_core::PROXY_PORT)) {
        return Err(format!(
            "{}: ожидался mixed-port: {} — файл не тот?",
            path.display(),
            proxy_core::PROXY_PORT
        ));
    }
    for marker in ["type: masque", "type: socks5", "listeners:", "proxy: WARP"] {
        if !text.contains(marker) {
            return Err(format!("{}: нет маркера «{}» — конфиг не psiphon-профиля", path.display(), marker));
        }
   }
    if text.contains("__") {
        return Err(format!(
            "{}: остались плейсхолдеры — учётка подставилась не полностью",
            path.display()
        ));
    }
    Ok(path)
}

// ---------- Sidecar ----------

/// TCP-живость socks-порта aether (500мс коннект).
fn socks_alive(port: u16) -> bool {
    match format!("127.0.0.1:{}", port).parse::<std::net::SocketAddr>() {
        Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok(),
        Err(_) => false,
    }
}

/// Старт aether для боевого канала: спавн (cwd = своя папка данных) + ожидание
/// готовности socks-порта (до 40с — datastore/транспорт Psiphon греются ~15с).
pub fn start_sidecar(app: &AppHandle) -> Result<(), String> {
    let bin_dir = process::get_bin_dir()?;
    let aether = bin_dir.join(AETHER_EXE);
    if !aether.exists() {
        return Err(format!(
            "aether.exe не найден в {} — sidecar Psiphon не собран в бандл",
            bin_dir.display()
        ));
    }
    stop_sidecar(); // страховка от дубля
    let cwd = sidecar_dir();
    std::fs::create_dir_all(&cwd).map_err(|e| format!("не создать {}: {}", cwd.display(), e))?;
    let child = spawn_aether(
        &aether,
        &format!("http://127.0.0.1:{}", LISTENER_PORT),
        SOCKS_PORT,
        &cwd,
        &log_path(),
    )?;
    emit_log(
        app,
        format!(
            "[PSIPHON] aether запущен (PID {}), жду готовности Psiphon (до 40с)...",
            child.id()
        ),
    );
    if let Ok(mut g) = CHILD.lock() {
        *g = Some(child);
    }
    match wait_socks(SOCKS_PORT, READY_TIMEOUT) {
        Ok(()) => {
            emit_log(app, format!("[PSIPHON] готов: socks {} жив.", SOCKS_PORT));
            Ok(())
        }
        Err(e) => {
            stop_sidecar();
            Err(format!(
                "[PSIPHON] socks {} не поднялся за 40с: {} — лог: {}",
                SOCKS_PORT,
                e,
                log_path().display()
            )
            .into())
        }
    }
}

/// Спавн aether: лог в файл (append), CREATE_NO_WINDOW, cwd = папка данных.
/// Не ждёт готовности — готовность проверяет wait_socks отдельно.
pub(crate) fn spawn_aether(
    aether_path: &Path,
    upstream: &str,
    bind: u16,
    cwd: &Path,
    log: &Path,
) -> Result<Child, String> {
    std::fs::create_dir_all(cwd).map_err(|e| format!("не создать {}: {}", cwd.display(), e))?;
    let open_log = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("не открыть лог {}: {}", log.display(), e))
    };
    let out = open_log()?;
    let err = open_log()?;
    Command::new(aether_path)
        .arg("--psiphon-only")
        .arg("--upstream")
        .arg(upstream)
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", bind))
        .arg("--psiphon-region")
        .arg(REGION)
        .current_dir(cwd)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| format!("Ошибка запуска {}: {}", aether_path.display(), e))
}

/// Ожидание живого socks-порта (poll 500мс).
pub(crate) fn wait_socks(port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if socks_alive(port) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("порт {} не поднялся", port));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Гасит sidecar aether (ветки channel_set и stop_channel зовут при переключении
/// каналов/выходе — висячий aether держал бы datastore и канал-порты).
pub fn stop_sidecar() {
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Статус для фронта (ключей/секретов не содержит).
pub fn psiphon_status_json() -> Value {
    let bin_dir = process::get_bin_dir().map(|d| d.join(AETHER_EXE));
    let installed = bin_dir.map(|p| p.exists()).unwrap_or(false);
    let running = CHILD.lock().map(|g| g.is_some()).unwrap_or(false);
    json!({
        "installed": installed,
        "running": running,
        "ready": running && socks_alive(SOCKS_PORT),
    })
}
