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
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::process;
use crate::proxy_core;
use crate::win_job::TreeChild;

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

static CHILD: Mutex<Option<TreeChild>> = Mutex::new(None);

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
    check_psiphon_text(&path.display().to_string(), &text)?;
    Ok(path)
}

/// Все проверки — только по реальному YAML: полные строки-комментарии
/// отрезаются перед contains, иначе contains("__") ловит доку шаблона
/// («плейсхолдеры __...__ подставляются из warp_account.json») и каждый
/// свежий профиль гарантированно проваливает — инцидент 22.11.26, второй
/// случай того же класса после awg (awg_config.rs::check_awg_text).
fn check_psiphon_text(display: &str, text: &str) -> Result<(), String> {
    let code = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if !code.contains(&format!("mixed-port: {}", proxy_core::PROXY_PORT)) {
        return Err(format!(
            "{}: ожидался mixed-port: {} — файл не тот?",
            display,
            proxy_core::PROXY_PORT
        ));
    }
    for marker in ["type: masque", "type: socks5", "listeners:", "proxy: WARP"] {
        if !code.contains(marker) {
            return Err(format!("{}: нет маркера «{}» — конфиг не psiphon-профиля", display, marker));
        }
    }
    if code.contains("__") {
        return Err(format!(
            "{}: остались плейсхолдеры — учётка подставилась не полностью",
            display
        ));
    }
    Ok(())
}

// ---------- Sidecar ----------

/// TCP-живость socks-порта aether (500мс коннект).
fn socks_alive(port: u16) -> bool {
    match format!("127.0.0.1:{}", port).parse::<std::net::SocketAddr>() {
        Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok(),
        Err(_) => false,
    }
}

/// Runtime-копия aether и его окружения: cygwin1.dll рядом (cygwin-бинд),
/// pt/ рядом (aether ищет psiphon-tunnel-core/lyrebird относительно своего
/// exe — раскладка бандла воспроизводится в runtime-папке). Живой aether не
/// лочит файлы бандла/папки сборки (инцидент 22.11.26, os error 32).
pub(crate) fn runtime_aether() -> Result<PathBuf, String> {
    for rel in [AETHER_EXE, "cygwin1.dll", "pt/psiphon-tunnel-core.exe", "pt/lyrebird.exe"] {
        process::runtime_file(rel)?;
    }
    Ok(process::runtime_dir().join(AETHER_EXE))
}

/// Старт aether для боевого канала: спавн (cwd = своя папка данных) + ожидание
/// готовности socks-порта (до 40с — datastore/транспорт Psiphon греются ~15с).
pub fn start_sidecar(app: &AppHandle) -> Result<(), String> {
    stop_sidecar(); // страховка от дубля
    let cwd = sidecar_dir();
    std::fs::create_dir_all(&cwd).map_err(|e| format!("не создать {}: {}", cwd.display(), e))?;
    let child = spawn_aether(
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
/// Экземпляр — runtime-копия (не бандл, см. runtime_aether). Ребёнок в Job
/// Object (win_job.rs): kill_tree гасит и его потомков — kill() родителя на
/// Windows оставлял сирот psiphon-tunnel-core, исполнявшихся из release/bin/
/// pt/ и валивших сборку релиза (инцидент 22.11.26). Не ждёт готовности —
/// готовность проверяет wait_socks отдельно.
pub(crate) fn spawn_aether(
    upstream: &str,
    bind: u16,
    cwd: &Path,
    log: &Path,
) -> Result<TreeChild, String> {
    std::fs::create_dir_all(cwd).map_err(|e| format!("не создать {}: {}", cwd.display(), e))?;
    let aether_path = runtime_aether()?;
    let open_log = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("не открыть лог {}: {}", log.display(), e))
    };
    let out = open_log()?;
    let err = open_log()?;
    let mut cmd = Command::new(&aether_path);
    cmd.arg("--psiphon-only")
        .arg("--upstream")
        .arg(upstream)
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", bind))
        .arg("--psiphon-region")
        .arg(REGION)
        .current_dir(cwd)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    TreeChild::spawn(&mut cmd)
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

/// Гасит sidecar aether ВМЕСТЕ С ДЕТЬМИ (Job Object, см. win_job.rs): ветки
/// channel_set и stop_channel зовут при переключении каналов/выходе — раньше
/// kill() оставлял сирот psiphon-tunnel-core, лочивших release/bin/pt/ при
/// сборке релиза (os error 32, инцидент 22.11.26).
pub fn stop_sidecar() {
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            c.kill_tree();
        }
    }
}

/// Подметание сирот прошлых сессий при старте приложения (аналог
/// cleanup_stale_windivert): aether/psiphon-tunnel-core/lyrebird, пережившие
/// смерть старой сборки без Job Object, исполнялись из bin/pt/ и валили
/// сборку релиза. На текущей сборке сирот не возникает (kill-on-close в
/// win_job.rs), но у машин, обновившихся со старой версии, хвосты остаются —
/// чистим при каждом старте. К моменту вызова боевой канал ещё не поднят,
/// своих процессов вида не бывает.
pub fn cleanup_stale_sidecar() {
    for exe in ["aether.exe", "psiphon-tunnel-core.exe", "lyrebird.exe"] {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", exe])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
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

#[cfg(test)]
mod tests {
    use super::*;

    // Собранный из РЕАЛЬНОГО шаблона профиль с фиктивными значениями
    // (секретов в тестах быть не должно; ключи-заглушки валидной длины b64).
    // Инцидент 22.11.26: contains("__") по сырому тексту ловил доку шаблона
    // («плейсхолдеры __...__ подставляются из warp_account.json», строка 3) —
    // Psiphon-канал нельзя было включить даже с полностью подставленной учёткой.
    fn assemble_psiphon_like(server: &str) -> String {
        include_str!("../defaults/psiphon_template.yaml")
            .replace("__LISTEN_PORT__", &proxy_core::PROXY_PORT.to_string())
            .replace("__API_PORT__", &proxy_core::API_PORT.to_string())
            .replace("__LISTENER_PORT__", &LISTENER_PORT.to_string())
            .replace("__SERVER__", server)
            .replace("__PRIVATE_KEY__", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq=")
            .replace("__PUBLIC_KEY__", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
            .replace("__IP__", "172.16.0.2")
            .replace("__IPV6__", "2606:4700:1800::1")
            .replace(
                "__PSIPHON_OUT__",
                &format!(
                    "- name: \"PSIPHON\"\n    type: socks5\n    server: 127.0.0.1\n    port: {}\n    udp: false",
                    SOCKS_PORT
                ),
            )
    }

    #[test]
    fn test_check_psiphon_text_template_comment_does_not_fail() {
        let text = assemble_psiphon_like("203.0.113.7");
        check_psiphon_text("тест", &text)
            .expect("дока-комментарии шаблона не должны валить валидацию psiphon");
    }

    #[test]
    fn test_check_psiphon_text_catches_real_placeholder() {
        let text = assemble_psiphon_like("__SERVER__");
        let err = check_psiphon_text("тест", &text).unwrap_err();
        assert!(err.contains("плейсхолдеры"), "ловим только РЕАЛЬНЫЙ плейсхолдер в коде: {}", err);
    }

    #[test]
    fn test_check_psiphon_text_missing_marker() {
        // Вырезали masque-outbound → нет маркера «type: masque»
        let text = assemble_psiphon_like("203.0.113.7").replace("type: masque", "type: foo");
        let err = check_psiphon_text("тест", &text).unwrap_err();
        assert!(err.contains("type: masque"), "{}", err);
    }
}
