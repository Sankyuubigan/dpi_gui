//! AWG-канал: аккаунт (curve25519-ключи от warpscout, AppData/proxy/warp/awg_account.json),
//! эндпоинты (AppData-скан → встроенный шортлист), регистрация в 1 клик.
//! Цепочка регистрации — 4 звена запасных путей (проверены живьём 20.11.26):
//!  (а) `warpscout register -a FILE` — внутри свои фолбэки: прямая API →
//!      релея (edge-client-api.vercel.app) → через WARP-туннель;
//!  (б) резерв: bootstrap mini-mihomo (7910/9110/7911, listener→WARP masque) +
//!      aether (socks 10819, cwd AppData/psiphon_bootstrap) + `warpscout register
//!      -x socks5://127.0.0.1:10819` — флаг -x ОТКЛЮЧАЕТ WARP-туннель fallback
//!      у warpscout. Требует masque-учётку (WARP-канал), 4-е звено страховки.
//! Приватность: private_key/token в статусах/логах НЕ отдаются (§ приватности).

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::process;
use crate::proxy_core;

const WARPS_EXE: &str = "warpscout.exe";
const CREATE_NO_WINDOW: u32 = 0x08000000;
/// Таймаут одного прогона warpscout register (внутри свои фолбэки — до 2 мин).
const REGISTER_TIMEOUT: Duration = Duration::from_secs(120);
/// Таймаут двухфазного скана эндпоинтов (find-junk + проверка живости).
const SCAN_TIMEOUT: Duration = Duration::from_secs(300);
/// Лимит сохраняемых эндпоинтов (в конфиг идёт максимум MAX_AWG_ENDPOINTS=6,
/// но скан может вернуть больше — храним с запасом).
const SAVED_ENDPOINTS_LIMIT: usize = 30;

fn emit_log(app: &AppHandle, msg: String) {
    let _ = app.emit("log", msg);
}

fn warp_dir() -> PathBuf {
    config::get_app_dir().join("proxy").join("warp")
}

fn account_file() -> PathBuf {
    warp_dir().join("awg_account.json")
}

/// Эндпоинты от кнопки «Пересканировать» (свежее встроенного шортлиста).
fn scanned_endpoints_file() -> PathBuf {
    warp_dir().join("awg_endpoints.txt")
}

fn logs_dir() -> PathBuf {
    warp_dir().join("logs")
}

/// Сколько байтов хвоста лога отдавать в ошибке (секретов в логе warpscout нет —
/// но хвост, а не весь файл).
const LOG_TAIL: u64 = 4000;

fn log_tail(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let start = bytes.len().saturating_sub(LOG_TAIL as usize);
            String::from_utf8_lossy(&bytes[start..]).to_string()
        }
        Err(_) => String::from("(лог пуст)"),
    }
}

/// AWG-учётка (top-level ключи warpscout-аккаунта; masque-блок для AWG не нужен).
/// НЕ путать с WarpAccount (ECDSA/masque) — это другой транспорт.
pub struct AwgAccount {
    pub(crate) id: String,
    /// Токен API — секрет, в статусах/логах НЕ отдаётся.
    pub(crate) token: String,
    pub(crate) private_key: String,
    pub(crate) peer_public_key: String,
    /// tunnel v4 (172.16.0.2).
    pub(crate) ipv4: String,
    /// tunnel v6; может отсутствовать (пустая строка).
    pub(crate) ipv6: String,
    pub(crate) source: String,
}

pub fn has_account() -> bool {
    account_file().exists()
}

/// Читает учётку; None = нет/битая (битая честно удаляется, чтобы не зацикливать
/// ошибки — паттерн warp.rs).
pub(crate) fn load_account() -> Option<AwgAccount> {
    let text = std::fs::read_to_string(account_file()).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    match account_from_json(&v) {
        Some(a) => Some(a),
        None => {
            let _ = std::fs::remove_file(account_file());
            None
        }
    }
}

fn account_from_json(v: &Value) -> Option<AwgAccount> {
    // tunnel_type-маркер не обязателен для чтения, но чужой masque-файл не примем:
    // если маркер есть и не "awg" — это не наша учётка.
    if let Some(t) = v["tunnel_type"].as_str() {
        if t != "awg" {
            return None;
        }
    }
    let get = |k: &str| v[k].as_str().filter(|s| !s.trim().is_empty()).map(|s| s.to_string());
    Some(AwgAccount {
        id: get("id")?,
        token: get("token")?,
        private_key: get("private_key")?,
        peer_public_key: get("peer_public_key")?,
        ipv4: get("ipv4")?,
        ipv6: get("ipv6").unwrap_or_default(),
        source: get("source").unwrap_or_else(|| String::from("warpscout")),
    })
}

fn account_to_json(a: &AwgAccount) -> Value {
    json!({
        "tunnel_type": "awg",
        "id": a.id,
        "token": a.token,
        "private_key": a.private_key,
        "peer_public_key": a.peer_public_key,
        "ipv4": a.ipv4,
        "ipv6": a.ipv6,
        "source": a.source,
    })
}

fn save_account(a: &AwgAccount) -> Result<(), String> {
    std::fs::create_dir_all(warp_dir())
        .map_err(|e| format!("не создать {}: {}", warp_dir().display(), e))?;
    let text = serde_json::to_string_pretty(&account_to_json(a)).map_err(|e| e.to_string())?;
    std::fs::write(account_file(), text)
        .map_err(|e| format!("не записать {}: {}", account_file().display(), e))
}

/// Эндпоинты: свежий AppData-скан → встроенный шортлист (bundled); оба пусты —
/// честная ошибка.
pub(crate) fn current_endpoints() -> Result<Vec<String>, String> {
    if let Ok(text) = std::fs::read_to_string(scanned_endpoints_file()) {
        let v = crate::awg_config::parse_endpoints(&text);
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let v = crate::awg_config::parse_endpoints(include_str!("../defaults/awg_endpoints.txt"));
    if v.is_empty() {
        return Err(String::from(
            "Нет AWG-эндпоинтов: и AppData-скан, и встроенный шортлист пусты",
        ));
    }
    Ok(v)
}

/// Источник эндпоинтов для статуса (честно: скан или бандл).
fn endpoints_source() -> &'static str {
    if let Ok(text) = std::fs::read_to_string(scanned_endpoints_file()) {
        if !crate::awg_config::parse_endpoints(&text).is_empty() {
            return "scan";
        }
    }
    "bundled"
}

// ---------- Регистрация ----------

/// Прогон warpscout с аргументами, лог stdout/stderr в файл, ожидание с дедлайном.
/// Честная ошибка: код выхода / таймаут + хвост лога.
fn run_warpscout(
    warpscout: &Path,
    args: &[&str],
    log_name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let log_path = logs_dir().join(log_name);
    std::fs::create_dir_all(logs_dir())
        .map_err(|e| format!("не создать {}: {}", logs_dir().display(), e))?;
    let open_log = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("не открыть лог {}: {}", log_path.display(), e))
    };
    let out = open_log()?;
    let err = open_log()?;
    let mut cmd = Command::new(warpscout);
    cmd.creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    for a in args {
        cmd.arg(a);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Ошибка запуска {}: {}", warpscout.display(), e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "warpscout {} упал (код {:?}). Хвост лога {}:\n{}",
                    args.first().unwrap_or(&""),
                    status.code(),
                    log_path.display(),
                    log_tail(&log_path)
                ));
                }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "warpscout {} висел > {}с — убит. Хвост лога {}:\n{}",
                        args.first().unwrap_or(&""),
                        timeout.as_secs(),
                        log_path.display(),
                        log_tail(&log_path)
                    ));
                }
            }
            Err(e) => return Err(format!("warpscout: ошибка ожидания: {}", e)),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Регистрация AWG-учётки (1 клик): путь (а) warpscout register без -x
/// (внутри свои фолбэки: прямая → релея → WARP-туннель); при неудаче — путь (б)
/// через aether-bootstrap. После успеха: перегенерация конфигов + синк реестра.
pub fn awg_register(app: &AppHandle) -> Result<Value, String> {
    // Runtime-копия: warpscout не лочит exe бандла/папки сборки (22.11.26).
    let warpscout = process::runtime_file(WARPS_EXE)?;
    std::fs::create_dir_all(warp_dir())
        .map_err(|e| format!("не создать {}: {}", warp_dir().display(), e))?;

    emit_log(
        app,
        String::from("[AWG] Регистрация: прямой/релейный путь (warpscout register)..."),
    );
    let account_str = account_file().display().to_string();
    let direct = run_warpscout(
        &warpscout,
        &["register", "-a", &account_str.as_str()],
        "register.log",
        REGISTER_TIMEOUT,
    );
    if direct.is_err() {
        emit_log(
            app,
            String::from("[AWG] Прямая/релея не пробились — резервный путь: через aether (Psiphon)..."),
        );
        register_via_aether(app, &warpscout)?;
    }

    let acct = load_account()
        .ok_or_else(|| String::from("Регистрация отработала, но учётка не сохранилась — смотри логи в AppData/proxy/warp/logs"))?;
    // секреты не логируем — только факт
    emit_log(app, "[AWG] Учётка зарегистрирована (ключи в AppData, в логи не пишутся).".to_string());
    let _ = acct;

    // Конфиги: awg всегда; pawg — только при наличии кредов Proton.
    match crate::awg_config::generate_awg_config() {
        Ok(p) => emit_log(app, format!("[AWG] Конфиг готов: {}", p.display())),
        Err(e) => emit_log(app, format!("[AWG] Конфиг не сгенерился (канал всё равно в селекторе): {}", e)),
    }
    if crate::reserve::load_creds().is_some() {
        match crate::awg_config::generate_pawg_config() {
            Ok(p) => emit_log(app, format!("[PAWG] Конфиг готов: {}", p.display())),
            Err(e) => emit_log(app, format!("[PAWG] Конфиг не сгенерился: {}", e)),
        }
    }
    proxy_core::special_channels_sync(app);
    emit_log(app, String::from("[AWG] Каналы «WARP AWG (YouTube)»/«Proton поверх WARP» в селекторе (стабильность не подтверждена — §9)."));
    Ok(awg_status_json())
}

/// Резервный путь (б): bootstrap mini-mihomo (7910/9110/7911) + aether
/// (socks 10819) + warpscout register -x socks5://127.0.0.1:10819. Всегда
/// чистит за собой bootstrap-процессы, даже при ошибке.
fn register_via_aether(app: &AppHandle, warpscout: &Path) -> Result<(), String> {
    if crate::warp::load_account().is_none() {
        return Err(String::from(
            "Резервная регистрация AWG через aether требует WARP masque-учётку — сначала зарегистрируй WARP-канал (1 клик), потом повтори AWG",
        ));
    }
    // Bootstrap-порты должны быть свободны (честная ошибка, не молча).
    for p in [
        crate::psiphon::BOOT_LISTEN_PORT,
        crate::psiphon::BOOT_API_PORT,
        crate::psiphon::BOOT_LISTENER_PORT,
        crate::psiphon::BOOT_SOCKS_PORT,
    ] {
        if proxy_core::port_alive(p) {
            return Err(format!(
                "Порт {} занят — bootstrap AWG не стартует; перезапусти приложение и повтори",
                p
            ));
        }
    }

    let mut mihomo_child: Option<Child> = None;
    let mut aether_child: Option<crate::win_job::TreeChild> = None;
    let result = (|| {
        // 1) bootstrap-конфиг mihomo (masque-учётка + listener→WARP, MATCH,DIRECT)
        let yaml = match crate::psiphon::generate_bootstrap_config() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let cfg = warp_dir().join("awg_bootstrap.yaml");
        if let Err(e) = std::fs::write(&cfg, &yaml) {
            return Err(format!("не записать {}: {}", cfg.display(), e));
        }
        let m = match Command::new(process::runtime_file(proxy_core::MIHOMO_EXE)?)
            .arg("-f")
            .arg(&cfg)
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return Err(format!("Ошибка запуска bootstrap mihomo: {}", e)),
        };
        mihomo_child = Some(m);

        // 2) ждём listener 7911 (до 10с)
        let dl = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if proxy_core::port_alive(crate::psiphon::BOOT_LISTENER_PORT) {
                break;
            }
            if std::time::Instant::now() >= dl {
                return Err(String::from("bootstrap mihomo не поднял listener 7911 за 10с"));
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        emit_log(app, String::from("[AWG] bootstrap mihomo готов (listener 7911 → WARP)."));

        // 3) aether: socks 10819, upstream listener 7911, cwd = своя папка (datastore!)
        let cwd = config::get_app_dir().join("psiphon_bootstrap");
        let a = match crate::psiphon::spawn_aether(
            &format!("http://127.0.0.1:{}", crate::psiphon::BOOT_LISTENER_PORT),
            crate::psiphon::BOOT_SOCKS_PORT,
            &cwd,
            &logs_dir().join("aether-bootstrap.log"),
        ) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        aether_child = Some(a);

        // 4) ждём socks 10819 (aether греется ~15с)
        if let Err(e) = crate::psiphon::wait_socks(
            crate::psiphon::BOOT_SOCKS_PORT,
            Duration::from_secs(40),
        ) {
            return Err(format!(
                "aether-bootstrap не поднял socks 10819: {} — лог: {}",
                e,
                logs_dir().join("aether-bootstrap.log").display()
            ));
        }
        emit_log(app, String::from("[AWG] aether-bootstrap готов (socks 10819)."));

        // 5) warpscout register через socks aether (-x ОТКЛЮЧАЕТ WARP-туннель fallback)
        let account_str = account_file().display().to_string();
        run_warpscout(
            warpscout,
            &[
                "register",
                "-a",
                &account_str.as_str(),
                "-x",
                "socks5://127.0.0.1:10819",
            ],
            "register_aether.log",
            REGISTER_TIMEOUT,
        )
    })();

    // Cleanup ВСЕГДА: aether деревом (Job Object — дети тоже) → mihomo.
    if let Some(mut c) = aether_child.take() {
        c.kill_tree();
    }
    if let Some(mut c) = mihomo_child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    result
}

/// Пересканирование эндпоинтов: `warpscout scan -a -conf OUT -conf-type mihomo`
/// (двухфазный: find-junk + проверка живости). server/port пары вынимаются,
/// junk-поля (i1/remote-dns-resolve и пр.) НЕ копируются — конфиг строится из
/// нашего шаблона.
pub fn awg_rescan(app: &AppHandle) -> Result<Value, String> {
    // Runtime-копия: warpscout не лочит exe бандла/папки сборки (22.11.26).
    let warpscout = process::runtime_file(WARPS_EXE)?;
    std::fs::create_dir_all(warp_dir())
        .map_err(|e| format!("не создать {}: {}", warp_dir().display(), e))?;
    let out = warp_dir().join("awg_scan_conf.yaml");
    let out_str = out.display().to_string();
    emit_log(app, String::from("[AWG] Пересканирование эндпоинтов (до 5 мин)..."));
    run_warpscout(
        &warpscout,
        &["scan", "-a", "-conf", &out_str.as_str(), "-conf-type", "mihomo"],
        "scan.log",
        SCAN_TIMEOUT,
    )?;
    let text = std::fs::read_to_string(&out)
        .map_err(|e| format!("скан отработал, но {} не читается: {}", out.display(), e))?;
    let eps = extract_endpoints_from_conf(&text)?;
    if eps.is_empty() {
        return Err(String::from(
            "Скан вернул 0 эндпоинтов — шортлист не обновлён (старый остался в силе)",
        ));
    }
    let capped: Vec<String> = eps.into_iter().take(SAVED_ENDPOINTS_LIMIT).collect();
    let count = capped.len();
    std::fs::write(&scanned_endpoints_file(), capped.join("\n") + "\n")
        .map_err(|e| format!("не записать {}: {}", scanned_endpoints_file().display(), e))?;
    emit_log(app, format!("[AWG] Найдено эндпоинтов: {} (сохранено {})", count, count));
    // учётка есть → перегенерация конфигов (кнопка доступна только с учёткой)
    if has_account() {
        match crate::awg_config::generate_awg_config() {
            Ok(_) => emit_log(app, String::from("[AWG] Конфиг канала перегенерирован под свежие эндпоинты.")),
            Err(e) => emit_log(app, format!("[AWG] Конфиг не перегенерился: {}", e)),
        }
        if crate::reserve::load_creds().is_some() {
            let _ = crate::awg_config::generate_pawg_config();
        }
    }
    Ok(awg_status_json())
}

/// Вынимает `server:`/`port:` пары из mihomo-конфига warpscout (последовательное
/// сопоставление: server открывает кандидата, ближайший port закрывает).
fn extract_endpoints_from_conf(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending_server: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("server:") {
            let v = rest.trim().trim_matches('"').to_string();
            if !v.is_empty() {
                pending_server = Some(v);
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("port:") {
            let v = rest.trim().trim_matches('"').to_string();
            if let Some(s) = pending_server.take() {
                if v.parse::<u16>().is_ok() && !out.contains(&format!("{}:{}", s, v)) {
                    out.push(format!("{}:{}", s, v));
                }
            }
        }
    }
    Ok(out)
}

/// Сброс AWG: учётка + скан-эндпоинты + конфиги. Активный канал — честный отказ.
pub fn awg_reset(app: &AppHandle) -> Result<Value, String> {
    let active = proxy_core::active_channel_id();
    if active == proxy_core::AWG_CHANNEL_ID || active == proxy_core::PAWG_CHANNEL_ID {
        return Err(String::from(
            "AWG/Proton-over-AWG сейчас активен — сначала выключи канал, потом сбрасывай учётку",
        ));
    }
    let _ = std::fs::remove_file(account_file());
    let _ = std::fs::remove_file(scanned_endpoints_file());
    let _ = std::fs::remove_file(proxy_core::proxy_dir().join("awg_profile.yaml"));
    let _ = std::fs::remove_file(proxy_core::proxy_dir().join("pawg_profile.yaml"));
    proxy_core::special_channels_sync(app);
    emit_log(app, String::from("[AWG] Учётка и конфиги сброшены."));
    Ok(awg_status_json())
}

/// Статус для фронта: факты без секретов (id/token/private_key не отдаются).
pub fn awg_status_json() -> Value {
    let has = has_account();
    let eps = current_endpoints().map(|v| v.len()).unwrap_or(0);
    json!({
        "has_account": has,
        "endpoints_count": eps,
        "endpoints_source": endpoints_source(),
        "pawg_available": has && crate::reserve::load_creds().is_some(),
    })
}

/// Точка входа команды awg_setup (main.rs, Шаг 4).
pub fn awg_setup(app: &AppHandle, action: String) -> Result<Value, String> {
    match action.as_str() {
        "register" => awg_register(app),
        "rescan" => awg_rescan(app),
        "reset" => awg_reset(app),
        _ => Err(format!("Неизвестное действие AWG: {}", action)),
    }
}
