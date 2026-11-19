//! Прокси-движок DPI GUI (PRP «18.11.26 Кнопка запасного канала» v3):
//! платный и запасной каналы на ОДНОМ процессе mihomo.exe, proxy-only,
//! ноль внешних зависимостей. Переключение режима = рестарт ядра с другим
//! конфигом (<1с). Управление из фронта — команды channel_status/channel_set
//! (обёртки в main.rs). Самолечение запасного — reserve.rs (гард на REST API).

use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::process;

const MIHOMO_EXE: &str = "mihomo.exe";
const CREATE_NO_WINDOW: u32 = 0x08000000;
/// Порт, который mihomo держит для программ (браузер-расширение и т.п.).
pub const PROXY_PORT: u16 = 7897;
/// REST API ядра: единственная точка управления нодами из гарда (reserve.rs).
pub const API_PORT: u16 = 9097;
/// Koala Clash гасится при первом переключении канала: юзер сам решил её
/// выключить, канал 7897 переезжает к нам. Файлы Koala не трогаем.
const KOALA_PROCESS: &str = "Koala Clash.exe";

struct ChannelState {
    child: Option<Child>,
    mode: String,
}

static CHANNEL: Mutex<ChannelState> = Mutex::new(ChannelState {
    child: None,
    mode: String::new(),
});

/// Флаг гарда запасного канала (reserve.rs): true = цикл здоровья работает.
pub static GUARD_ON: AtomicBool = AtomicBool::new(false);

/// Служба-сторож FlClashX/Koala (AUTO_START, LocalSystem): рестартит sidecar
/// mihomo после нашего taskkill. Инцидент 19.11.26: мы погасили Koala при
/// переключении канала, сторож воскресил её через минуту, а fake-ip-хвосты
/// (маршруты 198.18.x + DNS-кэш Windows) парализовали весь системный трафик.
const KOALA_WATCHDOG_SERVICE: &str = "FlClashHelperService";

/// Кэш детекта перехвата: фронт опрашивает статус каждые 3с, полный проход
/// (таблица маршрутов + системный резолв) — не чаще 1 раза в 10с.
static HIJACK_TS: AtomicU64 = AtomicU64::new(0);
static HIJACK_DETECTED: AtomicBool = AtomicBool::new(false);
static HIJACK_DETAIL: Mutex<String> = Mutex::new(String::new());

/// Каталог прокси-движка в AppData: источники конфигов + сгенерированный paid.yaml.
pub(crate) fn proxy_dir() -> PathBuf {
    config::get_app_dir().join("proxy")
}

// ===================== Платные профили (PRP «18.11.26 Вкладка Канал») =====================
// Список платных YAML-профилей — у каждого юзера СВОЙ (личные платные подписки,
// делиться ими юзер не обязан). Файлы копируются в AppData/proxy/paid_profiles/,
// реестр — paid_profiles.json. В репо/бандл личное не попадает: новые юзеры
// стартуют с пустым списком и добавляют свои профили импортом на вкладке «Канал».

fn profiles_dir() -> PathBuf {
    proxy_dir().join("paid_profiles")
}

fn registry_file() -> PathBuf {
    proxy_dir().join("paid_profiles.json")
}

fn read_registry() -> Value {
    match std::fs::read_to_string(registry_file()) {
        Ok(t) => serde_json::from_str(&t)
            .unwrap_or_else(|_| json!({"profiles": [], "active": ""})),
        Err(_) => json!({"profiles": [], "active": ""}),
    }
}

/// Id канала WireGuard в реестре (креды глобальные — запись одна).
pub const WG_CHANNEL_ID: &str = "__wg__";

/// Имя канала по id записи (file) — для честного статуса и логов.
fn entry_name_by_file(reg: &Value, file_id: &str) -> Option<String> {
    reg["profiles"].as_array()?.iter()
        .find(|p| p["file"].as_str() == Some(file_id))
        .and_then(|p| p["name"].as_str())
        .map(|s| s.to_string())
}

fn write_registry(v: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(registry_file(), text)
        .map_err(|e| format!("не записать {}: {}", registry_file().display(), e))
}

/// Список платных профилей для фронта (реестр как есть).
pub fn paid_profiles_list() -> Value {
    read_registry()
}

/// Безопасное имя файла профиля: из стема исходника, только [a-z0-9_-].
/// Пустой результат → «profile».
fn sanitize_profile_file(stem: &str) -> String {
    let s: String = stem
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "profile".to_string() } else { s }
}

/// Добавление канала юзера: копия YAML-профиля в AppData (личное не должно
/// зависеть от внешнего пути — юзер может удалить исходник), лёгкая валидация
/// «это похоже на профиль clash/mihomo», регистрация в реестре. ИМЯ канала
/// задаёт юзер (PRP-правка 18.11.26 по требованию юзера, не автостем).
pub fn paid_profile_add(src: &str, name_param: &str, app: &AppHandle) -> Result<Value, String> {
    let text = std::fs::read_to_string(src)
        .map_err(|e| format!("не прочитать {}: {}", src, e))?;
    let looks_like_profile = ["proxies:", "proxy-providers:", "proxy-groups:"]
        .iter()
        .any(|k| text.contains(k));
    if !looks_like_profile {
        return Err(String::from(
            "Файл не похож на профиль mihomo/clash: нет секций proxies / proxy-providers / proxy-groups",
        ));
    }
    let stem = std::path::Path::new(src)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("profile");
    // Имя канала — слово юзера; пустое → честный фолбэк на имя файла.
    let display_name = {
        let t = name_param.trim();
        if t.is_empty() { stem.to_string() } else { t.to_string() }
    };
    let base = sanitize_profile_file(stem);

    let dir = profiles_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let mut file = String::new();
    for attempt in 0.. {
        file = if attempt == 0 {
            format!("{}.yaml", base)
        } else {
            format!("{}_{}.yaml", base, attempt + 1)
        };
        if !dir.join(&file).exists() {
            break;
        }
    }
    let dst = dir.join(&file);
    std::fs::write(&dst, &text).map_err(|e| format!("не записать {}: {}", dst.display(), e))?;

    let mut reg = read_registry();
    if let Some(arr) = reg["profiles"].as_array_mut() {
        arr.push(json!({
            "name": display_name,
            "file": file,
            "type": "yaml",
            "added": chrono_now_str(),
            "added_ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "size": text.len(),
        }));
    }
    let was_empty = reg["active"].as_str().unwrap_or("").is_empty();
    if was_empty {
        reg["active"] = json!(file);
    }
    write_registry(&reg)?;
    emit_log(app, format!("Канал «{}» добавлен{}.", display_name,
        if was_empty { " и сделан активным" } else { "" }));
    Ok(reg)
}

/// Удаление канала по его id (имени файла в реестре): файл + запись. Если
/// удалили активный — активным честно становится первый оставшийся (или никого).
pub fn paid_profile_delete(file_id: &str, app: &AppHandle) -> Result<Value, String> {
    let reg = read_registry();
    let profiles = reg["profiles"].as_array().ok_or("Реестр каналов повреждён")?;
    let found = profiles.iter()
        .find(|p| p["file"].as_str() == Some(file_id))
        .ok_or_else(|| format!("Канал «{}» не найден в списке", file_id))?;
    let gone_file = found["file"].as_str().unwrap_or("").to_string();
    let gone_name = found["name"].as_str().unwrap_or("").to_string();
    let active = reg["active"].as_str().unwrap_or("").to_string();

    let mut reg = reg;
    let profiles = reg["profiles"].as_array_mut().ok_or("Реестр каналов повреждён")?;
    profiles.retain(|p| p["file"].as_str() != Some(file_id));
    // Файл удалённого — в мусор (личные данные юзера не должны переживать его выбор).
    let _ = std::fs::remove_file(profiles_dir().join(&gone_file));
    // Активный удалён? → первый оставшийся, иначе пусто.
    if active == gone_file {
        reg["active"] = json!(profiles.first().and_then(|p| p["file"].as_str()).unwrap_or(""));
    }
    write_registry(&reg)?;
    emit_log(app, format!("Канал «{}» удалён.", gone_name));
    Ok(reg)
}

/// Синхронизация WG-записи в реестре каналов: креды глобальные, канал один —
/// запись с file = WG_CHANNEL_ID. Есть (по file) → обновить имя; нет → добавить.
/// Активный канал не трогаем: импорт кредов сам по себе не переключает канал.
pub fn wg_channel_sync(app: &AppHandle, name: &str) -> Result<Value, String> {
    let mut reg = read_registry();
    let display = {
        let t = name.trim();
        if t.is_empty() { String::from("Запасной (WG)") } else { t.to_string() }
    };
    let profiles = reg["profiles"].as_array_mut().ok_or("Реестр каналов повреждён")?;
    if let Some(entry) = profiles.iter_mut().find(|p| p["file"].as_str() == Some(WG_CHANNEL_ID)) {
        entry["name"] = json!(display);
    } else {
        profiles.push(json!({
            "name": display,
            "file": WG_CHANNEL_ID,
            "type": "wg",
            "added": chrono_now_str(),
            "added_ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "size": 0,
        }));
    }
    write_registry(&reg)?;
    emit_log(app, format!("Канал «{}» (WireGuard) готов к включению.", display));
    Ok(reg)
}

/// Удаление WG-записи из реестра (при сбросе кредов). Активный «__wg__»?
/// → первый оставшийся канал, иначе пусто.
pub fn wg_channel_remove(app: &AppHandle) -> Result<Value, String> {
    let mut reg = read_registry();
    let active = reg["active"].as_str().unwrap_or("").to_string();
    if let Some(profiles) = reg["profiles"].as_array_mut() {
        profiles.retain(|p| p["file"].as_str() != Some(WG_CHANNEL_ID));
    }
    if active == WG_CHANNEL_ID {
        let first = reg["profiles"].as_array()
            .and_then(|a| a.first())
            .and_then(|p| p["file"].as_str())
            .unwrap_or("")
            .to_string();
        reg["active"] = json!(first);
    }
    write_registry(&reg)?;
    emit_log(app, "WG-канал убран из списка каналов.".into());
    Ok(reg)
}

/// Дата-время «18.11.26 21:45» для реестра (без внешних крейтов).
fn chrono_now_str() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    // Гражданское время из дней с эпохи (алгоритм Говарда Хиннанта, UTC+0
    // достаточно: дата добавления — справочная метка, не бизнес-логика).
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let sod = secs % 86400;
    format!("{:02}.{:02}.{} {:02}:{:02}", d, m, y % 100, sod / 3600, (sod % 3600) / 60)
}

/// Ensure-файлы движка (вызывается из init_app при каждом запуске):
/// 1) шаблон запасного и пул нод — жёсткая перезапись из встроенных исходников
///    (контракт владельца, как дефолтные списки config.rs: правки едут релизами);
/// 2) тихая миграция автора: старый paid_source.yaml регистрируется профилем,
///    WG-поля старого reserve_profile.yaml парсятся в wg_creds.json;
/// 3) перегенерация reserve_profile.yaml из ТЕКУЩЕГО шаблона + кредов (если
///    креды есть) — обновления шаблона доезжают до юзера без его действий.
pub fn ensure_proxy_files(app: &AppHandle) -> Result<(), String> {
    let dir = proxy_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let writes: &[(&str, &str)] = &[
        ("reserve_template.yaml", include_str!("../defaults/reserve_template.yaml")),
        ("providers/igareck_ss.yaml", include_str!("../defaults/igareck_ss.yaml")),
        ("providers/igareck_vless.yaml", include_str!("../defaults/igareck_vless.yaml")),
    ];
    for (rel, content) in writes {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("не создать {}: {}", parent.display(), e))?;
        }
        std::fs::write(&p, content)
            .map_err(|e| format!("не записать {}: {}", p.display(), e))?;
    }

    // Миграция платного: реестра нет, а paid_source.yaml есть → профиль «NeVPN (импорт)».
    if !registry_file().exists() {
        let old = dir.join("paid_source.yaml");
        if old.exists() {
            let old_str = old.to_string_lossy().to_string();
            if let Err(e) = paid_profile_add(&old_str, "", app) {
                emit_log(app, format!("Миграция платного профиля не удалась: {}", e));
            } else {
                emit_log(app, "Прежний платный профиль перенесён во вкладку «Канал».".into());
            }
        }
    }

    // Миграция WG-кредов + перегенерация reserve_profile.yaml из текущего шаблона.
    crate::reserve::migrate_existing_creds(app);
    if crate::reserve::has_wg_creds() {
        crate::reserve::generate_reserve_config()?;
    }
    Ok(())
}

/// TCP-живость порта: соединение с коротким таймаутом. Не «HTTP-успех», но
/// для честного статуса процесса этого достаточно (порт занят = процесс жив).
fn port_alive(port: u16) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    match addr.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_millis(700)).is_ok(),
        None => false,
    }
}

/// Честный статус канала для фронта. Мёртвый процесс = не «активен» (§2.2):
/// mode при этом может оставаться «paid», но running=false — честнее зелёного бейджа.
pub fn status() -> serde_json::Value {
    let (mode, has_child) = match CHANNEL.lock() {
        Ok(g) => (g.mode.clone(), g.child.is_some()),
        Err(_) => (String::from("off"), false),
    };
    let port_alive = port_alive(PROXY_PORT);
    // Человеческое имя канала из реестра юзера (id файла / «__wg__» → имя,
    // заданное юзером); «off» и незнакомый id — честная пустота.
    let mode_name = if mode.is_empty() {
        String::new()
    } else {
        entry_name_by_file(&read_registry(), &mode).unwrap_or_else(|| mode.clone())
    };
    let (hijack, hijack_detail) = hijack_check();
    json!({
        "mode": if mode.is_empty() { "off".to_string() } else { mode },
        "mode_name": mode_name,
        "running": has_child && port_alive,
        "proxy_alive": port_alive,
        "proxy_port": PROXY_PORT,
        "reserve": crate::reserve::guard_status(),
        // §честность: зелёный «порт жив» при перехваченном системном
        // трафике — ложь, поэтому детект перехвата едет рядом с портом.
        "hijack": hijack,
        "hijack_detail": hijack_detail,
    })
}

fn emit_log(app: &AppHandle, msg: String) {
    let _ = app.emit("log", format!("[Канал] {}", msg));
}

// ===================== Системный перехват: сторож, мины, честный детект =====================
// Инцидент 19.11.26: системный трафик целиком уходил в чужой fake-ip TUN
// (198.18.0.x — трассировка «1 хоп <1мс»), а наш статус рисовал зелёный
// «порт жив». Наш движок proxy-only (TUN всегда off, DNS на 53 не слушает),
// поэтому ЛЮБОЙ след 198.18.0.0/15 в системе — чужой перехватчик, о котором
// софт обязан говорить прямо (§честность) и предлагать починку.

/// Сторож-служба FlClashX: остановить и отключить, иначе она воскресит
/// sidecar после нашего taskkill (инцидент: воскресла через минуту).
/// Koala GUI при ЯВНОМ запуске юзером включит службу сама — её выбор,
/// а тихого воскресения за нашей спиной больше не будет.
fn stop_koala_watchdog() -> Vec<String> {
    let mut log = Vec::new();
    let stop = Command::new("sc")
        .args(["stop", KOALA_WATCHDOG_SERVICE])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let cfg = Command::new("sc")
        .args(["config", KOALA_WATCHDOG_SERVICE, "start=", "disabled"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    if let (Ok(s), Ok(c)) = (stop, cfg) {
        if c.status.success() {
            log.push(format!(
                "Сторож-служба {} остановлена ({}) и отключена — Koala не воскреснет за нами.",
                KOALA_WATCHDOG_SERVICE,
                if s.status.success() { "была жива" } else { "не была запущена" }
            ));
            thread::sleep(Duration::from_millis(600));
        } else if s.status.success() {
            log.push(format!(
                "Сторож-служба {} остановлена, но отключить не удалось (проверь вручную: sc qc {}).",
                KOALA_WATCHDOG_SERVICE, KOALA_WATCHDOG_SERVICE
            ));
        }
        // Обе команды с ошибкой = службы в системе нет: шум не логируем.
    }
    log
}

/// Маршруты-мины 198.18.0.0/15 в таблице маршрутов Windows: (назначение, маска).
fn fakeip_routes_in_table() -> Vec<(String, String)> {
    let out = match Command::new("route")
        .args(["print", "-4"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };
    parse_fakeip_routes(&out)
}

/// Чистый парс вывода route print -4 (тестируемый без живой системы).
/// OEM-кодировка заголовков не важна: парсятся только ASCII-поля IP.
fn parse_fakeip_routes(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let dest = match f[0].parse::<std::net::Ipv4Addr>() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if f[1].parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        let o = dest.octets();
        // 198.18.0.0/15 (RFC 2544; диапазон fake-ip mihomo/clash 198.18.0.1/16 внутри).
        if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
            found.push((f[0].to_string(), f[1].to_string()));
        }
    }
    found
}

/// Снятие маршрутов-мин из таблицы. DNS-кэш здесь не трогаем — решение
/// за вызывающим (channel_set сбрасывает только при снятых минах, фикс — всегда).
pub fn cleanup_stale_fakeip() -> Vec<String> {
    let mut removed = Vec::new();
    for (dest, mask) in fakeip_routes_in_table() {
        let del = Command::new("route")
            .args(["delete", &dest, "mask", &mask])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if del.map(|o| o.status.success()).unwrap_or(false) {
            removed.push(format!("{}/{}", dest, mask));
        }
    }
    removed
}

/// Сброс DNS-кэша Windows: резолвер мог насвиновать fake-ip-ответами,
/// которые переживут смерть перехватчика (кейс 198.18.0.98 в tracert).
fn flush_dns() {
    let _ = Command::new("ipconfig")
        .args(["/flushdns"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// Системный резолв контрольного домена без прокси: Ok(Some(ip)) — резолв
/// отдаёт fake-ip (перехват DNS-слоя); Ok(None) — чисто; Err — не ответил
/// за 3с (это не вердикт перехвата, сеть может быть просто мертва).
fn system_resolve_fakeip() -> Result<Option<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let bad = ("github.com", 0)
            .to_socket_addrs()
            .ok()
            .and_then(|it| {
                it.filter_map(|sa| match sa {
                    std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                    std::net::SocketAddr::V6(_) => None,
                })
                .find(|ip| {
                    let o = ip.octets();
                    o[0] == 198 && (o[1] == 18 || o[1] == 19)
                })
                .map(|ip| ip.to_string())
            });
        let _ = tx.send(bad);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(res) => Ok(res),
        Err(_) => Err(String::from("системный резолв не ответил за 3с")),
    }
}

/// Детект перехвата с троттлингом: (обнаружен, человеческое пояснение).
/// Перехват = маршруты-мины в 198.18.0.0/15 ИЛИ fake-ip в системном резолве.
fn hijack_check() -> (bool, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = HIJACK_TS.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < 10 {
        let detail = HIJACK_DETAIL.lock().map(|g| g.clone()).unwrap_or_default();
        return (HIJACK_DETECTED.load(Ordering::Relaxed), detail);
    }
    HIJACK_TS.store(now, Ordering::Relaxed);

    let routes = fakeip_routes_in_table().len();
    let (detected, detail) = match system_resolve_fakeip() {
        Ok(Some(ip)) => (
            true,
            format!(
                "системный резолв отдаёт fake-ip {} (чужой перехватчик){}",
                ip,
                if routes > 0 { format!(", маршрутов-мин: {}", routes) } else { String::new() }
            ),
        ),
        Ok(None) if routes > 0 => (
            true,
            format!("в таблице маршрутов {} мин(ы) 198.18.0.0/15 — остатки чужого TUN", routes),
        ),
        Ok(None) => (false, String::new()),
        Err(e) if routes > 0 => (
            true,
            format!("в таблице маршрутов {} мин(ы) 198.18.0.0/15 — остатки чужого TUN; {}", routes, e),
        ),
        Err(_) => (false, String::new()),
    };
    HIJACK_DETECTED.store(detected, Ordering::Relaxed);
    if let Ok(mut g) = HIJACK_DETAIL.lock() {
        *g = detail.clone();
    }
    (detected, detail)
}

/// Гасим Koala Clash, если она держит канал (taskkill; отсутствие процесса — норма).
/// СНАЧАЛА сторож-служба: без её гашения Koala воскресит sidecar через
/// минуту после taskkill (инцидент 19.11.26) и оставит мины в сети.
fn kill_koala(app: &AppHandle) {
    for line in stop_koala_watchdog() {
        emit_log(app, line);
    }
    let out = Command::new("taskkill")
        .args(["/F", "/IM", KOALA_PROCESS])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            emit_log(app, "Koala Clash остановлена — порт 7897 освобождён для канала.".into());
            thread::sleep(Duration::from_millis(800));
        }
    }
}

/// Убиваем ЛЮБОЙ mihomo.exe: наш дочерний handle теряется при рестарте GUI,
/// а сирота продолжает держать 7897 и сорвал бы новый спавн. Наш движок —
/// единственный владелец этого имени процесса в системе (PRP v3).
fn kill_mihomo_any() {
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", MIHOMO_EXE])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    // Child из CHANNEL добиваем вручную: taskkill снял процесс по имени, но
    // handle должен закрыться, чтобы не копился зомби-дескриптор.
    if let Ok(mut g) = CHANNEL.lock() {
        if let Some(mut child) = g.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        g.mode = String::from("off");
    }
}

/// Остановка канала (без убийства по имени — только наш ребёнок). Для «off».
fn stop_channel(app: Option<&AppHandle>) -> bool {
    GUARD_ON.store(false, Ordering::SeqCst);
    let had_child = if let Ok(mut g) = CHANNEL.lock() {
        let had = g.child.is_some();
        if let Some(mut child) = g.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(a) = app {
                emit_log(a, "Процесс mihomo остановлен.".into());
            }
        }
        g.mode = String::from("off");
        had
    } else {
        false
    };
    had_child
}

/// Гашение всего канала при выходе из приложения (main.rs CloseRequested):
/// гард останавливаем первее — он мог бы потушить/оживить уже убитое ядро.
pub fn shutdown_for_exit() {
    GUARD_ON.store(false, Ordering::SeqCst);
    stop_channel(None);
}

/// Старт mihomo с конфигом и ожидание живого порта. Ребёнок кладётся в CHANNEL.
fn start_mihomo(app: &AppHandle, config_path: &PathBuf) -> Result<(), String> {
    let bin_dir = process::get_bin_dir()?;
    let mihomo_path = bin_dir.join(MIHOMO_EXE);
    if !mihomo_path.exists() {
        return Err(format!(
            "mihomo.exe не найден в {} — движок прокси не собран в бандл",
            bin_dir.display()
        ));
    }
    let work_dir = proxy_dir();
    if !work_dir.exists() {
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("не создать {}: {}", work_dir.display(), e))?;
    }

    let mut child = Command::new(&mihomo_path)
        .arg("-d")
        .arg(&work_dir)
        .arg("-f")
        .arg(config_path)
        .current_dir(&work_dir)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Ошибка запуска {}: {}", MIHOMO_EXE, e))?;

    emit_log(app, format!("mihomo запущен (PID {}, конфиг {})", child.id(), config_path.display()));

    // stdout/stderr ядра → вкладка «Логи» (§2.5), как у winws.
    let app_out = app.clone();
    if let Some(out) = child.stdout.take() {
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(out).lines().flatten() {
                let _ = app_out.emit("log", format!("[mihomo] {}", line));
            }
        });
    }
    let app_err = app.clone();
    if let Some(err) = child.stderr.take() {
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(err).lines().flatten() {
                let _ = app_err.emit("log", format!("[mihomo ERROR] {}", line));
            }
        });
    }

    // Ожидание порта до 10с: старт ядра <1с, но правило модифицирует провайдеры —
    // запас времени на их загрузку (медленная машина не должна дать ложный отказ).
    let mut up = false;
    for _ in 0..20 {
        if port_alive(PROXY_PORT) {
            up = true;
            break;
        }
        // Мёртвый ребёнок дальше ждать бессмысленно — честная ошибка сейчас.
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    if !up {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Порт {} не поднялся за 10с — смотри логи mihomo во вкладке «Логи»",
            PROXY_PORT
        ));
    }
    emit_log(app, format!("Канал жив: порт {} принимает соединения.", PROXY_PORT));

    if let Ok(mut g) = CHANNEL.lock() {
        g.child = Some(child);
    }
    Ok(())
}

/// Чистый патч строк yaml-профиля (тестируемый без ФС; инвариант proxy-only).
/// 1) TUN off: в tun-блоке (от `tun:` до следующего ключа первого уровня)
///    `enable: true` с ЛЮБЫМ отступом → `enable: false` (старый матч через
///    trim_end() не снимал ведущий отступ — матч не срабатывал никогда, TUN
///    поднимался на yaml-каналах: весь трафик системы уходил в наш mihomo
///    через TUN + auto-route + dns-hijack any:53, инцидент 19.11.26); если
///    enable в блоке нет вообще — вставляется `enable: false` сразу после
///    `tun:` (гарантия инварианта); flow-style `tun: {enable: true, ...}` —
///    замена прямо в строке. dns.enable, sniffer.enable и прочие enable вне
///    блока не задеваются.
/// 2) Порты НЕ трогает: их вписывает generate_paid_config (замена/вставка
///    после log-level) — иначе они применятся дважды.
fn patch_yaml_lines(lines: &mut Vec<String>) {
    // --- 1) TUN off ---
    let first_level = |l: &str| {
        !l.is_empty() && !l.starts_with(' ') && !l.starts_with('#') && l.contains(':')
    };
    // Flow-style `tun: {enable: true, ...}` — замена прямо в строке: блочный
    // патч такой enable не увидит (он внутри одной строки).
    if let Some(i) = lines.iter().position(|l| l.starts_with("tun:") && l.contains("{")) {
        lines[i] = lines[i]
            .replace("enable: true", "enable: false")
            .replace("enable:true", "enable: false");
    }
    let (ti, ni) = {
        let mut ti = None;
        let mut ni = None;
        for (i, l) in lines.iter().enumerate() {
            if first_level(l) {
                if l.starts_with("tun:") {
                    ti = Some(i);
                } else if ti.is_some() {
                    ni = Some(i);
                    break;
                }
            }
        }
        (ti, ni)
    };
    if let Some(t) = ti {
        let end = ni.unwrap_or(lines.len());
        // Инцидент 19.11.26: enable: true ГЛУБОКО в блоке (за списком
        // exclude-package) с отступом — trim_end-матч его не находил, TUN
        // поднимался и перехватывал систему целиком.
        if let Some(i) = (t + 1..end).find(|&i| matches!(lines[i].trim(), "enable: true" | "enable:true")) {
            let indent = lines[i].len() - lines[i].trim_start().len();
            lines[i] = format!("{}enable: false", " ".repeat(indent));
        } else if !lines[t].contains("{") && !(t + 1..end).any(|i| lines[i].trim() == "enable: false") {
            // enable в блоке нет вообще — гарантированная вставка (инвариант
            // proxy-only обязан быть видимым в тексте конфига).
            lines.insert(t + 1, "  enable: false".to_string());
        }
    }
}

/// Патч yaml-канала юзера: вписать порты (mixed-port/external-controller) и
/// выключить TUN чистым патчером patch_yaml_lines (юнит-тесты patcher_tests;
/// после инцидента 19.11.26 «валидация» старого патча была фикцией). YAML-
/// библиотеки в зависимостях нет, а правки касаются только плоских скаляров.
/// Источник — id канала из реестра (имя файла без пути): патч-защита от
/// path traversal (mode со «/», «\», «..» не дойдёт до файловой системы),
/// плюс канал обязан быть в реестре юзера — чужой файл не патчим.
fn generate_paid_config(src_file: &str) -> Result<PathBuf, String> {
    if src_file.contains('\\') || src_file.contains('/') || src_file.contains("..") {
        return Err(format!("Недопустимый id канала: «{}»", src_file));
    }
    let reg = read_registry();
    if entry_name_by_file(&reg, src_file).is_none() {
        return Err(format!("Канал «{}» не найден в списке — добавь его заново", src_file));
    }
    let dir = proxy_dir();
    let src_path = profiles_dir().join(src_file);
    let out_path = dir.join("paid.yaml");
    let text = std::fs::read_to_string(&src_path)
        .map_err(|e| format!("не прочитать {}: {}", src_path.display(), e))?;

    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();

    // 1) TUN off: вынесен в чистый патчер patch_yaml_lines (trim-матч с любым
    //    отступом, гарантированная вставка enable: false при отсутствии, flow-style):
    //    старый trim_end-матч не снимал ведущий отступ и никогда не срабатывал —
    //    TUN поднимался на ВСЕХ yaml-каналах, весь трафик системы уходил в наш
    //    mihomo (TUN + auto-route + dns-hijack any:53), инцидент 19.11.26.
    patch_yaml_lines(&mut lines);

    // 2) Порты: заменить существующие ключи, иначе вставить после log-level.
    let ports = [
        format!("mixed-port: {}", PROXY_PORT),
        format!("external-controller: 127.0.0.1:{}", API_PORT),
    ];
    for key in ["mixed-port:", "external-controller:"] {
        if let Some(i) = lines
            .iter()
            .position(|l| l.starts_with(key) && !l.starts_with(' '))
        {
            lines.remove(i);
        }
    }
    let after = lines
        .iter()
        .position(|l| l.starts_with("log-level:"))
        .unwrap_or(0);
    for (off, port_line) in ports.iter().enumerate() {
        lines.insert(after + 1 + off, port_line.clone());
    }

    std::fs::write(&out_path, lines.join("\n") + "\n")
        .map_err(|e| format!("не записать {}: {}", out_path.display(), e))?;
    Ok(out_path)
}

/// Проверка запасного конфига: файл и ключевые поля (порты, WG-сервер).
fn validate_reserve_config() -> Result<PathBuf, String> {
    let path = proxy_dir().join("reserve_profile.yaml");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Нет запасного профиля {} — положи валидированный шаблон в эту папку", path.display()))?;
    if !text.contains(&format!("mixed-port: {}", PROXY_PORT)) {
        return Err(format!("{}: ожидался mixed-port: {} — файл не тот?", path.display(), PROXY_PORT));
    }
    if !text.contains("type: wireguard") {
        return Err(format!("{}: нет wireguard outbound — запасной канал без WG невозможен", path.display()));
    }
    Ok(path)
}

/// Переключение канала. mode — id из реестра юзера: «off», «__wg__»
/// (запасной WireGuard) или имя файла yaml-канала. Единственная бизнес-точка;
/// команды фронта её вызывают. Гейты ДО убийства Koala: нечего включать —
/// честная ошибка без побочных эффектов (Koala продолжает держать канал).
pub fn channel_set(app: &AppHandle, mode: &str) -> Result<String, String> {
    match mode {
        "off" => {
            let was = stop_channel(Some(app));
            // Вердикт перехвата пересчитать сразу: при живом канале TUN-хвост
            // мог быть валидным до чистки (баг патчера до 19.11.26).
            HIJACK_TS.store(0, Ordering::Relaxed);
            emit_log(app, "Канал выключен.".into());
            if was {
                Ok("Канал выключен.".into())
            } else {
                Ok("Канал и так был выключен.".into())
            }
        }
        "__wg__" => {
            if !crate::reserve::has_wg_creds() {
                return Err(String::from(
                    "Нет WireGuard-кредов — импортируй WG .conf на вкладке «Канал»",
                ));
            }
            GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            crate::reserve::generate_reserve_config()?;
            let config_path = validate_reserve_config()?;
            start_mihomo(app, &config_path)?;
            crate::reserve::start_guard(app.clone());
            emit_log(app, "Запасной канал: гард самолечения запущен.".into());
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| String::from("Запасной (WG)"));
            Ok(format!("Канал «{}» включён.", name))
        }
        _ => {
            // Любой другой mode — id yaml-канала из реестра юзера.
            let config_path = generate_paid_config(mode)?;
            GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            start_mihomo(app, &config_path)?;
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| mode.to_string());
            Ok(format!("Канал «{}» включён.", name))
        }
    }
}

/// Активный канал в реестре фиксируется только на УСПЕХЕ переключения
/// (упавший старт не должен переписывать прошлый выбор юзера).
fn mark_active_channel(file_id: &str) {
    let mut reg = read_registry();
    reg["active"] = json!(file_id);
    let _ = write_registry(&reg);
}

/// «Починить систему» — действие под честный баннер перехвата: гасим сторожа
/// Koala и ЧУЖИЕ mihomo-процессы (ядро перехватчика обязано умереть ДО снятия
/// маршрутов, иначе успеет накласть их заново; наш ребёнок, если канал
/// включён, не трогаем — починка не должна убивать канал юзера), снимаем
/// маршруты-мины, сбрасываем DNS-кэш. Построчный отчёт — в лог фронта.
pub fn channel_fix_system(app: &AppHandle) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    log.extend(stop_koala_watchdog());

    let our_pid = CHANNEL.lock().ok().and_then(|g| g.child.as_ref().map(|c| c.id()));
    let mut killed = Vec::new();
    if our_pid.is_none() {
        // Наш канал выключен: имя mihomo.exe в системе может носить только чужой.
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", MIHOMO_EXE])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", KOALA_PROCESS])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        killed.push(String::from("mihomo.exe и Koala Clash (по имени)"));
    } else {
        // Канал включён: чужие mihomo гасим по PID (wmic), наш не задеваем.
        if let Ok(o) = Command::new("wmic")
            .args(["process", "where", "name='mihomo.exe'", "get", "ProcessId"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    if Some(pid) != our_pid {
                        let _ = Command::new("taskkill")
                            .args(["/F", "/PID", &pid.to_string()])
                            .creation_flags(CREATE_NO_WINDOW)
                            .output();
                        killed.push(format!("mihomo PID {}", pid));
                    }
                }
            }
        }
    }
    if !killed.is_empty() {
        log.push(format!("Погашены чужие процессы: {}.", killed.join(", ")));
    }

    let removed = cleanup_stale_fakeip();
    if removed.is_empty() {
        log.push(String::from("Маршрутов-мин 198.18.0.0/15 в таблице нет."));
    } else {
        log.push(format!("Сняты маршруты-мины перехватчика: {}.", removed.join(", ")));
    }
    flush_dns();
    log.push(String::from("DNS-кэш Windows сброшен — fake-ip-ответы перехватчика вычищены."));

    // Детект пересчитываем немедленно (троттлинг сброшен) — честный вердикт.
    HIJACK_TS.store(0, Ordering::Relaxed);
    let (detected, detail) = hijack_check();
    if detected {
        log.push(format!("ПРЕДУПРЕЖДЕНИЕ: признаки перехвата остались — {}.", detail));
    } else {
        log.push(String::from("Система чиста: следов fake-ip нет."));
    }
    for line in &log {
        emit_log(app, line.clone());
    }
    Ok(log)
}

#[cfg(test)]
mod fakeip_tests {
    use super::parse_fakeip_routes;

    /// Фрагмент живой route print -4 с минами инцидента 19.11.26: строки
    /// «198.18.0.26  255.255.255.255  10.98.0.1  10.98.0.2  26» (хвосты
    /// Koala/FlClash fake-ip через TAP-шлюз) + шум, который не должен парситься.
    #[test]
    fn fakeip_routes_parsed_from_table() {
        let sample = "===========================================================================\n\
Список интерфейсов\n\
 12...xx Realtek PCIe GbE Family Controller\n\
===========================================================================\n\
\nАктивные маршруты:\n\
Сетевой адрес           Маска сети          Адрес шлюза       Интерфейс  Метрика\n\
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25\n\
     198.18.0.26  255.255.255.255         10.98.0.1        10.98.0.2     26\n\
     198.18.0.98  255.255.255.255      127.0.0.1         127.0.0.1     31\n\
        224.0.0.0        240.0.0.0   На канале\n";
        let r = parse_fakeip_routes(sample);
        assert_eq!(r.len(), 2, "мины 198.18.x должны найтись, шум остаться");
        assert_eq!(r[0], ("198.18.0.26".to_string(), "255.255.255.255".to_string()));
        assert_eq!(r[1], ("198.18.0.98".to_string(), "255.255.255.255".to_string()));
    }

    /// Чистая таблица без перехватчика: ноль мин (ложная тревога недопустима).
    #[test]
    fn clean_table_gives_no_mines() {
        let sample = "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25\n\
        127.0.0.0        255.0.0.0      127.0.0.1        127.0.0.1     31\n\
      198.20.0.1  255.255.255.255      192.168.1.1     192.168.1.10     26\n";
        assert!(parse_fakeip_routes(sample).is_empty(), "198.20.x вне /15 — не мина");
    }
}

#[cfg(test)]
mod patcher_tests {
    use super::patch_yaml_lines;

    fn patch(text: &str) -> Vec<String> {
        let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
        patch_yaml_lines(&mut lines);
        lines
    }

    /// Инцидент 19.11.26: enable: true ГЛУБОКО в tun-блоке (за списком
    /// exclude-package) с отступом — старый trim_end-патчер НЕ выключал TUN,
    /// весь трафик системы уходил в наш mihomo (TUN + auto-route + dns-hijack).
    #[test]
    fn deep_indented_tun_enable_true_is_disabled() {
        let out = patch("tun:\n  exclude-package:\n    - a.b\n    - c.d\n  enable: true\n  auto-route: true\ndns:\n  enable: true\n");
        let dns_at = out.iter().position(|l| l == "dns:").unwrap();
        let tun_block = &out[..dns_at];
        assert!(
            tun_block.iter().any(|l| l.trim() == "enable: false"),
            "tun enable обязан стать false"
        );
        assert!(
            !tun_block.iter().any(|l| l.trim() == "enable: true"),
            "в tun-блоке не должно остаться enable: true"
        );
        // dns.enable не тронут (контракт: правки только внутри tun-блока).
        assert_eq!(out.last().map(|l| l.as_str()), Some("  enable: true"));
        // auto-route остался на месте (не мешает при enable: false).
        assert!(out.iter().any(|l| l.trim() == "auto-route: true"));
    }

    /// enable в tun-блоке отсутствует → патчер ДОЛЖЕН вставить enable: false
    /// (инвариант proxy-only обязан быть видимым в конфиге).
    #[test]
    fn tun_without_enable_gets_explicit_false() {
        let out = patch("tun:\n  stack: gvisor\nlog-level: info\n");
        assert_eq!(out[1], "  enable: false");
        assert!(out.iter().any(|l| l.trim() == "stack: gvisor"));
    }

    /// Flow-style `tun: {enable: true, ...}` — замена прямо в строке, без
    /// вставки строк внутрь (вставка после flow-строки сломала бы YAML).
    #[test]
    fn flow_style_tun_enable_is_disabled_inplace() {
        let out = patch("tun: {enable: true, stack: mixed}\nlog-level: info\n");
        assert_eq!(out[0], "tun: {enable: false, stack: mixed}");
        assert_eq!(out[1], "log-level: info");
    }

    /// Порты и dns.enable патчер НЕ трогает (порты вписывает
    /// generate_paid_config — иначе дублировались бы).
    #[test]
    fn ports_and_dns_enable_untouched() {
        let out = patch("mixed-port: 7890\nlog-level: info\ndns:\n  enable: true\n");
        assert!(out.iter().any(|l| l == "mixed-port: 7890"));
        assert_eq!(out[1], "log-level: info");
        assert_eq!(out.last().map(|l| l.as_str()), Some("  enable: true"));
    }
}
