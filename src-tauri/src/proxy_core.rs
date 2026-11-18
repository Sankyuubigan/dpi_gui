//! Прокси-движок DPI GUI (PRP «18.11.26 Кнопка запасного канала» v3):
//! платный и запасной каналы на ОДНОМ процессе mihomo.exe, proxy-only,
//! ноль внешних зависимостей. Переключение режима = рестарт ядра с другим
//! конфигом (<1с). Управление из фронта — команды channel_status/channel_set
//! (обёртки в main.rs). Самолечение запасного — reserve.rs (гард на REST API).

use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
    json!({
        "mode": if mode.is_empty() { "off".to_string() } else { mode },
        "mode_name": mode_name,
        "running": has_child && port_alive,
        "proxy_alive": port_alive,
        "proxy_port": PROXY_PORT,
        "reserve": crate::reserve::guard_status(),
    })
}

fn emit_log(app: &AppHandle, msg: String) {
    let _ = app.emit("log", format!("[Канал] {}", msg));
}

/// Гасим Koala Clash, если она держит канал (taskkill; отсутствие процесса — норма).
fn kill_koala(app: &AppHandle) {
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

/// Патч yaml-канала юзера: вписать порты (mixed-port/external-controller) и
/// принудительно выключить TUN (инвариант proxy-only, PRP v3). Строковый
/// патч, валидированный на paid_test 18.11.26 (Шаг 1): YAML-библиотеки в
/// зависимостях нет, а правки касаются только плоских скаляров.
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

    // 1) TUN off внутри tun-блока (границы — ключи первого уровня; dns.enable
    //    и прочие enable за границей блока не задеваются).
    let first_level = |l: &String| {
        !l.is_empty() && !l.starts_with(' ') && !l.starts_with('#') && l.contains(':')
    };
    let mut ti = None;
    let mut ni = None;
    for (i, l) in lines.iter().enumerate() {
        if first_level(l) {
            if l.starts_with("tun:") {
                ti = Some(i);
            } else if ti.is_some() && ni.is_none() {
                ni = Some(i);
                break;
            }
        }
    }
    if let (Some(t), Some(n)) = (ti, ni) {
        for i in t + 1..n {
            if lines[i].trim_end() == "enable: true" {
                let indent = lines[i].len() - lines[i].trim_start().len();
                lines[i] = format!("{}enable: false", " ".repeat(indent));
                break;
            }
        }
    }

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
