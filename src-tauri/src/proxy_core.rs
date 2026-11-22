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

pub(crate) const MIHOMO_EXE: &str = "mihomo.exe";
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

/// Id канала WARP в реестре (учётка глобальная — запись одна; Этап B).
pub const WARP_CHANNEL_ID: &str = "__warp__";

/// Id канала AWG (WARP-ключи + amnezia-junk, loc=RU, ютуб) в реестре.
pub const AWG_CHANNEL_ID: &str = "__awg__";

/// Id канала Proton-over-AWG (Proton WG поверх AWG-туннеля, loc=NL) в реестре.
pub const PAWG_CHANNEL_ID: &str = "__pawg__";

/// Id канала Psiphon (aether sidecar, резерв §9) в реестре.
pub const PSIPHON_CHANNEL_ID: &str = "__psiphon__";

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

/// Канонические имена платных YAML-каналов (21.11.26: имя канала = метод,
/// переименование руками убрано): «Платная подписка», дубль → «Платная
/// подписка 2» по порядку реестра. Идемпотентно, вызывается из ensure —
/// юзерские имена не переживают запуск.
pub fn paid_names_canonicalize(app: &AppHandle) {
    let mut reg = read_registry();
    let mut n = 0u32;
    let mut changed = false;
    if let Some(profiles) = reg["profiles"].as_array_mut() {
        for p in profiles.iter_mut() {
            // Платные — записи с файловым id (не «__…»). У старых миграций
            // type может отсутствовать (смоук 21.11: paid_source остался без
            // канона) — критерий по id, не по type.
            let is_paid = p["file"].as_str()
                .map(|f| !f.starts_with("__") && (f.ends_with(".yaml") || f.ends_with(".yml")))
                .unwrap_or(false);
            if is_paid {
                n += 1;
                let canon = if n == 1 {
                    String::from("Платная подписка")
                } else {
                    format!("Платная подписка {}", n)
                };
                if p["name"].as_str() != Some(&canon) {
                    p["name"] = json!(canon);
                    changed = true;
                }
            }
        }
    }
    if changed {
        let _ = write_registry(&reg);
        emit_log(app, "Имена платных каналов приведены к канону метода («Платная подписка»).".into());
    }
}

/// Добавление канала юзера: копия YAML-профиля в AppData (личное не должно
/// зависеть от внешнего пути — юзер может удалить исходник), лёгкая валидация
/// «это похоже на профиль clash/mihomo», регистрация в реестре. ИМЯ канала —
/// канон метода (21.11.26: переименование руками убрано, имя задаёт код).
pub fn paid_profile_add(src: &str, app: &AppHandle) -> Result<Value, String> {
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
    // Имя канала — канон метода: «Платная подписка», при существующих
    // платных — следующий свободный номер (счётчик по реестру).
    let display_name = {
        let reg = read_registry();
        let existing: Vec<String> = reg["profiles"].as_array()
            .map(|arr| arr.iter().filter_map(|p| p["name"].as_str().map(String::from)).collect())
            .unwrap_or_default();
        let base = String::from("Платная подписка");
        if !existing.contains(&base) {
            base
        } else {
            let mut n = 2u32;
            while existing.contains(&format!("{} {}", base, n)) { n += 1; }
            format!("{} {}", base, n)
        }
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
/// Канон имени WG-канала (21.11.26: имя канала = метод, переименование руками
/// убрано). Провайдер кредов не вшивается в имя — у любого юзера свой .conf;
/// страну выхода показывает «Тест каналов».
pub const WG_CHANNEL_NAME: &str = "WireGuard через паблик Xray/V2Ray";

pub fn wg_channel_sync(app: &AppHandle) -> Result<Value, String> {
    let mut reg = read_registry();
    let display = WG_CHANNEL_NAME;
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

/// Синхронизация WARP-записи в реестре каналов (Этап B): учётка глобальная —
/// запись одна, file = WARP_CHANNEL_ID, type = "warp". Имя фиксированное:
/// учётка анонимная и одна — переименовывать нечего (в отличие от платных).
pub fn warp_channel_sync(app: &AppHandle) -> Result<Value, String> {
    let mut reg = read_registry();
    let display = String::from("WARP (Cloudflare)");
    let profiles = reg["profiles"].as_array_mut().ok_or("Реестр каналов повреждён")?;
    if let Some(entry) = profiles.iter_mut().find(|p| p["file"].as_str() == Some(WARP_CHANNEL_ID)) {
        entry["name"] = json!(display);
    } else {
        profiles.push(json!({
            "name": display,
            "file": WARP_CHANNEL_ID,
            "type": "warp",
            "added": chrono_now_str(),
            "added_ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "size": 0,
        }));
    }
    write_registry(&reg)?;
    emit_log(app, format!("Канал «{}» готов к включению.", display));
    Ok(reg)
}

/// Синхронизация «специальных» каналов (AWG / Proton-over-AWG / Psiphon) с
/// реестром: запись есть ⇔ есть данные (AWG-учётка / учётка+креды Proton /
/// Psiphon всегда — недостающие данные дают честную ошибку в channel_set).
/// Вызывается из ensure_proxy_files при каждом запуске и после регистрации/сброса AWG.
pub fn special_channels_sync(app: &AppHandle) {
    let has_awg = crate::awg::has_account();
    let rows: [(&str, &str, &str, bool); 3] = [
        (AWG_CHANNEL_ID, "WARP AWG", "awg", has_awg),
        (
            PAWG_CHANNEL_ID,
            "AWG Proton WARP",
            "pawg",
            has_awg && crate::reserve::load_creds().is_some(),
        ),
        (PSIPHON_CHANNEL_ID, "Psiphon", "psiphon", true),
    ];
    let mut reg = read_registry();
    if let Some(profiles) = reg["profiles"].as_array_mut() {
        for (id, name, ctype, want) in rows {
            if want {
                if let Some(entry) = profiles.iter_mut().find(|p| p["file"].as_str() == Some(id)) {
                    entry["name"] = json!(name);
                } else {
                    profiles.push(json!({
                        "name": name,
                        "file": id,
                        "type": ctype,
                        "added": chrono_now_str(),
                        "added_ts": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        "size": 0,
                    }));
                    emit_log(app, format!("Канал «{}» добавлен в селектор (стабильность не подтверждена — §9).", name));
                }
            } else if profiles.iter().any(|p| p["file"].as_str() == Some(id)) {
                profiles.retain(|p| p["file"].as_str() != Some(id));
                emit_log(app, format!("Канал «{}» убран из селектора (данных не хватает).", name));
            }
        }
        let _ = write_registry(&reg);
    }
}

/// Удаление WARP-записи из реестра (при сбросе учётки). Активный «__warp__»?
/// → первый оставшийся канал, иначе пусто (как wg_channel_remove).
pub fn warp_channel_remove(app: &AppHandle) -> Result<Value, String> {
    let mut reg = read_registry();
    let active = reg["active"].as_str().unwrap_or("").to_string();
    if let Some(profiles) = reg["profiles"].as_array_mut() {
        profiles.retain(|p| p["file"].as_str() != Some(WARP_CHANNEL_ID));
    }
    if active == WARP_CHANNEL_ID {
        let first = reg["profiles"].as_array()
            .and_then(|a| a.first())
            .and_then(|p| p["file"].as_str())
            .unwrap_or("")
            .to_string();
        reg["active"] = json!(first);
    }
    write_registry(&reg)?;
    emit_log(app, "WARP-канал убран из списка каналов.".into());
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
        ("warp_template.yaml", include_str!("../defaults/warp_template.yaml")),
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
            if let Err(e) = paid_profile_add(&old_str, app) {
                emit_log(app, format!("Миграция платного профиля не удалась: {}", e));
            } else {
                emit_log(app, "Прежний платный профиль перенесён во вкладку «Канал».".into());
            }
        }
    }

    // Миграция WG-кредов + перегенерация reserve_profile.yaml из текущего шаблона.
    crate::reserve::migrate_existing_creds(app);
    if crate::reserve::has_wg_creds() {
        // Канон имени WG-канала при каждом запуске (21.11.26): старые
        // юзерские имена («Запасной (WG)», stem файла) заменяются каноном.
        let _ = crate::proxy_core::wg_channel_sync(app);
        crate::reserve::generate_reserve_config()?;
    }
    // WARP (Этап B): регенерация warp_profile.yaml из ТЕКУЩЕГО шаблона + учётки —
    // обновления шаблона доезжают до юзера без его действий. Без учётки файла
    // быть не должно (сброс удаляет его сам). Ошибка не роняет запуск
    // приложения — честный лог; исправится при следующей регистрации/включении.
    if crate::warp::has_warp_account() {
        if let Err(e) = crate::warp::generate_warp_config() {
            emit_log(app, format!("[WARP] регенерация warp_profile.yaml не удалась: {}", e));
        }
    }
    // Специальные каналы (PRP 20.11.26): реестр (AWG/pawg/psiphon ⇔ данные)
    // + регенерация конфигов из ТЕКУЩИХ шаблонов (обновления едут релизами).
    // Ошибки не роняют запуск — честный лог, исправится при следующем включении.
    special_channels_sync(app);
    // Канонические имена платных (21.11.26: имя = метод, юзерские не выживают).
    paid_names_canonicalize(app);
    if crate::awg::has_account() {
        if let Err(e) = crate::awg_config::generate_awg_config() {
            emit_log(app, format!("[AWG] регенерация awg_profile.yaml не удалась: {}", e));
        }
        if crate::reserve::load_creds().is_some() {
            if let Err(e) = crate::awg_config::generate_pawg_config() {
                emit_log(app, format!("[PAWG] регенерация pawg_profile.yaml не удалась: {}", e));
            }
        }
    }
    if crate::warp::has_warp_account() {
        if let Err(e) = crate::psiphon::generate_psiphon_config() {
            emit_log(app, format!("[PSIPHON] регенерация psiphon_profile.yaml не удалась: {}", e));
        }
    }
    Ok(())
}

/// TCP-живость порта: соединение с коротким таймаутом. Не «HTTP-успех», но
/// для честного статуса процесса этого достаточно (порт занят = процесс жив).
pub(crate) fn port_alive(port: u16) -> bool {
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
    // PAC-подхват браузеров (Этап A, 19.11.26): на что настроен системный
    // PAC, чтобы UI честно показывал «браузеры подхвачены / нет».
    let pac_url = crate::pac_server::pac_configured();
    let pac_on = pac_url.as_deref() == Some(crate::routing::PAC_URL);
    json!({
        "mode": if mode.is_empty() { "off".to_string() } else { mode },
        "mode_name": mode_name,
        "running": has_child && port_alive,
        "proxy_alive": port_alive,
        "proxy_port": PROXY_PORT,
        "reserve": crate::reserve::guard_status(),
        // WARP (Этап B): последний trace-гард (warp=on/off, loc) для честного UI.
        "warp": crate::warp::warp_health_json(),
        // §честность: зелёный «порт жив» при перехваченном системном
        // трафике — ложь, поэтому детект перехвата едет рядом с портом.
        "hijack": hijack,
        "hijack_detail": hijack_detail,
        "pac_on": pac_on,
        "pac_url": pac_url.unwrap_or_default(),
    })
}

/// Живой режим канала (in-memory CHANNEL.mode): "off" или id канала, который
/// включён ПРЯМО СЕЙЧАС. Не путать с реестром `active` — тот переживает
/// рестарт (последний выбранный канал), а движок после рестарта не поднят
/// (инцидент 22.11.26: тест каналов решал «активный» по реестру и ложно
/// отдавал «МЁРТВ» для не поднятого боевого порта).
pub fn channel_mode() -> String {
    CHANNEL
        .lock()
        .map(|g| g.mode.clone())
        .unwrap_or_else(|_| String::from("off"))
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
    // Sidecar прежнего канала (aether Psiphon) гасим первее ядра — висячий
    // aether держал бы datastore и socks-порт следующего запуска.
    crate::psiphon::stop_sidecar();
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
    crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
    crate::psiphon::stop_sidecar(); // sidecar Psiphon умирает вместе с каналом
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
    crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
    stop_channel(None);
}

/// Старт mihomo с конфигом и ожидание живого порта. Ребёнок кладётся в CHANNEL.
fn start_mihomo(app: &AppHandle, config_path: &PathBuf) -> Result<(), String> {
    // Runtime-копия (AppData/runtime): боевой mihomo не лочит exe в бандле/
    // папке сборки — запущенный канал не мешает ни пересборке, ни обновлению
    // (инцидент 22.11.26: три случая os error 32 из-за процессов из release/bin).
    let mihomo_path = process::runtime_file(MIHOMO_EXE)?;
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
/// Структурный патчер платного профиля (v2, Этап A 19.11.26 — по ревью спеца,
/// замена построчного patch_yaml_lines): платные подписки бывают ЛЮБЫМИ —
/// якоря/алиасы, flow-style, глубокие вложенности. serde_yaml разворачивает
/// якоря при парсинге и сохраняет все неизвестные поля (Value-based).
/// Гарантии инвариантов proxy-only (каждая — юнит-тест в patcher_tests):
///  1) tun.enable = false, если tun-блок есть (вставляется при отсутствии) —
///     инцидент 19.11.26: TUN перехватывал ВСЮ систему;
///  2) dns.listen — УДАЛЯЕТСЯ: mihomo-DNS-сервер на :53 перехватывает
///     системный резолв даже при выключенном TUN (мины fake-ip в DNS-кэше);
///  3) dns.enhanced-mode: fake-ip → redir-host (адреса 198.18.x в proxy-only
///     бессмысленны для браузера: чистый обход их никуда не маршрутизирует);
///  4) mixed-port/external-controller — порты канала (7897/9097).
/// Битый yaml / не-словарь — честная ошибка наверх (молча не стартуем).
pub(crate) fn patch_paid_yaml_tree(text: &str) -> Result<String, String> {
    let mut root: serde_yaml::Mapping = serde_yaml::from_str(text)
        .map_err(|e| format!("профиль канала не является корректным YAML-словарём: {}", e))?;

    let s = |k: &str| serde_yaml::Value::String(String::from(k));

    // 1) TUN off — инвариант обязан быть ВИДИМ в конфиге (enable: false).
    if let Some(serde_yaml::Value::Mapping(tm)) = root.get_mut(&s("tun")) {
        tm.insert(s("enable"), serde_yaml::Value::Bool(false));
    }

    // 2) + 3) DNS: listen удалить, fake-ip → redir-host. dns.enable НЕ трогаем
    // (mihomo нужен DNS для своих запросов; без listen он не слушает систему).
    if let Some(serde_yaml::Value::Mapping(dm)) = root.get_mut(&s("dns")) {
        dm.remove(&s("listen"));
        if let Some(serde_yaml::Value::String(em)) = dm.get_mut(&s("enhanced-mode")) {
            if em == "fake-ip" {
                *em = String::from("redir-host");
            }
        }
    }

    // 4) Порты канала: перезапись существующих / вставка новых.
    root.insert(
        s("mixed-port"),
        serde_yaml::Value::Number(serde_yaml::Number::from(PROXY_PORT as u64)),
    );
    root.insert(
        s("external-controller"),
        s(&format!("127.0.0.1:{}", API_PORT)),
    );

    serde_yaml::to_string(&root).map_err(|e| format!("профиль не сериализуется обратно: {}", e))
}

/// Патч yaml-канала юзера: структурная переработка patch_paid_yaml_tree
/// (юнит-тесты patcher_tests). Источник — id канала из реестра (имя файла
/// без пути): патч-защита от path traversal (mode со «/», «\», «..» не дойдёт
/// до файловой системы), плюс канал обязан быть в реестре юзера — чужой
/// файл не патчим.
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

    // Структурный патчер v2 (Этап A 19.11.26, по ревью спеца): одним проходом
    // по yaml-дереву — TUN off, dns.listen удалён (mihomo-DNS на :53 ловил бы
    // системный резолв даже без TUN), fake-ip → redir-host, порты канала.
    // Построчный патчер заменён: якоря/алиасы и любые вложенности переживает
    // парсер, инцидент 19.11.26 показал цену наивной обработки yaml.
    let patched = patch_paid_yaml_tree(&text)?;

    std::fs::write(&out_path, patched)
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
            // Артефакт маршрутизации (Этап A): канала нет → channel-доменам
            // снова можно дизсинк (если dpi-режим = winws). Пустой exclude =
            // «ничего не исключать».
            if let Err(e) = crate::routing::write_channel_exclude(&[]) {
                emit_log(app, format!("[ROUTING] channel-exclude не очищен: {}", e));
            }
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
            // Артефакт маршрутизации (Этап A): channel-exclude = channel-домены
            // групп + домены нод живого канала (фейк ClientHello winws ломает
            // прокси-туннель изнутри — находка спеца 19.11.26).
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
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
        "__warp__" => {
            if !crate::warp::has_warp_account() {
                return Err(String::from(
                    "Нет WARP-учётки — зарегистрируйся (1 клик) или импортируй wgcf .conf на вкладке «Канал»",
                ));
            }
            // Оба гарда гасятся на любом переключении; живая ветка поднимает свой.
            GUARD_ON.store(false, Ordering::SeqCst);
            crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            crate::warp::generate_warp_config()?;
            let config_path = crate::warp::validate_warp_config()?;
            start_mihomo(app, &config_path)?;
            // Артефакт маршрутизации (Этап A): channel-exclude = channel-домены
            // групп + домены нод живого канала (фейк ClientHello winws ломает
            // туннель изнутри — находка спеца 19.11.26).
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
            // reserve-гард (204-проба) сюда НЕ ставим: на селективном конфиге
            // generate_204 уходит DIRECT и всегда «зелёный» при мёртвом туннеле —
            // ложь. WARP-гард (ревью спеца п.3/п.5): trace через 7897 (правило
            // www.cloudflare.com→WARP гоняет пробу через туннель), warp=on/loc;
            // три неудачи подряд → перезапуск канала (залипание WG, mihomo #1856).
            crate::warp_ops::start_guard(app.clone());
            emit_log(app, "WARP-канал: health-check туннеля запущен (trace через 7897).".into());
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| String::from("WARP (Cloudflare)"));
            Ok(format!("Канал «{}» включён.", name))
        }
        "__awg__" => {
            if !crate::awg::has_account() {
                return Err(String::from(
                    "Нет AWG-учётки — нажми «Зарегистрировать» в карточке канала",
                ));
            }
            GUARD_ON.store(false, Ordering::SeqCst);
            crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            crate::awg_config::generate_awg_config()?;
            let config_path = crate::awg_config::validate_awg_config()?;
            start_mihomo(app, &config_path)?;
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
            // Гард общий с WARP (warp_ops::guard_loop): для AWG trace идёт через
            // группу AWG WARP — это тот же WARP (warp=on), только amnezia-junk
            // сверху; три неудачи → рестарт канала (залипание WG, mihomo #1856).
            crate::warp_ops::start_guard(app.clone());
            emit_log(app, "AWG-канал: health-check туннеля запущен (trace через 7897).".into());
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| String::from("WARP AWG (YouTube)"));
            Ok(format!("Канал «{}» включён.", name))
        }
        "__pawg__" => {
            if !crate::awg::has_account() || crate::reserve::load_creds().is_none() {
                return Err(String::from(
                    "Proton-over-AWG требует AWG-учётку и WG-креды Proton (Запасной канал)",
                ));
            }
            GUARD_ON.store(false, Ordering::SeqCst);
            crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            crate::awg_config::generate_pawg_config()?;
            let config_path = crate::awg_config::validate_pawg_config()?;
            start_mihomo(app, &config_path)?;
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
            // trace идёт через PROTON (loc=NL, warp=off) — гард по критерию
            // loc != RU (WARP-метка на чужом выходе не светится).
            crate::warp_ops::start_guard(app.clone());
            emit_log(app, "Proton-over-AWG: health-check запущен (trace через 7897).".into());
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| String::from("AWG Proton WARP (гео)"));
            Ok(format!("Канал «{}» включён.", name))
        }
        "__psiphon__" => {
            if !crate::warp::has_warp_account() {
                return Err(String::from(
                    "Psiphon-канал ходит через WARP masque — сначала зарегистрируй WARP-канал (1 клик)",
                ));
            }
            GUARD_ON.store(false, Ordering::SeqCst);
            crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
            kill_koala(app);
            kill_mihomo_any();
            let removed = cleanup_stale_fakeip();
            if !removed.is_empty() {
                emit_log(app, format!("Сняты чужие fake-ip маршруты (остатки перехватчика): {}", removed.join(", ")));
                flush_dns();
            }
            crate::psiphon::generate_psiphon_config()?;
            let config_path = crate::psiphon::validate_psiphon_config()?;
            start_mihomo(app, &config_path)?;
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
            // Sidecar ПОСЛЕ mihomo: aether стучится в listener 7901 этого же ядра.
            // Не поднялся за 40с → гасим всё и честная ошибка (полуканала не оставляем).
            if let Err(e) = crate::psiphon::start_sidecar(app) {
                kill_mihomo_any();
                return Err(e);
            }
            crate::warp_ops::start_guard(app.clone());
            emit_log(app, "Psiphon-канал: health-check запущен (trace → loc != RU).".into());
            if let Ok(mut g) = CHANNEL.lock() {
                g.mode = mode.to_string();
            }
            mark_active_channel(mode);
            let name = entry_name_by_file(&read_registry(), mode)
                .unwrap_or_else(|| String::from("Psiphon (резерв)"));
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
            // Артефакт маршрутизации (Этап A): channel-exclude = channel-домены
            // групп + домены нод живого канала (фейк ClientHello winws ломает
            // прокси-туннель изнутри — находка спеца 19.11.26).
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                apply_channel_exclude(app, &text);
            } else {
                emit_log(app, "[ROUTING] конфиг канала не прочитан — channel-exclude не обновлён".into());
            }
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

/// Артефакт маршрутизации (Этап A): перезаписать lists/defaults/channel-exclude.txt
/// под включённый канал — channel-домены групп (routing.rs) + домены нод из текста
/// конфига. Пустой канал = winws дизсинкит всё как обычно. Ошибки не роняют
/// переключение канала (обход важнее артефакта), но честно пишутся в лог.
fn apply_channel_exclude(app: &AppHandle, config_text: &str) {
    let modes = match crate::routing::load_modes() {
        Ok(m) => m,
        Err(e) => {
            emit_log(app, format!("[ROUTING] routing.json не прочитан — channel-exclude не обновлён: {}", e));
            return;
        }
    };
    let nodes = crate::routing::node_domains_from_yaml(config_text);
    match crate::routing::compile_from_fs(&modes, true, None, &nodes, PROXY_PORT) {
        Ok(art) => match crate::routing::write_channel_exclude(&art.channel_exclude) {
            Ok(n) => emit_log(app, format!("[ROUTING] channel-exclude обновлён: {} доменов (winws их не дизсинкит).", n)),
            Err(e) => emit_log(app, format!("[ROUTING] channel-exclude не записан: {}", e)),
        },
        Err(e) => emit_log(app, format!("[ROUTING] компиляция channel-exclude не удалась: {}", e)),
    }
}

/// Активный канал («off», если ничего не включено). Нужен PAC-серверу
/// (компиляция pac_script без протекания состояния CHANNEL) и routing_set_mode.
pub fn active_channel_id() -> String {
    match CHANNEL.lock() {
        Ok(g) => {
            if g.mode.is_empty() {
                String::from("off")
            } else {
                g.mode.clone()
            }
        }
        Err(_) => String::from("off"),
    }
}

/// Пересборка channel-exclude под текущее состояние: канал off → пусто;
/// живой канал → текст его конфига (домены нод). Вызывается из routing_set_mode
/// после смены режимов. Ошибка — наверх честно (режимы сохранены, exclude старый).
pub fn refresh_channel_exclude() -> Result<usize, String> {
    let active = active_channel_id();
    if active == "off" {
        return crate::routing::write_channel_exclude(&[]);
    }
    let path = if active == WG_CHANNEL_ID {
        crate::reserve::reserve_profile_path()
    } else {
        proxy_dir().join("paid.yaml")
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("конфиг канала не прочитан ({}): {}", path.display(), e))?;
    let modes = crate::routing::load_modes()?;
    let nodes = crate::routing::node_domains_from_yaml(&text);
    let art = crate::routing::compile_from_fs(&modes, true, None, &nodes, PROXY_PORT)?;
    crate::routing::write_channel_exclude(&art.channel_exclude)
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
    use super::patch_paid_yaml_tree;

    fn out_val(out: &str) -> serde_yaml::Value {
        serde_yaml::from_str(out).expect("выход обязан быть валидным yaml")
    }

    fn s(k: &str) -> serde_yaml::Value {
        serde_yaml::Value::String(String::from(k))
    }

    fn num(n: u64) -> serde_yaml::Value {
        serde_yaml::Value::Number(serde_yaml::Number::from(n))
    }

    /// Инцидент 19.11.26: enable: true ГЛУБОКО в tun-блоке (за списком
    /// exclude-package). Структурный патчер обязан выключить TUN, удалить
    /// dns.listen; dns.enable и auto-route не трогать.
    #[test]
    fn deep_tun_disabled_and_dns_listen_removed() {
        let src = "tun:\n  exclude-package:\n    - a.b\n    - c.d\n  enable: true\n  auto-route: true\ndns:\n  enable: true\n  listen: 0.0.0.0:53\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        assert_eq!(v["tun"]["enable"], serde_yaml::Value::Bool(false), "TUN обязан быть выключен");
        assert_eq!(v["tun"]["auto-route"], serde_yaml::Value::Bool(true), "auto-route не трогаем");
        assert_eq!(v["dns"]["enable"], serde_yaml::Value::Bool(true), "dns.enable не трогаем");
        assert!(
            v["dns"].get("listen").is_none(),
            "dns.listen обязан быть удалён: mihomo-DNS на :53 перехватывал бы системный резолв"
        );
    }

    /// enable в tun-блоке отсутствует → вставляется enable: false (инвариант
    /// proxy-only обязан быть ВИДИМ в конфиге).
    #[test]
    fn tun_without_enable_gets_explicit_false() {
        let src = "tun:\n  stack: gvisor\nlog-level: info\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        assert_eq!(v["tun"]["enable"], serde_yaml::Value::Bool(false));
        assert_eq!(v["tun"]["stack"], s("gvisor"));
    }

    /// Flow-style `tun: {enable: true, ...}` выключается так же, как блочный.
    #[test]
    fn flow_style_tun_disabled() {
        let src = "tun: {enable: true, stack: mixed}\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        assert_eq!(v["tun"]["enable"], serde_yaml::Value::Bool(false));
        assert_eq!(v["tun"]["stack"], s("mixed"));
    }

    /// fake-ip → redir-host (адреса 198.18.x в proxy-only бессмысленны);
    /// уже redir-host — не ошибка и не перезапись; отсутствует — тоже.
    #[test]
    fn fake_ip_flips_to_redir_host() {
        let src = "dns:\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        assert_eq!(v["dns"]["enhanced-mode"], s("redir-host"));
        let v2 = out_val(&patch_paid_yaml_tree("dns:\n  enhanced-mode: redir-host\n").expect("патч ок"));
        assert_eq!(v2["dns"]["enhanced-mode"], s("redir-host"));
        let v3 = out_val(&patch_paid_yaml_tree("log-level: info\n").expect("патч ок без dns"));
        assert!(v3["dns"].is_null());
    }

    /// Порты канала: существующие перезаписываются, отсутствующие вставляются;
    /// соседние ключи не теряются.
    #[test]
    fn ports_overwritten_and_injected() {
        let src = "mixed-port: 7890\nlog-level: info\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        assert_eq!(v["mixed-port"], num(7897));
        assert_eq!(v["external-controller"], s("127.0.0.1:9097"));
        assert_eq!(v["log-level"], s("info"));
    }

    /// Якоря/алиасы разворачиваются парсером; неизвестные поля переживают
    /// патч (Value-based, не типизированная структура — платные подписки
    /// бывают любыми).
    #[test]
    fn anchors_and_unknown_fields_survive() {
        let src = "p: &p\n  name: n1\n  type: ss\nproxies:\n  - *p\n  - name: n2\n    type: trojan\nrules:\n  - MATCH,DIRECT\n";
        let v = out_val(&patch_paid_yaml_tree(src).expect("патч ок"));
        let proxies = v["proxies"].as_sequence().expect("proxies — список");
        assert_eq!(proxies.len(), 2, "алиас развёрнут, обе ноды на месте");
        assert_eq!(proxies[0]["name"], s("n1"));
        assert_eq!(proxies[1]["type"], s("trojan"));
        assert_eq!(v["rules"][0], s("MATCH,DIRECT"));
        assert!(v.get("p").is_some(), "корневой ключ-якорь сохранён");
    }

    /// Битый yaml и не-словарь — честная ошибка наверх, не молчаливый проход.
    #[test]
    fn broken_or_non_mapping_is_honest_error() {
        assert!(patch_paid_yaml_tree("{битый").is_err());
        assert!(patch_paid_yaml_tree("- просто список\n").is_err());
    }
}
