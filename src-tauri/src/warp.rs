// warp.rs — WARP-канал v2 «MASQUE H2» (метод спеца, 20.11.26). Чистая
// тестируемая часть: учётка WarpAccount (ECDSA P-256), парсеры ответов API
// (POST /reg → id+token; PATCH /reg/{id} → masque-конфиг), keygen P-256,
// storage в AppData (proxy/warp/warp_account.json), генерация warp_profile.yaml
// из шаблона + учётки с правилами компилятора групп (Этап A). Оркестрация
// регистрации/гарда — в warp_ops.rs (файл ≤ 500 строк).
//
// Контракт верифицирован по эталону Diniboy1123/usque (api/cloudflare.go,
// internal/consts.go, выгрузка 20.11.26) и подтверждён ЖИВОЙ регистрацией
// (temp/masque_reg.py, POST 200 + PATCH 200):
//   POST  /v0a4471/reg      — key = одноразовый случайный 32Б base64 ( WG-
//                             плейсхолдер), key_type curve25519,
//                             tunnel_type wireguard; сервер ключ НЕ валидирует.
//   PATCH /v0a4471/reg/{id} — Authorization: Bearer <token>; key = base64(PKIX
//                             SPKI DER) P-256, key_type secp256r1,
//                             tunnel_type masque.
//   Из ответа PATCH: server = config.peers[0].endpoint.v4 без суффикса «:0»
//   (привязка к edge-кластеру — подставлять строго этот IP), public_key =
//   PEM (PKIX SPKI) пира CF → чистый base64, приватный ключ клиента =
//   base64(SEC1 ECPrivateKey DER) — создаётся КЛИЕНТОМ, сервер его не знает.
// Ключи wgcf (Curve25519) для masque НЕ подходят; wgcf-импорт убран.
// Смоук транспорта (handoff 20.11.26 03:50): warp=on, loc=SG, aistudio 200.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::Engine as _;
// Приватный SEC1 DER собирается вручную по шаблону P-256 (см.
// gen_masque_keypair) — инерентный to_sec1_der() пишет DER без OID кривой.
// ToEncodedPoint — трейт точки (to_encoded_point(false) → 04||X||Y, 65 Б).
// to_public_key_der — из трейта pkcs8::EncodePublicKey → PKIX SPKI DER
// («MFkwEwYH…», 91 Б).
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePublicKey;
use serde_json::{json, Value};

use crate::config;

/// Анонимная учётка WARP MASQUE (личное юзера — ТОЛЬКО AppData, в репо/бандл
/// не едет). Все ключи — base64 DER-форматов контракта usque.
#[derive(Clone, Debug)]
pub struct WarpAccount {
    /// base64(SEC1 ECPrivateKey DER) — начинается с «MHcCAQEE».
    pub private_key: String,
    /// base64(PKIX SPKI DER) TLS-публичного ключа пира CF — начинается с «MFkwEwYH».
    pub peer_public_key: String,
    /// IPv4 endpoint СТРОГО из ответа PATCH (например 162.159.198.2).
    pub server: String,
    /// tunnel v4 (например 172.16.0.2).
    pub ip: String,
    /// tunnel v6 (например 2606:4700:110:…/128); может отсутствовать.
    pub ipv6: String,
    pub device_id: String,
    /// Токен авторизации API — секрет, в статусах/логах НЕ отдаётся.
    pub token: String,
    pub source: String, // "register"
}

/// Порт MASQUE-эндпоинта (TCP:443 — транспорт спеца; другого нет).
pub const MASQUE_PORT: u16 = 443;

// ---------- Хелс-статус туннеля (для честного UI) ----------

pub static WARP_GUARD_ON: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Default)]
struct WarpHealth {
    warp: String, // "on" | "off" | ""
    loc: String,  // страна выхода CF (trace loc=XX)
    ok: bool,
    error: String,
    checked_ts: u64,
    fails: u64,
}

static HEALTH: Mutex<WarpHealth> = Mutex::new(WarpHealth {
    warp: String::new(),
    loc: String::new(),
    ok: false,
    error: String::new(),
    checked_ts: 0,
    fails: 0,
});

/// Последний результат trace-пробы через 7897 (warp=on/off, loc). Мёртвая
/// проба (ok=false) — честный error, не «всё хорошо».
pub fn warp_health_json() -> Value {
    let h = HEALTH
        .lock()
        .map(|h| h.clone())
        .unwrap_or_else(|_| WarpHealth::default());
    json!({
        "warp": h.warp,
        "loc": h.loc,
        "ok": h.ok,
        "error": h.error,
        "checked_ts": h.checked_ts,
    })
}

pub(crate) fn health_update(warp: &str, loc: &str, ok: bool, error: &str, fails: u64) {
    if let Ok(mut h) = HEALTH.lock() {
        h.warp = warp.to_string();
        h.loc = loc.to_string();
        h.ok = ok;
        h.error = error.to_string();
        h.checked_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        h.fails = fails;
    }
}

pub(crate) fn health_fails() -> u64 {
    HEALTH.lock().map(|h| h.fails).unwrap_or(0)
}

/// Порог перезапуска канала: три подряд неудачных trace-пробы.
pub const GUARD_FAIL_LIMIT: u64 = 3;

pub fn guard_reset_fails() {
    // Сброс счётчика при ручном переключении канала/удачной ротации: прошлые
    // фейлы мёртвого туннеля не должны мгновенно рестартить новый.
    if let Ok(mut h) = HEALTH.lock() {
        h.fails = 0;
    }
}

// ---------- Storage (AppData, рядом с wg_creds.json) ----------

fn warp_dir() -> PathBuf {
    config::get_app_dir().join("proxy").join("warp")
}

fn account_file() -> PathBuf {
    warp_dir().join("warp_account.json")
}

/// Путь регенерированного конфига WARP-канала.
pub fn warp_profile_path() -> PathBuf {
    crate::proxy_core::proxy_dir().join("warp_profile.yaml")
}

fn account_to_json(a: &WarpAccount) -> Value {
    json!({
        "tunnel_type": "masque",
        "private_key": a.private_key,
        "peer_public_key": a.peer_public_key,
        "server": a.server,
        "ip": a.ip,
        "ipv6": a.ipv6,
        "device_id": a.device_id,
        "token": a.token,
        "source": a.source,
    })
}

fn account_from_json(v: &Value) -> Option<WarpAccount> {
    // Только v2 (masque). Учётки v1 (wireguard wgcf: endpoint/port/address/
    // reserved) парсеру не подходят — это честная «нет учётки» (файл v1
    // детектится в warp_status_json как legacy_account).
    if v.get("tunnel_type")?.as_str()? != "masque" {
        return None;
    }
    let mk = |k: &str| -> Option<String> {
        let s = v.get(k)?.as_str()?;
        if s.is_empty() && k != "ipv6" {
            return None;
        }
        Some(s.to_string())
    };
    Some(WarpAccount {
        private_key: mk("private_key")?,
        peer_public_key: mk("peer_public_key")?,
        server: mk("server")?,
        ip: mk("ip")?,
        ipv6: v.get("ipv6").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        device_id: mk("device_id")?,
        token: mk("token")?,
        source: v
            .get("source")
            .and_then(|x| x.as_str())
            .unwrap_or("register")
            .to_string(),
    })
}

pub(crate) fn save_account(a: &WarpAccount) -> Result<(), String> {
    let dir = warp_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let doc = account_to_json(a);
    std::fs::write(account_file(), serde_json::to_string_pretty(&doc).unwrap_or_default())
        .map_err(|e| format!("не записать {}: {}", account_file().display(), e))
}

pub(crate) fn load_account() -> Option<WarpAccount> {
    std::fs::read_to_string(account_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| account_from_json(&v))
}

pub(crate) fn remove_account() -> Result<(), String> {
    match std::fs::remove_file(account_file()) {
        Ok(_) => Ok(()),
        // Файла уже нет — цель «учётки нет» достигнута, не ошибка.
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("не удалить {}: {}", account_file().display(), e)),
    }
}

/// Гейт channel_set("__warp__") и условие регенерации warp_profile.yaml.
pub fn has_warp_account() -> bool {
    load_account().is_some()
}

/// Статус учётки для фронта. Приватный ключ/токен НЕ отдаём. Учётка v1
/// (wireguard wgcf, до 20.11.26) — present:false + legacy_account:true,
/// чтобы фронт честно позвал перерегистрацию вместо тихой загадки.
pub fn warp_status_json() -> Value {
    let raw = std::fs::read_to_string(account_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    match raw {
        Some(v) => match account_from_json(&v) {
            Some(a) => json!({
                "present": true,
                "endpoint": format!("{}:{}", a.server, MASQUE_PORT),
                "address": a.ip,
                "tunnel_type": "masque",
                "source": a.source,
            }),
            None => json!({ "present": false, "legacy_account": true }),
        },
        None => json!({ "present": false }),
    }
}

// ---------- Keygen + время ----------

/// Случайные n байт в base64 (одноразовый «WG-плейсхолдер» POST-запроса).
pub(crate) fn random_b64(n: usize) -> Result<String, String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| format!("OS-рандом недоступен: {}", e))?;
    Ok(B64.encode(buf))
}

/// Случайные n байт в hex (2n символов) — serial_number в POST (usque: 16 hex).
pub(crate) fn random_hex(n: usize) -> Result<String, String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| format!("OS-рандом недоступен: {}", e))?;
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Пара ключей MASQUE (ECDSA P-256): приватный = base64(SEC1 ECPrivateKey
/// DER), публичный = base64(PKIX SPKI DER) — ровно форматы usque/warp-reg.
/// Приватный НИКОГДА не уходит на сервер — в PATCH уходит только публичный.
pub fn gen_masque_keypair() -> Result<(String, String), String> {
    for _ in 0..8 {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| format!("OS-рандом недоступен: {}", e))?;
        // Вероятность невалидного скаляра ~2^-224, но не паникуем — retry.
        if let Ok(sk) = p256::SecretKey::from_slice(&seed) {
            // SEC1 ECPrivateKey собираем по фиксированному шаблону P-256
            // (121 Б, байт-в-байт как TraditionalOpenSSL в живом смоуке
            // temp/masque_reg.py — POST/PATCH 200). Инерентный
            // SecretKey::to_sec1_der() НЕ годится: он пишет parameters: None
            // (кривобезый DER 109 Б), а Go-парсер mihomo
            // (x509.ParseECPrivateKey) требует OID кривой.
            let scalar = sk.to_bytes();                          // 32 Б — OCTET STRING
            let point = sk.public_key().to_encoded_point(false); // 04||X||Y — 65 Б
            let mut der = Vec::with_capacity(121);
            // SEQUENCE(0x77) { INTEGER 1, OCTET STRING(0x20) scalar,
            //   [0] OID prime256v1 (1.2.840.10045.3.1.7),
            //   [1] BIT STRING(0x42) = 0x00 + точка }
            der.extend_from_slice(&[0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
            der.extend_from_slice(scalar.as_slice());
            der.extend_from_slice(&[
                0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1,
                0x44, 0x03, 0x42, 0x00,
            ]);
            der.extend_from_slice(point.as_bytes());
            let pub_der = sk
                .public_key()
                .to_public_key_der()
                .map_err(|e| format!("SPKI DER публичного ключа не собран: {}", e))?;
            return Ok((
                B64.encode(&der),
                B64.encode(pub_der.as_bytes()),
            ));
        }
    }
    Err(String::from(
        "P-256 keygen: 8 попыток подряд дали невалидный скаляр — сдаёмся честно",
    ))
}

/// ISO-время UTC «2026-11-20T12:34:56.000Z» для поля tos. Z-формат принят
/// сервером (live-проверка 20.11.26, POST 200). Без внешних крейтов —
/// алгоритм Хиннанта (как chrono_now_str в proxy_core).
pub fn iso_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let z = days + 719_468;
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
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

// ---------- Парсеры (чистые, тестируемые) ----------

/// PEM → чистый base64: срезает строки-заголовки/подвалы «-----…-----» и
/// переводы строк/пробелы (формат поля config.peers[0].public_key PATCH).
pub fn strip_pem(raw: &str) -> String {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

/// endpoint.v4 из PATCH приходит с суффиксом «:0» («162.159.198.2:0», контракт
/// usque — он срезает ровно 2 последних символа). Срезаем честно: только
/// суффикс «:0», иначе — ошибка, чтобы не подставить битый endpoint.
pub fn strip_v4_port0(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    match t.strip_suffix(":0") {
        Some(base) if !base.trim().is_empty() => Ok(base.trim().to_string()),
        _ => Err(format!(
            "endpoint.v4 «{}»: ожидался суффикс «:0» (контракт PATCH /reg)",
            raw
        )),
    }
}

/// Парс ответа POST /v0a4471/reg: нужны только id и token (ключи приходят в
/// PATCH, туннельный config — тоже).
pub fn parse_reg_post(text: &str) -> Result<(String, String), String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("Ответ POST /reg не JSON: {}", e))?;
    let device_id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or("В ответе POST /reg нет id устройства")?
        .to_string();
    let token = v
        .get("token")
        .and_then(|x| x.as_str())
        .ok_or("В ответе POST /reg нет token")?
        .to_string();
    Ok((device_id, token))
}

/// Парс ответа PATCH /reg/{id} (DeviceUpdate_200_Response): id, config.peers[0]
/// {public_key PEM, endpoint.v4}, config.interface.addresses.{v4,v6}.
/// private_key/token подставляет клиент — сервер их не знает/не возвращает.
pub fn parse_patch_response(
    text: &str,
    private_key: &str,
    token: &str,
) -> Result<WarpAccount, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("Ответ PATCH /reg не JSON: {}", e))?;
    let device_id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or("В ответе PATCH нет id устройства")?
        .to_string();
    let cfg = v.get("config").ok_or("В ответе PATCH нет config")?;
    let peer = cfg
        .get("peers")
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .ok_or("В ответе PATCH нет config.peers[0]")?;
    let ep = peer
        .get("endpoint")
        .ok_or("В ответе PATCH нет peers[0].endpoint")?;
    let v4 = ep
        .get("v4")
        .and_then(|x| x.as_str())
        .ok_or("В ответе PATCH нет peers[0].endpoint.v4")?;
    let server = strip_v4_port0(v4)?;
    let pub_raw = peer
        .get("public_key")
        .and_then(|x| x.as_str())
        .ok_or("В ответе PATCH нет peers[0].public_key")?;
    let peer_public_key = strip_pem(pub_raw);
    if peer_public_key.is_empty() {
        return Err("peers[0].public_key пуст после снятия PEM-обёртки".into());
    }
    let addrs = cfg
        .get("interface")
        .and_then(|i| i.get("addresses"))
        .ok_or("В ответе PATCH нет config.interface.addresses")?;
    let ip_raw = addrs
        .get("v4")
        .and_then(|x| x.as_str())
        .ok_or("В ответе PATCH нет addresses.v4")?;
    let ip = ip_raw
        .split('/')
        .next()
        .unwrap_or(ip_raw)
        .trim()
        .to_string();
    if ip.is_empty() {
        return Err("addresses.v4 пуст".into());
    }
    let ipv6 = addrs
        .get("v6")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(WarpAccount {
        private_key: private_key.to_string(),
        peer_public_key,
        server,
        ip,
        ipv6,
        device_id,
        token: token.to_string(),
        source: String::from("register"),
    })
}

/// Парс ответа https://www.cloudflare.com/cdn-cgi/trace (health-check, спец
/// п.3): warp=on|off — «запрос ушёл через туннель» (защита от ложного успеха
/// DIRECT'ом), loc=XX — честная страна выхода.
pub fn parse_trace(text: &str) -> Result<(String, String), String> {
    let mut warp = String::new();
    let mut loc = String::new();
    for l in text.lines() {
        if let Some(v) = l.strip_prefix("warp=") {
            warp = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("loc=") {
            loc = v.trim().to_string();
        }
    }
    if warp.is_empty() {
        return Err("В trace-ответе нет warp=".into());
    }
    Ok((warp, loc))
}

// ---------- Генерация warp_profile.yaml ----------

/// warp_profile.yaml из шаблона + учётки: плейсхолдеры → креды, хвост rules
/// заменяется правилами компилятора групп (Этап A; ревью спеца п.6) — в
/// шаблоне остаётся только trace-правило www.cloudflare.com→WARP.
pub fn generate_warp_config() -> Result<PathBuf, String> {
    let acct = load_account().ok_or(
        "Нет WARP-учётки (или она старого wgcf-формата) — нажми «Зарегистрировать» \
(MASQUE-учётка создаётся в 1 клик; wgcf-импорт с MASQUE несовместим)",
    )?;
    let tpl = include_str!("../defaults/warp_template.yaml");
    let modes = crate::routing::load_modes()?;
    let art = crate::routing::compile_from_fs(
        &modes,
        true,
        Some("WARP"),
        &[],
        crate::proxy_core::PROXY_PORT,
    )?;
    let out = assemble_warp_config(
        tpl,
        &acct.private_key,
        &acct.peer_public_key,
        &acct.server,
        &acct.ip,
        &acct.ipv6,
        &art.mihomo_rules,
    )?;

    let path = warp_profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не создать {}: {}", parent.display(), e))?;
    }
    std::fs::write(&path, &out).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(path)
}

/// Чистая (тестируемая) сборка текста warp-профиля: подстановка креды +
/// перестановка rules. Инцидент 02:33 20.11: правила компилятора хранятся с
/// нулевой колонки — без отступа здесь yaml рвался и mihomo падал до старта.
/// Учётка без ipv6: строка `ipv6: __IPV6__` удаляется целиком (пустой плейс-
/// холдер превратился бы в yaml-null — mihomo на парсинге падает).
fn assemble_warp_config(
    tpl: &str,
    private_key: &str,
    peer_public_key: &str,
    server: &str,
    ip: &str,
    ipv6: &str,
    rules: &[String],
) -> Result<String, String> {
    let base = if ipv6.trim().is_empty() {
        tpl.lines()
            .filter(|l| !l.contains("__IPV6__"))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        tpl.to_string()
    };
    let mut out = base
        .replace("__PRIVATE_KEY__", private_key)
        .replace("__PUBLIC_KEY__", peer_public_key)
        .replace("__SERVER__", server)
        .replace("__IP__", ip)
        .replace("__IPV6__", ipv6);

    let mut lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();
    let Some(ri) = lines.iter().position(|l| l.trim() == "rules:") else {
        return Err(String::from("Шаблон warp: не найдена секция rules"));
    };
    let trace_rule = lines
        .get(ri + 1)
        .ok_or("Шаблон warp: нет trace-правила после rules:")?
        .clone();
    if !trace_rule.contains("www.cloudflare.com") {
        return Err(format!(
            "Шаблон warp: первая строка rules — не trace-правило ({})",
            trace_rule
        ));
    }
    lines.truncate(ri);
    lines.push(String::from("rules:"));
    lines.push(trace_rule);
    // Правила компилятора — с 2-пробельным отступом: артефакт routing хранит
    // строки с нулевой колонки, а здесь rules уже открыт отступом trace-правила.
    lines.extend(rules.iter().map(|r| format!("  {}", r)));
    out = lines.join("\n") + "\n";
    Ok(out)
}

/// Валидация сгенерированного warp_profile.yaml перед стартом mihomo
/// (образец — validate_reserve_config): порты SSOT, masque-outbound на месте,
/// учётка подставлена (нет плейсхолдеров), транспортные маркеры спеца живы.
pub fn validate_warp_config() -> Result<PathBuf, String> {
    let path = warp_profile_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Нет warp-профиля {} — включи канал после регистрации", path.display()))?;
    if !text.contains(&format!("mixed-port: {}", crate::proxy_core::PROXY_PORT)) {
        return Err(format!(
            "{}: ожидался mixed-port: {} — файл не тот?",
            path.display(),
            crate::proxy_core::PROXY_PORT
        ));
    }
    if !text.contains("type: masque") {
        return Err(format!(
            "{}: нет masque outbound — канал v2 (MASQUE) невозможен; перерегистрируй учётку",
            path.display()
        ));
    }
    if !text.contains("network: h2") {
        return Err(format!(
            "{}: нет network: h2 — UDP-less транспорт спеца отключён",
            path.display()
        ));
    }
    if !text.contains("sni: consumer-masque.cloudflareclient.com") {
        return Err(format!(
            "{}: нет sni consumer-masque — CONNECT-IP не поднимется",
            path.display()
        ));
    }
    let leftovers: [&str; 5] = [
        "__PRIVATE_KEY__",
        "__PUBLIC_KEY__",
        "__SERVER__",
        "__IP__",
        "__IPV6__",
    ];
    if leftovers.iter().any(|p| text.contains(p)) {
        return Err(format!(
            "{}: в конфиге остались плейсхолдеры — учётка не подставилась",
            path.display()
        ));
    }
    // YAML-форма правил (инцидент 02:33 20.11: хвост компилятора с нулевой
    // колонки рвал yaml — mihomo падал до старта, порт 7897 «не поднимался»).
    if let Some(pos) = text.find("\nrules:\n") {
        for l in text[pos + 1..].lines().skip(1) {
            if l.starts_with('-') {
                return Err(format!(
                    "{}: правило без отступа в rules ({}) — yaml невалиден",
                    path.display(),
                    l.chars().take(60).collect::<String>()
                ));
            }
        }
    }
    Ok(path)
}

// ---------- Тесты (чистая логика; реальный AppData не трогаем) ----------

#[cfg(test)]
mod warp_tests {
    use super::*;

    /// Фикстура ответа POST /v0a4471/reg (контракт usque AccountData).
    fn post_fixture() -> String {
        String::from(
            r#"{
  "id": "67bc622f-0000-0000-0000-000000000000",
  "token": "9e8d7c6b-1111-2222-3333-444444444444",
  "account": { "license": "abc" },
  "config": { "client_id": "U4An" }
}"#,
        )
    }

    /// Фикстура ответа PATCH /reg/{id}: endpoint.v4 с «:0», PEM-публичный
    /// ключ, адреса туннеля (формы — как в живом ответе 20.11.26).
    fn patch_fixture() -> String {
        String::from(
            r#"{
  "id": "67bc622f-0000-0000-0000-000000000000",
  "account": { "license": "abc" },
  "config": {
    "interface": { "addresses": { "v4": "172.16.0.2/32", "v6": "2606:4700:110:804e:3f62:6b6a:e9:7e9f/128" } },
    "peers": [
      {
        "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n",
        "endpoint": { "v4": "162.159.198.2:0", "v6": "[2606:4700:a0::1]:0" }
      }
    ]
  }
}"#,
        )
    }

    #[test]
    fn reg_post_parses_id_and_token() {
        let (id, token) = parse_reg_post(&post_fixture()).expect("парс POST должен пройти");
        assert_eq!(id, "67bc622f-0000-0000-0000-000000000000");
        assert_eq!(token, "9e8d7c6b-1111-2222-3333-444444444444");
        for broken in [r#"{"id":"x"}"#.to_string(), r#"{"token":"t"}"#.to_string(), String::from("не-json")] {
            assert!(parse_reg_post(&broken).is_err(), "должна быть честная ошибка");
        }
    }

    #[test]
    fn patch_response_parses_full_contract() {
        let a = parse_patch_response(&patch_fixture(), "priv-b64", "tok-b64")
            .expect("парс PATCH должен пройти");
        assert_eq!(a.private_key, "priv-b64");
        assert_eq!(a.token, "tok-b64");
        assert_eq!(a.server, "162.159.198.2"); // «:0» срезан
        assert_eq!(a.ip, "172.16.0.2"); // /32 срезан
        assert_eq!(a.ipv6, "2606:4700:110:804e:3f62:6b6a:e9:7e9f/128");
        assert_eq!(
            a.peer_public_key,
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(a.device_id, "67bc622f-0000-0000-0000-000000000000");
        assert_eq!(a.source, "register");
    }

    #[test]
    fn patch_response_missing_fields_are_honest() {
        for broken in [
            r#"{"id":"x"}"#,
            r#"{"id":"x","config":{}}"#,
            r#"{"id":"x","config":{"peers":[]}}"#,
            r#"{"id":"x","config":{"peers":[{"public_key":"p","endpoint":{"v6":"[::1]:0"}}]}}"#,
            r#"{"id":"x","config":{"peers":[{"endpoint":{"v4":"162.159.198.2"}}]}}"#,
            r#"{"id":"x","config":{"peers":[{"public_key":"   ","endpoint":{"v4":"1.2.3.4:0"}}]}}"#,
            r#"{"id":"x","config":{"peers":[{"public_key":"p","endpoint":{"v4":"162.159.198.2"}}],"interface":{"addresses":{"v4":"1.2.3.4"}}}}"#,
            r#"{"id":"x","config":{"peers":[{"public_key":"p","endpoint":{"v4":"1.2.3.4:0"}}],"interface":{"addresses":{"v4":"  "}}}}"#,
            "не-json-вообще",
        ] {
            let err = parse_patch_response(broken, "priv", "tok")
                .expect_err("должна быть честная ошибка");
            assert!(!err.is_empty());
        }
    }

    #[test]
    fn strip_pem_removes_headers_and_newlines() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAAA\nBBB=\n-----END PUBLIC KEY-----\n";
        assert_eq!(strip_pem(pem), "AAABBB=");
        assert_eq!(strip_pem("  plain-b64  "), "plain-b64");
    }

    #[test]
    fn v4_port0_is_stripped_honestly() {
        assert_eq!(strip_v4_port0("162.159.198.2:0").expect("ок"), "162.159.198.2");
        let err = strip_v4_port0("162.159.198.2").expect_err("без :0 — честная ошибка");
        assert!(err.contains(":0"));
        assert!(strip_v4_port0(":0").is_err());
    }

    #[test]
    fn masque_keypair_has_usque_der_shapes() {
        let (priv_b64, pub_b64) = gen_masque_keypair().expect("keygen должен пройти");
        let priv_bytes = B64.decode(&priv_b64).expect("приватный — валидный base64");
        let pub_bytes = B64.decode(&pub_b64).expect("публичный — валидный base64");
        // SEC1 ECPrivateKey P-256: 121 байт, заголовок «MHcCAQEE».
        assert_eq!(priv_bytes.len(), 121);
        assert!(priv_b64.starts_with("MHcCAQEE"), "priv: {}", &priv_b64[..12]);
        // PKIX SPKI P-256: 91 байт, заголовок «MFkwEwYH» (как в live-ответе).
        assert_eq!(pub_bytes.len(), 91);
        assert!(pub_b64.starts_with("MFkwEwYH"), "pub: {}", &pub_b64[..12]);
    }

    #[test]
    fn random_helpers_have_right_shapes() {
        let b = random_b64(32).expect("b64");
        assert_eq!(B64.decode(&b).expect("декод").len(), 32);
        let h = random_hex(8).expect("hex");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn trace_parses_warp_and_loc() {
        let (warp, loc) = parse_trace("fl=123\nh=www.cloudflare.com\nwarp=on\ngateway=warp\nloc=DE\ncolo=FRA").expect("trace должен парситься");
        assert_eq!(warp, "on");
        assert_eq!(loc, "DE");
        let err = parse_trace("fl=123\nloc=US").expect_err("без warp= — честная ошибка");
        assert!(err.contains("warp="));
    }

    #[test]
    fn iso_utc_now_has_wgcf_shape() {
        let s = iso_utc_now();
        assert_eq!(s.len(), 24);
        assert!(s.starts_with("20"), "год: {}", s);
        assert!(s.contains('T'));
        assert!(s.ends_with(".000Z"));
    }

    #[test]
    fn legacy_v1_account_is_honestly_rejected() {
        // Учётка v1 (wgcf wireguard) больше не парсится: channel_set должен
        // потребовать перерегистрацию, а не молча собрать битый конфиг.
        let v1 = serde_json::from_str::<Value>(
            r#"{"private_key":"k","peer_public_key":"p","endpoint":"engage.cloudflareclient.com",
                "port":2408,"address":"172.16.0.2","reserved":[1,2,3],
                "device_id":"d","token":"t","source":"register"}"#,
        )
        .expect("v1-фикстура");
        assert!(account_from_json(&v1).is_none(), "v1 должна быть отклонена");
        assert!(account_from_json(&json!({ "tunnel_type": "masque" })).is_none());
        // Валидная v2 парсится:
        let v2 = json!({
            "tunnel_type": "masque",
            "private_key": "MHcCAQEE=", "peer_public_key": "MFkwEwYH=",
            "server": "162.159.198.2", "ip": "172.16.0.2",
            "ipv6": "2606::/128", "device_id": "d", "token": "t", "source": "register"
        });
        let a = account_from_json(&v2).expect("v2 должна парситься");
        assert_eq!(a.server, "162.159.198.2");
        // Пустой ipv6 — допустим (опциональное поле):
        let v2_no_v6 = json!({
            "tunnel_type": "masque", "private_key": "k", "peer_public_key": "p",
            "server": "s", "ip": "1.2.3.4", "device_id": "d", "token": "t"
        });
        assert!(account_from_json(&v2_no_v6).is_some());
    }

    // ---- Сборка конфига как целого (инцидент 02:33 20.11: rules с нулевой
    // ---- колонки рвали yaml; юнит-тесты парсеров этот класс не видели —
    // ---- сборка чистая и покрыта на РЕАЛЬНОМ шаблоне).

    /// Реальные правила компилятора приходят с нулевой колонки — как в
    /// routing-артефакте. Сборка обязана посадить их под отступ.
    #[test]
    fn assemble_indents_compiler_rules_on_real_template() {
        let rules = vec![
            String::from("- DOMAIN-SUFFIX,aistudio.google.com,WARP"),
            String::from("- DOMAIN-SUFFIX,openrouter.ai,WARP"),
            String::from("- MATCH,DIRECT"),
        ];
        let out = assemble_warp_config(
            include_str!("../defaults/warp_template.yaml"),
            "MHcCAQEEpriv=",
            "MFkwEwYHpub=",
            "162.159.198.2",
            "172.16.0.2",
            "2606:4700:110::/128",
            &rules,
        )
        .expect("сборка на реальном шаблоне");
        // Плейсхолдеров нет, креда на месте, masque-маркеры живы:
        for ph in ["__PRIVATE_KEY__", "__PUBLIC_KEY__", "__SERVER__", "__IP__", "__IPV6__"] {
            assert!(!out.contains(ph), "остался плейсхолдер {}", ph);
        }
        assert!(out.contains("private-key: \"MHcCAQEEpriv=\""));
        assert!(out.contains("public-key: MFkwEwYHpub="));
        assert!(out.contains("server: 162.159.198.2"));
        assert!(out.contains("type: masque"));
        assert!(out.contains("network: h2"));
        assert!(out.contains("ipv6: 2606:4700:110::/128"));
        assert!(!out.contains("wireguard"), "WG-хвостов быть не должно");
        assert!(!out.contains("reserved"), "reserved у masque нет");
        // Trace-правило осталось первым в rules:
        let pos = out.find("\nrules:\n").expect("rules есть");
        let tail = &out[pos + 1..];
        let mut it = tail.lines().skip(1);
        let first = it.next().expect("первая строка rules");
        assert!(first.contains("www.cloudflare.com"), "первое: {}", first);
        // НИ одна строка после rules: не начинается с '-' на нулевой колонке —
        // ровно тот дефект, что валит yaml («did not find expected key»).
        for l in it {
            assert!(!l.starts_with('-'), "нулевая колонка: «{}»", l);
        }
        assert!(tail.contains("  - DOMAIN-SUFFIX,aistudio.google.com,WARP"));
        assert!(tail.contains("  - MATCH,DIRECT"));
    }

    /// Учётка без ipv6: строка ipv6 из шаблона удаляется, а не превращается
    /// в yaml-null (mihomo на парсинге падает).
    #[test]
    fn assemble_drops_ipv6_line_when_empty() {
        let out = assemble_warp_config(
            include_str!("../defaults/warp_template.yaml"),
            "k=",
            "p=",
            "162.159.198.2",
            "172.16.0.2",
            "",
            &[],
        )
        .expect("сборка без v6");
        assert!(!out.contains("ipv6: __IPV6__"));
        assert!(!out.contains("__IPV6__"));
        // tunnel-ipv4 остался на месте:
        assert!(out.contains("ip: 172.16.0.2"));
    }

    #[test]
    fn assemble_rejects_template_without_rules_section() {
        let err = assemble_warp_config("mixed-port: 7897\n", "k=", "p=", "s", "1.2.3.4", "", &[])
            .expect_err("нет rules — честная ошибка");
        assert!(err.contains("rules"));
    }

    #[test]
    fn assemble_rejects_wrong_first_rule() {
        let err = assemble_warp_config(
            "rules:\n  - MATCH,DIRECT\n",
            "k=",
            "p=",
            "s",
            "1.2.3.4",
            "",
            &[],
        )
        .expect_err("первая строка не trace — честная ошибка");
        assert!(err.contains("trace-правило"));
    }
}
