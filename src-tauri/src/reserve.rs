//! Гард запасного канала (PRP v3): здоровье Proton-WG через ноды пула,
//! самолечение перебором живых нод через REST API ядра. Перенос логики
//! vg_guard.py без внешних процессов и системных маршрутов: живость =
//! 204-проба через порт канала, лечение = PUT /proxies/TR + повторная проба
//! (механика валидирована стендом wg_test 18.11.26: смена ноды-такси под
//! живым туннелем подхватывает WG мгновенно; холодный handshake греется ~10с).

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::proxy_core::{API_PORT, GUARD_ON, PROXY_PORT};

/// Провайдеры пула бесплатных нод (имена в reserve_profile.yaml, SSOT).
const PROVIDERS: [&str; 2] = ["igareck-ss", "igareck-vless"];
/// Сколько живых нод перебирать за один цикл лечения (validated: живых обычно 1-3).
const HEAL_TRY_MAX: usize = 12;
/// Пауза после смены ноды-такси: WG-переподхват мгновенный, но холодный
/// handshake греется ~10с (стенд wg_test) — меньше не ждём, иначе ложный фейл.
const NODE_SWITCH_PAUSE: Duration = Duration::from_secs(8);
/// Интервал-health-цикла и число подряд идущих проб (перенос vg_guard: ×3).
const HEALTH_INTERVAL: Duration = Duration::from_secs(60);
const PROBES_PER_ROUND: usize = 3;

struct GuardState {
    ok: bool,
    node: String,
    exit_cc: String,
    last_error: String,
    heals: u32,
}

static STATE: Mutex<GuardState> = Mutex::new(GuardState {
    ok: false,
    node: String::new(),
    exit_cc: String::new(),
    last_error: String::new(),
    heals: 0,
});

fn state_file() -> std::path::PathBuf {
    config::get_app_dir().join("proxy").join("guard_state.json")
}

fn save_state() {
    if let Ok(g) = STATE.lock() {
        let doc = json!({
            "good_node": g.node,
            "exit_cc": g.exit_cc,
            "heals": g.heals,
        });
        let _ = std::fs::write(state_file(), serde_json::to_string_pretty(&doc).unwrap_or_default());
    }
}

fn load_state() {
    if let Ok(text) = std::fs::read_to_string(state_file()) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) {
            if let Ok(mut g) = STATE.lock() {
                g.node = map.get("good_node").and_then(|v| v.as_str()).unwrap_or("").to_string();
                g.exit_cc = map.get("exit_cc").and_then(|v| v.as_str()).unwrap_or("").to_string();
                g.heals = map.get("heals").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            }
        }
    }
}

/// Статус для channel_status(): честно, без «зелёного бейджа» на мёртвом гарде.
pub fn guard_status() -> Value {
    match STATE.lock() {
        Ok(g) => json!({
            "guard_on": GUARD_ON.load(Ordering::SeqCst),
            "ok": g.ok,
            "node": g.node,
            "exit_cc": g.exit_cc,
            "last_error": g.last_error,
            "heals": g.heals,
        }),
        Err(_) => json!({ "guard_on": false, "ok": false, "node": "", "exit_cc": "", "last_error": "состояние недоступно", "heals": 0 }),
    }
}

fn emit_log(app: &AppHandle, msg: String) {
    let _ = app.emit("log", format!("[Канал] {}", msg));
}

/// Клиент для REST API ядра (9097) — без прокси, только localhost.
fn api_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(70))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Клиент для проб через канал (7897): всё, что идёт через него, вылетает
/// через Proton-WG — это и есть SSOT-живость запасного канала.
fn probe_client() -> Result<reqwest::blocking::Client, String> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", PROXY_PORT))
        .map_err(|e| format!("плохой адрес прокси: {}", e))?;
    reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(12))
        .connect_timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("не собрать клиент проб: {}", e))
}

fn api_get_json(client: &reqwest::blocking::Client, path: &str) -> Result<Value, String> {
    let url = format!("http://127.0.0.1:{}{}", API_PORT, path);
    let text = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {}: {}", path, e))?
        .text()
        .map_err(|e| format!("GET {}: чтение ответа: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("GET {}: не JSON: {}", path, e))
}

fn api_put_json(client: &reqwest::blocking::Client, path: &str, body: Value) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{}{}", API_PORT, path);
    let res = client
        .put(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| format!("PUT {}: {}", path, e))?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("PUT {}: HTTP {}", path, res.status()))
    }
}

/// 204-проба через канал (SSOT живости, как в стенде/Ф7). Одиночная.
fn probe_204(client: &reqwest::blocking::Client) -> bool {
    match client
        .get("https://www.youtube.com/generate_204")
        .send()
    {
        Ok(r) => r.status() == 204,
        Err(_) => false,
    }
}

/// Вердикт выходной страны по SSOT Ф7: `<html lang="xx-XX">` из первых 2000
/// символов главной ютуба. Тяжёлая проба (~1МБ) — только на старте/после лечения.
fn update_exit_cc(client: &reqwest::blocking::Client, app: &AppHandle) {
    let body = match client.get("https://www.youtube.com/").send() {
        Ok(r) => match r.text() {
            Ok(t) => t,
            Err(_) => return,
        },
        Err(_) => return,
    };
    let head: String = body.chars().take(2000).collect();
    let cc = match head.find("lang=\"") {
        Some(pos) => {
            let rest = &head[pos + 6..];
            let end = rest.find('"').unwrap_or(0);
            rest[..end].to_string()
        }
        None => String::new(),
    };
    if !cc.is_empty() {
        if let Ok(mut g) = STATE.lock() {
            if g.exit_cc != cc {
                g.exit_cc = cc.clone();
                emit_log(app, format!("Выход запасного канала: {}", cc));
            }
        }
        save_state();
    }
}

/// Живые TCP-ноды провайдера. Ленивый health-check лочится на актуальность:
/// сначала явный healthcheck endpoint, потом чтение alive-флагов. Нюанс mihomo
/// (стенд 18.11): per-node /proxies/{name}/delay отдаёт 404 на нодах
/// провайдера — жив только provider-endpoint.
fn alive_nodes(client: &reqwest::blocking::Client) -> Vec<String> {
    let mut alive = Vec::new();
    for prov in PROVIDERS {
        let hc = format!(
            "/providers/proxies/{}/healthcheck?url=https%3A%2F%2Fwww.youtube.com%2Fgenerate_204&timeout=4000",
            prov
        );
        // 70s-таймаут клиента покрывает конкурентный прогон всего провайдера.
        let _ = api_get_json(client, &hc);
        if let Ok(data) = api_get_json(client, &format!("/providers/proxies/{}", prov)) {
            if let Some(list) = data.get("proxies").and_then(|v| v.as_array()) {
                for p in list {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if p.get("alive").and_then(|v| v.as_bool()).unwrap_or(false) && !name.is_empty() {
                        alive.push(name.to_string());
                    }
                }
            }
        }
    }
    alive
}

/// Переключение ноды-такси: валидированная механика самолечения (wg_test).
fn switch_node(client: &reqwest::blocking::Client, name: &str) -> Result<(), String> {
    api_put_json(client, "/proxies/TR", json!({ "name": name }))
}

/// Цикл лечения: живые ноды → good_node в приоритете → PUT + проба. Возврат
/// Some(нода) при успехе.
fn heal(app: &AppHandle, client: &reqwest::blocking::Client) -> Option<String> {
    let nodes = alive_nodes(client);
    if nodes.is_empty() {
        emit_log(app, "Самолечение: живых нод пула нет вообще — повтор через минуту.".into());
        if let Ok(mut g) = STATE.lock() {
            g.last_error = "живых нод пула нет".into();
        }
        return None;
    }
    // good_node из прошлого успеха идёт первым (перенос vg_guard).
    let good = STATE.lock().ok().map(|g| g.node.clone()).unwrap_or_default();
    let mut order: Vec<String> = Vec::new();
    if nodes.contains(&good) {
        order.push(good.clone());
    }
    for n in &nodes {
        if *n != good {
            order.push(n.clone());
        }
    }
    emit_log(app, format!("Самолечение: живых нод {} — перебираю до {}.", order.len(), HEAL_TRY_MAX));

    for name in order.into_iter().take(HEAL_TRY_MAX) {
        if !GUARD_ON.load(Ordering::SeqCst) {
            return None;
        }
        let short: String = name.chars().take(46).collect();
        emit_log(app, format!("Пробую ноду {}…", short));
        if let Err(e) = switch_node(client, &name) {
            emit_log(app, format!("Смена ноды не удалась: {}", e));
            continue;
        }
        thread::sleep(NODE_SWITCH_PAUSE);
        if probe_204(client) {
            if let Ok(mut g) = STATE.lock() {
                g.node = name.clone();
                g.ok = true;
                g.last_error.clear();
                g.heals += 1;
            }
            save_state();
            emit_log(app, format!("Канал восстановлен через {}.", short));
            update_exit_cc(client, app);
            return Some(name);
        }
    }
    emit_log(app, "Ни одна живая нода не прокинула WG — повтор через минуту.".into());
    if let Ok(mut g) = STATE.lock() {
        g.last_error = "перебор живых нод не помог".into();
    }
    None
}

fn guard_loop(app: AppHandle) {
    load_state();
    emit_log(&app, "Гард запасного канала запущен (проверка каждые 60с).".into());
    let api = api_client();
    let probe = match probe_client() {
        Ok(c) => c,
        Err(e) => {
            emit_log(&app, format!("Гард остановлен: {}", e));
            return;
        }
    };

    // Стартовый прогон: сразу выставить честный статус (нода/выход).
    if probe_204(&probe) {
        if let Ok(mut g) = STATE.lock() {
            g.ok = true;
            g.last_error.clear();
        }
        if STATE.lock().map(|g| g.node.is_empty()).unwrap_or(false) {
            if let Ok(cur) = api_get_json(&api, "/proxies/TR") {
                if let Some(n) = cur.get("now").and_then(|v| v.as_str()) {
                    if let Ok(mut g) = STATE.lock() {
                        g.node = n.to_string();
                    }
                }
            }
        }
        update_exit_cc(&probe, &app);
    } else {
        emit_log(&app, "Канал не отвечает на старте — запускаю самолечение…".into());
        heal(&app, &probe);
    }
    save_state();

    let mut last_heal = Instant::now();
    loop {
        // Сон в мелких тиках: остановка гарда не ждёт минуту.
        for _ in 0..(HEALTH_INTERVAL.as_secs()) {
            if !GUARD_ON.load(Ordering::SeqCst) {
                emit_log(&app, "Гард запасного канала остановлен.".into());
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if !GUARD_ON.load(Ordering::SeqCst) {
            emit_log(&app, "Гард запасного канала остановлен.".into());
            return;
        }
        let mut healthy = true;
        for i in 0..PROBES_PER_ROUND {
            if i > 0 {
                thread::sleep(Duration::from_secs(2));
            }
            if !probe_204(&probe) {
                healthy = false;
                break;
            }
        }
        if healthy {
            if let Ok(mut g) = STATE.lock() {
                g.ok = true;
                g.last_error.clear();
            }
            save_state();
            continue;
        }
        if let Ok(mut g) = STATE.lock() {
            g.ok = false;
        }
        // Градация: частые сбои лечим не чаще раза в 3 минуты, иначе
        // перебор нод закружится вокруг едва живого канала.
        if last_heal.elapsed() < Duration::from_secs(180) {
            emit_log(&app, "Канал дёргается — самолечение отложено (не чаще раза в 3 мин).".into());
            continue;
        }
        last_heal = Instant::now();
        emit_log(&app, "Запасной канал не отвечает (204×3) — самолечение.".into());
        heal(&app, &probe);
        save_state();
    }
}

/// Старт гарда (идемпотентно: второй вызов при живом цикле — no-op).
pub fn start_guard(app: AppHandle) {
    if GUARD_ON.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(move || guard_loop(app));
}

// ===================== WG-креды и генерация reserve_profile.yaml =====================
// (PRP «18.11.26 Вкладка Канал»). Личные данные юзера (ключи WireGuard его
// провайдера) живут ТОЛЬКО в AppData/proxy/wg_creds.json и попадают туда
// ТОЛЬКО импортом WG .conf у него на машине. В репо/бандл едет публичный
// шаблон defaults/reserve_template.yaml с плейсхолдерами вместо секретов.

use std::path::PathBuf;

/// Креды WireGuard-провайдера юзера (личные, хранить только в AppData).
#[derive(Clone)]
pub struct WgCreds {
    pub(crate) private_key: String,
    pub(crate) public_key: String,
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) address: String,
    pub(crate) keepalive: u16,
    pub(crate) psk: Option<String>,
}

fn creds_file() -> PathBuf {
    config::get_app_dir().join("proxy").join("wg_creds.json")
}

fn reserve_path() -> PathBuf {
    config::get_app_dir().join("proxy").join("reserve_profile.yaml")
}

/// Путь регенерированного конфига запасного канала (публичная обёртка для
/// refresh_channel_exclude / routing_set_mode — Этап A, 19.11.26).
pub fn reserve_profile_path() -> PathBuf {
    reserve_path()
}

fn creds_to_json(c: &WgCreds, source: &str) -> Value {
    json!({
        "private_key": c.private_key,
        "public_key": c.public_key,
        "server": c.server,
        "port": c.port,
        "address": c.address,
        "keepalive": c.keepalive,
        "psk": c.psk,
        "source": source,
    })
}

fn creds_from_json(v: &Value) -> Option<WgCreds> {
    let port = v.get("port")?.as_u64()? as u16;
    let keepalive = v.get("keepalive").and_then(|x| x.as_u64()).unwrap_or(25) as u16;
    Some(WgCreds {
        private_key: v.get("private_key")?.as_str()?.to_string(),
        public_key: v.get("public_key")?.as_str()?.to_string(),
        server: v.get("server")?.as_str()?.to_string(),
        port,
        address: v.get("address")?.as_str()?.to_string(),
        keepalive,
        psk: v.get("psk").and_then(|x| x.as_str()).map(|s| s.to_string()),
    })
}

fn save_creds(c: &WgCreds, source: &str) -> Result<(), String> {
    let doc = creds_to_json(c, source);
    std::fs::write(creds_file(), serde_json::to_string_pretty(&doc).unwrap_or_default())
        .map_err(|e| format!("не записать {}: {}", creds_file().display(), e))
}

pub(crate) fn load_creds() -> Option<WgCreds> {
    std::fs::read_to_string(creds_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| creds_from_json(&v))
}

/// Гейт channel_set("reserve") и условие перегенерации.
pub fn has_wg_creds() -> bool {
    load_creds().is_some()
}

/// Статус кредов для фронта. Приватный ключ НЕ отдаём — фронт показывает
/// только endpoint/address и наличие PSK (§2.2: честный статус, без утечек).
pub fn wg_creds_status() -> Value {
    match load_creds() {
        Some(c) => json!({
            "present": true,
            "endpoint": format!("{}:{}", c.server, c.port),
            "address": c.address,
            "keepalive": c.keepalive,
            "psk": c.psk.is_some(),
        }),
        None => json!({ "present": false }),
    }
}

/// Парсер INI-style WireGuard .conf ([Interface]/[Peer]) — Proton или любой
/// WG-провайдер. Обязательные поля: PrivateKey, PublicKey, Endpoint, Address.
pub fn parse_wg_conf(text: &str) -> Result<WgCreds, String> {
    let mut iface: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut peer: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut section = String::new();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if l.starts_with('[') {
            section = l.trim_matches(|c| c == '[' || c == ']').to_lowercase();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue; // чужой мусор в файле не фатален — добор по обязательным полям ниже
        };
        let key = k.trim().to_lowercase();
        let val = v.trim().to_string();
        match section.as_str() {
            "interface" => { iface.insert(key, val); }
            "peer" => { peer.insert(key, val); }
            _ => {}
        }
    }

    let get = |m: &std::collections::HashMap<String, String>, k: &str| {
        m.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };

    let private_key = get(&iface, "privatekey")
        .ok_or("В .conf нет PrivateKey в [Interface]")?;
    let public_key = get(&peer, "publickey")
        .ok_or("В .conf нет PublicKey в [Peer]")?;
    let endpoint = get(&peer, "endpoint")
        .ok_or("В .conf нет Endpoint в [Peer]")?;
    let address_raw = get(&iface, "address")
        .ok_or("В .conf нет Address в [Interface]")?;

    // Address может быть списком через запятую ("10.2.0.2/32, fd00::/128") —
    // берём первый, без префикса длины (mihomo-поле ip ждёт чистый адрес).
    let address = address_raw
        .split(',')
        .next()
        .unwrap_or(&address_raw)
        .trim()
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if address.is_empty() {
        return Err("Address в [Interface] пуст".into());
    }

    // Endpoint "host:port"; IPv6 [2001:db8::1]:51820 — порт после последнего ':'.
    let (server, port) = match endpoint.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_start_matches('[').trim_end_matches(']').to_string(),
            p.trim().parse::<u16>()
                .map_err(|_| format!("Endpoint «{}»: порт не число", endpoint))?,
        ),
        None => return Err(format!("Endpoint «{}» без порта", endpoint)),
    };
    if server.is_empty() {
        return Err("Endpoint: пустой хост".into());
    }

    let keepalive = get(&peer, "persistentkeepalive")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(25);
    let psk = get(&peer, "presharedkey");

    Ok(WgCreds { private_key, public_key, server, port, address, keepalive, psk })
}

/// Импорт WG .conf: парс → сохранение кредов в AppData → запись канала в
/// реестр (имя — канон метода, канал один — file = «__wg__») → перегенерация
/// reserve_profile.yaml из шаблона + кредов. Возвращает статус для UI.
pub fn wg_creds_import(path: &str, app: &AppHandle) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("не прочитать {}: {}", path, e))?;
    let creds = parse_wg_conf(&text)?;
    save_creds(&creds, path)?;
    // Единый reconciler (баг №1, ревью спеца 24.11.26): синкает ВСЕ встроенные
    // каналы (WG + pawg + AWG + Psiphon) по фактическому состоянию на диске.
    // Раньше здесь был только wg_channel_sync → pawg не появлялся, если AWG
    // уже зарегистрирован (корень бага №1).
    crate::proxy_core::reconcile_builtin_channels(app);
    let out = generate_reserve_config()?;
    emit_log(app, format!(
        "WireGuard-креды импортированы ({}:{}), запасной конфиг собран: {}",
        creds.server, creds.port, out.display()
    ));
    Ok(wg_creds_status())
}

/// Сброс кредов: удаляем файл кредов, WG-запись реестра и reserve_profile.yaml
/// — после сброса включение WG-канала честно требует повторного импорта.
pub fn wg_creds_reset(app: &AppHandle) -> Result<String, String> {
    let _ = std::fs::remove_file(creds_file());
    let _ = std::fs::remove_file(crate::proxy_core::proxy_dir().join("reserve_profile.yaml"));
    // Единый reconciler: уберёт WG из реестра + удалит осиротевший pawg
    // (pawg_possible = false без кредов) + корректно обработает active.
    crate::proxy_core::reconcile_builtin_channels(app);
    emit_log(app, "WireGuard-креды сброшены — для WG-канала нужен повторный импорт.".into());
    Ok(String::from("Креды сброшены."))
}

/// Генерация reserve_profile.yaml: публичный шаблон + подстановка кредов.
/// Плейсхолдеры шаблона — SSOT набора полей; после подстановки проверяем,
/// что ничего не осталось (честность: не стартовать конфиг с дыркой в ключе).
pub fn generate_reserve_config() -> Result<PathBuf, String> {
    let creds = load_creds()
        .ok_or("Нет WireGuard-кредов — импортируй WG .conf на вкладке «Канал»")?;
    let tpl = include_str!("../defaults/reserve_template.yaml");
    let mut out = tpl
        .replace("__PRIVATE_KEY__", &creds.private_key)
        .replace("__PUBLIC_KEY__", &creds.public_key)
        .replace("__SERVER__", &creds.server)
        .replace("__PORT__", &creds.port.to_string())
        .replace("__ADDRESS__", &creds.address)
        .replace("__KEEPALIVE__", &creds.keepalive.to_string());

    // PSK опционален: дописываем строку сразу после public-key (mihomo-поле).
    if let Some(psk) = &creds.psk {
        let mut lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();
        if let Some(i) = lines.iter().position(|l| l.contains("public-key:")) {
            let indent = lines[i].len() - lines[i].trim_start().len();
            lines.insert(i + 1, format!("{}preshared-key: \"{}\"", " ".repeat(indent), psk));
        }
        out = lines.join("\n") + "\n";
    }

    // Правила маршрутизации от компилятора групп (Этап A, 19.11.26):
    // selective → channel-домены → PROTON-WG + MATCH,DIRECT (остальное
    // напрямую), fullport → MATCH,PROTON-WG (весь трафик через канал).
    // Шаблонный хвост rules заменяется — применились режимы юзера из
    // routing.json, а не зашитые в шаблоне. Домены нод сюда не нужны
    // (mihomo-правила их не используют) — их добавит apply_channel_exclude
    // в channel_set, когда конфиг уже сгенерирован.
    {
        let modes = crate::routing::load_modes()?;
        let art = crate::routing::compile_from_fs(
            &modes,
            true,
            Some("PROTON-WG"),
            &[],
            crate::proxy_core::PROXY_PORT,
        )?;
        let mut lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();
        let Some(ri) = lines.iter().position(|l| l.trim() == "rules:") else {
            return Err(String::from("Шаблон запасного: не найдена секция rules"));
        };
        lines.truncate(ri);
        lines.push(String::from("rules:"));
        lines.extend(art.mihomo_rules);
        out = lines.join("\n") + "\n";
    }

    const PLACEHOLDERS: [&str; 6] = [
        "__PRIVATE_KEY__", "__PUBLIC_KEY__", "__SERVER__",
        "__PORT__", "__ADDRESS__", "__KEEPALIVE__",
    ];
    for ph in PLACEHOLDERS {
        if out.contains(ph) {
            return Err(format!("Шаблон запасного: не подставился плейсхолдер {}", ph));
        }
    }

    let path = reserve_path();
    std::fs::write(&path, &out)
        .map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(path)
}

/// Миграция автора (тихая, одноразовая): если wg_creds.json ещё нет, а старый
/// reserve_profile.yaml лежит с реальными значениями — вытащить WG-поля в
/// креды. Формат старого файла: WG-секция YAML (private-key: "…", server: …).
pub fn migrate_existing_creds(app: &AppHandle) {
    if creds_file().exists() {
        return;
    }
    let Ok(text) = std::fs::read_to_string(reserve_path()) else { return };
    let pick = |key: &str| -> Option<String> {
        text.lines()
            .find(|l| l.trim_start().starts_with(key))
            .map(|l| l.trim_start()[key.len()..].trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
    };
    let (Some(private_key), Some(public_key), Some(server), Some(address)) = (
        pick("private-key:"),
        pick("public-key:"),
        pick("server:"),
        pick("ip:"),
    ) else {
        return;
    };
    let Ok(port) = pick("port:").unwrap_or_default().parse::<u16>() else { return };
    let keepalive = pick("persistent-keepalive:")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(25);
    let creds = WgCreds {
        private_key,
        public_key,
        server,
        port,
        address,
        keepalive,
        psk: pick("preshared-key:"),
    };
    if save_creds(&creds, "миграция reserve_profile.yaml").is_ok() {
        emit_log(app, "Прежние WG-креды перенесены во вкладку «Канал» (wg_creds.json).".into());
    }
}

#[cfg(test)]
mod wg_conf_tests {
    use super::parse_wg_conf;

    const PROTON_STYLE: &str = "\
[Interface]
# comment
PrivateKey = sF1KPF4Wvyw/0BnhbkcAjf0ChAuBXH+8C07dzyRlPlc=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = pUY22Gd3zhSoZZO6p0rxg2F96gwNgkpFjYSun4TWf2s=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.107.56.22:51820
PersistentKeepalive = 25";

    #[test]
    fn parses_proton_style() {
        let c = parse_wg_conf(PROTON_STYLE).expect("должен парситься");
        assert_eq!(c.private_key, "sF1KPF4Wvyw/0BnhbkcAjf0ChAuBXH+8C07dzyRlPlc=");
        assert_eq!(c.public_key, "pUY22Gd3zhSoZZO6p0rxg2F96gwNgkpFjYSun4TWf2s=");
        assert_eq!(c.server, "185.107.56.22");
        assert_eq!(c.port, 51820);
        assert_eq!(c.address, "10.2.0.2"); // /32 срезан
        assert_eq!(c.keepalive, 25);
        assert!(c.psk.is_none());
    }

    #[test]
    fn default_keepalive_and_psk() {
        let conf = PROTON_STYLE
            .replace("PersistentKeepalive = 25", "")
            .replace("AllowedIPs = 0.0.0.0/0, ::/0", "PresharedKey = uW1c8Hk3cQ==\nAllowedIPs = 0.0.0.0/0");
        let c = parse_wg_conf(&conf).expect("должен парситься");
        assert_eq!(c.keepalive, 25); // дефолт при отсутствии поля
        assert_eq!(c.psk.as_deref(), Some("uW1c8Hk3cQ=="));
    }

    #[test]
    fn ipv6_endpoint_and_address_list() {
        let conf = PROTON_STYLE
            .replace("Address = 10.2.0.2/32", "Address = 10.2.0.2/32, fd42::2/128")
            .replace("Endpoint = 185.107.56.22:51820", "Endpoint = [2001:db8::1]:443");
        let c = parse_wg_conf(&conf).expect("должен парситься");
        assert_eq!(c.address, "10.2.0.2"); // первый из списка, без /32
        assert_eq!(c.server, "2001:db8::1"); // скобки срезаны
        assert_eq!(c.port, 443);
    }

    #[test]
    fn missing_fields_are_honest_errors() {
        assert!(parse_wg_conf("[Interface]\nAddress = 10.2.0.2/32").is_err());
        let no_key = PROTON_STYLE.replace("PrivateKey = sF1KPF4Wvyw/0BnhbkcAjf0ChAuBXH+8C07dzyRlPlc=", "");
        assert!(parse_wg_conf(&no_key).is_err());
        assert!(parse_wg_conf("").is_err());
    }
}
