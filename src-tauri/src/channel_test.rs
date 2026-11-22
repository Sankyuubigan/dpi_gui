//! Тест каналов (21.11.26, запрос юзера: «я нажму кнопку и увижу, что работает,
//! а что нет — вместо того чтобы вручную тестить и верить агенту на слово»).
//!
//! Каждый канал реестра тестируется ЖИВЬЁМ на реальных HTTP-пробах:
//! ютуб-путь (generate_204), медиа-домен googlevideo, гео (aistudio),
//! страна выхода (cloudflare meta), скорость (cloudflare __down 10 МБ).
//!
//! Принципы (план «21.11.26 Плашка „Тест каналов"», не нарушать):
//! - тест НЕ трогает активный канал: он тестируется на своём боевом порту
//!   7897, остальные — тестовым mihomo на 7920 (REST 9120): 7898/9099 заняты
//!   оракулом/экспериментами (комментарий у PAC_PORT в routing.rs);
//! - тестовые процессы гасятся по PID (KillOnDrop у mihomo — kill по имени
//!   убил бы и боевой движок) или деревом (TreeChild/Job Object у aether —
//!   его дети psiphon-tunnel-core/lyrebird);
//! - тестовые процессы исполняются из runtime-копий (process::runtime_file),
//!   не из бандла/папки сборки: живой тест лочил release/bin/mihomo.exe и
//!   валил сборку релиза os error 32 (инцидент 22.11.26);
//! - каждая проба — реальный HTTP; эвристики запрещены (AGENTS.md §7),
//!   ошибка показывается как есть, без «считаем что ок»;
//! - тест = «работает СЕЙЧАС», не «стабильность 24/7» (§9 — суточный прогон);
//! - секреты не покидают AppData: тестовые конфиги — копии в AppData/proxy/test.

use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::config;
use crate::process;
use crate::proxy_core;

/// mixed-порт тестового mihomo (боевой 7897).
pub const TEST_MIXED_PORT: u16 = 7920;
/// external-controller тестового mihomo (боевой 9097).
pub const TEST_REST_PORT: u16 = 9120;
/// WARP-listener тестового psiphon-конфига (боевой 7901 — upstream aether).
const TEST_LISTENER_PORT: u16 = 7921;
/// socks aether в тестовом psiphon-стенде (боевой 10818).
const TEST_AETHER_SOCKS_PORT: u16 = 10828;

const MIHOMO_EXE: &str = "mihomo.exe";
const CREATE_NO_WINDOW: u32 = 0x08000000;
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const PORT_WAIT: Duration = Duration::from_secs(12);
const AETHER_WAIT: Duration = Duration::from_secs(40);
/// Бюджет прогрева туннеля: холодный WG/AWG-handshake греется 10-25с —
/// дольше таймаута проб (8с); без прогрева живые каналы ложно падали «МЁРТВ».
const WARMUP_BUDGET: Duration = Duration::from_secs(30);
/// Бюджет замера скорости: psiphon ~0.2 МБ/с — 10 МБ за полный бюджет не
/// успеют, честная скорость считается по частичному скачиванию.
const SPEED_BUDGET: Duration = Duration::from_secs(20);
const SPEED_BYTES: usize = 10_000_000;

fn emit_log(app: &AppHandle, msg: String) {
    // И в dpi_gui.log (плагин-коллектор через log::info), и в UI-панель:
    // до 21.11.26 детали теста уходили только в окно — файл был «пустым».
    log::info!("{}", msg);
    let _ = app.emit("log", msg);
}

fn test_dir() -> PathBuf {
    proxy_core::proxy_dir().join("test")
}

/// Ребёнок, гасящийся при любом выходе из области видимости (в т.ч. через `?`).
/// Гашение ТОЛЬКО по PID — kill_mihomo_any по имени убил бы боевой движок.
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Путь боевого конфига канала; для платных — None (собирается из профиля
/// юзера через patch_paid_yaml_tree). Файла нет → честная ошибка с причиной
/// (не учётки/кредов — канал настроить нельзя, тестировать нечего).
fn combat_config_path(id: &str) -> Result<Option<PathBuf>, String> {
    if id.contains('\\') || id.contains('/') || id.contains("..") {
        return Err(format!("Недопустимый id канала: «{}»", id));
    }
    let dir = proxy_core::proxy_dir();
    let p = match id {
        "__wg__" => Some(dir.join("reserve_profile.yaml")),
        "__warp__" => Some(dir.join("warp_profile.yaml")),
        "__awg__" => Some(dir.join("awg_profile.yaml")),
        "__pawg__" => Some(dir.join("pawg_profile.yaml")),
        "__psiphon__" => Some(dir.join("psiphon_profile.yaml")),
        _ => None,
    };
    if let Some(p) = &p {
        if !p.exists() {
            return Err(format!(
                "конфиг канала не собран ({} отсутствует) — для канала нет учётки/кредов",
                p.display()
            ));
        }
    }
    Ok(p)
}

/// Текст тестового конфига: боевые порты → тестовые (7897→7920, 9097→9120;
/// psiphon: +10818→10828, 7901→7921). Платный проходит через патчдерево
/// (TUN off, fake-ip, порты канала) — как в бою, но с тестовыми портами.
fn test_config_text(id: &str, combat_text: &str) -> Result<String, String> {
    let base = if id.starts_with("__") {
        combat_text.to_string()
    } else {
        proxy_core::patch_paid_yaml_tree(combat_text)?
    };
    let mut t = base.replace("7897", "7920").replace("9097", "9120");
    if id == "__psiphon__" {
        t = t.replace("10818", "10828").replace("7901", "7921");
    }
    Ok(t)
}

fn write_test_config(id: &str, combat_text: &str) -> Result<PathBuf, String> {
    let dir = test_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let text = test_config_text(id, combat_text)?;
    let text = prepend_echo_rules(&text)?;
    let file = if id.ends_with(".yaml") { id.to_string() } else { format!("{}.yaml", id) };
    let path = dir.join(file);
    std::fs::write(&path, &text)
        .map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(path)
}

/// Имена всех исходящих/групп (proxy-groups[].name + proxies[].name) — для
/// валидации target'а правила: наивный split ломается на логических правилах
/// (AND,((...)) в платном конфиге давал мусор «UDP)» → mihomo падал на старте).
fn outbound_names(v: &serde_yaml::Value) -> Vec<String> {
    let mut names = Vec::new();
    for key in ["proxy-groups", "proxies"] {
        if let Some(seq) = v.get(key).and_then(|x| x.as_sequence()) {
            for item in seq {
                if let Some(n) = item.get("name").and_then(|n| n.as_str()) {
                    names.push(n.to_string());
                }
            }
        }
    }
    names
}

/// Target одного правила mihomo; None для DIRECT/REJECT/PASS и пустых.
/// Логические правила (AND/OR/NOT с вложенными скобками) — target последний
/// элемент (после скобочного условия); обычные 3-частные (IP-CIDR/.../GROUP,
/// no-resolve-хвост игнорируем) и MATCH,GROUP — на своей позиции.
fn extract_rule_target(rule: &str) -> Option<&str> {
    let parts: Vec<&str> = rule.split(',').map(|s| s.trim()).collect();
    let head = *parts.first()?;
    let target = if matches!(head, "AND" | "OR" | "NOT") {
        parts.last()?
    } else if head == "MATCH" {
        parts.get(1)?
    } else {
        parts.get(2)?
    };
    let t = target.trim();
    if t.is_empty() || matches!(t, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS") {
        None
    } else {
        Some(t)
    }
}

/// Группа выхода туннеля. Приоритет — target MATCH-правила на настоящую
/// группу: это главный выход платных профилей (первое же правило платного
/// конфига может вести во вспомогательную группу с другим выходом — эхо
/// через неё давало ложную страну). Если MATCH,DIRECT (сгенерированные
/// профили) — первое туннельное правило. Валидация по именам групп отсекает
/// мусор от логических правил.
fn tunnel_group_of_rules(v: &serde_yaml::Value) -> Option<String> {
    let known = outbound_names(v);
    if known.is_empty() {
        return None;
    }
    let rules = v.get("rules")?.as_sequence()?;
    let strs: Vec<&str> = rules.iter().filter_map(|x| x.as_str()).collect();
    if let Some(match_rule) = strs
        .iter()
        .find(|r| r.split(',').map(str::trim).next() == Some("MATCH"))
    {
        if let Some(t) = extract_rule_target(match_rule) {
            if known.iter().any(|n| n == t) {
                return Some(t.to_string());
            }
        }
    }
    strs.iter().find_map(|r| {
        let t = extract_rule_target(r)?;
        known.iter().any(|n| n == t).then(|| t.to_string())
    })
}

/// IP-эхо и speed-пробы должны идти ЧЕРЕЗ ТУННЕЛЬ в ТЕСТОВОМ конфиге:
/// сгенерированные профили (wg/warp/awg/pawg/psiphon) гоняют через канал
/// только адресаты из правил (ютуб/гугл/DoH-шлюзы), остальное — MATCH,DIRECT.
/// Без этого проба страны ловит собственный IP юзера (RU) вместо выхода
/// туннеля, а скорость на мёртвом канале «заряжает» напрямую (инцидент
/// 21.11.26: страна RU и 26 МБ/с на мёртвом warp). Правила препендим в
/// начало списка; группу берём из первого туннельного правила профиля.
/// Меняется ТОЛЬКО тестовый конфиг (AppData/proxy/test) — боевой не трогаем.
fn prepend_echo_rules(yaml_text: &str) -> Result<String, String> {
    let mut v: serde_yaml::Value = serde_yaml::from_str(yaml_text)
        .map_err(|e| format!("тестовый конфиг не YAML: {}", e))?;
    if v.get("rules").and_then(|r| r.as_sequence()).is_none() {
        return Ok(yaml_text.to_string());
    }
    let Some(group) = tunnel_group_of_rules(&v) else {
        return Ok(yaml_text.to_string());
    };
    if let Some(seq) = v.get_mut("rules").and_then(|r| r.as_sequence_mut()) {
        for echo in [
            format!("DOMAIN,ipwho.is,{}", group),
            format!("DOMAIN,ipinfo.io,{}", group),
            format!("DOMAIN-SUFFIX,cloudflare.com,{}", group),
        ] {
            seq.insert(0, serde_yaml::Value::String(echo));
        }
    }
    serde_yaml::to_string(&v).map_err(|e| format!("тестовый конфиг не сериализуется: {}", e))
}

/// Тестовый mihomo: cwd/`-d` = proxy_dir (провайдеры резолвятся как в бою),
/// stdout/stderr в лог-файл (там причина, если порт не поднялся).
fn spawn_test_mihomo(cfg: &PathBuf) -> Result<KillOnDrop, String> {
    // Runtime-копия: тест не лочит exe в бандле/папке сборки — замер в
    // 21:00 держал release/bin/mihomo.exe и валил сборку юзера (22.11.26).
    let mihomo = process::runtime_file(MIHOMO_EXE)?;
    let work_dir = proxy_core::proxy_dir();
    let log = test_dir().join("mihomo_test.log");
    let out = std::fs::File::create(&log)
        .map_err(|e| format!("не открыть лог {}: {}", log.display(), e))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let child = Command::new(&mihomo)
        .arg("-d")
        .arg(&work_dir)
        .arg("-f")
        .arg(cfg)
        .current_dir(&work_dir)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| format!("Ошибка запуска {}: {}", MIHOMO_EXE, e))?;
    Ok(KillOnDrop(child))
}

fn wait_port(port: u16, child: &mut KillOnDrop, timeout: Duration) -> Result<(), String> {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if proxy_core::port_alive(port) {
            return Ok(());
        }
        if let Ok(Some(code)) = child.0.try_wait() {
            return Err(format!(
                "тестовый mihomo вышел сразу (код {:?}) — причина в {}",
                code,
                test_dir().join("mihomo_test.log").display()
            ));
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Err(format!(
        "порт {} не поднялся за {:.0}с — причина в {}",
        port,
        timeout.as_secs_f32(),
        test_dir().join("mihomo_test.log").display()
    ))
}

// ---------- Пробы (реальный HTTP, без эвристик — §7) ----------

/// Одна живая проба через порт канала.
#[derive(Clone, Debug)]
struct Probe {
    ok: bool,
    detail: String,
}

/// Самый глубокий источник ошибки (hyper), хвост до max символов: reqwest
/// прячет реальную причину («tunnel … 502») в source-цепочке.
fn err_tail(e: &reqwest::Error, max: usize) -> String {
    let mut cur: &dyn std::error::Error = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    let s = format!("{}", cur);
    s.chars().skip(s.chars().count().saturating_sub(max)).collect()
}

fn reqwest_err_short(e: &reqwest::Error) -> String {
    // Таймаут ПЕРВЫМ: connect-фаза тоже помечена is_connect (туннель висит).
    if e.is_timeout() {
        return String::from("таймаут — туннель не ответил вовремя");
    }
    if e.is_connect() {
        // hyper превращает не-200 ответ mihomo на CONNECT (мёртвая нода, 502)
        // в ConnectError: раньше любое из этого рисовалось как «нет соединения
        // через канал» даже на живом канале — теперь реальный хвост причины.
        let tail = err_tail(e, 100);
        return format!(
            "dial не прошёл{}",
            if tail.is_empty() { String::new() } else { format!(": {}", tail) }
        );
    }
    let s = format!("{}", e);
    s.chars().take(120).collect()
}

fn proxied_client(port: u16, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port))
            .map_err(|e| format!("не задать прокси: {}", e))?)
        .timeout(timeout)
        .build()
        .map_err(|e| format!("не создать HTTP-клиент: {}", e))
}

fn probe_status(port: u16, url: &str, ok_status: impl Fn(u16) -> bool, what: &str) -> Probe {
    let t0 = Instant::now();
    let client = match proxied_client(port, PROBE_TIMEOUT) {
        Ok(c) => c,
        Err(e) => return Probe { ok: false, detail: format!("{}: {}", what, e) },
    };
    match client.get(url).send() {
        Ok(resp) => {
            let st = resp.status().as_u16();
            Probe {
                ok: ok_status(st),
                detail: format!("HTTP {} ({:.1}с)", st, t0.elapsed().as_secs_f64()),
            }
        }
        Err(e) => Probe { ok: false, detail: format!("{}: {}", what, reqwest_err_short(&e)) },
    }
}

/// ТСПУ/РКН: ютуб-путь. generate_204 = «путь жив» (204 маленький и честный).
fn probe_youtube(port: u16) -> Probe {
    probe_status(port, "http://www.youtube.com/generate_204", |s| s == 204, "ютуб-путь")
}

/// Медиа-путь (боль юзера: кэш-мисс googlevideo). redirector — вход медиа-
/// домена; любой серверный ответ < 500 = путь до googlevideo не режется.
fn probe_media(port: u16) -> Probe {
    probe_status(
        port,
        "https://redirector.googlevideo.com/generate_204",
        |s| s < 500,
        "медиа (googlevideo)",
    )
}

/// Гео-обход: aistudio. 2xx/3xx = сайт открывается; 403/429/451 — сам сайт
/// отказывает (гео-ограничение); ошибка соединения — канал не проехал.
fn probe_geo(port: u16) -> Probe {
    probe_status(port, "https://aistudio.google.com/", |s| (200..=399).contains(&s), "гео (aistudio)")
}

/// Страна выхода: ip-эхо через канал + сопоставление IP→страна.
/// История (21.11.26): speed.cloudflare.com/meta отдаёт 403 `{}` не-браузерным
/// клиентам (проверено живьём через стенд, даже с браузерным UA); замена на
/// cloudflare trace (`loc=`) дала ложную RU на живых wg/awg — `loc` в trace
/// это страна ПОП-ТОЧКИ Cloudflare (для выхода TR ближайшая — Москва), не
/// страны выхода. Поэтому честный источник — ipwho.is / ipinfo.io: они
/// сопоставляют САМ IP выхода со страной (данные, не эвристика — §7).
/// Все канальные профили гоняют весь трафик через туннель (MATCH) — ip-эхо
/// идёт по каналу и показывает именно выход.
fn probe_country(port: u16) -> (Option<String>, Probe) {
    let client = match proxied_client(port, PROBE_TIMEOUT) {
        Ok(c) => c,
        Err(e) => return (None, Probe { ok: false, detail: format!("страна: {}", e) }),
    };
    // ipwho.is: JSON с country_code
    if let Ok(resp) = client.get("https://ipwho.is/").send() {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>() {
                if let Some(cc) = v["country_code"].as_str() {
                    if !cc.is_empty() {
                        return (
                            Some(cc.to_string()),
                            Probe { ok: true, detail: format!("выход {}", cc) },
                        );
                    }
                }
            }
        }
    }
    // Фолбэк: ipinfo.io/json (независимый второй источник того же факта).
    match client.get("https://ipinfo.io/json").send() {
        Ok(resp) => match resp.json::<Value>() {
            Ok(v) => match v["country"].as_str() {
                Some(cc) => (
                    Some(cc.to_string()),
                    Probe { ok: true, detail: format!("выход {} (ipinfo)", cc) },
                ),
                None => (None, Probe { ok: false, detail: String::from("страна: ipinfo без country") }),
            },
            Err(e) => (None, Probe { ok: false, detail: format!("страна: ipinfo не парсится: {}", e) }),
        },
        Err(e) => (None, Probe { ok: false, detail: format!("страна: {}", reqwest_err_short(&e)) }),
    }
}

/// Скорость: 10 МБ с cloudflare __down; чтение по чанкам с бюджетом —
/// медленный канал (psiphon) даёт честную скорость по частичному скачиванию.
fn probe_speed(port: u16) -> Probe {
    let client = match proxied_client(port, Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => return Probe { ok: false, detail: format!("скорость: {}", e) },
    };
    let url = format!("https://speed.cloudflare.com/__down?bytes={}", SPEED_BYTES);
    let mut resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => return Probe { ok: false, detail: format!("скорость: {}", reqwest_err_short(&e)) },
    };
    if !resp.status().is_success() {
        return Probe { ok: false, detail: format!("скорость: HTTP {}", resp.status()) };
    }
    let t0 = Instant::now();
    let mut total = 0usize;
    let mut err = String::new();
    // blocking::Response: impl Read — читаем по чанкам с бюджетом времени
    // (медленный psiphon даёт честную скорость по частичному скачиванию).
    let mut buf = [0u8; 16384];
    while t0.elapsed() < SPEED_BUDGET {
        match resp.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => {
                err = format!("{}", e);
                break;
            }
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    if total == 0 {
        return Probe {
            ok: false,
            detail: format!("скорость: 0 байт за {:.1}с{}", secs, if err.is_empty() { String::new() } else { format!(" ({})", err) }),
        };
    }
    let mbps = total as f64 / 1e6 / secs.max(0.001);
    Probe {
        ok: mbps > 0.05,
        detail: format!("{:.1} МБ/с ({} КБ за {:.1}с)", mbps, total / 1024, secs),
    }
}

/// Итог по каналу из реальных проб: РАБОТАЕТ / ЧАСТИЧНО (что именно) / МЁРТВ.
fn verdict(y: &Probe, m: &Probe, g: &Probe, cc: &Option<String>) -> (&'static str, String) {
    if !y.ok && !m.ok && !g.ok {
        return ("dead", String::from("ни одна проба не прошла"));
    }
    let mut partial = Vec::new();
    if !y.ok {
        partial.push(String::from("ютуб не отвечает"));
    }
    if !m.ok {
        partial.push(String::from("медиа-домен недоступен"));
    }
    if !g.ok {
        partial.push(String::from("гео-обход не работает"));
    }
    if cc.as_deref() == Some("RU") {
        partial.push(String::from("выход в РФ — гео-обхода нет"));
    }
    if partial.is_empty() {
        ("ok", String::from("все пробы прошли"))
    } else {
        ("partial", partial.join("; "))
    }
}

fn status_mark(status: &str) -> &'static str {
    match status {
        "ok" => "✅ РАБОТАЕТ",
        "partial" => "⚠ ЧАСТИЧНО",
        _ => "❌ МЁРТВ",
    }
}

/// Прогрев туннеля: поллим youtube generate_204 до первого отклика (холодный
/// WG/AWG-handshake греется 10-25с — дольше таймаута проб). Вердикт считается
/// по реальным пробам ниже — прогрев только даёт им прогретый канал; не ожил
/// за бюджет — пробы упадут ещё раз и покажут честную причину (§7).
fn warmup_channel(port: u16) -> Probe {
    let t0 = Instant::now();
    let mut last = Probe { ok: false, detail: String::from("бюджет не стартовал") };
    while t0.elapsed() < WARMUP_BUDGET {
        // Локальный порт стенда умер (тестовый mihomo убит/выпал) — греть
        // нечего: 30с мгновенных отказов os error 10061 не про канал, а про
        // стенд. Возвращаем честную причину сразу, не жжём бюджет.
        if !proxy_core::port_alive(port) {
            return Probe {
                ok: false,
                detail: format!("порт {} закрылся после старта — тестовый mihomo умер", port),
            };
        }
        last = probe_status(port, "http://www.youtube.com/generate_204", |s| s == 204, "прогрев");
        if last.ok {
            return Probe {
                ok: true,
                detail: format!("туннель готов за {:.1}с", t0.elapsed().as_secs_f64()),
            };
        }
        std::thread::sleep(Duration::from_millis(1200));
    }
    last
}

/// Живой тест одного канала. Активный — на его боевом порту (второй mihomo
/// не нужен), остальные — тестовый стенд (mihomo 7920 + aether 10828 для
/// psiphon). Тестовые процессы гасятся KillOnDrop'ом при любом выходе.
pub fn test_channel(app: &AppHandle, id: &str) -> Result<Value, String> {
    let t0 = Instant::now();
    let reg = proxy_core::paid_profiles_list();
    let name = reg["profiles"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|p| p["file"].as_str() == Some(id))
                .and_then(|p| p["name"].as_str())
        })
        .unwrap_or(id)
        .to_string();

    // «Активный» = включён ПРЯМО СЕЙЧАС (живой CHANNEL.mode), а не «последний
    // выбранный» из persisted-реестра: после рестарта приложения движок не
    // поднят, реестр всё ещё помечал канал активным — тест шёл на боевой порт
    // и ложно отдавал «МЁРТВ» (инцидент 22.11.26). Неактивный канал тестируется
    // на стенде, как все остальные.
    let active = proxy_core::channel_mode() == id;
    let port = if active { proxy_core::PROXY_PORT } else { TEST_MIXED_PORT };
    emit_log(app, format!("[Тест каналов] «{}»: старт{}...", name,
        if active { " (активный, боевой порт)" } else { " (тестовый стенд)" }));

    let mut aether_child: Option<crate::win_job::TreeChild> = None;
    // Тестовый mihomo должен жить ВСЮ test_channel (до конца функции). До
    // 21.11.26 `child` был локальной переменной if-блока ниже: блок кончался
    // раньше проб, KillOnDrop убивал процесс, и все пробы ловили os error
    // 10061 (порт закрылся) → ложные «МЁРТВ» на живых каналах (инцидент 21.11.26).
    let mut child: Option<KillOnDrop> = None;
    if !active {
        let combat_path = combat_config_path(id)?;
        let combat_text = match &combat_path {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| format!("не прочитать {}: {}", p.display(), e))?,
            None => {
                // Платный: исходник юзера в paid_profiles/ (личное, в AppData).
                let src = proxy_core::proxy_dir().join("paid_profiles").join(id);
                std::fs::read_to_string(&src)
                    .map_err(|e| format!("не прочитать {}: {}", src.display(), e))?
            }
        };
        let cfg = write_test_config(id, &combat_text)?;
        let mut c = spawn_test_mihomo(&cfg)?;
        wait_port(port, &mut c, PORT_WAIT)?;
        // Psiphon-стенд: aether (upstream = тестовый WARP-listener mihomo).
        if id == "__psiphon__" {
            let cwd = config::get_app_dir().join("psiphon_test");
            let aether_proc = crate::psiphon::spawn_aether(
                &format!("http://127.0.0.1:{}", TEST_LISTENER_PORT),
                TEST_AETHER_SOCKS_PORT,
                &cwd,
                &cwd.join("aether.log"),
            )?;
            aether_child = Some(aether_proc);
            crate::psiphon::wait_socks(TEST_AETHER_SOCKS_PORT, AETHER_WAIT)
                .map_err(|e| format!("psiphon-стенд не поднялся при тесте: {}", e))?;
        }
        // Владение mihomo переносим в конце блока (после всех `?`-выходов
        // выше): при ошибке подъёма стенда `c` честно гасится здесь, а при
        // успехе живёт до конца test_channel — пробы идут по живому порту.
        child = Some(c);
    } else if !proxy_core::port_alive(port) {
        // Честный статус, не «МЁРТВ»: канал включён в приложении, но движок
        // не отвечает — канал не тестировался вообще. Раньше этот ранний
        // выход не логировался (в dpi_gui.log не было ни строчки) и вёлся
        // в итог как мёртвый канал — юзер читал «платная не пашет».
        emit_log(app, format!(
            "[Тест каналов] «{}»: ⚪ НЕ ЗАПУЩЕН — канал включён, но боевой mihomo не отвечает (упал? выключили извне?)",
            name
        ));
        return Ok(json!({
            "id": id, "name": name, "status": "not_running", "active": true, "port": port,
            "note": "боевой mihomo не отвечает — выключи и включи канал заново, потом перетестируй",
            "elapsed": 0
        }));
    }

    let w = warmup_channel(port);
    emit_log(app, format!("[Тест каналов] «{}»: прогрев — {}", name, w.detail));
    let y = probe_youtube(port);
    let m = probe_media(port);
    let g = probe_geo(port);
    let (cc, _cc_probe) = probe_country(port);
    let s = probe_speed(port);
    let (status, note) = verdict(&y, &m, &g, &cc);

    emit_log(app, format!(
        "[Тест каналов] «{}»: {} — {}{}. ютуб: {}; гео: {}; скорость: {}.",
        name,
        status_mark(status),
        note,
        cc.as_deref().map(|c| format!(", выход {}", c)).unwrap_or_default(),
        y.detail, g.detail, s.detail
    ));

    Ok(json!({
        "id": id, "name": name, "status": status, "note": note,
        "active": active, "port": port, "country": cc,
        "youtube": { "ok": y.ok, "detail": y.detail },
        "media": { "ok": m.ok, "detail": m.detail },
        "geo": { "ok": g.ok, "detail": g.detail },
        "speed": { "ok": s.ok, "detail": s.detail },
        "elapsed": t0.elapsed().as_secs()
    }))
}

/// Тест всех каналов реестра по порядку, с прогресс-событиями в окно.
/// Ошибка одного канала — строка-ошибка в его результате, тест остальных
/// продолжается (юзер должен увидеть весь список, а не первый упавший).
pub fn channel_test_all(app: &AppHandle) -> Result<Vec<Value>, String> {
    let reg = proxy_core::paid_profiles_list();
    let ids: Vec<String> = reg["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p["file"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut results = Vec::new();
    for id in &ids {
        let _ = app.emit("channel-test-progress", json!({ "id": id, "state": "running" }));
        let r = match test_channel(app, id) {
            Ok(v) => v,
            Err(e) => {
                emit_log(app, format!("[Тест каналов] {}: ошибка — {}", id, e));
                json!({ "id": id, "status": "dead", "error": e })
            }
        };
        let _ = app.emit("channel-test-progress", json!({ "id": id, "state": "done", "result": r }));
        results.push(r);
    }
    Ok(results)
}

// ---------- Тесты чистой логики (порты/вердикты; живые пробы — только в UI) ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn p(ok: bool) -> Probe {
        Probe { ok, detail: String::from(if ok { "HTTP 204 (0.1с)" } else { "нет соединения через канал" }) }
    }

    #[test]
    fn test_config_replaces_combat_ports_with_test_ports() {
        let text = "mixed-port: 7897\nexternal-controller: 127.0.0.1:9097\nproxy-port: 7897\n";
        let out = test_config_text("__wg__", text).unwrap();
        assert!(out.contains("7920"));
        assert!(out.contains("9120"));
        assert!(!out.contains("7897"));
        assert!(!out.contains("9097"));
    }

    #[test]
    fn test_config_psiphon_also_moves_aether_socks_and_listener() {
        let text = "mixed-port: 7897\nlistener: 127.0.0.1:7901\nsocks: 10818\n";
        let out = test_config_text("__psiphon__", text).unwrap();
        assert!(out.contains("10828"));
        assert!(out.contains("7921"));
        assert!(!out.contains("10818"));
        assert!(!out.contains("7901"));
    }

    #[test]
    fn combat_config_path_rejects_traversal_ids() {
        assert!(combat_config_path("..\\evil.yaml").is_err());
        assert!(combat_config_path("a/b.yaml").is_err());
    }

    #[test]
    fn echo_rules_prepended_with_tunnel_group() {
        let yaml = "mixed-port: 7897\nproxy-groups:\n  - name: WARP\n    type: select\nrules:\n  - DOMAIN-SUFFIX,youtube.com,WARP\n  - MATCH,DIRECT\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(out.contains("DOMAIN,ipwho.is,WARP"));
        assert!(out.contains("DOMAIN,ipinfo.io,WARP"));
        assert!(out.contains("DOMAIN-SUFFIX,cloudflare.com,WARP"));
        let idx_echo = out.find("DOMAIN,ipwho.is,WARP").unwrap();
        let idx_yt = out.find("DOMAIN-SUFFIX,youtube.com,WARP").unwrap();
        assert!(idx_echo < idx_yt, "эхо-правила должны стоять раньше профильных");
    }

    #[test]
    fn echo_rules_skipped_when_only_direct() {
        let yaml = "rules:\n  - MATCH,DIRECT\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(!out.contains("ipwho.is"), "туннельной группы нет — препендить нечего");
    }

    #[test]
    fn echo_rules_target_is_not_no_resolve_tail() {
        // IP-CIDR,...,ГРУППА,no-resolve: target на 3-й позиции, не хвост.
        let yaml = "proxy-groups:\n  - name: WARP\nrules:\n  - IP-CIDR,1.1.1.1/32,WARP,no-resolve\n  - MATCH,DIRECT\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(out.contains("DOMAIN,ipwho.is,WARP"));
        assert!(!out.contains("DOMAIN,ipwho.is,no-resolve"));
    }

    #[test]
    fn echo_rules_skip_logical_rules_garbage_targets() {
        // AND/NOT с вложенными скобками не должны давать мусорный target
        // (инцидент 21.11.26: «UDP)» → mihomo падал на старте тестового стенда).
        let yaml = "proxy-groups:\n  - name: PROXY\nrules:\n  - AND,((NETWORK,UDP)),REJECT\n  - DOMAIN-SUFFIX,youtube.com,PROXY\n  - MATCH,DIRECT\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(out.contains("DOMAIN,ipwho.is,PROXY"));
        // Мусорный target недопустим в ИНЖЕКТИРОВАННЫХ правилах (в исходном
        // AND-правиле «UDP))» остаётся — это не инжекция).
        assert!(!out.contains("DOMAIN,ipwho.is,UDP)"));
        assert!(!out.contains("cloudflare.com,UDP)"));
    }

    #[test]
    fn echo_rules_match_group_wins_over_first_rule() {
        // Платный профиль: MATCH → главный выход (PROXY); первое правило —
        // вспомогательная группа (SPECIAL) с другим выходом — эхо туда
        // не должно уйти (ложная страна в прогоне 21.11.26).
        let yaml = "proxy-groups:\n  - name: SPECIAL\n  - name: PROXY\nrules:\n  - DOMAIN-SUFFIX,example.com,SPECIAL\n  - MATCH,PROXY\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(out.contains("DOMAIN,ipwho.is,PROXY"));
        assert!(!out.contains("DOMAIN,ipwho.is,SPECIAL"));
    }

    #[test]
    fn echo_rules_generated_profile_uses_first_tunnel_rule() {
        // Сгенерированный профиль: MATCH,DIRECT — группа из первого правила.
        let yaml = "proxy-groups:\n  - name: PROTON-WG\nrules:\n  - DOMAIN-SUFFIX,z-cdn.chatglm.cn,PROTON-WG\n  - MATCH,DIRECT\n";
        let out = prepend_echo_rules(yaml).unwrap();
        assert!(out.contains("DOMAIN,ipwho.is,PROTON-WG"));
    }

    #[test]
    fn verdict_dead_when_all_probes_fail() {
        let (status, _) = verdict(&p(false), &p(false), &p(false), &None);
        assert_eq!(status, "dead");
    }

    #[test]
    fn verdict_ru_exit_is_partial_even_with_live_probes() {
        // Канал «жив», но выход в РФ: гео-обхода нет — ЧАСТИЧНО, не РАБОТАЕТ.
        let (status, note) = verdict(&p(true), &p(true), &p(true), &Some("RU".into()));
        assert_eq!(status, "partial");
        assert!(note.contains("выход в РФ"));
    }

    #[test]
    fn verdict_ok_when_everything_passed_and_not_ru() {
        let (status, _) = verdict(&p(true), &p(true), &p(true), &Some("NL".into()));
        assert_eq!(status, "ok");
    }

    #[test]
    fn verdict_partial_names_the_dead_part() {
        let (status, note) = verdict(&p(true), &p(false), &p(true), &Some("NL".into()));
        assert_eq!(status, "partial");
        assert!(note.contains("медиа-домен"));
    }
}

// ---------- Живые тесты стенда (#[ignore]: реальная сеть, запуск руками) ----------
//
// Претензия юзера 21.11.26: правки test_channel отдавались на живой прогон
// юзеру («ты тестировал свой говнокод?»). Эти тесты гоняют РЕАЛЬНЫЙ путь
// test_channel — combat_config_path → write_test_config → spawn_test_mihomo →
// wait_port → прогрев → пробы — без UI. Запуск из корня src-tauri:
//   cargo test --release live -- --ignored --test-threads=1
//
// Что считается падением:
// - стенд не поднялся (wait_port / spawn) — код подъёма сломан;
// - «порт 7920 закрылся после старта» в прогреве — регрессия скоупа child
//   (KillOnDrop убил тестовый mihomo до проб; инцидент 21.11.26);
// - платный / активный WG мертвы (ютуб не 204) — каналы, чья живость
//   подтверждена ранее, обязаны проходить: иначе честный красный.
// Нестабильные каналы (§9: warp/awg/pawg) здоровье не ассертим — только
// подъём стенда и честные детали в вывод.

#[cfg(test)]
mod live {
    use super::*;

    struct Stand {
        warmup: Probe,
        youtube: Probe,
        media: Probe,
        geo: Probe,
        country: Option<String>,
        speed: Probe,
    }

    /// Реальный путь test_channel для одного канала: стенд → прогрев → пробы.
    fn run_stand(id: &str) -> Result<Stand, String> {
        let combat_path = combat_config_path(id)?;
        let combat_text = match &combat_path {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| format!("не прочитать {}: {}", p.display(), e))?,
            None => {
                let src = proxy_core::proxy_dir().join("paid_profiles").join(id);
                std::fs::read_to_string(&src).map_err(|e| {
                    format!("не прочитать {}: {} (нет платного профиля в AppData)", src.display(), e)
                })?
            }
        };
        let cfg = write_test_config(id, &combat_text)?;
        // Паттерн ИСПРАВЛЕННОГО test_channel: child живёт до конца функции
        // (после проб), а не до конца if-блока.
        let mut child = spawn_test_mihomo(&cfg)?;
        wait_port(TEST_MIXED_PORT, &mut child, PORT_WAIT)?;
        let warmup = warmup_channel(TEST_MIXED_PORT);
        let youtube = probe_youtube(TEST_MIXED_PORT);
        let media = probe_media(TEST_MIXED_PORT);
        let geo = probe_geo(TEST_MIXED_PORT);
        let (country, _cp) = probe_country(TEST_MIXED_PORT);
        let speed = probe_speed(TEST_MIXED_PORT);
        eprintln!(
            "[live] «{}»: прогрев={}; ютуб={}; медиа={}; гео={}; страна={:?}; скорость={}",
            id, warmup.detail, youtube.detail, media.detail, geo.detail, country, speed.detail
        );
        Ok(Stand { warmup, youtube, media, geo, country, speed })
    }

    fn assert_stand_alive(s: &Stand) {
        assert!(
            !s.warmup.detail.contains("закрылся после старта"),
            "РЕГРЕССИЯ СКОУПА child: тестовый mihomo умер до проб ({})",
            s.warmup.detail
        );
    }

    #[test]
    #[ignore]
    fn live_stand_paid_channel_probes_pass() {
        let s = run_stand("paid_source.yaml").expect("стенд платного канала");
        assert_stand_alive(&s);
        assert!(s.youtube.ok, "платный канал: ютуб не отвечает ({})", s.youtube.detail);
        assert!(s.geo.ok, "платный канал: гео не отвечает ({})", s.geo.detail);
    }

    #[test]
    #[ignore]
    fn live_stand_wg_channel_probes_pass() {
        let s = run_stand("__wg__").expect("стенд WG-канала");
        assert_stand_alive(&s);
        assert!(s.youtube.ok, "WG-канал: ютуб не отвечает ({})", s.youtube.detail);
        assert!(s.geo.ok, "WG-канал: гео не отвечает ({})", s.geo.detail);
    }

    #[test]
    #[ignore]
    fn live_stand_special_channels_stay_up_through_probes() {
        // Нестабильные каналы (§9): их ЖИВОСТЬ не ассертим, но стенд обязан
        // пережить все пробы (регрессия скоупа child валит любой канал).
        for id in ["__warp__", "__awg__", "__pawg__"] {
            let s = run_stand(id).unwrap_or_else(|e| panic!("стенд {}: {}", id, e));
            assert_stand_alive(&s);
        }
    }

    /// Число процессов с данным именем (tasklist). Для дельта-проверок дерева:
    /// боевая psiphon-сессия во время теста не должна давать ложный красный.
    fn count_proc(image: &str) -> usize {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", image)])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .expect("tasklist");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains(image))
            .count()
    }

    #[test]
    #[ignore]
    fn live_stand_psiphon_aether_from_runtime_and_tree_killed() {
        // Инцидент 22.11.26: aether-дети (psiphon-tunnel-core) переживали
        // гашение канала (kill() родителя на Windows не гасит дерево),
        // исполнялись из release/bin/pt/ и валили сборку релиза os error 32.
        // Проверяем оба фикса сразу: (1) aether стартует из AppData/runtime
        // (runtime_aether — бандл/папка сборки не лочится), (2) после гашения
        // стенда дерево мёртво (Job Object kill-on-close). Боевая psiphon-сессия
        // не мешает: считаем ДЕЛЬТУ (до спавна/после гашения), а не абсолютный
        // ноль — её psiphon-tunnel-core в проверку не попадает (автоматизация
        // замера гоняет тест без присмотра, гасить ради неё канал нельзя).
        let p = combat_config_path("__psiphon__")
            .expect("путь psiphon-профиля")
            .expect("psiphon-профиль есть");
        let combat_text = std::fs::read_to_string(&p).expect("прочитать профиль");
        let cfg = write_test_config("__psiphon__", &combat_text).expect("тест-конфиг");
        let mut child = spawn_test_mihomo(&cfg).expect("тестовый mihomo");
        wait_port(TEST_MIXED_PORT, &mut child, PORT_WAIT).expect("порт 7920");
        let before = count_proc("psiphon-tunnel-core.exe");
        let cwd = config::get_app_dir().join("psiphon_test");
        let aether = crate::psiphon::spawn_aether(
            &format!("http://127.0.0.1:{}", TEST_LISTENER_PORT),
            TEST_AETHER_SOCKS_PORT,
            &cwd,
            &cwd.join("aether.log"),
        )
        .expect("aether из runtime-копии не поднялся");
        crate::psiphon::wait_socks(TEST_AETHER_SOCKS_PORT, AETHER_WAIT)
            .expect("socks 10828 не поднялся — aether из runtime-копии не нашёл своё pt/-окружение?");
        assert!(process::runtime_dir().join("aether.exe").exists(), "runtime-копия aether не создана");
        let warm = warmup_channel(TEST_MIXED_PORT);
        eprintln!("[live] psiphon runtime: прогрев={}", warm.detail);
        // Гасим стенд: TreeChild::drop = kill_tree → НАШИ дети умирают (дельта).
        drop(aether);
        let dl = Instant::now() + Duration::from_secs(5);
        loop {
            let now = count_proc("psiphon-tunnel-core.exe");
            if now <= before {
                break;
            }
            assert!(
                Instant::now() < dl,
                "сироты psiphon-tunnel-core пережили kill_tree (до спавна {}, осталось {})",
                before, now
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        drop(child);
    }

    #[test]
    #[ignore]
    fn live_stand_psiphon_channel_probes_pass() {
        // §9-замер psiphon (добавлен 23.11 после вопроса юзера «а че сифона
        // нет в замере»): полный прогон проб через стенд — aether из runtime-
        // копий, upstream = тестовый WARP-masque listener (та же цепочка, что
        // у test_channel/боевого канала). ЖИВОСТЬ не ассертим: psiphon
        // наследует живость masque (§9) — мёртвый masque честно даёт фейлы
        // проб в [live], это данные вердикта, а не регрессия стенда.
        let p = combat_config_path("__psiphon__")
            .expect("путь psiphon-профиля")
            .expect("psiphon-профиль есть");
        let combat_text = std::fs::read_to_string(&p).expect("прочитать профиль");
        let cfg = write_test_config("__psiphon__", &combat_text).expect("тест-конфиг");
        let mut child = spawn_test_mihomo(&cfg).expect("тестовый mihomo");
        wait_port(TEST_MIXED_PORT, &mut child, PORT_WAIT).expect("порт 7920");
        let cwd = config::get_app_dir().join("psiphon_test");
        let aether = crate::psiphon::spawn_aether(
            &format!("http://127.0.0.1:{}", TEST_LISTENER_PORT),
            TEST_AETHER_SOCKS_PORT,
            &cwd,
            &cwd.join("aether.log"),
        )
        .expect("aether из runtime-копии не поднялся");
        crate::psiphon::wait_socks(TEST_AETHER_SOCKS_PORT, AETHER_WAIT)
            .expect("socks 10828 не поднялся");
        let warmup = warmup_channel(TEST_MIXED_PORT);
        let youtube = probe_youtube(TEST_MIXED_PORT);
        let media = probe_media(TEST_MIXED_PORT);
        let geo = probe_geo(TEST_MIXED_PORT);
        let (country, _cp) = probe_country(TEST_MIXED_PORT);
        let speed = probe_speed(TEST_MIXED_PORT);
        eprintln!(
            "[live] «__psiphon__»: прогрев={}; ютуб={}; медиа={}; гео={}; страна={:?}; скорость={}",
            warmup.detail, youtube.detail, media.detail, geo.detail, country, speed.detail
        );
        assert!(
            !warmup.detail.contains("закрылся после старта"),
            "РЕГРЕССИЯ СКОУПА child: тестовый mihomo умер до проб ({})",
            warmup.detail
        );
        drop(aether); // TreeChild::drop = kill_tree — сирот не остаётся
        drop(child);
    }
}
