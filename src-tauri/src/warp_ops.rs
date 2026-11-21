// warp_ops.rs — оркестрация WARP-канала v2 «MASQUE H2» (метод спеца
// 20.11.26): 2-шаговая регистрация учётки (POST curve25519-плейсхолдер →
// PATCH secp256r1/masque, контракт usque, live-верифицирован), сброс, и
// health-гард туннеля (trace через 7897, warp=on + loc; три неудачи →
// ротация ноды-такси TR, ни одной живой → перезапуск канала). Гейты
// регистрации (ревью п.2: второй winws поверх живого ЗАПРЕЩЁН — канал →
// через 7897, обход → напрямую (api.cloudflareclient.com в hostlist), оба
// выключены → временный однодоменный winws с RAII-очисткой). Чистая логика —
// в warp.rs. wgcf-импорт убран: Curve25519 с MASQUE несовместимы.

use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;
use tauri::{AppHandle, Emitter};

const CREATE_NO_WINDOW: u32 = 0x08000000;
/// Домен регистрации — тот же, что в hostlist-генерации (defaults/list-google.txt).
const REG_DOMAIN: &str = "api.cloudflareclient.com";
/// Контракт usque (эталон MASQUE-регистрации; live 20.11.26): версия API +
/// Android-заголовки. wgcf-версия v0a5641 выдаёт Curve25519 — для masque не годится.
const API_REG_URL: &str = "https://api.cloudflareclient.com/v0a4471/reg";
const UA: &str = "WARP for Android";
const CF_CLIENT_VERSION: &str = "a-6.35-4471";
/// Trace-проба health-гарда (через наш порт — правило www.cloudflare.com→WARP).
const TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

fn emit_log(app: &AppHandle, msg: String) {
    // И в UI-панель, и в dpi_gui.log (плагин-коллектор через log::info —
    // так же, как app_log в ip_probe): инцидент 02:20 20.11 — backend-ветки
    // регистрации не попадали в файл, диагностировать пришлось по косвенным.
    crate::ip_probe::app_log(app, msg.clone());
    let _ = app.emit("log", msg);
}

// ---------- Временный однодоменный winws (RAII) ----------

/// Дизсинк-рецепт юзера из активного профиля — но ВЗЯТЫЙ ИЗ ОДНОЙ СЕКЦИИ.
/// Профили многосекционные (--new): у каждой секции свои фильтры и свои
/// дизсинк-токены. Слепить все --dpi-desync* подряд — каша из шести
/// --dpi-desync= с разными фейками/seqovl: так регистрация 02:20 20.11 ушла
/// в таймаут (инцидент Этапа B). Берём секцию TCP:443 общего списка —
/// рецепт «General», доказанный live-тестом 23:30 19.11 (fake,multisplit +
/// tls_clienthello_max_ru пробил api.cloudflareclient.com за 0.35с).
fn temp_winws_args() -> Result<Vec<String>, String> {
    let cfg = crate::config::read_config()
        .map_err(|e| format!("config.json не прочитан: {}", e))?;
    let selected = cfg
        .get("selected_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if selected.is_empty() {
        return Err(String::from(
            "Нет активного профиля обхода — нечем пробить ТСПУ для регистрации. \
Включи канал или обход.",
        ));
    }
    let profiles = crate::config::read_profiles()
        .map_err(|e| format!("profiles.json не прочитан: {}", e))?;
    let args_tpl = profiles
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(selected.as_str()))
        .and_then(|p| p.get("args").and_then(|v| v.as_str()))
        .ok_or_else(|| format!("Профиль «{}» не найден в profiles.json", selected))?;
    let bin_dir = crate::process::get_bin_dir()?;
    let lists_dir = crate::config::get_app_dir()
        .join("lists")
        .to_string_lossy()
        .to_string();
    let tokens = shlex::split(args_tpl)
        .ok_or("Ошибка парсинга аргументов профиля (кавычки)?")?;
    let desync = extract_desync_from_profile_tokens(
        &tokens,
        &bin_dir.to_string_lossy(),
        &lists_dir,
    )?;
    let mut out = vec![
        String::from("--wf-tcp=443"),
        String::from("--filter-tcp=443"),
        format!("--hostlist-domains={}", REG_DOMAIN),
    ];
    out.extend(desync);
    Ok(out)
}

/// Чистая (тестируемая) часть сборки рецепта: из токенов профиля вырезаем
/// дизсинк-аргументы ОДНОЙ целевой секции. Приоритет: секция TCP:443 с
/// hostlist общего списка → любая секция TCP:443 → (односекционный профиль
/// без filter-tcp) все --dpi-desync* как есть. Многосекционный профиль без
/// TCP:443-секции — честная ошибка: слепленные секции дают нерабочую кашу.
fn extract_desync_from_profile_tokens(
    tokens: &[String],
    bin_dir: &str,
    lists_dir: &str,
) -> Result<Vec<String>, String> {
    let resolve = |t: &String| -> String {
        t.replace("{BIN_DIR}", bin_dir)
            .replace("{LISTS_DIR}", lists_dir)
            .replace("{EXCLUDE_DIR}", lists_dir)
    };
    let desync_of = |s: &[String]| -> Vec<String> {
        s.iter()
            .filter(|t| t.starts_with("--dpi-desync"))
            .cloned()
            .map(|t| resolve(&t))
            .collect()
    };
    // Секции winws: токены до/между --new. Фильтры и дизсинк секции
    // неразрывны — перенос токенов между секциями меняет смысл рецепта.
    let mut sections: Vec<Vec<String>> = vec![Vec::new()];
    for t in tokens {
        if t == "--new" {
            sections.push(Vec::new());
        } else if let Some(s) = sections.last_mut() {
            s.push(t.clone());
        }
    }
    let tcp_443 = |s: &[String]| -> bool {
        s.iter().any(|t| {
            t.starts_with("--filter-tcp=")
                && t.split('=')
                    .nth(1)
                    .map(|ports| ports.split(',').any(|p| p.trim() == "443"))
                    .unwrap_or(false)
        })
    };
    let target = sections
        .iter()
        .find(|s| tcp_443(s) && s.iter().any(|t| t.contains("list-general")))
        .or_else(|| sections.iter().find(|s| tcp_443(s)));
    match target {
        Some(s) => {
            let v = desync_of(s);
            if v.is_empty() {
                Err(String::from(
                    "В TCP:443-секции профиля нет дизсинк-аргументов --dpi-desync* — \
временному winws нечем пробивать ТСПУ",
                ))
            } else {
                Ok(v)
            }
        }
        None if sections.len() == 1 => {
            // Односекционный профиль: фильтры не важны, рецепт один на всё.
            let v = desync_of(&sections[0]);
            if v.is_empty() {
                Err(String::from(
                    "В профиле нет дизсинк-аргументов --dpi-desync* — \
временному winws нечем пробивать ТСПУ",
                ))
            } else {
                Ok(v)
            }
        }
        None => Err(String::from(
            "В профиле нет TCP:443-секции с дизсинком — временный winws нечем пробивать ТСПУ. \
Выбери профиль с пробивом 443.",
        )),
    }
}

/// Временный winws на время регистрации. Drop = гарантированная очистка
/// (taskkill + sc stop WinDivert* через stop_winws — урок os error 32, AGENTS §3).
/// Запуск допустим ТОЛЬКО при выключенном обходе (гейт в register_warp):
/// иначе получим «второй winws поверх живого» — запрещено ревью спеца п.2.
struct TempWinws {
    _active: bool,
}

impl TempWinws {
    fn start(app: &AppHandle) -> Result<TempWinws, String> {
        let args = temp_winws_args()?;
        let bin_dir = crate::process::get_bin_dir()?;
        let child = std::process::Command::new(bin_dir.join("winws.exe"))
            .args(&args)
            .current_dir(&bin_dir)
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("временный winws не запустился: {}", e))?;
        emit_log(
            app,
            format!(
                "[WARP] временный winws поднят (PID {}) — пробиваем {} на время регистрации",
                child.id(),
                REG_DOMAIN
            ),
        );
        // Драйвер WinDivert (установка службы) + инициализация winws: даём
        // осесть перед HTTP. 1.2с могло не хватить — первый ClientHello уходил
        // до того, как фильтр вставал (вклад в инцидент 02:20 20.11).
        std::thread::sleep(Duration::from_millis(3000));
        Ok(TempWinws { _active: true })
    }
}

impl Drop for TempWinws {
    fn drop(&mut self) {
        // Ошибка очистки не паникуем в Drop — stop_winws сам честно логирует
        // негрузящуюся службу; файл .sys освободится в штатном сценарии.
        let _ = crate::process::stop_winws();
        self._active = false;
    }
}

// ---------- Регистрация ----------

fn reg_client(proxy: bool) -> Result<reqwest::blocking::Client, String> {
    let mut b = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15));
    if proxy {
        b = b.proxy(
            reqwest::Proxy::all("http://127.0.0.1:7897")
                .map_err(|e| format!("прокси 7897 не задан: {}", e))?,
        );
    }
    b.build().map_err(|e| format!("HTTP-клиент не создан: {}", e))
}

/// Регистрация анонимной учётки MASQUE — 2 шага (контракт usque, live 20.11.26):
/// шаг 1 POST — одноразовый curve25519-плейсхолдер (сервер его не валидирует,
/// это форма-требование) → id + token; шаг 2 PATCH — публичный P-256-ключ
/// (SPKI DER) + tunnel_type masque → туннельный config (server из PATCH —
/// привязка к edge-кластеру, ip/ipv6 туннеля, peer_public_key PEM). Приватный
/// ключ никуда не уходит — только в AppData.
fn register_warp(app: &AppHandle) -> Result<serde_json::Value, String> {
    let (priv_b64, pub_b64) = crate::warp::gen_masque_keypair()?;
    let body = json!({
        "key": crate::warp::random_b64(32)?, // одноразовый WG-плейсхолдер POST
        "install_id": "",
        "fcm_token": "",
        "locale": "en_US",
        "model": "PC",
        "tos": crate::warp::iso_utc_now(),
        "serial_number": crate::warp::random_hex(8)?, // 16 hex (usque)
        "os_version": "",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
    })
    .to_string();

    let channel_active = crate::proxy_core::active_channel_id() != "off";
    let winws_running = crate::process::is_winws_running();
    // RAII живёт до конца функции — фильтр активен весь HTTP-разговор.
    let mut _temp: Option<TempWinws> = None;
    let client = if channel_active {
        emit_log(
            app,
            "[WARP] канал активен — регистрируюсь через 127.0.0.1:7897".into(),
        );
        reg_client(true)?
    } else {
        if !winws_running {
            _temp = Some(TempWinws::start(app)?);
        } else {
            emit_log(
                app,
                "[WARP] обход активен — регистрируюсь через него (домен в hostlist)".into(),
            );
        }
        reg_client(false)?
    };

    emit_log(app, format!("[WARP] POST {} …", API_REG_URL));
    let resp = client
        .post(API_REG_URL)
        .header("User-Agent", UA)
        .header("CF-Client-Version", CF_CLIENT_VERSION)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|e| format!("POST /reg не прошёл (ТСПУ/сеть): {}", e))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("ответ API не прочитан: {}", e))?;
    if !status.is_success() {
        return Err(format!(
            "POST вернул {}: {}",
            status,
            text.chars().take(300).collect::<String>()
        ));
    }
    let (device_id, token) = crate::warp::parse_reg_post(&text)?;

    // Шаг 2: PATCH /reg/{id} — masque-туннель на P-256. Авторизация Bearer
    // token'ом из POST; PATCH-ответ token НЕ возвращает и ключей не содержит.
    let patch_url = format!("{}/{}", API_REG_URL, device_id);
    emit_log(app, format!("[WARP] PATCH {} … (tunnel_type=masque)", patch_url));
    let resp = client
        .patch(patch_url)
        .header("User-Agent", UA)
        .header("CF-Client-Version", CF_CLIENT_VERSION)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(
            json!({
                "key": pub_b64,
                "key_type": "secp256r1",
                "tunnel_type": "masque",
            })
            .to_string(),
        )
        .send()
        .map_err(|e| format!("PATCH /reg не прошёл (ТСПУ/сеть): {}", e))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("ответ PATCH API не прочитан: {}", e))?;
    if !status.is_success() {
        return Err(format!(
            "PATCH вернул {}: {}",
            status,
            text.chars().take(300).collect::<String>()
        ));
    }
    let acct = crate::warp::parse_patch_response(&text, &priv_b64, &token)?;
    crate::warp::save_account(&acct)?;
    crate::proxy_core::warp_channel_sync(app)?;
    let out = crate::warp::generate_warp_config()?;
    let id_short: String = acct.device_id.chars().take(8).collect();
    emit_log(
        app,
        format!(
            "[WARP] учётка MASQUE зарегистрирована (device {}…), endpoint {}:{} (TCP:443, h2); профиль собран: {}",
            id_short,
            acct.server,
            crate::warp::MASQUE_PORT,
            out.display()
        ),
    );
    Ok(crate::warp::warp_status_json())
}

// ---------- Диспетчер команд ----------

/// warp_setup(action): "register" | "reset" ("import" оставлен для
/// совместимости invoke-контракта, честно отказывает — wgcf несовместим с
/// MASQUE). Возвращает статус учётки для фронта (без приватных полей).
pub fn warp_setup(
    app: &AppHandle,
    action: &str,
    _path: Option<&str>, // wgcf-импорт убран — путь больше не нужен
) -> Result<serde_json::Value, String> {
    match action {
        "register" => register_warp(app),
        // wgcf-импорт убран (v2 MASQUE): ключи Curve25519 из .conf с MASQUE-
        // туннелем несовместимы. Контракт invoke сохранён, но честно отказывает —
        // учётка создаётся только регистрацией.
        "import" => Err(String::from(
            "Импорт wgcf .conf больше не поддерживается: канал v2 работает через MASQUE \
(ECDSA P-256), а ключи из .conf — Curve25519. Нажми «Зарегистрировать» — учётка \
создаётся анонимно в 1 клик.",
        )),
        "reset" => {
            if crate::proxy_core::active_channel_id() == crate::proxy_core::WARP_CHANNEL_ID {
                return Err(String::from(
                    "WARP-канал сейчас активен — сначала выключи его, потом сбрасывай учётку",
                ));
            }
            crate::warp::remove_account()?;
            // Профиль без учётки бессмысленен: удалить (отсутствие — не ошибка).
            let _ = std::fs::remove_file(crate::warp::warp_profile_path());
            crate::proxy_core::warp_channel_remove(app)?;
            emit_log(app, "[WARP] учётка и профиль удалены.".into());
            Ok(crate::warp::warp_status_json())
        }
        _ => Err(format!("warp_setup: неизвестное действие «{}»", action)),
    }
}

// ---------- Health-гард туннеля ----------

static GUARD_RESTARTING: AtomicBool = AtomicBool::new(false);

/// Trace-проба ЧЕРЕЗ наш порт (ревью спеца п.3): правило
/// www.cloudflare.com→WARP гоняет запрос через туннель; warp=on отличает
/// живой туннель от ложного «сеть работает» (запрос ушёл DIRECT'ом).
fn trace_probe() -> Result<(String, String), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .proxy(
            reqwest::Proxy::all("http://127.0.0.1:7897")
                .map_err(|e| format!("прокси 7897 не задан: {}", e))?,
        )
        .build()
        .map_err(|e| format!("HTTP-клиент не создан: {}", e))?;
    let text = client
        .get(TRACE_URL)
        .send()
        .map_err(|e| format!("trace через 7897: {}", e))?
        .text()
        .map_err(|e| format!("trace-ответ не прочитан: {}", e))?;
    crate::warp::parse_trace(&text)
}

/// Ротация ноды-такси TR (смоук 20.11.26, handoff): Cloudflare-Worker ноды
/// режут исходящие сокеты (Error 1101), медленные VPS не поднимают MASQUE за
/// 8с — health-check провайдеров отсеивает их не мгновенно, а рестарт ядра
/// ноду не меняет. Перебираем живые ноды обоих провайдеров: PUT /proxies/TR →
/// delay-проба WARP-аутбаунда (CONNECT-IP реально поднимается — нода годится).
/// Первая удачная остаётся текущей TR; ни одной живой — Ok(None).
fn rotate_tr_node() -> Result<Option<String>, String> {
    let api = format!("http://127.0.0.1:{}", crate::proxy_core::API_PORT);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP-клиент не создан: {}", e))?;
    let mut candidates: Vec<String> = Vec::new();
    for prov in ["igareck-vless", "igareck-ss"] {
        let url = format!("{}/providers/proxies/{}", api, prov);
        let text = client
            .get(&url)
            .send()
            .and_then(|r| r.text())
            .map_err(|e| format!("провайдер {} не прочитан: {}", prov, e))?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("ответ провайдера {} не JSON: {}", prov, e))?;
        if let Some(arr) = v.get("proxies").and_then(|p| p.as_array()) {
            for p in arr {
                let alive = p.get("alive").and_then(|a| a.as_bool()).unwrap_or(true);
                if alive {
                    if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                        candidates.push(name.to_string());
                    }
                }
            }
        }
    }
    for name in candidates.into_iter().take(15) {
        // PUT TR мгновенный; delay-проба сама ждёт до 8с (холодный CONNECT-IP).
        let put = client
            .put(format!("{}/proxies/TR", api))
            .header("Content-Type", "application/json")
            .body(json!({ "name": name.clone() }).to_string())
            .send();
        if let Err(e) = put {
            return Err(format!("PUT /proxies/TR: {}", e));
        }
        let resp = client
            .get(format!("{}/proxies/WARP/delay", api))
            .query(&[("url", TRACE_URL), ("timeout", "8000")])
            .send();
        if let Ok(r) = resp {
            if r.status().is_success() {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

/// Каналы под общим trace-гардом (первое правило rules гоняет пробу через
/// туннель канала). Критерий здоровья по каналу:
///  - WARP/AWG: warp=on (оба — WARP-туннели: masque и AWG поверх тех же ключей);
///  - PAWG/PSIPHON: выход НЕ RU (Proton=NL / Psiphon=DE — warp-метки на чужих
///    выходах нет; честный критерий = гео сменилось).
const GUARD_CHANNELS: [&str; 4] = [
    crate::proxy_core::WARP_CHANNEL_ID,
    crate::proxy_core::AWG_CHANNEL_ID,
    crate::proxy_core::PAWG_CHANNEL_ID,
    crate::proxy_core::PSIPHON_CHANNEL_ID,
];

fn guard_log_tag(ch: &str) -> &'static str {
    match ch {
        crate::proxy_core::AWG_CHANNEL_ID => "[AWG]",
        crate::proxy_core::PAWG_CHANNEL_ID => "[PAWG]",
        crate::proxy_core::PSIPHON_CHANNEL_ID => "[PSIPHON]",
        _ => "[WARP]",
    }
}

/// Канал жив? Критерий по типу канала (см. GUARD_CHANNELS); Err = причина.
fn probe_healthy(ch: &str, warp: &str, loc: &str) -> Result<(String, String), String> {
    match ch {
        crate::proxy_core::WARP_CHANNEL_ID | crate::proxy_core::AWG_CHANNEL_ID => {
            if warp == "on" {
                Ok((warp.to_string(), loc.to_string()))
            } else {
                Err(format!("проба ушла мимо туннеля (warp={}, loc={})", warp, loc))
            }
        }
        // PAWG/PSIPHON: warp-метки на чужом выходе нет — критерий «гео сменилось».
        _ => {
            if !loc.is_empty() && loc != "RU" {
                Ok((warp.to_string(), loc.to_string()))
            } else {
                Err(format!("выход не сменился (warp={}, loc={})", warp, loc))
            }
        }
    }
}

/// Старт health-гарда канала (вызывается channel_set("__warp__"/"__awg__"/
/// "__pawg__"/"__psiphon__") после успешного старта mihomo; критерий — см.
/// probe_healthy). reserve-гард (204-проба) здесь НЕ запускается: его
/// generate_204 уходит DIRECT и всегда «зелёный» при мёртвом туннеле.
pub fn start_guard(app: AppHandle) {
    crate::warp::WARP_GUARD_ON.store(true, Ordering::SeqCst);
    crate::warp::guard_reset_fails();
    std::thread::spawn(move || guard_loop(app));
}

fn guard_loop(app: AppHandle) {
    loop {
        if !crate::warp::WARP_GUARD_ON.load(Ordering::SeqCst) {
            break;
        }
        let ch = crate::proxy_core::active_channel_id();
        if !GUARD_CHANNELS.contains(&ch.as_str()) {
            break;
        }
        let tag = guard_log_tag(&ch);
        // warp=on для WARP/AWG обязателен (ревью спеца п.3): проба, ушедшая
        // DIRECT'ом — мёртвый/залипший туннель, успехом считать НЕЛЬЗЯ.
        let probe = match trace_probe() {
            Ok((warp, loc)) => probe_healthy(&ch, &warp, &loc),
            Err(e) => Err(e),
        };
        match probe {
            Ok((warp, loc)) => {
                crate::warp::health_update(&warp, &loc, true, "", 0);
                if loc == "RU"
                    && (ch == crate::proxy_core::WARP_CHANNEL_ID
                        || ch == crate::proxy_core::AWG_CHANNEL_ID)
                {
                    emit_log(
                        &app,
                        format!("{} туннель жив, но egress RU — гео на этом провайдере не сменится (честно, не «успех»)", tag),
                    );
                }
            }
            Err(e) => {
                let fails = crate::warp::health_fails() + 1;
                crate::warp::health_update("", "", false, &e, fails);
                emit_log(
                    &app,
                    format!(
                        "{} trace-проба не прошла ({}/{}): {}",
                        tag,
                        fails,
                        crate::warp::GUARD_FAIL_LIMIT,
                        e
                    ),
                );
                if fails >= crate::warp::GUARD_FAIL_LIMIT
                    && GUARD_RESTARTING
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    // TR-ротация — только у WARP (masque с нодой-такси TR: медленные
                    // VPS не поднимают MASQUE за 8с, рестарт ядра это не лечит —
                    // нужна другая нода). У AWG/pawg/psiphon такси нет — сразу рестарт.
                    let rotated = if ch == crate::proxy_core::WARP_CHANNEL_ID {
                        emit_log(
                            &app,
                            format!("{} три неудачи подряд — ротирую ноду-такси TR (PUT /proxies/TR + delay-проба WARP)", tag),
                        );
                        match rotate_tr_node() {
                            Ok(Some(node)) => {
                                emit_log(
                                    &app,
                                    format!(
                                        "{} нода-такси сменена на «{}» — следующая trace-проба подтвердит туннель",
                                        tag, node
                                    ),
                                );
                                crate::warp::guard_reset_fails();
                                GUARD_RESTARTING.store(false, Ordering::SeqCst);
                                true
                            }
                            Ok(None) => {
                                emit_log(
                                    &app,
                                    format!("{} ни одна живая нода не подняла MASQUE — перезапускаю канал", tag),
                                );
                                false
                            }
                            Err(e) => {
                                emit_log(
                                    &app,
                                    format!("{} ротация не удалась ({}): перезапускаю канал", tag, e),
                                );
                                false
                            }
                        }
                    } else {
                        emit_log(&app, format!("{} три неудачи подряд — перезапускаю канал", tag));
                        false
                    };
                    if !rotated {
                        match crate::proxy_core::channel_set(&app, &ch) {
                            Ok(msg) => emit_log(&app, format!("{} канал перезапущен: {}", tag, msg)),
                            Err(err) => emit_log(&app, format!("{} перезапуск не удался: {}", tag, err)),
                        }
                        GUARD_RESTARTING.store(false, Ordering::SeqCst);
                        // Перезапуск поднял НОВЫЙ гард (start_guard в channel_set) —
                        // этот поток завершается, чтобы не дублировать пробы.
                        return;
                    }
                }
            }
        }
        // Интервал 45–60с (ревью спеца п.3); спим порциями по 1с, чтобы
        // выключение канала замечалось почти мгновенно.
        for _ in 0..50 {
            if !crate::warp::WARP_GUARD_ON.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    crate::warp::WARP_GUARD_ON.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod temp_args_tests {
    use super::extract_desync_from_profile_tokens;

    const BIN: &str = r"C:\bin";
    const LISTS: &str = r"C:\lists";

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| String::from(*s)).collect()
    }

    /// Инцидент 02:20 20.11: раньше все --dpi-desync* слеплялись в одну кашу.
    /// Теперь берётся ровно секция TCP:443 общего списка (рецепт General).
    #[test]
    fn multi_section_picks_general_tcp443_not_merged() {
        let tokens = v(&[
            "--filter-udp=443",
            "--hostlist={LISTS_DIR}/list-general.txt",
            "--dpi-desync=fake",
            "--dpi-desync-repeats=11",
            "--dpi-desync-fake-quic={BIN_DIR}/quic.bin",
            "--new",
            "--filter-tcp=443",
            "--hostlist={LISTS_DIR}/list-google.txt",
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-seqovl=681",
            "--dpi-desync-fake-tls={BIN_DIR}/tls_www_google.bin",
            "--new",
            "--filter-tcp=80,443",
            "--hostlist={LISTS_DIR}/list-general.txt",
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-seqovl=654",
            "--dpi-desync-repeats=8",
            "--dpi-desync-fake-tls={BIN_DIR}/tls_max_ru.bin",
        ]);
        let out = extract_desync_from_profile_tokens(&tokens, BIN, LISTS)
            .expect("должна выбраться general TCP:443-секция");
        assert!(out.iter().any(|t| t == "--dpi-desync-split-seqovl=654"));
        assert!(out
            .iter()
            .any(
            |t| t.starts_with("--dpi-desync-fake-tls=") && t.ends_with("tls_max_ru.bin")
        ));
        assert!(out.iter().any(|t| t == "--dpi-desync-repeats=8"));
        // Чужие секции не просочились:
        assert!(!out.iter().any(|t| t.contains("quic.bin")));
        assert!(!out.iter().any(|t| t.contains("seqovl=681")));
    }

    /// Нет general-секции — падаем на любую другую TCP:443 (google).
    #[test]
    fn falls_back_to_any_tcp443_section() {
        let tokens = v(&[
            "--filter-udp=443",
            "--dpi-desync=fake",
            "--dpi-desync-repeats=11",
            "--new",
            "--filter-tcp=443",
            "--hostlist={LISTS_DIR}/list-google.txt",
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-fake-tls={BIN_DIR}/tls_www_google.bin",
        ]);
        let out = extract_desync_from_profile_tokens(&tokens, BIN, LISTS)
            .expect("должна выбраться google TCP:443-секция");
        assert!(out
            .iter()
            .any(
            |t| t.starts_with("--dpi-desync-fake-tls=") && t.ends_with("tls_www_google.bin")
        ));
        assert!(!out.iter().any(|t| t.contains("repeats=11")));
    }

    /// Односекционный профиль без filter-tcp — все дизсинк-токены как есть.
    #[test]
    fn single_section_takes_all_desync_tokens() {
        let tokens = v(&[
            "--wf-tcp=443",
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-fake-tls={BIN_DIR}/x.bin",
        ]);
        let out = extract_desync_from_profile_tokens(&tokens, BIN, LISTS).expect("одна секция");
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(
            |t| t.starts_with("--dpi-desync-fake-tls=") && t.ends_with("x.bin")
        ));
    }

    /// Многосекционный UDP-only профиль — честная ошибка (каша запрещена).
    #[test]
    fn multi_section_without_tcp443_is_honest_error() {
        let tokens = v(&[
            "--filter-udp=443",
            "--dpi-desync=fake",
            "--new",
            "--filter-udp=53",
            "--dpi-desync=fake",
        ]);
        let err = extract_desync_from_profile_tokens(&tokens, BIN, LISTS)
            .expect_err("многосекционный без TCP:443 обязан быть ошибкой");
        assert!(err.contains("TCP:443"));
    }
}
