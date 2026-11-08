//! Встроенный браузер ВО ВКЛАДКЕ (08.11.26, переделка PRP-3 после инцидента
//! «отдельное окно не то, что просили»): embedded webview — child главного
//! окна (Window::add_child, tauri feature "unstable") на вкладке «Браузер».
//! Собственный профиль WebView2 (куки/логины persist в
//! AppData/Local/DPI_GUI/browser-profile); адреса из «Подбора DNS» применяются
//! через `--host-resolver-rules` (MAP). ПКМ-меню рисует initialization_script;
//! его действия уходят в единственную bridge-команду `browser_ctx_action`,
//! разрешённую внешним страницам через remote capability
//! (capabilities/browser.json, webviews: ["browser-tab"]).
//!
//! Верифицировано прототипом (temp/embed-proto/, 08.11.26):
//! - add_child embedded webview работает; init-скрипт исполняется на внешних
//!   сайтах; remote IPC работает (AppManifest::commands + capability webviews
//!   + withGlobalTauri — все три части обязательны);
//! - MAP перенаправляет навигацию (включая subrequests), порт из URL
//!   сохраняется, TLS/SNI не затрагиваются;
//! - close + add_child заново применяют НОВЫЕ args к тому же профилю
//!   (логины сохраняются) — доказано живым тестом с двумя серверами;
//! - set_bounds (Logical) / hide / show работают;
//! - args КОНКАТЕНИРУЮТСЯ с дефолтом wry: чистая замена ломала исполнение
//!   init-скрипта (DEFAULT_ARGS повторяет дефолт wry — не удалять).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Rect, Url, Webview, WebviewBuilder,
    WebviewUrl,
};
use tauri_plugin_shell::ShellExt;

use crate::dns_pick::{DnsPickOutcome, ProbeVerdict};
use crate::events::app_log;

/// Label embedded webview вкладки «Браузер» (capability browser.json — webviews).
const WEBVIEW_LABEL: &str = "browser-tab";
/// Повторяет дефолт wry 0.55.1 (см. док-коммент модуля: замена дефолта
/// целиком своей строкой ломает исполнение initialization_script).
const DEFAULT_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";
/// Ключ config.json с привязками домен → адрес (SSOT маппингов на диске).
const MAPPINGS_KEY: &str = "browserHostMappings";

/// Сериализация для пересоздания webview (он один; конкурентные команды
/// «открыть/применить» не должны строить два webview с гонкой close/build).
static RECREATE_LOCK: Mutex<()> = Mutex::new(());
/// Последний URL, виденный on_navigation — восстановление страницы после
/// пересоздания webview (применение нового маппинга).
static LAST_URL: Mutex<Option<String>> = Mutex::new(None);
/// args последнего построенного webview — чтобы «Открыть» при неизменных
/// маппингах не пересоздавало его (логины и так на диске, но мигание лишнее).
static LAST_ARGS: Mutex<Option<String>> = Mutex::new(None);
/// Дефолтные границы embedded webview (логические px) до первой синхронизации
/// с фронтом; фронт шлёт getBoundingClientRect контейнера на mount/resize.
const DEFAULT_BOUNDS: (f64, f64, f64, f64) = (40.0, 10.0, 900.0, 560.0);
/// Последние границы embedded webview в логических CSS px (от фронта).
/// Пересоздание после применения MAP восстанавливает позицию/размер. (x, y, w, h).
static LAST_BOUNDS: Mutex<(f64, f64, f64, f64)> = Mutex::new(DEFAULT_BOUNDS);
/// Попыток создания webview: WebView2 иногда падает транзиентно
/// (0x8007139F ERROR_INVALID_STATE, инцидент 08.11.26 22:48) — умирающий
/// browser process держит user-data-folder; между попытками он отпускает.
const BUILD_ATTEMPTS: usize = 3;
/// Пауза между попытками сборки webview, мс.
const BUILD_RETRY_PAUSE_MS: u64 = 400;

// ---------------------------------------------------------------------------
// Маппинги (config.json) и args
// ---------------------------------------------------------------------------

/// Читает привязки из config.json. Отсутствие ключа/файла — пустая карта
/// (не ошибка: до первого применения маппинга её и не должно быть).
pub fn read_mappings() -> BTreeMap<String, String> {
    match crate::config::read_config() {
        Ok(cfg) => cfg
            .get(MAPPINGS_KEY)
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| {
                        v.as_str().map(|ip| (k.clone(), ip.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
}

/// Пишет одну привязку (None — снять). Домен нормализуется к нижнему регистру.
pub fn write_mapping(domain: &str, ip: Option<String>) -> Result<(), String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err("пустой домен".into());
    }
    if let Some(ip) = &ip {
        let parsed: std::net::IpAddr =
            ip.trim().parse().map_err(|_| format!("неверный IP: {ip}"))?;
        if !parsed.is_ipv4() {
            return Err("пока поддерживаются только IPv4-адреса (ограничение проб DNS)".into());
        }
    }
    let mut cfg = crate::config::read_config().map_err(|e| e.to_string())?;
    let obj = cfg
        .as_object_mut()
        .ok_or("config.json — не объект")?;
    let mut mappings = obj
        .get(MAPPINGS_KEY)
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    match &ip {
        Some(ip) => {
            mappings.insert(domain, serde_json::Value::String(ip.trim().to_string()));
            obj.insert(
                MAPPINGS_KEY.to_string(),
                serde_json::Value::Object(mappings),
            );
        }
        None => {
            mappings.remove(&domain);
            if mappings.is_empty() {
                obj.remove(MAPPINGS_KEY);
            } else {
                obj.insert(
                    MAPPINGS_KEY.to_string(),
                    serde_json::Value::Object(mappings),
                );
            }
        }
    }
    crate::config::write_config(&cfg).map_err(|e| e.to_string())
}

/// Строка правил host-resolver-rules: `MAP домен IP` через запятую.
fn resolver_rules(mappings: &BTreeMap<String, String>) -> Option<String> {
    if mappings.is_empty() {
        None
    } else {
        Some(
            mappings
                .iter()
                .map(|(d, ip)| format!("MAP {d} {ip}"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Полные args окна браузера: дефолт wry + правила. Чистая функция — юнит-тесты.
pub fn browser_args(mappings: &BTreeMap<String, String>) -> String {
    match resolver_rules(mappings) {
        Some(rules) => format!("{DEFAULT_ARGS} --host-resolver-rules=\"{rules}\""),
        None => DEFAULT_ARGS.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Выбор адреса для MAP из результата подбора DNS (SSOT: DnsPickOutcome)
// ---------------------------------------------------------------------------

/// Отказ выбора адреса: Unverified — НЕ финальный (юзер может подтвердить
/// force-повтором — честное окно из PRP-1), остальные — финальные. Тип вместо
/// строки — чтобы фронт отличал «спросить юзера» от «ничего не найдено» без
/// снифанья текста.
#[derive(Debug)]
pub enum PickMapErr {
    /// Есть кандидат, но проба — Unverified (JS-оболочка): пояснение юзеру.
    Unverified(String),
    /// Применять нечего (нет адресов / нет результата подбора).
    Other(String),
}

/// Первый подходящий адрес из результата `run_pick`: запись с честной пробой
/// Open (сайт открывается через адреса резолвера) или GatewayAlive (фронтинг —
/// кейс посессионных гео-блоков). Unverified (JS-оболочка, PRP-1) молча НЕ
/// применяется: без force — вопрос юзеру (PickMapErr::Unverified). Чистая
/// функция — юнит-тесты; возвращает (домен, IP, откуда адрес).
pub fn pick_mapping_from_outcome(
    outcome: &DnsPickOutcome,
    force: bool,
) -> Result<(String, String, String), PickMapErr> {
    let mut unverified_note: Option<String> = None;
    for e in &outcome.entries {
        if e.resolved.is_empty() {
            continue;
        }
        match e.probe {
            Some(ProbeVerdict::Open) | Some(ProbeVerdict::GatewayAlive) => {
                return Ok((
                    outcome.domain.clone(),
                    e.resolved[0].clone(),
                    format!("{} ({}; {})", e.service, e.resolved[0], e.probe_note),
                ));
            }
            Some(ProbeVerdict::Unverified) => {
                if unverified_note.is_none() {
                    unverified_note = Some(format!(
                        "{}: {}",
                        e.service,
                        if e.probe_note.is_empty() { e.note.clone() } else { e.probe_note.clone() }
                    ));
                }
            }
            _ => {}
        }
    }
    if let Some(note) = unverified_note {
        if force {
            // Юзер явно подтвердил: транспорт работает, доступность после
            // входа не подтверждена — применяем первый Unverified-адрес.
            for e in &outcome.entries {
                if e.probe == Some(ProbeVerdict::Unverified) && !e.resolved.is_empty() {
                    return Ok((
                        outcome.domain.clone(),
                        e.resolved[0].clone(),
                        format!("{} ({}; подтверждено юзером при Unverified)", e.service, e.resolved[0]),
                    ));
                }
            }
        }
        return Err(PickMapErr::Unverified(format!(
            "Доступность сайта через найденные адреса НЕ подтверждена (страница — JS-оболочка: {}). \
Если ограничение появляется только после входа в аккаунт — смена DNS бессильна.",
            note
        )));
    }
    Err(PickMapErr::Other(
        "в результате подбора нет адресов с пробой «открывается» или «живой шлюз» — применять нечего".into(),
    ))
}

// ---------------------------------------------------------------------------
// Embedded webview: сборка, пересоздание, bounds
// ---------------------------------------------------------------------------

fn wait_webview_gone(app: &AppHandle, max_ms: u64) {
    let step = 100;
    let mut waited = 0;
    while app.get_webview(WEBVIEW_LABEL).is_some() && waited < max_ms {
        std::thread::sleep(Duration::from_millis(step));
        waited += step;
    }
}

fn last_url_snapshot() -> Option<String> {
    LAST_URL.lock().ok().and_then(|g| g.clone())
}

fn last_bounds_snapshot() -> (f64, f64, f64, f64) {
    LAST_BOUNDS.lock().map(|g| *g).unwrap_or(DEFAULT_BOUNDS)
}

/// Пульс живости webview: `url()` — runtime-getter с ответом через канал
/// (tauri-runtime-wry, macro webview_getter): обработчик находит webview →
/// шлёт url; НЕ находит (создание упало) → sender дропается → recv возвращает
/// Err. Нужен потому, что при провале создания tauri-runtime-wry ГЛОТАЕТ
/// ошибку (Message::CreateWebview: log::error + Ok-дескриптор в любом случае),
/// и add_child возвращает Ok с мёртвым хэндлом — без пульса фронт лгал
/// «[OK] Браузер открыт» на мёртвом webview (инцидент 08.11.26 22:48,
/// HRESULT 0x8007139F).
fn webview_alive(webview: &Webview) -> bool {
    webview.url().is_ok()
}

/// Строит embedded webview в главном окне (Window::add_child). Позиция/размер —
/// LAST_BOUNDS (шлёт фронт из getBoundingClientRect контейнера). Args
/// фиксируются при создании — смена маппингов требует пересоздания (шаг 0).
/// До BUILD_ATTEMPTS попыток: провал WebView2 часто транзиентен; успех
/// подтверждается пульсом webview_alive (Err add_child runtime не отдаёт).
fn build_webview(app: &AppHandle) -> Result<Webview, String> {
    let profile = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("browser-profile");
    let mappings = read_mappings();
    let args = browser_args(&mappings);
    let (x, y, w, h) = last_bounds_snapshot();
    let main = app.get_window("main").ok_or("главное окно не найдено")?;
    for attempt in 1..=BUILD_ATTEMPTS {
        let handle = app.clone();
        let builder = WebviewBuilder::new(
            WEBVIEW_LABEL,
            WebviewUrl::External(Url::parse("about:blank").map_err(|e| e.to_string())?),
        )
        .data_directory(profile.clone())
        .additional_browser_args(&args)
        .initialization_script(CTX_SCRIPT)
        // Синхронизация адресной строки и лога: каждый переход логируется; факт
        // ошибки загрузки (chrome-error://…) тоже честно виден в адресной строке.
        .on_navigation(move |url| {
            let s = url.to_string();
            if let Ok(mut g) = LAST_URL.lock() {
                *g = Some(s.clone());
            }
            app_log(&handle, format!("[Браузер] Переход: {s}"));
            let _ = handle.emit("browser-url", s);
            true
        });
        let webview = main
            .add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w, h))
            .map_err(|e| e.to_string())?;
        if webview_alive(&webview) {
            if let Ok(mut g) = LAST_ARGS.lock() {
                *g = Some(args);
            }
            return Ok(webview);
        }
        // Мёртвый хэндл снять с учёта (get_webview → None — статус не лжёт),
        // дать умирающему browser process освободить user-data-folder и
        // повторить.
        let _ = webview.close();
        wait_webview_gone(app, 2000);
        app_log(
            app,
            format!(
                "[Браузер] Попытка {attempt}/{BUILD_ATTEMPTS}: webview не создался (WebView2), повторяю..."
            ),
        );
        std::thread::sleep(Duration::from_millis(BUILD_RETRY_PAUSE_MS));
    }
    Err(format!(
        "не удалось создать встроенный браузер ({BUILD_ATTEMPTS} попыток); точная причина WebView2 — [ERROR] строка в логе выше"
    ))
}

/// Открыть (или переиспользовать живой webview) и перейти на url. bounds —
/// прямоугольник контейнера на фронте в логических px ([x, y, w, h] из
/// getBoundingClientRect); при изменённых маппингах webview пересоздаётся
/// (args фиксируются при создании — шаг 0).
#[tauri::command]
pub async fn browser_open(
    app: AppHandle,
    url: String,
    bounds: Option<[f64; 4]>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _g = RECREATE_LOCK.lock().map_err(|e| e.to_string())?;
        let normalized = normalize_url(&url)?;
        if let Some([x, y, w, h]) = bounds {
            if let Ok(mut g) = LAST_BOUNDS.lock() {
                *g = (x, y, w, h);
            }
        }
        let args = browser_args(&read_mappings());
        let fresh = LAST_ARGS.lock().map_err(|e| e.to_string())?.as_deref() != Some(args.as_str());
        if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
            if fresh {
                let _ = webview.close();
                wait_webview_gone(&app, 5000);
                let webview = build_webview(&app)?;
                navigate(&webview, &normalized)?;
            } else {
                navigate(&webview, &normalized)?;
            }
        } else {
            let webview = build_webview(&app)?;
            navigate(&webview, &normalized)?;
        }
        Ok(format!("Браузер открыт во вкладке: {normalized}"))
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")))
}

fn navigate(webview: &Webview, url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("неверный URL {url}: {e}"))?;
    webview.navigate(parsed).map_err(|e| e.to_string())
}

/// Домен/URL к абсолютному http(s)-URL: голый домен → https://домен.
fn normalize_url(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("пустой адрес".into());
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return Ok(s.to_string());
    }
    Ok(format!("https://{s}"))
}

/// Закрыть webview браузера (профиль остаётся на диске — логины переживают).
#[tauri::command]
pub async fn browser_close(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _g = RECREATE_LOCK.lock().map_err(|e| e.to_string())?;
        if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
            webview.close().map_err(|e| e.to_string())?;
            wait_webview_gone(&app, 5000);
            app_log(&app, "[Браузер] Браузер закрыт (профиль сохранён).");
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")))
}

/// Синхронизация границ embedded webview с контейнером на фронте (логические
/// px из getBoundingClientRect — шлётся на mount/resize). Границы сохраняются
/// в LAST_BOUNDS даже если webview ещё не создан — build_webview возьмёт их.
#[tauri::command]
pub fn browser_set_bounds(app: AppHandle, x: f64, y: f64, w: f64, h: f64) -> Result<(), String> {
    if w <= 0.0 || h <= 0.0 {
        return Err("нулевой размер webview недопустим".into());
    }
    if let Ok(mut g) = LAST_BOUNDS.lock() {
        *g = (x, y, w, h);
    }
    if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
        webview
            .set_bounds(Rect {
                position: LogicalPosition::new(x, y).into(),
                size: LogicalSize::new(w, h).into(),
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Уход со вкладки: webview скрывается (страница и профиль живут в фоне).
#[tauri::command]
pub fn browser_hide(app: AppHandle) -> Result<(), String> {
    if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
        webview.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Возврат на вкладку: показать webview.
#[tauri::command]
pub fn browser_show(app: AppHandle) -> Result<(), String> {
    if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
        webview.show().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    pub open: bool,
    pub mappings: BTreeMap<String, String>,
    pub current_url: Option<String>,
}

/// Статус вкладки: открыт ли webview, какие маппинги применены.
#[tauri::command]
pub fn browser_status(app: AppHandle) -> BrowserStatus {
    BrowserStatus {
        open: app.get_webview(WEBVIEW_LABEL).is_some(),
        mappings: read_mappings(),
        current_url: last_url_snapshot(),
    }
}

/// Применить одну привязку вручную (поле вкладки). Если браузер открыт во
/// вкладке — webview пересоздаётся (args фиксируются при создании — шаг 0);
/// если закрыт — привязка сохранится до следующего открытия (не открываем
/// браузер принудительно). ip = None — снять привязку (обычный резолвинг).
#[tauri::command]
pub async fn browser_apply_mapping(
    app: AppHandle,
    domain: String,
    ip: Option<String>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _g = RECREATE_LOCK.lock().map_err(|e| e.to_string())?;
        write_mapping(&domain, ip.clone())?;
        let was_open = app.get_webview(WEBVIEW_LABEL).is_some();
        let note = match &ip {
            Some(ip) => format!("[Браузер] Привязка применена: {domain} → {ip}."),
            None => format!("[Браузер] Привязка снята: {domain}."),
        };
        app_log(&app, note);
        if was_open {
            if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
                let _ = webview.close();
                wait_webview_gone(&app, 5000);
                let webview = build_webview(&app)?;
                let target = last_url_snapshot()
                    .unwrap_or_else(|| normalize_url(&domain).unwrap_or_default());
                if !target.is_empty() {
                    navigate(&webview, &target)?;
                }
            }
        }
        Ok(match (ip, was_open) {
            (Some(ip), true) => format!("Привязка {domain} → {ip} применена, браузер пересоздан (логины сохранены)."),
            (Some(ip), false) => format!("Привязка {domain} → {ip} сохранена — применится при открытии браузера."),
            (None, true) => format!("Привязка {domain} снята, браузер пересоздан."),
            (None, false) => format!("Привязка {domain} снята."),
        })
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")))
}

/// Результат применения подбора: применено / вопрос юзеру (Unverified —
/// фронт показывает кнопку «Применить принудительно») / финальный отказ.
/// Ok-структура вместо Err — отказ из-за Unverified не ошибка сети, а вопрос,
/// и фронт отличает его от инфраструктурных сбоев без снифанья текста.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyPickResult {
    pub applied: bool,
    /// true — отказ именно из-за Unverified: показываем «Применить принудительно».
    pub needs_force: bool,
    pub message: String,
}

/// Применить результат «Подбора DNS» (SSOT: LAST_PICK dns_pick) к браузеру:
/// выбор адреса по пробам, запись привязки, пересоздание окна. force=true —
/// подтверждение юзера при Unverified (PRP-1: транспорт работает, доступность
/// после входа не подтверждена — молча не применяем).
#[tauri::command]
pub async fn browser_apply_pick(app: AppHandle, force: bool) -> Result<ApplyPickResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _g = RECREATE_LOCK.lock().map_err(|e| e.to_string())?;
        // Outcome не приходит через invoke (CommandArg не реализуется для
        // сложных структур) — берём последний продуктовый результат run_pick
        // (set_last_pick в run_pick при Some(app)).
        let outcome = match crate::dns_pick::last_pick() {
            Some(o) => o,
            None => {
                return Ok(ApplyPickResult {
                    applied: false,
                    needs_force: false,
                    message: "Результат подбора DNS не найден — сначала запустите «Подбор DNS» (вкладка «Починка сайтов» или ПКМ на странице браузера)".into(),
                });
            }
        };
        let (domain, ip, source) = match pick_mapping_from_outcome(&outcome, force) {
            Ok(triple) => triple,
            Err(PickMapErr::Unverified(note)) => {
                return Ok(ApplyPickResult {
                    applied: false,
                    needs_force: true,
                    message: note,
                });
            }
            Err(PickMapErr::Other(m)) => {
                return Ok(ApplyPickResult {
                    applied: false,
                    needs_force: false,
                    message: m,
                });
            }
        };
        write_mapping(&domain, Some(ip.clone()))?;
        app_log(
            &app,
            format!("[Браузер] Применяю результат подбора: {domain} → {ip} (источник: {source})"),
        );
        let was_open = app.get_webview(WEBVIEW_LABEL).is_some();
        if was_open {
            if let Some(webview) = app.get_webview(WEBVIEW_LABEL) {
                let _ = webview.close();
                wait_webview_gone(&app, 5000);
                let webview = build_webview(&app)?;
                navigate(&webview, &normalize_url(&domain)?)?;
            }
        }
        Ok(ApplyPickResult {
            applied: true,
            needs_force: false,
            message: if was_open {
                format!("Привязка {domain} → {ip} применена, браузер пересоздан (логины сохранены).")
            } else {
                format!("Привязка {domain} → {ip} сохранена — применится при открытии браузера.")
            },
        })
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")))
}

/// ЕДИНСТВЕННАЯ bridge-команда внешних страниц (пункты ПКМ-меню инжекта).
/// Whitelist сознательно узкий: страница сайта не может менять настройки,
/// hosts и списки — только запустить «Подбор DNS» для домена ссылки (SSOT
/// run_pick, лог — в общий лог приложения) или открыть ссылку в системном
/// браузере. Каждый вызов логируется.
#[tauri::command]
pub async fn browser_ctx_action(app: AppHandle, kind: String, url: String) -> Result<String, String> {
    app_log(&app, format!("[Браузер] Действие из страницы: {kind} ({url})"));
    match kind.as_str() {
        "pick_dns" => {
            let host = Url::parse(&normalize_url(&url)?)
                .ok()
                .and_then(|u| u.host_str().map(|s| s.to_string()))
                .ok_or("не удалось определить домен из ссылки")?;
            let app2 = app.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                crate::cancel::reset(crate::cancel::DNS_PICK);
                crate::dns_pick::run_pick(Some(&app2), &host)
            })
            .await
            .map_err(|e| format!("Ошибка потока: {e}"))?;
            match res {
                Ok(outcome) => {
                    for e in &outcome.entries {
                        app_log(&app, format!("[Подбор DNS] {} — {}", e.service, e.note));
                    }
                    app_log(&app, format!("[Подбор DNS] {}", outcome.summary));
                    Ok(outcome.summary)
                }
                Err(e) => Err(e),
            }
        }
        "open_external" => {
            let parsed = Url::parse(&normalize_url(&url)?).map_err(|e| e.to_string())?;
            app.shell().open(parsed, None).map_err(|e| e.to_string())?;
            Ok("Открыто в системном браузере".into())
        }
        other => Err(format!(
            "действие «{other}» не входит в whitelist моста браузера"
        )),
    }
}

/// Список DoH-сервисов для поля вкладки «Браузер» (SSOT: doh-services.txt).
#[tauri::command]
pub fn get_doh_services() -> Result<Vec<String>, String> {
    let read = crate::config::read_doh_services();
    if !read.file_found {
        return Err("doh-services.txt не найден".into());
    }
    Ok(read.hosts)
}

// ---------------------------------------------------------------------------
// Инжект-скрипт: ПКМ-меню (шаг 2 PRP-3)
// ---------------------------------------------------------------------------

const CTX_SCRIPT: &str = r#"
(function () {
  if (window.__dpiBrowserCtx) return;
  window.__dpiBrowserCtx = true;
  var STYLE = 'position:fixed;z-index:2147483647;background:#ffffff;border:1px solid #d1d5db;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.18);padding:6px;font:14px system-ui,sans-serif;min-width:240px;display:none;';
  var ITEM = 'display:block;width:100%;text-align:left;background:none;border:0;padding:8px 12px;border-radius:6px;cursor:pointer;font:inherit;color:#1f2937;';
  var menu = null;
  function closeMenu() { if (menu) { menu.remove(); menu = null; document.removeEventListener('click', closeMenu, true); document.removeEventListener('keydown', escClose, true); } }
  function escClose(e) { if (e.key === 'Escape') closeMenu(); }
  function bridge(kind, url) {
    var inv = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
    if (!inv) { alert('Мост браузера ещё не инициализирован'); return; }
    inv('browser_ctx_action', { kind: kind, url: url })
      .then(function (msg) { try { console.log('[dpi-bridge] ' + msg); } catch (e) {} })
      .catch(function (err) { alert('Браузер: ' + err); });
  }
  function copyText(t) {
    try { navigator.clipboard.writeText(t); } catch (e) { alert('Не удалось скопировать: ' + t); }
  }
  function showMenu(x, y, linkUrl) {
    closeMenu();
    menu = document.createElement('div');
    menu.setAttribute('style', STYLE);
    var mk = function (label, fn) {
      var b = document.createElement('button');
      b.setAttribute('style', ITEM);
      b.textContent = label;
      b.onmouseenter = function () { b.style.background = '#eff6ff'; };
      b.onmouseleave = function () { b.style.background = 'none'; };
      b.onclick = function () { closeMenu(); fn(); };
      menu.appendChild(b);
    };
    mk('Подбор DNS для обхода геоблока', function () { bridge('pick_dns', linkUrl); });
    mk('Копировать адрес ссылки', function () { copyText(linkUrl); });
    mk('Открыть в системном браузере', function () { bridge('open_external', linkUrl); });
    document.documentElement.appendChild(menu);
    var r = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - r.width - 8) + 'px';
    menu.style.top = Math.min(y, window.innerHeight - r.height - 8) + 'px';
    menu.style.display = 'block';
    setTimeout(function () {
      document.addEventListener('click', closeMenu, true);
      document.addEventListener('keydown', escClose, true);
    }, 0);
  }
  window.addEventListener('contextmenu', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    var url = a ? a.href : location.href;
    e.preventDefault();
    showMenu(e.clientX, e.clientY, url);
  }, true);
})();
"#;

// ---------------------------------------------------------------------------
// Юнит-тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_args_without_mappings_is_default_only() {
        let m = BTreeMap::new();
        let args = browser_args(&m);
        assert_eq!(args, DEFAULT_ARGS);
        assert!(!args.contains("host-resolver-rules"));
    }

    #[test]
    fn browser_args_with_mappings_concatenates_rules() {
        let mut m = BTreeMap::new();
        m.insert("example.com".to_string(), "93.184.216.34".to_string());
        let args = browser_args(&m);
        // Правило и дефолт в одной строке (конкатенация, не замена — шаг 0)
        assert!(args.starts_with(DEFAULT_ARGS));
        assert!(args.contains("--host-resolver-rules=\"MAP example.com 93.184.216.34\""));
    }

    #[test]
    fn resolver_rules_joins_multiple_domains() {
        let mut m = BTreeMap::new();
        m.insert("a.com".to_string(), "1.2.3.4".to_string());
        m.insert("b.org".to_string(), "5.6.7.8".to_string());
        let rules = resolver_rules(&m).unwrap();
        assert_eq!(rules, "MAP a.com 1.2.3.4, MAP b.org 5.6.7.8");
    }

    fn entry(service: &str, ips: &[&str], kind_probe: (crate::dns_pick::ResolverKind, Option<ProbeVerdict>)) -> crate::dns_pick::DnsPickEntry {
        crate::dns_pick::DnsPickEntry {
            service: service.to_string(),
            resolved: ips.iter().map(|s| s.to_string()).collect(),
            kind: kind_probe.0,
            note: String::new(),
            probe: kind_probe.1,
            probe_note: String::new(),
        }
    }

    #[test]
    fn pick_mapping_prefers_open_probe() {
        let outcome = DnsPickOutcome {
            domain: "aistudio.google.com".into(),
            entries: vec![
                entry("dns.google", &["8.8.8.8"], (crate::dns_pick::ResolverKind::Resolves, Some(ProbeVerdict::Unverified))),
                entry("eu.geohide.ru", &["80.74.30.162"], (crate::dns_pick::ResolverKind::Gateway, Some(ProbeVerdict::GatewayAlive))),
            ],
            summary: String::new(),
            verdict_level: "warn".into(),
        };
        let (domain, ip, src) = pick_mapping_from_outcome(&outcome, false).unwrap();
        assert_eq!(domain, "aistudio.google.com");
        assert_eq!(ip, "80.74.30.162");
        assert!(src.contains("eu.geohide.ru"));
    }

    #[test]
    fn pick_mapping_unverified_requires_force() {
        let outcome = DnsPickOutcome {
            domain: "a.com".into(),
            entries: vec![entry("svc", &["1.1.1.1"], (crate::dns_pick::ResolverKind::Resolves, Some(ProbeVerdict::Unverified)))],
            summary: String::new(),
            verdict_level: "warn".into(),
        };
        assert!(
            matches!(pick_mapping_from_outcome(&outcome, false), Err(PickMapErr::Unverified(_))),
            "Unverified молча не применяется (это вопрос юзеру, а не финальный отказ)"
        );
        let (d, ip, src) = pick_mapping_from_outcome(&outcome, true).unwrap();
        assert_eq!((d.as_str(), ip.as_str()), ("a.com", "1.1.1.1"));
        assert!(src.contains("подтверждено юзером"));
    }

    #[test]
    fn pick_mapping_no_candidates_is_error() {
        let outcome = DnsPickOutcome {
            domain: "a.com".into(),
            entries: vec![entry("dead", &[], (crate::dns_pick::ResolverKind::Dead, None))],
            summary: String::new(),
            verdict_level: "fail".into(),
        };
        assert!(pick_mapping_from_outcome(&outcome, true).is_err());
    }

    #[test]
    fn normalize_url_adds_https_to_bare_domain() {
        assert_eq!(normalize_url("example.com").unwrap(), "https://example.com");
        assert_eq!(normalize_url("http://example.com/x").unwrap(), "http://example.com/x");
        assert!(normalize_url("").is_err());
    }
}
