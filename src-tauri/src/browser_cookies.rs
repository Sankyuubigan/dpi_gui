//! Кукисы из браузера для честных проб (PRP 08.11.26, крейт rookie 0.5.6).
//!
//! Кнопка на «Починке сайтов»: юзер выбирает браузер в <select> — из него
//! забираются кукисы текущего домена; SSOT-проба http_via_ip автоматически
//! прикрепляет Cookie к пробам подбора DNS / verify_site_via_ip /
//! контрольной пробы с обходом. Приватность: кукисы живут ТОЛЬКО в памяти
//! процесса; на диск не пишутся; в логи — количества и источники, НИКОГДА
//! значения.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use url::Url;

use crate::events::app_log;
use crate::site_probe::registrable_domain;

/// Браузеры для выпадающего списка UI (поддержка rookie 0.5.6 на Windows).
/// Порядок = порядок в UI; id уходит обратно в grab_cookies.
/// SSOT списка — функции крейта (chrome/edge/firefox/...).
pub const BROWSERS: &[(&str, &str)] = &[
    ("chrome", "Chrome"),
    ("edge", "Edge"),
    ("firefox", "Firefox"),
    ("brave", "Brave"),
    ("opera", "Opera"),
    ("opera_gx", "Opera GX"),
    ("vivaldi", "Vivaldi"),
    ("chromium", "Chromium"),
    ("arc", "Arc"),
    ("librewolf", "LibreWolf"),
    ("zen", "Zen"),
];

/// Пункт списка браузеров для UI.
#[derive(Serialize, Clone)]
pub struct CookieBrowserOption {
    pub id: String,
    pub label: String,
}

/// Результат захвата: сколько всего кукис в памяти, строка источника
/// (sources) и честные отказы с причиной (notes — напр. App-Bound
/// Encryption в Chrome/Edge ≥127).
#[derive(Serialize, Clone)]
pub struct GrabOutcome {
    pub count: usize,
    pub sources: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct CookiesStatus {
    pub count: usize,
    pub sources: Vec<String>,
    /// Последний сохранённый источник автозабора (config.json): id браузера
    /// и/или путь папки User Data — фронт ставит дефолт select.
    pub last_browser: Option<String>,
    pub last_dir: Option<String>,
}

/// Кукиса в памяти: только то, что нужно для Cookie-заголовка.
/// domain с ведущей точкой (".google.com") = доменная кукиса (суффикс-матчинг
/// с границей по точке); без точки — host-only (только точный хост).
#[derive(Debug, Clone)]
struct StoredCookie {
    domain: String,
    path: String,
    name: String,
    value: String,
    expires: Option<u64>,
}

/// Хранилище в памяти процесса. sources — строки «Chrome: 42 шт.»
/// (метаданные захватов; значений кукис тут нет).
#[derive(Debug, Default)]
struct Store {
    cookies: Vec<StoredCookie>,
    sources: Vec<String>,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn lock() -> std::sync::MutexGuard<'static, Option<Store>> {
    STORE.lock().unwrap_or_else(|p| p.into_inner())
}

/// id → функция rookie. any_browser у rookie принимает ПУТИ (не диспетчер
/// по имени), поэтому матчинг здесь. Тип rookie::Cookie не именуется —
/// выводится из сигнатур функций крейта.
fn grab_from(id: &str, domains: Option<Vec<String>>) -> Result<Vec<StoredCookie>, String> {
    // domains = None — вся база (автозабор при старте, PRP 09.11.26).
    let raw = match id {
        "chrome" => rookie::chrome(domains),
        "edge" => rookie::edge(domains),
        "firefox" => rookie::firefox(domains),
        "brave" => rookie::brave(domains),
        "opera" => rookie::opera(domains),
        "opera_gx" => rookie::opera_gx(domains),
        "vivaldi" => rookie::vivaldi(domains),
        "chromium" => rookie::chromium(domains),
        "arc" => rookie::arc(domains),
        "librewolf" => rookie::librewolf(domains),
        "zen" => rookie::zen(domains),
        _ => {
            return Err(format!(
                "неизвестный идентификатор браузера «{id}» (список — cookies_browsers)"
            ))
        }
    };
    let now = unix_now();
    raw.map_err(|e| e.to_string())
        .map(|list| list.iter().filter(|c| not_expired(c.expires, now)).map(|c| StoredCookie {
            domain: c.domain.to_lowercase(),
            path: c.path.clone(),
            name: c.name.clone(),
            value: c.value.clone(),
            expires: c.expires,
        }).collect())
}

/// Unix-секунды сейчас.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Сессионная кукиса (expires: None) — держим: именно они несут логин.
/// Истёкшая (expires <= now) — прочь.
fn not_expired(expires: Option<u64>, now: u64) -> bool {
    expires.map_or(true, |e| e > now)
}

/// Матчинг кукисы к хосту пробы: доменная (с точкой) — суффикс с границей по
/// точке (google.com покрывает aistudio.google.com, но НЕ evilgoogle.com);
/// host-only — точное совпадение.
fn match_host(cookie_domain: &str, host: &str) -> bool {
    if let Some(d) = cookie_domain.strip_prefix('.') {
        host == d || host.ends_with(&format!(".{d}"))
    } else {
        cookie_domain == host
    }
}

/// Cookie-заголовок из отфильтрованных кукис: один name — одна кукиса
/// (самая специфичная — самая длинная domain), порядок по имени (BTreeMap —
/// детерминированный для тестов).
fn build_header(cookies: &[StoredCookie]) -> Option<String> {
    let mut best: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for c in cookies {
        let pair = format!("{}={}", c.name, c.value);
        match best.get(c.name.as_str()) {
            None => {
                best.insert(c.name.clone(), (pair, c.domain.len()));
            }
            Some((_, dom_len)) => {
                if *dom_len < c.domain.len() {
                    best.insert(c.name.clone(), (pair, c.domain.len()));
                }
            }
        }
    }
    if best.is_empty() {
        None
    } else {
        Some(
            best.into_values()
                .map(|(pair, _)| pair)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// Cookie-заголовок для хоста пробы (None — кукис для домена нет).
pub fn cookies_header_for(host: &str) -> Option<String> {
    let g = lock();
    let st = g.as_ref()?;
    let filtered: Vec<StoredCookie> = st
        .cookies
        .iter()
        .filter(|c| match_host(&c.domain, host))
        .cloned()
        .collect();
    build_header(&filtered)
}

/// Сколько кукис этого хоста в памяти (для одноразового лога подбора DNS).
pub fn count_for(host: &str) -> usize {
    let g = lock();
    match g.as_ref() {
        None => 0,
        Some(st) => st
            .cookies
            .iter()
            .filter(|c| match_host(&c.domain, host))
            .count(),
    }
}

/// «https://Example.COM:443/path» → «example.com»; голый домен тоже ок.
fn parse_host(url: &str) -> Result<String, String> {
    let raw = url.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let u = Url::parse(&with_scheme).map_err(|e| format!("«{url}» не похоже на адрес: {e}"))?;
    u.host_str()
        .map(|s| s.trim_end_matches('.').to_lowercase())
        .ok_or_else(|| format!("«{url}» — не удалось выделить домен"))
}

#[tauri::command]
pub async fn grab_cookies(
    app: AppHandle,
    url: String,
    browser: String,
    dir: Option<String>,
) -> Result<GrabOutcome, String> {
    let browser_id = browser.clone();
    let dir_src = dir.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        grab_blocking(&app, &url, &browser, dir.as_deref())
    })
        .await
        .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")));
    // Источник автозабора (PRP 09.11.26): сохраняем намерение юзера при
    // любом Ok — даже с 0 кукис (нота подскажет залогиниться). Err (битый
    // url) не сохраняем, чтобы не портить прошлый источник.
    if res.is_ok() {
        let (b, d) = if dir_src.is_some() {
            (None, dir_src)
        } else {
            (Some(browser_id), None)
        };
        if let Err(e) = crate::config::update_cookie_source(b, d) {
            log::warn!("[Кукисы] источник автозабора не сохранён в config: {e}");
        }
    }
    res
}

/// Кукисы из указанной юзером папки User Data — любой Chromium-форк
/// (Thorium, Яндекс и прочие): ключ — Local State, базы — Default и
/// Profile * (старые Cookies и новые Network/Cookies, как в config.json
/// rookie). Захват — rookie::any_browser. Приватность та же: в лог —
/// только количества.

/// Автозабор кукисов при старте (PRP 09.11.26, Вариант A): из config.json
/// берётся последний источник (браузер или папка User Data) — его база
/// целиком уходит в память. Браузер запущен/ABE-отказ → честная нота в лог,
/// кнопка «Забрать кукисы» остаётся ручным путём. Источника нет — тихий
/// выход (первый запуск после обновления).
pub async fn auto_grab_on_startup(app: AppHandle) {
    let (browser, dir) = crate::config::cookie_source();
    if browser.is_none() && dir.is_none() {
        return;
    }
    let handle = app.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        grab_impl(&app, None, browser.as_deref().unwrap_or(""), dir.as_deref())
    })
        .await
        .unwrap_or_else(|e| Err(format!("Ошибка потока: {e}")));
    match res {
        Ok(out) => {
            if !out.sources.is_empty() {
                app_log(
                    &handle,
                    format!("[Кукисы] Автозабор при старте: {}", out.sources.join("; ")),
                );
            }
            for n in &out.notes {
                app_log(&handle, format!("[Кукисы] Автозабор: {n}"));
            }
        }
        Err(e) => app_log(
            &handle,
            format!(
                "[Кукисы] Автозабор при старте не удался: {e} — жми «Забрать кукисы» вручную"
            ),
        ),
    }
    // Фронт перечитает cookies_status по событию — чип обновится сам.
    let _ = handle.emit("cookies-updated", ());
}

fn grab_from_dir(
    app: &AppHandle,
    host: Option<&str>,
    dom: Option<&str>,
    dir: &str,
    domains: Option<Vec<String>>,
) -> Result<GrabOutcome, String> {
    let base = std::path::PathBuf::from(dir.trim().trim_matches('"'));
    if !base.is_dir() {
        return Err(format!("папка не найдена: {}", base.display()));
    }
    let cookie_files = find_cookie_bases(&base);
    if cookie_files.is_empty() {
        return Err(format!(
            "в {} нет кукис-баз Chromium (ожидаются Default/Network/Cookies или Profile */Cookies) — укажи именно папку User Data браузера",
            base.display()
        ));
    }
    let key_path = {
        let k = base.join("Local State");
        if k.is_file() {
            Some(k.to_string_lossy().into_owned())
        } else {
            None
        }
    };
    let Some(key) = key_path else {
        return Err(format!(
            "в {} нет файла ключей Local State — укажи именно папку User Data браузера",
            base.display()
        ));
    };
    let now = unix_now();
    let mut fresh: Vec<StoredCookie> = Vec::new();
    let mut fails: Vec<String> = Vec::new();
    for cf in &cookie_files {
        match rookie::any_browser(&cf.to_string_lossy(), domains.clone(), Some(&key)) {
            Ok(list) => fresh.extend(
                list.iter()
                    .filter(|c| not_expired(c.expires, now))
                    .map(|c| StoredCookie {
                        domain: c.domain.to_lowercase(),
                        path: c.path.clone(),
                        name: c.name.clone(),
                        value: c.value.clone(),
                        expires: c.expires,
                    }),
            ),
            Err(e) => fails.push(format!(
                "{}: {}",
                cf.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                e
            )),
        }
    }
    // Метка источника: имя родительской папки («Thorium», «YandexBrowser») —
    // сама папка обычно называется «User Data»; без родителя — имя папки.
    let label = format!(
        "Папка: {}",
        base.parent()
            .and_then(|p| p.file_name())
            .or_else(|| base.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| base.to_string_lossy().into_owned())
    );
    let n = fresh.len();
    let total = merge_into_store(fresh);
    let line = format!("{label}: {n} шт.");
    replace_source_line(line.clone(), &label);
    app_log(
        app,
        match host {
            Some(h) => format!(
                "[Кукисы] {label}: {n} шт. для {h} ({} баз) — держу в памяти, пробы с ними",
                cookie_files.len()
            ),
            None => format!(
                "[Кукисы] {label}: {n} шт. (автозабор при старте, {} баз) — держу в памяти",
                cookie_files.len()
            ),
        },
    );
    let mut notes = Vec::new();
    if n == 0 {
        notes.push(match host {
            Some(_) => format!(
                "{label}: кукис для {} не найден — залогиньтесь в этом браузере и повторите",
                dom.as_deref().unwrap_or("?")
            ),
            None => format!(
                "{label}: кукисов в базах нет — залогиньтесь в этом браузере и повторите"
            ),
        });
    }
    notes.extend(fails);
    Ok(GrabOutcome {
        count: total,
        sources: vec![line],
        notes,
    })
}

/// Cookies-базы Chromium в папке User Data: Default и Profile * (старый
/// <профиль>/Cookies и новый <профиль>/Network/Cookies — как в config.json
/// rookie). Сортировка детерминирована.
fn find_cookie_bases(base: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    let d = base.join("Default");
    if d.is_dir() {
        dirs.push(d);
    }
    if let Ok(rd) = std::fs::read_dir(base) {
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") && e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        for sub in ["Cookies", "Network/Cookies"] {
            let p = d.join(sub);
            if p.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Общая механика захвата. host = Some — фильтр по домену юзера (команда
/// grab_cookies); host = None — ВСЯ база источника (автозабор при старте,
/// PRP 09.11.26: сайт юзер выберет позже, наружу в пробы всё равно уйдут
/// только кукисы совпавшего хоста — cookies_header_for фильтрует по хосту).
fn grab_impl(
    app: &AppHandle,
    host: Option<&str>,
    browser: &str,
    dir: Option<&str>,
) -> Result<GrabOutcome, String> {
    let dom = host.map(registrable_domain);
    // Фильтр rookie — contains по домену кукисы: передаю полный хост +
    // регистрируемый домен (покрывает и host-only, и .google.com).
    let domains: Option<Vec<String>> = host.map(|h| {
        let d = dom.as_deref().unwrap_or(h);
        if d == h {
            vec![h.to_string()]
        } else {
            vec![h.to_string(), d.to_string()]
        }
    });
    if let Some(d) = dir {
        // Папка User Data от юзера: ЛЮБОЙ Chromium-форк без списков —
        // ключ и кукис-базы ищем сами (Local State, Default, Profile *).
        return grab_from_dir(app, host, dom.as_deref(), d, domains);
    }
    let label = browser_label(browser)?;
    match grab_from(browser, domains) {
        Ok(fresh) => {
            let n = fresh.len();
            let total = merge_into_store(fresh);
            let line = format!("{label}: {n} шт.");
            replace_source_line(line.clone(), label);
            app_log(
                app,
                match host {
                    Some(h) => format!(
                        "[Кукисы] {label}: {n} шт. для {h} — держу в памяти, пробы с ними"
                    ),
                    None => format!(
                        "[Кукисы] {label}: {n} шт. (автозабор при старте) — держу в памяти"
                    ),
                },
            );
            let mut notes = Vec::new();
            if n == 0 {
                notes.push(match host {
                    Some(_) => format!(
                        "{label}: кукис для {} не найден — залогиньтесь в этом браузере и повторите",
                        dom.as_deref().unwrap_or("?")
                    ),
                    None => format!(
                        "{label}: кукисов в базе нет — залогиньтесь в этом браузере и повторите"
                    ),
                });
            }
            Ok(GrabOutcome {
                count: total,
                sources: vec![line],
                notes,
            })
        }
        Err(e) => {
            let msg = format!("{label} — не удалось: {e}");
            app_log(app, format!("[Кукисы] {msg}"));
            Ok(GrabOutcome {
                count: store_total(),
                sources: Vec::new(),
                notes: vec![msg],
            })
        }
    }
}

/// Тонкая обёртка команды: url → хост, фильтр по домену — прежнее поведение.
fn grab_blocking(
    app: &AppHandle,
    url: &str,
    browser: &str,
    dir: Option<&str>,
) -> Result<GrabOutcome, String> {
    let host = parse_host(url)?;
    grab_impl(app, Some(&host), browser, dir)
}

/// Метаданные источников в store: строку того же браузера заменить
/// (повторный захват не плодит дублей), новой — добавить.
fn replace_source_line(line: String, label: &str) {
    let mut g = lock();
    let st = g.get_or_insert_with(Default::default);
    let key = format!("{label}:");
    if let Some(slot) = st.sources.iter().position(|s| s.starts_with(&key)) {
        st.sources[slot] = line;
    } else {
        st.sources.push(line);
    }
}

/// Слияние в хранилище: ключ (name, domain, path) — свежее значение затирает
/// старое (юзер мог перелогиниться), иначе добавить. Возврат — новый total.
fn merge_into_store(fresh: Vec<StoredCookie>) -> usize {
    let mut g = lock();
    if fresh.is_empty() {
        return store_total();
    }
    let st = g.get_or_insert_with(Default::default);
    for c in fresh {
        if let Some(slot) = st
            .cookies
            .iter()
            .position(|e| e.name == c.name && e.domain == c.domain && e.path == c.path)
        {
            st.cookies[slot] = c;
        } else {
            st.cookies.push(c);
        }
    }
    st.cookies.len()
}

fn store_total() -> usize {
    let g = lock();
    g.as_ref().map(|st| st.cookies.len()).unwrap_or(0)
}

fn browser_label(id: &str) -> Result<&'static str, String> {
    BROWSERS
        .iter()
        .find(|(bid, _)| *bid == id)
        .map(|(_, l)| *l)
        .ok_or_else(|| format!("неизвестный браузер «{id}»"))
}

/// Каталоги данных для детекта «реально установлен» (SSOT — пути кукис-баз
/// из config.json rookie 0.5.6, родительские каталоги; Arc — UWP-пакет).
const DATA_DIRS: &[(&str, &[&str])] = &[
    ("chrome", &["Google/Chrome"]),
    ("edge", &["Microsoft/Edge"]),
    ("brave", &["BraveSoftware"]),
    (
        "opera",
        &[
            "Opera Software/Opera Stable",
            "Opera Software/Opera Beta",
            "Opera Software/Opera Developer",
        ],
    ),
    (
        "opera_gx",
        &[
            "Opera Software/Opera GX Stable",
            "Opera Software/Opera GX Beta",
            "Opera Software/Opera GX Developer",
        ],
    ),
    ("vivaldi", &["Vivaldi"]),
    ("chromium", &["Chromium"]),
    ("firefox", &["Mozilla/Firefox"]),
    ("librewolf", &["librewolf"]),
    ("zen", &["zen"]),
];

/// id реально установленных браузеров: существует каталог данных (в
/// LOCALAPPDATA или APPDATA — обе базы, как ищет сам rookie) или UWP-пакет
/// Arc (имя с суффиксом-хэшем, поэтому только префикс).
fn detect_installed() -> Vec<&'static str> {
    let bases: Vec<std::path::PathBuf> = [dirs::data_local_dir(), dirs::data_dir()]
        .into_iter()
        .flatten()
        .collect();
    DATA_DIRS
        .iter()
        .filter(|(id, subdirs)| {
            if *id == "arc" {
                return bases
                    .iter()
                    .any(|b| {
                        std::fs::read_dir(b.join("Packages"))
                            .map(|rd| {
                                rd.filter_map(|e| e.ok()).any(|e| {
                                    e.file_name()
                                        .to_string_lossy()
                                        .starts_with("TheBrowserCompany.Arc")
                                })
                            })
                            .unwrap_or(false)
                    });
            }
            subdirs
                .iter()
                .any(|sub| bases.iter().any(|b| b.join(sub).exists()))
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Список браузеров для UI-select: ТОЛЬКО фактически установленные (детект
/// по каталогам данных). Ничего не нашлось (portable/нестандартные пути) —
/// отдаю весь список: rookie при захвате честно скажет, где кукисов нет.
#[tauri::command]
pub fn cookies_browsers() -> Vec<CookieBrowserOption> {
    browsers_response(&detect_installed())
}

fn browsers_response(installed: &[&str]) -> Vec<CookieBrowserOption> {
    let picked = BROWSERS
        .iter()
        .filter(|(id, _)| installed.contains(id))
        .map(|(id, label)| CookieBrowserOption {
            id: id.to_string(),
            label: label.to_string(),
        })
        .collect::<Vec<_>>();
    if picked.is_empty() {
        BROWSERS
            .iter()
            .map(|(id, label)| CookieBrowserOption {
                id: id.to_string(),
                label: label.to_string(),
            })
            .collect()
    } else {
        picked
    }
}

/// Статус для чипа UI (на mount вкладки) + сохранённый источник автозабора
/// (фронт ставит дефолт select).
#[tauri::command]
pub fn cookies_status() -> CookiesStatus {
    let (last_browser, last_dir) = crate::config::cookie_source();
    let g = lock();
    match g.as_ref() {
        None => CookiesStatus {
            count: 0,
            sources: Vec::new(),
            last_browser,
            last_dir,
        },
        Some(st) => CookiesStatus {
            count: st.cookies.len(),
            sources: st.sources.clone(),
            last_browser,
            last_dir,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(domain: &str, name: &str, value: &str) -> StoredCookie {
        StoredCookie {
            domain: domain.into(),
            path: "/".into(),
            name: name.into(),
            value: value.into(),
            expires: None,
        }
    }

    #[test]
    fn domain_suffix_match() {
        assert!(match_host(".google.com", "aistudio.google.com"));
        assert!(match_host(".google.com", "google.com"));
        assert!(!match_host(".google.com", "evilgoogle.com"));
        assert!(!match_host("aistudio.google.com", "www.google.com"));
        assert!(match_host("aistudio.google.com", "aistudio.google.com"));
    }

    #[test]
    fn expired_filtered() {
        assert!(not_expired(None, 100));
        assert!(!not_expired(Some(50), 100));
        assert!(not_expired(Some(150), 100));
    }

    #[test]
    fn header_dedup_most_specific() {
        let cookies = vec![
            sc(".google.com", "SID", "1"),
            sc("aistudio.google.com", "SID", "2"),
            sc(".google.com", "NID", "3"),
        ];
        let h = build_header(&cookies).unwrap();
        assert_eq!(h, "NID=3; SID=2");
        assert!(build_header(&[]).is_none());
    }

    #[test]
    fn parse_host_strips_scheme_path_port() {
        assert_eq!(
            parse_host("aistudio.google.com").unwrap(),
            "aistudio.google.com"
        );
        assert_eq!(parse_host("https://Example.COM:443/path").unwrap(), "example.com");
        assert_eq!(parse_host("http://example.com:8443/x?y=1").unwrap(), "example.com");
        assert!(parse_host(":::bad:::").is_err());
    }

    #[test]
    fn browsers_response_filters_installed_and_falls_back() {
        let picked = browsers_response(&["firefox", "chrome"]);
        assert_eq!(picked.len(), 2);
        // Порядок сохраняется как в BROWSERS, а не как в списке детекта.
        assert_eq!(picked[0].id, "chrome");
        assert_eq!(picked[1].id, "firefox");
        // Детект пуст (portable/нестандартные пути) — честный фолбэк на все.
        assert_eq!(browsers_response(&[]).len(), BROWSERS.len());
        // Политика фолбэка едина: выбор не нашёл ничего знакомого → весь список.
        assert_eq!(browsers_response(&["nope"]).len(), BROWSERS.len());
    }

    #[test]
    fn find_cookie_bases_default_and_profiles() {
        let root = std::env::temp_dir().join(format!("dpi_gui_cookietest_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dn = root.join("Default").join("Network");
        std::fs::create_dir_all(&dn).unwrap();
        std::fs::write(dn.join("Cookies"), b"").unwrap();
        let p1 = root.join("Profile 1");
        std::fs::create_dir_all(&p1).unwrap();
        std::fs::write(p1.join("Cookies"), b"").unwrap();
        let mut want = vec![
            root.join("Default").join("Network").join("Cookies"),
            p1.join("Cookies"),
        ];
        want.sort();
        assert_eq!(find_cookie_bases(&root), want);
        let _ = std::fs::remove_dir_all(&root);
    }
}
