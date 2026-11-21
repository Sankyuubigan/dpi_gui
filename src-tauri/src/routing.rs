//! Модель маршрутизации (Этап A, PRP 19.11.26 «Группы маршрутизации»).
//!
//! SSOT доменов — СУЩЕСТВУЮЩИЕ списки (параллельных реестров не создаём):
//!   dpi-группа  : defaults/list-general.txt + defaults/list-google.txt (системные)
//!                 + lists/list-general.txt (юзер, «Управление списками»);
//!   geo-группа  : defaults/geo-list.txt (системный, новый) + lists/geo-custom.txt (юзер);
//!   trusted     : defaults/default-exclude.txt + lists/list-exclude.txt.
//! SSOT режимов — AppData/routing.json: ТОЛЬКО переключатели «что делать с группой»
//! (dpi → winws | channel | direct; geo → channel | direct; route → selective | fullport).
//!
//! Компилятор `compile` детерминированно строит 3 артефакта из одной модели:
//!   1) channel-exclude.txt — домены, которые winws НЕ должен дизсинкить
//!      (уходят в канал; находка спеца: фейк ClientHello ломает прокси-туннель
//!      изнутри, т.к. исходящий 443 mihomo проходит через WinDivert);
//!   2) rules для наших mihomo-шаблонов (reserve): channel-домены → outbound,
//!      остальное MATCH,DIRECT (платный yaml юзера НЕ патчим — его правила);
//!   3) proxy.pac — браузер: только channel-домены → PROXY 127.0.0.1:7897,
//!      всё остальное DIRECT мимо mihomo (QUIC/банки не трогаем; TUN-off инвариант).

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::config;

/// Порт PAC-слушателя. SSOT портов: 7897 — mihomo mixed, 9097 — REST API,
/// 7896 — PAC (свободен; 7898/9099 заняты оракулом/экспериментами).
pub const PAC_PORT: u16 = 7896;
pub const PAC_URL: &str = "http://127.0.0.1:7896/proxy.pac";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiMode {
    /// YouTube/Discord через winws (дефолт: полная скорость, не грузит прокси).
    Winws,
    /// Домены dpi-группы отправляются в активный канал.
    Channel,
    /// Без обхода и без канала (чистый DIRECT).
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoMode {
    /// AI Studio/Adobe/ChatGPT через активный канал (дефолт).
    Channel,
    /// Гео-группа без канала.
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    /// В канал идут только channel-домены, остальное MATCH,DIRECT (дефолт).
    Selective,
    /// Весь трафик, дошедший до порта, уходит в канал (MATCH,<out>).
    FullPort,
}

#[derive(Debug, Clone, Copy)]
pub struct RoutingModes {
    pub dpi_mode: DpiMode,
    pub geo_mode: GeoMode,
    pub route_mode: RouteMode,
}

impl Default for RoutingModes {
    fn default() -> Self {
        // Ютуб-группа в канал по умолчанию (21.11.26, приказ юзера «вшивай во
        // все каналы»): канал включён → ютуб через узел (NL-выход, фикс
        // кэш-мисса ютуба, winws это не умеет). Канал off → exclude/rules
        // при channel_active=false не генерятся вовсе → ютуб остаётся в
        // winws-хостлисте и обходится как раньше. Двусторонне безопасно.
        Self { dpi_mode: DpiMode::Channel, geo_mode: GeoMode::Channel, route_mode: RouteMode::Selective }
    }
}

pub fn parse_dpi_mode(s: &str) -> Result<DpiMode, String> {
    match s {
        "winws" => Ok(DpiMode::Winws),
        "channel" => Ok(DpiMode::Channel),
        "direct" => Ok(DpiMode::Direct),
        other => Err(format!("неизвестный dpi_mode «{other}»")),
    }
}

pub fn parse_geo_mode(s: &str) -> Result<GeoMode, String> {
    match s {
        "channel" => Ok(GeoMode::Channel),
        "direct" => Ok(GeoMode::Direct),
        other => Err(format!("неизвестный geo_mode «{other}»")),
    }
}

pub fn parse_route_mode(s: &str) -> Result<RouteMode, String> {
    match s {
        "selective" => Ok(RouteMode::Selective),
        "fullport" => Ok(RouteMode::FullPort),
        other => Err(format!("неизвестный route_mode «{other}»")),
    }
}

pub fn dpi_mode_str(m: DpiMode) -> &'static str {
    match m {
        DpiMode::Winws => "winws",
        DpiMode::Channel => "channel",
        DpiMode::Direct => "direct",
    }
}

pub fn geo_mode_str(m: GeoMode) -> &'static str {
    match m {
        GeoMode::Channel => "channel",
        GeoMode::Direct => "direct",
    }
}

pub fn route_mode_str(m: RouteMode) -> &'static str {
    match m {
        RouteMode::Selective => "selective",
        RouteMode::FullPort => "fullport",
    }
}

fn modes_file() -> PathBuf {
    config::get_app_dir().join("routing.json")
}

/// Читает режимы из файла. Файла нет → дефолт (первый запуск).
/// Битый JSON / неизвестные значения — честная ошибка (не молча-дефолт).
pub fn load_modes_from(path: &PathBuf) -> Result<RoutingModes, String> {
    if !path.exists() {
        return Ok(RoutingModes::default());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("routing.json не читается: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("routing.json битый: {e}"))?;
    let d = v.get("dpi_mode").and_then(|x| x.as_str()).unwrap_or("winws");
    let g = v.get("geo_mode").and_then(|x| x.as_str()).unwrap_or("channel");
    let r = v.get("route_mode").and_then(|x| x.as_str()).unwrap_or("selective");
    Ok(RoutingModes {
        dpi_mode: parse_dpi_mode(d)?,
        geo_mode: parse_geo_mode(g)?,
        route_mode: parse_route_mode(r)?,
    })
}

pub fn load_modes() -> Result<RoutingModes, String> {
    load_modes_from(&modes_file())
}

/// Сохраняет режимы. Логи до/после — у вызывающего (он знает AppHandle).
pub fn save_modes_to(path: &PathBuf, modes: &RoutingModes) -> Result<(), String> {
    let json = serde_json::json!({
        "dpi_mode": dpi_mode_str(modes.dpi_mode),
        "geo_mode": geo_mode_str(modes.geo_mode),
        "route_mode": route_mode_str(modes.route_mode),
    });
    fs::write(path, serde_json::to_string_pretty(&json).unwrap())
        .map_err(|e| format!("routing.json не пишется: {e}"))
}

pub fn save_modes(modes: &RoutingModes) -> Result<(), String> {
    save_modes_to(&modes_file(), modes)
}

/// Читает домены из списка winws-формата: `#`-комментарии пропускаются,
/// префикс `^` (точное совпадение) сохраняется, пустые/дубли — долой.
pub fn load_domains_file(path: &PathBuf) -> Vec<String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let d = line.trim();
        if d.is_empty() || d.starts_with('#') {
            continue;
        }
        let d = d.to_lowercase();
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

fn lists_dir() -> PathBuf {
    config::get_app_dir().join("lists")
}

/// dpi-группа с диска: юзерский список + системные general/google
/// (порядок повторяет порядок загрузки списков в resolve_args_core).
pub fn dpi_domains() -> Vec<String> {
    let mut out = Vec::new();
    for p in [
        lists_dir().join("list-general.txt"),
        lists_dir().join("defaults").join("list-general.txt"),
        lists_dir().join("defaults").join("list-google.txt"),
    ] {
        for d in load_domains_file(&p) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// geo-группа с диска: системный дефолт + юзерские дополнения.
pub fn geo_domains() -> Vec<String> {
    let mut out = Vec::new();
    for p in [
        lists_dir().join("defaults").join("geo-list.txt"),
        lists_dir().join("geo-custom.txt"),
    ] {
        for d in load_domains_file(&p) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// trusted-группа с диска: банки/РФ-ресурсы — всегда напрямую (winws не
/// дизсинкит, канал не берёт). Системный default-exclude + юзерский
/// list-exclude («Управление списками»).
pub fn trusted_domains() -> Vec<String> {
    let mut out = Vec::new();
    for p in [
        lists_dir().join("defaults").join("default-exclude.txt"),
        lists_dir().join("list-exclude.txt"),
    ] {
        for d in load_domains_file(&p) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// Извлекает домены прокси-нод из текста yaml-конфига (ключи server/sni/
/// server-name/servername). IP-адреса и плейсхолдеры пропускаются: hostlist
/// winws — доменный. Строчный проход вместо полного парсинга yaml: платные
/// подписки бывают любыми, и ломать их парсером недопустимо.
pub fn node_domains_from_yaml(text: &str) -> Vec<String> {
    const KEYS: [&str; 4] = ["server", "sni", "server-name", "servername"];
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let Some(colon) = t.find(':') else { continue };
        let key = t[..colon].trim().to_lowercase();
        if !KEYS.contains(&key.as_str()) {
            continue;
        }
        let val = t[colon + 1..].trim().trim_matches(['"', '\'']).to_lowercase();
        if val.is_empty() || val.starts_with("__") || val.contains('$') {
            continue;
        }
        // host:port → срезаем порт
        let host = val.rsplit_once(':').map_or(val.as_str(), |(h, _)| h);
        if host.is_empty() || IpAddr::from_str(host).is_ok() {
            continue;
        }
        if !out.iter().any(|d| d == host) {
            out.push(host.to_string());
        }
    }
    out
}

/// Результат компиляции: 3 артефакта из одной модели.
#[derive(Debug, PartialEq)]
pub struct Artifacts {
    /// Строки для lists/defaults/channel-exclude.txt (без trusted-доменов —
    /// тот winws уже грузит из default-exclude.txt).
    pub channel_exclude: Vec<String>,
    /// Строки секции rules (без заголовка `rules:`). Пусто → правила не наши.
    pub mihomo_rules: Vec<String>,
    /// Тело proxy.pac.
    pub pac_script: String,
}

/// PAC-сопоставление одного домена. `^` — точное совпадение; `*` — маска
/// (shExpMatch); прочее — сам домен или поддомен (защита от suffix-ложки
/// вида xaistudio.google.com через явную точку).
fn pac_domain_checks(domain: &str) -> String {
    if let Some(exact) = domain.strip_prefix('^') {
        format!("host === \"{}\"", exact)
    } else if domain.contains('*') {
        format!("shExpMatch(host, \"{}\")", domain)
    } else {
        format!("host === \"{}\" || dnsDomainIs(host, \".{}\")", domain, domain)
    }
}

fn mihomo_rule_for(domain: &str, outbound: &str) -> Option<String> {
    if let Some(exact) = domain.strip_prefix('^') {
        Some(format!("- DOMAIN,{},{}", exact, outbound))
    } else if domain.contains('*') {
        // Маски в DOMAIN-SUFFIX не поддерживаются — честно пропускаем с комментом.
        None
    } else {
        Some(format!("- DOMAIN-SUFFIX,{},{}", domain, outbound))
    }
}

/// Компиляция всех артефактов. Чистая функция (без ФС) — списки передаются
/// параметрами; обёртки compile_from_fs/load_* читают их с диска.
///
/// `dpi`/`geo` — полные домены групп; `outbound` — имя mihomo-outbound
/// активного канала (None = канал off или платный: его правила не наши);
/// `node_domains` — домены активных прокси-нод.
pub fn compile(
    modes: &RoutingModes,
    dpi: &[String],
    geo: &[String],
    channel_active: bool,
    outbound: Option<&str>,
    node_domains: &[String],
    proxy_port: u16,
) -> Artifacts {
    let mut ch: Vec<String> = Vec::new();
    if modes.dpi_mode == DpiMode::Channel {
        for d in dpi {
            if !ch.contains(d) {
                ch.push(d.clone());
            }
        }
    }
    if modes.geo_mode == GeoMode::Channel {
        for d in geo {
            if !ch.contains(d) {
                ch.push(d.clone());
            }
        }
    }

    // 1) winws-exclude: только при живом канале — оберегаем то, что уходит в узел.
    let mut channel_exclude: Vec<String> = Vec::new();
    if channel_active {
        for d in ch.iter().chain(node_domains.iter()) {
            if !channel_exclude.contains(d) {
                channel_exclude.push(d.clone());
            }
        }
    }

    // 2) mihomo rules (только для наших шаблонов: outbound задан).
    let mut mihomo_rules: Vec<String> = Vec::new();
    if let Some(out) = outbound {
        if channel_active {
            if modes.route_mode == RouteMode::FullPort {
                mihomo_rules.push(format!("- MATCH,{}", out));
            } else {
                for d in &ch {
                    match mihomo_rule_for(d, out) {
                        Some(r) => mihomo_rules.push(r),
                        None => mihomo_rules
                            .push(format!("# маска не поддерживается mihomo, пропущена: {}", d)),
                    }
                }
                mihomo_rules.push("- MATCH,DIRECT".to_string());
            }
        }
    }

    // 3) PAC: браузер отправляет в порт только channel-домены. Цепочка
    //    "PROXY …; DIRECT" деградирует в прямой доступ, если канал упал;
    //    без канала правил PROXY нет вовсе — браузер не ждёт мёртвый порт.
    let mut pac = String::from(
        "// Автогенерация DPI GUI (routing.rs) — не редактировать вручную.\n\
         function FindProxyForURL(url, host) {\n  host = String(host).toLowerCase();\n",
    );
    if channel_active {
        for d in &ch {
            pac.push_str(&format!(
                "  if ({}) return \"PROXY 127.0.0.1:{}; DIRECT\";\n",
                pac_domain_checks(d),
                proxy_port
            ));
        }
    }
    pac.push_str("  return \"DIRECT\";\n}\n");

    Artifacts { channel_exclude, mihomo_rules, pac_script: pac }
}

/// Обёртка над compile со списками с диска (для живых команд/PAC-сервера).
pub fn compile_from_fs(
    modes: &RoutingModes,
    channel_active: bool,
    outbound: Option<&str>,
    node_domains: &[String],
    proxy_port: u16,
) -> Result<Artifacts, String> {
    let dpi = dpi_domains();
    let geo = geo_domains();
    Ok(compile(modes, &dpi, &geo, channel_active, outbound, node_domains, proxy_port))
}

/// Пишет channel-exclude.txt (артефакт winws). Возвращает число доменов.
pub fn write_channel_exclude(domains: &[String]) -> Result<usize, String> {
    let path = lists_dir().join("defaults").join("channel-exclude.txt");
    let mut body = String::from(
        "# Генерируется routing.rs при переключении канала/режимов — НЕ РЕДАКТИРОВАТЬ.\n",
    );
    for d in domains {
        body.push_str(d);
        body.push('\n');
    }
    fs::write(&path, body).map_err(|e| format!("channel-exclude.txt не пишется: {e}"))?;
    Ok(domains.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes(dpi: DpiMode, geo: GeoMode, route: RouteMode) -> RoutingModes {
        RoutingModes { dpi_mode: dpi, geo_mode: geo, route_mode: route }
    }

    fn set(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// tmp-каталог тестов: fs::write не создаёт родителей, каталог обязателен.
    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join("dpi_gui_routing_test");
        fs::create_dir_all(&d).expect("tmp-каталог тестов создаётся");
        d
    }

    // ---------- load/save режимов ----------

    #[test]
    fn missing_modes_file_gives_defaults() {
        let tmp = std::env::temp_dir().join("dpi_gui_routing_test");
        let f = tmp.join("absent-routing.json");
        let _ = fs::remove_file(&f);
        let m = load_modes_from(&f).unwrap();
        // Дефолт 21.11.26: ютуб-группа в канал (вшит во все каналы; при
        // канале off остаётся в winws-хостлисте — обход сохраняется).
        assert_eq!(m.dpi_mode, DpiMode::Channel);
        assert_eq!(m.geo_mode, GeoMode::Channel);
        assert_eq!(m.route_mode, RouteMode::Selective);
    }

    #[test]
    fn modes_roundtrip() {
        let tmp = tmp_dir();
        let f = tmp.join("routing.json");
        save_modes_to(&f, &modes(DpiMode::Channel, GeoMode::Direct, RouteMode::FullPort)).unwrap();
        let m = load_modes_from(&f).unwrap();
        assert_eq!(m.dpi_mode, DpiMode::Channel);
        assert_eq!(m.geo_mode, GeoMode::Direct);
        assert_eq!(m.route_mode, RouteMode::FullPort);
    }

    #[test]
    fn broken_or_unknown_modes_are_honest_errors() {
        let tmp = tmp_dir();
        let f = tmp.join("routing-bad.json");
        fs::write(&f, "{битый").unwrap();
        assert!(load_modes_from(&f).is_err());
        fs::write(&f, r#"{"dpi_mode":"что-то"}"#).unwrap();
        assert!(load_modes_from(&f).is_err());
    }

    // ---------- парсинг списков ----------

    #[test]
    fn domains_file_strips_comments_and_dupes_keeps_caret() {
        let tmp = tmp_dir();
        let f = tmp.join("list.txt");
        fs::write(&f, "# коммент\n\ngooglevideo.com\n^dns.google\nGOOGLEVIDEO.COM\n  youtube.com  \n")
            .unwrap();
        assert_eq!(
            load_domains_file(&f),
            set(&["googlevideo.com", "^dns.google", "youtube.com"])
        );
    }

    // ---------- node_domains_from_yaml ----------

    #[test]
    fn node_domains_skip_ips_and_placeholders() {
        let yaml = "proxies:\n  - name: a\n    server: node.example.com\n  - name: b\n    server: 1.2.3.4\n  - name: c\n    server: \"__PRIVATE__\"\n    sni: cdn.example.org\n    server-name: reality.name.net\n    servername: 'Quoted.Host'\n    server: host:8443\n";
        assert_eq!(
            node_domains_from_yaml(yaml),
            set(&["node.example.com", "cdn.example.org", "reality.name.net", "quoted.host", "host"])
        );
    }

    // ---------- компиляция ----------

    #[test]
    fn channel_off_yields_empty_artifacts_and_direct_pac() {
        let m = modes(DpiMode::Winws, GeoMode::Channel, RouteMode::Selective);
        let a = compile(&m, &[], &set(&["aistudio.google.com"]), false, None, &[], 7897);
        assert!(a.channel_exclude.is_empty());
        assert!(a.mihomo_rules.is_empty());
        assert!(a.pac_script.contains("return \"DIRECT\";"));
        assert!(!a.pac_script.contains("PROXY"));
    }

    #[test]
    fn geo_channel_produces_exclude_rules_and_pac() {
        let m = modes(DpiMode::Winws, GeoMode::Channel, RouteMode::Selective);
        let a = compile(
            &m,
            &[],
            &set(&["aistudio.google.com", "firefly.adobe.com"]),
            true,
            Some("PROTON-WG"),
            &set(&["node.example.com"]),
            7897,
        );
        // exclude = geo + ноды
        assert!(a.channel_exclude.contains(&"aistudio.google.com".to_string()));
        assert!(a.channel_exclude.contains(&"node.example.com".to_string()));
        // rules: geo → outbound, dpi (winws) НЕ в rules, хвост MATCH,DIRECT
        assert!(a.mihomo_rules.contains(&"- DOMAIN-SUFFIX,aistudio.google.com,PROTON-WG".to_string()));
        assert!(!a.mihomo_rules.iter().any(|r| r.contains("googlevideo")));
        assert_eq!(a.mihomo_rules.last().unwrap(), "- MATCH,DIRECT");
        // pac: только geo в PROXY, с защитой от suffix-ложки
        assert!(a.pac_script.contains("dnsDomainIs(host, \".aistudio.google.com\")"));
        assert!(a.pac_script.contains("PROXY 127.0.0.1:7897; DIRECT"));
        assert!(!a.pac_script.contains("googlevideo"));
    }

    #[test]
    fn dpi_channel_moves_youtube_into_channel_artifacts() {
        let m = modes(DpiMode::Channel, GeoMode::Channel, RouteMode::Selective);
        let a = compile(&m, &set(&["discord.com"]), &[], true, Some("PROTON-WG"), &[], 7897);
        assert!(a.channel_exclude.contains(&"discord.com".to_string()));
        assert!(a.mihomo_rules.contains(&"- DOMAIN-SUFFIX,discord.com,PROTON-WG".to_string()));
        assert!(a.pac_script.contains("discord.com"));
    }

    #[test]
    fn dpi_direct_excludes_group_everywhere() {
        let m = modes(DpiMode::Direct, GeoMode::Direct, RouteMode::Selective);
        let a = compile(&m, &set(&["discord.com"]), &set(&["aistudio.google.com"]), true, Some("OUT"), &[], 7897);
        // Direct-группы не идут ни в exclude, ни в rules, ни в PAC
        assert!(a.channel_exclude.is_empty());
        assert_eq!(a.mihomo_rules, vec!["- MATCH,DIRECT".to_string()]);
        assert!(!a.pac_script.contains("PROXY"));
    }

    #[test]
    fn fullport_is_single_match_rule() {
        let m = modes(DpiMode::Winws, GeoMode::Channel, RouteMode::FullPort);
        let a = compile(&m, &[], &set(&["aistudio.google.com"]), true, Some("PROTON-WG"), &[], 7897);
        assert_eq!(a.mihomo_rules, vec!["- MATCH,PROTON-WG".to_string()]);
        // exclude всё равно содержит channel-домены: они идут через узел
        assert!(a.channel_exclude.contains(&"aistudio.google.com".to_string()));
    }

    #[test]
    fn wildcard_skipped_in_rules_matched_in_pac_caret_is_exact() {
        let m = modes(DpiMode::Winws, GeoMode::Channel, RouteMode::Selective);
        let a = compile(
            &m,
            &[],
            &set(&["*.tunnel.example", "^exact.example"]),
            true,
            Some("OUT"),
            &[],
            7897,
        );
        assert!(a.mihomo_rules.iter().any(|r| r.contains("# маска не поддерживается")));
        assert!(a.mihomo_rules.contains(&"- DOMAIN,exact.example,OUT".to_string()));
        assert!(a.pac_script.contains("shExpMatch(host, \"*.tunnel.example\")"));
        assert!(a.pac_script.contains("host === \"exact.example\""));
    }

    #[test]
    fn paid_channel_gets_no_generated_rules() {
        let m = modes(DpiMode::Winws, GeoMode::Channel, RouteMode::Selective);
        let a = compile(&m, &[], &set(&["aistudio.google.com"]), true, None, &[], 7897);
        // Платный yaml: правила юзера не трогаем, но exclude/PAC работают
        assert!(a.mihomo_rules.is_empty());
        assert!(a.channel_exclude.contains(&"aistudio.google.com".to_string()));
        assert!(a.pac_script.contains("PROXY 127.0.0.1:7897; DIRECT"));
    }

    // write_channel_exclude — тонкая обёртка fs::write в реальный AppData:
    // в тестах НЕ вызывается (перезаписал бы файл живого приложения).
}
