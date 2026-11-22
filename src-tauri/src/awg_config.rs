//! Генераторы конфигов каналов AWG и Proton-over-AWG (шаблоны defaults/, SSOT).
//! Эталоны — проверенные живьём 20.11.26 конфиги (temp/proton_test/): awg_hel.yaml
//! (порт 7908, ютуб 15-18 МБ/с на HEL-эндпоинтах) и proton_over_awg.yaml (7909,
//! loc=NL). Квирки (НЕ УБИРАТЬ — каждая обойдена кровью):
//!  - i1 — ШАБЛОН-НОТАЦИЯ warpscout `<b 0x..><r N>`: mihomo v1.19.34 (amnezia
//!    device_v1) парсит i1 только как junk-генератор через ParseTagJunkGenerator;
//!    голый hex mihomo отвергает («IPC error -22: invalid i1: empty input»);
//!  - НЕ добавлять remote-dns-resolve/dns ВНУТРЬ wireguard-outbound: userspace
//!    L3-стек AWG домены сам не резолвит (проверено 20.11: dns resolve failed);
//!    warpscout-шаблон это поле несёт — генератор его НЕ копирует;
//!  - DoH только top-level: голый udp 8.8.8.8:53 от Дом.ру травит ютуб-домены;
//!  - allowed-ips '0.0.0.0/0' + persistent-keepalive 25 — как в эталоне.

use std::path::PathBuf;

use crate::awg::AwgAccount;
use crate::proxy_core;
use crate::reserve::WgCreds;

/// i1 junk-генератор QUIC (warpscout find-junk; проверен 20.11.26 — ютуб жив).
const I1_QUIC: &str = "<b 0xc00000000101220000405b487778fe500caf8501eb7e9fae869cc97d2febfd><r 23><b 0x19fa2f32358494c5a515120377dca785caf32f83f63776d910e64e95210ee313><r 16>";

// Junk-константы amnezia — как в проверенном awg_hel.yaml (эталон, не менять).
const AWG_JC: u32 = 6;
const AWG_JMIN: u32 = 10;
const AWG_JMAX: u32 = 50;
const AWG_S1: u32 = 0;
const AWG_S2: u32 = 0;
const AWG_H1: u32 = 1;
const AWG_H2: u32 = 2;
const AWG_H3: u32 = 3;
const AWG_H4: u32 = 4;

/// Лимит эндпоинтов в конфиге: fallback-группа держит trace-пробу на каждом
/// (interval 300), 6 хватит с запасом — первый (8.39.125.77:4500) проверен
/// живьём (2мс коннект).
const MAX_AWG_ENDPOINTS: usize = 6;

/// Парсинг списка эндпоинтов: строки `ip:port`, пустые и #-комментарии пропускаются,
/// мусорные строки отбрасываются (порт не число / пустой ip).
pub(crate) fn parse_endpoints(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| match l.rsplit_once(':') {
            Some((ip, port)) => !ip.is_empty() && port.parse::<u16>().is_ok(),
            None => false,
        })
        .map(|l| l.to_string())
        .collect()
}

/// Один AWG-outbound (формат — точная копия проверенного awg_hel.yaml).
fn awg_outbound(idx: usize, ep: &str, account: &AwgAccount) -> Option<String> {
    let (server, port) = ep.rsplit_once(':')?;
    Some(format!(
        "  - name: \"AWG {idx}\"\n    type: wireguard\n    private-key: {pk}\n    ip: {ip}\n    peers:\n      - server: {server}\n        port: {port}\n        public-key: {peer}\n        allowed-ips: ['0.0.0.0/0']\n        persistent-keepalive: 25\n    amnezia-wg-option:\n      jc: {jc}\n      jmin: {jmin}\n      jmax: {jmax}\n      s1: {s1}\n      s2: {s2}\n      h1: {h1}\n      h2: {h2}\n      h3: {h3}\n      h4: {h4}\n      i1: {i1}\n    udp: true\n",
        idx = idx,
        pk = account.private_key,
        ip = account.ipv4,
        server = server,
        port = port,
        peer = account.peer_public_key,
        jc = AWG_JC,
        jmin = AWG_JMIN,
        jmax = AWG_JMAX,
        s1 = AWG_S1,
        s2 = AWG_S2,
        h1 = AWG_H1,
        h2 = AWG_H2,
        h3 = AWG_H3,
        h4 = AWG_H4,
        i1 = I1_QUIC,
    ))
}

/// PROTON-outbound (формат — точная копия проверенного proton_over_awg.yaml):
/// UDP-в-UDP через dialer-proxy на группу AWG — без TCP-in-TCP meltdown.
fn proton_outbound(c: &WgCreds) -> String {
    let mut s = format!(
        "  - name: PROTON\n    type: wireguard\n    server: {server}\n    port: {port}\n    private-key: \"{pk}\"\n    public-key: \"{pub_}\"\n    ip: {addr}\n    mtu: 1280\n    udp: true\n    dialer-proxy: \"AWG WARP\"\n",
        server = c.server,
        port = c.port,
        pk = c.private_key,
        pub_ = c.public_key,
        addr = c.address,
    );
    if let Some(psk) = &c.psk {
        s.push_str(&format!("    preshared-key: \"{}\"\n", psk));
    }
    s
}

/// Блок proxies: N AWG-outbound'ов (общие ключи учётки, разные server/port) +
/// опциональный PROTON. MAX_AWG_ENDPOINTS — жёсткий потолок.
pub(crate) fn build_proxies_block(
    endpoints: &[String],
    account: &AwgAccount,
    proton: Option<&WgCreds>,
) -> Result<String, String> {
    if endpoints.is_empty() {
        return Err(String::from("Список AWG-эндпоинтов пуст"));
    }
    let mut block = String::new();
    for (i, ep) in endpoints.iter().take(MAX_AWG_ENDPOINTS).enumerate() {
        match awg_outbound(i + 1, ep, account) {
            Some(b) => block.push_str(&b),
            None => {
                return Err(format!("Кривая строка эндпоинта (ожидался ip:port): {}", ep));
            }
        }
    }
    if let Some(c) = proton {
        block.push_str(&proton_outbound(c));
    }
    Ok(block)
}

/// Строка members для fallback-группы: `["AWG 1", "AWG 2", ...]`.
pub(crate) fn group_members(n: usize) -> String {
    let items: Vec<String> = (1..=n).map(|i| format!("\"AWG {}\"", i)).collect();
    format!("[{}]", items.join(", "))
}

/// Сборка полного конфига из шаблона: подстановка блока + хвост rules из
/// компилятора групп (routing.rs): ПЕРВОЕ правило — trace (критерий гарда),
/// дальше компиляторные с 2-пробельным отступом (инцидент 02:33). Паттерн
/// warp.rs::generate_warp_config / psiphon.rs::generate_psiphon_config.
fn assemble(
    tpl: &str,
    proxies_block: &str,
    members: &str,
    target: &str,
) -> Result<String, String> {
    let mut out = tpl
        .replace("__PROXIES_BLOCK__", proxies_block)
        .replace("__GROUP_MEMBERS__", members);
    let modes = crate::routing::load_modes()?;
    let art = crate::routing::compile_from_fs(
        &modes,
        true,
        Some(target),
        &[],
        proxy_core::PROXY_PORT,
    )?;
    let mut lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();
    let Some(ri) = lines.iter().position(|l| l.trim() == "rules:") else {
        return Err(format!("Шаблон AWG: не найдена секция rules (target {})", target));
    };
    lines.truncate(ri);
    lines.push(String::from("rules:"));
    lines.push(format!("  - DOMAIN,www.cloudflare.com,{}", target));
    lines.extend(art.mihomo_rules.iter().map(|r| format!("  {}", r)));
    out = lines.join("\n") + "\n";
    if !out.contains(&format!("DOMAIN,www.cloudflare.com,{}", target)) {
        return Err(format!("Сборка AWG: trace-правило не вшилось (target {})", target));
    }
    Ok(out)
}

/// Конфиг AWG-канала → proxy_dir/awg_profile.yaml.
pub fn generate_awg_config() -> Result<PathBuf, String> {
    let account = crate::awg::load_account()
        .ok_or_else(|| String::from("Нет AWG-учётки — нажми «Зарегистрировать» в карточке канала"))?;
    let endpoints = crate::awg::current_endpoints()?;
    let block = build_proxies_block(&endpoints, &account, None)?;
    let tpl = include_str!("../defaults/awg_template.yaml");
    let n = endpoints.len().min(MAX_AWG_ENDPOINTS);
    let text = assemble(tpl, &block, &group_members(n), "AWG WARP")?;
    write_profile(proxy_core::proxy_dir().join("awg_profile.yaml"), &text)
}

/// Конфиг Proton-over-AWG → proxy_dir/pawg_profile.yaml. Требует и AWG-учётку
/// (такси-слой), и WG-креды Proton (туннель).
pub fn generate_pawg_config() -> Result<PathBuf, String> {
    let account = crate::awg::load_account()
        .ok_or_else(|| String::from("Нет AWG-учётки — Proton-over-AWG строится поверх AWG-канала"))?;
    let creds = crate::reserve::load_creds()
        .ok_or_else(|| String::from("Нет WG-кредов Proton — сначала настрой Запасной канал"))?;
    let endpoints = crate::awg::current_endpoints()?;
    let block = build_proxies_block(&endpoints, &account, Some(&creds))?;
    let tpl = include_str!("../defaults/awg_template.yaml");
    let n = endpoints.len().min(MAX_AWG_ENDPOINTS);
    let text = assemble(tpl, &block, &group_members(n), "PROTON")?;
    write_profile(proxy_core::proxy_dir().join("pawg_profile.yaml"), &text)
}

fn write_profile(path: PathBuf, text: &str) -> Result<PathBuf, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не создать {}: {}", parent.display(), e))?;
    }
    std::fs::write(&path, text).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(path)
}

/// Текстовый гейт AWG-конфига перед стартом mihomo (образец validate_reserve_config):
/// порт SSOT, amnezia-блок и шаблон-нотация i1 на месте, плейсхолдеров нет,
/// remote-dns-resolve внутрь outbound не просочился.
pub fn validate_awg_config() -> Result<PathBuf, String> {
    let path = proxy_core::proxy_dir().join("awg_profile.yaml");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Нет awg-профиля {} — сгенерируй конфиг канала", path.display()))?;
    check_awg_text(&path.display().to_string(), &text, false)?;
    Ok(path)
}

/// Текстовый гейт pawg-конфига: то же + dialer-proxy и PROTON-outbound.
pub fn validate_pawg_config() -> Result<PathBuf, String> {
    let path = proxy_core::proxy_dir().join("pawg_profile.yaml");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Нет pawg-профиля {} — сгенерируй конфиг канала", path.display()))?;
    check_awg_text(&path.display().to_string(), &text, true)?;
    Ok(path)
}

fn check_awg_text(display: &str, text: &str, with_proton: bool) -> Result<(), String> {
    // Все проверки — только по реальному YAML: полные строки-комментарии
    // отрезаются перед contains. Шаблон сам несёт доку-комментарий «НЕ
    // добавлять remote-dns-resolve…» и «плейсхолдеры __...__» — contains по
    // сырому тексту ловил собственную доку шаблона и гарантированно валил
    // каждый свежий профиль (инцидент 22.11.26: awg/pawg невозможно включить).
    let code = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if !code.contains(&format!("mixed-port: {}", proxy_core::PROXY_PORT)) {
        return Err(format!(
            "{}: ожидался mixed-port: {} — файл не тот?",
            display,
            proxy_core::PROXY_PORT
        ));
    }
    for marker in ["type: wireguard", "amnezia-wg-option:", "i1: <b 0x"] {
        if !code.contains(marker) {
            return Err(format!("{}: нет маркера «{}» — конфиг не AWG-профиля", display, marker));
        }
    }
    if code.contains("remote-dns-resolve") {
        return Err(format!(
            "{}: remote-dns-resolve внутри AWG-outbound ломает канал (dns resolve failed) — перегенерируй конфиг",
            display
        ));
    }
    if code.contains("__") {
        return Err(format!(
            "{}: остались плейсхолдеры — учётка/эндпоинты подставились не полностью",
            display
        ));
    }
    if with_proton {
        for marker in ["dialer-proxy: \"AWG WARP\"", "name: PROTON", "mtu: 1280"] {
            if !code.contains(marker) {
                return Err(format!("{}: нет маркера «{}» — PROTON-outbound не на месте", display, marker));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Фейковая учётка для тестов генераторов: ключи-заглушки (валидная длина
    // b64, содержимое — мусор). Секретов в тестах быть не должно.
    fn dummy_account() -> AwgAccount {
        AwgAccount {
            id: String::from("test-id"),
            token: String::from("fake-token"),
            private_key: String::from("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq="),
            peer_public_key: String::from("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
            ipv4: String::from("172.16.0.2"),
            ipv6: String::new(),
            source: String::from("test"),
        }
    }

    fn dummy_creds() -> WgCreds {
        WgCreds {
            private_key: String::from("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr="),
            public_key: String::from("sssssssssssssssssssssssssssssssssssssssssss="),
            server: String::from("185.107.56.22"),
            port: 51820,
            address: String::from("10.2.0.2/32"),
            keepalive: 25,
            psk: None,
        }
    }

    #[test]
    fn test_parse_endpoints_filters_junk() {
        let text = "# комментарий\n8.39.125.77:4500\n\nмусор\n8.39.125.77:abc\n:2408\n  8.47.69.204:500  \n";
        let v = parse_endpoints(text);
        assert_eq!(v, vec![
            String::from("8.39.125.77:4500"),
            String::from("8.47.69.204:500"),
        ]);
    }

    #[test]
    fn test_proxies_block_two_outbounds() {
        let eps = vec![
            String::from("8.39.125.77:4500"),
            String::from("162.159.192.62:1701"),
        ];
        let block = build_proxies_block(&eps, &dummy_account(), None).unwrap();
        assert!(block.contains("name: \"AWG 1\""));
        assert!(block.contains("name: \"AWG 2\""));
        assert!(!block.contains("AWG 3"));
        // шаблон-нотация i1 жива, udp на месте
        assert!(block.contains("i1: <b 0x"));
        assert!(block.contains("udp: true"));
        // отступы yaml: ровно 4 пробела у полей (инцидент \x20-продолжений), не 5
        assert!(block.contains("\n    type: wireguard"));
        assert!(!block.contains("\n     type"));
        // квирка: remote-dns-resolve внутрь AWG не едет
        assert!(!block.contains("remote-dns-resolve"));
        // ключи учётки подставились
        assert!(block.contains("private-key: qqqqqq"));
        assert!(block.contains("server: 8.39.125.77"));
        assert!(block.contains("port: 4500"));
        // разные эндпоинты — разные порты в пирах
        assert!(block.contains("port: 1701"));
    }

    #[test]
    fn test_proxies_block_proton() {
        let eps = vec![String::from("8.39.125.77:4500")];
        let block = build_proxies_block(&eps, &dummy_account(), Some(&dummy_creds())).unwrap();
        assert!(block.contains("name: PROTON"));
        assert!(block.contains("dialer-proxy: \"AWG WARP\""));
        assert!(block.contains("mtu: 1280"));
        assert!(block.contains("ip: 10.2.0.2/32"));
        assert!(block.contains("server: 185.107.56.22"));
        assert!(block.contains("port: 51820"));
        // psk отсутствует — preshared-key не пишется
        assert!(!block.contains("preshared-key"));
    }

    #[test]
    fn test_proxies_block_empty_endpoints_is_error() {
        let res = build_proxies_block(&[], &dummy_account(), None);
        assert!(res.is_err());
    }

    #[test]
    fn test_group_members_flow() {
        assert_eq!(group_members(2), String::from("[\"AWG 1\", \"AWG 2\"]"));
        assert_eq!(group_members(1), String::from("[\"AWG 1\"]"));
    }

    #[test]
    fn test_proxies_block_caps_at_max() {
        // 10 эндпоинтов → в блоке ровно MAX (6): AWG 7 не существует
        let eps: Vec<String> = (1..=10).map(|i| format!("10.0.0.{}:4500", i)).collect();
        let block = build_proxies_block(&eps, &dummy_account(), None).unwrap();
        assert!(block.contains("name: \"AWG 6\""));
        assert!(!block.contains("name: \"AWG 7\""));
    }

    // Собранный из РЕАЛЬНОГО шаблона профиль (с докой-комментарием «НЕ
    // добавлять remote-dns-resolve…» и «плейсхолдеры __...__» в шапке)
    // обязан проходить валидацию. Инцидент 22.11.26: contains по сырому
    // тексту ловил эти комментарии и awg/pawg нельзя было включить.
    fn assemble_pawg_like(block_tail: &str) -> String {
        let eps = vec![String::from("8.39.125.77:4500")];
        let mut block = build_proxies_block(&eps, &dummy_account(), Some(&dummy_creds())).unwrap();
        block.push_str(block_tail);
        include_str!("../defaults/awg_template.yaml")
            .replace("__PROXIES_BLOCK__", &block)
            .replace("__GROUP_MEMBERS__", &group_members(1))
    }

    #[test]
    fn test_check_awg_text_template_comments_do_not_fail() {
        let text = assemble_pawg_like("");
        check_awg_text("тест", &text, true)
            .expect("дока-комментарии шаблона не должны валить валидацию awg/pawg");
    }

    #[test]
    fn test_check_awg_text_catches_real_remote_dns_resolve() {
        let text = assemble_pawg_like("\n    remote-dns-resolve: true");
        let err = check_awg_text("тест", &text, true).unwrap_err();
        assert!(err.contains("remote-dns-resolve"), "ловим только РЕАЛЬНЫЙ ключ, не комментарий: {}", err);
    }

    #[test]
    fn test_check_awg_text_catches_placeholder_in_code() {
        let text = assemble_pawg_like("\n    private-key: __PRIVATE_KEY__");
        let err = check_awg_text("тест", &text, true).unwrap_err();
        assert!(err.contains("плейсхолдеры"), "{}", err);
    }
}
