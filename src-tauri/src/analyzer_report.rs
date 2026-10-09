use std::collections::HashSet;
use std::path::PathBuf;

use crate::analyzer_probe::Classification;
use crate::bypass_lists;
use crate::diagnostics_probe::DnsState;
use crate::site_probe::{self, Verdict as SiteVerdict};

/// Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅР°СЏ РёРЅС„РѕСЂРјР°С†РёСЏ РґР»СЏ РѕС‚С‡С‘С‚Р°, РЅРµ СЃРІСЏР·Р°РЅРЅР°СЏ СЃ РєР»Р°СЃСЃРёС„РёРєР°С†РёРµР№ РґРѕРјРµРЅРѕРІ.
pub struct ReportMeta {
    pub target_url: String,
    pub discovered: Vec<String>,
    pub bypass_on: bool,
    /// РћР±С…РѕРґ Р±С‹Р» РІСЂРµРјРµРЅРЅРѕ РІС‹РєР»СЋС‡РµРЅ РґР»СЏ РїРѕРІС‚РѕСЂРЅРѕР№ РїСЂРѕР±С‹ (РґРІСѓС…С„Р°Р·РЅС‹Р№ Р°РЅР°Р»РёР·).
    pub bypass_toggled: bool,
    /// РЎРѕРѕР±С‰РµРЅРёРµ Рѕ СЂРµР·СѓР»СЊС‚Р°С‚Рµ Р°РІС‚Рѕ-РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РѕР±С…РѕРґР° РїРѕСЃР»Рµ Р°РЅР°Р»РёР·Р° (РµСЃР»Рё Р±С‹Р»Рѕ).
    pub restore_note: Option<String>,
    /// Р’ Р±СЂР°СѓР·РµСЂРµ С„РёРєСЃРёСЂРѕРІР°Р»РёСЃСЊ РѕР±СЂС‹РІС‹ (LoadingFailed) вЂ” РІРѕР·РјРѕР¶РµРЅ С‚СЂР°С„РёРє РїРѕ IP/WebSocket.
    pub had_browser_failures: bool,
    /// Р”РёР°РіРЅРѕСЃС‚РёРєР° РіР»Р°РІРЅРѕРіРѕ РґРѕРјРµРЅР° (DNS/СЂР°Р±РѕС‡РёР№ IP/РїРµСЂРІРѕРїСЂРёС‡РёРЅР°).
    pub main_probe: Option<site_probe::DomainProbe>,
    /// РђРІС‚РѕРїСЂРѕРІРµСЂРєР° В«РїРѕРґРјРµРЅС‹ DNSВ» РґР»СЏ РіР»Р°РІРЅРѕРіРѕ РґРѕРјРµРЅР° (РїСѓСЃС‚Рѕ, РµСЃР»Рё СЃР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ).
    pub main_dns_sub: Vec<site_probe::DnsSubstitution>,
    /// РџСЂРѕРІРµСЂРєР° РїРѕРґРјРµРЅС‹ DNS РґР»СЏ РґРѕРјРµРЅРѕРІ РёР· СЃРїРёСЃРєР° В«РЅРµ СЂРµР·РѕР»РІРёС‚СЃСЏВ» (РґРѕ 5).
    pub dns_fail_sub: Vec<(String, Vec<site_probe::DnsSubstitution>)>,
}

/// РџСѓС‚СЊ Рє РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРѕРјСѓ general-Р»РёСЃС‚Сѓ (РґР»СЏ РїРѕРґСЃРєР°Р·РѕРє В«РґРѕР±Р°РІСЊС‚Рµ РІ РѕР±С…РѕРґВ»).
fn general_list_path() -> String {
    crate::config::get_app_dir()
        .join("lists")
        .join("list-general.txt")
        .to_string_lossy()
        .replace("\\", "/")
}

fn is_builtin(p: &PathBuf) -> bool {
    p.to_string_lossy().replace("\\", "/").contains("default-bypass/")
}

pub fn build_report(meta: &ReportMeta, c: &Classification) -> String {
    let mut log = String::new();
    log.push_str(&format!("=== РђРќРђР›РР— Р”РћРњР•РќРћР’: {} ===\n\n", meta.target_url));

    // Р”РёР°РіРЅРѕР· РёРґС‘С‚ РџР•Р Р’Р«Рњ: РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ РґРѕР»Р¶РµРЅ СЃСЂР°Р·Сѓ РїРѕРЅСЏС‚СЊ РїСЂРёС‡РёРЅСѓ, Р° РЅРµ
    // РїСЂРѕРґРёСЂР°С‚СЊСЃСЏ С‡РµСЂРµР· РґРµС‚Р°Р»Рё, С‡С‚РѕР±С‹ РµС‘ РЅР°Р№С‚Рё.
    write_diagnosis(&mut log, meta);

    // Р¤Р°РєС‚С‹ РїРѕ РіР»Р°РІРЅРѕРјСѓ РґРѕРјРµРЅСѓ (DNS, IP, РјР°С‚СЂРёС†Р° РїСЂРѕР±).
    write_main_domain(&mut log, meta);

    // РђРІС‚РѕРїСЂРѕРІРµСЂРєР° РїРѕРґРјРµРЅС‹ DNS вЂ” РµСЃР»Рё РѕР±С‹С‡РЅС‹Р№ DNS РѕС‚СЂР°РІР»РµРЅ Рё СЃР°Р№С‚ РЅРµ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ.
    write_dns_substitution(&mut log, meta);

    log.push_str(&format!(
        "РћР±С…РѕРґ (winws) Р°РєС‚РёРІРµРЅ: {}\n",
        if meta.bypass_on { "Р”Рђ" } else { "РќР•Рў" }
    ));
    if !meta.bypass_on {
        log.push_str("вљ пёЏ РћР±С…РѕРґ Р’Р«РљР›Р®Р§Р•Рќ. Р§С‚РѕР±С‹ РЅР°Р№С‚Рё РґРѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ Р»РѕРјР°РµС‚ РѕР±С…РѕРґ, Р’РљР›Р®Р§РРўР• РїСЂРѕС„РёР»СЊ РѕР±С…РѕРґР° Рё Р·Р°РїСѓСЃС‚РёС‚Рµ Р°РЅР°Р»РёР· СЃРЅРѕРІР°.\n");
    }
    if meta.bypass_toggled {
        log.push_str("в„№пёЏ РћР±С…РѕРґ Р±С‹Р» РІСЂРµРјРµРЅРЅРѕ РІС‹РєР»СЋС‡РµРЅ РґР»СЏ РїРѕРІС‚РѕСЂРЅРѕР№ РїСЂРѕРІРµСЂРєРё (СЃСЂР°РІРЅРµРЅРёРµ В«СЃ РѕР±С…РѕРґРѕРј / Р±РµР· РѕР±С…РѕРґР°В»).\n");
    }
    if let Some(note) = &meta.restore_note {
        log.push_str(&format!("{}\n", note));
    }
    log.push_str(&format!("рџ”Ћ РћР±РЅР°СЂСѓР¶РµРЅРѕ РґРѕРјРµРЅРѕРІ: {}\n\n", meta.discovered.len()));

    // === Р”РѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ РќРЈР–РќРћ РґРѕР±Р°РІРёС‚СЊ РІ РѕР±С…РѕРґ (general-Р»РёСЃС‚) ===
    write_need_bypass(&mut log, c);

    // === Р”РѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ Р›РћРњРђР•Рў РѕР±С…РѕРґ (РІ РёСЃРєР»СЋС‡РµРЅРёСЏ) ===
    write_bypass_breaks(&mut log, c);

    // === Р”РѕРјРµРЅС‹, РЅРµРґРѕСЃС‚СѓРїРЅС‹Рµ РїСЂРё РІС‹РєР»СЋС‡РµРЅРЅРѕРј РѕР±С…РѕРґРµ (РїСЂРёС‡РёРЅР° РЅРµ СѓСЃС‚Р°РЅРѕРІР»РµРЅР°) ===
    write_broken(&mut log, meta, c);

    // === Р”РѕРјРµРЅС‹ СЃР°Р№С‚Р°, СѓР¶Рµ РІРЅРµСЃС‘РЅРЅС‹Рµ РІ РѕР±С…РѕРґ ===
    write_already_in_bypass(&mut log, meta, c);

    // === Р’РѕР·РјРѕР¶РЅРѕ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅС‹ РЅР° СѓСЂРѕРІРЅРµ Р Р¤ (DNS) ===
    if !c.dns_fail.is_empty() {
        log.push_str("вљ пёЏ Р’РћР—РњРћР–РќРћ Р—РђР‘Р›РћРљРР РћР’РђРќР« РќРђ РЈР РћР’РќР• Р Р¤ (РѕС€РёР±РєР° DNS):\n");
        for h in &c.dns_fail {
            log.push_str(&format!("  - {}\n", h));
        }
        if !meta.dns_fail_sub.is_empty() {
            log.push_str("  РџСЂРѕРІРµСЂРєР° РїРѕРґРјРµРЅС‹ DNS (DoH: xbox-dns.ru, geohide.ru):\n");
            for (h, subs) in &meta.dns_fail_sub {
                let ok = subs.iter().find(|s| s.http_ok);
                match ok {
                    Some(s) => log.push_str(&format!(
                        "    {} в†’ РїРѕРґРјРµРЅР° С‡РµСЂРµР· {} РќРђРЁР›Рђ РґРѕРјРµРЅ (IP {} РѕС‚РІРµС‡Р°РµС‚ РЅР° TCP:443)\n",
                        h,
                        s.service,
                        s.working_ip.as_ref().unwrap_or(&"-".to_string())
                    )),
                    None => log.push_str(&format!(
                        "    {} в†’ РїРѕРґРјРµРЅР° IP РЅРµ РЅР°С€Р»Р° (РґРѕРјРµРЅ СЂРµР°Р»СЊРЅРѕ РЅРµ СЂРµР·РѕР»РІРёС‚СЃСЏ)\n",
                        h
                    )),
                }
            }
        }
        log.push('\n');
    }

    log.push_str(&format!(
        "вњ… Р”РѕСЃС‚СѓРїРЅС‹Рµ (РЅРµ С‚СЂРµР±СѓСЋС‚ РёСЃРєР»СЋС‡РµРЅРёР№): {}\n\n",
        c.ok.len()
    ));

    log.push_str("рџ“‹ РџРѕР»РЅС‹Р№ СЃРїРёСЃРѕРє РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹С… РґРѕРјРµРЅРѕРІ:\n");
    if meta.discovered.is_empty() {
        log.push_str("  - (РЅРµ СѓРґР°Р»РѕСЃСЊ РѕР±РЅР°СЂСѓР¶РёС‚СЊ РЅРё РѕРґРЅРѕРіРѕ РґРѕРјРµРЅР° вЂ” РІРѕР·РјРѕР¶РЅРѕ, СЃР°Р№С‚ РЅРµРґРѕСЃС‚СѓРїРµРЅ С†РµР»РёРєРѕРј)\n");
    } else {
        for h in &meta.discovered {
            log.push_str(&format!("  - {}\n", h));
        }
    }

    // РћР±С‰Р°СЏ Р·Р°РјРµС‚РєР° РїСЂРѕ С‚СЂР°С„РёРє РїРѕ РіРѕР»С‹Рј IP / WebSocket.
    if meta.had_browser_failures && c.need_bypass.is_empty() && c.bypass_breaks.is_empty() {
        log.push_str("\nв„№пёЏ Р’ Р±СЂР°СѓР·РµСЂРµ Р±С‹Р»Рё РѕР±СЂС‹РІС‹ СЃРѕРµРґРёРЅРµРЅРёР№, РЅРѕ РґРѕРјРµРЅС‹-РєР°РЅРґРёРґР°С‚С‹ РЅРµ РІС‹СЏРІР»РµРЅС‹. Р§Р°СЃС‚СЊ С‚СЂР°С„РёРєР° СЃР°Р№С‚Р° РјРѕР¶РµС‚ РёРґС‚Рё РїРѕ РїСЂСЏРјС‹Рј IP-Р°РґСЂРµСЃР°Рј РёР»Рё WebSocket вЂ” С‚Р°РєРѕР№ С‚СЂР°С„РёРє РѕР±С…РѕРґ РїРѕ СЃРїРёСЃРєСѓ РґРѕРјРµРЅРѕРІ (hostlist) РЅРµ РїРѕРєСЂС‹РІР°РµС‚.\n");
    }

    log.push_str("\nрџ’Ў РЎРћР’Р•Рў: РґРѕРјРµРЅС‹ РёР· СЃРїРёСЃРєР° рџ›ЎпёЏ РґРѕР±Р°РІСЊС‚Рµ РІ СЃРїРёСЃРѕРє РѕР±С…РѕРґР° (general-Р»РёСЃС‚). Р”РѕРјРµРЅС‹ РёР· СЃРїРёСЃРєР° вќЊ (В«Р»РѕРјР°РµС‚ РѕР±С…РѕРґВ») РІРЅРµСЃРёС‚Рµ РІ СЃРїРёСЃРѕРє РёСЃРєР»СЋС‡РµРЅРёР№. Р”РѕРјРµРЅС‹ РёР· СЃРїРёСЃРєР° рџ—‘пёЏ СѓРґР°Р»СЏР№С‚Рµ РёР· РѕР±С…РѕРґР° С‚РѕР»СЊРєРѕ РµСЃР»Рё РѕРЅРё РїРѕРјРµС‡РµРЅС‹ В«Р›РћРњРђР•Рў РЎРђР™РўВ».");

    log
}

fn write_diagnosis(log: &mut String, meta: &ReportMeta) {
    let probe = match &meta.main_probe {
        Some(p) => p,
        None => return,
    };

    // Р•СЃР»Рё СЃР°Р№С‚ РѕС‚РєСЂС‹С‚ вЂ” РєРѕСЂРѕС‚РєРёР№ РїРѕРґС‚РІРµСЂР¶РґР°СЋС‰РёР№ Р±Р»РѕРє, Р±РµР· С€СѓРјР°.
    if probe.verdict == SiteVerdict::Open {
        log.push_str(&format!(
            "вњ… РЎРђР™Рў В«{}В» Р”РћРЎРўРЈРџР•Рќ вЂ” РґРѕРјРµРЅ Рё СЃРµС‚СЊ РІ РїРѕСЂСЏРґРєРµ ({}).\n\n",
            probe.host, probe.http_note
        ));
        return;
    }

    let diag = match &probe.diagnosis {
        Some(d) => d,
        None => return,
    };

    let icon = match probe.verdict {
        SiteVerdict::WwwOnly => "рџЊђ",
        SiteVerdict::DnsBlocked => "рџ”’",
        SiteVerdict::IpReset => "рџљ«",
        SiteVerdict::TlsBroken | SiteVerdict::BadCert => "рџ”ђ",
        SiteVerdict::BlockPage => "в›”",
        _ => "вљ пёЏ",
    };

    log.push_str(&format!(
        "{} Р’Р•Р РћРЇРўРќРђРЇ РџР РР§РРќРђ ({}):\n",
        icon,
        probe.verdict.verdict_name()
    ));
    log.push_str(&format!("  {}\n", diag.probable_cause));

    // Р§С‚Рѕ РґРµР»Р°С‚СЊ.
    if !diag.do_this.is_empty() {
        log.push_str("\n  вњ… Р§РўРћ РЎР”Р•Р›РђРўР¬:\n");
        for a in &diag.do_this {
            log.push_str(&format!("     вЂў {}\n", a));
        }
    }

    // Р§С‚Рѕ РќР• РїРѕРјРѕР¶РµС‚ вЂ” СЌРєРѕРЅРѕРјРёС‚ СЋР·РµСЂСѓ РІСЂРµРјСЏ РЅР° Р±РµСЃРїРѕР»РµР·РЅС‹Рµ РґРµР№СЃС‚РІРёСЏ.
    if !diag.wont_help.is_empty() {
        log.push_str("\n  вќЊ Р§РўРћ РќР• РџРћРњРћР–Р•Рў:\n");
        for a in &diag.wont_help {
            log.push_str(&format!("     вЂў {}\n", a));
        }
    }
    log.push('\n');
}

fn write_main_domain(log: &mut String, meta: &ReportMeta) {
    let probe = match &meta.main_probe {
        Some(p) => p,
        None => return,
    };

    if probe.verdict == SiteVerdict::Open {
        return;
    }

    let icon = match probe.verdict {
        SiteVerdict::WwwOnly => "рџЊђ",
        SiteVerdict::DnsBlocked => "рџ”’",
        SiteVerdict::IpReset => "рџљ«",
        SiteVerdict::TlsBroken => "рџ”ђ",
        SiteVerdict::BadCert => "рџ”ђ",
        SiteVerdict::BlockPage => "в›”",
        _ => "вљ пёЏ",
    };
    log.push_str(&format!(
        "{} Р“Р›РђР’РќР«Р™ Р”РћРњР•Рќ В«{}В» РќР• РћРўРљР Р«Р’РђР•РўРЎРЇ.\n",
        icon, probe.host
    ));

    // DNS-СЃС‚СЂРѕРєР°: СЂР°Р·Р»РёС‡Р°РµРј В«NXDOMAINВ», В«СЂРµР·РѕР»РІРµСЂ РЅРµ РѕС‚РІРµС‚РёР»В» Рё СЂРµР°Р»СЊРЅС‹Р№ СЃРїРёСЃРѕРє IP,
    // РёРЅР°С‡Рµ РїСѓСЃС‚РѕР№ РїСѓР±Р»РёС‡РЅС‹Р№ СЂРµР·РѕР»РІРµСЂ С‡РёС‚Р°РµС‚СЃСЏ РєР°Рє РѕС‚СЃСѓС‚СЃС‚РІРёРµ РґРѕРјРµРЅР°.
    let sys = dns_label(&probe.dns.system, probe.dns.system_state);
    let cf = dns_label(&probe.dns.cloudflare, probe.dns.cloudflare_state);
    let gg = dns_label(&probe.dns.google, probe.dns.google_state);
    log.push_str(&format!("  DNS (СЃРёСЃС‚РµРјР°):      {}\n", sys));
    log.push_str(&format!("  DNS (1.1.1.1):      {}\n", cf));
    log.push_str(&format!("  DNS (8.8.8.8):      {}\n", gg));
    log.push_str(&format!(
        "  DNS-С†РµРЅР·СѓСЂР°:        {}\n",
        if probe.dns_consistent {
            "РЅРµ РѕР±РЅР°СЂСѓР¶РµРЅР°"
        } else {
            "РџРћР”РћР—Р Р•РќРР• РќРђ Р¦Р•РќР—РЈР РЈ (СЃРёСЃС‚РµРјРЅС‹Р№ DNS СЂР°СЃС…РѕРґРёС‚СЃСЏ СЃ РїСѓР±Р»РёС‡РЅС‹РјРё)"
        }
    ));

    // Apex Рё www вЂ” Р РђР—РќР«Р• СЃС‚СЂРѕРєРё: РёС… СЂР°Р·Р»РёС‡РёРµ Рё РµСЃС‚СЊ РіР»Р°РІРЅР°СЏ РїРѕРґСЃРєР°Р·РєР°.
    let prim = if probe.primary_ips.is_empty() {
        "(РїСѓСЃС‚Рѕ)".to_string()
    } else {
        probe.primary_ips.join(", ")
    };
    log.push_str(&format!("  IP apex (СЃРёСЃС‚РµРјРЅС‹Р№ DNS): {}\n", prim));
    if let Some(wh) = &probe.www_host {
        let www = if probe.www_ips.is_empty() {
            "(РЅРµ СЂРµР·РѕР»РІРёС‚СЃСЏ)".to_string()
        } else {
            probe.www_ips.join(", ")
        };
        let status = match &probe.www_url {
            Some(u) => format!("РћРўРљР Р«Р’РђР•РўРЎРЇ: {}", u),
            None => "РЅРµ РѕС‚РІРµС‡Р°РµС‚".to_string(),
        };
        log.push_str(&format!("  IP www (СЃРёСЃС‚РµРјРЅС‹Р№ DNS):  {} вЂ” {}\n", www, status));
        log.push_str(&format!("  РРјСЏ РґР»СЏ РґРѕСЃС‚СѓРїР°:        {}\n", wh));
    }

    log.push_str(&format!("  РЎРѕРµРґРёРЅРµРЅРёРµ РіР»Р°РІРЅРѕРіРѕ IP:    {}\n", probe.http_note));
    if let Some(ip) = &probe.working_ip {
        let status = if probe.http_note.contains("RST") {
            "TCP:443 Р¶РёРІ, РЅРѕ HTTPS RST вЂ” Р±Р»РѕРє РїРѕ SNI/IP, РїРѕРґРјРµРЅР° РІ hosts РЅРµ РїРѕРјРѕР¶РµС‚"
        } else if probe.http_note.contains("С‚Р°Р№РјР°СѓС‚") || probe.http_note.contains("timeout") {
            "TCP:443 Р¶РёРІ, HTTPS С‚Р°Р№РјР°СѓС‚"
        } else {
            "TCP:443 Р¶РёРІ"
        };
        log.push_str(&format!("  Р Р°Р±РѕС‡РёР№ IP:          {} ({})\n", ip, status));
    } else {
        log.push_str("  Р Р°Р±РѕС‡РёР№ IP:          РЅРµ РЅР°Р№РґРµРЅ\n");
    }

    log.push('\n');
}

/// РўРµРєСЃС‚ СЃРѕСЃС‚РѕСЏРЅРёСЏ DNS-СЂРµР·РѕР»РІРµСЂР° РґР»СЏ РѕС‚С‡С‘С‚Р°.
fn dns_label(ips: &[std::net::IpAddr], state: DnsState) -> String {
    use std::net::IpAddr;
    match state {
        DnsState::Nxdomain => "NXDOMAIN вЂ” С‚Р°РєРѕРіРѕ РґРѕРјРµРЅР° РЅРµ СЃСѓС‰РµСЃС‚РІСѓРµС‚".to_string(),
        DnsState::Unreachable => "СЂРµР·РѕР»РІРµСЂ РЅРµ РѕС‚РІРµС‚РёР» (UDP:53 Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ РёР»Рё С‚Р°Р№РјР°СѓС‚)".to_string(),
        DnsState::Ok if ips.is_empty() => "РѕС‚РІРµС‚ РїСѓСЃС‚РѕР№".to_string(),
        DnsState::Ok => ips.iter().map(|i: &IpAddr| i.to_string()).collect::<Vec<_>>().join(", "),
    }
}

fn write_dns_substitution(log: &mut String, meta: &ReportMeta) {
    if meta.main_dns_sub.is_empty() {
        return;
    }
    let host = meta.main_probe.as_ref().map(|p| p.host.clone()).unwrap_or_default();

    log.push_str("рџ”Ѓ РџР РћР’Р•Р РљРђ РџРћР”РњР•РќР« DNS (РѕР±С…РѕРґ РѕС‚СЂР°РІР»РµРЅРЅРѕРіРѕ DNS С‡РµСЂРµР· DoH):\n");
    for sub in &meta.main_dns_sub {
        if sub.http_ok {
            log.push_str(&format!("  вњ… {} вЂ” {}\n", sub.service, sub.http_note));
        } else {
            if sub.resolved.is_empty() {
                log.push_str(&format!("  вќЊ {} вЂ” {}\n", sub.service, sub.http_note));
            } else {
                log.push_str(&format!(
                    "  вќЊ {} вЂ” {}. IP {} СЂРµР°Р»СЊРЅРѕ РЅРµ РѕС‚РєСЂС‹РІР°СЋС‚ HTTPS (RST/С‚Р°Р№РјР°СѓС‚ вЂ” Р±Р»РѕРє РїРѕ SNI, Р° РЅРµ DNS)\n",
                    sub.service,
                    sub.http_note,
                    sub.resolved.join(", ")
                ));
            }
        }
    }
    if let Some(sub) = meta.main_dns_sub.iter().find(|s| s.http_ok) {
        log.push_str("  в†’ РџРћР”РњР•РќРђ DNS Р РђР‘РћРўРђР•Рў. РЎР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С‡РµСЂРµР· СЂР°Р±РѕС‡РёР№ IP.\n");
        if !host.is_empty() {
            if let Some(ip) = &sub.working_ip {
                log.push_str("    Р”РѕР±Р°РІСЊС‚Рµ РІ hosts (C:\\Windows\\System32\\drivers\\etc\\hosts):\n");
                log.push_str(&format!("      {} {}\n", ip, host));
                log.push_str(&format!("      {} www.{}\n", ip, host));
            }
        }
        log.push_str("    Р—Р°С‚РµРј РІС‹РїРѕР»РЅРёС‚Рµ: ipconfig /flushdns\n");
    } else {
        // РќРµ СЃРѕРІРµС‚СѓРµРј hosts, РµСЃР»Рё РЅРё РѕРґРёРЅ IP РЅРµ РґР°Р» РІР°Р»РёРґРЅРѕРіРѕ HTTPS: РїРѕРґСЃРєР°Р·РєР°
        // В«РїСЂРѕРїРёС€РёС‚Рµ IP РІСЂСѓС‡РЅСѓСЋВ» Р±РµР· РґРѕРєР°Р·Р°РЅРЅРѕРіРѕ СЂР°Р±РѕС‡РµРіРѕ Р°РґСЂРµСЃР° Р±РµСЃРїРѕР»РµР·РЅР°.
        log.push_str("  в†’ РџРѕРґРјРµРЅР° DNS РЅРµ РїРѕРјРѕРіР»Р°: РЅРё РѕРґРёРЅ РёР· РЅР°Р№РґРµРЅРЅС‹С… IP РЅРµ РѕС‚РґР°Р» РІР°Р»РёРґРЅС‹Р№ HTTPS-РѕС‚РІРµС‚ РґР»СЏ СЌС‚РѕРіРѕ РёРјРµРЅРё.\n");
        log.push_str("    РЎРјРµРЅР° DNS Рё Р·Р°РїРёСЃСЊ РІ hosts С‚СѓС‚ РЅРµ РїРѕРјРѕРіСѓС‚ вЂ” РёС‰РёС‚Рµ РїСЂРёС‡РёРЅСѓ РІ Р±Р»РѕРєРµ В«Р’Р•Р РћРЇРўРќРђРЇ РџР РР§РРќРђВ» РІС‹С€Рµ.\n");
    }
    log.push('\n');
}

fn write_need_bypass(log: &mut String, c: &Classification) {
    log.push_str("рџ›ЎпёЏ Р”РћРњР•РќР«, РљРћРўРћР Р«Р• РќРЈР–РќРћ Р”РћР‘РђР’РРўР¬ Р’ РћР‘РҐРћР” (general-Р»РёСЃС‚):\n");
    if c.need_bypass.is_empty() {
        log.push_str("  - (РїСѓСЃС‚Рѕ) РЅРѕРІС‹С… РґРѕРјРµРЅРѕРІ РґР»СЏ РѕР±С…РѕРґР° РЅРµ РЅР°Р№РґРµРЅРѕ\n");
    } else {
        let bypass_map = bypass_lists::load_bypass_domains();
        let path = general_list_path();
        let mut parent_suggestions: Vec<String> = Vec::new();
        for h in &c.need_bypass {
            // Р•СЃР»Рё РґРѕРјРµРЅ СѓР¶Рµ РїРѕРєСЂС‹С‚ РѕР±С…РѕРґРѕРј (РЅР°РїСЂРёРјРµСЂ, СЂРѕРґРёС‚РµР»РµРј) вЂ” РЅРµ СЃРѕРІРµС‚СѓРµРј РґСѓР±Р»РёСЂРѕРІР°С‚СЊ.
            let already = !bypass_lists::find_bypass_matches(std::slice::from_ref(h), &bypass_map).is_empty();
            let parent = bypass_lists::parent_domain(h);
            let kind = if parent == h.to_lowercase() {
                "[РєРѕСЂРЅРµРІРѕР№ РґРѕРјРµРЅ]".to_string()
            } else {
                format!("[СЃСѓР±РґРѕРјРµРЅ, СЂРѕРґРёС‚РµР»СЊ: {}]", parent)
            };
            let action = if already {
                "СѓР¶Рµ РїРѕРєСЂС‹С‚ РѕР±С…РѕРґРѕРј вЂ” РЅРµ РґСѓР±Р»РёСЂСѓР№С‚Рµ".to_string()
            } else {
                if parent != h.to_lowercase() && !parent_suggestions.contains(&parent) {
                    parent_suggestions.push(parent.clone());
                }
                format!("РґРѕР±Р°РІСЊС‚Рµ РІ {}", path)
            };
            log.push_str(&format!("  - {}   {}   {}\n", h, kind, action));
        }
        if !parent_suggestions.is_empty() {
            parent_suggestions.sort();
            log.push_str(&format!(
                "  рџ’Ў Р РѕРґРёС‚РµР»СЊСЃРєРёРµ РґРѕРјРµРЅС‹ (winws РјР°С‚С‡РёС‚ РїРѕРґРґРѕРјРµРЅС‹, РјРѕР¶РЅРѕ СЃРѕРєСЂР°С‚РёС‚СЊ СЃРїРёСЃРѕРє): {}\n",
                parent_suggestions.join(", ")
            ));
        }
    }
    log.push('\n');
}

fn write_bypass_breaks(log: &mut String, c: &Classification) {
    log.push_str("вќЊ Р”РћРњР•РќР«, РљРћРўРћР Р«Р• Р›РћРњРђР•Рў РћР‘РҐРћР” (РґРѕР±Р°РІСЊС‚Рµ РІ РёСЃРєР»СЋС‡РµРЅРёСЏ):\n");
    if c.bypass_breaks.is_empty() {
        log.push_str("  - (РїСѓСЃС‚Рѕ) РѕР±С…РѕРґ РЅРµ Р»РѕРјР°РµС‚ РЅРё РѕРґРёРЅ РґРѕРјРµРЅ\n");
    } else {
        let exclude_set = bypass_lists::load_exclude_domains();
        let mut parent_suggestions: Vec<String> = Vec::new();
        for (h, err) in &c.bypass_breaks {
            let reason = err.lines().next().unwrap_or(err);
            let parent = bypass_lists::parent_domain(h);
            let kind = if parent == h.to_lowercase() {
                "[РєРѕСЂРЅРµРІРѕР№ РґРѕРјРµРЅ]".to_string()
            } else {
                format!("[СЃСѓР±РґРѕРјРµРЅ, СЂРѕРґРёС‚РµР»СЊ: {}]", parent)
            };
            let covered = bypass_lists::is_excluded(h, &exclude_set);
            let action = match covered {
                Some(entry) => format!("СѓР¶Рµ РІ РёСЃРєР»СЋС‡РµРЅРёСЏС…: {} вЂ” РЅРµ РґСѓР±Р»РёСЂСѓР№С‚Рµ", entry),
                None => {
                    if parent != h.to_lowercase() && !parent_suggestions.contains(&parent) {
                        parent_suggestions.push(parent.clone());
                    }
                    "РґРѕР±Р°РІСЊС‚Рµ РІ РёСЃРєР»СЋС‡РµРЅРёСЏ".to_string()
                }
            };
            log.push_str(&format!(
                "  - {}   (РїСЂРёС‡РёРЅР°: {})   {}   {}\n",
                h, reason, kind, action
            ));
        }
        if !parent_suggestions.is_empty() {
            parent_suggestions.sort();
            log.push_str(&format!(
                "  рџ’Ў Р РѕРґРёС‚РµР»СЊСЃРєРёРµ РґРѕРјРµРЅС‹ (winws РјР°С‚С‡РёС‚ РїРѕРґРґРѕРјРµРЅС‹, РјРѕР¶РЅРѕ СЃРѕРєСЂР°С‚РёС‚СЊ СЃРїРёСЃРѕРє): {}\n",
                parent_suggestions.join(", ")
            ));
        }
    }
    log.push('\n');
}

/// Р”РѕРјРµРЅС‹, РєРѕС‚РѕСЂС‹Рµ РЅРµ РѕС‚РєСЂС‹Р»РёСЃСЊ РїСЂРё Р’Р«РљР›Р®Р§Р•РќРќРћРњ РѕР±С…РѕРґРµ. РћС‚Р»РёС‡РёС‚СЊ В«Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ
/// СЃР°РјВ» РѕС‚ В«РѕР±С…РѕРґ РµРіРѕ Р»РѕРјР°РµС‚В» РІ СЌС‚РѕРј РїСЂРѕРіРѕРЅРµ РЅРµР»СЊР·СЏ, РїРѕСЌС‚РѕРјСѓ РЅРµ СЃРѕРІРµС‚СѓРµРј
/// РёСЃРєР»СЋС‡РµРЅРёСЏ вЂ” Р° РїСЂРѕСЃРёРј РїСЂРѕРіРЅР°С‚СЊ Р°РЅР°Р»РёР· СЃ РІРєР»СЋС‡С‘РЅРЅС‹Рј РїСЂРѕС„РёР»РµРј.
fn write_broken(log: &mut String, meta: &ReportMeta, c: &Classification) {
    if c.broken.is_empty() {
        return;
    }
    log.push_str("в›” РќР•Р”РћРЎРўРЈРџРќР«Р• Р”РћРњР•РќР« (РїСЂРёС‡РёРЅР° РЅРµ СѓСЃС‚Р°РЅРѕРІР»РµРЅР°):\n");
    for h in &c.broken {
        let parent = bypass_lists::parent_domain(h);
        let kind = if parent == h.to_lowercase() {
            "[РєРѕСЂРЅРµРІРѕР№ РґРѕРјРµРЅ]".to_string()
        } else {
            format!("[СЃСѓР±РґРѕРјРµРЅ, СЂРѕРґРёС‚РµР»СЊ: {}]", parent)
        };
        log.push_str(&format!("  - {}   {}\n", h, kind));
    }
    if meta.bypass_on {
        log.push_str("  в„№пёЏ РќРµ РѕС‚РєСЂС‹РІР°СЋС‚СЃСЏ РґР°Р¶Рµ СЃ РІРєР»СЋС‡С‘РЅРЅС‹Рј РѕР±С…РѕРґРѕРј вЂ” РЅРѕ Р±РµР· РѕР±С…РѕРґР° РЅРµ РїСЂРѕРІРµСЂСЏР»РёСЃСЊ.\n");
    } else {
        log.push_str("  в„№пёЏ РћР±С…РѕРґ Р±С‹Р» Р’Р«РљР›Р®Р§Р•Рќ, РїРѕСЌС‚РѕРјСѓ В«Р»РѕРјР°РµС‚ РѕР±С…РѕРґ РёР»Рё РґРѕРјРµРЅ СЃР°РјВ» вЂ” РЅРµРїРѕРЅСЏС‚РЅРѕ. Р’РєР»СЋС‡РёС‚Рµ РїСЂРѕС„РёР»СЊ РѕР±С…РѕРґР° Рё Р·Р°РїСѓСЃС‚РёС‚Рµ Р°РЅР°Р»РёР· СЃРЅРѕРІР°: С‚РѕРіРґР° СЃС‚Р°РЅРµС‚ РІРёРґРЅРѕ, С‡С‚Рѕ С‡РёРЅРёС‚СЊ (РѕР±С…РѕРґ РёР»Рё РёСЃРєР»СЋС‡РµРЅРёСЏ).\n");
    }
    log.push_str("  в„№пёЏ Р•СЃР»Рё С‚Р°РєРёРµ РґРѕРјРµРЅС‹ вЂ” РїРѕРґРґРѕРјРµРЅС‹ РІР°С€РµРіРѕ РіР»Р°РІРЅРѕРіРѕ РґРѕРјРµРЅР°, СЃРЅР°С‡Р°Р»Р° РїРѕСЃРјРѕС‚СЂРёС‚Рµ Р±Р»РѕРє В«Р’Р•Р РћРЇРўРќРђРЇ РџР РР§РРќРђВ» РІС‹С€Рµ: РІРѕР·РјРѕР¶РЅРѕ, Сѓ СЃР°Р№С‚Р° РїСЂРѕСЃС‚Рѕ РЅРµ РЅР°СЃС‚СЂРѕРµРЅС‹ Р°РґСЂРµСЃР° РґР»СЏ СЌС‚РёС… РёРјС‘РЅ.\n");
    log.push('\n');
}

fn write_already_in_bypass(log: &mut String, meta: &ReportMeta, c: &Classification) {
    let bypass_map = bypass_lists::load_bypass_domains();
    let bypass_matches = bypass_lists::find_bypass_matches(&meta.discovered, &bypass_map);
    let broken_set: HashSet<String> = c.bypass_breaks.iter().map(|(h, _)| h.clone()).collect();

    log.push_str("рџ—‘пёЏ Р”РћРњР•РќР« РЎРђР™РўРђ, РЈР–Р• Р’РќР•РЎРЃРќРќР«Р• Р’ РћР‘РҐРћР” (РїСЂРѕРІРµСЂСЊС‚Рµ, РЅРµ Р»РѕРјР°СЋС‚ Р»Рё РѕРЅРё СЃР°Р№С‚):\n");
    if bypass_matches.is_empty() {
        log.push_str("  - (РїСѓСЃС‚Рѕ) РЅРё РѕРґРёРЅ РґРѕРјРµРЅ СЃР°Р№С‚Р° РЅРµ РЅР°Р№РґРµРЅ РІ СЃРїРёСЃРєР°С… РѕР±С…РѕРґР°\n");
    } else {
        for (domain, files) in &bypass_matches {
            let also_broken = broken_set.contains(domain);
            let mut labels: Vec<String> = Vec::new();
            for f in files {
                let path = f.to_string_lossy().replace("\\", "/");
                if is_builtin(f) {
                    labels.push(format!("РІСЃС‚СЂРѕРµРЅРЅС‹Р№ СЃРїРёСЃРѕРє {}", path));
                } else {
                    labels.push(format!("СЃРїРёСЃРѕРє РѕР±С…РѕРґР° {}", path));
                }
            }
            if also_broken {
                log.push_str(&format!(
                    "  - {}   (РІ {} вЂ” Р›РћРњРђР•Рў РЎРђР™Рў, СѓРґР°Р»РёС‚Рµ РёР· РѕР±С…РѕРґР° РІ РїСЂРёРѕСЂРёС‚РµС‚Рµ!)\n",
                    domain,
                    labels.join(", ")
                ));
            } else if is_builtin(files.first().unwrap()) {
                log.push_str(&format!(
                    "  - {}   (РІ {} вЂ” РІСЃС‚СЂРѕРµРЅРЅС‹Р№, РїРµСЂРµР·Р°РїРёСЃС‹РІР°РµС‚СЃСЏ РїСЂРё Р·Р°РїСѓСЃРєРµ; СЂР°Р±РѕС‚Р°РµС‚, С‚СЂРѕРіР°С‚СЊ РЅРµ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ)\n",
                    domain,
                    labels.join(", ")
                ));
            } else {
                log.push_str(&format!(
                    "  - {}   (РІ {} вЂ” СЂР°Р±РѕС‚Р°РµС‚, С‚СЂРѕРіР°С‚СЊ РЅРµ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ)\n",
                    domain,
                    labels.join(", ")
                ));
            }
        }
    }
    log.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer_probe::Classification;
    use crate::diagnostics_probe::{DnsInfo, DnsState};
    use crate::site_probe::{CauseContext, DomainProbe, Verdict};

    fn empty_classification() -> Classification {
        Classification {
            need_bypass: Vec::new(),
            bypass_breaks: Vec::new(),
            dns_fail: Vec::new(),
            ok: Vec::new(),
            broken: Vec::new(),
        }
    }

    fn meta_with(probe: DomainProbe) -> ReportMeta {
        ReportMeta {
            target_url: "https://cactuscompute.com/blog/whistle".to_string(),
            discovered: vec!["cactuscompute.com".to_string()],
            bypass_on: true,
            bypass_toggled: false,
            restore_note: None,
            had_browser_failures: false,
            main_probe: Some(probe),
            main_dns_sub: Vec::new(),
            dns_fail_sub: Vec::new(),
        }
    }

    /// Apex DNS points at a dead IP; the site answers only under `www`.
    fn www_only_probe() -> DomainProbe {
        let host = "cactuscompute.com";
        let www_url = "https://www.cactuscompute.com/";
        let verdict = Verdict::WwwOnly;
        let diagnosis = crate::site_probe::explain(
            verdict,
            &CauseContext {
                host,
                www_url: Some(www_url),
                apex_ip: Some("216.150.1.1"),
                dns_consistent: true,
                same_host_alt_ip_works: false,
            },
        );
        let mut dns = DnsInfo::new();
        dns.system = vec!["216.150.1.1".parse().unwrap()];
        DomainProbe {
            host: host.to_string(),
            dns,
            dns_consistent: true,
            primary_ips: vec!["216.150.1.1".to_string()],
            working_ip: None,
            http_note: "TCP timeout".to_string(),
            verdict,
            www_host: Some("www.cactuscompute.com".to_string()),
            www_ips: vec!["216.150.16.65".to_string()],
            www_url: Some(www_url.to_string()),
            diagnosis: Some(diagnosis),
        }
    }

    /// The point of the change: the report must lead with the cause and must
    /// name the working `www` host instead of burying it.
    #[test]
    fn report_leads_with_cause_and_mentions_www() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        let cause_pos = log.find("Р’Р•Р РћРЇРўРќРђРЇ РџР РР§РРќРђ").expect(&log);
        let domains_pos = log.find("РќР• РћРўРљР Р«Р’РђР•РўРЎРЇ").expect(&log);
        assert!(cause_pos < domains_pos, "{}", log);
        assert!(log.contains("www.cactuscompute.com"), "{}", log);
        assert!(log.contains("https://www.cactuscompute.com/"), "{}", log);
        // The dead IP is named explicitly, so the user understands the cause.
        assert!(log.contains("216.150.1.1"), "{}", log);
        assert!(log.contains("Р§РўРћ РЎР”Р•Р›РђРўР¬"), "{}", log);
        assert!(log.contains("Р§РўРћ РќР• РџРћРњРћР–Р•Рў"), "{}", log);
    }

    /// The broken hosts advice must not survive anywhere in the report.
    #[test]
    fn report_does_not_advise_hosts_for_dead_apex_ip() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        assert!(!log.contains("System32\\drivers\\etc\\hosts"), "{}", log);
        assert!(!log.contains("ipconfig /flushdns"), "{}", log);
    }

    #[test]
    fn dead_domain_is_never_advised_for_bypass() {
        let c = Classification {
            broken: vec!["cactuscompute.com".to_string()],
            ..empty_classification()
        };
let log = build_report(&meta_with(www_only_probe()), &c);
        // The domain must not be pushed into the bypass list.
        assert!(
            !log.contains("list-general.txt"),
            "dead IP must not be advised for bypass: {}",
            log
        );
        assert!(log.contains("РќР•Р”РћРЎРўРЈРџРќР«Р• Р”РћРњР•РќР«"), "{}", log);
    }

    /// Unreachable public resolvers must be reported as such, not as "(empty)".
    #[test]
    fn unreachable_resolvers_are_not_empty_strings() {
        let mut p = www_only_probe();
        p.dns.cloudflare_state = DnsState::Unreachable;
        p.dns.google_state = DnsState::Unreachable;
let log = build_report(&meta_with(p), &empty_classification());
        // The DNS lines must explain the empty answer instead of showing "(РїСѓСЃС‚Рѕ)".
        let line = log
            .lines()
            .find(|l| l.contains("DNS (1.1.1.1)"))
            .expect("no cloudflare DNS line");
        assert!(line.contains("РЅРµ РѕС‚РІРµС‚РёР»"), "{}", line);
        assert!(!line.contains("(РїСѓСЃС‚Рѕ)"), "{}", line);
    }

    #[test]
    fn nxdomain_is_reported_as_nxdomain() {
        let mut p = www_only_probe();
        p.dns.cloudflare_state = DnsState::Nxdomain;
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("NXDOMAIN"), "{}", log);
    }

    #[test]
    fn open_site_gets_short_confirmation() {
        let mut p = www_only_probe();
        p.verdict = Verdict::Open;
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("Р”РћРЎРўРЈРџР•Рќ"), "{}", log);
        assert!(!log.contains("Р’Р•Р РћРЇРўРќРђРЇ РџР РР§РРќРђ"), "{}", log);
    }
}