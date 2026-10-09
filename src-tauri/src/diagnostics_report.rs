use std::collections::BTreeSet;
use crate::diagnostics_probe::DnsInfo;
use crate::diagnostics_techniques::TechniqueSpec;

/// РљРѕРјРїР°РєС‚РЅС‹Р№ РѕС‚РїРµС‡Р°С‚РѕРє СЃРѕРµРґРёРЅРµРЅРёСЏ РґР»СЏ СЂР°Р·СЂР°Р±РѕС‚С‡РёРєР° (Р»РµРіРєРѕ РєРѕРїРёСЂРѕРІР°С‚СЊ/РІСЃС‚Р°РІР»СЏС‚СЊ).
pub fn build_fingerprint(
    admin: bool,
    windivert_ok: bool,
    ipv6: bool,
    dns: &DnsInfo,
    connect: &str,
    tls: &str,
    quic: &str,
    passed: &[String],
) -> String {
    let join = |v: &[std::net::IpAddr]| -> String {
        v.iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "ADMIN={} WINDIVERT={} IPv6={} | DNS_SYS=[{}] DNS_1_1=[{}] DNS_8_8=[{}] | CONNECT_443={} TLS={} QUIC={} | TECH_PASS=[{}]",
        if admin { "1" } else { "0" },
        if windivert_ok { "OK" } else { "FAIL" },
        if ipv6 { "1" } else { "0" },
        join(&dns.system),
        join(&dns.cloudflare),
        join(&dns.google),
        connect,
        tls,
        quic,
        passed.join(",")
    )
}

/// Р§РµР»РѕРІРµРєРѕС‡РёС‚Р°РµРјР°СЏ СЂРµРєРѕРјРµРЅРґР°С†РёСЏ РЅР° РѕСЃРЅРѕРІРµ СЃРѕР±СЂР°РЅРЅС‹С… СЃРёРіРЅР°Р»РѕРІ.
pub fn build_recommendation(
    admin: bool,
    winws_present: bool,
    windivert_ok: bool,
    windivert_detail: &str,
    ipv6: bool,
    dns: &DnsInfo,
    connect: &str,
    tls: &str,
    passed: &[String],
    profile_saved: bool,
    verified: Option<bool>,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    if !admin {
        lines.push("рџ”ґ Р—Р°РїСѓСЃС‚РёС‚Рµ РїСЂРёР»РѕР¶РµРЅРёРµ РѕС‚ РёРјРµРЅРё РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° вЂ” WinDivert С‚СЂРµР±СѓРµС‚ РїСЂР°РІ.".into());
    }
    if !winws_present {
        lines.push("рџ”ґ РћС‚СЃСѓС‚СЃС‚РІСѓРµС‚ bin/winws.exe СЂСЏРґРѕРј СЃ РїСЂРёР»РѕР¶РµРЅРёРµРј. РџРµСЂРµСѓСЃС‚Р°РЅРѕРІРёС‚Рµ РїСЂРѕРіСЂР°РјРјСѓ.".into());
    }
    if !windivert_ok {
        lines.push(format!(
            "рџ”ґ Р”СЂР°Р№РІРµСЂ WinDivert РЅРµ Р·Р°РіСЂСѓР¶Р°РµС‚СЃСЏ ({}). Р”РѕР±Р°РІСЊС‚Рµ РїСЂРёР»РѕР¶РµРЅРёРµ/WinDivert РІ РёСЃРєР»СЋС‡РµРЅРёСЏ Р°РЅС‚РёРІРёСЂСѓСЃР°, РїРµСЂРµСѓСЃС‚Р°РЅРѕРІРёС‚Рµ РґСЂР°Р№РІРµСЂ (РїРµСЂРµР·Р°РїСѓСЃРє РѕС‚ Р°РґРјРёРЅР°).",
            windivert_detail
        ));
    }

    // DNS (СЃСЂР°РІРЅРёРІР°РµРј РєР°Рє РњРќРћР–Р•РЎРўР’Рђ, Р° РЅРµ РїРѕРєРѕСЂРґРёРЅР°С‚РЅРѕ вЂ” РїРѕСЂСЏРґРѕРє РЅРµ РІР°Р¶РµРЅ)
    let to_set = |v: &[std::net::IpAddr]| -> BTreeSet<std::net::IpAddr> {
        v.iter().copied().collect()
    };
    let sys_set = to_set(&dns.system);
    let cf_set = to_set(&dns.cloudflare);
    let g_set = to_set(&dns.google);
    let sys_ok = !sys_set.is_empty();
    let pub_ok = !cf_set.is_empty() || !g_set.is_empty();

    if sys_ok && pub_ok && sys_set == cf_set && cf_set == g_set {
        lines.push(
            "рџџЎ Р’СЃРµ DNS-СЂРµР·РѕР»РІРµСЂС‹ (СЃРёСЃС‚РµРјРЅС‹Р№ Рё РїСѓР±Р»РёС‡РЅС‹Рµ) РѕС‚РґР°СЋС‚ РћР”РРќРђРљРћР’Р«Р™ РЅР°Р±РѕСЂ IP. Р’РµСЂРѕСЏС‚РЅР° РїРѕРґРјРµРЅР° DNS (hijack) вЂ” РґР°Р¶Рµ 1.1.1.1/8.8.8.8 РїРµСЂРµРЅР°РїСЂР°РІР»СЏСЋС‚СЃСЏ. DPI-РїСЂРѕС„РёР»Рё РјРѕРіСѓС‚ РЅРµ РїРѕРјРѕС‡СЊ, РЅСѓР¶РµРЅ DNS-over-HTTPS/TLS (DoH/DoT).".into(),
        );
    } else if sys_ok && pub_ok && sys_set != cf_set {
        lines.push(
            "рџџЎ РћР±РЅР°СЂСѓР¶РµРЅР° DNS-С†РµРЅР·СѓСЂР°: СЃРёСЃС‚РµРјРЅС‹Р№ DNS РѕС‚РґР°С‘С‚ РѕС‚Р»РёС‡Р°СЋС‰РёР№СЃСЏ РѕС‚РІРµС‚ РѕС‚ РїСѓР±Р»РёС‡РЅРѕРіРѕ. РџСЂРѕРїРёС€РёС‚Рµ DNS 1.1.1.1 / 8.8.8.8 РІ РЅР°СЃС‚СЂРѕР№РєР°С… СЃРµС‚Рё. DPI-РїСЂРѕС„РёР»Рё РјРѕРіСѓС‚ РЅРµ РїРѕРјРѕС‡СЊ.".into(),
        );
    } else if !sys_ok && pub_ok {
        lines.push(
            "рџџЎ РЎРёСЃС‚РµРјРЅС‹Р№ DNS РЅРµ СЂРµР·РѕР»РІРёС‚ РґРѕРјРµРЅ (NXDOMAIN/РїСѓСЃС‚Рѕ), РїСѓР±Р»РёС‡РЅС‹Р№ вЂ” СЂРµР·РѕР»РІРёС‚. РџСЂРёР·РЅР°Рє DNS-Р±Р»РѕРєРёСЂРѕРІРєРё. РСЃРїРѕР»СЊР·СѓР№С‚Рµ РїСѓР±Р»РёС‡РЅС‹Р№ DNS.".into(),
        );
    } else if sys_ok {
        lines.push("рџџў DNS СЂРµР·РѕР»РІРёС‚СЃСЏ С€С‚Р°С‚РЅРѕ (РїСЂРёР·РЅР°РєРѕРІ DNS-С†РµРЅР·СѓСЂС‹ РЅРµС‚).".into());
    }

    // Connect / TLS
    if connect == "Success" && (tls.contains("RST") || tls.contains("Timeout") || tls.contains("Tls")) {
        lines.push("рџџЎ Р‘Р»РѕРєРёСЂРѕРІРєР° РЅР° СѓСЂРѕРІРЅРµ DPI (TLS/SNI): СЃРѕРµРґРёРЅРµРЅРёРµ СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ, РЅРѕ HTTPS-Р·Р°РїСЂРѕСЃ СЃСЂРµР·Р°РµС‚СЃСЏ. РџРѕРґР±РѕСЂ desync-С‚РµС…РЅРёРєРё РґРѕР»Р¶РµРЅ РїРѕРјРѕС‡СЊ.".into());
    } else if connect.contains("RST") || connect.contains("REFUSED") {
        lines.push("рџџ  Р‘Р»РѕРєРёСЂРѕРІРєР° РЅР° СѓСЂРѕРІРЅРµ IP/connect (RST РЅР° РїРѕСЂС‚ 443). DPI-РїСЂРѕС„РёР»Рё РјРѕРіСѓС‚ РЅРµ СЃСЂР°Р±РѕС‚Р°С‚СЊ вЂ” РІРѕР·РјРѕР¶РЅРѕ, С‚СЂРµР±СѓРµС‚СЃСЏ VPN РёР»Рё СЃРјРµРЅР° IP.".into());
    }

    if ipv6 {
        lines.push(
            "рџџЎ РћР±РЅР°СЂСѓР¶РµРЅ СЂР°Р±РѕС‡РёР№ IPv6 РґРѕ СЃР°Р№С‚Р°. winws С„РёР»СЊС‚СЂСѓРµС‚ С‚РѕР»СЊРєРѕ IPv4 вЂ” С‚СЂР°С„РёРє РјРѕР¶РµС‚ СѓС…РѕРґРёС‚СЊ РїРѕ IPv6 РІ РѕР±С…РѕРґ РѕР±С…РѕРґР°. РћС‚РєР»СЋС‡РёС‚Рµ IPv6 РёР»Рё РґРѕР±Р°РІСЊС‚Рµ IPv6-РѕР±С…РѕРґ.".into(),
        );
    }

    // РўРµС…РЅРёРєРё
    if passed.is_empty() {
        lines.push(
            "рџ”ґ РќРё РѕРґРЅР° desync-С‚РµС…РЅРёРєР° РЅРµ РїСЂРѕР±РёР»Р° Р±Р»РѕРє. Р’РµСЂРѕСЏС‚РЅРѕ Р±Р»РѕРєРёСЂРѕРІРєР° РЅР° IP/connect РёР»Рё DNS-СѓСЂРѕРІРЅРµ, Р»РёР±Рѕ РЅРµСЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ DPI. РџСЂРёС€Р»РёС‚Рµ РѕС‚РїРµС‡Р°С‚РѕРє СЂР°Р·СЂР°Р±РѕС‚С‡РёРєСѓ РґР»СЏ СЂСѓС‡РЅРѕРіРѕ РїСЂРѕС„РёР»СЏ.".into(),
        );
    } else {
        let verdict: String = match verified {
            Some(true) => "РїСЂРѕРІРµСЂРµРЅ Рё Р РђР‘РћРўРђР•Рў".to_string(),
            Some(false) => "СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅ, РЅРѕ РїСЂРѕРІРµСЂРєР° РЅРµ РїСЂРѕС€Р»Р° (РІРѕР·РјРѕР¶РЅРѕ, СЃР°Р№С‚ РїР°РґР°РµС‚ РїРѕ РґСЂСѓРіРѕР№ РїСЂРёС‡РёРЅРµ)".to_string(),
            None => "СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅ".to_string(),
        };
        lines.push(format!(
            "рџџў РџРѕРґРѕР±СЂР°РЅР°(С‹) СЂР°Р±РѕС‡Р°СЏ(РёРµ) С‚РµС…РЅРёРєР°(Рё): {}. РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ {}{}",
            passed.join(", "),
            verdict,
            if profile_saved { " Рё СЃРѕС…СЂР°РЅС‘РЅ РІ СЃРїРёСЃРєРµ РїСЂРѕС„РёР»РµР№." } else { "." }
        ));
    }

    lines.join("\n")
}

/// Р“РµРЅРµСЂР°С†РёСЏ С‡РµСЂРЅРѕРІРёРєР° РїСЂРѕС„РёР»СЏ РёР· РїСЂРѕС€РµРґС€РёС… С‚РµС…РЅРёРє.
/// Р’РѕР·РІСЂР°С‰Р°РµС‚ (РёРјСЏ, Р°СЂРіСѓРјРµРЅС‚С‹). Р’РѕР·РІСЂР°С‰Р°РµС‚ None, РµСЃР»Рё С‚РµС…РЅРёРє РЅРµС‚.
pub fn generate_profile(
    domain: &str,
    techniques: &[TechniqueSpec],
    passed: &[String],
    lists_dir: &str,
    bin_dir: &str,
) -> Option<(String, String)> {
    if passed.is_empty() {
        return None;
    }
    let chosen = techniques.iter().find(|t| passed.contains(&t.name))?;
    let desync = chosen
        .desync
        .replace("{BIN_DIR}", bin_dir)
        .replace("{LISTS_DIR}", lists_dir);

    let name = format!("РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ ({})", domain);
    let diag_host = format!("{}/diag-autoprofile.txt", lists_dir);

    // Р”РѕРјРµРЅРЅРѕ-СЃРїРµС†РёС„РёС‡РЅС‹Р№ Р±Р»РѕРє (РґР»СЏ РїСЂРѕРІРµСЂРєРё Рё РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕРіРѕ РїРѕРєСЂС‹С‚РёСЏ РґРѕРјРµРЅР°)
    // + РѕР±С‰РёРµ Р±Р»РѕРєРё РїРѕ СЃРїРёСЃРєР°Рј, РєР°Рє РІ С€С‚Р°С‚РЅС‹С… РїСЂРѕС„РёР»СЏС….
    let args = format!(
        "--wf-tcp=80,443 --wf-udp=443 \
         --filter-udp=443 --hostlist=\"{l}/list-general.txt\" --hostlist-exclude=\"{l}/default-exclude.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{b}/quic_initial_www_google_com.bin\" --new \
         --filter-tcp=443 --hostlist=\"{h}\" {d} --new \
         --filter-tcp=80,443 --hostlist=\"{l}/list-general.txt\" --hostlist-exclude=\"{l}/default-exclude.txt\" {d}",
        l = lists_dir,
        b = bin_dir,
        h = diag_host,
        d = desync
    );

    Some((name, args))
}

/// РљР»РѕРЅРёСЂРѕРІР°РЅРёРµ СЂР°Р±РѕС‡РµРіРѕ РїСЂРѕС„РёР»СЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ, РµСЃР»Рё РЅРё РѕРґРЅР° РёР·РѕР»РёСЂРѕРІР°РЅРЅР°СЏ
/// С‚РµС…РЅРёРєР° РЅРµ РїСЂРѕС€Р»Р°. Р‘РµСЂС‘Рј Р°СЂРіСѓРјРµРЅС‚С‹ РёСЃС…РѕРґРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ Рё РґРѕР±Р°РІР»СЏРµРј
/// РґРѕРјРµРЅРЅРѕ-СЃРїРµС†РёС„РёС‡РЅС‹Р№ Р±Р»РѕРє (РЅР° С‚РѕС‚ Р¶Рµ desync, С‡С‚Рѕ Рё РІ РёСЃС…РѕРґРЅРёРєРµ), С‡С‚РѕР±С‹
/// РїСЂРѕРІРµСЂРєР° РїРѕ С‚РµСЃС‚РѕРІРѕРјСѓ РґРѕРјРµРЅСѓ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕ РїСЂРѕС€Р»Р°.
pub fn clone_profile(
    src_name: &str,
    src_args: &str,
    lists_dir: &str,
    bin_dir: &str,
) -> Option<(String, String)> {
    let diag_host = format!("{}/diag-autoprofile.txt", lists_dir);
    let bin_str = bin_dir.replace("\\", "/");

    // Р’С‹С‚Р°СЃРєРёРІР°РµРј РїРµСЂРІС‹Р№ --dpi-desync=... РёР· РёСЃС…РѕРґРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ
    let desync = src_args
        .split("--dpi-desync=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .map(|d| d.to_string())
        .unwrap_or_else(|| {
            format!(
                "fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{}/tls_clienthello_www_google_com.bin\"",
                bin_str
            )
        });

    let name = format!("РђРІС‚Рѕ-РїСЂРѕС„РёР»СЊ (clone: {})", src_name);
    let args = format!(
        "{} --new --filter-tcp=443 --hostlist=\"{}\" --dpi-desync={}",
        src_args, diag_host, desync
    );

    Some((name, args))
}
