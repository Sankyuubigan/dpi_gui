use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::blocking::Client;

use crate::diagnostics_probe::{
    classify_reqwest_err, dns_multi, resolve_via_doh, tcp_connect, DnsInfo, HttpResult,
    DOH_RESOLVERS,
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    Open,
    /// Р”РѕРјРµРЅ Р±РµР· `www.` РЅРµ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ, РЅРѕ С‚РѕС‚ Р¶Рµ СЃР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ РїРѕ `www.`.
    /// РљР»Р°СЃСЃРёС‡РµСЃРєРёР№ СЃР»СѓС‡Р°Р№: Сѓ СЃР°Р№С‚Р° Р±РёС‚Р°СЏ A-Р·Р°РїРёСЃСЊ apex-РґРѕРјРµРЅР°, Р° `www` Р¶РёРІ.
    WwwOnly,
    IpUnreachable,
    IpReset,
    TlsBroken,
    /// РЎР°Р№С‚ РѕС‚РІРµС‡Р°РµС‚ РїРѕ TCP/TLS, РЅРѕ СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ РґР»СЏ РёРјРµРЅРё РґРѕРјРµРЅР°
    /// (Р±СЂР°СѓР·РµСЂ: NET::ERR_CERT_COMMON_NAME_INVALID Рё С‚.Рї.).
    BadCert,
    DnsBlocked,
    BlockPage,
    NoPath,
    Unknown,
}

impl Verdict {
    /// Сайт реально недоступен пользователю — нужна диагностика и подсказка.
    pub fn site_broken(self) -> bool {
        !matches!(self, Verdict::Open)
    }

    /// Короткое техническое имя вердикта — для заголовка в отчёте.
    pub fn verdict_name(self) -> &'static str {
        match self {
            Verdict::Open => "САЙТ ОТКРЫВАЕТСЯ",
            Verdict::WwwOnly => "РАБОТАЕТ ТОЛЬКО С WWW",
            Verdict::IpUnreachable => "IP НЕ ОТВЕЧАЕТ",
            Verdict::IpReset => "СБРОС СОЕДИНЕНИЯ (DPI)",
            Verdict::TlsBroken => "TLS РВЁТСЯ",
            Verdict::BadCert => "НЕВАЛИДНЫЙ СЕРТИФИКАТ",
            Verdict::DnsBlocked => "DNS-ПОДМЕНА",
            Verdict::BlockPage => "СТРАНИЦА БЛОКИРОВКИ",
            Verdict::NoPath => "НЕТ СВЯЗИ",
            Verdict::Unknown => "ПРИЧИНА НЕ ЯСНА",
        }
    }
}

/// РљРѕРЅС‚РµРєСЃС‚ РґР»СЏ РѕР±СЉСЏСЃРЅРµРЅРёСЏ РїСЂРёС‡РёРЅС‹. РЎРѕР±РёСЂР°РµС‚СЃСЏ РёР· СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ РїСЂРѕР± Рё РЅРµ
/// СЃРѕРґРµСЂР¶РёС‚ РЅРёС‡РµРіРѕ, РєСЂРѕРјРµ С„Р°РєС‚РѕРІ, вЂ” С‡С‚РѕР±С‹ `explain()` РѕСЃС‚Р°РІР°Р»Р°СЃСЊ С‡РёСЃС‚РѕР№
/// С„СѓРЅРєС†РёРµР№, РїРѕРєСЂС‹РІР°РµРјРѕР№ СЋРЅРёС‚-С‚РµСЃС‚Р°РјРё Р±РµР· СЃРµС‚Рё.
pub struct CauseContext<'a> {
    pub host: &'a str,
    /// Рабочий URL с `www.`, если сайт открылся только под ним.
    pub www_url: Option<&'a str>,
    /// IP, выданный DNS для apex-домена (даже если он не отвечает).
    pub apex_ip: Option<&'a str>,
    /// Системный DNS совпадает с публичными (false = вероятна подмена DNS).
    pub dns_consistent: bool,
    /// То же имя открывается по IP, отличному от системного DNS (подмена DNS).
    pub same_host_alt_ip_works: bool,
}

/// Р§РµР»РѕРІРµС‡РµСЃРєРёР№ РґРёР°РіРЅРѕР·: РѕРґРЅР° СЃС‚СЂРѕРєР° РїСЂРёС‡РёРЅС‹ + С‡С‚Рѕ РґРµР»Р°С‚СЊ + С‡С‚Рѕ РќР• РїРѕРјРѕР¶РµС‚.
#[derive(Debug)]
pub struct Diagnosis {
    pub probable_cause: String,
    pub do_this: Vec<String>,
    pub wont_help: Vec<String>,
}

/// РџРѕСЏСЃРЅРµРЅРёРµ РїСЂРёС‡РёРЅС‹ РЅРµРґРѕСЃС‚СѓРїРЅРѕСЃС‚Рё. РќРёРєР°РєРёС… СЃРµС‚РµРІС‹С… РІС‹Р·РѕРІРѕРІ вЂ” С‚РѕР»СЊРєРѕ С„Р°РєС‚С‹.
pub fn explain(verdict: Verdict, ctx: &CauseContext) -> Diagnosis {
    let mut do_this = Vec::new();
    let mut wont_help = Vec::new();

    let probable_cause = match verdict {
        Verdict::Open => "РЎР°Р№С‚ РґРѕСЃС‚СѓРїРµРЅ, СЃ РґРѕРјРµРЅРѕРј Рё СЃРµС‚СЊСЋ РІСЃС‘ РІ РїРѕСЂСЏРґРєРµ.".to_string(),

        Verdict::WwwOnly => {
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.dns_consistent {
                format!(
                    "DNS-С†РµРЅР·СѓСЂС‹ РЅРµС‚: РЅР°СЃС‚РѕСЏС‰Р°СЏ A-Р·Р°РїРёСЃСЊ В«{}В» СѓРєР°Р·С‹РІР°РµС‚ РЅР° {}, РЅРѕ СЌС‚РѕС‚ Р°РґСЂРµСЃ РЅРµ РѕС‚РІРµС‡Р°РµС‚. \
                     Р­С‚Рѕ Р±РёС‚Р°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ РЅР° СЃС‚РѕСЂРѕРЅРµ СЃР°Р№С‚Р°, Р° РЅРµ Р±Р»РѕРєРёСЂРѕРІРєР°. \
                     РЎР°Р№С‚ Р¶РёРІС‘С‚ РЅР° РґСЂСѓРіРѕРј Р°РґСЂРµСЃРµ Рё РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РїРѕРґ РёРјРµРЅРµРј СЃ В«www.В»",
                    ctx.host, apex
                )
            } else {
                format!(
                    "DNS-РѕС‚РІРµС‚С‹ СЃРёСЃС‚РµРјРЅРѕРіРѕ Рё РїСѓР±Р»РёС‡РЅС‹С… СЂРµР·РѕР»РІРµСЂРѕРІ СЂР°СЃС…РѕРґСЏС‚СЃСЏ вЂ” DNS РїРѕРґРјРµРЅС‘РЅ. \
                     РРјСЏ В«{}В» РѕС‚РґР°С‘С‚СЃСЏ РЅР° Р±Р»РѕРєРёСЂРѕРІР°РЅРЅС‹Р№ Р°РґСЂРµСЃ ({}), Р° РёРјСЏ СЃ В«www.В» РЅРµ РѕС‚СЂР°РІР»РµРЅРѕ \
                     Рё РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С€С‚Р°С‚РЅРѕ",
                    ctx.host, apex
                )
            }
        }

        Verdict::IpReset => {
            wont_help.push("РјРµРЅСЏС‚СЊ DNS вЂ” СЃРѕРµРґРёРЅРµРЅРёРµ СЃР±СЂР°СЃС‹РІР°РµС‚СЃСЏ СѓР¶Рµ РїРѕСЃР»Рµ СѓСЃС‚Р°РЅРѕРІРєРё TCP.".to_string());
            "РЎРѕРµРґРёРЅРµРЅРёРµ СЃР±СЂР°СЃС‹РІР°РµС‚СЃСЏ (RST) РґРѕ РѕР±РјРµРЅР° РґР°РЅРЅС‹РјРё вЂ” С‚РёРїРёС‡РЅС‹Р№ DPI-Р±Р»РѕРє РЅР° СѓСЂРѕРІРЅРµ IP РёР»Рё SNI."
                .to_string()
        }

        Verdict::TlsBroken => {
            wont_help.push("СЃРјРµРЅР° DNS РёР»Рё Р·Р°РїРёСЃСЊ РІ hosts вЂ” TCP РґРѕ СЃРµСЂРІРµСЂР° РґРѕС…РѕРґРёС‚.".to_string());
            "TCP-РїРѕСЂС‚ РѕС‚РєСЂС‹С‚, РЅРѕ TLS-СЂСѓРєРѕРїРѕР¶Р°С‚РёРµ СЂРІС‘С‚СЃСЏ. Р•СЃР»Рё РѕР±С…РѕРґ РІРєР»СЋС‡С‘РЅ вЂ” РµРіРѕ РґРµСЃРёРЅРє Р»РѕРјР°РµС‚ TLS; \
             РµСЃР»Рё РІС‹РєР»СЋС‡РµРЅ вЂ” РїСЂРѕР±Р»РµРјР° РЅР° СЃС‚РѕСЂРѕРЅРµ СЃРµСЂРІРµСЂР°."
                .to_string()
        }

        Verdict::BadCert => {
            wont_help.push("РѕР±С…РѕРґ DPI вЂ” РѕРЅ С‚СѓС‚ РЅРё РїСЂРё С‡С‘Рј.".to_string());
            wont_help.push("СЃРјРµРЅР° DNS Рё hosts вЂ” СЃРµС‚РµРІРѕР№ РїСѓС‚СЊ СЂР°Р±РѕС‚Р°РµС‚.".to_string());
            "РЎРµСЂРІРµСЂ РѕС‚РІРµС‡Р°РµС‚ РїРѕ СЃРµС‚Рё, РЅРѕ SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ РґР»СЏ СЌС‚РѕРіРѕ РёРјРµРЅРё вЂ” \
             Р±СЂР°СѓР·РµСЂ РїРѕРєР°Р¶РµС‚ NET::ERR_CERT_COMMON_NAME_INVALID. Р­С‚Рѕ РѕС€РёР±РєР° СЃРµСЂС‚РёС„РёРєР°С‚Р°, РЅРµ Р±Р»РѕРєРёСЂРѕРІРєР°."
                .to_string()
        }

        Verdict::DnsBlocked => {
            do_this.push("СЃРјРµРЅРёС‚Рµ DNS РЅР° 1.1.1.1 / 8.8.8.8 РёР»Рё РІРєР»СЋС‡РёС‚Рµ DoH РІ Р±СЂР°СѓР·РµСЂРµ".to_string());
            "Р”РѕРјРµРЅ РЅРµ СЂРµР·РѕР»РІРёС‚СЃСЏ РёР»Рё DNS-РѕС‚РІРµС‚С‹ РїРѕРґРјРµРЅРµРЅС‹ вЂ” РІРµСЂРѕСЏС‚РЅР° Р±Р»РѕРєРёСЂРѕРІРєР° РЅР° СѓСЂРѕРІРЅРµ DNS."
                .to_string()
        }

        Verdict::BlockPage => {
            do_this.push("РґРѕР±Р°РІСЊС‚Рµ РґРѕРјРµРЅ РІ СЃРїРёСЃРѕРє РѕР±С…РѕРґР° (general-Р»РёСЃС‚)".to_string());
            wont_help.push("СЃРјРµРЅР° DNS вЂ” DNS СЂР°Р±РѕС‚Р°РµС‚ РїСЂР°РІРёР»СЊРЅРѕ, Р±Р»РѕРєРёСЂРѕРІРєСѓ РѕС‚РґР°С‘С‚ СЃРµСЂРІРµСЂ.".to_string());
            "РЎРµСЂРІРµСЂ РѕС‚РІРµС‡Р°РµС‚, РЅРѕ РѕС‚РґР°С‘С‚ СЃС‚СЂР°РЅРёС†Сѓ-Р·Р°РіР»СѓС€РєСѓ Р±Р»РѕРєРёСЂРѕРІРєРё (403/451).".to_string()
        }

        Verdict::IpUnreachable => {
            wont_help.push("РѕР±С…РѕРґ winws вЂ” РѕРЅ РїРµСЂРµС…РІР°С‚С‹РІР°РµС‚ СѓР¶Рµ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅС‹Рµ СЃРѕРµРґРёРЅРµРЅРёСЏ.".to_string());
            wont_help.push("СЃРјРµРЅР° DNS Рё hosts вЂ” DNS РѕС‚РґР°С‘С‚ РЅР°СЃС‚РѕСЏС‰РёР№ Р°РґСЂРµСЃ СЃР°Р№С‚Р°.".to_string());
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.same_host_alt_ip_works {
                "DNS РѕС‚РґР°С‘С‚ РЅР°СЃС‚РѕСЏС‰РёР№ Р°РґСЂРµСЃ СЃР°Р№С‚Р°, РЅРѕ РЅР° РЅРµРіРѕ РЅРµС‚ РѕС‚РІРµС‚Р° СЃ РІР°С€РµР№ СЃРµС‚Рё. \
                 РџСЂРѕР±Р»РµРјР° РЅР° РјР°СЂС€СЂСѓС‚Рµ РґРѕ СЃРµСЂРІРµСЂР°, Р° РЅРµ РІ РѕР±С…РѕРґРµ."
                    .to_string()
            } else {
                format!(
                    "DNS РѕС‚РґР°С‘С‚ РЅР°СЃС‚РѕСЏС‰РёР№ Р°РґСЂРµСЃ СЃР°Р№С‚Р° ({}), РЅРѕ СЃРµСЂРІРµСЂ РЅР° РЅРµРіРѕ РЅРµ РѕС‚РІРµС‡Р°РµС‚ вЂ” \
                     РѕРЅ РЅРµ РѕР±СЃР»СѓР¶РёРІР°РµС‚ СЌС‚РѕС‚ РґРѕРјРµРЅ. РџСЂРѕР±Р»РµРјР° РЅР° СЃС‚РѕСЂРѕРЅРµ СЃР°Р№С‚Р°, РѕР±С…РѕРґ С‚СѓС‚ РЅРµ РїРѕРјРѕР¶РµС‚.",
                    apex
                )
            }
        }

        Verdict::NoPath => {
            wont_help.push("РѕР±С…РѕРґ winws вЂ” РґРѕ Р°РґСЂРµСЃРѕРІ СЃР°Р№С‚Р° СЃРІСЏР·Рё РЅРµС‚ РІ РїСЂРёРЅС†РёРїРµ.".to_string());
            "РќРё РѕРґРёРЅ Р°РґСЂРµСЃ СЃР°Р№С‚Р° РЅРµ РїСЂРёРЅСЏР» СЃРѕРµРґРёРЅРµРЅРёРµ. РџСЂРѕРІРµСЂСЊС‚Рµ РѕР±С‰РµРµ РїРѕРґРєР»СЋС‡РµРЅРёРµ Рє РёРЅС‚РµСЂРЅРµС‚Сѓ."
                .to_string()
        }

        Verdict::Unknown => "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРґРЅРѕР·РЅР°С‡РЅРѕ РѕРїСЂРµРґРµР»РёС‚СЊ РїСЂРёС‡РёРЅСѓ.".to_string(),
    };

    // Р•РґРёРЅС‹Рµ РґРµР№СЃС‚РІРёСЏ: СЂР°Р±РѕС‚Р°СЋС‰РµРµ РёРјСЏ вЂ” РіР»Р°РІРЅС‹Р№ СЃРѕРІРµС‚.
    if verdict == Verdict::WwwOnly {
        if let Some(url) = ctx.www_url {
            do_this.insert(0, format!("РѕС‚РєСЂРѕР№С‚Рµ СЃР°Р№С‚ РїРѕ Р°РґСЂРµСЃСѓ СЃ В«wwwВ»: {}", url));
        }
        do_this.push("РїРµСЂРµС…РѕРґРёС‚Рµ РїРѕ СЌС‚РѕР№ СЃСЃС‹Р»РєРµ вЂ” РѕРЅР° Рё РµСЃС‚СЊ СЂР°Р±РѕС‡Р°СЏ".to_string());
        wont_help.push("РїСЂР°РІРёС‚СЊ hosts Рё РѕС‚РєР»СЋС‡Р°С‚СЊ DoH вЂ” РїСЂРѕС‰Рµ РѕС‚РєСЂС‹С‚СЊ СЂР°Р±РѕС‡СѓСЋ СЃСЃС‹Р»РєСѓ.".to_string());
        wont_help.push("РґРѕР±Р°РІР»СЏС‚СЊ РґРѕРјРµРЅ РІ СЃРїРёСЃРѕРє РѕР±С…РѕРґР° вЂ” РѕРЅ РЅРµ Р·Р°СЃС‚Р°РІРёС‚ РјС‘СЂС‚РІС‹Р№ Р°РґСЂРµСЃ РѕС‚РІРµС‡Р°С‚СЊ.".to_string());
    }

    if verdict == Verdict::Open {
        return Diagnosis {
            probable_cause,
            do_this,
            wont_help,
        };
    }

    if verdict == Verdict::BlockPage || verdict == Verdict::DnsBlocked {
        // РґРµР№СЃС‚РІРёСЏ СѓР¶Рµ СЃС„РѕСЂРјСѓР»РёСЂРѕРІР°РЅС‹ РІС‹С€Рµ
    } else if do_this.is_empty() && verdict != Verdict::WwwOnly {
        do_this.push("РїРѕРїСЂРѕР±СѓР№С‚Рµ VPN/РїСЂРѕРєСЃРё Рё РїРѕРІС‚РѕСЂРёС‚Рµ Р°РЅР°Р»РёР· РїРѕР·Р¶Рµ".to_string());
    }

    Diagnosis {
        probable_cause,
        do_this,
        wont_help,
    }
}

#[derive(Debug)]
pub struct DomainProbe {
    pub host: String,
    pub dns: DnsInfo,
    pub dns_consistent: bool,
    /// Адреса, выданные системным DNS для apex-имени.
    pub primary_ips: Vec<String>,
    /// Адрес, на котором сервер принял соединение (не значит, что HTTPS прошёл).
    pub working_ip: Option<String>,
    pub http_note: String,
    pub verdict: Verdict,
    /// Имя с `www.`, если по нему сайт открывается.
    pub www_host: Option<String>,
    /// IP, выданные DNS для `www.`
    pub www_ips: Vec<String>,
    /// Рабочий URL с `www.` — его и нужно открыть пользователю.
    pub www_url: Option<String>,
    /// Диагноз: причина + действия + «что не поможет».
    pub diagnosis: Option<Diagnosis>,
}

fn dedup_ips(addrs: impl Iterator<Item = IpAddr>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for a in addrs {
        let s = a.to_string();
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Р§РµР»РѕРІРµРєРѕС‡РёС‚Р°РµРјС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚ HTTPS-РїСЂРѕР±С‹.
pub fn http_result_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::Tls => "TLS СЃР»РѕРјР°РЅ".to_string(),
        HttpResult::BadCert => "SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ".to_string(),
        HttpResult::Rst => "RST".to_string(),
        HttpResult::Timeout => "С‚Р°Р№РјР°СѓС‚".to_string(),
        HttpResult::Dns => "DNS-РѕС€РёР±РєР°".to_string(),
        HttpResult::BlockPage => "СЃС‚СЂР°РЅРёС†Р° Р±Р»РѕРєРёСЂРѕРІРєРё".to_string(),
        HttpResult::Other(m) => m.clone(),
    }
}

fn http_via_ip(host: &str, ip: IpAddr) -> HttpResult {
    let client = match Client::builder()
        .resolve(host, SocketAddr::new(ip, 443))
        .timeout(Duration::from_secs(6))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResult::Other(format!("РЅРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ РєР»РёРµРЅС‚: {}", e)),
    };
    match client.get(format!("https://{}/", host)).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 403 || status == 451 {
                return HttpResult::BlockPage;
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if low.contains("СЂРѕСЃРєРѕРјРЅР°РґР·РѕСЂ")
                    || low.contains("Р·Р°Р±Р»РѕРєРёСЂ")
                    || low.contains("this site is blocked")
                    || low.contains("access denied: by order")
                    || low.contains("СЃС‚СЂР°РЅРёС†Р° РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РѕС‚РѕР±СЂР°Р¶РµРЅР°")
                {
                    HttpResult::BlockPage
                } else {
                    HttpResult::Ok(status)
                }
            } else {
                HttpResult::Ok(status)
            }
        }
        Err(e) => classify_reqwest_err(&e),
    }
}

/// Р§РёСЃС‚Р°СЏ Р»РѕРіРёРєР° РєР»Р°СЃСЃРёС„РёРєР°С†РёРё РїРµСЂРІРѕРїСЂРёС‡РёРЅС‹ вЂ” РѕС‚РґРµР»РµРЅР° РѕС‚ I/O, С‡С‚РѕР±С‹ РµС‘ РјРѕР¶РЅРѕ
/// Р±С‹Р»Рѕ РїРѕРєСЂС‹С‚СЊ СЋРЅРёС‚-С‚РµСЃС‚Р°РјРё Р±РµР· СЃРµС‚Рё.
///
/// * `dns_consistent` вЂ” СЃРёСЃС‚РµРјРЅС‹Р№ DNS СЃРѕРІРїР°РґР°РµС‚ СЃ РїСѓР±Р»РёС‡РЅС‹РјРё СЂРµР·РѕР»РІРµСЂР°РјРё.
/// * `primary_ok` вЂ” С…РѕС‚СЏ Р±С‹ РѕРґРёРЅ IP СЃРёСЃС‚РµРјРЅРѕРіРѕ DNS РѕС‚РІРµС‚РёР» РЅР° TCP:443.
/// * `alt_ok` вЂ” С…РѕС‚СЏ Р±С‹ РѕРґРёРЅ В«Р°Р»СЊС‚РµСЂРЅР°С‚РёРІРЅС‹Р№В» IP (www + DoH) РѕС‚РІРµС‚РёР» РЅР° TCP:443.
/// * `any_reset` вЂ” СЃСЂРµРґРё РІСЃРµС… РїРѕРїС‹С‚РѕРє Р±С‹Р»Рѕ RST.
/// * `http` вЂ” СЂРµР·СѓР»СЊС‚Р°С‚ HTTPS-Р·Р°РїСЂРѕСЃР° С‡РµСЂРµР· РїРµСЂРІС‹Р№ СЂР°Р±РѕС‡РёР№ IP.
/// * `www_ok` вЂ” СЃР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ РїРѕРґ РёРјРµРЅРµРј СЃ `www.`
pub fn classify(
    dns_consistent: bool,
    primary_ok: bool,
    alt_ok: bool,
    any_reset: bool,
    http: Option<&HttpResult>,
    www_ok: bool,
) -> Verdict {
    // РЎРЅР°С‡Р°Р»Р° вЂ” С„Р°РєС‚РёС‡РµСЃРєР°СЏ СЂР°Р±РѕС‚РѕСЃРїРѕСЃРѕР±РЅРѕСЃС‚СЊ СЃР°Р№С‚Р°. Р”Р°Р¶Рµ РµСЃР»Рё DNS-СЃРїРёСЃРєРё
    // СЂР°Р·РЅС‹С… СЂРµР·РѕР»РІРµСЂРѕРІ РѕС‚Р»РёС‡Р°СЋС‚СЃСЏ (РЅРѕСЂРјР°Р»СЊРЅС‹Р№ anycast Сѓ РєСЂСѓРїРЅС‹С… CDN), СЃР°Р№С‚
    // РјРѕР¶РµС‚ РѕС‚РєСЂС‹РІР°С‚СЊСЃСЏ вЂ” СЌС‚Рѕ РЅРµ С†РµРЅР·СѓСЂР°.
    match http {
        Some(HttpResult::Ok(_)) => {
            return if primary_ok {
                Verdict::Open
            } else {
                Verdict::IpUnreachable
            };
        }
        Some(HttpResult::BlockPage) => return Verdict::BlockPage,
        Some(HttpResult::BadCert) => return Verdict::BadCert,
        Some(HttpResult::Tls) => return Verdict::TlsBroken,
        Some(HttpResult::Rst) => return Verdict::IpReset,
        _ => {}
    }

    // РЎР°Р№С‚ Р¶РёРІ, РЅРѕ С‚РѕР»СЊРєРѕ РїРѕРґ РёРјРµРЅРµРј СЃ В«www.В» вЂ” С‚РёРїРёС‡РЅР°СЏ Р±РёС‚Р°СЏ A-Р·Р°РїРёСЃСЊ apex.
    // РџСЂРѕРІРµСЂСЏРµРј РџРћРЎР›Р• РѕС†РµРЅРєРё HTTP: РµСЃР»Рё apex РѕС‚РґР°Р» Р·Р°РіР»СѓС€РєСѓ РёР»Рё РїР»РѕС…РѕР№
    // СЃРµСЂС‚РёС„РёРєР°С‚, В«wwwВ» РЅРµ РёСЃРїСЂР°РІРёС‚ СЃРёС‚СѓР°С†РёСЋ Рё РІРµСЂРґРёРєС‚ РґРѕР»Р¶РµРЅ РѕСЃС‚Р°С‚СЊСЃСЏ С‚РѕС‡РЅС‹Рј.
    if www_ok {
        return Verdict::WwwOnly;
    }

    if !dns_consistent {
        return Verdict::DnsBlocked;
    }
    match http {
        Some(HttpResult::Dns) => Verdict::DnsBlocked,
        Some(HttpResult::Timeout) => {
            if alt_ok {
                Verdict::IpUnreachable
            } else if any_reset {
                Verdict::IpReset
            } else {
                Verdict::IpUnreachable
            }
        }
        Some(HttpResult::Other(_)) => Verdict::Unknown,
        None => {
            if alt_ok {
                Verdict::IpUnreachable
            } else if any_reset {
                Verdict::IpReset
            } else if !primary_ok && !alt_ok {
                Verdict::IpUnreachable
            } else {
                Verdict::NoPath
            }
        }
        _ => Verdict::Unknown,
    }
}

/// Проба одного имени по списку его IP. Имя и SNI всегда совпадают — именно
/// поэтому пробы apex и `www.` независимы: у CDN имя привязано к адресу, и один
/// и тот же IP может отвечать под `www.`, но не отвечать под apex.
///
/// Перебирает адреса, пока не найдёт тот, на котором HTTPS реально ответил: у
/// крупных CDN (Vercel, Cloudflare) DNS отдаёт пул адресов, часть которых может
/// не обслуживать конкретное имя или быть недоступна из вашей сети. Останавливаемся
/// на первом успешном HTTPS, но если ни один не ответил — берём первый, кто
/// принял TCP, чтобы в отчёте был правдивый «рабочий IP».
fn probe_host_at(
    host: &str,
    ips: &[String],
    any_reset: &mut bool,
) -> (bool, Option<String>, Option<HttpResult>, String) {
    const MAX_IPS: usize = 3;
    let mut tcp_only: Option<(String, HttpResult)> = None;

    for ip in ips.iter().take(MAX_IPS) {
        let Ok(addr) = ip.parse::<IpAddr>() else { continue };
        match tcp_connect(addr, 443).as_str() {
            "RST/REFUSED" => {
                *any_reset = true;
                continue;
            }
            "Success" => {}
            _ => continue,
        }
        let r = http_via_ip(host, ip.parse().unwrap());
        if let HttpResult::Ok(code) = r {
            return (
                true,
                Some(ip.clone()),
                Some(r),
                format!("HTTPS через {}: HTTP {}", ip, code),
            );
        }
        if tcp_only.is_none() {
            tcp_only = Some((ip.clone(), r));
        }
    }

    match tcp_only {
        Some((ip, r)) => {
            let note = format!("HTTPS через {}: {}", ip, http_result_note(&r));
            (true, Some(ip), Some(r), note)
        }
        None => (false, None, None, "ни один IP не ответил на TCP:443".to_string()),
    }
}

pub fn probe_domain(host: &str) -> DomainProbe {
    let dns = dns_multi(host);

    let mut dns_consistent = true;
    if dns.system.is_empty() {
        // РЎРёСЃС‚РµРјРЅС‹Р№ DNS РЅРµ СЂРµР·РѕР»РІРёС‚ РґРѕРјРµРЅ, РЅРѕ РїСѓР±Р»РёС‡РЅС‹Рµ СЂРµР·РѕР»РІРµСЂС‹ РѕС‚РІРµС‡Р°СЋС‚ вЂ”
        // РїСЂРёР·РЅР°Рє СЃР±РѕСЏ/С†РµРЅР·СѓСЂС‹ Р»РѕРєР°Р»СЊРЅРѕРіРѕ DNS. Р Р°СЃС…РѕР¶РґРµРЅРёРµ СЃР°РјРёС… IP-Р°РґСЂРµСЃРѕРІ
        // (anycast РєСЂСѓРїРЅС‹С… CDN) С†РµРЅР·СѓСЂРѕР№ РќР• СЃС‡РёС‚Р°РµС‚СЃСЏ.
        if !dns.cloudflare.is_empty() || !dns.google.is_empty() {
            dns_consistent = false;
        }
    }

    let is_www = host.starts_with("www.");
    let www_host = if is_www {
        host.to_string()
    } else {
        format!("www.{}", host)
    };

    let primary_ips = dedup_ips(dns.system.iter().copied());
    // РўРѕР»СЊРєРѕ Р°РґСЂРµСЃР° С‚РѕРіРѕ Р¶Рµ РёРјРµРЅРё, РїРѕР»СѓС‡РµРЅРЅС‹Рµ РЅРµ РёР· СЃРёСЃС‚РµРјРЅРѕРіРѕ DNS вЂ” СЌС‚Рѕ Рё РµСЃС‚СЊ
    // РєР°РЅРґРёРґР°С‚С‹ РґР»СЏ РїСЂРѕРІРµСЂРєРё В«РїРѕРґРјРµРЅС‹ DNSВ».
    let doh_ips = dedup_ips(dns.cloudflare.iter().chain(dns.google.iter()).copied());

    let mut any_reset = false;
    let (primary_tcp_ok, mut working_ip, http, mut http_note) =
        probe_host_at(host, &primary_ips, &mut any_reset);

    // Р•СЃР»Рё СЃРёСЃС‚РµРјРЅС‹Р№ DNS РЅРµ РїРѕРґРѕС€С‘Р» вЂ” РїСЂРѕР±СѓРµРј DoH-Р°РґСЂРµСЃР° С‚РѕРіРѕ Р¶Рµ РёРјРµРЅРё.
    let mut alt_tcp_ok = false;
    let mut same_host_alt_ip_works = false;
    if working_ip.is_none() && !doh_ips.is_empty() {
        let (tcp_ok, ip, _http2, note) = probe_host_at(host, &doh_ips, &mut any_reset);
        alt_tcp_ok = tcp_ok;
        if ip.is_some() {
            same_host_alt_ip_works = true;
            working_ip = ip;
            http_note = note;
        }
    }

    // РџСЂРѕР±Р° `www.` вЂ” РїРѕР»РЅРѕСЃС‚СЊСЋ РЅРµР·Р°РІРёСЃРёРјР°СЏ: СЃРІРѕРё Р°РґСЂРµСЃР° Рё СЃРІРѕР№ SNI. РЈ CDN РёРјСЏ
    // РїСЂРёРІСЏР·Р°РЅРѕ Рє Р°РґСЂРµСЃСѓ, РїРѕСЌС‚РѕРјСѓ apex Рё www РЅРµР»СЊР·СЏ РјРµС€Р°С‚СЊ РІ РѕРґРЅРѕР№ РїСЂРѕР±Рµ.
    let (www_ips, www_url, www_ok) = if is_www {
        let ok = matches!(http, Some(HttpResult::Ok(_)));
        (primary_ips.clone(), None, ok)
    } else {
        let www_dns = dns_multi(&www_host);
        let ips = dedup_ips(www_dns.system.iter().copied());
        let mut ignored = false;
        let (_, _, w_http, _w_note) = probe_host_at(&www_host, &ips, &mut ignored);
        let ok = matches!(w_http, Some(HttpResult::Ok(_)));
        let url = ok.then(|| format!("https://{}/", www_host));
        (ips, url, ok)
    };
    if is_www && www_ok {
        http_note = format!("HTTPS С‡РµСЂРµР· www-РёРјСЏ СЂР°Р±РѕС‚Р°РµС‚: {}", http_result_note(http.as_ref().unwrap()));
    }

    let verdict = classify(
        dns_consistent,
        primary_tcp_ok,
        alt_tcp_ok,
        any_reset,
        http.as_ref(),
        www_ok,
    );

    let apex_ip = primary_ips.first().cloned();
    let diagnosis = explain(
        verdict,
        &CauseContext {
            host,
            www_url: www_url.as_deref(),
            apex_ip: apex_ip.as_deref(),
            dns_consistent,
            same_host_alt_ip_works,
        },
    );

    DomainProbe {
        host: host.to_string(),
        dns,
        dns_consistent,
        primary_ips,
        working_ip,
        http_note,
        verdict,
        www_host: if is_www { None } else { Some(www_host) },
        www_ips,
        www_url,
        diagnosis: Some(diagnosis),
    }
}

/// Р РµР·СѓР»СЊС‚Р°С‚ РїСЂРѕРІРµСЂРєРё В«РїРѕРґРјРµРЅС‹ DNSВ» С‡РµСЂРµР· РѕРґРёРЅ DoH-СЃРµСЂРІРёСЃ.
/// РЎРµСЂРІРёСЃ РїС‹С‚Р°РµС‚СЃСЏ РІРµСЂРЅСѓС‚СЊ РЅР°СЃС‚РѕСЏС‰РёР№ СЂР°Р±РѕС‡РёР№ IP РІ РѕР±С…РѕРґ РѕС‚СЂР°РІР»РµРЅРЅРѕРіРѕ DNS.
#[derive(Debug)]
pub struct DnsSubstitution {
    pub service: String,
    pub resolved: Vec<String>,
    /// Р РµР°Р»СЊРЅРѕ В«СЂР°Р±РѕС‡РёР№В» IP вЂ” HTTPS С‡РµСЂРµР· РЅРµРіРѕ РѕС‚РєСЂС‹Р»СЃСЏ (`http_ok == true`).
    /// Р•СЃР»Рё `http_ok == false`, С‚СѓС‚ РјРѕР¶РµС‚ Р»РµР¶Р°С‚СЊ РєР°РЅРґРёРґР°С‚, РїСЂРѕС€РµРґС€РёР№ С‚РѕР»СЊРєРѕ TCP:443.
    pub working_ip: Option<String>,
    pub http_note: String,
    /// HTTPS-РїСЂРѕР±Р° С‡РµСЂРµР· `working_ip` СЂРµР°Р»СЊРЅРѕ РІРµСЂРЅСѓР»Р° OK. РћС‚ СЌС‚РѕРіРѕ Р·Р°РІРёСЃРёС‚,
    /// РјРѕР¶РЅРѕ Р»Рё СЃРѕРІРµС‚РѕРІР°С‚СЊ РїРѕРґРјРµРЅСѓ РІ hosts (РёРЅР°С‡Рµ RST вЂ” hosts Р±РµСЃРїРѕР»РµР·РµРЅ).
    pub http_ok: bool,
}

/// Р­РєСЃРїРѕСЂС‚ HTTPS-РїСЂРѕР±С‹ РїРѕ РєРѕРЅРєСЂРµС‚РЅРѕРјСѓ IP (РґР»СЏ hosts-С„РёС‡Рё: РїСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ
/// СЃР°Р№С‚ СЂРµР°Р»СЊРЅРѕ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ С‡РµСЂРµР· РІС‹Р±СЂР°РЅРЅС‹Р№ Р°РґСЂРµСЃ РїРѕСЃР»Рµ Р·Р°РїРёСЃРё РІ hosts).
pub fn probe_https_by_ip(host: &str, ip: IpAddr) -> HttpResult {
    http_via_ip(host, ip)
}

/// РџСЂРѕРІРµСЂРєР° В«РїРѕРґРјРµРЅС‹ DNSВ»: СЂРµР·РѕР»РІ РґРѕРјРµРЅР° С‡РµСЂРµР· DoH-СЃРµСЂРІРёСЃС‹ (xbox-dns.ru,
/// geohide.ru) Рё РїРѕРёСЃРє СЂР°Р±РѕС‡РµРіРѕ IP. Р•СЃР»Рё СЃРёСЃС‚РµРјРЅС‹Р№/РїСѓР±Р»РёС‡РЅС‹Р№ UDP-DNS РѕС‚СЂР°РІР»РµРЅ,
/// СЌС‚Рё СЃРµСЂРІРёСЃС‹ РјРѕРіСѓС‚ РІРµСЂРЅСѓС‚СЊ РЅР°СЃС‚РѕСЏС‰РёР№ Р°РґСЂРµСЃ, Рё СЃР°Р№С‚ РѕС‚РєСЂРѕРµС‚СЃСЏ С‡РµСЂРµР· РїРѕРґРјРµРЅСѓ.
///
/// * `probe_http` вЂ” РґРµР»Р°С‚СЊ Р»Рё РїРѕР»РЅСѓСЋ HTTPS-РїСЂРѕР±Сѓ РїРµСЂРІРѕРіРѕ СЂР°Р±РѕС‡РµРіРѕ IP
///   (РґР»СЏ РіР»Р°РІРЅРѕРіРѕ РґРѕРјРµРЅР° РґР°/РґР»СЏ РґРѕР»РіРѕРіРѕ РїРµСЂРµР±РѕСЂР° вЂ” РЅРµС‚).
pub fn check_dns_substitution(host: &str, probe_http: bool) -> Vec<DnsSubstitution> {
    let mut out = Vec::new();
    for service in DOH_RESOLVERS {
        let ips = resolve_via_doh(host, service);
        if ips.is_empty() {
            out.push(DnsSubstitution {
                service: service.to_string(),
                resolved: vec![],
                working_ip: None,
                http_note: "РЅРµ РІРµСЂРЅСѓР» IP-Р°РґСЂРµСЃРѕРІ (DoH РЅРµРґРѕСЃС‚СѓРїРµРЅ РёР»Рё РЅРµ СЂРµР·РѕР»РІРёС‚)".to_string(),
                http_ok: false,
            });
            continue;
        }
        let display: Vec<String> = ips.iter().take(4).map(|i| i.to_string()).collect();

        let mut working: Option<IpAddr> = None;
        for ip in ips.iter().take(6) {
            if tcp_connect(*ip, 443) == "Success" {
                working = Some(*ip);
                break;
            }
        }

        let mut http_ok = false;
        let mut http_note;
        if let Some(ip) = working {
            match http_via_ip(host, ip) {
                HttpResult::Ok(code) => {
                    http_ok = true;
                    http_note = format!("HTTPS {} С‡РµСЂРµР· {}", code, ip);
                }
                HttpResult::BlockPage => {
                    http_note = format!("СЃС‚СЂР°РЅРёС†Р° Р±Р»РѕРєРёСЂРѕРІРєРё С‡РµСЂРµР· {}", ip);
                }
                HttpResult::Tls => {
                    http_note = format!("TLS СЃР»РѕРјР°РЅ С‡РµСЂРµР· {}", ip);
                }
                HttpResult::BadCert => {
                    http_note = format!("SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ С‡РµСЂРµР· {}", ip);
                }
                HttpResult::Rst => {
                    http_note = format!("RST С‡РµСЂРµР· {} вЂ” TCP:443 РѕС‚РєСЂС‹С‚, РЅРѕ HTTPS СЂРІС‘С‚СЃСЏ (DPI РїРѕ SNI)", ip);
                }
                HttpResult::Timeout => {
                    http_note = format!("С‚Р°Р№РјР°СѓС‚ С‡РµСЂРµР· {}", ip);
                }
                HttpResult::Dns => {
                    http_note = format!("DNS-РѕС€РёР±РєР° С‡РµСЂРµР· {}", ip);
                }
                HttpResult::Other(m) => {
                    http_note = m;
                }
            }
        } else {
            http_note = "РЅРё РѕРґРёРЅ IP РёР· РїРѕРґРјРµРЅС‹ РЅРµ РѕС‚РІРµС‚РёР» РЅР° TCP:443".to_string();
        }
        if !probe_http {
            // Р›С‘РіРєРёР№ РїСЂРѕРіРѕРЅ (СЃРїРёСЃРѕРє dns_fail): HTTPS РЅРµ РіРѕРЅСЏРµРј, РЅРѕ Рё РЅРµ РЅР°Р·С‹РІР°РµРј
            // IP В«СЂР°Р±РѕС‡РёРјВ» вЂ” С‚РѕР»СЊРєРѕ РєР°РЅРґРёРґР°С‚РѕРј.
            let res = working.is_some();
            http_ok = res;
            if let Some(ip) = working {
                http_note = format!("TCP:443 РѕС‚РІРµС‡Р°РµС‚ ({})", ip);
            }
            out.push(DnsSubstitution {
                service: service.to_string(),
                resolved: display,
                working_ip: working.map(|i| i.to_string()),
                http_note,
                http_ok,
            });
            continue;
        }

        out.push(DnsSubstitution {
            service: service.to_string(),
            resolved: display,
            working_ip: working.map(|i| i.to_string()),
            http_note,
            http_ok,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> HttpResult {
        HttpResult::Ok(200)
    }

    fn ctx<'a>(
        host: &'a str,
        www: Option<&'a str>,
        apex_ip: Option<&'a str>,
    ) -> CauseContext<'a> {
        CauseContext {
            host,
            www_url: www,
            apex_ip,
            dns_consistent: true,
            same_host_alt_ip_works: false,
        }
    }

    #[test]
    fn open_when_primary_reachable() {
        assert_eq!(
            classify(true, true, true, false, Some(&ok()), false),
            Verdict::Open
        );
    }

    #[test]
    fn ip_unreachable_but_alt_works() {
        assert_eq!(
            classify(true, false, true, false, Some(&ok()), false),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn ip_unreachable_all_timeout() {
        assert_eq!(
            classify(true, false, false, false, None, false),
            Verdict::IpUnreachable
        );
    }

    #[test]
    fn dns_censorship_when_inconsistent() {
        assert_eq!(
            classify(false, true, true, false, None, false),
            Verdict::DnsBlocked
        );
    }

    #[test]
    fn dns_mismatch_but_site_ok() {
        assert_eq!(
            classify(false, true, true, false, Some(&ok()), false),
            Verdict::Open
        );
    }

    #[test]
    fn rst_is_dpi_block() {
        assert_eq!(
            classify(true, false, false, true, None, false),
            Verdict::IpReset
        );
    }

    #[test]
    fn tls_broken_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::Tls), false),
            Verdict::TlsBroken
        );
    }

    #[test]
    fn block_page_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BlockPage), false),
            Verdict::BlockPage
        );
    }

    #[test]
    fn bad_cert_verdict() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BadCert), false),
            Verdict::BadCert
        );
    }

    // --- Regression: apex dead, site alive only under www. ---

    #[test]
    fn apex_dead_but_www_ok_is_www_only() {
        assert_eq!(
            classify(
                true,
                false,
                true,
                false,
                Some(&HttpResult::Timeout),
                true
            ),
            Verdict::WwwOnly
        );
    }

    #[test]
    fn www_ok_does_not_mask_block_page() {
        // A block page on apex is a block, not "works with www".
        assert_eq!(
            classify(
                true,
                true,
                true,
                false,
                Some(&HttpResult::BlockPage),
                true
            ),
            Verdict::BlockPage
        );
    }

    #[test]
    fn www_ok_does_not_mask_bad_cert() {
        assert_eq!(
            classify(true, true, true, false, Some(&HttpResult::BadCert), true),
            Verdict::BadCert
        );
    }

    #[test]
    fn www_only_diagnosis_points_to_www_url() {
        let d = explain(
            Verdict::WwwOnly,
            &ctx(
                "cactuscompute.com",
                Some("https://www.cactuscompute.com/"),
                Some("216.150.1.1"),
            ),
        );
        assert!(d.probable_cause.contains("216.150.1.1"), "{}", d.probable_cause);
        assert!(
            d.do_this
                .iter()
                .any(|a| a.contains("https://www.cactuscompute.com/")),
            "{:?}",
            d.do_this
        );
        // Useless actions must be called out, otherwise the user retries blind.
        assert!(!d.wont_help.is_empty(), "wont_help must not be empty");
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
    }

    #[test]
    fn www_only_reason_differs_when_dns_poisoned() {
        let clean = explain(
            Verdict::WwwOnly,
            &ctx("example.com", Some("https://www.example.com/"), Some("1.2.3.4")),
        );
        let mut poisoned = ctx(
            "example.com",
            Some("https://www.example.com/"),
            Some("127.0.0.1"),
        );
        poisoned.dns_consistent = false;
        let dirty = explain(Verdict::WwwOnly, &poisoned);
        // Poisoned DNS and a broken site record must be reported differently.
        assert_ne!(clean.probable_cause, dirty.probable_cause);
    }

    #[test]
    fn unreachable_ip_says_bypass_wont_help() {
        let d = explain(Verdict::IpUnreachable, &ctx("example.com", None, Some("1.2.3.4")));
        assert!(
            d.wont_help.iter().any(|a| a.contains("winws")),
            "{:?}",
            d.wont_help
        );
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts")),
            "hosts must not be advised for a dead IP: {:?}",
            d.do_this
        );
    }

    #[test]
    fn open_has_no_action_noise() {
        let d = explain(Verdict::Open, &ctx("example.com", None, None));
        assert!(d.do_this.is_empty(), "{:?}", d.do_this);
        assert!(d.wont_help.is_empty(), "{:?}", d.wont_help);
    }

    #[test]
    fn verdict_names_are_unique() {
        let all = [
            Verdict::Open,
            Verdict::WwwOnly,
            Verdict::IpUnreachable,
            Verdict::IpReset,
            Verdict::TlsBroken,
            Verdict::BadCert,
            Verdict::DnsBlocked,
            Verdict::BlockPage,
            Verdict::NoPath,
            Verdict::Unknown,
        ];
        let mut names: Vec<&str> = all.iter().map(|v| v.verdict_name()).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "duplicated verdict names: {:?}", names);
    }

    #[test]
    fn site_broken_flag() {
        assert!(!Verdict::Open.site_broken());
        assert!(Verdict::WwwOnly.site_broken());
        assert!(Verdict::IpReset.site_broken());
    }

    #[test]
    #[ignore = "requires network"]
    fn live_probe_google() {
        let p = probe_domain("google.com");
        assert_eq!(p.verdict, Verdict::Open, "probe: {:?}", p);
    }

    /// Real user case: apex DNS returns a dead IP, `www` serves the site.
    #[test]
    #[ignore = "requires network"]
    fn live_probe_cactuscompute() {
        let p = probe_domain("cactuscompute.com");
        println!("verdict: {:?}", p.verdict);
        println!("apex: {:?}", p.primary_ips);
        println!("www: {:?}", p.www_ips);
        println!("www_url: {:?}", p.www_url);
        println!("diagnosis: {:#?}", p.diagnosis);
        assert_eq!(p.verdict, Verdict::WwwOnly, "probe: {:?}", p);
    }
}
