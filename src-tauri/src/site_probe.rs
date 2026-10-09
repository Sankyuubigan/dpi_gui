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
    /// Р вЂќР С•Р СР ВµР Р… Р В±Р ВµР В· `www.` Р Р…Р Вµ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ, Р Р…Р С• РЎвЂљР С•РЎвЂљ Р В¶Р Вµ РЎРѓР В°Р в„–РЎвЂљ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ Р С—Р С• `www.`.
    /// Р С™Р В»Р В°РЎРѓРЎРѓР С‘РЎвЂЎР ВµРЎРѓР С”Р С‘Р в„– РЎРѓР В»РЎС“РЎвЂЎР В°Р в„–: РЎС“ РЎРѓР В°Р в„–РЎвЂљР В° Р В±Р С‘РЎвЂљР В°РЎРЏ A-Р В·Р В°Р С—Р С‘РЎРѓРЎРЉ apex-Р Т‘Р С•Р СР ВµР Р…Р В°, Р В° `www` Р В¶Р С‘Р Р†.
    WwwOnly,
    IpUnreachable,
    IpReset,
    TlsBroken,
    /// Р РЋР В°Р в„–РЎвЂљ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ Р С—Р С• TCP/TLS, Р Р…Р С• РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљ Р Р…Р ВµР Р†Р В°Р В»Р С‘Р Т‘Р ВµР Р… Р Т‘Р В»РЎРЏ Р С‘Р СР ВµР Р…Р С‘ Р Т‘Р С•Р СР ВµР Р…Р В°
    /// (Р В±РЎР‚Р В°РЎС“Р В·Р ВµРЎР‚: NET::ERR_CERT_COMMON_NAME_INVALID Р С‘ РЎвЂљ.Р С—.).
    BadCert,
    DnsBlocked,
    BlockPage,
    NoPath,
    Unknown,
}

impl Verdict {
    /// РЎР°Р№С‚ СЂРµР°Р»СЊРЅРѕ РЅРµРґРѕСЃС‚СѓРїРµРЅ РїРѕР»СЊР·РѕРІР°С‚РµР»СЋ вЂ” РЅСѓР¶РЅР° РґРёР°РіРЅРѕСЃС‚РёРєР° Рё РїРѕРґСЃРєР°Р·РєР°.
    pub fn site_broken(self) -> bool {
        !matches!(self, Verdict::Open)
    }

    /// РљРѕСЂРѕС‚РєРѕРµ С‚РµС…РЅРёС‡РµСЃРєРѕРµ РёРјСЏ РІРµСЂРґРёРєС‚Р° вЂ” РґР»СЏ Р·Р°РіРѕР»РѕРІРєР° РІ РѕС‚С‡С‘С‚Рµ.
    pub fn verdict_name(self) -> &'static str {
        match self {
            Verdict::Open => "РЎРђР™Рў РћРўРљР Р«Р’РђР•РўРЎРЇ",
            Verdict::WwwOnly => "Р РђР‘РћРўРђР•Рў РўРћР›Р¬РљРћ РЎ WWW",
            Verdict::IpUnreachable => "IP РќР• РћРўР’Р•Р§РђР•Рў",
            Verdict::IpReset => "РЎР‘Р РћРЎ РЎРћР•Р”РРќР•РќРРЇ (DPI)",
            Verdict::TlsBroken => "TLS Р Р’РЃРўРЎРЇ",
            Verdict::BadCert => "РќР•Р’РђР›РР”РќР«Р™ РЎР•Р РўРР¤РРљРђРў",
            Verdict::DnsBlocked => "DNS-РџРћР”РњР•РќРђ",
            Verdict::BlockPage => "РЎРўР РђРќРР¦Рђ Р‘Р›РћРљРР РћР’РљР",
            Verdict::NoPath => "РќР•Рў РЎР’РЇР—Р",
            Verdict::Unknown => "РџР РР§РРќРђ РќР• РЇРЎРќРђ",
        }
    }
}

/// Р С™Р С•Р Р…РЎвЂљР ВµР С”РЎРѓРЎвЂљ Р Т‘Р В»РЎРЏ Р С•Р В±РЎР‰РЎРЏРЎРѓР Р…Р ВµР Р…Р С‘РЎРЏ Р С—РЎР‚Р С‘РЎвЂЎР С‘Р Р…РЎвЂ№. Р РЋР С•Р В±Р С‘РЎР‚Р В°Р ВµРЎвЂљРЎРѓРЎРЏ Р С‘Р В· РЎР‚Р ВµР В·РЎС“Р В»РЎРЉРЎвЂљР В°РЎвЂљР С•Р Р† Р С—РЎР‚Р С•Р В± Р С‘ Р Р…Р Вµ
/// РЎРѓР С•Р Т‘Р ВµРЎР‚Р В¶Р С‘РЎвЂљ Р Р…Р С‘РЎвЂЎР ВµР С–Р С•, Р С”РЎР‚Р С•Р СР Вµ РЎвЂћР В°Р С”РЎвЂљР С•Р Р†, РІР‚вЂќ РЎвЂЎРЎвЂљР С•Р В±РЎвЂ№ `explain()` Р С•РЎРѓРЎвЂљР В°Р Р†Р В°Р В»Р В°РЎРѓРЎРЉ РЎвЂЎР С‘РЎРѓРЎвЂљР С•Р в„–
/// РЎвЂћРЎС“Р Р…Р С”РЎвЂ Р С‘Р ВµР в„–, Р С—Р С•Р С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµР СР С•Р в„– РЎР‹Р Р…Р С‘РЎвЂљ-РЎвЂљР ВµРЎРѓРЎвЂљР В°Р СР С‘ Р В±Р ВµР В· РЎРѓР ВµРЎвЂљР С‘.
pub struct CauseContext<'a> {
    pub host: &'a str,
    /// Р Р°Р±РѕС‡РёР№ URL СЃ `www.`, РµСЃР»Рё СЃР°Р№С‚ РѕС‚РєСЂС‹Р»СЃСЏ С‚РѕР»СЊРєРѕ РїРѕРґ РЅРёРј.
    pub www_url: Option<&'a str>,
    /// IP, РІС‹РґР°РЅРЅС‹Р№ DNS РґР»СЏ apex-РґРѕРјРµРЅР° (РґР°Р¶Рµ РµСЃР»Рё РѕРЅ РЅРµ РѕС‚РІРµС‡Р°РµС‚).
    pub apex_ip: Option<&'a str>,
    /// РЎРёСЃС‚РµРјРЅС‹Р№ DNS СЃРѕРІРїР°РґР°РµС‚ СЃ РїСѓР±Р»РёС‡РЅС‹РјРё (false = РІРµСЂРѕСЏС‚РЅР° РїРѕРґРјРµРЅР° DNS).
    pub dns_consistent: bool,
    /// РўРѕ Р¶Рµ РёРјСЏ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ РїРѕ IP, РѕС‚Р»РёС‡РЅРѕРјСѓ РѕС‚ СЃРёСЃС‚РµРјРЅРѕРіРѕ DNS (РїРѕРґРјРµРЅР° DNS).
    pub same_host_alt_ip_works: bool,
}

/// Р В§Р ВµР В»Р С•Р Р†Р ВµРЎвЂЎР ВµРЎРѓР С”Р С‘Р в„– Р Т‘Р С‘Р В°Р С–Р Р…Р С•Р В·: Р С•Р Т‘Р Р…Р В° РЎРѓРЎвЂљРЎР‚Р С•Р С”Р В° Р С—РЎР‚Р С‘РЎвЂЎР С‘Р Р…РЎвЂ№ + РЎвЂЎРЎвЂљР С• Р Т‘Р ВµР В»Р В°РЎвЂљРЎРЉ + РЎвЂЎРЎвЂљР С• Р СњР вЂў Р С—Р С•Р СР С•Р В¶Р ВµРЎвЂљ.
#[derive(Debug)]
pub struct Diagnosis {
    pub probable_cause: String,
    pub do_this: Vec<String>,
    pub wont_help: Vec<String>,
}

/// Р СџР С•РЎРЏРЎРѓР Р…Р ВµР Р…Р С‘Р Вµ Р С—РЎР‚Р С‘РЎвЂЎР С‘Р Р…РЎвЂ№ Р Р…Р ВµР Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р Р…Р С•РЎРѓРЎвЂљР С‘. Р СњР С‘Р С”Р В°Р С”Р С‘РЎвЂ¦ РЎРѓР ВµРЎвЂљР ВµР Р†РЎвЂ№РЎвЂ¦ Р Р†РЎвЂ№Р В·Р С•Р Р†Р С•Р Р† РІР‚вЂќ РЎвЂљР С•Р В»РЎРЉР С”Р С• РЎвЂћР В°Р С”РЎвЂљРЎвЂ№.
pub fn explain(verdict: Verdict, ctx: &CauseContext) -> Diagnosis {
    let mut do_this = Vec::new();
    let mut wont_help = Vec::new();

    let probable_cause = match verdict {
        Verdict::Open => "Р РЋР В°Р в„–РЎвЂљ Р Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р ВµР Р…, РЎРѓ Р Т‘Р С•Р СР ВµР Р…Р С•Р С Р С‘ РЎРѓР ВµРЎвЂљРЎРЉРЎР‹ Р Р†РЎРѓРЎвЂ Р Р† Р С—Р С•РЎР‚РЎРЏР Т‘Р С”Р Вµ.".to_string(),

        Verdict::WwwOnly => {
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.dns_consistent {
                format!(
                    "DNS-РЎвЂ Р ВµР Р…Р В·РЎС“РЎР‚РЎвЂ№ Р Р…Р ВµРЎвЂљ: Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р В°РЎРЏ A-Р В·Р В°Р С—Р С‘РЎРѓРЎРЉ Р’В«{}Р’В» РЎС“Р С”Р В°Р В·РЎвЂ№Р Р†Р В°Р ВµРЎвЂљ Р Р…Р В° {}, Р Р…Р С• РЎРЊРЎвЂљР С•РЎвЂљ Р В°Р Т‘РЎР‚Р ВµРЎРѓ Р Р…Р Вµ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ. \
                     Р В­РЎвЂљР С• Р В±Р С‘РЎвЂљР В°РЎРЏ Р С”Р С•Р Р…РЎвЂћР С‘Р С–РЎС“РЎР‚Р В°РЎвЂ Р С‘РЎРЏ Р Р…Р В° РЎРѓРЎвЂљР С•РЎР‚Р С•Р Р…Р Вµ РЎРѓР В°Р в„–РЎвЂљР В°, Р В° Р Р…Р Вµ Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р В°. \
                     Р РЋР В°Р в„–РЎвЂљ Р В¶Р С‘Р Р†РЎвЂРЎвЂљ Р Р…Р В° Р Т‘РЎР‚РЎС“Р С–Р С•Р С Р В°Р Т‘РЎР‚Р ВµРЎРѓР Вµ Р С‘ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ РЎвЂљР С•Р В»РЎРЉР С”Р С• Р С—Р С•Р Т‘ Р С‘Р СР ВµР Р…Р ВµР С РЎРѓ Р’В«www.Р’В»",
                    ctx.host, apex
                )
            } else {
                format!(
                    "DNS-Р С•РЎвЂљР Р†Р ВµРЎвЂљРЎвЂ№ РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…Р С•Р С–Р С• Р С‘ Р С—РЎС“Р В±Р В»Р С‘РЎвЂЎР Р…РЎвЂ№РЎвЂ¦ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р ВµРЎР‚Р С•Р Р† РЎР‚Р В°РЎРѓРЎвЂ¦Р С•Р Т‘РЎРЏРЎвЂљРЎРѓРЎРЏ РІР‚вЂќ DNS Р С—Р С•Р Т‘Р СР ВµР Р…РЎвЂР Р…. \
                     Р ВР СРЎРЏ Р’В«{}Р’В» Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљРЎРѓРЎРЏ Р Р…Р В° Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р В°Р Р…Р Р…РЎвЂ№Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ ({}), Р В° Р С‘Р СРЎРЏ РЎРѓ Р’В«www.Р’В» Р Р…Р Вµ Р С•РЎвЂљРЎР‚Р В°Р Р†Р В»Р ВµР Р…Р С• \
                     Р С‘ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ РЎв‚¬РЎвЂљР В°РЎвЂљР Р…Р С•",
                    ctx.host, apex
                )
            }
        }

        Verdict::IpReset => {
            wont_help.push("Р СР ВµР Р…РЎРЏРЎвЂљРЎРЉ DNS РІР‚вЂќ РЎРѓР С•Р ВµР Т‘Р С‘Р Р…Р ВµР Р…Р С‘Р Вµ РЎРѓР В±РЎР‚Р В°РЎРѓРЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ РЎС“Р В¶Р Вµ Р С—Р С•РЎРѓР В»Р Вµ РЎС“РЎРѓРЎвЂљР В°Р Р…Р С•Р Р†Р С”Р С‘ TCP.".to_string());
            "Р РЋР С•Р ВµР Т‘Р С‘Р Р…Р ВµР Р…Р С‘Р Вµ РЎРѓР В±РЎР‚Р В°РЎРѓРЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ (RST) Р Т‘Р С• Р С•Р В±Р СР ВµР Р…Р В° Р Т‘Р В°Р Р…Р Р…РЎвЂ№Р СР С‘ РІР‚вЂќ РЎвЂљР С‘Р С—Р С‘РЎвЂЎР Р…РЎвЂ№Р в„– DPI-Р В±Р В»Р С•Р С” Р Р…Р В° РЎС“РЎР‚Р С•Р Р†Р Р…Р Вµ IP Р С‘Р В»Р С‘ SNI."
                .to_string()
        }

        Verdict::TlsBroken => {
            wont_help.push("РЎРѓР СР ВµР Р…Р В° DNS Р С‘Р В»Р С‘ Р В·Р В°Р С—Р С‘РЎРѓРЎРЉ Р Р† hosts РІР‚вЂќ TCP Р Т‘Р С• РЎРѓР ВµРЎР‚Р Р†Р ВµРЎР‚Р В° Р Т‘Р С•РЎвЂ¦Р С•Р Т‘Р С‘РЎвЂљ.".to_string());
            "TCP-Р С—Р С•РЎР‚РЎвЂљ Р С•РЎвЂљР С”РЎР‚РЎвЂ№РЎвЂљ, Р Р…Р С• TLS-РЎР‚РЎС“Р С”Р С•Р С—Р С•Р В¶Р В°РЎвЂљР С‘Р Вµ РЎР‚Р Р†РЎвЂРЎвЂљРЎРѓРЎРЏ. Р вЂўРЎРѓР В»Р С‘ Р С•Р В±РЎвЂ¦Р С•Р Т‘ Р Р†Р С”Р В»РЎР‹РЎвЂЎРЎвЂР Р… РІР‚вЂќ Р ВµР С–Р С• Р Т‘Р ВµРЎРѓР С‘Р Р…Р С” Р В»Р С•Р СР В°Р ВµРЎвЂљ TLS; \
             Р ВµРЎРѓР В»Р С‘ Р Р†РЎвЂ№Р С”Р В»РЎР‹РЎвЂЎР ВµР Р… РІР‚вЂќ Р С—РЎР‚Р С•Р В±Р В»Р ВµР СР В° Р Р…Р В° РЎРѓРЎвЂљР С•РЎР‚Р С•Р Р…Р Вµ РЎРѓР ВµРЎР‚Р Р†Р ВµРЎР‚Р В°."
                .to_string()
        }

        Verdict::BadCert => {
            wont_help.push("Р С•Р В±РЎвЂ¦Р С•Р Т‘ DPI РІР‚вЂќ Р С•Р Р… РЎвЂљРЎС“РЎвЂљ Р Р…Р С‘ Р С—РЎР‚Р С‘ РЎвЂЎРЎвЂР С.".to_string());
            wont_help.push("РЎРѓР СР ВµР Р…Р В° DNS Р С‘ hosts РІР‚вЂќ РЎРѓР ВµРЎвЂљР ВµР Р†Р С•Р в„– Р С—РЎС“РЎвЂљРЎРЉ РЎР‚Р В°Р В±Р С•РЎвЂљР В°Р ВµРЎвЂљ.".to_string());
            "Р РЋР ВµРЎР‚Р Р†Р ВµРЎР‚ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ Р С—Р С• РЎРѓР ВµРЎвЂљР С‘, Р Р…Р С• SSL-РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљ Р Р…Р ВµР Р†Р В°Р В»Р С‘Р Т‘Р ВµР Р… Р Т‘Р В»РЎРЏ РЎРЊРЎвЂљР С•Р С–Р С• Р С‘Р СР ВµР Р…Р С‘ РІР‚вЂќ \
             Р В±РЎР‚Р В°РЎС“Р В·Р ВµРЎР‚ Р С—Р С•Р С”Р В°Р В¶Р ВµРЎвЂљ NET::ERR_CERT_COMMON_NAME_INVALID. Р В­РЎвЂљР С• Р С•РЎв‚¬Р С‘Р В±Р С”Р В° РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљР В°, Р Р…Р Вµ Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р В°."
                .to_string()
        }

        Verdict::DnsBlocked => {
            do_this.push("РЎРѓР СР ВµР Р…Р С‘РЎвЂљР Вµ DNS Р Р…Р В° 1.1.1.1 / 8.8.8.8 Р С‘Р В»Р С‘ Р Р†Р С”Р В»РЎР‹РЎвЂЎР С‘РЎвЂљР Вµ DoH Р Р† Р В±РЎР‚Р В°РЎС“Р В·Р ВµРЎР‚Р Вµ".to_string());
            "Р вЂќР С•Р СР ВµР Р… Р Р…Р Вµ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р С‘РЎвЂљРЎРѓРЎРЏ Р С‘Р В»Р С‘ DNS-Р С•РЎвЂљР Р†Р ВµРЎвЂљРЎвЂ№ Р С—Р С•Р Т‘Р СР ВµР Р…Р ВµР Р…РЎвЂ№ РІР‚вЂќ Р Р†Р ВµРЎР‚Р С•РЎРЏРЎвЂљР Р…Р В° Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р В° Р Р…Р В° РЎС“РЎР‚Р С•Р Р†Р Р…Р Вµ DNS."
                .to_string()
        }

        Verdict::BlockPage => {
            do_this.push("Р Т‘Р С•Р В±Р В°Р Р†РЎРЉРЎвЂљР Вµ Р Т‘Р С•Р СР ВµР Р… Р Р† РЎРѓР С—Р С‘РЎРѓР С•Р С” Р С•Р В±РЎвЂ¦Р С•Р Т‘Р В° (general-Р В»Р С‘РЎРѓРЎвЂљ)".to_string());
            wont_help.push("РЎРѓР СР ВµР Р…Р В° DNS РІР‚вЂќ DNS РЎР‚Р В°Р В±Р С•РЎвЂљР В°Р ВµРЎвЂљ Р С—РЎР‚Р В°Р Р†Р С‘Р В»РЎРЉР Р…Р С•, Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”РЎС“ Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљ РЎРѓР ВµРЎР‚Р Р†Р ВµРЎР‚.".to_string());
            "Р РЋР ВµРЎР‚Р Р†Р ВµРЎР‚ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ, Р Р…Р С• Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљ РЎРѓРЎвЂљРЎР‚Р В°Р Р…Р С‘РЎвЂ РЎС“-Р В·Р В°Р С–Р В»РЎС“РЎв‚¬Р С”РЎС“ Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р С‘ (403/451).".to_string()
        }

        Verdict::IpUnreachable => {
            wont_help.push("Р С•Р В±РЎвЂ¦Р С•Р Т‘ winws РІР‚вЂќ Р С•Р Р… Р С—Р ВµРЎР‚Р ВµРЎвЂ¦Р Р†Р В°РЎвЂљРЎвЂ№Р Р†Р В°Р ВµРЎвЂљ РЎС“Р В¶Р Вµ РЎС“РЎРѓРЎвЂљР В°Р Р…Р С•Р Р†Р В»Р ВµР Р…Р Р…РЎвЂ№Р Вµ РЎРѓР С•Р ВµР Т‘Р С‘Р Р…Р ВµР Р…Р С‘РЎРЏ.".to_string());
            wont_help.push("РЎРѓР СР ВµР Р…Р В° DNS Р С‘ hosts РІР‚вЂќ DNS Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљ Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р С‘Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ РЎРѓР В°Р в„–РЎвЂљР В°.".to_string());
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.same_host_alt_ip_works {
                "DNS Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљ Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р С‘Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ РЎРѓР В°Р в„–РЎвЂљР В°, Р Р…Р С• Р Р…Р В° Р Р…Р ВµР С–Р С• Р Р…Р ВµРЎвЂљ Р С•РЎвЂљР Р†Р ВµРЎвЂљР В° РЎРѓ Р Р†Р В°РЎв‚¬Р ВµР в„– РЎРѓР ВµРЎвЂљР С‘. \
                 Р СџРЎР‚Р С•Р В±Р В»Р ВµР СР В° Р Р…Р В° Р СР В°РЎР‚РЎв‚¬РЎР‚РЎС“РЎвЂљР Вµ Р Т‘Р С• РЎРѓР ВµРЎР‚Р Р†Р ВµРЎР‚Р В°, Р В° Р Р…Р Вµ Р Р† Р С•Р В±РЎвЂ¦Р С•Р Т‘Р Вµ."
                    .to_string()
            } else {
                format!(
                    "DNS Р С•РЎвЂљР Т‘Р В°РЎвЂРЎвЂљ Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р С‘Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ РЎРѓР В°Р в„–РЎвЂљР В° ({}), Р Р…Р С• РЎРѓР ВµРЎР‚Р Р†Р ВµРЎР‚ Р Р…Р В° Р Р…Р ВµР С–Р С• Р Р…Р Вµ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ РІР‚вЂќ \
                     Р С•Р Р… Р Р…Р Вµ Р С•Р В±РЎРѓР В»РЎС“Р В¶Р С‘Р Р†Р В°Р ВµРЎвЂљ РЎРЊРЎвЂљР С•РЎвЂљ Р Т‘Р С•Р СР ВµР Р…. Р СџРЎР‚Р С•Р В±Р В»Р ВµР СР В° Р Р…Р В° РЎРѓРЎвЂљР С•РЎР‚Р С•Р Р…Р Вµ РЎРѓР В°Р в„–РЎвЂљР В°, Р С•Р В±РЎвЂ¦Р С•Р Т‘ РЎвЂљРЎС“РЎвЂљ Р Р…Р Вµ Р С—Р С•Р СР С•Р В¶Р ВµРЎвЂљ.",
                    apex
                )
            }
        }

        Verdict::NoPath => {
            wont_help.push("Р С•Р В±РЎвЂ¦Р С•Р Т‘ winws РІР‚вЂќ Р Т‘Р С• Р В°Р Т‘РЎР‚Р ВµРЎРѓР С•Р Р† РЎРѓР В°Р в„–РЎвЂљР В° РЎРѓР Р†РЎРЏР В·Р С‘ Р Р…Р ВµРЎвЂљ Р Р† Р С—РЎР‚Р С‘Р Р…РЎвЂ Р С‘Р С—Р Вµ.".to_string());
            "Р СњР С‘ Р С•Р Т‘Р С‘Р Р… Р В°Р Т‘РЎР‚Р ВµРЎРѓ РЎРѓР В°Р в„–РЎвЂљР В° Р Р…Р Вµ Р С—РЎР‚Р С‘Р Р…РЎРЏР В» РЎРѓР С•Р ВµР Т‘Р С‘Р Р…Р ВµР Р…Р С‘Р Вµ. Р СџРЎР‚Р С•Р Р†Р ВµРЎР‚РЎРЉРЎвЂљР Вµ Р С•Р В±РЎвЂ°Р ВµР Вµ Р С—Р С•Р Т‘Р С”Р В»РЎР‹РЎвЂЎР ВµР Р…Р С‘Р Вµ Р С” Р С‘Р Р…РЎвЂљР ВµРЎР‚Р Р…Р ВµРЎвЂљРЎС“."
                .to_string()
        }

        Verdict::Unknown => "Р СњР Вµ РЎС“Р Т‘Р В°Р В»Р С•РЎРѓРЎРЉ Р С•Р Т‘Р Р…Р С•Р В·Р Р…Р В°РЎвЂЎР Р…Р С• Р С•Р С—РЎР‚Р ВµР Т‘Р ВµР В»Р С‘РЎвЂљРЎРЉ Р С—РЎР‚Р С‘РЎвЂЎР С‘Р Р…РЎС“.".to_string(),
    };

    // Р вЂўР Т‘Р С‘Р Р…РЎвЂ№Р Вµ Р Т‘Р ВµР в„–РЎРѓРЎвЂљР Р†Р С‘РЎРЏ: РЎР‚Р В°Р В±Р С•РЎвЂљР В°РЎР‹РЎвЂ°Р ВµР Вµ Р С‘Р СРЎРЏ РІР‚вЂќ Р С–Р В»Р В°Р Р†Р Р…РЎвЂ№Р в„– РЎРѓР С•Р Р†Р ВµРЎвЂљ.
    if verdict == Verdict::WwwOnly {
        if let Some(url) = ctx.www_url {
            do_this.insert(0, format!("Р С•РЎвЂљР С”РЎР‚Р С•Р в„–РЎвЂљР Вµ РЎРѓР В°Р в„–РЎвЂљ Р С—Р С• Р В°Р Т‘РЎР‚Р ВµРЎРѓРЎС“ РЎРѓ Р’В«wwwР’В»: {}", url));
        }
        do_this.push("Р С—Р ВµРЎР‚Р ВµРЎвЂ¦Р С•Р Т‘Р С‘РЎвЂљР Вµ Р С—Р С• РЎРЊРЎвЂљР С•Р в„– РЎРѓРЎРѓРЎвЂ№Р В»Р С”Р Вµ РІР‚вЂќ Р С•Р Р…Р В° Р С‘ Р ВµРЎРѓРЎвЂљРЎРЉ РЎР‚Р В°Р В±Р С•РЎвЂЎР В°РЎРЏ".to_string());
        wont_help.push("Р С—РЎР‚Р В°Р Р†Р С‘РЎвЂљРЎРЉ hosts Р С‘ Р С•РЎвЂљР С”Р В»РЎР‹РЎвЂЎР В°РЎвЂљРЎРЉ DoH РІР‚вЂќ Р С—РЎР‚Р С•РЎвЂ°Р Вµ Р С•РЎвЂљР С”РЎР‚РЎвЂ№РЎвЂљРЎРЉ РЎР‚Р В°Р В±Р С•РЎвЂЎРЎС“РЎР‹ РЎРѓРЎРѓРЎвЂ№Р В»Р С”РЎС“.".to_string());
        wont_help.push("Р Т‘Р С•Р В±Р В°Р Р†Р В»РЎРЏРЎвЂљРЎРЉ Р Т‘Р С•Р СР ВµР Р… Р Р† РЎРѓР С—Р С‘РЎРѓР С•Р С” Р С•Р В±РЎвЂ¦Р С•Р Т‘Р В° РІР‚вЂќ Р С•Р Р… Р Р…Р Вµ Р В·Р В°РЎРѓРЎвЂљР В°Р Р†Р С‘РЎвЂљ Р СРЎвЂРЎР‚РЎвЂљР Р†РЎвЂ№Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°РЎвЂљРЎРЉ.".to_string());
    }

    if verdict == Verdict::Open {
        return Diagnosis {
            probable_cause,
            do_this,
            wont_help,
        };
    }

    if verdict == Verdict::BlockPage || verdict == Verdict::DnsBlocked {
        // Р Т‘Р ВµР в„–РЎРѓРЎвЂљР Р†Р С‘РЎРЏ РЎС“Р В¶Р Вµ РЎРѓРЎвЂћР С•РЎР‚Р СРЎС“Р В»Р С‘РЎР‚Р С•Р Р†Р В°Р Р…РЎвЂ№ Р Р†РЎвЂ№РЎв‚¬Р Вµ
    } else if do_this.is_empty() && verdict != Verdict::WwwOnly {
        do_this.push("Р С—Р С•Р С—РЎР‚Р С•Р В±РЎС“Р в„–РЎвЂљР Вµ VPN/Р С—РЎР‚Р С•Р С”РЎРѓР С‘ Р С‘ Р С—Р С•Р Р†РЎвЂљР С•РЎР‚Р С‘РЎвЂљР Вµ Р В°Р Р…Р В°Р В»Р С‘Р В· Р С—Р С•Р В·Р В¶Р Вµ".to_string());
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
    /// РђРґСЂРµСЃР°, РІС‹РґР°РЅРЅС‹Рµ СЃРёСЃС‚РµРјРЅС‹Рј DNS РґР»СЏ apex-РёРјРµРЅРё.
    pub primary_ips: Vec<String>,
    /// РђРґСЂРµСЃ, РЅР° РєРѕС‚РѕСЂРѕРј СЃРµСЂРІРµСЂ РїСЂРёРЅСЏР» СЃРѕРµРґРёРЅРµРЅРёРµ (РЅРµ Р·РЅР°С‡РёС‚, С‡С‚Рѕ HTTPS РїСЂРѕС€С‘Р»).
    pub working_ip: Option<String>,
    pub http_note: String,
    pub verdict: Verdict,
    /// РРјСЏ СЃ `www.`, РµСЃР»Рё РїРѕ РЅРµРјСѓ СЃР°Р№С‚ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ.
    pub www_host: Option<String>,
    /// IP, РІС‹РґР°РЅРЅС‹Рµ DNS РґР»СЏ `www.`
    pub www_ips: Vec<String>,
    /// Р Р°Р±РѕС‡РёР№ URL СЃ `www.` вЂ” РµРіРѕ Рё РЅСѓР¶РЅРѕ РѕС‚РєСЂС‹С‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЋ.
    pub www_url: Option<String>,
    /// Р”РёР°РіРЅРѕР·: РїСЂРёС‡РёРЅР° + РґРµР№СЃС‚РІРёСЏ + В«С‡С‚Рѕ РЅРµ РїРѕРјРѕР¶РµС‚В».
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

/// Р В§Р ВµР В»Р С•Р Р†Р ВµР С”Р С•РЎвЂЎР С‘РЎвЂљР В°Р ВµР СРЎвЂ№Р в„– РЎР‚Р ВµР В·РЎС“Р В»РЎРЉРЎвЂљР В°РЎвЂљ HTTPS-Р С—РЎР‚Р С•Р В±РЎвЂ№.
pub fn http_result_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::Tls => "TLS РЎРѓР В»Р С•Р СР В°Р Р…".to_string(),
        HttpResult::BadCert => "SSL-РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљ Р Р…Р ВµР Р†Р В°Р В»Р С‘Р Т‘Р ВµР Р…".to_string(),
        HttpResult::Rst => "RST".to_string(),
        HttpResult::Timeout => "РЎвЂљР В°Р в„–Р СР В°РЎС“РЎвЂљ".to_string(),
        HttpResult::Dns => "DNS-Р С•РЎв‚¬Р С‘Р В±Р С”Р В°".to_string(),
        HttpResult::BlockPage => "РЎРѓРЎвЂљРЎР‚Р В°Р Р…Р С‘РЎвЂ Р В° Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р С‘".to_string(),
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
        Err(e) => return HttpResult::Other(format!("Р Р…Р Вµ РЎС“Р Т‘Р В°Р В»Р С•РЎРѓРЎРЉ РЎРѓР С•Р В·Р Т‘Р В°РЎвЂљРЎРЉ Р С”Р В»Р С‘Р ВµР Р…РЎвЂљ: {}", e)),
    };
    match client.get(format!("https://{}/", host)).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 403 || status == 451 {
                return HttpResult::BlockPage;
            }
            if (200..=399).contains(&status) {
                let low = resp.text().unwrap_or_default().to_lowercase();
                if low.contains("РЎР‚Р С•РЎРѓР С”Р С•Р СР Р…Р В°Р Т‘Р В·Р С•РЎР‚")
                    || low.contains("Р В·Р В°Р В±Р В»Р С•Р С”Р С‘РЎР‚")
                    || low.contains("this site is blocked")
                    || low.contains("access denied: by order")
                    || low.contains("РЎРѓРЎвЂљРЎР‚Р В°Р Р…Р С‘РЎвЂ Р В° Р Р…Р Вµ Р СР С•Р В¶Р ВµРЎвЂљ Р В±РЎвЂ№РЎвЂљРЎРЉ Р С•РЎвЂљР С•Р В±РЎР‚Р В°Р В¶Р ВµР Р…Р В°")
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

/// Р В§Р С‘РЎРѓРЎвЂљР В°РЎРЏ Р В»Р С•Р С–Р С‘Р С”Р В° Р С”Р В»Р В°РЎРѓРЎРѓР С‘РЎвЂћР С‘Р С”Р В°РЎвЂ Р С‘Р С‘ Р С—Р ВµРЎР‚Р Р†Р С•Р С—РЎР‚Р С‘РЎвЂЎР С‘Р Р…РЎвЂ№ РІР‚вЂќ Р С•РЎвЂљР Т‘Р ВµР В»Р ВµР Р…Р В° Р С•РЎвЂљ I/O, РЎвЂЎРЎвЂљР С•Р В±РЎвЂ№ Р ВµРЎвЂ Р СР С•Р В¶Р Р…Р С•
/// Р В±РЎвЂ№Р В»Р С• Р С—Р С•Р С”РЎР‚РЎвЂ№РЎвЂљРЎРЉ РЎР‹Р Р…Р С‘РЎвЂљ-РЎвЂљР ВµРЎРѓРЎвЂљР В°Р СР С‘ Р В±Р ВµР В· РЎРѓР ВµРЎвЂљР С‘.
///
/// * `dns_consistent` РІР‚вЂќ РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…РЎвЂ№Р в„– DNS РЎРѓР С•Р Р†Р С—Р В°Р Т‘Р В°Р ВµРЎвЂљ РЎРѓ Р С—РЎС“Р В±Р В»Р С‘РЎвЂЎР Р…РЎвЂ№Р СР С‘ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р ВµРЎР‚Р В°Р СР С‘.
/// * `primary_ok` РІР‚вЂќ РЎвЂ¦Р С•РЎвЂљРЎРЏ Р В±РЎвЂ№ Р С•Р Т‘Р С‘Р Р… IP РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…Р С•Р С–Р С• DNS Р С•РЎвЂљР Р†Р ВµРЎвЂљР С‘Р В» Р Р…Р В° TCP:443.
/// * `alt_ok` РІР‚вЂќ РЎвЂ¦Р С•РЎвЂљРЎРЏ Р В±РЎвЂ№ Р С•Р Т‘Р С‘Р Р… Р’В«Р В°Р В»РЎРЉРЎвЂљР ВµРЎР‚Р Р…Р В°РЎвЂљР С‘Р Р†Р Р…РЎвЂ№Р в„–Р’В» IP (www + DoH) Р С•РЎвЂљР Р†Р ВµРЎвЂљР С‘Р В» Р Р…Р В° TCP:443.
/// * `any_reset` РІР‚вЂќ РЎРѓРЎР‚Р ВµР Т‘Р С‘ Р Р†РЎРѓР ВµРЎвЂ¦ Р С—Р С•Р С—РЎвЂ№РЎвЂљР С•Р С” Р В±РЎвЂ№Р В»Р С• RST.
/// * `http` РІР‚вЂќ РЎР‚Р ВµР В·РЎС“Р В»РЎРЉРЎвЂљР В°РЎвЂљ HTTPS-Р В·Р В°Р С—РЎР‚Р С•РЎРѓР В° РЎвЂЎР ВµРЎР‚Р ВµР В· Р С—Р ВµРЎР‚Р Р†РЎвЂ№Р в„– РЎР‚Р В°Р В±Р С•РЎвЂЎР С‘Р в„– IP.
/// * `www_ok` РІР‚вЂќ РЎРѓР В°Р в„–РЎвЂљ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ Р С—Р С•Р Т‘ Р С‘Р СР ВµР Р…Р ВµР С РЎРѓ `www.`
pub fn classify(
    dns_consistent: bool,
    primary_ok: bool,
    alt_ok: bool,
    any_reset: bool,
    http: Option<&HttpResult>,
    www_ok: bool,
) -> Verdict {
    // Р РЋР Р…Р В°РЎвЂЎР В°Р В»Р В° РІР‚вЂќ РЎвЂћР В°Р С”РЎвЂљР С‘РЎвЂЎР ВµРЎРѓР С”Р В°РЎРЏ РЎР‚Р В°Р В±Р С•РЎвЂљР С•РЎРѓР С—Р С•РЎРѓР С•Р В±Р Р…Р С•РЎРѓРЎвЂљРЎРЉ РЎРѓР В°Р в„–РЎвЂљР В°. Р вЂќР В°Р В¶Р Вµ Р ВµРЎРѓР В»Р С‘ DNS-РЎРѓР С—Р С‘РЎРѓР С”Р С‘
    // РЎР‚Р В°Р В·Р Р…РЎвЂ№РЎвЂ¦ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р ВµРЎР‚Р С•Р Р† Р С•РЎвЂљР В»Р С‘РЎвЂЎР В°РЎР‹РЎвЂљРЎРѓРЎРЏ (Р Р…Р С•РЎР‚Р СР В°Р В»РЎРЉР Р…РЎвЂ№Р в„– anycast РЎС“ Р С”РЎР‚РЎС“Р С—Р Р…РЎвЂ№РЎвЂ¦ CDN), РЎРѓР В°Р в„–РЎвЂљ
    // Р СР С•Р В¶Р ВµРЎвЂљ Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°РЎвЂљРЎРЉРЎРѓРЎРЏ РІР‚вЂќ РЎРЊРЎвЂљР С• Р Р…Р Вµ РЎвЂ Р ВµР Р…Р В·РЎС“РЎР‚Р В°.
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

    // Р РЋР В°Р в„–РЎвЂљ Р В¶Р С‘Р Р†, Р Р…Р С• РЎвЂљР С•Р В»РЎРЉР С”Р С• Р С—Р С•Р Т‘ Р С‘Р СР ВµР Р…Р ВµР С РЎРѓ Р’В«www.Р’В» РІР‚вЂќ РЎвЂљР С‘Р С—Р С‘РЎвЂЎР Р…Р В°РЎРЏ Р В±Р С‘РЎвЂљР В°РЎРЏ A-Р В·Р В°Р С—Р С‘РЎРѓРЎРЉ apex.
    // Р СџРЎР‚Р С•Р Р†Р ВµРЎР‚РЎРЏР ВµР С Р СџР С›Р РЋР вЂєР вЂў Р С•РЎвЂ Р ВµР Р…Р С”Р С‘ HTTP: Р ВµРЎРѓР В»Р С‘ apex Р С•РЎвЂљР Т‘Р В°Р В» Р В·Р В°Р С–Р В»РЎС“РЎв‚¬Р С”РЎС“ Р С‘Р В»Р С‘ Р С—Р В»Р С•РЎвЂ¦Р С•Р в„–
    // РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљ, Р’В«wwwР’В» Р Р…Р Вµ Р С‘РЎРѓР С—РЎР‚Р В°Р Р†Р С‘РЎвЂљ РЎРѓР С‘РЎвЂљРЎС“Р В°РЎвЂ Р С‘РЎР‹ Р С‘ Р Р†Р ВµРЎР‚Р Т‘Р С‘Р С”РЎвЂљ Р Т‘Р С•Р В»Р В¶Р ВµР Р… Р С•РЎРѓРЎвЂљР В°РЎвЂљРЎРЉРЎРѓРЎРЏ РЎвЂљР С•РЎвЂЎР Р…РЎвЂ№Р С.
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

/// РџСЂРѕР±Р° РѕРґРЅРѕРіРѕ РёРјРµРЅРё РїРѕ СЃРїРёСЃРєСѓ РµРіРѕ IP. РРјСЏ Рё SNI РІСЃРµРіРґР° СЃРѕРІРїР°РґР°СЋС‚ вЂ” РёРјРµРЅРЅРѕ
/// РїРѕСЌС‚РѕРјСѓ РїСЂРѕР±С‹ apex Рё `www.` РЅРµР·Р°РІРёСЃРёРјС‹: Сѓ CDN РёРјСЏ РїСЂРёРІСЏР·Р°РЅРѕ Рє Р°РґСЂРµСЃСѓ, Рё РѕРґРёРЅ
/// Рё С‚РѕС‚ Р¶Рµ IP РјРѕР¶РµС‚ РѕС‚РІРµС‡Р°С‚СЊ РїРѕРґ `www.`, РЅРѕ РЅРµ РѕС‚РІРµС‡Р°С‚СЊ РїРѕРґ apex.
///
/// РџРµСЂРµР±РёСЂР°РµС‚ Р°РґСЂРµСЃР°, РїРѕРєР° РЅРµ РЅР°Р№РґС‘С‚ С‚РѕС‚, РЅР° РєРѕС‚РѕСЂРѕРј HTTPS СЂРµР°Р»СЊРЅРѕ РѕС‚РІРµС‚РёР»: Сѓ
/// РєСЂСѓРїРЅС‹С… CDN (Vercel, Cloudflare) DNS РѕС‚РґР°С‘С‚ РїСѓР» Р°РґСЂРµСЃРѕРІ, С‡Р°СЃС‚СЊ РєРѕС‚РѕСЂС‹С… РјРѕР¶РµС‚
/// РЅРµ РѕР±СЃР»СѓР¶РёРІР°С‚СЊ РєРѕРЅРєСЂРµС‚РЅРѕРµ РёРјСЏ РёР»Рё Р±С‹С‚СЊ РЅРµРґРѕСЃС‚СѓРїРЅР° РёР· РІР°С€РµР№ СЃРµС‚Рё. РћСЃС‚Р°РЅР°РІР»РёРІР°РµРјСЃСЏ
/// РЅР° РїРµСЂРІРѕРј СѓСЃРїРµС€РЅРѕРј HTTPS, РЅРѕ РµСЃР»Рё РЅРё РѕРґРёРЅ РЅРµ РѕС‚РІРµС‚РёР» вЂ” Р±РµСЂС‘Рј РїРµСЂРІС‹Р№, РєС‚Рѕ
/// РїСЂРёРЅСЏР» TCP, С‡С‚РѕР±С‹ РІ РѕС‚С‡С‘С‚Рµ Р±С‹Р» РїСЂР°РІРґРёРІС‹Р№ В«СЂР°Р±РѕС‡РёР№ IPВ».
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
                format!("HTTPS С‡РµСЂРµР· {}: HTTP {}", ip, code),
            );
        }
        if tcp_only.is_none() {
            tcp_only = Some((ip.clone(), r));
        }
    }

    match tcp_only {
        Some((ip, r)) => {
            let note = format!("HTTPS С‡РµСЂРµР· {}: {}", ip, http_result_note(&r));
            (true, Some(ip), Some(r), note)
        }
        None => (false, None, None, "РЅРё РѕРґРёРЅ IP РЅРµ РѕС‚РІРµС‚РёР» РЅР° TCP:443".to_string()),
    }
}

pub fn probe_domain(host: &str) -> DomainProbe {
    let dns = dns_multi(host);

    let mut dns_consistent = true;
    if dns.system.is_empty() {
        // Р РЋР С‘РЎРѓРЎвЂљР ВµР СР Р…РЎвЂ№Р в„– DNS Р Р…Р Вµ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р С‘РЎвЂљ Р Т‘Р С•Р СР ВµР Р…, Р Р…Р С• Р С—РЎС“Р В±Р В»Р С‘РЎвЂЎР Р…РЎвЂ№Р Вµ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р ВµРЎР‚РЎвЂ№ Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°РЎР‹РЎвЂљ РІР‚вЂќ
        // Р С—РЎР‚Р С‘Р В·Р Р…Р В°Р С” РЎРѓР В±Р С•РЎРЏ/РЎвЂ Р ВµР Р…Р В·РЎС“РЎР‚РЎвЂ№ Р В»Р С•Р С”Р В°Р В»РЎРЉР Р…Р С•Р С–Р С• DNS. Р В Р В°РЎРѓРЎвЂ¦Р С•Р В¶Р Т‘Р ВµР Р…Р С‘Р Вµ РЎРѓР В°Р СР С‘РЎвЂ¦ IP-Р В°Р Т‘РЎР‚Р ВµРЎРѓР С•Р Р†
        // (anycast Р С”РЎР‚РЎС“Р С—Р Р…РЎвЂ№РЎвЂ¦ CDN) РЎвЂ Р ВµР Р…Р В·РЎС“РЎР‚Р С•Р в„– Р СњР вЂў РЎРѓРЎвЂЎР С‘РЎвЂљР В°Р ВµРЎвЂљРЎРѓРЎРЏ.
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
    // Р СћР С•Р В»РЎРЉР С”Р С• Р В°Р Т‘РЎР‚Р ВµРЎРѓР В° РЎвЂљР С•Р С–Р С• Р В¶Р Вµ Р С‘Р СР ВµР Р…Р С‘, Р С—Р С•Р В»РЎС“РЎвЂЎР ВµР Р…Р Р…РЎвЂ№Р Вµ Р Р…Р Вµ Р С‘Р В· РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…Р С•Р С–Р С• DNS РІР‚вЂќ РЎРЊРЎвЂљР С• Р С‘ Р ВµРЎРѓРЎвЂљРЎРЉ
    // Р С”Р В°Р Р…Р Т‘Р С‘Р Т‘Р В°РЎвЂљРЎвЂ№ Р Т‘Р В»РЎРЏ Р С—РЎР‚Р С•Р Р†Р ВµРЎР‚Р С”Р С‘ Р’В«Р С—Р С•Р Т‘Р СР ВµР Р…РЎвЂ№ DNSР’В».
    let doh_ips = dedup_ips(dns.cloudflare.iter().chain(dns.google.iter()).copied());

    let mut any_reset = false;
    let (primary_tcp_ok, mut working_ip, http, mut http_note) =
        probe_host_at(host, &primary_ips, &mut any_reset);

    // Р вЂўРЎРѓР В»Р С‘ РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…РЎвЂ№Р в„– DNS Р Р…Р Вµ Р С—Р С•Р Т‘Р С•РЎв‚¬РЎвЂР В» РІР‚вЂќ Р С—РЎР‚Р С•Р В±РЎС“Р ВµР С DoH-Р В°Р Т‘РЎР‚Р ВµРЎРѓР В° РЎвЂљР С•Р С–Р С• Р В¶Р Вµ Р С‘Р СР ВµР Р…Р С‘.
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

    // Р СџРЎР‚Р С•Р В±Р В° `www.` РІР‚вЂќ Р С—Р С•Р В»Р Р…Р С•РЎРѓРЎвЂљРЎРЉРЎР‹ Р Р…Р ВµР В·Р В°Р Р†Р С‘РЎРѓР С‘Р СР В°РЎРЏ: РЎРѓР Р†Р С•Р С‘ Р В°Р Т‘РЎР‚Р ВµРЎРѓР В° Р С‘ РЎРѓР Р†Р С•Р в„– SNI. Р Р€ CDN Р С‘Р СРЎРЏ
    // Р С—РЎР‚Р С‘Р Р†РЎРЏР В·Р В°Р Р…Р С• Р С” Р В°Р Т‘РЎР‚Р ВµРЎРѓРЎС“, Р С—Р С•РЎРЊРЎвЂљР С•Р СРЎС“ apex Р С‘ www Р Р…Р ВµР В»РЎРЉР В·РЎРЏ Р СР ВµРЎв‚¬Р В°РЎвЂљРЎРЉ Р Р† Р С•Р Т‘Р Р…Р С•Р в„– Р С—РЎР‚Р С•Р В±Р Вµ.
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
        http_note = format!("HTTPS РЎвЂЎР ВµРЎР‚Р ВµР В· www-Р С‘Р СРЎРЏ РЎР‚Р В°Р В±Р С•РЎвЂљР В°Р ВµРЎвЂљ: {}", http_result_note(http.as_ref().unwrap()));
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

/// Р В Р ВµР В·РЎС“Р В»РЎРЉРЎвЂљР В°РЎвЂљ Р С—РЎР‚Р С•Р Р†Р ВµРЎР‚Р С”Р С‘ Р’В«Р С—Р С•Р Т‘Р СР ВµР Р…РЎвЂ№ DNSР’В» РЎвЂЎР ВµРЎР‚Р ВµР В· Р С•Р Т‘Р С‘Р Р… DoH-РЎРѓР ВµРЎР‚Р Р†Р С‘РЎРѓ.
/// Р РЋР ВµРЎР‚Р Р†Р С‘РЎРѓ Р С—РЎвЂ№РЎвЂљР В°Р ВµРЎвЂљРЎРѓРЎРЏ Р Р†Р ВµРЎР‚Р Р…РЎС“РЎвЂљРЎРЉ Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р С‘Р в„– РЎР‚Р В°Р В±Р С•РЎвЂЎР С‘Р в„– IP Р Р† Р С•Р В±РЎвЂ¦Р С•Р Т‘ Р С•РЎвЂљРЎР‚Р В°Р Р†Р В»Р ВµР Р…Р Р…Р С•Р С–Р С• DNS.
#[derive(Debug)]
pub struct DnsSubstitution {
    pub service: String,
    pub resolved: Vec<String>,
    /// Р В Р ВµР В°Р В»РЎРЉР Р…Р С• Р’В«РЎР‚Р В°Р В±Р С•РЎвЂЎР С‘Р в„–Р’В» IP РІР‚вЂќ HTTPS РЎвЂЎР ВµРЎР‚Р ВµР В· Р Р…Р ВµР С–Р С• Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р В»РЎРѓРЎРЏ (`http_ok == true`).
    /// Р вЂўРЎРѓР В»Р С‘ `http_ok == false`, РЎвЂљРЎС“РЎвЂљ Р СР С•Р В¶Р ВµРЎвЂљ Р В»Р ВµР В¶Р В°РЎвЂљРЎРЉ Р С”Р В°Р Р…Р Т‘Р С‘Р Т‘Р В°РЎвЂљ, Р С—РЎР‚Р С•РЎв‚¬Р ВµР Т‘РЎв‚¬Р С‘Р в„– РЎвЂљР С•Р В»РЎРЉР С”Р С• TCP:443.
    pub working_ip: Option<String>,
    pub http_note: String,
    /// HTTPS-Р С—РЎР‚Р С•Р В±Р В° РЎвЂЎР ВµРЎР‚Р ВµР В· `working_ip` РЎР‚Р ВµР В°Р В»РЎРЉР Р…Р С• Р Р†Р ВµРЎР‚Р Р…РЎС“Р В»Р В° OK. Р С›РЎвЂљ РЎРЊРЎвЂљР С•Р С–Р С• Р В·Р В°Р Р†Р С‘РЎРѓР С‘РЎвЂљ,
    /// Р СР С•Р В¶Р Р…Р С• Р В»Р С‘ РЎРѓР С•Р Р†Р ВµРЎвЂљР С•Р Р†Р В°РЎвЂљРЎРЉ Р С—Р С•Р Т‘Р СР ВµР Р…РЎС“ Р Р† hosts (Р С‘Р Р…Р В°РЎвЂЎР Вµ RST РІР‚вЂќ hosts Р В±Р ВµРЎРѓР С—Р С•Р В»Р ВµР В·Р ВµР Р…).
    pub http_ok: bool,
}

/// Р В­Р С”РЎРѓР С—Р С•РЎР‚РЎвЂљ HTTPS-Р С—РЎР‚Р С•Р В±РЎвЂ№ Р С—Р С• Р С”Р С•Р Р…Р С”РЎР‚Р ВµРЎвЂљР Р…Р С•Р СРЎС“ IP (Р Т‘Р В»РЎРЏ hosts-РЎвЂћР С‘РЎвЂЎР С‘: Р С—РЎР‚Р С•Р Р†Р ВµРЎР‚РЎРЏР ВµР С, РЎвЂЎРЎвЂљР С•
/// РЎРѓР В°Р в„–РЎвЂљ РЎР‚Р ВµР В°Р В»РЎРЉР Р…Р С• Р С•РЎвЂљР С”РЎР‚РЎвЂ№Р Р†Р В°Р ВµРЎвЂљРЎРѓРЎРЏ РЎвЂЎР ВµРЎР‚Р ВµР В· Р Р†РЎвЂ№Р В±РЎР‚Р В°Р Р…Р Р…РЎвЂ№Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ Р С—Р С•РЎРѓР В»Р Вµ Р В·Р В°Р С—Р С‘РЎРѓР С‘ Р Р† hosts).
pub fn probe_https_by_ip(host: &str, ip: IpAddr) -> HttpResult {
    http_via_ip(host, ip)
}

/// Р СџРЎР‚Р С•Р Р†Р ВµРЎР‚Р С”Р В° Р’В«Р С—Р С•Р Т‘Р СР ВµР Р…РЎвЂ№ DNSР’В»: РЎР‚Р ВµР В·Р С•Р В»Р Р† Р Т‘Р С•Р СР ВµР Р…Р В° РЎвЂЎР ВµРЎР‚Р ВµР В· DoH-РЎРѓР ВµРЎР‚Р Р†Р С‘РЎРѓРЎвЂ№ (xbox-dns.ru,
/// geohide.ru) Р С‘ Р С—Р С•Р С‘РЎРѓР С” РЎР‚Р В°Р В±Р С•РЎвЂЎР ВµР С–Р С• IP. Р вЂўРЎРѓР В»Р С‘ РЎРѓР С‘РЎРѓРЎвЂљР ВµР СР Р…РЎвЂ№Р в„–/Р С—РЎС“Р В±Р В»Р С‘РЎвЂЎР Р…РЎвЂ№Р в„– UDP-DNS Р С•РЎвЂљРЎР‚Р В°Р Р†Р В»Р ВµР Р…,
/// РЎРЊРЎвЂљР С‘ РЎРѓР ВµРЎР‚Р Р†Р С‘РЎРѓРЎвЂ№ Р СР С•Р С–РЎС“РЎвЂљ Р Р†Р ВµРЎР‚Р Р…РЎС“РЎвЂљРЎРЉ Р Р…Р В°РЎРѓРЎвЂљР С•РЎРЏРЎвЂ°Р С‘Р в„– Р В°Р Т‘РЎР‚Р ВµРЎРѓ, Р С‘ РЎРѓР В°Р в„–РЎвЂљ Р С•РЎвЂљР С”РЎР‚Р С•Р ВµРЎвЂљРЎРѓРЎРЏ РЎвЂЎР ВµРЎР‚Р ВµР В· Р С—Р С•Р Т‘Р СР ВµР Р…РЎС“.
///
/// * `probe_http` РІР‚вЂќ Р Т‘Р ВµР В»Р В°РЎвЂљРЎРЉ Р В»Р С‘ Р С—Р С•Р В»Р Р…РЎС“РЎР‹ HTTPS-Р С—РЎР‚Р С•Р В±РЎС“ Р С—Р ВµРЎР‚Р Р†Р С•Р С–Р С• РЎР‚Р В°Р В±Р С•РЎвЂЎР ВµР С–Р С• IP
///   (Р Т‘Р В»РЎРЏ Р С–Р В»Р В°Р Р†Р Р…Р С•Р С–Р С• Р Т‘Р С•Р СР ВµР Р…Р В° Р Т‘Р В°/Р Т‘Р В»РЎРЏ Р Т‘Р С•Р В»Р С–Р С•Р С–Р С• Р С—Р ВµРЎР‚Р ВµР В±Р С•РЎР‚Р В° РІР‚вЂќ Р Р…Р ВµРЎвЂљ).
pub fn check_dns_substitution(host: &str, probe_http: bool) -> Vec<DnsSubstitution> {
    let mut out = Vec::new();
    for service in DOH_RESOLVERS {
        let ips = resolve_via_doh(host, service);
        if ips.is_empty() {
            out.push(DnsSubstitution {
                service: service.to_string(),
                resolved: vec![],
                working_ip: None,
                http_note: "Р Р…Р Вµ Р Р†Р ВµРЎР‚Р Р…РЎС“Р В» IP-Р В°Р Т‘РЎР‚Р ВµРЎРѓР С•Р Р† (DoH Р Р…Р ВµР Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р ВµР Р… Р С‘Р В»Р С‘ Р Р…Р Вµ РЎР‚Р ВµР В·Р С•Р В»Р Р†Р С‘РЎвЂљ)".to_string(),
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
                    http_note = format!("HTTPS {} РЎвЂЎР ВµРЎР‚Р ВµР В· {}", code, ip);
                }
                HttpResult::BlockPage => {
                    http_note = format!("РЎРѓРЎвЂљРЎР‚Р В°Р Р…Р С‘РЎвЂ Р В° Р В±Р В»Р С•Р С”Р С‘РЎР‚Р С•Р Р†Р С”Р С‘ РЎвЂЎР ВµРЎР‚Р ВµР В· {}", ip);
                }
                HttpResult::Tls => {
                    http_note = format!("TLS РЎРѓР В»Р С•Р СР В°Р Р… РЎвЂЎР ВµРЎР‚Р ВµР В· {}", ip);
                }
                HttpResult::BadCert => {
                    http_note = format!("SSL-РЎРѓР ВµРЎР‚РЎвЂљР С‘РЎвЂћР С‘Р С”Р В°РЎвЂљ Р Р…Р ВµР Р†Р В°Р В»Р С‘Р Т‘Р ВµР Р… РЎвЂЎР ВµРЎР‚Р ВµР В· {}", ip);
                }
                HttpResult::Rst => {
                    http_note = format!("RST РЎвЂЎР ВµРЎР‚Р ВµР В· {} РІР‚вЂќ TCP:443 Р С•РЎвЂљР С”РЎР‚РЎвЂ№РЎвЂљ, Р Р…Р С• HTTPS РЎР‚Р Р†РЎвЂРЎвЂљРЎРѓРЎРЏ (DPI Р С—Р С• SNI)", ip);
                }
                HttpResult::Timeout => {
                    http_note = format!("РЎвЂљР В°Р в„–Р СР В°РЎС“РЎвЂљ РЎвЂЎР ВµРЎР‚Р ВµР В· {}", ip);
                }
                HttpResult::Dns => {
                    http_note = format!("DNS-Р С•РЎв‚¬Р С‘Р В±Р С”Р В° РЎвЂЎР ВµРЎР‚Р ВµР В· {}", ip);
                }
                HttpResult::Other(m) => {
                    http_note = m;
                }
            }
        } else {
            http_note = "Р Р…Р С‘ Р С•Р Т‘Р С‘Р Р… IP Р С‘Р В· Р С—Р С•Р Т‘Р СР ВµР Р…РЎвЂ№ Р Р…Р Вµ Р С•РЎвЂљР Р†Р ВµРЎвЂљР С‘Р В» Р Р…Р В° TCP:443".to_string();
        }
        if !probe_http {
            // Р вЂєРЎвЂР С–Р С”Р С‘Р в„– Р С—РЎР‚Р С•Р С–Р С•Р Р… (РЎРѓР С—Р С‘РЎРѓР С•Р С” dns_fail): HTTPS Р Р…Р Вµ Р С–Р С•Р Р…РЎРЏР ВµР С, Р Р…Р С• Р С‘ Р Р…Р Вµ Р Р…Р В°Р В·РЎвЂ№Р Р†Р В°Р ВµР С
            // IP Р’В«РЎР‚Р В°Р В±Р С•РЎвЂЎР С‘Р СР’В» РІР‚вЂќ РЎвЂљР С•Р В»РЎРЉР С”Р С• Р С”Р В°Р Р…Р Т‘Р С‘Р Т‘Р В°РЎвЂљР С•Р С.
            let res = working.is_some();
            http_ok = res;
            if let Some(ip) = working {
                http_note = format!("TCP:443 Р С•РЎвЂљР Р†Р ВµРЎвЂЎР В°Р ВµРЎвЂљ ({})", ip);
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
