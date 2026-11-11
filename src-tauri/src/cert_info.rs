//! TLS-щуп: факты о серверном сертификате, когда HTTPS-проба упала с BadCert.
//!
//! reqwest не отдаёт сертификат при падении рукопожатия (Response нет, в error
//! chain — только локализованный текст schannel). Поэтому при BadCert проба
//! делает отдельное рукопожатие через native-tls с
//! `danger_accept_invalid_certs` — оно завершается даже с чужим/заглушечным
//! сертификатом, и цепочку можно прочитать.
//!
//! Никаких вердиктов по содержимому сертификата (запрет хардкода «GTS = ок»):
//! только факты в заметке пробы и логе. По issuer отчёт отличает РКН-заглушку
//! от настоящего ЦС, а SANs показывают, какие имена вообще покрыты (кейс
//! googlevideo.com 11.11.26: wildcard `*.googlevideo.com` apex не покрывает —
//! «невалиден» на apex может быть честным фронтом Google, а не цензором).

use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// Таймауты TLS-щупа: соединение и каждый шаг рукопожатия ограничены —
/// висящий щуп не может задержать окно анализа дольше ~13 с (thread не join-им,
/// см. http_probe_slots_parallel).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(4);

/// Извлечённые факты о листовом сертификате сервера.
#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    /// CN издателя (у современных промежуточных ЦС — короткий код: WR2, R10).
    pub issuer_cn: String,
    /// O издателя (человекочитаемое имя: «Google Trust Services», «Let's Encrypt»).
    pub issuer_o: String,
    /// CN владельца сертификата (часто wildcard: `*.googlevideo.com`).
    pub subject_cn: String,
    /// dNSName из subjectAltName — какие имена сертификат реально покрывает.
    pub sans: Vec<String>,
}

impl fmt::Display for CertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Издатель: если есть и CN, и O — показываем «O (CN)»: у Google
        // промежуточный CN «WR2» сам по себе ничего не говорит юзеру.
        let issuer = match (self.issuer_o.is_empty(), self.issuer_cn.is_empty()) {
            (false, false) => format!("{} ({})", self.issuer_o, self.issuer_cn),
            (false, true) => self.issuer_o.clone(),
            (true, false) => self.issuer_cn.clone(),
            (true, true) => "не указан".to_string(),
        };
        write!(f, "issuer=\"{}\" cn=\"{}\"", issuer, self.subject_cn)?;
        if !self.sans.is_empty() {
            write!(f, " sans=\"{}\"", self.sans.iter().take(4).cloned().collect::<Vec<_>>().join(", "))?;
            if self.sans.len() > 4 {
                write!(f, " (+{})", self.sans.len() - 4)?;
            }
        }
        Ok(())
    }
}

/// Рукопожатие с любым сертификатом и разбор цепочки. `None` — щуп не
/// состоялся (TCP/ TLS/парсер): заметка пробы остаётся без добавки, это честно.
pub fn tls_cert_info(ip: IpAddr, sni: &str) -> Option<CertInfo> {
    let addr = SocketAddr::new(ip, 443);
    let stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            log::info!("[TLS-щуп] {} через {}: TCP не открылся: {}", sni, ip, e);
            return None;
        }
    };
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::info!("[TLS-щуп] {} через {}: коннектор не собрался: {}", sni, ip, e);
            return None;
        }
    };
    let tls = match connector.connect(sni, stream) {
        Ok(t) => t,
        Err(e) => {
            log::info!("[TLS-щуп] {} через {}: рукопожатие не состоялось: {}", sni, ip, e);
            return None;
        }
    };
    let cert = match tls.peer_certificate() {
        Ok(Some(c)) => c,
        Ok(None) => {
            log::info!("[TLS-щуп] {} через {}: сервер не предъявил сертификат", sni, ip);
            return None;
        }
        Err(e) => {
            log::info!("[TLS-щуп] {} через {}: сертификат недоступен: {}", sni, ip, e);
            return None;
        }
    };
    let der = match cert.to_der() {
        Ok(d) => d,
        Err(e) => {
            log::info!("[TLS-щуп] {} через {}: DER не прочитан: {}", sni, ip, e);
            return None;
        }
    };
    let info = parse_cert_info(&der);
    match &info {
        Some(c) => log::info!("[TLS-щуп] {} через {}: {}", sni, ip, c),
        None => log::info!("[TLS-щуп] {} через {}: DER не разобран", sni, ip),
    }
    info
}

/// Один TLV: (тег, содержимое, остаток). Теги у нас однобайтовые
/// (0x30/0x31/0x02/0x06/…/0xA3) — многобайтовые в X.509 не встречаются.
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (len, hdr) = parse_len(rest)?;
    let end = hdr.checked_add(len)?;
    if end > rest.len() {
        return None;
    }
    Some((tag, &rest[hdr..end], &rest[end..]))
}

/// Длина DER-объекта: (значение, сколько байт заголовка съедено). 0x80
/// (неопределённая длина) и длиннее 2 байт — не наши случаи, отбой.
fn parse_len(buf: &[u8]) -> Option<(usize, usize)> {
    let (&b, rest) = buf.split_first()?;
    match b {
        0x00..=0x7f => Some((b as usize, 1)),
        0x81 => Some((*rest.first()? as usize, 2)),
        0x82 => Some((u16::from_be_bytes([*rest.first()?, *rest.get(1)?]) as usize, 3)),
        _ => None,
    }
}

/// OID в базовой-128 в арки. Первая арка = 40·x + y (для 2.x — первый байт ≥ 80).
fn decode_oid(bytes: &[u8]) -> Vec<u64> {
    let (&first, rest) = bytes.split_first().unwrap_or((&0, &[]));
    let mut arcs = if first >= 80 {
        vec![2u64, first as u64 - 80]
    } else {
        vec![first as u64 / 40, first as u64 % 40]
    };
    let mut val: u64 = 0;
    for &b in rest {
        val = (val << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(val);
            val = 0;
        }
    }
    arcs
}

fn oid_is(arcs: &[u64], expected: &[u64]) -> bool {
    arcs == expected
}

/// Значение атрибута Name: UTF8String/PrintableString/IA5String — как есть,
/// BMPString — UTF-16BE (кириллические ЦС часто в нём).
fn decode_string(tag: u8, bytes: &[u8]) -> String {
    match tag {
        0x1e => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Name (RDNSequence: SEQ → SET → SEQ → OID+значение) → (CN, O).
/// CN = 2.5.4.3, O = 2.5.4.10. Внутри SET'а обходим ВСЕ атрибутные SEQ —
/// бывают SET'ы с несколькими AttributeTypeAndValue.
fn name_parts(name: &[u8]) -> (String, String) {
    let mut cn = String::new();
    let mut o = String::new();
    let mut rest = name;
    while let Some((tag, set, tail)) = tlv(rest) {
        if tag != 0x31 {
            break;
        }
        let mut set_rest = set;
        while let Some((0x30, attrs, seq_tail)) = tlv(set_rest) {
            let mut cur = attrs;
            while let Some((atag, acontent, atail)) = tlv(cur) {
                if atag != 0x06 {
                    cur = atail;
                    continue;
                }
                let oid = decode_oid(acontent);
                cur = match tlv(atail) {
                    Some((vtag, vcontent, vtail)) => {
                        match oid.as_slice() {
                            [2, 5, 4, 3] => cn = decode_string(vtag, vcontent),
                            [2, 5, 4, 10] => o = decode_string(vtag, vcontent),
                            _ => {}
                        }
                        vtail
                    }
                    // Значения нет — идём дальше по оставшимся атрибутам.
                    None => atail,
                };
            }
            set_rest = seq_tail;
        }
        rest = tail;
    }
    (cn, o)
}

/// SAN (2.5.29.17) из OCTET STRING расширения → список dNSName (тег 0x82).
/// IP-адреса и прочие GeneralName пропускаем — нам нужны имена.
fn parse_sans(ext_value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((0x30, names, _)) = tlv(ext_value) {
        let mut rest = names;
        while let Some((tag, content, tail)) = tlv(rest) {
            if tag == 0x82 {
                if let Ok(s) = std::str::from_utf8(content) {
                    out.push(s.to_string());
                }
            }
            rest = tail;
        }
    }
    out
}

/// Минимальный X.509-парсер: Certificate → tbsCertificate → issuer/subject →
/// extensions [3] → SAN. Ошибка в любом месте → None (не паникуем на кривом DER).
pub(crate) fn parse_cert_info(der: &[u8]) -> Option<CertInfo> {
    let (0x30, cert_body, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert_body)? else {
        return None;
    };
    let mut rest = tbs;
    // [0] EXPLICIT версия (0xA0) — опциональна (v1-сертификаты её не пишут).
    if let Some((0xa0, _, tail)) = tlv(rest) {
        rest = tail;
    }
    // serialNumber
    let (0x02, _, tail) = tlv(rest)? else {
        return None;
    };
    rest = tail;
    // signature AlgorithmIdentifier
    let (0x30, _, tail) = tlv(rest)? else {
        return None;
    };
    rest = tail;
    // issuer
    let (0x30, issuer, tail) = tlv(rest)? else {
        return None;
    };
    let (issuer_cn, issuer_o) = name_parts(issuer);
    rest = tail;
    // subject
    let (0x30, subject, tail) = tlv(rest)? else {
        return None;
    };
    let (subject_cn, _) = name_parts(subject);
    rest = tail;
    // validity
    let (0x30, _, tail) = tlv(rest)? else {
        return None;
    };
    rest = tail;
    // subjectPublicKeyInfo
    let (0x30, _, tail) = tlv(rest)? else {
        return None;
    };
    rest = tail;
    // [1] issuerUniqueID / [2] subjectUniqueID / [3] extensions — в любом порядке
    let mut sans = Vec::new();
    loop {
        match tlv(rest) {
            Some((0xa1, _, tail)) | Some((0xa2, _, tail)) => rest = tail,
            Some((0xa3, exts, tail)) => {
                // [3] EXPLICIT содержит SEQUENCE OF Extension{ OID, [0] critical,
                // OCTET STRING } — разбираем её содержимое ПО ЭЛЕМЕНТНО: SAN бывает
                // НЕ первым расширением (кейс Google 03:16 11.11.26: перед SAN
                // идут keyUsage/CT-расширения — первый вариант цикла видел только
                // первое расширение и терял SAN).
                if let Some((0x30, ext_list, _)) = tlv(exts) {
                    let mut cur = ext_list;
                    while let Some((0x30, ext, ext_tail)) = tlv(cur) {
                        if let Some((0x06, oid, after)) = tlv(ext) {
                            // critical [0] — опциональный BOOLEAN
                            let after = match tlv(after) {
                                Some((0x01, _, t)) => t,
                                _ => after,
                            };
                            if let Some((0x04, value, _)) = tlv(after) {
                                if oid_is(&decode_oid(oid), &[2, 5, 29, 17]) {
                                    sans = parse_sans(value);
                                }
                            }
                        }
                        cur = ext_tail;
                    }
                }
                rest = tail;
            }
            _ => break,
        }
    }
    Some(CertInfo {
        issuer_cn,
        issuer_o,
        subject_cn,
        sans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- мини-конструктор DER для тестов (детерминированный, без сети) ---

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(der_len(content.len()));
        v.extend_from_slice(content);
        v
    }

    /// OID в base-128: первая арка = 40·a + b (для 2.x — 80 + b), остальные
    /// арки — от старших 7-битных групп к младшим (продолжение = старший бит).
    fn oid(arcs: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::new();
        if arcs[0] == 2 {
            bytes.push((80 + arcs[1]) as u8);
        } else {
            bytes.push((40 * arcs[0] + arcs[1]) as u8);
        }
        for &arc in &arcs[2..] {
            if arc < 128 {
                bytes.push(arc as u8);
            } else {
                let mut groups = Vec::new();
                let mut v = arc;
                loop {
                    groups.push((v & 0x7f) as u8);
                    v >>= 7;
                    if v == 0 {
                        break;
                    }
                }
                for (i, g) in groups.iter().enumerate().rev() {
                    if i == 0 {
                        bytes.push(*g);
                    } else {
                        bytes.push(0x80 | g);
                    }
                }
            }
        }
        bytes
    }

    /// Значение RDN: utf8=true → UTF8String (0x0C), false → BMPString (0x1E, UTF-16BE).
    fn encode_value(value: &str, utf8: bool) -> Vec<u8> {
        if utf8 {
            tlv(0x0c, value.as_bytes())
        } else {
            let units: Vec<u8> = value
                .encode_utf16()
                .flat_map(|u| u.to_be_bytes())
                .collect();
            tlv(0x1e, &units)
        }
    }

    /// Один атрибут Name: SET{ SEQ{ OID, значение } } — как в настоящем X.509.
    fn rdn_attr(oid_arcs: &[u64], value: &str, utf8: bool) -> Vec<u8> {
        let mut attr = tlv(0x06, &oid(oid_arcs));
        attr.extend(encode_value(value, utf8));
        tlv(0x31, &tlv(0x30, &attr))
    }

    /// Name — SEQUENCE из SET-атрибутов (CN всегда, O — если задан).
    fn name_tlv(cn: &str, o: Option<&str>, utf8: bool) -> Vec<u8> {
        let mut name = rdn_attr(&[2, 5, 4, 3], cn, utf8);
        if let Some(o_val) = o {
            name.extend(rdn_attr(&[2, 5, 4, 10], o_val, utf8));
        }
        tlv(0x30, &name)
    }

    /// Минимальный валидный сертификат с SAN (или без, если sans пуст).
    /// `pre_ext_oids` — OID'ы дополнительных расширений ПЕРЕД SAN (регресс на
    /// кейс Google: SAN не первое расширение).
    fn build_test_cert(issuer_cn: &str, issuer_o: Option<&str>, subject_cn: &str, sans: &[&str], utf8: bool) -> Vec<u8> {
        build_cert_with_pre_exts(issuer_cn, issuer_o, subject_cn, sans, utf8, &[])
    }

    fn build_cert_with_pre_exts(
        issuer_cn: &str,
        issuer_o: Option<&str>,
        subject_cn: &str,
        sans: &[&str],
        utf8: bool,
        pre_ext_oids: &[&[u64]],
    ) -> Vec<u8> {
        let mut tbs = tlv(0xa0, &tlv(0x02, &[0x02])); // [0] версия 2 (v3)
        tbs.extend(tlv(0x02, &[0x01])); // serial
        tbs.extend(tlv(0x30, &tlv(0x06, &oid(&[1, 2, 840, 113_549, 1, 1, 11])))); // sigAlg
        tbs.extend(name_tlv(issuer_cn, issuer_o, utf8)); // issuer
        tbs.extend(name_tlv(subject_cn, None, true)); // subject
        tbs.extend(tlv(0x30, &[0x13, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'])); // validity
        // SPKI: ОДИН SEQUENCE с алгоритмом и BIT STRING внутри.
        let mut spki = tlv(0x06, &oid(&[1, 2, 840, 113_549, 1, 1, 1]));
        spki.extend(tlv(0x03, &[0x00, 0x01, 0x02]));
        tbs.extend(tlv(0x30, &spki));
        if !pre_ext_oids.is_empty() || !sans.is_empty() {
            let mut ext_list = Vec::new();
            for arcs in pre_ext_oids {
                let mut ext = tlv(0x06, &oid(arcs));
                ext.extend(tlv(0x04, &[0x00])); // пустое значение расширения
                ext_list.extend(tlv(0x30, &ext));
            }
            if !sans.is_empty() {
                let mut gns = Vec::new();
                for s in sans {
                    gns.extend(tlv(0x82, s.as_bytes()));
                }
                let mut ext = tlv(0x06, &oid(&[2, 5, 29, 17]));
                ext.extend(tlv(0x04, &tlv(0x30, &gns)));
                ext_list.extend(tlv(0x30, &ext));
            }
            tbs.extend(tlv(0xa3, &tlv(0x30, &ext_list)));
        }
        tlv(0x30, &tlv(0x30, &tbs))
    }

    /// РЕГРЕСС живого прогона 03:16 11.11.26: на настоящем сертификате Google
    /// SAN — НЕ первое расширение (перед ним keyUsage/CT), и первый вариант
    /// парсера видел только первое расширение — cn="" и sans пустые.
    #[test]
    fn sans_found_when_not_first_extension() {
        let der = build_cert_with_pre_exts(
            "WR2",
            Some("Google Trust Services"),
            "",
            &["*.google.com", "google.com"],
            true,
            &[&[2, 5, 29, 15], &[2, 5, 29, 19]], // keyUsage, basicConstraints — перед SAN
        );
        let info = parse_cert_info(&der).expect("сертификат должен разобраться");
        assert_eq!(info.issuer_cn, "WR2");
        assert_eq!(info.sans, vec!["*.google.com", "google.com"]);
    }

    #[test]
    fn parse_extracts_issuer_subject_and_sans() {
        let der = build_test_cert(
            "Тестовый ЦС",
            Some("Заглушка-тест"),
            "*.example.com",
            &["*.example.com", "example.com", "sub.example.org"],
            true,
        );
        let info = parse_cert_info(&der).expect("сертификат должен разобраться");
        assert_eq!(info.issuer_cn, "Тестовый ЦС");
        assert_eq!(info.issuer_o, "Заглушка-тест");
        assert_eq!(info.subject_cn, "*.example.com");
        assert_eq!(info.sans, vec!["*.example.com", "example.com", "sub.example.org"]);
    }

    #[test]
    fn bmp_string_issuer_decodes_from_utf16be() {
        let der = build_test_cert("Русский ЦС", None, "www.example.com", &[], false);
        let info = parse_cert_info(&der).expect("сертификат должен разобраться");
        assert_eq!(info.issuer_cn, "Русский ЦС");
        assert_eq!(info.subject_cn, "www.example.com");
        assert!(info.sans.is_empty());
    }

    #[test]
    fn cert_without_san_extension_parses() {
        let der = build_test_cert("R10", Some("Let's Encrypt"), "www.example.com", &[], true);
        let info = parse_cert_info(&der).expect("v3 без SAN должен разбираться");
        assert_eq!(info.issuer_cn, "R10");
        assert_eq!(info.issuer_o, "Let's Encrypt");
        assert!(info.sans.is_empty());
    }

    #[test]
    fn garbage_der_returns_none() {
        assert!(parse_cert_info(&[]).is_none());
        assert!(parse_cert_info(&[0x30]).is_none()); // обрыв на длине
        assert!(parse_cert_info(&[0x04, 0x02, 0x01, 0x02]).is_none()); // не SEQUENCE
        let mut bad = build_test_cert("ЦС", None, "a.b", &[], true);
        bad.truncate(bad.len() / 2); // обрыв в середине tbs
        assert!(parse_cert_info(&bad).is_none());
    }

    #[test]
    fn oid_decode_handles_multibyte_arcs() {
        // 1.2.840.113549.1.1.11 — sha256WithRSA (113549 > 127, двухбайтовая арка)
        let der = oid(&[1, 2, 840, 113_549, 1, 1, 11]);
        assert_eq!(decode_oid(&der), vec![1, 2, 840, 113_549, 1, 1, 11]);
        // 2.5.29.17 — subjectAltName
        assert_eq!(decode_oid(&oid(&[2, 5, 29, 17])), vec![2, 5, 29, 17]);
    }

    #[test]
    fn display_prefers_o_and_wraps_cn() {
        let info = CertInfo {
            issuer_cn: "WR2".into(),
            issuer_o: "Google Trust Services".into(),
            subject_cn: "*.googlevideo.com".into(),
            sans: vec!["*.googlevideo.com".into()],
        };
        let s = info.to_string();
        assert!(s.contains("issuer=\"Google Trust Services (WR2)\""), " got: {s}");
        assert!(s.contains("cn=\"*.googlevideo.com\""), " got: {s}");
        // Пустые поля — честное «не указан», не пустая кавычка.
        let empty = CertInfo {
            issuer_cn: String::new(),
            issuer_o: String::new(),
            subject_cn: "x".into(),
            sans: Vec::new(),
        };
        assert!(empty.to_string().contains("issuer=\"не указан\""));
    }

    #[test]
    fn display_caps_sans_at_four() {
        let info = CertInfo {
            issuer_cn: "R10".into(),
            issuer_o: String::new(),
            subject_cn: "*.example.com".into(),
            sans: (0..6).map(|i| format!("host{}.example.com", i)).collect(),
        };
        let s = info.to_string();
        assert!(s.contains("host3.example.com"), " got: {s}");
        assert!(!s.contains("host4.example.com"), " sans должен обрезаться на 4: {s}");
        assert!(s.contains("(+2)"), " got: {s}");
    }

    /// Live-тест (#[ignore], запуск вручную: `cargo test live_ -- --ignored`):
    /// парсер на НАСТОЯЩЕМ сертификате (google.com — не под SNI-блоком, TCP
    /// проходит и без обхода). Ассерты структурные — бренды ЦС меняются.
    #[test]
    #[ignore]
    fn live_cert_info_google_front() {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = ("google.com", 443)
            .to_socket_addrs()
            .expect("DNS доступен")
            .collect();
        let ip = addrs.first().expect("есть адрес").ip();
        let info = tls_cert_info(ip, "google.com").expect("TLS-щуп до google.com состоялся");
        eprintln!("live cert: {}", info);
        assert!(
            !info.sans.is_empty(),
            "SAN парсятся на настоящем сертификате (SAN не первый): got {}",
            info
        );
        assert!(
            !(info.issuer_cn.is_empty() && info.issuer_o.is_empty()),
            "issuer читается: got {}",
            info
        );
    }
}
