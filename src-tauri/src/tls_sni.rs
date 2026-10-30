//! SSOT-парсер TLS ClientHello (достаёт SNI).
//!
//! Этот модуль — единственное место разбора TLS ClientHello в проекте:
//! - TCP-сниффер `domain_monitor` подаёт сюда payload TCP-потока;
//! - QUIC-сниффер `quic_sniff` подаёт сюда РАСШИФРОВАННЫЙ Crypto-кадр
//!   (TLS Client Hello из QUIC Initial).
//!
//! Контракт: не паникует на мусоре/обрезанных байтах, возвращает статус
//! вместо исключения. Двери: `parse_client_hello`, `CliHelloStatus`.

/// Статус разбора ClientHello (тестовый контракт, не меняется наружу без нужды).
#[derive(Debug, PartialEq)]
pub enum CliHelloStatus {
    Found(String),
    Incomplete,
    NotClientHello,
}

pub(crate) fn be16(b: &[u8], off: usize) -> usize {
    ((b[off] as usize) << 8) | (b[off + 1] as usize)
}

pub(crate) fn be24(b: &[u8], off: usize) -> usize {
    ((b[off] as usize) << 16) | ((b[off + 1] as usize) << 8) | b[off + 2] as usize
}

/// Строгий hostname: только [a-z0-9.-] (после lowercase), непустой, с точкой,
/// без точек на краях и двойных точек подряд. Это фильтр МУСОРА, а не полный
/// RFC-валидатор. Мотивация (кейс 30.10.26): fake-TLS-тулы (TgWsProxy и т.п.)
/// шлют ClientHello с произвольной строкой в SNI — URL с «https://» и набивкой
/// из NUL-байтов; NUL — валидный UTF-8 и trim его не убирает, а через DNS-запросы
/// (DoH 400) и список «Ошибки сети» такой «домен» ломился в анализ. Обычный SNI
/// браузеров/приложений всегда проходит; UTF-8 без NUL здесь гарантирует from_utf8.
fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// Распарсить TLS ClientHello из байтов потока (TCP payload / TLS record) и
/// взять SNI. Гарантии: не паникует на мусоре/обрезанных байтах; берёт ПЕРВЫЙ
/// server_name с name_type = 0; домен — lowercase, с точкой, только из символов
/// имени хоста ([a-z0-9.-]) — см. `is_valid_hostname`.
pub fn parse_client_hello(b: &[u8]) -> CliHelloStatus {
    if b.is_empty() {
        return CliHelloStatus::Incomplete;
    }
    // Два входа SSOT-парсера:
    // - TCP: TLS record (type 0x16 + version + length + handshake);
    // - QUIC (RFC 9001 §4.1): Crypto-кадр несёт ГОЛОЕ TLS handshake-сообщение
    //   (0x01 ClientHello ...) БЕЗ record-обёртки.
    let hs: &[u8] = if b[0] == 0x16 {
        if b.len() < 5 {
            return CliHelloStatus::Incomplete;
        }
        let rec_len = be16(b, 3);
        if 5 + rec_len > b.len() {
            return CliHelloStatus::Incomplete;
        }
        &b[5..5 + rec_len]
    } else if b[0] == 0x01 {
        b
    } else {
        return CliHelloStatus::NotClientHello;
    };
    if hs.is_empty() {
        return CliHelloStatus::Incomplete;
    }
    if hs[0] != 0x01 {
        return CliHelloStatus::NotClientHello;
    }
    if hs.len() < 4 {
        return CliHelloStatus::Incomplete;
    }
    let hs_len = be24(hs, 1);
    if 4 + hs_len > hs.len() {
        return CliHelloStatus::Incomplete;
    }
    let body = &hs[4..4 + hs_len];

    // ClientHello body: version(2) random(32).
    if body.len() < 34 {
        return CliHelloStatus::Incomplete;
    }
    let mut p: usize = 34;
    // session_id
    if p >= body.len() {
        return CliHelloStatus::Incomplete;
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    if p + 2 > body.len() {
        return CliHelloStatus::Incomplete;
    }
    // cipher_suites
    let cs_len = be16(body, p);
    p += 2 + cs_len;
    if p >= body.len() {
        return CliHelloStatus::Incomplete;
    }
    // compression_methods
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    if p + 2 > body.len() {
        return CliHelloStatus::Incomplete;
    }
    // extensions
    let exts_len = be16(body, p);
    p += 2;
    let end = p + exts_len;
    if p > body.len() || end > body.len() {
        return CliHelloStatus::Incomplete;
    }

    let mut have_name = false;
    while p + 4 <= body.len() {
        let etype = be16(body, p);
        let elen = be16(body, p + 2);
        p += 4;
        if p + elen > body.len() {
            return CliHelloStatus::Incomplete;
        }
        let edata = &body[p..p + elen];
        p += elen;

        if etype == 0x0000 && elen >= 5 {
            have_name = true;
            // server_name_list: [u16 list_len][u8 name_type=0][u16 host_len][host]
            if edata[2] == 0 {
                let host_len = be16(edata, 3);
                if 5 + host_len > edata.len() {
                    return CliHelloStatus::Incomplete;
                }
                let host_bytes = &edata[5..5 + host_len];
                if let Ok(host) = std::str::from_utf8(host_bytes) {
                    let host = host.trim().to_ascii_lowercase();
                    let host = host.trim_end_matches('.');
                    // Домен обязан быть валидным именем хоста: SNI-«localhost»,
                    // пустые имена и МУСОР детектору не интересны.
                    if is_valid_hostname(host) {
                        return CliHelloStatus::Found(host.to_string());
                    }
                }
            }
        }
    }
    if have_name {
        return CliHelloStatus::NotClientHello;
    }
    CliHelloStatus::NotClientHello
}

// ---------------------------------------------------------------------------
// Тестовый билдер: синтетический ClientHello (никаких реальных доменов).
// ---------------------------------------------------------------------------
#[cfg(test)]
pub fn build_client_hello(host: &[u8]) -> Vec<u8> {
    let host_len = (host.len() as u16).to_be_bytes();
    let mut sni = Vec::new();
    let list_len = (host.len() as u32 + 3) as u16;
    sni.extend_from_slice(&list_len.to_be_bytes());
    sni.push(0u8); // name_type = hostname
    sni.extend_from_slice(&host_len);
    sni.extend_from_slice(host);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type: server_name
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);

    let mut body = Vec::new();
    body.extend_from_slice(&[3u8, 3]); // client version TLS1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0u8); // session_id len=0
    body.extend_from_slice(&0u16.to_be_bytes()); // ciphers len=0
    body.push(0u8); // comps len=0
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::new();
    hs.push(0x01u8); // handshake: ClientHello
    let hs_len = body.len();
    hs.push((hs_len >> 16) as u8);
    hs.push((hs_len >> 8) as u8);
    hs.push(hs_len as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16u8); // TLS record: Handshake
    rec.extend_from_slice(&[3u8, 1]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_parse_tls12_full() {
        // Синтетический ClientHello c SNI (одна name, name_type=0).
        let b = build_client_hello(b"example.org");
        if let CliHelloStatus::Found(host) = parse_client_hello(&b) {
            assert_eq!(host, "example.org");
        } else {
            panic!("SNI не найден");
        }
    }

    #[test]
    fn sni_parse_incomplete_and_garbage() {
        assert_eq!(parse_client_hello(&[0x16, 0x03]), CliHelloStatus::Incomplete);
        let junk = vec![0u8; 64];
        let res = parse_client_hello(&junk);
        // Первая запись 0x00 не handshake → NotClientHello.
        assert_eq!(res, CliHelloStatus::NotClientHello);
        assert_eq!(parse_client_hello(&[]), CliHelloStatus::Incomplete);
    }

    #[test]
    fn sni_record_cut() {
        // Настоящая запись TLS с SNI, но обрезанная — Incomplete, не паника.
        let full = build_client_hello(b"example.org");
        let cut = &full[..full.len() / 2];
        assert_eq!(parse_client_hello(cut), CliHelloStatus::Incomplete);
    }

    #[test]
    fn sni_parse_quic_bare_handshake() {
        // QUIC Crypto-кадр = то же handshake-сообщение БЕЗ record-обёртки
        // (RFC 9001 §4.1). SSOT-парсер обязан принимать и такой вход.
        let rec = build_client_hello(b"example.test");
        let bare = &rec[5..];
        match parse_client_hello(bare) {
            CliHelloStatus::Found(host) => assert_eq!(host, "example.test"),
            other => panic!("ожидали Found, получили {:?}", other),
        }
    }

    // ---- Санитизация SNI (кейс 30.10.26: fake-TLS-тулы шлют мусорные SNI) ----

    /// Мусорный SNI fake-TLS-тула: URL-строка с NUL-набивкой (реальный кейс
    /// «https://ww\0\0…com» из отчёта массового анализа) не должен попадать
    /// в список ошибок ни под каким видом.
    #[test]
    fn garbage_sni_with_url_and_nul_padding_is_rejected() {
        let junk: &[&[u8]] = &[
            b"https://ww\x00\x00\x00\x00\x00\x00\x00.com",
            b"ww\x00\x00\x00.com",
            b"e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00gstatic.com",
            b"https://example.com/path",
            b"not a hostname",
            b"my_site.example.com", // подчёркивание — не символ имени хоста в SNI
            b"..double.dots..",
        ];
        for host in junk {
            let res = parse_client_hello(&build_client_hello(host));
            assert_eq!(res, CliHelloStatus::NotClientHello, "мусорный SNI {:?} обязан быть отброшен", host);
        }
    }

    /// Нормальные имена (дефисы, цифры, многоуровневые, punycode) проходят.
    #[test]
    fn valid_hostnames_still_pass() {
        for host in [
            &b"example.org"[..],
            b"my-site.example.org",
            b"123.host.example",
            b"xn--80ak6aa92e.example",
            b"a.b.c.d.example.co.uk",
        ] {
            match parse_client_hello(&build_client_hello(host)) {
                CliHelloStatus::Found(h) => assert_eq!(h, String::from_utf8_lossy(host)),
                other => panic!("валидный SNI {:?} отброшен: {:?}", host, other),
            }
        }
    }
}
