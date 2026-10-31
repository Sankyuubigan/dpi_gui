//! Проба «большим ClientHello» (инцидент 31.10.26, opencode).
//!
//! Провайдер молча дропает первый TLS-пакет размером ~1.5–1.7 КБ на части
//! CDN-диапазонов: постквантовые клиенты (Bun, Node 24+, свежий Chromium)
//! шлют ClientHello с X25519MLKEM768 (~1.7 КБ) и висят до таймаута (в
//! opencode это выглядит как ECONNRESET), тогда как классический маленький
//! ClientHello (~300 Б) проходит всегда. Пробы анализатора ходят reqwest'ом
//! (schannel, без MLKEM) — потому фича «Анализ сайта» видела «всё открыто»
//! и честно говорила «чинить нечего», хотя у реального клиента сайт мёртв.
//!
//! Модуль строит синтетический TLS 1.3 ClientHello с key share
//! X25519MLKEM768 (группа 0x11EC, ключ 1216 Б) + ALPN + паддинг до ~1.7 КБ
//! и смотрит реакцию сервера: ответ (ServerHello/alert) — большой
//! ClientHello проходит; RST/тишина до таймаута — дропается фильтром.
//! Проба идёт сырым TCP-сокетом, поэтому видна winws так же, как трафик
//! реального клиента: под рабочим обходом она честно проходит.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Размер итогового handshake (~как у реального клиента с MLKEM — за порогом
/// фильтра; эксперименты 31.10.26 показали дроп с ~1.5 КБ).
const TARGET_CH_SIZE: usize = 1700;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Сколько альтернативных адресов зондируем в поисках edge, пропускающего
/// большой ClientHello.
const MAX_ALT_IPS: usize = 3;

// --- сборка TLS-записей вручную (зависимостей в Cargo.toml нет) ---

fn push_u16(v: &mut Vec<u8>, n: usize) {
    v.extend_from_slice(&(n as u16).to_be_bytes());
}

fn push_ext(v: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    push_u16(v, ext_type as usize);
    push_u16(v, body.len());
    v.extend_from_slice(body);
}

/// Псевдослучайные байты без внешних крейтов (xorshift от времени).
/// Криптостойкость не нужна — байты ключа только для размера пакета.
fn fill_random(buf: &mut [u8]) {
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    for b in buf.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed & 0xFF) as u8;
    }
}

/// Собрать TLS 1.3 ClientHello «как у постквантового клиента»:
/// X25519MLKEM768 (1216-байтный key share) + ALPN h2/http1.1 + паддинг,
/// итоговая TLS-запись ровно [`TARGET_CH_SIZE`] байт.
pub fn build_big_client_hello(sni: &str) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    // SNI
    let sni_b = sni.as_bytes();
    let mut sni_body = vec![0u8]; // name_type: host_name
    push_u16(&mut sni_body, sni_b.len());
    sni_body.extend_from_slice(sni_b);
    push_ext(&mut exts, 0x0000, &sni_body);

    // ALPN: h2, http/1.1
    let mut alpn_body = Vec::new();
    for proto in [&b"h2"[..], b"http/1.1"] {
        alpn_body.push(proto.len() as u8);
        alpn_body.extend_from_slice(proto);
    }
    push_ext(&mut exts, 0x0010, &alpn_body);

    // supported_groups: X25519MLKEM768 (0x11EC) + x25519 (0x001D)
    push_ext(&mut exts, 0x000A, &[0x00, 0x04, 0x11, 0xEC, 0x00, 0x1D]);

    // signature_algorithms (набор как у Chrome)
    push_ext(
        &mut exts,
        0x000D,
        &[0x00, 0x08, 0x04, 0x01, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06],
    );

    // supported_versions: TLS 1.3
    push_ext(&mut exts, 0x002B, &[0x02, 0x03, 0x04]);

    // key_share: X25519MLKEM768, 1216 байт (1184 enc MLKEM-768 + 32 x25519)
    let mut ks_entry = Vec::new();
    ks_entry.extend_from_slice(&0x11ECu16.to_be_bytes());
    push_u16(&mut ks_entry, 1216);
    let mut key = vec![0u8; 1216];
    fill_random(&mut key);
    ks_entry.extend_from_slice(&key);
    let mut ks_body = Vec::new();
    push_u16(&mut ks_body, ks_entry.len());
    ks_body.extend_from_slice(&ks_entry);
    push_ext(&mut exts, 0x0033, &ks_body);

    // padding (0x0015) добивает запись до TARGET_CH_SIZE; заголовок
    // расширения (4 Б) учитываем отдельно
    let fixed = 5   // record header
        + 4         // handshake header
        + 2 + 32    // legacy version + random
        + 1 + 32    // session id
        + 2 + 6     // cipher suites
        + 2         // compression methods
        + 2;        // extensions length
    let pad_len = TARGET_CH_SIZE.saturating_sub(fixed + exts.len() + 4);
    if pad_len > 0 {
        push_ext(&mut exts, 0x0015, &vec![0u8; pad_len]);
    }

    let mut body = Vec::with_capacity(fixed + exts.len());
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    let mut rnd = [0u8; 32];
    fill_random(&mut rnd);
    body.extend_from_slice(&rnd);
    body.push(32);
    let mut sess = [0u8; 32];
    fill_random(&mut sess);
    body.extend_from_slice(&sess);
    push_u16(&mut body, 6); // cipher suites length
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    push_u16(&mut body, exts.len());
    body.extend_from_slice(&exts);

    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // handshake type: ClientHello
    let blen = body.len();
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.extend_from_slice(&[0x16, 0x03, 0x01]); // record: handshake
    let hlen = hs.len();
    rec.extend_from_slice(&[(hlen >> 8) as u8, hlen as u8]);
    rec.extend_from_slice(&hs);
    rec
}

/// Чем ответил сервер на большой ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BigChVerdict {
    /// Есть ответ (ServerHello или TLS alert) — пакет прошёл.
    Alive,
    /// Соединение сброшено (RST).
    Reset,
    /// Молчание до таймаута — так выглядит дроп фильтром.
    Silence,
    /// TCP не установился — об адресе ничего сказать нельзя.
    TcpFail,
}

/// Единичная проба: большой ClientHello на `ip:443` от имени `sni`.
pub fn probe_big_ch(ip: &str, sni: &str) -> BigChVerdict {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return BigChVerdict::TcpFail;
    };
    let sa = SocketAddr::new(addr, 443);
    let Ok(mut stream) = TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) else {
        return BigChVerdict::TcpFail;
    };
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    // TCP_NODELAY: ClientHello обязан уйти одним сегментом — иначе проба
    // намеряет не фильтр провайдера, а собственную фрагментацию сокета
    let _ = stream.set_nodelay(true);

    let ch = build_big_client_hello(sni);
    if let Err(e) = stream.write_all(&ch) {
        return if e.kind() == std::io::ErrorKind::ConnectionReset {
            BigChVerdict::Reset
        } else {
            BigChVerdict::TcpFail
        };
    }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        // ServerHello (0x16) или alert (0x15) — любой ответ значит «прошёл»
        Ok(_) => BigChVerdict::Alive,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => BigChVerdict::Reset,
        // таймаут чтения на Windows приходит как TimedOut
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            BigChVerdict::Silence
        }
        Err(_) => BigChVerdict::Reset,
    }
}

/// Результат большой пробы по домену.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BigChCheck {
    /// true — большой ClientHello дропается, хотя классический проходит.
    pub dropped: bool,
    /// Альтернативный адрес, где большой ClientHello проходит (кандидат
    /// hosts-лечения, когда домен уже покрыт обходом и тот не спасает).
    pub working_ip: Option<String>,
}

/// Проверить домен: рабочий адрес — большим ClientHello; при дропе
/// параллельно зондируем остальные известные адреса (DoH + системные) в
/// поисках edge, который большой ClientHello пропускает.
pub fn check_domain(host: &str, working_ip: &str, candidate_ips: &[String]) -> BigChCheck {
    let verdict = probe_big_ch(working_ip, host);
    if !matches!(verdict, BigChVerdict::Silence | BigChVerdict::Reset) {
        // Alive — фильтра нет; TcpFail — адрес мёртв и о фильтре ничего
        // не говорит, пугать им нельзя.
        return BigChCheck { dropped: false, working_ip: None };
    }
    let working_ip = find_alt_ip(host, working_ip, candidate_ips);
    BigChCheck { dropped: true, working_ip }
}

fn find_alt_ip(host: &str, working_ip: &str, candidates: &[String]) -> Option<String> {
    let mut seen = HashSet::new();
    let ips: Vec<&str> = candidates
        .iter()
        .map(|s| s.as_str())
        .filter(|ip| {
            *ip != working_ip && ip.parse::<IpAddr>().is_ok() && seen.insert(*ip)
        })
        .take(MAX_ALT_IPS)
        .collect();
    if ips.is_empty() {
        return None;
    }
    let (tx, rx) = mpsc::channel::<(String, BigChVerdict)>();
    for ip in &ips {
        let tx = tx.clone();
        let ip = (*ip).to_string();
        let host = host.to_string();
        std::thread::spawn(move || {
            let v = probe_big_ch(&ip, &host);
            let _ = tx.send((ip, v));
        });
    }
    drop(tx);
    let results: Vec<(String, BigChVerdict)> = rx.iter().collect();
    // порядок кандидатов важнее порядка прихода: берём первый по списку
    for ip in &ips {
        if let Some((_, v)) = results.iter().find(|(rip, _)| rip == ip) {
            if matches!(v, BigChVerdict::Alive) {
                return Some((*ip).to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_ch_is_actually_big() {
        let ch = build_big_client_hello("opencode.ai");
        assert_eq!(ch.len(), TARGET_CH_SIZE, "паддинг должен добить запись точно");
    }

    #[test]
    fn ch_structure_is_tls_with_mlkem() {
        let ch = build_big_client_hello("example.com");
        assert_eq!(&ch[0..3], &[0x16, 0x03, 0x01], "TLS handshake record");
        assert_eq!(ch[5], 0x01, "handshake type: ClientHello");
        // группа X25519MLKEM768 присутствует в key_share
        assert!(ch.windows(2).any(|w| w == [0x11, 0xEC]));
        // и паддинг-расширение на месте
        assert!(ch.windows(2).any(|w| w == [0x00, 0x15]));
    }

    #[test]
    fn tcp_fail_is_not_dropped() {
        // невалидный IP не должен считаться «дропается фильтром»
        let c = check_domain("example.com", "999.999.999.999", &[]);
        assert!(!c.dropped);
        assert_eq!(c.working_ip, None);
    }

    #[test]
    fn find_alt_ip_skips_working_and_garbage() {
        // 192.0.2.x — зарезервированный TEST-NET: соединение не установится,
        // но функция обязана честно вернуть None, а не падать
        let cands: Vec<String> = vec![
            "203.0.113.9".into(),   // working_ip — должен быть исключён
            "not-an-ip".into(),     // мусор — исключён
            "192.0.2.10".into(),
            "192.0.2.10".into(),    // дубликат — исключён
            "192.0.2.11".into(),
        ];
        let r = find_alt_ip("example.invalid", "203.0.113.9", &cands);
        assert_eq!(r, None);
    }
}
