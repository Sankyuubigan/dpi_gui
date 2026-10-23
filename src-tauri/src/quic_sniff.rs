//! QUIC-сниффер: пассивный разбор UDP-трафика (QUIC v1/v2 Initial), HTTP/3.
//!
//! Принцип (проф-стандарт: Wireshark QUIC dissector, aioquic, RFC 9001):
//! ключи Initial-пакета выводятся из самого пакета (RFC 9001 §5.2), поэтому
//! наблюдатель на своей машине легитимно расшифровывает Initial и достаёт
//! TLS Client Hello с SNI, НЕ зная дальше handshake. Мы не вмешиваемся в
//! трафик (WinDivert RECV_ONLY), события отдаёт `domain_monitor`.
//!
//! Референсы (проверенные источники, не память):
//! - RFC 9000 §17.2 — формат Long Header / Initial;
//! - RFC 9001 §5.2 «Initial Secrets», §5.3 nonce, §5.4 header protection;
//! - RFC 9369 — QUIC v2 (другая соль, другие packet-type биты и метки);
//! - aioquic/quic/crypto.py — эталонные соли и метки HKDF (проверено fetch'ом).

use std::net::{IpAddr, Ipv4Addr};

use aes::Aes128;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes_gcm::{aead::{Aead, Payload}, Nonce, Aes128Gcm};
use hkdf::Hkdf;
use sha2::Sha256;

// v1: 0x0000_0001 (RFC 9000 §15), v2: 0x6b33_43cf (RFC 9369 §5.1).
const QUIC_VERSION_1: u32 = 0x0000_0001;
const QUIC_VERSION_2: u32 = 0x6b33_43cf;

// Соли HKDF-Extract для Initial Secrets (RFC 9001 §5.2; RFC 9369 §5.2.2;
// сверены с aioquic/quic/crypto.py — INITIAL_SALT_VERSION_1/2).
const INITIAL_SALT_V1: &[u8; 20] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const INITIAL_SALT_V2: &[u8; 20] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Размер sample для header protection (AES-128: 16 байт, RFC 9001 §5.4.3).
pub const SAMPLE_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// UDP-разбор (IPv4). IPv6 — вне скоупа этого этапа (честно: None).
// ---------------------------------------------------------------------------
pub struct UdpInfo<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], off: usize) -> usize {
    ((b[off] as usize) << 8) | (b[off + 1] as usize)
}

/// IPv4 (протокол 17 = UDP). Для IPv6 или не-UDP — None.
pub fn parse_udp_packet(b: &[u8], ipv6: bool) -> Option<UdpInfo<'_>> {
    if ipv6 {
        // IPv6 не парсим на этом этапе (PRP; право на дополнительных декодерах).
        return None;
    }
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0F) as usize) * 4;
    if ihl < 20 || b.len() < ihl + 8 {
        return None;
    }
    if b[9] != 17 {
        return None; // не UDP
    }
    let total = be16(b, 2).min(b.len());
    let udp = &b[ihl..total];
    if udp.len() < 8 {
        return None;
    }
    let udp_len = be16(udp, 4);
    if udp_len < 8 || udp_len > udp.len() {
        return None; // мусор/урезанная датаграмма
    }
    Some(UdpInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
        dst_ip: IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..udp_len],
    })
}

// ---------------------------------------------------------------------------
// Классификация QUIC-датаграммы: первый пакет и его тип.
// ---------------------------------------------------------------------------
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuicPacketKind {
    Initial,
    Handshake,
    ZeroRtt,
    Retry,
    /// Short-header (засекреченный 1-RTT) — SNI там не достать.
    ShortHeaderOther,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuicVersionId {
    V1,
    V2,
}

/// Версия QUIC из Long-header payload (первой датаграммы). None = не QUIC v1/v2.
pub fn quic_version(payload: &[u8]) -> Option<QuicVersionId> {
    if payload.len() < 5 {
        return None;
    }
    let v = ((payload[1] as u32) << 24)
        | ((payload[2] as u32) << 16)
        | ((payload[3] as u32) << 8)
        | (payload[4] as u32);
    match v {
        QUIC_VERSION_1 => Some(QuicVersionId::V1),
        QUIC_VERSION_2 => Some(QuicVersionId::V2),
        _ => None,
    }
}

/// Тип первого QUIC-пакета в датаграмме. None = не интересующий нас QUIC.
///
/// Биты типа (0x30) у Initial РЕАЛЬНО не защищены header protection —
/// поэтому классификация достоверна ещё до расшифровки.
pub fn classify_quic(payload: &[u8]) -> Option<QuicPacketKind> {
    if payload.len() < 5 {
        return None;
    }
    if payload[0] & 0x80 == 0 {
        return Some(QuicPacketKind::ShortHeaderOther);
    }
    let ver = quic_version(payload)?;
    let tt = (payload[0] >> 4) & 0x03;
    Some(match (ver, tt) {
        (QuicVersionId::V1, 0) => QuicPacketKind::Initial,
        (QuicVersionId::V1, 1) => QuicPacketKind::ZeroRtt,
        (QuicVersionId::V1, 2) => QuicPacketKind::Handshake,
        (QuicVersionId::V1, 3) => QuicPacketKind::Retry,
        // v2 (RFC 9369 §17): Initial и Handshake поменяли тип-код местами.
        (QuicVersionId::V2, 0) => QuicPacketKind::Handshake,
        (QuicVersionId::V2, 1) => QuicPacketKind::Initial,
        (QuicVersionId::V2, 2) => QuicPacketKind::ZeroRtt,
        (QuicVersionId::V2, 3) => QuicPacketKind::Retry,
        _ => return None, // недостижимо (tt — 2 бита)
    })
}

// ---------------------------------------------------------------------------
// Крипто-примитивы Initial (RFC 9001 §5.2): HKDF-SHA256, метки RFC 8446 §7.1.
// ---------------------------------------------------------------------------
/// HKDF-Expand-Label (RFC 8446 §7.1): info = u16(len) ++ u8(len("tls13 "+label))
/// ++ "tls13 "+label ++ u8(len(ctx)) ++ ctx; сверено с aioquic/tls.py hkdf_label.
/// `prk32` обязан быть ровно 32 байта (PRK = RFC 5869 extract-output; для HKDF-
/// SHA256 это гарантированно валидный PRK — `from_prk` подтвердит).
fn hkdf_expand_label(prk32: &[u8], label: &[u8], context: &[u8], length: usize) -> Option<Vec<u8>> {
    let full_label_len = 6 + label.len(); // b"tls13 " — ровно 6 байт
    if full_label_len > 255 || context.len() > 255 || length > u16::MAX as usize {
        return None;
    }
    let hk = Hkdf::<Sha256>::from_prk(prk32).ok()?;
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut okm = vec![0u8; length];
    hk.expand(&info, &mut okm).ok()?;
    Some(okm)
}

pub(crate) struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// Ключи Initial сессии (RFC 9001 §5.2):
///   initial_secret      = HKDF-Extract(salt, DCID);
///   client_secret       = HKDF-Expand-Label(initial_secret, "client in", "", 32);
///   key / iv / hp       = HKDF-Expand-Label(client_secret, "quic[?] <x>", ...).
/// Соль и метки зависят от версии (v1/v2).
pub(crate) fn derive_initial_keys(dcid: &[u8], ver: QuicVersionId) -> InitialKeys {
    let bad = "фиксированные длины всегда валидны для HKDF-SHA256";
    let salt: &[u8] = match ver {
        QuicVersionId::V1 => INITIAL_SALT_V1,
        QuicVersionId::V2 => INITIAL_SALT_V2,
    };
    // Хитрость: Hkdf::new хранит PRK = HKDF-Extract(salt, DCID) внутри себя,
    // и `.expand()` даёт HKDF-Expand(ПРК, info) — ровно то, что требует
    // HKDF-Expand-Label. Отдельно извлекать initial_secret не нужно.
    let initial = Hkdf::<Sha256>::new(Some(salt), dcid);

    let mut client_info = Vec::with_capacity(18);
    client_info.extend_from_slice(&32u16.to_be_bytes());
    client_info.push((6 + b"client in".len()) as u8); // len("tls13 client in") = 15
    client_info.extend_from_slice(b"tls13 client in");
    client_info.push(0); // пустой контекст
    let mut client_secret = [0u8; 32];
    initial.expand(&client_info, &mut client_secret).expect(bad);

    let (key_label, iv_label, hp_label): (&[u8], &[u8], &[u8]) = match ver {
        QuicVersionId::V1 => (b"quic key", b"quic iv", b"quic hp"),
        QuicVersionId::V2 => (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
    };
    let key = hkdf_expand_label(&client_secret, key_label, b"", 16).expect(bad);
    let iv = hkdf_expand_label(&client_secret, iv_label, b"", 12).expect(bad);
    let hp = hkdf_expand_label(&client_secret, hp_label, b"", 16).expect(bad);
    let mut key16 = [0u8; 16];
    key16.copy_from_slice(&key);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv);
    let mut hp16 = [0u8; 16];
    hp16.copy_from_slice(&hp);
    InitialKeys { key: key16, iv: iv12, hp: hp16 }
}

/// AES-128-ECB одного блока (маска header protection).
fn aes_ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ga = GenericArray::from_mut_slice(block);
    cipher.encrypt_block(&mut ga);
}

// ---------------------------------------------------------------------------
// Разбор QUIC Initial: заголовок → защита → AES-GCM → фреймы → Crypto-кадры.
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct ParsedInitial {
    /// DCID в открытой форме (RFC 9000 §17.2).
    pub dcid: Vec<u8>,
    /// Crypto-кадры: (offset в потоке Crypto, данные).
    pub crypto_chunks: Vec<(u64, Vec<u8>)>,
}

/// QUIC varint (RFC 9000 §16): 2 старших бита задают длину (1..8 байт).
fn read_varint(b: &[u8], off: usize) -> Option<(u64, usize)> {
    if off >= b.len() {
        return None;
    }
    let first = b[off];
    match first >> 6 {
        0 => Some(((first & 0x3F) as u64, off + 1)),
        1 => {
            if off + 1 >= b.len() {
                return None;
            }
            Some(((((first & 0x3F) as u64) << 8) | (b[off + 1] as u64), off + 2))
        }
        2 => {
            if off + 3 >= b.len() {
                return None;
            }
            Some((
                (((first & 0x3F) as u64) << 24)
                    | ((b[off + 1] as u64) << 16)
                    | ((b[off + 2] as u64) << 8)
                    | (b[off + 3] as u64),
                off + 4,
            ))
        }
        _ => {
            if off + 7 >= b.len() {
                return None;
            }
            let mut v: u64 = ((first & 0x3F) as u64) << 56;
            for i in 1..8 {
                v |= (b[off + i] as u64) << (8 * (7 - i));
            }
            Some((v, off + 8))
        }
    }
}

/// Пропуск ACK-фрейма: largest, delay, range_count, first_range, затем
/// (range_count-1) пар (gap, range); при ECN — ещё 3 счётчика.
/// None = усечён/мусор (сканирование фреймов прекращаем).
fn skip_ack_frame(b: &[u8], mut p: usize, ecn: bool) -> Option<usize> {
    let (_largest, np) = read_varint(b, p)?;
    p = np;
    let (_delay, np) = read_varint(b, p)?;
    p = np;
    let (cnt, np) = read_varint(b, p)?;
    p = np;
    let (_first, np) = read_varint(b, p)?;
    p = np;
    // Защита от зацикливания: каждая пара (gap, range) — минимум 2 байта.
    let pairs = cnt.saturating_sub(1);
    if pairs.saturating_mul(2) > (b.len() - p) as u64 {
        return None;
    }
    for _ in 0..pairs {
        let (_gap, np) = read_varint(b, p)?;
        p = np;
        let (_r, np) = read_varint(b, p)?;
        p = np;
    }
    if ecn {
        for _ in 0..3 {
            let (_x, np) = read_varint(b, p)?;
            p = np;
        }
    }
    Some(p)
}

/// Пропуск CONNECTION_CLOSE: transport-версия (есть поле frame_type)
/// или application-версия (только error_code + reason).
fn skip_conn_close(b: &[u8], mut p: usize, transport_close: bool) -> Option<usize> {
    let (_ec, np) = read_varint(b, p)?;
    p = np;
    if transport_close {
        let (_ft, np) = read_varint(b, p)?;
        p = np;
    }
    let (rl, np) = read_varint(b, p)?;
    p = np;
    let end = p + rl as usize;
    if end > b.len() {
        return None;
    }
    Some(end)
}

/// CRYPTO-кадры на позициях в расшифрованном payload.
fn extract_crypto_chunks(plain: &[u8], ver: QuicVersionId) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < plain.len() {
        let (ftype, np) = match read_varint(plain, p) {
            Some(v) => v,
            None => break,
        };
        p = np;
        match ftype {
            0x00 => {} // PADDING
            0x01 => {} // PING
            0x02 | 0x03 => {
                // ACK (0x02 без ECN, 0x03 с ECN; RFC 9000 §19.3).
                match skip_ack_frame(plain, p, ftype == 0x03) {
                    Some(np) => p = np,
                    None => break,
                }
            }
            0x06 => {
                // CRYPTO: offset varint, length varint, data (§19.6).
                let (off, np) = match read_varint(plain, p) {
                    Some(v) => v,
                    None => break,
                };
                p = np;
                let (len, np) = match read_varint(plain, p) {
                    Some(v) => v,
                    None => break,
                };
                p = np;
                let end = p + len as usize;
                if end > plain.len() {
                    break;
                }
                out.push((off, plain[p..end].to_vec()));
                p = end;
            }
            0x1C | 0x1D => {
                // CONNECTION_CLOSE: v1: 0x1c transport / 0x1d app;
                // v2: 0x1c app / 0x1d transport (RFC 9369 §9.1).
                let transport_close = match ver {
                    QuicVersionId::V1 => ftype == 0x1C,
                    QuicVersionId::V2 => ftype == 0x1D,
                };
                match skip_conn_close(plain, p, transport_close) {
                    Some(np) => p = np,
                    None => break,
                }
            }
            _ => break, // прочие фреймы в Initial не встречаются
        }
    }
    out
}

/// Полный разбор QUIC Initial: DCID (открытый) + Crypto-кадры.
///
/// None, если это не Initial, ключи не вывелись или AEAD-тег невалиден
/// (мусор / иные протоколы на UDP:443 / повреждение).
pub fn parse_initial_payload(payload: &[u8]) -> Option<ParsedInitial> {
    if payload.len() < 5 {
        return None;
    }
    let ver = quic_version(payload)?;
    if classify_quic(payload) != Some(QuicPacketKind::Initial) {
        return None;
    }

    // --- Заголовок в открытой форме (RFC 9000 §17.2) ---
    let mut p = 5usize;
    if p >= payload.len() {
        return None;
    }
    let dcid_len = payload[p] as usize;
    p += 1;
    if dcid_len > 20 || p + dcid_len > payload.len() {
        return None;
    }
    let dcid = payload[p..p + dcid_len].to_vec();
    p += dcid_len;
    if p >= payload.len() {
        return None;
    }
    let scid_len = payload[p] as usize;
    p += 1;
    if scid_len > 20 || p + scid_len > payload.len() {
        return None;
    }
    p += scid_len;
    let (token_len, np) = read_varint(payload, p)?;
    p = np;
    let token_len = token_len as usize;
    if token_len > payload.len() - p {
        return None;
    }
    p += token_len;
    let (length, np) = read_varint(payload, p)?;
    p = np;
    let length = length as usize;
    // Length = protected PN + шифртекст (включая 16-байтный тег GCM).
    if length < 2 || p + length > payload.len() {
        return None;
    }
    let pn_offset = p;

    // --- Header protection (RFC 9001 §5.4) --- sample: 16 байт чистого
    // шифртекста с фиксированного отступа pn_offset+4 (не зависит от pn_len;
    // консенсус aioquic: apply-сдвиг `4 - pn_length` == remove `+4`).
    let keys = derive_initial_keys(&dcid, ver);
    if pn_offset + 4 + SAMPLE_SIZE > payload.len() {
        return None;
    }
    let mut mask = [0u8; 16];
    mask.copy_from_slice(&payload[pn_offset + 4..pn_offset + 4 + SAMPLE_SIZE]);
    aes_ecb_encrypt_block(&keys.hp, &mut mask);

    let plain0 = payload[0] ^ (mask[0] & 0x0F); // у long-заголовка маска — 4 бита
    if plain0 & 0x0C != 0 {
        // Reserved-биты не нулевые после снятия защиты — мусор/иная реализация.
        return None;
    }
    let pn_len = ((plain0 & 0x03) as usize) + 1;
    if pn_offset + pn_len > payload.len() {
        return None;
    }
    let mut pn_bytes = payload[pn_offset..pn_offset + pn_len].to_vec();
    for (i, b) in pn_bytes.iter_mut().enumerate() {
        *b ^= mask[i + 1];
    }
    let mut pn_be4 = [0u8; 4];
    pn_be4[4 - pn_len..].copy_from_slice(&pn_bytes);
    // AAD для AEAD = полный заголовок с открытым byte0 и открытым PN.
    let plain_header = {
        let mut h = payload[..pn_offset].to_vec();
        h[0] = plain0;
        h.extend_from_slice(&pn_bytes);
        h
    };

    // --- Payload protection: AES-128-GCM (RFC 9001 §5.3) ---
    let ct_end = pn_offset + length;
    let ct = &payload[pn_offset + pn_len..ct_end];
    if ct.len() < 16 {
        return None; // тег GCM не влезает
    }
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    // Nonce = IV XOR PN (BE, right-aligned в младших 4 байтах).
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&keys.iv);
    for i in 0..4 {
        nonce[8 + i] ^= pn_be4[i];
    }
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: ct, aad: plain_header.as_slice() },
        )
        .ok()?;

    Some(ParsedInitial {
        dcid,
        crypto_chunks: extract_crypto_chunks(&plain, ver),
    })
}

// ---------------------------------------------------------------------------
// Сборка Crypto-потока (per DCID) и вытащенный SNI.
// ---------------------------------------------------------------------------
pub struct QuicCryptoBuffer {
    data: Vec<u8>,
    done: Option<String>,
    attempts: u8,
}

impl QuicCryptoBuffer {
    const MAX_ATTEMPTS: u8 = 2;

    pub fn new() -> Self {
        Self { data: Vec::new(), done: None, attempts: 0 }
    }

    /// В проде не вызывается (domain_monitor использует hostname()); метод
    /// нужен только тестам → cfg(test), чтобы prod-сборка не сыпала warning.
    #[cfg(test)]
    pub fn done(&self) -> bool {
        self.done.is_some()
    }

    pub fn hostname(&self) -> Option<String> {
        self.done.clone()
    }

    /// Добавить Crypto-фрагмент (offset в потоке). Разбор — через SSOT
    /// `tls_sni::parse_client_hello` (ОДИН парсер на TCP и QUIC).
    pub fn feed(&mut self, offset: u64, chunk: &[u8]) {
        if self.done.is_some() || chunk.is_empty() {
            return;
        }
        let end = (offset as usize).saturating_add(chunk.len());
        if end > crate::domain_monitor::COLLECT_CAP {
            return; // абсурдно большой поток — refuse (защита от мусора)
        }
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[offset as usize..end].copy_from_slice(chunk);
        match crate::tls_sni::parse_client_hello(&self.data) {
            crate::tls_sni::CliHelloStatus::Found(h) => self.done = Some(h),
            crate::tls_sni::CliHelloStatus::Incomplete => {}
            crate::tls_sni::CliHelloStatus::NotClientHello => {
                self.attempts += 1;
                if self.attempts >= Self::MAX_ATTEMPTS {
                    self.data.clear();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Тестовые билдеры (внутри crate, cfg(test)): синтетические пакеты.
// ---------------------------------------------------------------------------
#[cfg(test)]
fn uvarint(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16_384 {
        vec![(0x40 | (v >> 8) as u8), (v & 0xFF) as u8]
    } else if v < 1_073_741_824 {
        vec![
            (0x80 | (v >> 24) as u8),
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ]
    } else {
        // 8-байтная форма (проверяется round-trip-тестом; QUIC varint <= 2^62-1):
        // первый байт = 0xC0 | биты 56..61, затем 7 младших байтов BE.
        let mut out = vec![0xC0 | ((v >> 56) as u8 & 0x3F)];
        out.extend_from_slice(&(v & 0x00FF_FFFF_FFFF_FFFF).to_be_bytes()[1..]);
        out
    }
}

/// Собрать КОРРЕКТНЫЙ QUIC Initial (v1) с CRYPTO = TLS ClientHello(SNI).
/// Шифрование — теми же примитивами, что и разбор; тестовый round-trip
/// проверяет трубопровод, а корректность КОНСТАНТ уже подтверждена
/// референсом aioquic (fetch) в комментариях выше.
#[cfg(test)]
pub(crate) fn build_quic_initial_v1(dcid: &[u8], ch: &[u8]) -> Vec<u8> {
    assert!(!ch.is_empty());
    // Плоскость QUIC frames: PADDING + CRYPTO(offset=0, len, data).
    let mut plain = vec![0x00u8]; // PADDING
    plain.push(0x06); // CRYPTO frame
    plain.extend_from_slice(&uvarint(0)); // offset = 0
    plain.extend_from_slice(&uvarint(ch.len() as u64)); // length
    plain.extend_from_slice(ch);

    let keys = derive_initial_keys(dcid, QuicVersionId::V1);
    // Заголовок Initial v1: byte0 = long|fixed|Initial|0b00 (pn_len=1).
    let mut header = vec![0xC0u8];
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // SCID length = 0
    header.extend_from_slice(&uvarint(0)); // token length = 0
    let total = (plain.len() + 1 + 16) as u64; // pn (1) + payload + тег
    header.extend_from_slice(&uvarint(total));
    let pn_offset = header.len();

    // Payload protection: GCM, nonce = iv XOR pn(0) — младший байт не меняется.
    let mut nonce = keys.iv;
    nonce[11] ^= 0; // pn = 0
    let mut aad = header.clone();
    aad.push(0); // открытый байт PN (pn = 0)
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plain.as_slice(), aad: aad.as_slice() },
        )
        .expect("шифрование тестового Initial");

    let mut packet = header;
    packet.push(0); // байт PN (pn_len = 1)
    packet.extend_from_slice(&ct);

    // Header protection (RFC 9001 §5.4.2): sample = 16 байт шифртекста
    // с позиции pn_offset+4 (зеркалит парсер; байты PN не входят в sample).
    let mut sample = [0u8; SAMPLE_SIZE];
    sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 4 + SAMPLE_SIZE]);
    let mut mask = sample;
    aes_ecb_encrypt_block(&keys.hp, &mut mask);
    packet[0] ^= mask[0] & 0x0F;
    packet[pn_offset] ^= mask[1]; // pn_len = 1
    packet
}

// ---------------------------------------------------------------------------
// Тесты: синтетические пакеты и домены (никаких реальных). Никакой сети.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_sni::build_client_hello;

    #[test]
    fn quic_udp_parse_4tuple() {
        // IPv4+UDP (протокол 17): src 10.0.0.2:51234 → 1.2.3.4:443.
        let mut raw = vec![0u8; 20 + 8 + 4];
        raw[0] = 0x45;
        let total = (raw.len() as u16).to_be_bytes();
        raw[2..=3].copy_from_slice(&total);
        raw[9] = 17;
        raw[12..=15].copy_from_slice(&[10, 0, 0, 2]);
        raw[16..=19].copy_from_slice(&[1, 2, 3, 4]);
        raw[20..=21].copy_from_slice(&51234u16.to_be_bytes());
        raw[22..=23].copy_from_slice(&443u16.to_be_bytes());
        let udp_len = (raw.len() - 20) as u16; // всего 7 байт UDP заголовка + 4
        raw[24..=25].copy_from_slice(&udp_len.to_be_bytes());
        let u = parse_udp_packet(&raw, false).expect("udp parse");
        assert_eq!(u.src_port, 51234);
        assert_eq!(u.dst_port, 443);
        assert_eq!(u.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(u.dst_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(u.payload.len(), 4);
        // IPv6 — честный None.
        assert!(parse_udp_packet(&raw, true).is_none());
        // Не UDP (протокол 6) — None.
        raw[9] = 6;
        assert!(parse_udp_packet(&raw, false).is_none());
    }

    #[test]
    fn quic_classify_v1_and_v2() {
        // v1 Initial: byte0 = 0xC0 (type bits 00).
        let p1 = [
            0xC0u8, 0x00, 0x00, 0x00, 0x01, 0x08, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify_quic(&p1), Some(QuicPacketKind::Initial));
        // v1 Handshake: tt = 10 → биты 0x20.
        let p2 = [0xE0u8, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(classify_quic(&p2), Some(QuicPacketKind::Handshake));
        // v2 Initial: tt = 01 → 0xC0 | 0x10.
        let p3 = [0xD0u8, 0x6b, 0x33, 0x43, 0xcf];
        assert_eq!(classify_quic(&p3), Some(QuicPacketKind::Initial));
        // v2 Handshake: tt = 00.
        let p4 = [0xC0u8, 0x6b, 0x33, 0x43, 0xcf];
        assert_eq!(classify_quic(&p4), Some(QuicPacketKind::Handshake));
        // Short header — SNI не достать.
        let p5 = [0x40u8, 1, 2, 3, 4];
        assert_eq!(classify_quic(&p5), Some(QuicPacketKind::ShortHeaderOther));
        // Версия negotiation (0) и мусорная версия — None.
        assert_eq!(classify_quic(&[0xC0u8, 0, 0, 0, 0]), None);
        assert_eq!(classify_quic(&[0xC0u8, 1, 2, 3, 4]), None);
    }

    #[test]
    fn quic_initial_sni_roundtrip_v1() {
        let ch = build_client_hello(b"example.test");
        let dcid = [7u8; 8];
        let packet = build_quic_initial_v1(&dcid, &ch);
        assert_eq!(classify_quic(&packet), Some(QuicPacketKind::Initial));
        let parsed = parse_initial_payload(&packet).expect("расшифровка Initial");
        assert_eq!(parsed.dcid, dcid.to_vec());
        assert_eq!(parsed.crypto_chunks.len(), 1);
        assert_eq!(parsed.crypto_chunks[0].0, 0); // offset 0
        let mut buf = QuicCryptoBuffer::new();
        buf.feed(0, &parsed.crypto_chunks[0].1);
        assert_eq!(buf.hostname().as_deref(), Some("example.test"));
        assert!(buf.done());
    }

    #[test]
    fn quic_crypto_buffer_two_fragments() {
        let ch = build_client_hello(b"example.test");
        let cut = ch.len() / 2;
        let dcid = [9u8; 8];
        let packet = build_quic_initial_v1(&dcid, &ch);
        let parsed = parse_initial_payload(&packet).expect("расшифровка");
        let data = parsed.crypto_chunks[0].1.clone();
        let mut buf = QuicCryptoBuffer::new();
        buf.feed(0, &data[..cut]);
        assert!(buf.hostname().is_none(), "первый фрагмент — Incomplete");
        buf.feed(cut as u64, &data[cut..]);
        assert_eq!(buf.hostname().as_deref(), Some("example.test"));
        // Задержка повторного feed после done — тихо и без panic.
        buf.feed(0, &data[..1]);
        assert_eq!(buf.hostname().as_deref(), Some("example.test"));
    }

    #[test]
    fn quic_garbage_is_none() {
        assert!(parse_initial_payload(&[1, 2, 3]).is_none());
        // Long header Initial с мусорным шифртекстом — тег GCM не сойдётся.
        let mut junk = vec![0xC0u8];
        junk.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        junk.push(8);
        junk.extend_from_slice(&[1u8; 8]); // DCID (dcid_len trước)
        junk.extend_from_slice(&[0u8; 64]);
        assert!(parse_initial_payload(&junk).is_none());
        // Short header — не Initial.
        let short = vec![0x40u8, 0, 0, 0, 1];
        assert!(parse_initial_payload(&short).is_none());
    }

    #[test]
    fn quic_varint_roundtrip_all_n() {
        // Значения не «из памяти»: кодирование и декодирование — отдельные
        // функции, round-trip проверяет их согласованность на всех длинах
        // форм (1/2/4/8 байт).
        for v in [0u64, 1, 63, 64, 15_293, 494_878_333, 1_073_741_824, 4_611_686_018_427_387_903] {
            let enc = uvarint(v);
            let (dec, used) = read_varint(&enc, 0).expect("декод синтетического varint");
            assert_eq!(dec, v, "значение {} потерялось при round-trip", v);
            assert_eq!(used, enc.len());
        }
        // Усечённые формы — None, не паника.
        assert_eq!(read_varint(&[0x7B], 0), None);
        assert_eq!(read_varint(&[0x9D, 0x7F], 0), None);
        assert_eq!(read_varint(&[0xC2, 0x94], 0), None);
    }
}
