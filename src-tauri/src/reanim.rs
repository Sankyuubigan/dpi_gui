//! Реаниматор зависшего видео (M0-контракт инжекции из PRP
//! «10.11.26 Реаниматор подвисшего YouTube-видео»; М4 — карантин QUIC-стола).
//!
//! Проблема: ТСПУ режет QUIC-поток видео посреди стрима, а TCP-фолбэк Chrome к
//! googlevideo висит навсегда (блок по IP без RST) — плеер «залипает» на мёртвом
//! сокете до обновления страницы. Для TCP работает инжекция inbound RST.
//! Для установленного QUIC подделки пакетов мертвы (доказано 10.11.26): ICMP
//! Chrome глотает (SIO_UDP_CONNRESET), VN отбрасывает (RFC 9000 §17.2.1),
//! остальное зашифровано — там работает КАРАНТИН: глушим оба направления флоу
//! (capture-хендл, изъятие пакетов) на QUARANTINE_T → Chrome сам видит
//! idle-timeout и переоткрывает соединение (Initial с фейком winws проходит).
//!
//! Здесь живут только SSOT-константы, сборка RST-пакета (RFC-корректные
//! чексумы) и лимит-леджер. Детект зависшего флоу — в domain_monitor.rs (M1),
//! который и решает, когда звать `build_inbound_rst` + `SendHandle::send_packet`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::win_divert::WinDivertAddress;

// ---------------------------------------------------------------------------
// SSOT-константы (PRP: менять только вместе с тестами).
// ---------------------------------------------------------------------------
/// Висящее рукопожатие: ClientHello ушёл, входящих данных нет `HANDSHAKE_T`.
pub const HANDSHAKE_T: Duration = Duration::from_secs(5);
/// Установленный поток: входящие DATA молчат `SILENCE_T` при дупретрансах.
pub const SILENCE_T: Duration = Duration::from_secs(25);
/// Не чаще одной инжекции на 4-tuple за `COOLDOWN_T`.
pub const COOLDOWN_T: Duration = Duration::from_secs(30);
/// Максимум инжекций на один 4-tuple — дальше честное «не реанимировалось».
pub const MAX_RST: u8 = 3;
/// Окно ожидания «нового потока» после инжекции (факт успеха).
pub const SUCCESS_WINDOW: Duration = Duration::from_secs(10);
/// QUIC-флоу (М4): медиа-данных нет ≥ `QUIC_SILENCE_T` при свежих исходящих
/// ретраях → поток убит посреди стрима (здоровый RTT < 1 c).
pub const QUIC_SILENCE_T: Duration = Duration::from_secs(10);
/// М4: «медиа-данные» = полноразмерный пакет ≥ `QUIC_DATA_MIN` (QUIC-датаграммы
/// медиа ~1200-1350 б; ACK/PING-мелочь 60-200 б ходит и по мёртвому потоку —
/// в счёт данных не идёт).
pub const QUIC_DATA_MIN: usize = 1100;
/// М4: исходящие полноразмерные ретраи свежее `QUIC_RETRANS_FRESH_T` → Chrome
/// ещё борется (PTO-ретрансмиты незаэкношенных данных). Старше — Chrome сдался
/// или поток жив в idle: карантин не нужен (не рвём буферизацию вперёд).
pub const QUIC_RETRANS_FRESH_T: Duration = Duration::from_secs(15);
/// М4: длительность карантина — глушения обоих направлений зависшего флоу.
/// Хватает на QUIC idle-timeout Chrome (согласованный max_idle_timeout ~30 с):
/// после молчания Chrome сам закрывает соединение и ретраит на новом порту.
pub const QUARANTINE_T: Duration = Duration::from_secs(40);
/// М4: кулдаун карантина на 3-tuple — реже, чем RST-кулдаун: после снятия
/// Chrome переоткрывает соединение с НОВЫМ портом (карантин не задевает),
/// но старый 3-tuple может какое-то время оставаться кандидатом.
pub const QUAR_COOLDOWN_T: Duration = Duration::from_secs(60);
/// М4: максимум карантинов на один 3-tuple — дальше честное «не реанимировалось».
pub const MAX_QUAR: u8 = 2;
/// М4: максимум ОДНОВРЕМЕННЫХ карантинов (каждый — свой recv-тред + хендл).
pub const QUAR_MAX_CONCURRENT: usize = 2;
/// Период строки отчёта о транспорте (M2): исходящие ClientHello TCP:443
/// против новых QUIC-потоков к googlevideo.
pub const STATS_WINDOW: Duration = Duration::from_secs(300);

/// Целевой хост-суффикс: видео-CDN, который ТСПУ душит по IP.
pub const GOOGLEVIDEO_SUFFIX: &str = "googlevideo.com";

/// Честный суффикс-чек без догадок: домен потока заканчивается на
/// `googlevideo.com` (регистр SNI — ASCII, приводим к lower на всякий случай).
pub fn is_googlevideo(host: &str) -> bool {
    host.to_ascii_lowercase()
        .ends_with(GOOGLEVIDEO_SUFFIX)
}

// ---------------------------------------------------------------------------
// Чексумы RFC1071.
// ---------------------------------------------------------------------------

/// Классический Internet checksum (RFC 1071): сумма 16-битных слов BE с
/// переносами, дополнение до единицы. Данные нечётной длины дополняются
/// нулевым байтом (pad-байт не входит в длину, см. RFC 1071 §2).
pub fn rfc1071_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP-чексум: псевдозаголовок (src, dst, ноль, proto=6, длина сегмента)
/// + сам сегмент. Вызывается на сегменте БЕЗ уже вписанного поля checksum.
pub fn tcp_checksum(segment: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let mut buf: Vec<u8> = Vec::with_capacity(12 + segment.len() + 1);
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(6); // IPPROTO_TCP
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    if segment.len() % 2 == 1 {
        buf.push(0); // pad-байт
    }
    rfc1071_checksum(&buf)
}

// ---------------------------------------------------------------------------
// Сборка inbound RST.
// ---------------------------------------------------------------------------

/// Параметры инжекции: всё, что нужно для честного RST от имени сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RstParams {
    pub server_ip: Ipv4Addr,
    pub client_ip: Ipv4Addr,
    /// Порт сервера (для видео-CDN всегда 443, но контракт общий).
    pub server_port: u16,
    pub client_port: u16,
    /// SEQ для RST = RCV.NXT клиента (ACK-поле его исходящих сегментов).
    pub seq: u32,
    /// ACK для RST|ACK = SND.NXT клиента (последний outgoing seq + длина).
    pub ack: u32,
}

/// Собирает полный IPv4+TCP пакет (40 байт): inbound RST|ACK от сервера.
/// Окно 0 — сервер «ничего не принимает»; TTL 64 как у реального Google-ответа.
pub fn build_inbound_rst(p: &RstParams) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];

    // --- IPv4 (20 байт, без опций) ---
    pkt[0] = 0x45; // v4, IHL=5
                   // TOS=0, ID=0, flags/frag=0 — и так нули.
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
    pkt[8] = 64; // TTL
    pkt[9] = 6; // proto TCP
    pkt[12..16].copy_from_slice(&p.server_ip.octets());
    pkt[16..20].copy_from_slice(&p.client_ip.octets());
    let ip_ck = rfc1071_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    // --- TCP (20 байт, без опций) ---
    const TCP: usize = 20;
    pkt[TCP..TCP + 2].copy_from_slice(&p.server_port.to_be_bytes());
    pkt[TCP + 2..TCP + 4].copy_from_slice(&p.client_port.to_be_bytes());
    pkt[TCP + 4..TCP + 8].copy_from_slice(&p.seq.to_be_bytes());
    pkt[TCP + 8..TCP + 12].copy_from_slice(&p.ack.to_be_bytes());
    pkt[TCP + 12] = 0x50; // data offset 5 слов (20 байт)
    pkt[TCP + 13] = 0x14; // RST | ACK
                          // Window=0, checksum=0 (заполним), urgent=0 — нули.
    let tcp_ck = tcp_checksum(&pkt[TCP..40], p.server_ip, p.client_ip);
    pkt[TCP + 16..TCP + 18].copy_from_slice(&tcp_ck.to_be_bytes());

    pkt
}

/// Адрес для WinDivertSend инжекции: копия sniffed-адреса флоу (IfIdx/SubIfIdx
/// в union_data[0..8]) с перенаправлением INBOUND: Outbound=0, Loopback=0,
/// IPv6=0. Биты валидности чексумов (21/22) не ставим: чексумы собраны
/// RFC-корректно (golden-тесты ниже) — драйвер при необходимости сам
/// пересчитает/проверит, наша инфорсация не нужна и не может наврать.
/// Контрактная форма (рабочий путь — make_send_address_ifidx); #[allow] — не
/// суррогат: функция реально проверяется юнит-тестом send_address_is_inbound_ipv4.
#[allow(dead_code)]
pub fn make_send_address(sniffed: &WinDivertAddress) -> WinDivertAddress {
    let mut a = *sniffed;
    a.timestamp = 0;
    // Layer=NETWORK(0), Event=0, Sniffed=0, Outbound=0 (INBOUND), Loopback=0,
    // Impostor=0, IPv6=0.
    a.bitfields = 0;
    a.reserved2 = 0;
    a
}

/// То же, но из запомненного IfIdx/SubIfIdx флоу (для свипки, где sniffed-
/// адреса пакетов уже нет): интерфейс флоу не меняется на лету.
pub fn make_send_address_ifidx(ifidx: (u32, u32)) -> WinDivertAddress {
    let mut a = WinDivertAddress {
        timestamp: 0,
        bitfields: 0, // INBOUND IPv4 (см. make_send_address)
        reserved2: 0,
        union_data: [0u8; 64],
    };
    a.union_data[0..4].copy_from_slice(&ifidx.0.to_le_bytes());
    a.union_data[4..8].copy_from_slice(&ifidx.1.to_le_bytes());
    a
}

/// Кандидат инжекции — решение детектора (domain_monitor) одним пакетом:
/// всё, что нужно для сборки RST и честного лога.
#[derive(Debug, Clone)]
pub struct ReanimCandidate {
    pub params: RstParams,
    /// "handshake" (ClientHello ушёл, ответа нет) | "stall" (поток замер
    /// посреди данных: дупретрансы + тишина).
    pub reason: &'static str,
    /// Домен потока (SNI) — для лога.
    pub host: String,
    /// Максимум дупретрансов одного seq (для лога).
    pub retx_n: u32,
    /// Возраст зависшего рукопожатия / тишина входящих DATA (для лога).
    pub silence: Duration,
    /// IfIdx/SubIfIdx флоу — адресация инжекции в тот же интерфейс.
    pub ifidx: (u32, u32),
}

// ---------------------------------------------------------------------------
// Лимит-леджер: cooldown + максимум на 4-tuple + факт успеха.
// ---------------------------------------------------------------------------

/// 4-tuple в «плоской» форме для леджера (IPv4; v6 вне этапа).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKeyLite {
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub local_port: u16,
}

/// Причина отказа в инжекции (честно в лог).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionDecision {
    /// Инжекция разрешена (лимиты записаны).
    Allow,
    /// Недавно уже инжектили — cooldown.
    Cooldown,
    /// MAX_RST исчерпан — дальше тишина (флоу не реанимируется).
    Limit,
}

/// Леджер инжекций. Потокобезопасность не нужна: живёт в воркере монитора.
#[derive(Debug, Default)]
pub struct ReanimLedger {
    flows: HashMap<FlowKeyLite, (u8, Option<Instant>)>,
    /// Инжекция, ждущая подтверждения (новый поток к googlevideo) ≤ SUCCESS_WINDOW.
    pending: Option<(FlowKeyLite, Instant)>,
    total_injections: u64,
}

impl ReanimLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Решение по инжекции для 4-tuple. При Allow записывает факт
    /// (count += 1, метка cooldown) — повторный вызов до истечения COOLDOWN_T
    /// вернёт Cooldown.
    pub fn decide(&mut self, key: &FlowKeyLite, now: Instant) -> InjectionDecision {
        self.decide_with(key, now, COOLDOWN_T, MAX_RST)
    }

    /// То же с внешними лимитами (М4: карантин ходит 60 с / 2 на 3-tuple,
    /// RST — 30 с / 3 на 4-tuple; леджер один, лимиты разные).
    pub fn decide_with(
        &mut self,
        key: &FlowKeyLite,
        now: Instant,
        cooldown: Duration,
        max: u8,
    ) -> InjectionDecision {
        let entry = self.flows.entry(*key).or_insert((0, None));
        let (count, last) = *entry;
        if count >= max {
            return InjectionDecision::Limit;
        }
        if let Some(t) = last {
            if now.duration_since(t) < cooldown {
                return InjectionDecision::Cooldown;
            }
        }
        *entry = (count + 1, Some(now));
        self.total_injections += 1;
        InjectionDecision::Allow
    }

    /// Факт инжекции: ждём новый поток ≤ SUCCESS_WINDOW.
    pub fn note_injected(&mut self, key: FlowKeyLite, now: Instant) {
        self.pending = Some((key, now));
    }

    /// Новый исходящий ClientHello/QUIC-Initial к googlevideo — подтверждение?
    /// Другой 4-tuple внутри SUCCESS_WINDOW = видео переоткрылось.
    pub fn note_new_handshake(&mut self, key: &FlowKeyLite, now: Instant) -> bool {
        match self.pending.take() {
            Some((k, t)) => {
                if key != &k && now.duration_since(t) <= SUCCESS_WINDOW {
                    true
                } else {
                    // Не тот ключ / окно вышло — pending не восстанавливаем:
                    // факт уже разряжён, дальше решает expire_pending.
                    false
                }
            }
            None => false,
        }
    }

    /// Если pending истёк без подтверждения — вернуть ключ (для честного
    /// «не подтвердилось» в логе). Иначе — None, pending ждёт дальше.
    pub fn expire_pending(&mut self, now: Instant) -> Option<FlowKeyLite> {
        match self.pending {
            Some((k, t)) => {
                if now.duration_since(t) > SUCCESS_WINDOW {
                    self.pending = None;
                    Some(k)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Сервер сам закрыл поток RST'ом до нашей инжекции — pending теряет смысл.
    pub fn cancel_pending_on_server_rst(&mut self, key: &FlowKeyLite) {
        if let Some((k, _)) = self.pending {
            if k == *key {
                self.pending = None;
            }
        }
    }

    pub fn total_injections(&self) -> u64 {
        self.total_injections
    }
}

// ---------------------------------------------------------------------------
// Тесты (PRP М0: golden + структурные, без драйвера).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const DUMMY: RstParams = RstParams {
        server_ip: Ipv4Addr::new(173, 194, 160, 161),
        client_ip: Ipv4Addr::new(192, 168, 1, 5),
        server_port: 443,
        client_port: 51_234,
        seq: 0x1122_3344,
        ack: 0x5566_7788,
    };

    #[test]
    fn rfc1071_golden_example() {
        // Пример из RFC 1071: 00 01 f2 03 f4 f5 f6 f7 → 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(rfc1071_checksum(&data), 0x220d);
    }

    #[test]
    fn rfc1071_odd_length_pads() {
        // Нечётная длина: pad-байт в младшем (втор) байте слова, сумма BE.
        // 00 01 f2 (pad) = 0x0001 + 0xf200 → sum 0xf201 → ~ = 0x0dfe.
        assert_eq!(rfc1071_checksum(&[0x00, 0x01, 0xf2]), 0x0dfe);
    }

    #[test]
    fn built_rst_ip_checksum_selfverifying() {
        // Инвариант RFC1071: сумма слов заголовка ВМЕСТЕ с полем чексума = 0xFFFF.
        let pkt = build_inbound_rst(&DUMMY);
        assert_eq!(pkt.len(), 40);
        let mut sum: u32 = 0;
        for w in pkt[0..20].chunks_exact(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF, "IP-чексум не самоверифицируется");
    }

    #[test]
    fn built_rst_tcp_checksum_selfverifying() {
        // То же для TCP-сегмента с псевдозаголовком.
        let pkt = build_inbound_rst(&DUMMY);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&DUMMY.server_ip.octets());
        buf.extend_from_slice(&DUMMY.client_ip.octets());
        buf.push(0);
        buf.push(6);
        buf.extend_from_slice(&20u16.to_be_bytes());
        buf.extend_from_slice(&pkt[20..40]); // checksum уже вписан
        let mut sum: u32 = 0;
        for w in buf.chunks_exact(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF, "TCP-чексум не самоверифицируется");
    }

    #[test]
    fn built_rst_fields_at_right_offsets() {
        let pkt = build_inbound_rst(&DUMMY);
        assert_eq!(pkt[0], 0x45);
        assert_eq!(&pkt[2..4], &40u16.to_be_bytes());
        assert_eq!(pkt[8], 64); // TTL
        assert_eq!(pkt[9], 6); // TCP
        assert_eq!(&pkt[12..16], &DUMMY.server_ip.octets());
        assert_eq!(&pkt[16..20], &DUMMY.client_ip.octets());
        assert_eq!(&pkt[20..22], &DUMMY.server_port.to_be_bytes());
        assert_eq!(&pkt[22..24], &DUMMY.client_port.to_be_bytes());
        assert_eq!(&pkt[24..28], &DUMMY.seq.to_be_bytes());
        assert_eq!(&pkt[28..32], &DUMMY.ack.to_be_bytes());
        assert_eq!(pkt[32], 0x50); // data offset
        assert_eq!(pkt[33], 0x14); // RST|ACK
        assert_eq!(&pkt[34..36], &0u16.to_be_bytes()); // window 0
    }

    #[test]
    fn send_address_is_inbound_ipv4() {
        let mut sniffed = WinDivertAddress {
            timestamp: 42,
            bitfields: (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19), // sniffed|outbound|loopback|impostor
            reserved2: 7,
            union_data: [0u8; 64],
        };
        // IfIdx=5, SubIfIdx=9 в union_data[0..8].
        sniffed.union_data[0..4].copy_from_slice(&5u32.to_le_bytes());
        sniffed.union_data[4..8].copy_from_slice(&9u32.to_le_bytes());

        let a = make_send_address(&sniffed);
        assert_eq!(a.timestamp, 0);
        assert_eq!(a.bitfields, 0, "inbound IPv4 без loopback/impostor/sniffed");
        assert!(!a.is_outbound());
        assert!(!a.is_loopback());
        assert!(!a.is_ipv6());
        assert!(!a.is_sniffed());
        // IfIdx/SubIfIdx скопированы из sniffed-адреса.
        assert_eq!(u32::from_le_bytes(a.union_data[0..4].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(a.union_data[4..8].try_into().unwrap()), 9);
    }

    #[test]
    fn googlevideo_suffix_check() {
        assert!(is_googlevideo("rr1---sn-aj5go5-5i.googlevideo.com"));
        assert!(is_googlevideo("RR1---Sn-Aj5Go5-5i.GoogleVideo.COM"));
        assert!(is_googlevideo("redirector.googlevideo.com"));
        assert!(!is_googlevideo("www.google.com"));
        assert!(!is_googlevideo("googlevideo.com.evil.example"));
        assert!(!is_googlevideo(""));
    }

    #[test]
    fn ledger_cooldown_and_limit() {
        let mut l = ReanimLedger::new();
        let key = FlowKeyLite {
            remote_ip: Ipv4Addr::new(142, 251, 20, 94),
            remote_port: 443,
            local_port: 50_000,
        };
        let t0 = Instant::now();
        assert_eq!(l.decide(&key, t0), InjectionDecision::Allow);
        // Внутри cooldown — отказ, лимит не тратится.
        assert_eq!(l.decide(&key, t0 + Duration::from_secs(10)), InjectionDecision::Cooldown);
        assert_eq!(l.decide(&key, t0 + Duration::from_secs(29)), InjectionDecision::Cooldown);
        assert_eq!(l.decide(&key, t0 + COOLDOWN_T), InjectionDecision::Allow);
        assert_eq!(l.decide(&key, t0 + COOLDOWN_T + COOLDOWN_T), InjectionDecision::Allow);
        assert_eq!(l.decide(&key, t0 + 3 * COOLDOWN_T), InjectionDecision::Limit);
        // Чужой 4-tuple не страдает.
        let other = FlowKeyLite { local_port: 50_001, ..key };
        assert_eq!(l.decide(&other, t0), InjectionDecision::Allow);
        assert_eq!(l.total_injections(), 4);
    }

    // М4: decide_with — карантинные лимиты (60 с / 2) на том же леджере, что и
    // RST-лимиты (30 с / 3): один 4-tuple может пройти оба пути независимо.
    #[test]
    fn ledger_decide_with_quarantine_limits() {
        let mut l = ReanimLedger::new();
        let key = FlowKeyLite {
            remote_ip: Ipv4Addr::new(142, 251, 20, 94),
            remote_port: 443,
            local_port: 50_100,
        };
        let t0 = Instant::now();
        assert_eq!(
            l.decide_with(&key, t0, QUAR_COOLDOWN_T, MAX_QUAR),
            InjectionDecision::Allow
        );
        // Внутри карантинного кулдауна — отказ, лимит не тратится.
        assert_eq!(
            l.decide_with(&key, t0 + Duration::from_secs(30), QUAR_COOLDOWN_T, MAX_QUAR),
            InjectionDecision::Cooldown
        );
        assert_eq!(
            l.decide_with(&key, t0 + QUAR_COOLDOWN_T, QUAR_COOLDOWN_T, MAX_QUAR),
            InjectionDecision::Allow
        );
        assert_eq!(
            l.decide_with(&key, t0 + 2 * QUAR_COOLDOWN_T, QUAR_COOLDOWN_T, MAX_QUAR),
            InjectionDecision::Limit
        );
        // Запись леджера одна: карантинный максимум (2) записан, но RST-лимит
        // выше (3) — RST-путь на том же ключе ещё разрешит одну инжекцию.
        assert_eq!(l.decide(&key, t0 + 3 * QUAR_COOLDOWN_T), InjectionDecision::Allow);
        assert_eq!(l.total_injections(), 3);
    }

    #[test]
    fn ledger_success_window() {
        let mut l = ReanimLedger::new();
        let rst = FlowKeyLite {
            remote_ip: Ipv4Addr::new(142, 251, 20, 94),
            remote_port: 443,
            local_port: 50_000,
        };
        let new_flow = FlowKeyLite { local_port: 50_100, ..rst };
        let t0 = Instant::now();
        l.note_injected(rst, t0);
        // Тот же ключ — не подтверждение (это же соединение).
        assert!(!l.note_new_handshake(&rst, t0 + Duration::from_secs(2)));
        // После take() pending пуст — повторные проверки не лгут.
        assert!(!l.note_new_handshake(&new_flow, t0 + Duration::from_secs(3)));
        // Заново ждём и подтверждаем другим 4-tuple внутри окна.
        l.note_injected(rst, t0 + Duration::from_secs(4));
        assert!(l.note_new_handshake(&new_flow, t0 + Duration::from_secs(4) + Duration::from_millis(500)));
        // Окно вышло — expire_pending отдаёт ключ, повторно не отдаёт.
        l.note_injected(rst, t0);
        assert_eq!(l.expire_pending(t0 + Duration::from_secs(5)), None);
        assert_eq!(l.expire_pending(t0 + SUCCESS_WINDOW + Duration::from_millis(1)), Some(rst));
        assert_eq!(l.expire_pending(t0 + SUCCESS_WINDOW + Duration::from_secs(2)), None);
        // RST от сервера снимает pending своего ключа.
        l.note_injected(rst, t0);
        l.cancel_pending_on_server_rst(&new_flow);
        assert_eq!(l.expire_pending(t0 + SUCCESS_WINDOW + Duration::from_secs(1)), Some(rst));
        l.note_injected(rst, t0);
        l.cancel_pending_on_server_rst(&rst);
        assert_eq!(l.expire_pending(t0 + SUCCESS_WINDOW + Duration::from_secs(1)), None);
    }

    #[test]
    fn rst_params_from_flowkey_conversion_sanity() {
        // FlowKeyLite ↔ параметры RST: удалённая сторона = сервер.
        let key = FlowKeyLite {
            remote_ip: Ipv4Addr::new(142, 251, 30, 149),
            remote_port: 443,
            local_port: 52_100,
        };
        // (Конверсия живёт в domain_monitor; тут фиксируем ожидаемую форму.)
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));
        let client_ip = match client_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!(),
        };
        let p = RstParams {
            server_ip: key.remote_ip,
            client_ip,
            server_port: key.remote_port,
            client_port: key.local_port,
            seq: 100,
            ack: 517,
        };
        let pkt = build_inbound_rst(&p);
        assert_eq!(&pkt[12..16], &key.remote_ip.octets());
        assert_eq!(&pkt[16..20], &client_ip.octets());
    }
}
