//! Фоновый детектор «ломающихся» доменов (ревизия 3 PRP).
//!
//! Принципы:
//! - единственный пассивный WinDivert-sniff-хендл (`SNIFF | RECV_ONLY`, приоритет
//!   `WINDIVERT_PRIORITY_LOWEST`) — детектор физически не влияет на трафик/обход;
//! - сигнал = входящий RST от сервера на TCP:443 соединении, домен берётся из SNI
//!   исходящего TLS ClientHello (штучно собирается по сегментам, в т.ч. разрезанным
//!   tamper-движком winws); второй сигнал — повторные исходящие DATA-диапазоны
//!   (ретрансмиссии), порог ровно как у winws (default retrans-threshold = 3);
//!   третий сигнал — QUIC (UDP:443): повторные Initial при полном молчании
//!   сервера (расшифровка Initial — модуль quic_sniff, RFC 9001 Initial Secrets);
//! - пакеты, совпадающие с фейками активной стратегии winws (модуль
//!   fake_payloads), отсекаются ДО коллекторов и счётчиков: подставные копии
//!   (8–11 на каждый подменяемый пакет) без фильтра считались ретрансмиссиями/
//!   QUIC Initial, а SNI лочился на SNI ИЗ ФАЙЛА-ФЕЙКА (onetrust/google) —
//!   фантомы в «Ошибках сети» (инцидент 27.10.26);
//! - НИКАКИХ записей на диск: события только в память процесса и в UI;
//! - списки пользователя НИКАК не затрагиваются (детектор списки даже не читает);
//! - ошибки не молчат: честная строка в лог с кодом ошибки.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Emitter};

use crate::events::app_log;
use crate::fake_payloads::FakeBlobs;
use crate::list_index::ListIndex;
use crate::quic_sniff::{
    classify_quic, parse_initial_payload, parse_udp_packet, ParsedInitial, QuicCryptoBuffer,
    QuicPacketKind,
};
use crate::win_divert::{
    open_sniff_handle, SniffHandle, WinDivertAddress, MAX_PACKET_LEN,
};

// ---------------------------------------------------------------------------
// Константы детектора — SSOT, менять «на глаз» запрещено (PRP §2).
// ---------------------------------------------------------------------------
/// Порог ретрансмиссий (как у winws по умолчанию: retrans-threshold = 3).
pub const RETRANS_THRESHOLD: u8 = 3;
/// Максимальный объём собранных байтов ClientHello на поток (защита от мусора).
pub const COLLECT_CAP: usize = 16 * 1024;
/// Максимум одновременно отслеживаемых соединений.
pub const MAX_FLOWS: usize = 10_000;
/// TTL состояния потока, если соединение тихо (RST/FIN уже погасили).
pub const FLOW_TTL_SECS: u64 = 15 * 60;
/// Дедуп-окно повторного события по паре (домен, причина).
pub const DEDUP_WINDOW_SECS: u64 = 30;
/// Ограничение событий в UI.
pub const MAX_UI_EVENTS_PER_SEC: u32 = 10;
/// Каждые NO_DOMAIN_FLUSH_EVERY «событий без домена» — агрегированная строка.
pub const NO_DOMAIN_FLUSH_EVERY: u64 = 100;

/// TCP-флаги из заголовка.
const FLAG_FIN: u8 = 0x01;
const FLAG_RST: u8 = 0x04;

// ---------------------------------------------------------------------------
// Событие для UI.
// ---------------------------------------------------------------------------
#[derive(Clone, serde::Serialize)]
pub struct DomainDiscoveryEvent {
    pub domain: String,
    /// "rst" | "retrans" | "quic"
    pub reason: &'static str,
    /// «1.2.3.4:443» (сервер).
    pub client_ip_port: String,
    pub l7proto: &'static str,
    pub observed_at_ms: u64,
    /// PRP ревизия 4 §7.5 (ШАГ D): лейблы списков, где нашёлся домен;
    /// пусто = «в списках отсутствует».
    pub lists: Vec<&'static str>,
    /// PRP ревизия 4 §7.6 (ШАГ E): имя процесса, который стучался;
    /// пустая строка = не определился.
    pub proc_name: String,
    /// Полный путь exe того же процесса (хинт в UI при наведении на чип);
    /// пустая строка = путь не отдала система.
    pub proc_path: String,
}

// ---------------------------------------------------------------------------
// Режим из конфига (SSOT: domain_monitor_mode; legacy-алиас autohostlist_mode).
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MonitorMode {
    Off,
    Observe,
}

impl MonitorMode {
    fn from_str(raw: &str) -> Self {
        if raw.eq_ignore_ascii_case("off") {
            MonitorMode::Off
        } else {
            MonitorMode::Observe
        }
    }
}

/// Читает режим из config.json (через существующую read_config), дефолт «observe».
pub fn read_mode() -> MonitorMode {
    let raw = match crate::config::read_config() {
        Ok(v) => v
            .get("domain_monitor_mode")
            .or_else(|| v.get("autohostlist_mode"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        Err(_) => None,
    };
    MonitorMode::from_str(raw.as_deref().unwrap_or("observe"))
}

/// Строка фильтра WinDivert — ровно одна функция сборки (SSOT).
/// UDP:443 нужен для QUIC/HTTP-3 (PRP 23.10.26): без него браузерные
/// QUIC-запросы целиком проходят мимо детектора.
pub fn sniff_filter() -> &'static str {
    "tcp.DstPort == 443 or tcp.SrcPort == 443 or udp.DstPort == 443 or udp.SrcPort == 443"
}

// ---------------------------------------------------------------------------
// SNI-парсер — SSOT в tls_sni (ОДИН парсер на весь проект; его же шлёт
// QUIC-ветка). Локально остаются be16/be24 — разбор IPv4-заголовка ниже.
// ---------------------------------------------------------------------------
pub use crate::tls_sni::{parse_client_hello, CliHelloStatus};

fn be16(b: &[u8], off: usize) -> usize {
    ((b[off] as usize) << 8) | (b[off + 1] as usize)
}

// ---------------------------------------------------------------------------
// SniCollector: сборка исходящего потока по seq, обработка фрагментов и ретрансов.
// ---------------------------------------------------------------------------
struct SniCollector {
    base_seq: Option<u32>,
    collected: Vec<u8>,
    pending: HashMap<u32, Vec<u8>>,
    attempts: u8,
    done: Option<String>,
}

impl SniCollector {
    const MAX_ATTEMPTS: u8 = 2;

    fn new() -> Self {
        Self {
            base_seq: None,
            collected: Vec::new(),
            pending: HashMap::new(),
            attempts: 0,
            done: None,
        }
    }

    fn stop_collecting(&mut self) {
        self.base_seq = None;
        self.collected.clear();
        self.pending.clear();
        self.attempts = Self::MAX_ATTEMPTS; // больше попыток нет
    }

    /// Подчинённый шаг: попытка распарсить собранное; при Incomplete — ждём дальше;
    /// при NotClientHello — либо дать шанс на новое потоковое seq (новое соединение
    /// на тот же 4-tuple), либо остановиться навсегда.
    fn try_parse(&mut self) {
        if self.done.is_some() {
            return;
        }
        match parse_client_hello(&self.collected) {
            CliHelloStatus::Found(h) => {
                self.done = Some(h);
                // Освобождаем буферы — домен уже извлечён.
                self.collected.clear();
                self.pending.clear();
            }
            CliHelloStatus::Incomplete => {}
            CliHelloStatus::NotClientHello => {
                self.attempts += 1;
                if self.attempts >= Self::MAX_ATTEMPTS {
                    self.stop_collecting();
                } else {
                    // Новый поток (SYN re-использование 4-tuple): начинаем с чистого.
                    self.base_seq = None;
                    self.collected.clear();
                    self.pending.clear();
                }
            }
        }
    }

    fn feed(&mut self, seq: u32, payload: &[u8]) {
        if self.done.is_some() || self.attempts >= Self::MAX_ATTEMPTS || payload.is_empty() {
            return;
        }
        let start = match self.base_seq {
            None => {
                if self.collected.capacity() == 0 {
                    self.collected.reserve(1024);
                }
                if payload.len() > COLLECT_CAP {
                    return;
                }
                self.base_seq = Some(seq);
                self.collected.extend_from_slice(payload);
                self.try_parse();
                return;
            }
            Some(s) => s,
        };
        let offset = seq.wrapping_sub(start) as usize;
        if offset > COLLECT_CAP {
            self.stop_collecting();
            return;
        }
        if offset == self.collected.len() {
            // Идеально подряд: приклеиваем в конец.
            let end = self.collected.len() + payload.len();
            if end > COLLECT_CAP {
                self.stop_collecting();
                return;
            }
            self.collected.extend_from_slice(payload);
            self.splice_pending();
            self.try_parse();
            return;
        }
        if offset > self.collected.len() {
            // Дыра: хвост ждёт в pending, пока дыру не закроют.
            // НИКАКОГО заполнения нулями — иначе байты сдвинутся и поток сломается.
            let end = offset + payload.len();
            if end > COLLECT_CAP {
                self.stop_collecting();
                return;
            }
            self.pending.insert(offset as u32, payload.to_vec());
            return;
        }
        // offset внутри собранного диапазона: перекрытие/ретранс — перезапись.
        self.merge_at(offset, payload);
        self.splice_pending();
        self.try_parse();
    }

    /// Перезапись байтов внутри УЖЕ собранного диапазона (никогда не расширяет).
    fn merge_at(&mut self, offset: usize, payload: &[u8]) {
        for (i, byte) in payload.iter().enumerate() {
            let abs = offset + i;
            if abs >= self.collected.len() {
                break; // страховка: merge_at вызывается только при offset < len
            }
            self.collected[abs] = *byte;
        }
    }

    fn splice_pending(&mut self) {
        loop {
            let next_off = self.collected.len() as u32;
            if let Some(bytes) = self.pending.remove(&next_off) {
                let end = self.collected.len() + bytes.len();
                if end > COLLECT_CAP {
                    self.stop_collecting();
                    return;
                }
                self.collected.extend_from_slice(&bytes);
                self.try_parse();
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FlowTracker: ключ 4-tuple (мини-коннн-трек).
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
}

struct FlowState {
    sni: SniCollector,
    hostname: Option<String>,
    /// Кто стучался (ШАГ E, PRP §7.6): имя процесса-владельца сокета.
    /// Кэш на флоу: запрашиваем ТОЛЬКО на исходящем пакете (соединение живо),
    /// пока None — к моменту RST таблица Windows уже пуста для этого сокета.
    proc: Option<String>,
    /// Полный путь exe того же процесса (для хинта в UI). None = не отдала
    /// система (защищённые процессы / правки прав) — имя остаётся.
    proc_path: Option<String>,
    /// seq исходящих DATA → (количество повторов | флаг «событие уже отдали» = бит 0x80).
    retx: HashMap<u32, u8>,
    last_seen: Instant,
}

impl FlowState {
    const RETX_FLAGGED: u8 = 0x80;

    fn new() -> Self {
        Self {
            sni: SniCollector::new(),
            hostname: None,
            proc: None,
            proc_path: None,
            retx: HashMap::new(),
            last_seen: Instant::now(),
        }
    }

    /// Возвращает Some((reason, домен)), если по этому seq надо отдать событие
    /// и домен уже известен.
    fn record_outgoing(&mut self, seq: u32, payload: &[u8]) -> Option<(&'static str, String)> {
        self.last_seen = Instant::now();

        // Сборка потока → hostname.
        self.sni.feed(seq, payload);
        if self.hostname.is_none() {
            if let Some(h) = self.sni.done.clone() {
                self.hostname = Some(h);
            }
        }

        // Ретрансмиссии: тот же seq и та же длина payload повторилось ≥ порога.
        if payload.is_empty() {
            return None;
        }
        let entry = self.retx.entry(seq).or_insert(0);
        if *entry & FlowState::RETX_FLAGGED != 0 {
            return None; // уже отдали событие по этому seq
        }
        let count = (*entry & 0x7F) + 1;
        if count >= RETRANS_THRESHOLD {
            if let Some(h) = self.hostname.clone() {
                *entry = FlowState::RETX_FLAGGED;
                return Some(("retrans", h));
            } else {
                // SNI ещё не распознали — счётчик прижимаем к максимуму,
                // события отдаём только при известном домене.
                *entry = 0x7F;
                return None;
            }
        } else {
            *entry = count;
        }
        None
    }

    fn maintenance(&mut self, now: Instant) {
        if self.retx.len() > 4096 {
            self.retx.clear(); // защита от переполнения счётчиков ретрансов
        }
        self.last_seen = now;
    }
}

struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTracker {
    fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    fn get_or_create(&mut self, key: FlowKey) -> &mut FlowState {
        if !self.flows.contains_key(&key as &FlowKey) {
            self.flows.insert(key.clone(), FlowState::new());
        }
        self.flows.get_mut(&key).unwrap()
    }

        /// Чистка TTL + вытеснение при превышении MAX_FLOWS (самый старый).
    fn maintain(&mut self, now: Instant) {
        self.flows.retain(|_, st| now.duration_since(st.last_seen) < Duration::from_secs(FLOW_TTL_SECS));
        if self.flows.len() > MAX_FLOWS {
            // Удаляем самых старых по last_seen.
            let mut vec: Vec<(Instant, FlowKey)> = self
                .flows
                .iter()
                .map(|(k, v)| (v.last_seen, k.clone()))
                .collect();
            vec.sort_by_key(|(t, _)| *t);
            let excess = self.flows.len() - MAX_FLOWS;
            let mut removed: Vec<FlowKey> = Vec::with_capacity(excess);
            for (_, key) in vec.into_iter().take(excess) {
                removed.push(key);
            }
            for key in removed {
                self.flows.remove(&key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Дедуп (домен, причина) и rate-limit ошибок UI.
// ---------------------------------------------------------------------------
struct Dedupe {
    last: HashMap<(String, &'static str), Instant>,
}

impl Dedupe {
    fn new() -> Self {
        Self { last: HashMap::new() }
    }
    /// false — повтор в дедуп-окне (второй раз emit'ить нельзя), true — новое событие.
    fn allow(&mut self, domain: &str, reason: &'static str, now: Instant) -> bool {
        let win = Duration::from_secs(DEDUP_WINDOW_SECS);
        let key = (domain.to_string(), reason);
        match self.last.get(&key) {
            Some(prev) if now.duration_since(*prev) < win => false,
            _ => {
                self.last.insert(key, now);
                true
            }
        }
    }
}

struct RateLimiter {
    window_start: Instant,
    used: u32,
    dropped: u32,
}

impl RateLimiter {
    fn new() -> Self {
        Self { window_start: Instant::now(), used: 0, dropped: 0 }
    }
    fn allow(&mut self, app: &AppHandle) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            if self.dropped > 0 {
                app_log(
                    app,
                    format!("[Автомонитор] rate-limit: дропнуто {} событий избыточных", self.dropped),
                );
            }
            self.dropped = 0;
            self.window_start = now;
            self.used = 1;
            true
        } else if self.used < MAX_UI_EVENTS_PER_SEC {
            self.used += 1;
            true
        } else {
            self.dropped += 1;
            false
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// QUIC (UDP:443) — HTTP/3-поток: собираем Crypto из расшифрованных Initial.
// Крипто-разбор живёт в модуле quic_sniff; здесь — только трекинг и решения.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicFlowKey {
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
    dcid: Vec<u8>,
}

struct QuicFlowState {
    crypto: QuicCryptoBuffer,
    hostname: Option<String>,
    initials_out: u8,
    event_sent: bool,
    proc: Option<String>,
    /// Полный путь exe владельца (для хинта в UI), None = не отдала система.
    proc_path: Option<String>,
    last_seen: Instant,
}

impl QuicFlowState {
    fn new() -> Self {
        Self {
            crypto: QuicCryptoBuffer::new(),
            hostname: None,
            initials_out: 0,
            event_sent: false,
            proc: None,
            proc_path: None,
            last_seen: Instant::now(),
        }
    }

    /// Учитывает один расшифрованный Initial; возвращает домен, когда пора
    /// отдать событие (>= RETRANS_THRESHOLD Initial: QUIC-клиент ретранслирует
    /// Initial ТОЛЬКО если сервер молчит — это и есть «QUIC ломается»).
    fn note_initial(&mut self, parsed: ParsedInitial) -> Option<String> {
        self.last_seen = Instant::now();
        for (offset, chunk) in &parsed.crypto_chunks {
            self.crypto.feed(*offset, chunk);
        }
        if self.hostname.is_none() {
            self.hostname = self.crypto.hostname();
        }
        self.initials_out = self.initials_out.saturating_add(1);
        if !self.event_sent && self.initials_out >= RETRANS_THRESHOLD {
            if let Some(h) = self.hostname.clone() {
                self.event_sent = true;
                return Some(h);
            }
        }
        None
    }
}

struct QuicTracker {
    flows: HashMap<QuicFlowKey, QuicFlowState>,
    no_decrypt_initials: u64,
}

impl QuicTracker {
    fn new() -> Self {
        Self { flows: HashMap::new(), no_decrypt_initials: 0 }
    }

    /// TTL и вытеснение при MAX_FLOWS — та же дисциплина, что у TCP-трекера.
    fn maintain(&mut self, now: Instant) {
        self.flows.retain(|_, st| {
            now.duration_since(st.last_seen) < Duration::from_secs(FLOW_TTL_SECS)
        });
        if self.flows.len() > MAX_FLOWS {
            let mut vec: Vec<(Instant, QuicFlowKey)> = self
                .flows
                .iter()
                .map(|(k, v)| (v.last_seen, k.clone()))
                .collect();
            vec.sort_by_key(|(t, _)| *t);
            let excess = self.flows.len() - MAX_FLOWS;
            let removed: Vec<QuicFlowKey> =
                vec.into_iter().take(excess).map(|(_, k)| k).collect();
            for key in removed {
                self.flows.remove(&key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Данные одного пакета.
// ---------------------------------------------------------------------------
struct TcpInfo<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: u8,
    payload: &'a [u8],
}

/// IPv4: обязателен протокол 6 (TCP); IPv6: только без extension-заголовков
/// (next header = TCP) — редкие v6-чужие-заголовки пропускаем честно.
/// Направление пакета (outbound) определяется ТОЛЬКО по addr (`is_outbound`).
fn parse_tcp_packet(b: &[u8], ipv6: bool) -> Option<TcpInfo<'_>> {
    if b.is_empty() {
        return None;
    }
    let version = b[0] >> 4;
    if ipv6 {
        // IPv6 header: 40 байт.
        if b.len() < 41 || version != 6 {
            return None;
        }
        let next_hdr = b[6];
        if next_hdr != 6 {
            return None; // extension-заголовки — пропускаем
        }
        let payload_total = (((b[4] as usize) << 8) | b[5] as usize) + 40;
        let total = payload_total.min(b.len());
        if total < 60 {
            return None;
        }
        let tcp = &b[40..total];
        let thl = (((tcp[12] >> 4) as usize) * 4).max(20);
        if thl > tcp.len() {
            return None;
        }
        let src = ipv6_from(&b[8..24]);
        let dst = ipv6_from(&b[24..40]);
        make_tcp(tcp, thl, src, dst)
    } else {
        if b.len() < 20 {
            return None;
        }
        let ihl = ((b[0] & 0x0F) * 4) as usize;
        if ihl < 20 || b.len() < ihl + 20 {
            return None;
        }
        if b[9] != 6 {
            return None; // не TCP
        }
        let total_len = (be16(b, 2)).max(ihl + 20);
        let total = total_len.min(b.len());
        let tcp = &b[ihl..total];
        let thl = (((tcp[12] >> 4) as usize) * 4).max(20);
        if thl > tcp.len() {
            return None;
        }
        let src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
        make_tcp(tcp, thl, src, dst)
    }
}

fn ipv6_from(b: &[u8]) -> IpAddr {
    use std::net::Ipv6Addr;
    let mut oct = [0u8; 16];
    oct.copy_from_slice(&b[0..16]);
    IpAddr::V6(Ipv6Addr::from(oct))
}

fn make_tcp<'a>(
    tcp: &'a [u8],
    thl: usize,
    src: IpAddr,
    dst: IpAddr,
) -> Option<TcpInfo<'a>> {
    if tcp.len() < 20 {
        return None;
    }
    let seq = ((tcp[4] as u32) << 24) | ((tcp[5] as u32) << 16) | ((tcp[6] as u32) << 8) | tcp[7] as u32;
    let flags = tcp[13];
    let payload = &tcp[thl..];
    Some(TcpInfo {
        src_ip: src,
        dst_ip: dst,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq,
        flags,
        payload,
    })
}

// ---------------------------------------------------------------------------
// Агрегатор состояния рабочего потока.
// ---------------------------------------------------------------------------
struct WorkerCtx {
    tracker: FlowTracker,
    /// QUIC (UDP:443) поток-трекер (PRP 23.10.26, шаг 3).
    quic: QuicTracker,
    dedup: Dedupe,
    rate: RateLimiter,
    /// Принадлежность домена спискам (ШАГ D, PRP §7.5).
    lists: ListIndex,
    /// Байты фейков активной стратегии winws (инцидент 27.10.26).
    fakes: Arc<FakeBlobs>,
    no_domain_count: u64,
    /// Честное предупреждение не молчит, но и не шумит: один лог за сессию.
    ipv6_warned: bool,
    packets_since_maintain: u64,
}

fn handle_packet(app: &AppHandle, ctx: &mut WorkerCtx, bytes: &[u8], addr: &WinDivertAddress) {
    if addr.is_loopback() {
        return; // loopback — вне первого этапа (PRP §4.4)
    }
    if addr.is_ipv6() {
        // IPv6 — вне этапа (PRP §4.4); ошибки не молчат: ОДИН лог за сессию.
        if !ctx.ipv6_warned {
            ctx.ipv6_warned = true;
            app_log(app, "[Автомонитор] IPv6-пакеты не разбираются (этап — только IPv4)");
        }
        return;
    }
    let outbound = addr.is_outbound();

    // UDP → QUIC-ветка (HTTP/3), всё остальное — классический TCP-детектор.
    if bytes.len() >= 10 && bytes[9] == 17 {
        handle_udp_packet(app, ctx, bytes, outbound);
        return;
    }
    let Some(t) = parse_tcp_packet(bytes, false) else {
        return;
    };

    let (remote_ip, remote_port, local_port) = if outbound {
        (t.dst_ip, t.dst_port, t.src_port)
    } else {
        (t.src_ip, t.src_port, t.dst_port)
    };
    let key = FlowKey { remote_ip, remote_port, local_port };

    ctx.packets_since_maintain += 1;
    if ctx.packets_since_maintain >= 512 {
        ctx.packets_since_maintain = 0;
        let now = Instant::now();
        ctx.tracker.maintain(now);
        ctx.quic.maintain(now);
    }

    // Исходящий (клиент → сервер): собираем ClientHello и считаем ретрансы.
    if outbound {
        if t.payload.is_empty() {
            return;
        }
        if ctx.fakes.is_fake_payload(t.payload) {
            // Подставной пакет winws — детектору не сигнал: фейки идут по 8–11
            // копий с SNI из файла-фейка и без фильтра считались ретрансмиссиями
            // и лочили SNI-коллектор (фантомы onetrust/google, инцидент 27.10.26).
            return;
        }
        let state = ctx.tracker.get_or_create(key.clone());
        // ШАГ E (PRP §7.6): владелец сокета кэшируем на живом соединении
        // (исходящий пакет), один lookup на флоу; remote = dst.
        if state.proc.is_none() {
            if let Some((name, exe)) =
                crate::process_owner::owner_name_and_exe(local_port, remote_ip, remote_port)
            {
                state.proc = Some(name);
                state.proc_path = if exe.is_empty() { None } else { Some(exe) };
            }
        }
        if let Some((reason, domain)) = state.record_outgoing(t.seq, t.payload) {
            let proc_name = state.proc.clone();
            let proc_path = state.proc_path.clone();
            ctx.emit(app, domain, reason, remote_ip, remote_port, proc_name, proc_path, "tls");
        }
        return;
    }

    // Входящий: RST (главный сигнал) и FIN (гашение состояния).
    if t.flags & FLAG_RST != 0 {
        if let Some(mut state) = ctx.tracker.flows.remove(&key) {
            let proc_name = state.proc.clone();
            let proc_path = state.proc_path.clone();
            state.maintenance(Instant::now());
            match state.hostname.clone() {
                Some(domain) => {
                    ctx.emit(app, domain, "rst", remote_ip, remote_port, proc_name, proc_path, "tls")
                }
                None => {
                    ctx.no_domain_count += 1;
                    if ctx.no_domain_count % NO_DOMAIN_FLUSH_EVERY == 0 {
                        app_log(
                            app,
                            format!(
                                "[Автомонитор] RST без домена (соединение до ClientHello): {} шт.",
                                ctx.no_domain_count
                            ),
                        );
                    }
                }
            }
        }
        return;
    }
    if t.flags & FLAG_FIN != 0 {
        ctx.tracker.flows.remove(&key);
    }
}

// ---------------------------------------------------------------------------
// QUIC-обработка UDP-датаграммы (в общий sniff-хендл теперь падает и UDP:443).
// ---------------------------------------------------------------------------
fn handle_udp_packet(app: &AppHandle, ctx: &mut WorkerCtx, bytes: &[u8], outbound: bool) {
    let Some(u) = parse_udp_packet(bytes, false) else {
        return; // урезанный/нечитаемый IP-пакет — детектор трафик не трогает
    };
    let (remote_ip, remote_port, local_port) = if outbound {
        (u.dst_ip, u.dst_port, u.src_port)
    } else {
        (u.src_ip, u.src_port, u.dst_port)
    };

    if !outbound {
        // Сервер ответил (Handshake/VN/Retry) — соединение живо: гасим треки
        // данного 4-tuple БЕЗ события (событие тут не нужно).
        ctx.quic.flows.retain(|k, _| {
            k.remote_ip != remote_ip || k.remote_port != remote_port || k.local_port != local_port
        });
        return;
    }

    // QUIC-фейк winws (11 копий Initial с DCID и SNI из файла-фейка) — не сигнал:
    // без фильтра каждый подменяемый флоу давал фантомное
    // «QUIC: сервер не отвечает на Initial» (инцидент 27.10.26).
    if ctx.fakes.is_fake_payload(u.payload) {
        return;
    }

    let Some(kind) = classify_quic(u.payload) else { return };
    if kind != QuicPacketKind::Initial {
        return; // SNI живёт только в Initial (RFC 9001 §4.4)
    }
    let Some(parsed) = parse_initial_payload(u.payload) else {
        // Расшифровать Initial не удалось (мусор/иная реализация UDP:443).
        // Не молчим: ОДИН честный лог на сессию детектора, дальше — тишина.
        ctx.quic.no_decrypt_initials += 1;
        if ctx.quic.no_decrypt_initials == 1 {
            app_log(
                app,
                "[Автомонитор] QUIC Initial не расшифрован (мусор/иная реализация) — детектор продолжает работу",
            );
        }
        return;
    };

    let key = QuicFlowKey { remote_ip, remote_port, local_port, dcid: parsed.dcid.clone() };
    // Один lookup на флоу (кэш в состоянии) — так же, как в TCP-ветке ШАГа E.
    // UDP-сокет не имеет удалённой пары: владелец ищется по локальному порту
    // в UDP-таблице (до 27.10.26 QUIC-события писали «процесс не определён»).
    let (owner_name, owner_path) =
        crate::process_owner::udp_owner_name_and_exe(local_port)
            .map(|(n, e)| (Some(n), if e.is_empty() { None } else { Some(e) }))
            .unwrap_or((None, None));
    let state = ctx.quic.flows.entry(key).or_insert_with(|| QuicFlowState {
        proc: owner_name,
        proc_path: owner_path,
        ..QuicFlowState::new()
    });
    if let Some(domain) = state.note_initial(parsed) {
        let proc_name = state.proc.clone();
        let proc_path = state.proc_path.clone();
        ctx.emit(app, domain, "quic", remote_ip, remote_port, proc_name, proc_path, "quic");
    }
}

impl WorkerCtx {
    fn emit(
        &mut self,
        app: &AppHandle,
        domain: String,
        reason: &'static str,
        ip: IpAddr,
        port: u16,
        proc_name: Option<String>,
        proc_path: Option<String>,
        l7proto: &'static str,
    ) {
        let now = Instant::now();
        if !self.dedup.allow(&domain, reason, now) {
            return;
        }
        if !self.rate.allow(app) {
            return;
        }
        let ip_port = format!("{}:{}", ip, port);
        // ШАГ D (PRP §7.5): в каких наших списках нашёлся домен.
        let lists = self.lists.find(&domain);
        let ev = DomainDiscoveryEvent {
            domain: domain.clone(),
            reason,
            client_ip_port: ip_port.clone(),
            l7proto,
            observed_at_ms: now_ms(),
            lists,
            // ШАГ E: кто стучался; пустая строка = не определился (фронт
            // честно показывает «процесс не определён», не молчит).
            proc_name: proc_name.unwrap_or_default(),
            // Полный путь exe — для хинта по наведению мыши в UI.
            proc_path: proc_path.unwrap_or_default(),
        };
        // Решение юзера (21.10.26, финал): строки блокировок в «Лог событий»
        // НЕ пишем — их единственное место это список подозрений (дедуп по
        // домену, счётчик ×N). Человекочитаемый текст события (причина по-
        // и списки) собирает фронт: reasonText.ts + строка списка (SSOT).
        // Бэкендовые human-дубли удалены. В лог попадают только системные
        // сообщения (старт/стоп/ошибки).
        if let Err(err) = app.emit("domain_discovery", &ev) {
            app_log(app, format!("[Автомонитор] не удалось доставить событие в UI: {}", err));
        }
    }
}

// ---------------------------------------------------------------------------
// Жизненный цикл мониторинга (start / stop).
// ---------------------------------------------------------------------------

struct MonitorState {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    /// Сырой WinDivert-хендл для WinDivertShutdown из stop-потока (хендл владеет
    /// рабочий поток; останавливаем его ДО глушения обхода, см. PRP ШАГ 3).
    raw: *mut std::ffi::c_void,
}

unsafe impl Send for MonitorState {}

static MONITOR: Mutex<Option<MonitorState>> = Mutex::new(None);

pub fn start_domain_monitor(app: AppHandle, winws_args: &[String]) -> Result<(), String> {
    let mut guard = MONITOR.lock().expect("MONITOR mutex poisoned");
    if let Some(state) = guard.as_ref() {
        if !state.thread.is_finished() {
            app_log(&app, "[Автомонитор] уже запущен");
            return Ok(());
        }
    }

    if read_mode() == MonitorMode::Off {
        return Ok(()); // режим off — тихо и молча ничего не делаем (PRP)
    }

    // Фильтр фейков (инцидент 27.10.26): байты фейков активной стратегии —
    // из аргументов запуска winws (SSOT: те же final_args, что у процесса;
    // монитор живёт ровно между stop_winws и spawn_winws, рассинхрона нет).
    let (fakes, fake_warnings) = FakeBlobs::from_winws_args(winws_args);
    if fakes.is_empty() {
        app_log(
            &app,
            "[Автомонитор] фейк-файлы в аргументах winws не найдены — фильтр фейков не активен".to_string(),
        );
    } else {
        app_log(
            &app,
            format!(
                "[Автомонитор] фильтр фейков winws: {} блоб(ов), {} байт — {}",
                fakes.len(),
                fakes.total_len(),
                fakes.source_names().join(", ")
            ),
        );
    }
    // Ошибки не молчат (core §2.2): каждый непрочитанный фейк — видимое предупреждение.
    for warn in &fake_warnings {
        app_log(&app, format!("[Автомонитор] фейк: {}", warn));
    }
    let fakes = Arc::new(fakes);

    let handle = open_sniff_handle(sniff_filter())
        .map_err(|e| format!("[Автомонитор] не запущен: {}", e))?;
    let raw = handle.raw();

    // ШАГ D (PRP §7.5): индекс списков грузится ОДНАЗОВО при старте детектора;
    // правки списков юзер подхватывает рестартом обхода (тот же ритм, что у winws).
    let lists_dir = crate::config::get_app_dir().join("lists");
    let (lists, warnings) = ListIndex::load(&lists_dir);
    for warn in &warnings {
        app_log(&app, format!("[Автомонитор] список не прочитан: {}", warn));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let app_thread = app.clone();
    let thread = std::thread::Builder::new()
        .name("domain-monitor".into())
        .spawn(move || {
            worker(app_thread, handle, stop_thread, lists, fakes);
        })
        .map_err(|e| format!("[Автомонитор] старт потока не удался: {}", e))?;

    app_log(&app, "[Автомонитор] старт (SNIFF, TCP/UDP:443, priority LOWEST)");
    *guard = Some(MonitorState { stop, thread, raw });
    Ok(())
}

pub fn stop_domain_monitor() {
    let mut guard = MONITOR.lock().expect("MONITOR mutex poisoned");
    if let Some(state) = guard.take() {
        state.stop.store(true, Ordering::Relaxed);
        // Официальная остановка очереди чтения — из другого потока:
        // Recv в рабочем цикле вернёт ERROR_NO_DATA (232), поток выйдет,
        // SniffHandle в нём дропнется и закроет хендл.
        if let Ok(syms) = crate::win_divert::get_sniff_syms() {
            let _ = syms.shutdown_read(state.raw);
        }
        let _ = state.thread.join();
    }
}

// ---------------------------------------------------------------------------
// Рабочий цикл (Recv → parse → события).
// ---------------------------------------------------------------------------
fn worker(
    app: AppHandle,
    handle: SniffHandle,
    stop: Arc<AtomicBool>,
    lists: ListIndex,
    fakes: Arc<FakeBlobs>,
) {
    let mut ctx = WorkerCtx {
        tracker: FlowTracker::new(),
        quic: QuicTracker::new(),
        dedup: Dedupe::new(),
        rate: RateLimiter::new(),
        lists,
        fakes,
        no_domain_count: 0,
        ipv6_warned: false,
        packets_since_maintain: 0,
    };
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    let mut addr = WinDivertAddress { timestamp: 0, bitfields: 0, reserved2: 0, union_data: [0u8; 64] };

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match handle.recv_packet(&mut buf, &mut addr) {
            Ok(0) => break, // официальный сигнал shutdown (пустая очередь)
            Ok(n) => handle_packet(&app, &mut ctx, &buf[..n], &addr),
            Err(ref e) if e.code == 232 => break, // ERROR_NO_DATA — очередь погашена
            Err(e) => {
                app_log(&app, format!("[Автомонитор] ошибка Recv: {}", e));
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    app_log(&app, "[Автомонитор] рабочий поток завершён");
}

// ---------------------------------------------------------------------------
// Тесты (unit): без драйвера, чистая логика.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_client_hello ------------------------------------------------
    #[test]
    fn sni_parse_tls12_full() {
        // Честный TLS ClientHello c SNI = example.org (одна name, name_type=0).
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
        // настоящая запись TLS с SNI, но обрезанная — Incomplete, не паника.
        let full = build_client_hello(b"example.org");
        let cut = &full[..full.len() / 2];
        assert_eq!(parse_client_hello(cut), CliHelloStatus::Incomplete);
    }

    // --- FlowTracker / SniCollector ----------------------------------------
    #[test]
    fn collector_fragments_seq_hole() {
        let payload = build_client_hello(b"example.org");
        let m = payload.len() / 2;
        assert!(payload.len() > 10);
        let mut col = SniCollector::new();
        // Первая часть приходит по seq=0.
        col.feed(0, &payload[..m]);
        assert!(col.done.is_none());
        // Хвост приходит РАНЬШЕ середины: дыра (m..m+10) — уходит в pending.
        col.feed((m + 10) as u32, &payload[m + 10..]);
        assert!(col.done.is_none(), "дыра не закрыта — done появляться не должен");
        // Закрываем дыру.
        col.feed(m as u32, &payload[m..m + 10]);
        assert!(col.done.is_some(), "Ожидали hostname после закрытия дыры");
    }

    #[test]
    fn retransmit_produces_event_after_3() {
        let mut st = FlowState::new();
        st.hostname = Some("example.com".to_string());
        let payload = vec![1u8, 2, 3, 4];
        assert!(st.record_outgoing(0, &payload).is_none());
        assert!(st.record_outgoing(0, &payload).is_none());
        let ev = st.record_outgoing(0, &payload);
        assert_eq!(ev, Some(("retrans", "example.com".to_string())));
        // Повтор после отдачи — давно flagged → NONE.
        assert!(st.record_outgoing(0, &payload).is_none());
    }

    #[test]
    fn retransmit_without_hostname_is_quiet() {
        let mut st = FlowState::new();
        let payload = vec![1u8, 2, 3, 4];
        for _ in 0..3 {
            st.record_outgoing(0, &payload);
        }
        assert!(st.record_outgoing(0, &payload).is_none(), "без домена событие НЕ отдали");
    }

    // --- Дедуп/раз rate -----------------------------------------------------
    // --- QUIC (UDP:443) -----------------------------------------------------
    #[test]
    fn quic_initial_event_on_third_initial_server_silent() {
        let ch = build_client_hello(b"example.test");
        let dcid = [7u8; 8];
        let packet = crate::quic_sniff::build_quic_initial_v1(&dcid, &ch);
        let mut st = QuicFlowState::new();
        let mut got = None;
        for _ in 0..3 {
            let parsed = crate::quic_sniff::parse_initial_payload(&packet)
                .expect("синтетический Initial обязан расшифровываться");
            got = st.note_initial(parsed);
        }
        assert_eq!(got.as_deref(), Some("example.test"), "событие — на 3-м Initial");
        assert!(st.event_sent, "событие однократно");
        // Повторные Initial после отдачи события — тишина.
        let parsed = crate::quic_sniff::parse_initial_payload(&packet).expect("расшифровка");
        assert!(st.note_initial(parsed).is_none(), "повтор после event_sent — тишина");
    }

    #[test]
    fn quic_hostname_missing_is_quiet() {
        // Initial БЕЗ Crypto-кадров: домен не появится — событие НЕ отдаём.
        let parsed = ParsedInitial { dcid: vec![1u8; 8], crypto_chunks: vec![] };
        let mut st = QuicFlowState::new();
        for _ in 0..5 {
            assert!(st.note_initial(parsed.clone()).is_none());
        }
    }

    #[test]
    fn quic_tracker_ttl_and_cap() {
        let mut t = QuicTracker::new();
        let mut st = QuicFlowState::new();
        st.last_seen = Instant::now() - Duration::from_secs(FLOW_TTL_SECS + 1);
        t.flows.insert(
            QuicFlowKey {
                remote_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                remote_port: 443,
                local_port: 50000,
                dcid: vec![1; 8],
            },
            st,
        );
        t.maintain(Instant::now());
        assert!(t.flows.is_empty(), "по TTL затухло");

        // Лимит MAX_FLOWS: лишние (самые старые) вытесняются.
        for i in 0..(MAX_FLOWS + 5) {
            let mut st = QuicFlowState::new();
            // Возрасты в МУХАХ: i как миллисекунды (i*секунды при i≥900
            // вынесли бы запись за TTL в 15 минут и тест ловил бы сам себя).
            st.last_seen = Instant::now() - Duration::from_millis(i as u64);
            t.flows.insert(
                QuicFlowKey {
                    remote_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, (i % 250) as u8)),
                    remote_port: 443,
                    local_port: 50000,
                    dcid: vec![(i % 251) as u8; 8],
                },
                st,
            );
        }
        t.maintain(Instant::now());
        assert_eq!(t.flows.len(), MAX_FLOWS);
    }

    // --- Дедуп/раз rate -----------------------------------------------------
    #[test]
    fn dedup_window_blocks_repeat() {
        let mut d = Dedupe::new();
        let now = Instant::now();
        assert!(d.allow("a.com", "rst", now));
        assert!(!d.allow("a.com", "rst", now));
        assert!(d.allow("a.com", "retrans", now));
        // После окна — снова можно.
        let later = now + Duration::from_secs(31);
        assert!(d.allow("a.com", "rst", later));
    }

    // --- parse TCP ----------------------------------------------------------
    #[test]
    fn tcp_parse_ipv4_rst() {
        // Соберём IPv4 пакет: 20 байт IP + 20 байт TCP (без payload).
        // IPv4: ver/ihl(0x45), DSCP(0x00), total_len(0x0028=40), id, flags, ttl(0x40=64),
        // protocol(6=TCP), checksum, src ip, dst ip.
        let mut raw = vec![0u8; 40];
        raw[0] = 0x45; // version=4, IHL=5
        raw[1] = 0x00;
        raw[2] = 0x00;
        raw[3] = 40;   // total length = 40
        raw[8] = 64;   // TTL
        raw[9] = 6;    // protocol TCP
        raw[12..=15].copy_from_slice(&[1, 2, 3, 4]);  // src ip
        raw[16..=19].copy_from_slice(&[8, 8, 8, 8]);  // dst ip
        // TCP header (offset 20):
        raw[20..=21].copy_from_slice(&100u16.to_be_bytes()); // src port 100
        raw[22..=23].copy_from_slice(&443u16.to_be_bytes()); // dst port 443
        raw[24..=27].copy_from_slice(&42u32.to_be_bytes());  // seq = 42
        raw[28..=31].copy_from_slice(&0u32.to_be_bytes());   // ack
        raw[32] = 0x50;       // data offset = 5*4 = 20 байт заголовка TCP
        raw[33] = FLAG_RST;   // флаг RST
        let t = parse_tcp_packet(&raw, false).expect("parse ipv4");
        assert_eq!(t.flags & FLAG_RST, FLAG_RST);
        assert_eq!(t.src_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(t.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(t.src_port, 100);
        assert_eq!(t.dst_port, 443);
        assert_eq!(t.seq, 42);
        assert!(t.payload.is_empty());
    }

/// Строит реальный байтовый поток TLS ClientHello c единственным SNI (name_type=0).
fn build_client_hello(host: &[u8]) -> Vec<u8> {
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
    body.extend_from_slice(&[3u8, 3]);            // client version TLS1.2
    body.extend_from_slice(&[0u8; 32]);           // random
    body.push(0u8);                                // session_id len=0
    body.extend_from_slice(&0u16.to_be_bytes());   // ciphers len=0
    body.push(0u8);                                // comps len=0
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
}
