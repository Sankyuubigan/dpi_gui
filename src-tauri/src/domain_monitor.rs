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

use std::collections::{HashMap, HashSet};
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
use crate::reanim::{
    build_inbound_rst, is_googlevideo, make_send_address_ifidx, FlowKeyLite, InjectionDecision,
    ReanimCandidate, ReanimLedger, RstParams, HANDSHAKE_T, MAX_QUAR, MAX_RST,
    QUAR_COOLDOWN_T, QUARANTINE_T, QUAR_MAX_CONCURRENT, QUIC_DATA_MIN, QUIC_RETRANS_FRESH_T,
    QUIC_SILENCE_T, SILENCE_T, STATS_WINDOW, SUCCESS_WINDOW,
};
use crate::win_divert::{
    open_capture_handle, open_send_handle, open_sniff_handle, CaptureHandle, SendHandle,
    SniffHandle, WinDivertAddress, MAX_PACKET_LEN,
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
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;

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

/// Реаниматор (PRP 10.11.26): включён ли. Config-ключ `media_reanim_mode`,
/// дефолт «on»; тумблер двухпозиционный — всё, кроме «off», трактуем как «on».
pub fn read_reanim_mode() -> bool {
    let raw = match crate::config::read_config() {
        Ok(v) => v
            .get("media_reanim_mode")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        Err(_) => None,
    };
    raw.as_deref() != Some("off")
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
    /// Конфликтные записи слота хоста (hostfakesplit): (offset, варианты
    /// байтов). Zapret шлёт фейк-хост ДВАЖДЫ — вокруг реального (altorder=0:
    /// before, fake, real, fake, after) или после after_host (altorder=1) —
    /// сборка ClientHello завершается на фейке, реальный хост живёт здесь.
    alternates: Vec<(usize, Vec<Vec<u8>>)>,
}

impl SniCollector {
    const MAX_ATTEMPTS: u8 = 2;
    const MAX_ALT_SETS: usize = 3;
    const MAX_ALT_VALS: usize = 4;
    const MAX_CANDIDATES: usize = 8;

    fn new() -> Self {
        Self {
            base_seq: None,
            collected: Vec::new(),
            pending: HashMap::new(),
            attempts: 0,
            done: None,
            alternates: Vec::new(),
        }
    }

    fn stop_collecting(&mut self) {
        self.base_seq = None;
        self.collected.clear();
        self.pending.clear();
        self.alternates.clear();
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
                // Освобождаем pending — домен извлечён. collected НЕ чистим:
                // hostfakesplit завершает сборку на фейк-хосте, а конфликтные
                // записи слота хоста приходят ПОСЛЕ первой сборки — без базы
                // candidate_hosts не соберёт кандидатов (см. merge_at).
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

    /// Все хостнеймы, восстановимые из сборки: сама сборка плюс варианты
    /// конфликтных перезаписей слота хоста. hostfakesplit завершает сборку
    /// на фейк-хосте (слот пишется фейком последним перед after_host либо
    /// after_host завершает сборку до реального хоста) — реальный хост
    /// обязан выбираться отсюда, а не из done.
    fn candidate_hosts(&self) -> Vec<String> {
        if self.alternates.is_empty() {
            return match parse_client_hello(&self.collected) {
                CliHelloStatus::Found(h) => vec![h],
                _ => Vec::new(),
            };
        }
        // Перечисление: база (текущие байты) + сплайс каждой альтернативы.
        let mut bufs: Vec<Vec<u8>> = vec![self.collected.clone()];
        for (off, vals) in &self.alternates {
            let mut grown: Vec<Vec<u8>> = Vec::new();
            for b in &bufs {
                for v in vals {
                    if off + v.len() <= b.len() && &b[*off..*off + v.len()] != v.as_slice() {
                        let mut c = b.clone();
                        c[*off..*off + v.len()].copy_from_slice(v);
                        grown.push(c);
                        if bufs.len() + grown.len() >= Self::MAX_CANDIDATES {
                            break;
                        }
                    }
                }
                if bufs.len() + grown.len() >= Self::MAX_CANDIDATES {
                    break;
                }
            }
            bufs.extend(grown);
            if bufs.len() >= Self::MAX_CANDIDATES {
                bufs.truncate(Self::MAX_CANDIDATES);
                break;
            }
        }
        let mut hosts: Vec<String> = Vec::new();
        for b in &bufs {
            if let CliHelloStatus::Found(h) = parse_client_hello(b) {
                if !hosts.contains(&h) {
                    hosts.push(h);
                }
            }
        }
        hosts
    }

    fn feed(&mut self, seq: u32, payload: &[u8]) {
        // done больше НЕ блокирует приём: hostfakesplit завершает сборку на
        // фейк-хосте, а реальные части идут ПОСЛЕ (altorder=1) либо затираются
        // вторым фейком до after_host (altorder=0) — без дальнейшего приёма
        // конфликты не попадут в alternates. Лочение hostname решает
        // record_outgoing по не-фейковым кандидатам.
        if self.attempts >= Self::MAX_ATTEMPTS || payload.is_empty() {
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
    /// Отличающиеся same-length записи запоминаются как альтернативы слота —
    /// без них реальный хост hostfakesplit теряется (затирается вторым фейком).
    fn merge_at(&mut self, offset: usize, payload: &[u8]) {
        let end = (offset + payload.len()).min(self.collected.len());
        if offset + payload.len() <= self.collected.len()
            && self.collected[offset..end] != payload[..end - offset]
        {
            let pre = self.collected[offset..end].to_vec();
            let want_len = pre.len();
            if let Some((_, vals)) = self
                .alternates
                .iter_mut()
                .find(|(o, vs)| *o == offset && vs[0].len() == want_len)
            {
                if vals.len() < Self::MAX_ALT_VALS && !vals.iter().any(|v| *v == pre) {
                    vals.push(pre);
                }
            } else if self.alternates.len() < Self::MAX_ALT_SETS {
                self.alternates.push((offset, vec![pre]));
            }
        }
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
    /// Фейк-хосты конфига winws (hostfakesplit) — выбор реального hostname
    /// среди кандидатов сборки (группы ALT13 шлют фейк-хост вокруг реального).
    fakes: Arc<crate::fake_payloads::FakeBlobs>,
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
    // --- Реаниматор (M1, PRP 10.11.26): заполняются только при включённом режиме ---
    /// Клиентский IP (src исходящих пакетов) — адресация RST.
    client_ip: Option<Ipv4Addr>,
    /// RCV.NXT клиента = ACK-поле его исходящих сегментов (bare-ACK тоже) —
    /// это SEQ для RST.
    rcv_nxt: Option<u32>,
    /// SND.NXT клиента = последний outgoing seq + длина payload (+1 на SYN/FIN)
    /// — это ACK для RST|ACK.
    snd_nxt: Option<u32>,
    /// Входящие DATA видели (ServerHello пришёл) — живой путь, guard: такой
    /// поток для кейса «висящее рукопожатие» не трогаем.
    saw_inbound_data: bool,
    /// Момент последнего входящего DATA (порог тишины SILENCE_T).
    last_inbound_data: Option<Instant>,
    /// Начало попытки рукопожатия — первый исходящий пакет с DATA.
    first_out_at: Option<Instant>,
    /// Дупретрансы какого-то seq достигали RETRANS_THRESHOLD (кейс 2).
    stalled_retrans: bool,
    /// IfIdx/SubIfIdx флоу (из WinDivertAddress исходящего пакета) — адресация
    /// инжекции в тот же интерфейс.
    ifidx: (u32, u32),
}

impl FlowState {
    const RETX_FLAGGED: u8 = 0x80;

    fn new(fakes: Arc<crate::fake_payloads::FakeBlobs>) -> Self {
        Self {
            sni: SniCollector::new(),
            hostname: None,
            fakes,
            proc: None,
            proc_path: None,
            retx: HashMap::new(),
            last_seen: Instant::now(),
            client_ip: None,
            rcv_nxt: None,
            snd_nxt: None,
            saw_inbound_data: false,
            last_inbound_data: None,
            first_out_at: None,
            stalled_retrans: false,
            ifidx: (0, 0),
        }
    }

    /// Метаданные исходящего пакета для реаниматора (в т.ч. bare-ACK без
    /// payload — ACK-поле и есть RCV.NXT клиента).
    fn note_outgoing_meta(
        &mut self,
        client_ip: IpAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload_len: usize,
        addr: &WinDivertAddress,
    ) {
        if let IpAddr::V4(v4) = client_ip {
            self.client_ip = Some(v4);
        }
        if flags & FLAG_ACK != 0 {
            self.rcv_nxt = Some(ack);
        }
        // SYN/FIN съедают один номер seq.
        let adv = payload_len as u32
            + if flags & (FLAG_SYN | FLAG_FIN) != 0 { 1 } else { 0 };
        self.snd_nxt = Some(seq.wrapping_add(adv));
        if payload_len > 0 && self.first_out_at.is_none() {
            self.first_out_at = Some(Instant::now());
        }
        // IfIdx/SubIfIdx лежат в union_data[0..8] (LE) — интерфейс флоу.
        self.ifidx = (
            u32::from_le_bytes(addr.union_data[0..4].try_into().expect("4 байта")),
            u32::from_le_bytes(addr.union_data[4..8].try_into().expect("4 байта")),
        );
    }

    /// M1: условия инжекции для зависшего googlevideo-потока (PRP «уточнение
    /// триггера»). Кейс 1 — висящее рукопожатие: ClientHello ушёл, ServerHello
    /// не пришёл HANDSHAKE_T. Кейс 2 — установленный поток замер: дупретрансы
    /// ≥ RETRANS_THRESHOLD и входящие DATA молчат SILENCE_T.
    fn reanim_stall_check(&self, key: &FlowKey, now: Instant) -> Option<ReanimCandidate> {
        let host = self.hostname.as_ref()?;
        if !is_googlevideo(host) {
            return None;
        }
        let (reason, silence) = if !self.saw_inbound_data {
            let first = self.first_out_at?;
            let age = now.duration_since(first);
            if age < HANDSHAKE_T {
                return None;
            }
            ("handshake", age)
        } else {
            if !self.stalled_retrans {
                return None;
            }
            let last = self.last_inbound_data?;
            let quiet = now.duration_since(last);
            if quiet < SILENCE_T {
                return None;
            }
            ("stall", quiet)
        };
        // Без RCV.NXT/SND.NXT честный RST не собрать — не инжектим (не молчим:
        // такое состояние уже не детектится как «зависшее» до появления ACK).
        let client_ip = self.client_ip?;
        let rcv_nxt = self.rcv_nxt?;
        let snd_nxt = self.snd_nxt?;
        let IpAddr::V4(server_ip) = key.remote_ip else { return None };
        let retx_n = self.retx.values().map(|v| (*v & 0x7F) as u32).max().unwrap_or(0);
        Some(ReanimCandidate {
            params: RstParams {
                server_ip,
                client_ip,
                server_port: key.remote_port,
                client_port: key.local_port,
                seq: rcv_nxt,
                ack: snd_nxt,
            },
            reason,
            host: host.clone(),
            retx_n,
            silence,
            ifidx: self.ifidx,
        })
    }

    /// Возвращает Some((reason, домен)), если по этому seq надо отдать событие
    /// и домен уже известен.
    fn record_outgoing(&mut self, seq: u32, payload: &[u8]) -> Option<(&'static str, String)> {
        self.last_seen = Instant::now();

        // Сборка потока → hostname. После лочения сборка не нужна.
        if self.hostname.is_none() {
            self.sni.feed(seq, payload);
            // hostfakesplit завершает сборку на ФЕЙК-хосте (слот хоста перед
            // after_host пишется фейком, либо after_host завершает сборку до
            // прихода реального хоста) — берём первого кандидата, НЕ
            // совпадающего с фейк-хостами конфига winws (тот же SSOT final_args,
            // что у блоб-фильтра). Без фейк-конфига — первый кандидат (как
            // раньше). Идентичные ретрансы альтернатив не создают.
            let host = self
                .sni
                .candidate_hosts()
                .into_iter()
                .find(|h| !self.fakes.is_fake_hostname(h));
            if let Some(h) = host {
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
            // Кейс 2 реаниматора: дупретрансы уже на пороге (событие «retrans»
            // как было, так и остаётся — реаниматор смотрит ещё и на тишину).
            self.stalled_retrans = true;
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
    /// Фейк-хосты hostfakesplit из конфига winws (SSOT) — для выбора
    /// реального hostname среди кандидатов сборки (см. record_outgoing).
    fakes: Arc<crate::fake_payloads::FakeBlobs>,
}

impl FlowTracker {
    fn new(fakes: Arc<crate::fake_payloads::FakeBlobs>) -> Self {
        Self { flows: HashMap::new(), fakes }
    }

    fn get_or_create(&mut self, key: FlowKey) -> &mut FlowState {
        if !self.flows.contains_key(&key as &FlowKey) {
            self.flows.insert(key.clone(), FlowState::new(self.fakes.clone()));
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

/// 4-tuple в «плоской» форме леджера реаниматора (только IPv4; v6 вне этапа).
fn flow_key_lite_parts(remote_ip: IpAddr, remote_port: u16, local_port: u16) -> Option<FlowKeyLite> {
    match remote_ip {
        IpAddr::V4(ip) => {
            Some(FlowKeyLite { remote_ip: ip, remote_port, local_port })
        }
        IpAddr::V6(_) => None,
    }
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
// М3: стол QUIC-потока к googlevideo (исходящие есть — входящие молчат).
// ---------------------------------------------------------------------------

/// 3-tuple (без dcid): для столова соединение идентифицируется тройкой
/// (клиент, сервер, локальный порт) — dcid меняется при ретрае Chrome.
#[derive(Clone, PartialEq, Eq, Hash)]
struct QuicStallKey {
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
}

/// Состояние одного QUIC-флоу для реанимации (М4).
#[derive(Clone)]
struct QuicStallState {
    /// SNI googlevideo подтверждён (расшифрованный Initial) — только такие
    /// потоки реанимируем.
    hostname_gv: bool,
    /// Последний полноразмерный входящий пакет (≥ QUIC_DATA_MIN — медиа-данные).
    /// ACK-мелочь не считается: она ходит и по мёртвому потоку.
    last_inbound_data: Option<Instant>,
    /// Последний полноразмерный исходящий пакет (запрос/ретрансмит
    /// незаэкношенного стрима). Здоровый PING-idle полноразмерных не даёт.
    last_outbound_data: Option<Instant>,
    last_seen: Instant,
}

/// Трекер столов QUIC — часть рантайма реаниматора (М4).
struct QuicStallTracker {
    flows: HashMap<QuicStallKey, QuicStallState>,
}

impl QuicStallTracker {
    fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    /// Исходящий пакет: полноразмерный = исходящие данные живы. Карта
    /// пополняется всеми UDP:443-флоу (когда реаниматор включён) — лимит
    /// MAX_FLOWS и TTL срезают балласт в maintain().
    fn note_outbound(&mut self, key: QuicStallKey, bytes: &[u8], now: Instant) {
        let st = self.flows.entry(key).or_insert_with(|| QuicStallState {
            hostname_gv: false,
            last_inbound_data: None,
            last_outbound_data: None,
            last_seen: now,
        });
        st.last_seen = now;
        if bytes.len() >= QUIC_DATA_MIN {
            st.last_outbound_data = Some(now);
        }
    }

    /// Входящий пакет: полноразмерный = медиа-данные подтвердились.
    fn note_inbound(
        &mut self,
        remote_ip: IpAddr,
        remote_port: u16,
        local_port: u16,
        bytes_len: usize,
        now: Instant,
    ) {
        if let Some(st) =
            self.flows.get_mut(&QuicStallKey { remote_ip, remote_port, local_port })
        {
            st.last_seen = now;
            if bytes_len >= QUIC_DATA_MIN {
                st.last_inbound_data = Some(now);
            }
        }
    }

    /// hostname-переход googlevideo (расшифрованный Initial) — поток
    /// подтверждён, кандидат на карантин.
    fn mark_gv(&mut self, remote_ip: IpAddr, remote_port: u16, local_port: u16) {
        if let Some(st) =
            self.flows.get_mut(&QuicStallKey { remote_ip, remote_port, local_port })
        {
            st.hostname_gv = true;
        }
    }

    /// Кандидаты на карантин: SNI googlevideo, входящие медиа-данные молчат
    /// ≥ `QUIC_SILENCE_T`, при этом полноразмерные исходящие СВЕЖЕЕ входящих
    /// (`lo > li` — Chrome гребёт против молчащего сервера) и свежие
    /// (≤ `QUIC_RETRANS_FRESH_T` — ретрансмиты незаэкношенного; отсекает
    /// PING-idle буфера и паузу ролика, где полноразмерных исходящих нет).
    fn candidates(&self, now: Instant) -> Vec<(QuicStallKey, QuicStallState)> {
        self.flows
            .iter()
            .filter(|(_, st)| {
                let Some(li) = st.last_inbound_data else { return false };
                let Some(lo) = st.last_outbound_data else { return false };
                st.hostname_gv
                    && lo > li
                    && now.duration_since(li) >= QUIC_SILENCE_T
                    && now.duration_since(lo) <= QUIC_RETRANS_FRESH_T
            })
            .map(|(k, st)| (k.clone(), st.clone()))
            .collect()
    }

    /// TTL и вытеснение — та же дисциплина, что у TCP/QUIC-трекеров.
    fn maintain(&mut self, now: Instant) {
        self.flows.retain(|_, st| {
            now.duration_since(st.last_seen) < Duration::from_secs(FLOW_TTL_SECS)
        });
        if self.flows.len() > MAX_FLOWS {
            let mut vec: Vec<(Instant, QuicStallKey)> = self
                .flows
                .iter()
                .map(|(k, v)| (v.last_seen, k.clone()))
                .collect();
            vec.sort_by_key(|(t, _)| *t);
            let excess = self.flows.len() - MAX_FLOWS;
            for (_, k) in vec.into_iter().take(excess) {
                self.flows.remove(&k);
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
    /// ACK-поле сегмента (номер, который отправитель ЖДЁТ = его RCV.NXT);
    /// валиден только при флаге ACK — реаниматору для адресации RST.seq.
    ack: u32,
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
    let ack = ((tcp[8] as u32) << 24) | ((tcp[9] as u32) << 16) | ((tcp[10] as u32) << 8) | tcp[11] as u32;
    let flags = tcp[13];
    let payload = &tcp[thl..];
    Some(TcpInfo {
        src_ip: src,
        dst_ip: dst,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq,
        ack,
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
    /// Реаниматор (M1): None = выключен (media_reanim_mode=off) или send-хендл
    /// не открылся (причина — в логе старта).
    reanim: Option<ReanimRuntime>,
}

/// Рантайм реаниматора: хендл инжекции + лимиты + счётчики транспорта (M2).
struct ReanimRuntime {
    handle: SendHandle,
    ledger: ReanimLedger,
    /// Ключи, по которым «лимит исчерпан» уже отдали в лог (не спамим).
    limit_logged: HashSet<FlowKeyLite>,
    /// M2: исходящие ClientHello к googlevideo (TCP:443) за окно отчёта.
    gc_ch_tcp: u64,
    /// M2: новые QUIC-потоки к googlevideo (UDP:443) за окно отчёта.
    gc_quic: u64,
    /// Момент последней строки отчёта о транспорте.
    last_stats_flush: Option<Instant>,
    /// М4: трекер столов QUIC-потоков (медиа-данных нет ≥ 10 с, ретраи свежие).
    stall: QuicStallTracker,
    /// М4: активные карантины флоу → (capture-хендл, дедлайн). Снятие — по
    /// дедлайну в свипке: закрытие хендла (Drop) → blocked recv треда
    /// карантина вернёт ошибку → тред завершится, трафик флоу отпущен.
    quarantines: HashMap<FlowKeyLite, (CaptureHandle, Instant)>,
}

impl WorkerCtx {
    /// M1: инжекция RST в зависший поток — лимиты, сборка, отправка, логи.
    fn reanim_inject(&mut self, app: &AppHandle, key: &FlowKey, cand: ReanimCandidate) {
        let Some(rt) = self.reanim.as_mut() else { return };
        let Some(lite) = flow_key_lite_parts(key.remote_ip, key.remote_port, key.local_port) else {
            return;
        };
        let now = Instant::now();
        match rt.ledger.decide(&lite, now) {
            InjectionDecision::Cooldown => {} // недавно уже сбрасывали — тишина
            InjectionDecision::Limit => {
                if rt.limit_logged.insert(lite) {
                    app_log(
                        app,
                        format!(
                            "[Реаниматор] не реанимировалось: {}:443 ({}) — лимит {} сбросов исчерпан",
                            cand.params.server_ip, cand.host, MAX_RST
                        ),
                    );
                }
            }
            InjectionDecision::Allow => {
                let pkt = build_inbound_rst(&cand.params);
                let addr = make_send_address_ifidx(cand.ifidx);
                let reason_text = match cand.reason {
                    "handshake" => "рукопожатие без ответа",
                    _ => "поток замер посреди данных",
                };
                match rt.handle.send_packet(&pkt, &addr) {
                    Ok(()) => {
                        rt.ledger.note_injected(lite, now);
                        app_log(
                            app,
                            format!(
                                "[Реаниматор] сброшен зависший поток {}:{} ({}): причина — {}, {:?} назад, дупретранс {}",
                                cand.params.server_ip,
                                cand.params.server_port,
                                cand.host,
                                reason_text,
                                cand.silence,
                                cand.retx_n
                            ),
                        );
                    }
                    Err(e) => {
                        app_log(app, format!("[Реаниматор] ошибка отправки RST: {}", e));
                    }
                }
            }
        }
    }

    /// Факт успеха: новый поток к googlevideo (TCP ClientHello или QUIC
    /// Initial) в окне SUCCESS_WINDOW после инжекции → «реанимировано».
    fn reanim_note_new_flow(&mut self, app: &AppHandle, lite: FlowKeyLite) {
        let Some(rt) = self.reanim.as_mut() else { return };
        if rt.ledger.note_new_handshake(&lite, Instant::now()) {
            app_log(
                app,
                "[Реаниматор] подтверждено: плеер открыл новый поток к googlevideo — видео должно ожить"
                    .to_string(),
            );
        }
    }

    /// Периодическая свипка реаниматора (каждые 512 пакетов): истечение
    /// pending без подтверждения + строка отчёта о транспорте (M2).
    fn reanim_sweep(&mut self, app: &AppHandle, now: Instant) {
        let Some(rt) = self.reanim.as_mut() else { return };
        if let Some(expired) = rt.ledger.expire_pending(now) {
            app_log(
                app,
                format!(
                    "[Реаниматор] не подтвердилось: новый поток к googlevideo не появился за {} с (инжекция {})",
                    SUCCESS_WINDOW.as_secs(),
                    expired.remote_ip
                ),
            );
        }

        // М4: зависшие QUIC-потоки к googlevideo — медиа-данных (пакеты
        // ≥ QUIC_DATA_MIN) нет ≥ QUIC_SILENCE_T, исходящие полноразмерные
        // ретраи свежие → карантин: capture-хендл изымает пакеты ОБЕИХ
        // направлений 5-tuple на QUARANTINE_T → Chrome не видит ни одного
        // пакета → QUIC idle-timeout (согласованный ~30 с) → Chrome сам
        // закрывает соединение и ретраит на новом порту (Initial с фейком
        // winws проходит — доказано) → видео оживает. Подделки пакетов мертвы:
        // ICMP Chrome глотает (SIO_UDP_CONNRESET), VN отбрасывает
        // (RFC 9000 §17.2.1), остальное зашифровано — тишина единственный
        // честный внешний «убийца» установленного QUIC.
        rt.stall.maintain(now);
        // Просроченные карантины снимаются: закрытие хендла (Drop) завершает
        // recv-цикл треда, пакеты флоу снова идут в стек.
        let expired: Vec<FlowKeyLite> = rt
            .quarantines
            .iter()
            .filter_map(|(k, (_, deadline))| (*deadline <= now).then_some(*k))
            .collect();
        for lite in expired {
            if let Some((qh, _)) = rt.quarantines.remove(&lite) {
                drop(qh); // WinDivertClose → blocked recv треда выйдет
                app_log(
                    app,
                    format!(
                        "[Реаниматор] карантин {}:{} снят — поток отпущен, исходное соединение Chrome уже переоткрыл",
                        lite.remote_ip,
                        lite.local_port
                    ),
                );
            }
        }
        let cands = rt.stall.candidates(now);
        if !cands.is_empty() {
            // Деструктуризация: заимствования раздельных полей рантайма.
            let ReanimRuntime { ledger, quarantines, limit_logged, .. } = rt;
            for (key, _st) in cands {
                let IpAddr::V4(server_v4) = key.remote_ip else { continue };
                let lite = FlowKeyLite {
                    remote_ip: server_v4,
                    remote_port: key.remote_port,
                    local_port: key.local_port,
                };
                if quarantines.contains_key(&lite) {
                    continue; // уже гасим этот флоу — ждём idle-timeout Chrome
                }
                if quarantines.len() >= QUAR_MAX_CONCURRENT {
                    if limit_logged.insert(lite) {
                        app_log(
                            app,
                            format!(
                                "[Реаниматор] {}:{} — слоты карантина заняты (максимум {}), отложено до освобождения",
                                server_v4, key.remote_port, QUAR_MAX_CONCURRENT
                            ),
                        );
                    }
                    continue;
                }
                match ledger.decide_with(&lite, now, QUAR_COOLDOWN_T, MAX_QUAR) {
                    InjectionDecision::Cooldown => {} // недавно уже гасили — тишина
                    InjectionDecision::Limit => {
                        if limit_logged.insert(lite) {
                            app_log(
                                app,
                                format!(
                                    "[Реаниматор] не реанимировалось: {}:{} — лимит {} карантинов на флоу исчерпан",
                                    server_v4, key.remote_port, MAX_QUAR
                                ),
                            );
                        }
                    }
                    InjectionDecision::Allow => {
                        let filter = quarantine_filter(server_v4, key.local_port);
                        match open_capture_handle(&filter) {
                            Ok(qh) => {
                                spawn_quarantine_thread(qh.raw());
                                quarantines.insert(lite, (qh, now + QUARANTINE_T));
                                ledger.note_injected(lite, now);
                                app_log(
                                    app,
                                    format!(
                                        "[Реаниматор] карантин зависшего QUIC-потока {}:{}: медиа-данных нет {} с, исходящие ретраи есть → гашу оба направления на {} с — Chrome сам переоткроет соединение (idle-timeout)",
                                        server_v4,
                                        key.remote_port,
                                        QUIC_SILENCE_T.as_secs(),
                                        QUARANTINE_T.as_secs()
                                    ),
                                );
                            }
                            Err(e) => {
                                app_log(
                                    app,
                                    format!(
                                        "[Реаниматор] ошибка открытия capture-хендла для {}:{}: {}",
                                        server_v4, key.remote_port, e
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
        match rt.last_stats_flush {
            None => rt.last_stats_flush = Some(now),
            Some(t) if now.duration_since(t) >= STATS_WINDOW => {
                rt.last_stats_flush = Some(now);
                app_log(
                    app,
                    format!(
                        "[Реаниматор] транспорт видео за 5 мин: ClientHello TCP:443 — {}, новых QUIC-потоков — {}, инжекций всего (RST + карантин) — {}",
                        rt.gc_ch_tcp,
                        rt.gc_quic,
                        rt.ledger.total_injections()
                    ),
                );
                rt.gc_ch_tcp = 0;
                rt.gc_quic = 0;
            }
            Some(_) => {}
        }
    }
}

/// М4: фильтр карантина на полный 5-tuple (оба направления флоу). Порт сервера
/// всегда 443 (ветка трекера гейтится на remote_port == 443), локальный — от
/// флоу. Capture-хендл с этим фильтром изымает совпавшие пакеты из стека.
fn quarantine_filter(server_ip: Ipv4Addr, local_port: u16) -> String {
    format!(
        "(outbound and ip.DstAddr == {ip} and udp.DstPort == 443 and udp.SrcPort == {lp}) or \
         (inbound and ip.SrcAddr == {ip} and udp.SrcPort == 443 and udp.DstPort == {lp})",
        ip = server_ip,
        lp = local_port
    )
}

/// М4: тред карантина — recv-цикл на capture-хендле. Полученный пакет НЕ
/// реинжектится = изъятие (дроп): Chrome не видит ни одного пакета флоу.
/// Завершение — по закрытию хендла родителем (WinDivertClose при Drop → recv
/// вернёт Err) — официальный механизм остановки recv-потока WinDivert 2.x.
fn spawn_quarantine_thread(raw: *mut std::ffi::c_void) {
    // Raw pointer не Send — переносим хендл как usize (WinDivert допускает
    // использование/закрытие хендла из других потоков, доки 2.x).
    let raw_addr = raw as usize;
    let _ = std::thread::Builder::new()
        .name("quarantine".into())
        .spawn(move || {
            let raw = raw_addr as *mut std::ffi::c_void;
            let mut buf = vec![0u8; MAX_PACKET_LEN];
            let mut addr = unsafe { std::mem::zeroed::<WinDivertAddress>() };
            while crate::win_divert::recv_raw_packet(raw, &mut buf, &mut addr).is_ok() {
                // Пакет изъят и отброшен сознательно: не send'им его обратно.
            }
        });
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

    // Шлюз периодики — общий для TCP и UDP (М4): UDP-трафик видео обязан
    // питать свипку реаниматора. До правки UDP-ветка выходила ДО шлюза —
    // при QUIC-просмотре свипка голодала (тест юзера: 1 прогон за 9 мин).
    ctx.packets_since_maintain += 1;
    if ctx.packets_since_maintain >= 512 {
        ctx.packets_since_maintain = 0;
        let now = Instant::now();
        ctx.tracker.maintain(now);
        ctx.quic.maintain(now);
        ctx.reanim_sweep(app, now);
    }

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

    // Исходящий (клиент → сервер): собираем ClientHello и считаем ретрансы.
    if outbound {
        let reanim_on = ctx.reanim.is_some();
        if t.payload.is_empty() {
            // Реаниматору нужен bare-ACK: ACK-поле = RCV.NXT (SEQ для RST).
            if reanim_on {
                let st = ctx.tracker.get_or_create(key.clone());
                st.note_outgoing_meta(t.src_ip, t.seq, t.ack, t.flags, 0, addr);
            }
            return;
        }
        if ctx.fakes.is_fake_payload(t.payload) {
            // Подставной пакет winws — детектору не сигнал: фейки идут по 8–11
            // копий с SNI из файла-фейка и без фильтра считались ретрансмиссиями
            // и лочили SNI-коллектор (фантомы onetrust/google, инцидент 27.10.26).
            return;
        }
        let mut cand: Option<ReanimCandidate> = None;
        let mut gv_new_flow = false;
        {
            let state = ctx.tracker.get_or_create(key.clone());
            if reanim_on {
                state.note_outgoing_meta(t.src_ip, t.seq, t.ack, t.flags, t.payload.len(), addr);
            }
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
            let hostname_was = state.hostname.is_some();
            let event = state.record_outgoing(t.seq, t.payload);
            let proc_name = state.proc.clone();
            let proc_path = state.proc_path.clone();
            if reanim_on {
                // M1/M2: новый ClientHello к googlevideo — счётчик транспорта
                // + потенциальное подтверждение реанимации.
                gv_new_flow = !hostname_was
                    && state.hostname.as_ref().is_some_and(|h| is_googlevideo(h));
                cand = state.reanim_stall_check(&key, Instant::now());
            }
            if let Some((reason, domain)) = event {
                ctx.emit(app, domain, reason, remote_ip, remote_port, proc_name, proc_path, "tls");
            }
        }
        if gv_new_flow {
            if let Some(rt) = ctx.reanim.as_mut() {
                rt.gc_ch_tcp += 1;
            }
            if let Some(lite) =
                flow_key_lite_parts(remote_ip, remote_port, local_port)
            {
                ctx.reanim_note_new_flow(app, lite);
            }
        }
        if let Some(c) = cand {
            ctx.reanim_inject(app, &key, c);
        }
        return;
    }

    // Входящий: RST (главный сигнал), FIN (гашение состояния) и DATA (живость).
    if t.flags & FLAG_RST != 0 {
        if addr.is_impostor() {
            // Это НАША инжекция RST, вернувшаяся через сниффер: поток умирает —
            // гасим состояние молча (фантомное «RST от сервера» в UI не пишем).
            ctx.tracker.flows.remove(&key);
            return;
        }
        if let Some(mut state) = ctx.tracker.flows.remove(&key) {
            let proc_name = state.proc.clone();
            let proc_path = state.proc_path.clone();
            state.maintenance(Instant::now());
            // Сервер сам закрыл поток — ожидание подтверждения реанимации
            // этого ключа теряет смысл.
            if let Some(rt) = ctx.reanim.as_mut() {
                if let Some(lite) =
                    flow_key_lite_parts(remote_ip, remote_port, local_port)
                {
                    rt.ledger.cancel_pending_on_server_rst(&lite);
                }
            }
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
        if let Some(rt) = ctx.reanim.as_mut() {
            if let Some(lite) = flow_key_lite_parts(remote_ip, remote_port, local_port) {
                rt.ledger.cancel_pending_on_server_rst(&lite);
            }
        }
    } else if !t.payload.is_empty() {
        // Входящие DATA: путь жив — guard честности реаниматора (ServerHello
        // пришёл: кейс «висящее рукопожатие» на этот поток не действует).
        // Только при включённом реаниматоре — поведение детектора не меняется.
        if ctx.reanim.is_some() {
            let st = ctx.tracker.get_or_create(key.clone());
            st.saw_inbound_data = true;
            st.last_inbound_data = Some(Instant::now());
            st.last_seen = Instant::now(); // живой поток — TTL не рвёт
        }
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
        // М4: сервер ответил — QUIC-поток жив. В счёт «данных» идёт только
        // полноразмерный пакет (≥ QUIC_DATA_MIN): ACK-мелочь ходит и по
        // мёртвому потоку, ей стол не опровергнуть.
        if remote_port == 443 {
            if let Some(rt) = ctx.reanim.as_mut() {
                rt.stall.note_inbound(
                    remote_ip,
                    remote_port,
                    local_port,
                    bytes.len(),
                    Instant::now(),
                );
            }
        }
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

    // М4: исходящий пакет UDP:443 — живость ИСХОДЯЩИХ ДАННЫХ (полноразмерный
    // пакет = запрос/ретрансмит незаэкношенного стрима; ACK-мелочь не считается).
    if remote_port == 443 {
        if let Some(rt) = ctx.reanim.as_mut() {
            rt.stall.note_outbound(
                QuicStallKey { remote_ip, remote_port, local_port },
                bytes,
                Instant::now(),
            );
        }
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
    let hostname_was = state.hostname.is_some();
    let proc_name = state.proc.clone();
    let proc_path = state.proc_path.clone();
    let event = state.note_initial(parsed);
    // M1/M2: новый QUIC-поток к googlevideo — счётчик транспорта + факт успеха
    // реанимации (Chrome ретраит видео по QUIC после нашего RST на TCP-фолбэк).
    let gv_new_flow = ctx.reanim.is_some()
        && !hostname_was
        && state.hostname.as_deref().is_some_and(|h| is_googlevideo(h));
    if let Some(domain) = event {
        ctx.emit(app, domain, "quic", remote_ip, remote_port, proc_name, proc_path, "quic");
    }
    if gv_new_flow {
        if let Some(rt) = ctx.reanim.as_mut() {
            rt.gc_quic += 1;
            // М3: поток подтверждён SNI googlevideo — кандидат на ICMP-реанимацию.
            rt.stall.mark_gv(remote_ip, remote_port, local_port);
        }
        if let Some(lite) = flow_key_lite_parts(remote_ip, remote_port, local_port) {
            ctx.reanim_note_new_flow(app, lite);
        }
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

    // Реаниматор (PRP 10.11.26): send-хендл SNIFF|SEND_ONLY. Фильтр тот же
    // (tcp/udp src/dst 443) — инжектируемый RST (src=сервер:443) под него
    // подпадает по построению. Ошибка открытия не валит монитор: детектор
    // продолжает работать, реаниматор честно сообщает о неготовности.
    let reanim_handle = if read_reanim_mode() {
        match open_send_handle(sniff_filter()) {
            Ok(h) => Some(h),
            Err(e) => {
                app_log(
                    &app,
                    format!("[Реаниматор] НЕ активен — хендл инжекции не открылся: {}", e),
                );
                None
            }
        }
    } else {
        app_log(&app, "[Реаниматор] выключен (media_reanim_mode = off)");
        None
    };

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
            worker(app_thread, handle, stop_thread, lists, fakes, reanim_handle);
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
    reanim_handle: Option<SendHandle>,
) {
    let reanim = reanim_handle.map(|h| ReanimRuntime {
        handle: h,
        ledger: ReanimLedger::new(),
        limit_logged: HashSet::new(),
        gc_ch_tcp: 0,
        gc_quic: 0,
        last_stats_flush: None,
        stall: QuicStallTracker::new(),
        quarantines: HashMap::new(),
    });
    let mut ctx = WorkerCtx {
        tracker: FlowTracker::new(fakes.clone()),
        quic: QuicTracker::new(),
        dedup: Dedupe::new(),
        rate: RateLimiter::new(),
        lists,
        fakes,
        no_domain_count: 0,
        ipv6_warned: false,
        packets_since_maintain: 0,
        reanim,
    };
    if ctx.reanim.is_some() {
        app_log(
            &app,
            format!(
                "[Реаниматор] активен: рукопожатие без ответа {} с / тишина {} с → RST; карантин QUIC-стола: медиа-данных нет {} с → гашу поток на {} с (Chrome переоткроет сам)",
                HANDSHAKE_T.as_secs(),
                SILENCE_T.as_secs(),
                QUIC_SILENCE_T.as_secs(),
                QUARANTINE_T.as_secs()
            ),
        );
    }
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

    // --- QuicStallTracker (М4: детект по медиа-данным ≥ QUIC_DATA_MIN) ------
    #[test]
    fn quic_stall_candidate_requires_gv_and_data_direction() {
        let key = QuicStallKey {
            remote_ip: IpAddr::V4(Ipv4Addr::new(173, 194, 160, 161)),
            remote_port: 443,
            local_port: 51000,
        };
        let data_pkt = [0u8; 1200]; // ≥ QUIC_DATA_MIN — «медиа-данные»
        let small_pkt = [0u8; 80]; // ACK/PING-мелочь — «данные» не считается
        let t0 = Instant::now();

        // 1) Только мелочь в обе стороны — «входящие данные» не обновлялись
        //    вовсе (li = None) → кандидата нет (PING-idle не реанимируем).
        let mut tr = QuicStallTracker::new();
        tr.note_outbound(key.clone(), &small_pkt, t0);
        tr.note_inbound(key.remote_ip, key.remote_port, key.local_port, small_pkt.len(), t0);
        tr.mark_gv(key.remote_ip, key.remote_port, key.local_port);
        assert!(tr.candidates(t0 + Duration::from_secs(30)).is_empty());

        // 2) Обмен полноразмерными: out t0, in t0 → lo == li → не кандидат
        //    (застопорило сразу после ответа — исходящих ретраев ещё нет).
        let mut tr = QuicStallTracker::new();
        tr.note_outbound(key.clone(), &data_pkt, t0);
        tr.note_inbound(key.remote_ip, key.remote_port, key.local_port, data_pkt.len(), t0);
        tr.mark_gv(key.remote_ip, key.remote_port, key.local_port);
        assert!(tr.candidates(t0 + Duration::from_secs(12)).is_empty());

        // 3) Стол: сервер замолчал после t0, клиент ретрансммитит
        //    полноразмерные через 1 с → кандидат на t12 (молчание 12 с).
        tr.note_outbound(key.clone(), &data_pkt, t0 + Duration::from_secs(1));
        let cands = tr.candidates(t0 + Duration::from_secs(12));
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].0.local_port, 51000);

        // ACK-мелочь от сервера НЕ освежает «входящие данные» (ACK ходит и по
        // мёртвому потоку) — кандидат остаётся.
        tr.note_inbound(key.remote_ip, key.remote_port, key.local_port, small_pkt.len(), t0 + Duration::from_secs(3));
        assert!(!tr.candidates(t0 + Duration::from_secs(12)).is_empty());

        // Ретраи старше QUIC_RETRANS_FRESH_T → не кандидат (Chrome сдался
        // или поток жив в idle — карантин не нужен).
        assert!(tr.candidates(t0 + Duration::from_secs(17)).is_empty());

        // 4) Пауза ролика: сервер ответил ПОСЛЕ последнего исходящего
        //    (li > lo) → не кандидат.
        let mut tr = QuicStallTracker::new();
        tr.note_outbound(key.clone(), &data_pkt, t0);
        tr.note_inbound(key.remote_ip, key.remote_port, key.local_port, data_pkt.len(), t0 + Duration::from_secs(2));
        tr.mark_gv(key.remote_ip, key.remote_port, key.local_port);
        assert!(tr.candidates(t0 + Duration::from_secs(20)).is_empty());

        // 5) Не-googlevideo — не кандидат никогда (51000 не помечен, 51001
        //    помечен по чужому IP).
        let mut tr = QuicStallTracker::new();
        tr.note_outbound(key.clone(), &data_pkt, t0);
        tr.mark_gv(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443, 51001);
        tr.note_outbound(
            QuicStallKey {
                remote_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                remote_port: 443,
                local_port: 51001,
            },
            &data_pkt,
            t0,
        );
        assert!(tr.candidates(t0 + Duration::from_secs(30)).is_empty());
    }

    // --- parse_client_hello ------------------------------------------------
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
        let mut st = FlowState::new(Arc::new(FakeBlobs::from_winws_args(&[]).0));
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
        let mut st = FlowState::new(Arc::new(FakeBlobs::from_winws_args(&[]).0));
        let payload = vec![1u8, 2, 3, 4];
        for _ in 0..3 {
            st.record_outgoing(0, &payload);
        }
        assert!(st.record_outgoing(0, &payload).is_none(), "без домена событие НЕ отдали");
    }

    // --- Hostfakesplit: слепота Реаниматора (кейс yt-dlp 11.11.26) -----------
    // Провод hostfakesplit (zapret desync.c): слот хоста ClientHello пишется
    // ТРИ раза — fake_host, real_host, fake_host(второй, altorder=0). Фейк-хост
    // = случайные [a-z0-9] + "." + хост из --dpi-desync-hostfakesplit-mod —
    // ВАЛИДНЫЙ hostname, is_googlevideo = false. Сборка завершается на
    // after_host, когда в слоте последний ФЕЙК → done лочился фейком →
    // Реаниматор слеп (прод: ClientHello TCP:443 — 0 во всех строках
    // статистики). Реальный хост обязан восстанавливаться из конфликтных
    // перезаписей слота.
    const HS_POS: usize = 58; // rec5+hs4+ver2+rand32+sid1+ciphers2+comps1+extlen2+type2+len2+list2+nametype1+hostlen2

    /// ClientHello с хвостовым расширением (как у реальных) — чтобы
    /// after_host-часть была непустой и сборка завершалась на after_host.
    fn ch_with_tail(host: &[u8]) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend(((host.len() as u32 + 3) as u16).to_be_bytes());
        sni.push(0u8); // name_type
        sni.extend((host.len() as u16).to_be_bytes());
        sni.extend(host);

        let mut ext = Vec::new();
        ext.extend(0x0000u16.to_be_bytes()); // server_name
        ext.extend((sni.len() as u16).to_be_bytes());
        ext.extend(&sni);
        // Хвост после хоста: ec_point_formats-заглушка (6 байт).
        ext.extend(0x000bu16.to_be_bytes());
        ext.extend(2u16.to_be_bytes());
        ext.extend([0x01u8, 0x00]);

        let mut body = Vec::new();
        body.extend([3u8, 3]); // версия TLS1.2
        body.extend([0u8; 32]); // random
        body.push(0u8); // session_id len=0
        body.extend(0u16.to_be_bytes()); // ciphers len=0
        body.push(0u8); // comps len=0
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(&ext);

        let mut hs = Vec::new();
        hs.push(0x01u8);
        hs.push((body.len() >> 16) as u8);
        hs.push((body.len() >> 8) as u8);
        hs.push(body.len() as u8);
        hs.extend(&body);

        let mut rec = Vec::new();
        rec.push(0x16u8);
        rec.extend([3u8, 1]);
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    /// FlowState с фейк-конфигом всех hostfakesplit-групп ALT13 (как в
    /// final_args прода: группа 4 без altorder + группы 5-7 с altorder=1).
    fn hostfakesplit_state() -> FlowState {
        let (fakes, warns) = FakeBlobs::from_winws_args(&[
            "--dpi-desync-hostfakesplit-mod=host=www.google.com".to_string(),
            "--dpi-desync-hostfakesplit-mod=host=mail.ru,altorder=1".to_string(),
        ]);
        assert!(warns.is_empty());
        FlowState::new(Arc::new(fakes))
    }

    /// Провод altorder=0 (группа 4: googlevideo): before, fake, real, fake, after.
    #[test]
    fn hostfakesplit_altorder0_recovers_real_host() {
        let mut st = hostfakesplit_state();
        let host = b"rr3---sn-ixh7yn7e.googlevideo.com";
        let ch = ch_with_tail(host);
        assert_eq!(&ch[HS_POS..HS_POS + host.len()], &host[..], "хост-слот по фикс. смещению");
        // Фейк-хост zapret: 18 случайных [a-z0-9] + "." + "www.google.com" (=33).
        let fake1 = b"q7x2m9w4z1n5v8c3pd.www.google.com";
        let fake2 = b"k1p6t3y8r5h2j7s4f0.www.google.com";
        assert_eq!(fake1.len(), host.len());
        st.record_outgoing(1000, &ch[..HS_POS]);
        st.record_outgoing(1058, fake1);
        st.record_outgoing(1058, &ch[HS_POS..HS_POS + host.len()]);
        st.record_outgoing(1058, fake2);
        st.record_outgoing(1091, &ch[HS_POS + host.len()..]);
        assert_eq!(
            st.hostname.as_deref(),
            Some("rr3---sn-ixh7yn7e.googlevideo.com"),
            "реальный хост обязан восстановиться из перезаписей слота"
        );
    }

    /// Провод altorder=1 (группы 5-7, mail.ru): before, fake, after, real —
    /// сборка завершается на фейке ДО прихода реального хоста.
    #[test]
    fn hostfakesplit_altorder1_recovers_real_host() {
        let mut st = hostfakesplit_state();
        let host = b"rr3---sn-ixh7yn7e.googlevideo.com";
        let ch = ch_with_tail(host);
        // Фейк zapret для mail.ru: 25 случайных + "." + "mail.ru" (=33).
        let fake = b"qq22xx44zz66ww88yy00aa11b.mail.ru";
        assert_eq!(fake.len(), host.len());
        st.record_outgoing(1000, &ch[..HS_POS]);
        st.record_outgoing(1058, fake);
        st.record_outgoing(1091, &ch[HS_POS + host.len()..]);
        st.record_outgoing(1058, &ch[HS_POS..HS_POS + host.len()]);
        assert_eq!(
            st.hostname.as_deref(),
            Some("rr3---sn-ixh7yn7e.googlevideo.com"),
            "реальный хост приходит последним — обязан перезаписать фейк"
        );
    }

    /// Чистый флоу без конфига фейков: старое поведение — первый распарсенный
    /// hostname; идентичные ретрансы альтернатив не создают и не ломают.
    #[test]
    fn plain_flow_and_identical_retrans() {
        let mut st = FlowState::new(Arc::new(FakeBlobs::from_winws_args(&[]).0));
        let host = b"example.org";
        let ch = ch_with_tail(host);
        st.record_outgoing(2000, &ch[..HS_POS]);
        // Идентичный ретранс ДО завершения сборки — конфликт не регистрируется.
        st.record_outgoing(2000, &ch[..HS_POS]);
        st.record_outgoing((2000 + HS_POS) as u32, &ch[HS_POS..]);
        assert_eq!(
            st.hostname.as_deref(),
            Some("example.org"),
            "чистый флоу лочит первый распарсенный hostname"
        );
        assert!(st.sni.alternates.is_empty(), "идентичные байты — не конфликт");
        // Ретранс после лочения — hostname не меняется.
        st.record_outgoing(2000, &ch[..HS_POS]);
        assert_eq!(st.hostname.as_deref(), Some("example.org"));
    }

    /// Конечная цель фикса: после провода hostfakesplit reanim_stall_check
    /// видит googlevideo-флоу и отдаёт кандидата (кейс 1 — рукопожатие).
    #[test]
    fn stall_check_fires_after_hostfakesplit_recovery() {
        let mut st = hostfakesplit_state();
        let host = b"rr3---sn-ixh7yn7e.googlevideo.com";
        let ch = ch_with_tail(host);
        let fake1 = b"q7x2m9w4z1n5v8c3pd.www.google.com";
        st.record_outgoing(1000, &ch[..HS_POS]);
        st.record_outgoing(1058, fake1);
        st.record_outgoing(1058, &ch[HS_POS..HS_POS + host.len()]);
        st.record_outgoing(1091, &ch[HS_POS + host.len()..]);
        assert_eq!(st.hostname.as_deref(), Some("rr3---sn-ixh7yn7e.googlevideo.com"));

        let t0 = Instant::now() - Duration::from_secs(6);
        st.first_out_at = Some(t0);
        st.client_ip = Some(Ipv4Addr::new(192, 168, 1, 5));
        st.rcv_nxt = Some(5000);
        st.snd_nxt = Some(1234);
        let key = FlowKey {
            remote_ip: IpAddr::V4(Ipv4Addr::new(74, 125, 104, 232)),
            remote_port: 443,
            local_port: 51000,
        };
        let cand = st
            .reanim_stall_check(&key, Instant::now())
            .expect("после восстановления хоста флоу обязан попасть в кандидаты");
        assert_eq!(cand.host, "rr3---sn-ixh7yn7e.googlevideo.com");
        assert_eq!(cand.reason, "handshake");
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
