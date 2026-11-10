//! Тонкая FFI-обёртка над WinDivert.dll 2.2 — строго сниффер-режим (детектор блокировок).
//!
//! Контракт, подтверждённый официальной документацией WinDivert 2.2
//! (https://github.com/basil00/WinDivert, doc/windivert.html + include/windivert.h):
//! - `WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_LOWEST, flags)`
//!   открывается с маской флагов `SNIFF | RECV_ONLY`:
//!   * SNIFF: «original packet is not dropped-and-diverted (the default) but
//!     copied-and-diverted» — пакет НЕ изымается из стека, наш хендл получает копию и
//!     физически не может повлиять на трафик/обход (применение дока прямо приводит как
//!     режим для WinPcap-подобных снифферов);
//!   * RECV_ONLY: «effectively disables WinDivertSend()» — инжекция пакетов от имени
//!     процесса в принципе невозможна.
//!   Приоритет `-30000` (WINDIVERT_PRIORITY_LOWEST, header 2.x строки 315-316): nfqws
//!   открывает свои хендлы с жёстким приоритетом 0 (zapret nfq/darkmagic.c:1438), наш
//!   уровнь ни с чем не совпадает — правило «packet is only diverted once per priority
//!   level» повреждения не создаёт.
//! - Остановка чтения — ОФИЦИАЛЬНАЯ: `WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV)`;
//!   при пустой очереди `WinDivertRecv` завершится ошибкой ERROR_NO_DATA (232).
//! - Экспорт WinDivert: `extern __declspec(dllimport)` → конвенция cdecl (Rust: `extern "C"`).
//! - DLL грузится динамически из bin рядом с экзешником (тот же bin, что и для
//!   winws.exe — AGENTS.md §4.1); AppData тут ни при чём — DLL не «данные пользователя».

use std::ffi::{c_char, c_void, CString};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Константы API (include/windivert.h 2.x, сверено) — именованные, менять запрещено:
// маска SNIFF|RECV_ONLY + приоритет LOWEST = контракт «сниффер не влияет на трафик».
// ---------------------------------------------------------------------------

/// `WINDIVERT_LAYER_NETWORK = 0` (пакеты к/от локальной машины).
pub const LAYER_NETWORK: i32 = 0;

/// `WINDIVERT_FLAG_SNIFF = 0x0001` | `WINDIVERT_FLAG_RECV_ONLY = 0x0004` (READ_ONLY).
pub const SNIFF_FLAGS: u64 = 0x0001 | 0x0004;

/// `WINDIVERT_FLAG_SNIFF = 0x0001` | `WINDIVERT_FLAG_SEND_ONLY = 0x0008`.
/// SNIFF оставляет легитимный трафик стеку (копия, не изъятие); SEND_ONLY
/// запрещает Recv — хендл умеет только WinDivertSend (реаниматор инжектит RST).
pub const SEND_FLAGS: u64 = 0x0001 | 0x0008;

/// `WINDIVERT_PRIORITY_LOWEST = -30000` (header 2.x: `-WINDIVERT_PRIORITY_HIGHEST`).
pub const SNIFF_PRIORITY: i16 = -30000;

/// Флаги capture-хендла карантина (М4): 0 = ни SNIFF (пакет ИЗЫМАЕТСЯ из
/// стека, а не копируется), ни SEND_ONLY (Recv разрешён). Дока WinDivert 2.x:
/// полученный пакет, который хендл не реинжектировал, отбрасывается — это и
/// есть механизм карантина (глушение обоих направлений зависшего флоу).
pub const CAPTURE_FLAGS: u64 = 0;

/// `WINDIVERT_PRIORITY_HIGHEST = 30000`: capture-хендл карантина обязан
/// увидеть пакет РАНЬШЕ снифферов (иначе изъятие будет неполным).
pub const CAPTURE_PRIORITY: i16 = 30000;

/// `WINDIVERT_SHUTDOWN_RECV = 0x1` — штатная остановка очереди читающего потока.
pub const SHUTDOWN_RECV: u32 = 0x1;

/// Максимальный размер пакета для Recv-буфера (дока: uint16-размер буфера).
pub const MAX_PACKET_LEN: usize = 0xFFFF;

/// `INVALID_HANDLE_VALUE` в WinAPI = `(HANDLE)-1`.
const INVALID_HANDLE_VALUE: isize = -1;

// ---------------------------------------------------------------------------
// WINDIVERT_ADDRESS — точный C-макет (header 2.2, строки 141-164):
//   INT64 Timestamp;
//   UINT32 bitfield { Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1,
//                     Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1,
//                     UDPChecksum:1, Reserved1:8 };
//   UINT32 Reserved2;
//   union { ... } ;        // максимальный размер 64 байта (Reserved3[64])
// Итого: 8 + 4 + 4 + 64 = 80 байт, выравнивание 8 (assert в тестах).
// Битовые поля читаем операциями над u32, а не C-битфилдами, чтобы не зависеть
// от поведения компилятора C — раскладка MSVC однозначна (LSB → старшие поля).
// ---------------------------------------------------------------------------
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    /// Упакованные битовые поля (см. над заголовком структуры).
    pub bitfields: u32,
    pub reserved2: u32,
    /// Сырые данные union: для NETWORK-слоя — `IfIdx(u32)` в байтах 0..4 и
    /// `SubIfIdx(u32)` в байтах 4..8 (LE). Детектор эти поля не использует.
    pub union_data: [u8; 64],
}

// Геттеры-битфилды — контрактная документация структуры; вне тестов детектор
// пользуется только is_outbound/is_loopback/is_ipv6. #[allow] — не суррогат:
// геттеры реально проверяются юнит-тестом bitfield_extraction.
#[allow(dead_code)]
impl WinDivertAddress {
    /// Поле Layer (биты 0..=7).
    pub fn layer(&self) -> u32 {
        self.bitfields & 0xFF
    }
    /// Поле Event (биты 8..=15).
    pub fn event(&self) -> u32 {
        (self.bitfields >> 8) & 0xFF
    }
    /// Sniffed (бит 16).
    pub fn is_sniffed(&self) -> bool {
        self.bitfields & (1 << 16) != 0
    }
    /// Outbound (бит 17): пакет летит наружу (клиент → сервер)?
    pub fn is_outbound(&self) -> bool {
        self.bitfields & (1 << 17) != 0
    }
    /// Loopback (бит 18): локальный трафик (если true — детектор пакет пропускает).
    pub fn is_loopback(&self) -> bool {
        self.bitfields & (1 << 18) != 0
    }
    /// IPv6 (бит 20).
    pub fn is_ipv6(&self) -> bool {
        self.bitfields & (1 << 20) != 0
    }
    /// Impostor (бит 19): пакет был заинжекчен через WinDivertSend другим
    /// хендлом/процессом (наша инжекция RST видна снифферу с этим битом).
    pub fn is_impostor(&self) -> bool {
        self.bitfields & (1 << 19) != 0
    }
}

// ---------------------------------------------------------------------------
// Ошибки: честный код + человекочитаемое описание по документации 5.4/5.6.
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct WinDivertError {
    pub code: u32,
    pub detail: String,
}

impl fmt::Display for WinDivertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let meaning = error_meaning(self.code);
        write!(f, "{} (код {})", meaning, self.code)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

/// Человекочитаемое описание по разделам «Common errors» документации 5.4/5.6.
fn error_meaning(code: u32) -> &'static str {
    match code {
        2 => "WinDivert64.sys не найден (драйвер не установлен в комплект)",
        5 => "нет прав администратора (WinDivert требует elevated-процесс)",
        87 => "некорректный фильтр/layer/приоритет/flags (ERROR_INVALID_PARAMETER)",
        122 => "буфер меньше пакета (ERROR_INSUFFICIENT_BUFFER)",
        126 => "DLL или её зависимости не найдены по указанному пути (ERROR_MOD_NOT_FOUND)",
        232 => "хендл остановлен через WinDivertShutdown (ERROR_NO_DATA)",
        577 => "драйвер не имеет действующей цифровой подписи",
        654 => "загружена несовместимая версия драйвера WinDivert (ERROR_DRIVER_FAILED_PRIOR_UNLOAD)",
        1060 => "служба WinDivert не установлена (ERROR_SERVICE_DOES_NOT_EXIST)",
        _ => "см. документацию WinDivert (раздел WinDivertOpen, Common errors)",
    }
}

// ---------------------------------------------------------------------------
// Динамическая загрузка DLL. Статический #[link] не подходит: DLL лежит вне
// системных путей поиска. Используем LoadLibraryExW с LOAD_WITH_ALTERED_SEARCH_PATH.
// ---------------------------------------------------------------------------

type WinDivertOpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> *mut c_void;
type WinDivertRecvFn = unsafe extern "C" fn(
    *mut c_void,            // handle
    *mut u8,                // pPacket
    u32,                    // packetLen
    *mut u32,               // pRecvLen
    *mut WinDivertAddress,  // pAddr
) -> i32; // BOOL
type WinDivertShutdownFn = unsafe extern "C" fn(*mut c_void, u32) -> i32;
type WinDivertCloseFn = unsafe extern "C" fn(*mut c_void) -> i32;
type WinDivertSendFn = unsafe extern "C" fn(
    *mut c_void,                  // handle
    *const u8,                    // pPacket
    u32,                          // packetLen
    *const WinDivertAddress,      // pAddr
) -> i32; // BOOL

#[derive(Debug)]
pub struct Syms {
    // HMODULE сознательно НЕ храним: LoadLibrary увеличил refcount, FreeLibrary
    // никто не вызывает — DLL остаётся в памяти до конца процесса.
    open: WinDivertOpenFn,
    recv: WinDivertRecvFn,
    shutdown: WinDivertShutdownFn,
    close: WinDivertCloseFn,
    send: WinDivertSendFn,
}

impl Syms {
    /// Штатная остановка очереди чтения по сырому хендлу (вызывается ИЗ ДРУГОГО
    /// потока — хендл владеет рабочий поток, для него Recv вернёт ERROR_NO_DATA).
    pub fn shutdown_read(&self, handle: *mut c_void) -> bool {
        unsafe { (self.shutdown)(handle, SHUTDOWN_RECV) != 0 }
    }
}

/// Кеш: None — ещё не грузили, Some(Err(..)) — загрузить не вышло (честная причина).
static SYMS: Mutex<Option<Result<Syms, String>>> = Mutex::new(None);

const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

// kernel32 (линкуются неявно, без доп. фич windows-sys).
unsafe extern "C" {
    fn GetLastError() -> u32;
    /// Файл передаётся UTF-16 with NUL.
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

fn load_syms_from(dll_path: &Path) -> Result<Syms, String> {
    let path_str = dll_path.to_string_lossy().into_owned();
    let mut wide: Vec<u16> = path_str.encode_utf16().collect();
    wide.push(0);

    unsafe {
        let lib = LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH);
        if lib.is_null() || lib as isize == INVALID_HANDLE_VALUE {
            let code = GetLastError();
            return Err(format!(
                "не удалось загрузить «{}»: {}",
                path_str,
                WinDivertError { code, detail: String::new() }
            ));
        }

        macro_rules! proc {
            ($name:expr) => {{
                let sym = GetProcAddress(lib, concat!($name, "\0").as_ptr());
                if sym.is_null() {
                    return Err(format!(
                        "в «{}» отсутствует экспорт \"{}\" — нужна WinDivert.dll версии ≥ 2.2",
                        path_str, $name
                    ));
                }
                std::mem::transmute(sym)
            }};
        }

        let open: WinDivertOpenFn = proc!("WinDivertOpen");
        let recv: WinDivertRecvFn = proc!("WinDivertRecv");
        let shutdown: WinDivertShutdownFn = proc!("WinDivertShutdown");
        let close: WinDivertCloseFn = proc!("WinDivertClose");
        let send: WinDivertSendFn = proc!("WinDivertSend");

        Ok(Syms { open, recv, shutdown, close, send })
    }
}

/// Загружает (однократно) WinDivert.dll из bin рядом с экзешником — того же bin,
/// где живёт winws.exe (AGENTS.md §4.1). AppData тут ни при чём: get_app_dir —
/// каталог пользовательских данных (config.json, lists), DLL в нём не бывает
/// (именно из-за такого путаницы происходил код 126 из прошлого прогона).
pub fn get_sniff_syms() -> Result<&'static Syms, String> {
    let mut guard = SYMS.lock().expect("SYMS mutex poisoned");
    if guard.is_none() {
        let dll = crate::process::get_bin_dir()?.join("WinDivert.dll");
        *guard = Some(load_syms_from(&dll));
    }
    match guard.as_ref().expect("заполнен выше") {
        Ok(syms) => Ok(unsafe {
            // Приводим к 'static: Syms живёт в static-кеше до конца процесса.
            std::mem::transmute::<&Syms, &Syms>(syms)
        }),
        Err(e) => Err(e.clone()),
    }
}

/// Открытие сниффер-хендла по строке фильтра (язык фильтров WinDivert).
pub fn open_sniff_handle(filter: &str) -> Result<SniffHandle, WinDivertError> {
    let c_filter = CString::new(filter)
        .map_err(|_| WinDivertError { code: 87, detail: "в фильтре есть NUL-байт".into() })?;
    let syms = get_sniff_syms()
        .map_err(|detail| WinDivertError { code: 0, detail })?;
    let handle = unsafe { (syms.open)(c_filter.as_ptr(), LAYER_NETWORK, SNIFF_PRIORITY, SNIFF_FLAGS) };

    if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(WinDivertError {
            code,
            detail: format!("фильтры: «{}»", filter),
        });
    }
    Ok(SniffHandle { handle, close: syms.close })
}

/// Открытие send-хендла (реаниматор): flags `SNIFF|SEND_ONLY`, приоритет LOWEST.
/// Тот же контракт SNIFF (не изымает легитимный трафик), но Recv запрещён —
/// только инжекция через WinDivertSend.
pub fn open_send_handle(filter: &str) -> Result<SendHandle, WinDivertError> {
    let c_filter = CString::new(filter)
        .map_err(|_| WinDivertError { code: 87, detail: "в фильтре есть NUL-байт".into() })?;
    let syms = get_sniff_syms()
        .map_err(|detail| WinDivertError { code: 0, detail })?;
    let handle = unsafe { (syms.open)(c_filter.as_ptr(), LAYER_NETWORK, SNIFF_PRIORITY, SEND_FLAGS) };

    if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(WinDivertError {
            code,
            detail: format!("фильтры: «{}»", filter),
        });
    }
    Ok(SendHandle { handle, close: syms.close })
}

/// Открытие capture-хендла (карантин М4): flags 0 — пакет изымается из стека и
/// отбрасывается, если его не реинжектировать; приоритет HIGHEST — изъятие
/// раньше остальных хендлов.
pub fn open_capture_handle(filter: &str) -> Result<CaptureHandle, WinDivertError> {
    let c_filter = CString::new(filter)
        .map_err(|_| WinDivertError { code: 87, detail: "в фильтре есть NUL-байт".into() })?;
    let syms = get_sniff_syms()
        .map_err(|detail| WinDivertError { code: 0, detail })?;
    let handle = unsafe { (syms.open)(c_filter.as_ptr(), LAYER_NETWORK, CAPTURE_PRIORITY, CAPTURE_FLAGS) };

    if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(WinDivertError {
            code,
            detail: format!("фильтры: «{}»", filter),
        });
    }
    Ok(CaptureHandle { handle, close: syms.close })
}

/// RAII-хендл карантина (М4): recv-цикл треда глотает пакеты (не реинжектит),
/// закрытие из Drop снимает карантин — blocked recv треда вернёт ошибку и
/// тред завершится.
#[derive(Debug)]
pub struct CaptureHandle {
    handle: *mut c_void,
    close: WinDivertCloseFn,
}

unsafe impl Send for CaptureHandle {}

impl CaptureHandle {
    /// Сырой хендл для recv-треда карантина (владелец хендла — рантайм).
    pub fn raw(&self) -> *mut c_void {
        self.handle
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle as isize != INVALID_HANDLE_VALUE {
            unsafe { (self.close)(self.handle) };
        }
        self.handle = std::ptr::null_mut();
    }
}

/// RAII-хендл для инжекции пакетов (WinDivertSend). Drop — официальное close.
#[derive(Debug)]
pub struct SendHandle {
    handle: *mut c_void,
    close: WinDivertCloseFn,
}

unsafe impl Send for SendHandle {}

impl SendHandle {
    /// Инжектит готовый пакет (например, inbound RST реаниматора). Адрес
    /// (`WinDivertAddress`) несёт IfIdx/SubIfIdx + направление (inbound):
    /// реаниматор копирует их из последнего sniffed-адреса этого флоу.
    pub fn send_packet(
        &self,
        bytes: &[u8],
        addr: &WinDivertAddress,
    ) -> Result<(), WinDivertError> {
        if bytes.len() > MAX_PACKET_LEN {
            return Err(WinDivertError {
                code: 122,
                detail: format!("пакет {} байт больше лимита 0xFFFF", bytes.len()),
            });
        }
        let syms = get_sniff_syms()
            .map_err(|detail| WinDivertError { code: 0, detail })?;
        let ok = unsafe { (syms.send)(self.handle, bytes.as_ptr(), bytes.len() as u32, addr) };
        if ok != 0 {
            Ok(())
        } else {
            Err(WinDivertError {
                code: unsafe { GetLastError() },
                detail: String::new(),
            })
        }
    }
}

impl Drop for SendHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle as isize != INVALID_HANDLE_VALUE {
            unsafe { (self.close)(self.handle) };
        }
        self.handle = std::ptr::null_mut();
    }
}

/// RAII-хендл: Drop вызывает официальное WinDivertClose. `Send` — штатно для
/// WinDivert (хендл можно использовать/закрывать из других потоков — сам
/// WinDivertShutdown объявлен как механизм остановки из другого потока).
#[derive(Debug)]
pub struct SniffHandle {
    handle: *mut c_void,
    close: WinDivertCloseFn,
}

unsafe impl Send for SniffHandle {}

impl SniffHandle {
    /// Читает один пакет. Возвращает Ok(0) если хендл остановлен (shutdown) и
    /// очередь пуста — официальный сигнал завершения recv-потока.
    pub fn recv_packet(
        &self,
        buf: &mut [u8],
        addr: &mut WinDivertAddress,
    ) -> Result<usize, WinDivertError> {
        let syms = get_sniff_syms()
            .map_err(|detail| WinDivertError { code: 0, detail })?;
        if buf.len() > MAX_PACKET_LEN {
            return Err(WinDivertError {
                code: 122,
                detail: "буфер больше 0xFFFF — контракту драйвера не соответствует".into(),
            });
        }
        let mut recv_len: u32 = 0;
        let ok = unsafe { (syms.recv)(self.handle, buf.as_mut_ptr(), buf.len() as u32, &mut recv_len, addr) };
        if ok != 0 {
            Ok(recv_len as usize)
        } else {
            Err(WinDivertError {
                code: unsafe { GetLastError() },
                detail: String::new(),
            })
        }
    }

    /// Сырой хендл (нужен для WinDivertShutdown из владеющего state'а приложения).
    pub fn raw(&self) -> *mut c_void {
        self.handle
    }
}

/// Recv на СЫРОМ хендле (карантин М4): тред карантина держит только
/// `CaptureHandle::raw()` и читает через эту функцию — поля `Syms` закрыты.
/// При закрытии хендла владельцем (Drop) вернёт Err — штатное завершение
/// recv-цикла треда карантина.
pub fn recv_raw_packet(
    handle: *mut c_void,
    buf: &mut [u8],
    addr: &mut WinDivertAddress,
) -> Result<usize, WinDivertError> {
    let syms = get_sniff_syms()
        .map_err(|detail| WinDivertError { code: 0, detail })?;
    let mut recv_len: u32 = 0;
    let ok = unsafe { (syms.recv)(handle, buf.as_mut_ptr(), buf.len() as u32, &mut recv_len, addr) };
    if ok != 0 {
        Ok(recv_len as usize)
    } else {
        Err(WinDivertError {
            code: unsafe { GetLastError() },
            detail: String::new(),
        })
    }
}

impl Drop for SniffHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle as isize != INVALID_HANDLE_VALUE {
            unsafe { (self.close)(self.handle) };
        }
        self.handle = std::ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// Тесты без драйвера (правило PRP ШАГ 1).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout_matches_c_header() {
        // INT64(8) + UINT32(4) + UINT32(4) + union[64] = 80 байт при align 8.
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);
        assert_eq!(std::mem::align_of::<WinDivertAddress>(), 8);
    }

    // М4: capture-хендл карантина = ИЗЪЯТИЕ (flags 0) на приоритете HIGHEST.
    #[test]
    fn capture_flags_allow_recv_and_isolate() {
        assert_eq!(CAPTURE_FLAGS, 0);
        assert_eq!(CAPTURE_FLAGS & 0x0001, 0, "SNIFF превратил бы изъятие в копию");
        assert_eq!(CAPTURE_FLAGS & 0x0008, 0, "SEND_ONLY запретил бы Recv-цикл");
        assert_eq!(CAPTURE_PRIORITY, 30000);
    }

    #[test]
    fn bitfield_extraction_layer_event_outbound() {
        // Layer=0 (NETWORK), Event=0 (packet), Sniffed=1, Outbound=1, Loopback=0,
        // IPv6=0: bits: 1<<16 | 1<<17.
        let mut a = WinDivertAddress {
            timestamp: 1,
            bitfields: (1 << 16) | (1 << 17),
            reserved2: 0,
            union_data: [0u8; 64],
        };
        assert_eq!(a.layer(), 0);
        assert_eq!(a.event(), 0);
        assert!(a.is_sniffed());
        assert!(a.is_outbound());
        assert!(!a.is_loopback());
        assert!(!a.is_ipv6());
        assert!(!a.is_impostor());
        // IPv6-флаг.
        a.bitfields |= 1 << 20;
        assert!(a.is_ipv6());
        // Impostor: пакет, заинжекченный чужим WinDivertSend (наш RST).
        a.bitfields |= 1 << 19;
        assert!(a.is_impostor());
    }

    #[test]
    fn send_handle_nul_filter_rejected() {
        // NUL отсекается ДО загрузки DLL — честный код 87 без драйвера.
        let res = open_send_handle("bad\0filter");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, 87);
    }

    #[test]
    fn send_flags_dont_allow_recv_only_mixup() {
        // SEND_FLAGS обязан содержать SEND_ONLY (0x0008) и НЕ содержать
        // RECV_ONLY (0x0004) — иначе Recv/Send-контракты хендлов перепутаются.
        assert_eq!(SEND_FLAGS & 0x0008, 0x0008, "нет SEND_ONLY");
        assert_eq!(SEND_FLAGS & 0x0004, 0, "лишний RECV_ONLY");
        assert_eq!(SEND_FLAGS & 0x0001, 0x0001, "нет SNIFF");
    }

    #[test]
    fn error_meaning_common_codes() {
        assert!(error_meaning(5).contains("прав администратора"));
        assert!(error_meaning(232).contains("Shutdown"));
        assert!(error_meaning(9999).contains("WinDivert"));
    }

    #[test]
    fn missing_dll_produces_honest_error_not_panic() {
        let fake = Path::new("Z:\\такой_каталога_нет\\WinDivert.dll");
        let res = load_syms_from(fake);
        assert!(res.is_err());
        let msg = res.unwrap_err();
        assert!(msg.contains("не удалось загрузить") || msg.contains("WinDivert.dll"), "msg={}", msg);
    }

    #[test]
    fn filter_with_nul_rejected() {
        let res = open_sniff_handle("bad\0filter");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, 87);
    }
}
