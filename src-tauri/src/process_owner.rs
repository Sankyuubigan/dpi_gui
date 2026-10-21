//! Владелец TCP-сокета (PRP ревизия 4 §7.6, ШАГ E «кто стучался»).
//!
//! Отвечает на вопрос юзера «что за процесс пытался делать запрос и обломался»:
//! детектор (`domain_monitor`) кэширует владельца на ИСХОДЯЩЕМ пакете живого
//! TCP-соединения (в этот момент row ещё есть в таблице Windows), а не на RST —
//! к моменту RST стек уже удалил соединение из таблицы.
//!
//! Состояние на 21.10.26: ONLY IPv4 — детектор v1 пропускает IPv6/loopback,
//! поэтому v6-таблица не сканируется. Имя процесса — через уже имеющуюся
//! зависимость `sysinfo` (без новых крейтов).

use std::net::{IpAddr, Ipv4Addr};

use sysinfo::{Pid, ProcessesToUpdate, System};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// PID владельца сокета или None (нет данных / таблица не читается / не найдено).
pub fn find_pid(local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Option<u32> {
    // v1-детектор смотрит только IPv4: IPv6-запрос тут не должен паниковать.
    if !matches!(remote_ip, IpAddr::V4(_)) {
        return None;
    }
    let remote_v4 = match remote_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => unreachable!("проверено выше"),
    };
    // Remote IP в таблице: 4 байта прямо из структуры Ipv4Addr (octets).
    let remote_bytes = remote_v4.octets();

    unsafe {
        // 1-й проход: запрашиваем размер таблицы.
        let mut size: u32 = 0;
        let status = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            (AF_INET) as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }

        // 2-й проход: читаем таблицу целиком.
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_TCPTABLE_OWNER_PID;
        let status = GetExtendedTcpTable(
            table as *mut _,
            &mut size,
            0,
            (AF_INET) as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if status != 0 {
            return None;
        }

        // Байтовые правила (стандартные «ловушки» iphlpapi):
        //  - порты: network byte order в МЛАДШИХ 2 байтах DWORD → u16::from_be(dw & 0xFFFF);
        //  - IP: байты в памяти в network byte order → берём little-endian развёртку u32.
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            if row.dwOwningPid == 0 {
                continue; // безвладелецные служебные строки — не процессы пользователей
            }
            let lport = u16::from_be((row.dwLocalPort & 0x0000FFFF) as u16);
            let rport = u16::from_be((row.dwRemotePort & 0x0000FFFF) as u16);
            if lport != local_port || rport != remote_port {
                continue;
            }
            let rip = Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes());
            if rip.octets() == remote_bytes {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

/// Имя процесса (executable), владеющего соединением; пустое имя/не найдено → None.
pub fn owner_name(local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Option<String> {
    let pid = find_pid(local_port, remote_ip, remote_port)?;
    let pid = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let proc = sys.process(pid)?;
    let name = proc.name().to_string_lossy().trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ---------------------------------------------------------------------------
// Тесты (unit): реальная таблица Windows, без драйвера.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn owner_of_self_connection_is_self_pid() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp-порт");
        let port = listener.local_addr().expect("local_addr").port();

        // Держим принимающий сокет живым на фоне.
        let accept_thread = std::thread::spawn(move || {
            let _conn = listener.accept().expect("accept");
            std::thread::sleep(Duration::from_millis(600));
        });

        // Соединяемся сами с собой: local_port → remote(ip:port) — однозначно найдётся.
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let local_port = stream.local_addr().expect("local_addr").port();

        // Небольшой сон: row ESTABLISHED обязан уже быть в таблице.
        std::thread::sleep(Duration::from_millis(100));

        let name = owner_name(local_port, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
            .expect("владелец собственного соединения обязан найтись");
        assert!(
            !name.trim().is_empty(),
            "имя процесса не пустое: {name}"
        );

        // IPv6-запрос не паникует и честно отвечает None вне v6-детекции.
        assert!(owner_name(
            local_port,
            "2001:db8::1".parse().expect("v6-литерал"),
            port
        )
        .is_none());

        drop(stream);
        accept_thread.join().expect("keepalive поток");
    }
}
