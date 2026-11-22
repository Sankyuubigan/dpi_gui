//! Job Object Windows — атомарное гашение ДЕРЕВА процессов sidecar'ов.
//!
//! Архитектурный фикс класса «процесс-сирота держит файл» (инцидент 22.11.26,
//! os error 32 в release.bat — третий случай): stop_sidecar убивал ТОЛЬКО
//! aether.exe, его дети (psiphon-tunnel-core.exe, lyrebird.exe) выживали,
//! продолжали исполняться из release/bin/pt/ и блокировали перезапись файла
//! сборкой. Windows не гасит потомков по kill() родителя — гасит Job Object:
//! потомки наследуют джоб (spawn без CREATE_BREAKAWAY_FROM_JOB, Go/Rust std
//! его не ставят), TerminateJobObject убивает всё дерево разом, а
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE добивает дерево даже при смерти
//! dpi_gui без graceful stop (taskkill /F на приложение, падение, вырубание)
//! — хэндл джоба закрывает ОС вместе с процессом, дерево умирает с ним.
//!
//! Гонки нет: aether спавнит psiphon-tunnel-core на порядок позже нашего
//! AssignProcessToJobObject (datastore/инициализация занимают секунды).

use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// Ребёнок в Job Object: гасится вместе со всем своим деревом потомков.
/// HANDLE в windows-sys 0.52 — isize; несуществующий дескриптор = 0.
pub struct TreeChild {
    child: Child,
    job: HANDLE,
}

impl TreeChild {
    /// Спавн + немедленный ассайн в новый job с kill-on-close.
    pub fn spawn(cmd: &mut Command) -> Result<TreeChild, String> {
        let prog = cmd.get_program().display().to_string();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Ошибка запуска {}: {}", prog, e))?;
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job == 0 {
                let _ = child.kill();
                return Err(String::from("CreateJobObjectW не удался — дерево процессов не будет гаситься"));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(job);
                let _ = child.kill();
                return Err(String::from("SetInformationJobObject не удался — дерево процессов не будет гаситься"));
            }
            let ok = AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE);
            if ok == 0 {
                CloseHandle(job);
                let _ = child.kill();
                return Err(format!(
                    "{}: не привязать к Job Object — дерево процессов не будет гаситься",
                    prog
                ));
            }
            Ok(TreeChild { child, job })
        }
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Гасит ВСЁ дерево (ребёнка и всех потомков) и дожидается завершения.
    /// Повторный вызов безопасен (джоб уже закрыт — ничего не делает).
    pub fn kill_tree(&mut self) {
        if self.job == 0 {
            return;
        }
        unsafe {
            TerminateJobObject(self.job, 0);
        }
        let _ = self.child.wait();
        unsafe {
            CloseHandle(self.job);
        }
        self.job = 0;
    }
}

impl Drop for TreeChild {
    fn drop(&mut self) {
        self.kill_tree();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::time::{Duration, Instant};

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    #[test]
    fn test_kill_tree_kills_grandchildren() {
        // Инцидент 22.11.26: kill() родителя оставлял детей-сирот
        // (psiphon-tunnel-core из release/bin/pt/), валивших сборку релиза.
        // powershell → ping: в джобе обязаны умереть ОБА, ping — не выжить.
        let mut cmd = Command::new("powershell");
        cmd.creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-Command", "ping -n 30 127.0.0.1"]);
        let mut t = TreeChild::spawn(&mut cmd).expect("spawn powershell");
        // Даём powershell стартовать и спавнить ping-ребёнка.
        std::thread::sleep(Duration::from_millis(3000));
        t.kill_tree();
        let dl = Instant::now() + Duration::from_secs(5);
        loop {
            let out = Command::new("tasklist")
                .args(["/FI", "IMAGENAME eq ping.exe"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .expect("tasklist");
            let s = String::from_utf8_lossy(&out.stdout);
            if !s.contains("ping.exe") {
                break;
            }
            assert!(Instant::now() < dl, "дети дерева пережили kill_tree");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    #[test]
    fn test_tree_child_natural_exit_then_kill_tree() {
        // Уже завершившийся сам ребёнок: kill_tree не виснет и не паникует.
        let mut cmd = Command::new("cmd");
        cmd.creation_flags(CREATE_NO_WINDOW).args(["/C", "exit 0"]);
        let mut t = TreeChild::spawn(&mut cmd).expect("spawn cmd");
        std::thread::sleep(Duration::from_millis(300));
        t.kill_tree();
        // Повторный вызов — no-op.
        t.kill_tree();
    }
}
