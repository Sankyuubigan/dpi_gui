//! Общая логика «сохранить активный профиль обхода → остановить winws →
//! восстановить». Единое место (SSOT) для доменного анализа и IP-режима:
//! раньше эта связка жила в analyzer.rs и при появлении второго потребителя
//! неизбежно дублировалась бы.

use std::thread;
use std::time::Duration;

use tauri::AppHandle;

use crate::config;
use crate::events::app_log;
use crate::process;

/// Сохранённое состояние обхода на момент начала двухфазовой пробы.
pub struct SavedBypass {
    pub profile: Option<String>,
    pub game_filter: bool,
}

/// Читает активный профиль обхода и флаг game_filter из config.json.
pub fn read_active_profile() -> (Option<String>, bool) {
    match config::read_config() {
        Ok(cfg) => {
            let profile = cfg
                .get("selected_profile")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let game_filter = cfg
                .get("game_filter")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            (profile, game_filter)
        }
        Err(_) => (None, false),
    }
}

pub fn capture_active() -> SavedBypass {
    let (profile, game_filter) = read_active_profile();
    SavedBypass { profile, game_filter }
}

/// Остановка обхода и ожидание выгрузки драйвера WinDivert
/// (см. AGENTS.md п. 3: `stop_winws` делает `sc stop WinDivert`,
/// драйверу нужно время на выгрузку). Ждём ФАКТ выгрузки поллингом, а не
/// фиксированную паузу: перехватывающий трафик драйвер после слепого сна
/// давал пробам анализа ложные обрывы «без обхода» (кейс eu.aptabase.com).
/// Потолок — щедрый (драйвер может выгружаться секундами), settle-пауза —
/// на до-зачистку стека фильтров после того, как служба уже не RUNNING.
pub fn stop_bypass() {
    let _ = process::stop_winws();
    process::wait_bypass_fully_stopped(Duration::from_secs(8));
    thread::sleep(Duration::from_millis(500));
}

/// Восстановление обхода сохранённым профилем. Возвращает готовый текст
/// заметки для отчёта (в т.ч. честную ошибку — при неудаче восстановления
/// или отсутствии профиля, core rules §2.2).
pub fn restore_bypass(app: &AppHandle, saved: &SavedBypass) -> Option<String> {
    match &saved.profile {
        Some(profile) => match process::start_winws(app.clone(), profile, saved.game_filter) {
            Ok(_) => Some(format!("✅ Обход восстановлен (профиль «{}»).", profile)),
            Err(e) => Some(format!(
                "⚠️ Не удалось восстановить обход автоматически ({}). Включите профиль вручную.",
                e
            )),
        },
        None => Some(
            "⚠️ Активный профиль не определён — включите обход вручную.".to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Окно «обход выключен» с ГАРАНТИЕЙ восстановления.
//
// Инцидент 27.10.26: паника анализа между stop_bypass и restore_bypass
// оставляла обход выключенным навсегда — юзер видел «не включается заново».
// Корень — восстановление не было связаны с окном lifetime'ом. OffWindowGuard
// делает отказ невозможным (core §1.10): Drop всегда возвращает обход, даже
// при панике/раннем выходе из окна.
// ---------------------------------------------------------------------------
pub struct OffWindowGuard {
    app: AppHandle,
    saved: SavedBypass,
    armed: bool,
}

impl OffWindowGuard {
    /// Захватывает активный профиль и глушит обход (с ожиданием выгрузки
    /// драйвера — см. stop_bypass). Пока guard жив, окно открыто.
    pub fn open(app: &AppHandle) -> Self {
        let saved = capture_active();
        stop_bypass();
        Self { app: app.clone(), saved, armed: true }
    }

    /// Чистое закрытие окна: восстановление обхода сохранённым профилем.
    /// Возвращает заметку для отчёта (как restore_bypass).
    pub fn close(mut self) -> Option<String> {
        let note = restore_bypass(&self.app, &self.saved);
        self.armed = false;
        note
    }
}

impl Drop for OffWindowGuard {
    fn drop(&mut self) {
        if self.armed {
            let note = restore_bypass(&self.app, &self.saved);
            app_log(
                &self.app,
                format!(
                    "[Обход] аварийное восстановление после незакрытого окна без обхода: {}",
                    note.unwrap_or_else(|| "заметки нет".to_string())
                ),
            );
        }
    }
}
