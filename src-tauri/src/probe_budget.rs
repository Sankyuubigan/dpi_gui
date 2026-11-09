//! Общий бюджет времени для фаз фактовых проб (SSOT дедлайнов проб).
//!
//! Раньше каждая проба жила своим внутренним временем (DoH-сервисы и
//! http_via_ip по IP — подряд), и сумма легко достигала 300 с на сайтах с
//! тихим дропом TLS (инцидент 09.11.26: анализ youtube.com горел до дедлайна
//! очереди и умирал без отчёта). Теперь внешняя фаза (анализ, массовый
//! анализ) выдаёт пробам общий [`StageBudget`]: проба опрашивает остаток и,
//! когда бюджет исчерпан или пришла внешняя отмена, прекращает перебор и
//! возвращает частичный результат с честной пометкой «не проверено: не
//! хватило бюджета» — никаких додуманных вердиктов (core rules §1.9).

use std::time::{Duration, Instant};

/// Бюджет одной фазы фактовых проб. `Copy`: тиражируется в потоки параллельного
/// перебора без Arc/Mutex — `started` у всех копий один и тот же момент.
#[derive(Clone, Copy)]
pub struct StageBudget {
    started: Instant,
    total: Duration,
    /// Внешняя отмена (кнопка «Стоп»): `Some` — опрашивается вместе с остатком
    /// времени; `true` = немедленный стоп. `None` — ограничение только временем.
    stop: Option<fn() -> bool>,
}

impl StageBudget {
    /// Бюджет только по времени (массовый анализ: у пачки своя механика).
    pub fn new(total: Duration) -> Self {
        StageBudget {
            started: Instant::now(),
            total,
            stop: None,
        }
    }

    /// Бюджет с внешней отменой (кнопка «Стоп» анализа).
    pub fn new_with_cancel(total: Duration, stop: fn() -> bool) -> Self {
        StageBudget {
            started: Instant::now(),
            total,
            stop: Some(stop),
        }
    }

    /// Сколько времени осталось до исчерпания бюджета.
    pub fn left(&self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    /// Бюджет исчерпан или пришла внешняя отмена — перебор прекращается.
    pub fn stopped(&self) -> bool {
        if self.left().is_zero() {
            return true;
        }
        self.stop.map(|f| f()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_counts_down() {
        let b = StageBudget::new(Duration::from_millis(150));
        assert!(!b.stopped());
        assert!(b.left() <= Duration::from_millis(150));
        std::thread::sleep(Duration::from_millis(200));
        assert!(b.stopped());
        assert_eq!(b.left(), Duration::ZERO);
    }

    #[test]
    fn external_stop_is_honored() {
        let b = StageBudget::new_with_cancel(Duration::from_secs(60), || true);
        assert!(b.stopped());
        let b = StageBudget::new_with_cancel(Duration::from_secs(60), || false);
        assert!(!b.stopped());
    }
}
