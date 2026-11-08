//! Реестр флагов отмены долгих операций (SSOT).
//!
//! Кооперативная отмена: Rust не умеет безопасно убивать поток, поэтому
//! долгая операция проверяет свой флаг в контрольных точках (между фазами/
//! итерациями) и завершается честной ошибкой/вердиктом. Гарантий мгновенности
//! нет и не требуется: задержка = длительность одного шага между точками.
//!
//! Имена операций — константы здесь; парные строковые константы фронта —
//! src/ops.ts (команда cancel_operation матчает ровно эти строки).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Вкладка «Починка сайтов»: анализ сайта / IP (manual-джобы очереди анализа).
pub const SITE_ANALYSIS: &str = "site_analysis";
/// Вкладка «Починка сайтов»: подбор рабочего DNS.
pub const DNS_PICK: &str = "dns_pick";
/// Вкладка «Профили обхода»: тест всех профилей по домену.
pub const PROFILE_TEST: &str = "profile_test";
/// Вкладка «Профили обхода»: комплексная диагностика + авто-профиль.
pub const DIAGNOSTICS: &str = "diagnostics";

fn entry(name: &str) -> Arc<AtomicBool> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("cancel registry poisoned")
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// Сброс флага при СТАРТЕ новой операции той же категории: «Стоп» действует
/// только на операцию, запущенную в этот момент. Операции эксклюзивны на
/// фронте (общий isTesting), поэтому «наезд» нового запуска на неубитый
/// прошлый флаг невозможен.
pub fn reset(name: &str) {
    entry(name).store(false, Ordering::Relaxed);
}

/// Запрос отмены (кнопка «Стоп»): операция остановится в ближайшей точке.
pub fn cancel(name: &str) {
    entry(name).store(true, Ordering::Relaxed);
}

/// Проверка в контрольной точке долгой операции.
pub fn is_cancelled(name: &str) -> bool {
    entry(name).load(Ordering::Relaxed)
}
