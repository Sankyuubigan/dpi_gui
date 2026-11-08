use crate::{cancel, process, diagnostics_probe};
use std::thread;
use std::time::{Duration, Instant};
use serde::Serialize;
use tauri::AppHandle;

/// Результат теста одного профиля — возвращается на фронтенд.
#[derive(Serialize, Debug)]
pub struct ProfileTestOutcome {
    pub name: String,
    pub ok: bool,
    /// Человеко-читаемый вердикт: «УСПЕХ (200 OK)», «Таймаут соединения», «RST — сброс (DPI)» и т.п.
    pub verdict: String,
    /// Дополнительная деталь (для провала).
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Человеко-читаемое описание классифицированного результата HTTP-пробы.
fn verdict_from_http(r: &diagnostics_probe::HttpResult) -> (bool, String) {
    match r {
        diagnostics_probe::HttpResult::Ok(s) => (true, format!("УСПЕХ (HTTP {})", s)),
        diagnostics_probe::HttpResult::Unverified => (true, "УСПЕХ по транспорту, но страница без видимого контента (JS-оболочка) — доступность после входа не подтверждена".to_string()),
        diagnostics_probe::HttpResult::BlockPage => (false, "Страница блокировки (подставил оператор)".to_string()),
        diagnostics_probe::HttpResult::Forbidden(s) => (false, format!("Отказ сервера HTTP {} (возможно, региональное ограничение — проверьте через VPN)", s)),
        diagnostics_probe::HttpResult::ServiceRestrict => (false, "Сервис вернул страницу с сообщением об ограничении (регион/доступность) — профиль не при чём, нужен VPN".to_string()),
        diagnostics_probe::HttpResult::Dns => (false, "DNS не резолвится (NXDOMAIN / DNS-цензура)".to_string()),
        diagnostics_probe::HttpResult::Rst => (false, "RST — соединение сброшено (типично для DPI)".to_string()),
        diagnostics_probe::HttpResult::Tls => (false, "TLS-рукопожатие рвётся".to_string()),
        diagnostics_probe::HttpResult::BadCert => (false, "SSL-сертификат сайта невалиден (NET::ERR_CERT_*)".to_string()),
        diagnostics_probe::HttpResult::Timeout => (false, "Таймаут соединения".to_string()),
        diagnostics_probe::HttpResult::Other(msg) => (false, format!("Ошибка: {}", msg)),
    }
}

pub fn test_single_profile(app: AppHandle, profile_name: &str, url: &str, game_filter: bool) -> Result<ProfileTestOutcome, String> {
    let started = Instant::now();
    let target_url = if !url.starts_with("http") { format!("https://{}", url) } else { url.to_string() };

    // Честный вердикт отмены (ok=false, отдельный от обычных неудач): фронт
    // пишет его в лог как результат и рвёт цикл по оставшимся профилям.
    let cancelled = |detail: &str| ProfileTestOutcome {
        name: profile_name.to_string(),
        ok: false,
        verdict: "Отменено".to_string(),
        detail: detail.to_string(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    };

    // Контрольная точка до старта winws: отмена до прогрева — мгновенная.
    if cancel::is_cancelled(cancel::PROFILE_TEST) {
        return Ok(cancelled("остановлено до запуска профиля"));
    }

    if let Err(e) = process::start_winws_quiet(app.clone(), profile_name, game_filter) {
        return Ok(ProfileTestOutcome {
            name: profile_name.to_string(),
            ok: false,
            verdict: "Ошибка запуска".to_string(),
            detail: e,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Даем WinDivert время на перехват трафика. Сон кусочками с проверкой
    // флага: тест рулит winws, «Стоп» не должен ждать лишних секунд.
    for _ in 0..8 {
        if cancel::is_cancelled(cancel::PROFILE_TEST) {
            let _ = process::stop_winws();
            return Ok(cancelled("остановлено во время прогрева WinDivert"));
        }
        thread::sleep(Duration::from_millis(250));
    }

    // Десинк-профили часто пробивают только со второй/третьей попытки
    // (первый коннект съедается DPI, winws пересылает модифицированные пакеты).
    let mut result: diagnostics_probe::HttpResult = diagnostics_probe::HttpResult::Timeout;
    for attempt in 1..=2 {
        if cancel::is_cancelled(cancel::PROFILE_TEST) {
            break;
        }
        let r = diagnostics_probe::http_classify_with(&target_url, 5);
        if matches!(r, diagnostics_probe::HttpResult::Ok(_) | diagnostics_probe::HttpResult::Unverified) {
            result = r;
            break;
        }
        result = r;
        if attempt == 1 {
            for _ in 0..4 {
                if cancel::is_cancelled(cancel::PROFILE_TEST) {
                    break;
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    // Финализация обязательна: тест сам поднимал winws — отменённый тест не
    // оставляет обход висеть. Факт отмены фиксируем ДО глушения.
    let was_cancelled = cancel::is_cancelled(cancel::PROFILE_TEST);
    let _ = process::stop_winws();
    if was_cancelled {
        return Ok(cancelled("остановлено во время пробы"));
    }
    thread::sleep(Duration::from_secs(1));

    let (ok, verdict) = verdict_from_http(&result);
    let detail = if ok {
        String::new()
    } else {
        match &result {
            diagnostics_probe::HttpResult::Other(m) => m.clone(),
            diagnostics_probe::HttpResult::BlockPage => "получена страница-заглушка вместо сайта".to_string(),
            diagnostics_probe::HttpResult::Forbidden(s) => format!("сервер отказал с HTTP {} без признаков подмены (возможно, гео-блок — проверьте через VPN)", s),
            diagnostics_probe::HttpResult::Dns => "запись домена не найдена системным DNS".to_string(),
            diagnostics_probe::HttpResult::Rst => "соединение оборвано RST при рукопожатии".to_string(),
            diagnostics_probe::HttpResult::Tls => "TLS-хендшейк не завершился за время пробы".to_string(),
            diagnostics_probe::HttpResult::BadCert => "сервер ответил, но его SSL-сертификат невалиден для домена — обход не починит это".to_string(),
            diagnostics_probe::HttpResult::Timeout => "сервер не ответил за ~5 секунд".to_string(),
            _ => format!("{:?}", result),
        }
    };

    Ok(ProfileTestOutcome {
        name: profile_name.to_string(),
        ok,
        verdict,
        detail,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}