//! Единая очередь «тяжёлых» сетевых операций: одиночный анализ, массовый
//! анализ списка ошибок, применение найденного решения.
//!
//! Почему очередь и только очередь (core §1.10 — отказ делается невозможным):
//! анализ глушит и восстанавливает обход (winws + драйвер WinDivert —
//! ГЛОБАЛЬНОЕ состояние процесса), «починка» правит списки и перезапускает
//! winws. Два параллельных анализа перемешали бы окна «обход выключен»: пробы
//! шли бы по чужому обходу, отчёты врали бы. Один worker ⇒ такой отказ
//! невозможен. Массовый анализ собирает факты всей пачки в ОДНОМ окне
//! (mass_analysis), так что очередь и пачка вместе = минимум гашений обхода.
//!
//! Ручной анализ и «Починка» идут через эту же очередь, иначе ручной запуск
//! пересекался бы с окном без обхода идущего массового прогона.
//!
//! Внешние операции, которые сами рулят обходом (тесты профилей, диагностика),
//! берут [`begin_external`]: worker дожидается текущего джоба и ставится на
//! паузу до их конца.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::analyzer::{self, DomainAnalysisOutcome};
use crate::cancel;
use crate::events::app_log;
use crate::site_solution::SiteSolution;

/// Потолок ожидания внешним оператором (тесты/диагностика) освобождения очереди.
pub const EXTERNAL_WAIT: Duration = Duration::from_secs(180);
/// Период опроса worker-цикла (очередь мала, гонять condvar нечего).
const POLL: Duration = Duration::from_millis(200);
/// Жёсткий дедлайн анализа одного домена (инцидент 03.11.26: заклинившая
/// проба держала running=true навсегда, фича «висела намертво»). Дедлайн
/// покрывает полный конвейер analyze_url (Chrome-этап ~30с + IPSCAN до
/// ~2 мин + восстановление обхода) с запасом.
const ANALYSIS_DEADLINE: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Событие прогресса для UI: статусы в строках «Ошибок сети».
// ---------------------------------------------------------------------------
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnalysisProgress {
    /// Домен (или IP-цель), к которому относится статус.
    domain: String,
    /// "queued" | "running" | "done" | "failed"
    state: &'static str,
    /// Заполнено при "done": найдено ли решение.
    found: Option<bool>,
    summary: Option<String>,
    none_reason: Option<String>,
    /// Полное решение — данные для кнопки «Починить» из списка ошибок.
    solution: Option<SiteSolution>,
    /// Заполнено при "failed".
    error: Option<String>,
}

pub(crate) fn emit_progress(
    app: &AppHandle,
    domain: &str,
    state: &'static str,
    outcome: Option<&DomainAnalysisOutcome>,
    error: Option<String>,
) {
    let (found, summary, none_reason, solution) = match outcome {
        Some(o) => (
            Some(o.solution.found),
            Some(o.solution.summary.clone()),
            o.solution.none_reason.clone(),
            Some(o.solution.clone()),
        ),
        None => (None, None, None, None),
    };
    let ev = AnalysisProgress {
        domain: domain.to_string(),
        state,
        found,
        summary,
        none_reason,
        solution,
        error,
    };
    if let Err(e) = app.emit("analysis_progress", &ev) {
        app_log(app, format!("[Анализ] не удалось доставить прогресс в UI: {}", e));
    }
}

// ---------------------------------------------------------------------------
// Очередь.
// ---------------------------------------------------------------------------
enum Job {
    /// Ручной анализ (вкладка «Починка сайтов») — результат уходит в ответ.
    Manual { url: String, respond: mpsc::Sender<Result<DomainAnalysisOutcome, String>> },
    /// Массовый анализ списка ошибок — вся пачка в одном окне без обхода
    /// (mass_analysis), по-доменные события уходят из него, сюда — сводка.
    Mass { domains: Vec<String>, respond: mpsc::Sender<Result<String, String>> },
    /// Применение решения — через очередь: правка списков + перезапуск winws
    /// трогают то же глобальное состояние, что и анализ.
    Apply { solution: SiteSolution, respond: mpsc::Sender<Result<String, String>> },
    /// «Починить все»: пачка решений сливается в ОДНО (site_solution::merge_solutions)
    /// и применяется одним проходом — одна правка списков, ОДИН перезапуск
    /// обхода на всю пачку (N отдельных вызовов рестартили бы winws N раз).
    ApplyBatch { solutions: Vec<SiteSolution>, respond: mpsc::Sender<Result<String, String>> },
}

struct QueueState {
    queue: VecDeque<Job>,
    running: bool,
    /// Идёт внешняя операция, рулящая обходом (тесты/диагностика) — worker ждёт.
    external_busy: bool,
}

impl QueueState {
    fn new() -> Self {
        Self { queue: VecDeque::new(), running: false, external_busy: false }
    }

    /// Ручные джобы — вперёд очереди: человек ждёт сейчас.
    fn push_manual(&mut self, job: Job) {
        self.queue.push_front(job);
    }

    /// Взять следующий исполняемый джоб.
    fn pop_next(&mut self) -> Option<Job> {
        if self.running || self.external_busy {
            return None;
        }
        let job = self.queue.pop_front()?;
        self.running = true;
        Some(job)
    }
}

fn state() -> &'static Mutex<QueueState> {
    static S: OnceLock<Mutex<QueueState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(QueueState::new()))
}

fn ensure_worker(app: &AppHandle) {
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_ok() {
        let app_worker = app.clone();
        let spawned = std::thread::Builder::new()
            .name("analysis-queue".into())
            .spawn(move || worker(app_worker));
        if let Err(e) = spawned {
            app_log(app, format!("[Анализ] поток очереди не запущен: {}", e));
        }
    }
}

// ---------------------------------------------------------------------------
// Worker: единственный исполнитель всех джобов.
// ---------------------------------------------------------------------------
fn worker(app: AppHandle) {
    loop {
        let job = {
            let mut st = state().lock().expect("analysis queue poisoned");
            st.pop_next()
        };

        let Some(job) = job else {
            std::thread::sleep(POLL);
            continue;
        };

        match job {
            Job::Manual { url, respond } => {
                // «Стоп» мог сработать в окне между постановкой в очередь и
                // стартом (drain не застал джоб — он уже взят): не стартуем
                // отменённый анализ. finish_job обязателен — pop_next уже
                // выставил running.
                if cancel::is_cancelled(cancel::SITE_ANALYSIS) {
                    let _ = respond.send(Err("анализ отменён пользователем".into()));
                    finish_job();
                    continue;
                }
                let label = display_domain_of(&url);
                emit_progress(&app, &label, "running", None, None);
                app_log(&app, format!("[Анализ] анализ {}...", label));
                // Анализ живёт в своём потоке, worker ждёт только до дедлайна
                // (иначе один заклинивший probe() держал бы очередь навсегда —
                // инцидент 03.11.26). Поток-зомби НЕ join-ится.
                let outcome = match run_manual_with_deadline(&app, &url) {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        // Дедлайн/обрыв потока: честный Err, очередь свободна,
                        // обход восстанавливаем ИЗВНЕ окна (Guard ранить нельзя:
                        // зомби-поток свой Drop не вызовет).
                        app_log(&app, format!("[Анализ] {e}"));
                        let _ = respond.send(Err(e.clone()));
                        emit_progress(&app, &label, "failed", None, Some(e));
                        if let Some(note) = crate::bypass_toggle::emergency_restore(&app) {
                            app_log(&app, note);
                        }
                        finish_job();
                        app_log(
                            &app,
                            format!(
                                "[Анализ] очередь освобождена (джоб {} сброшен по дедлайну)",
                                label
                            ),
                        );
                        continue;
                    }
                };
                // Ответ ждёт команда run_domain_analysis; событие обновит и
                // бейдж в «Ошибках сети», если этот домен там есть.
                let _ = respond.send(outcome.clone());
                match &outcome {
                    Ok(o) => emit_progress(&app, &label, "done", Some(o), None),
                    Err(e) => emit_progress(&app, &label, "failed", None, Some(e.clone())),
                }
                finish_job();
            }
            Job::Mass { domains, respond } => {
                app_log(&app, "[Анализ] массовый анализ списка ошибок...");
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::mass_analysis::run_mass(&app, domains)
                }))
                .unwrap_or_else(|p| {
                    Err(format!(
                        "массовый анализ упал: {}",
                        panic_msg(p)
                    ))
                });
                let _ = respond.send(res);
                finish_job();
            }
            Job::Apply { solution, respond } => {
                let r = apply_solution_now(&app, &solution);
                let _ = respond.send(r);
                finish_job();
            }
            Job::ApplyBatch { solutions, respond } => {
                let merged = crate::site_solution::merge_solutions(&solutions);
                let r = if merged.found {
                    apply_solution_now(&app, &merged)
                } else {
                    Err(merged.none_reason.unwrap_or_else(|| "применять нечего".into()))
                };
                let _ = respond.send(r);
                finish_job();
            }
        }
    }
}

fn finish_job() {
    state().lock().expect("analysis queue poisoned").running = false;
}

fn panic_msg(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "неизвестная паника".into())
}

/// Одиночный анализ не должен убивать worker: паника → честный «failed» джобу.
fn analyze_catch(app: &AppHandle, url: &str) -> Result<DomainAnalysisOutcome, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| analyzer::analyze_url(app, url)))
        .unwrap_or_else(|p| Err(format!("внутренняя паника анализа: {}", panic_msg(p))))
}

/// Запуск ручного анализа в ОТДЕЛЬНОМ потоке с жёстким дедлайном ожидания
/// ([`ANALYSIS_DEADLINE`]). Ok(outcome) — анализ закончился сам; Err —
/// дедлайн/обрыв канала: поток-зомби остаётся жить (join был бы вечен),
/// а caller обязан вызвать `finish_job()` + `emergency_restore`.
fn run_manual_with_deadline(
    app: &AppHandle,
    url: &str,
) -> Result<Result<DomainAnalysisOutcome, String>, String> {
    let (tx, rx) = mpsc::channel::<Result<DomainAnalysisOutcome, String>>();
    let app_thread = app.clone();
    let url_thread = url.to_string();
    let spawned = std::thread::Builder::new()
        .name(format!("analysis-manual-{}", display_domain_of(url)))
        .spawn(move || {
            let out = analyze_catch(&app_thread, &url_thread);
            let _ = tx.send(out);
        });
    let handle = spawned.map_err(|e| format!("поток анализа не запущен: {}", e))?;
    match rx.recv_timeout(ANALYSIS_DEADLINE) {
        Ok(outcome) => Ok(outcome),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // ибо убивать поток нельзя (Rust не умеет безопасно) — join
            // пропускаем сознательно, зомби-поток останется висеть.
            Err(format!(
                "анализ не уложился в дедлайн {} сек; поток анализа брошен, обход восстанавливается",
                ANALYSIS_DEADLINE.as_secs()
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Поток умер, не послав ответ. handle.join() здесь безопасен:
            // раз канала нет — поток уже ЗАВЕРШИЛСЯ (не заклинил).
            let panic_note = handle
                .join()
                .err()
                .map(|_| "поток паниковал")
                .unwrap_or("поток завершился без ответа");
            Err(format!("поток анализа прервался: {}", panic_note))
        }
    }
}

/// Человекочитаемый ярлык джоба: нормализованный хост введённого адреса
/// (для сверки с бейджами в «Ошибках сети»), IP-цель — как есть.
fn display_domain_of(input: &str) -> String {
    match crate::ip_target::parse_target(input) {
        crate::ip_target::AnalysisTarget::Domain { host } => host,
        crate::ip_target::AnalysisTarget::Ip { ip, port } => format!("{}:{}", ip, port),
    }
}

// ---------------------------------------------------------------------------
// Точки входа для команд.
// ---------------------------------------------------------------------------

/// Ручной анализ: джоб в очередь, ответ — через канал, пока worker занят
/// (например, дожимает массовый прогон) — команда честно ждёт своей очереди.
/// Потолок ожидания — ANALYSIS_DEADLINE + запас: зависший воркер не держит
/// команду навсегда, приходит честный Err (инцидент 03.11.26).
pub async fn enqueue_manual(app: AppHandle, url: String) -> Result<DomainAnalysisOutcome, String> {
    // Новая операция сбрасывает флаг прошлой отмены: «Стоп» действует только
    // на операцию, запущенную в этот момент (операции эксклюзивны на фронте
    // через общий isTesting, так что наезд запуска на неотвеченную отмену
    // невозможен: кнопки заблокированы, пока предыдущий анализ не ответит).
    cancel::reset(cancel::SITE_ANALYSIS);
    let (tx, rx) = mpsc::channel();
    {
        let mut st = state().lock().expect("analysis queue poisoned");
        st.push_manual(Job::Manual { url, respond: tx });
    }
    ensure_worker(&app);
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv_timeout(ANALYSIS_DEADLINE + Duration::from_secs(60))
            .unwrap_or_else(|_| {
                Err(format!(
                    "очередь анализа не ответила за {} сек (вероятно, очередь занята долгим массовым анализом) — повторите попытку",
                    (ANALYSIS_DEADLINE + Duration::from_secs(60)).as_secs()
                ))
            })
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

/// Кнопка «Стоп» анализа сайта: снять все ЖДУЩИЕ manual-джобы очереди, каждому
/// — честный Err (фронт разблокируется мгновенно). Идущий анализ гасится
/// отдельно — контрольными точками в analyzer::analyze_domain по флагу
/// site_analysis (ранний Err там безопасен: OffWindowGuard::Drop вернёт обход).
/// Mass/Apply не трогаются: у них свои жизненные циклы, «Стоп» на вкладке
/// «Починка сайтов» отменяет только анализ сайта.
pub fn cancel_manual_queued() {
    let drained: Vec<mpsc::Sender<Result<DomainAnalysisOutcome, String>>> = {
        let mut st = state().lock().expect("analysis queue poisoned");
        let mut kept = VecDeque::with_capacity(st.queue.len());
        let mut drained = Vec::new();
        while let Some(job) = st.queue.pop_front() {
            match job {
                Job::Manual { respond, .. } => drained.push(respond),
                other => kept.push_back(other),
            }
        }
        st.queue = kept;
        drained
    };
    for respond in drained {
        let _ = respond.send(Err("анализ отменён пользователем".into()));
    }
}

/// Массовый анализ: вся пачка в одном окне без обхода; сводка — через канал.
pub async fn enqueue_mass(app: AppHandle, domains: Vec<String>) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    {
        let mut st = state().lock().expect("analysis queue poisoned");
        st.push_manual(Job::Mass { domains, respond: tx });
    }
    ensure_worker(&app);
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv().unwrap_or_else(|_| Err("очередь анализа не ответила: воркер завершился".into()))
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

/// Применение решения через очередь (см. комментарий Job::Apply).
pub async fn enqueue_apply(app: AppHandle, solution: SiteSolution) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    {
        let mut st = state().lock().expect("analysis queue poisoned");
        st.push_manual(Job::Apply { solution, respond: tx });
    }
    ensure_worker(&app);
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv().unwrap_or_else(|_| Err("очередь анализа не ответила: воркер завершился".into()))
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

/// «Починить все»: пачка решений одним джобом (см. комментарий Job::ApplyBatch).
pub async fn enqueue_apply_batch(app: AppHandle, solutions: Vec<SiteSolution>) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    {
        let mut st = state().lock().expect("analysis queue poisoned");
        st.push_manual(Job::ApplyBatch { solutions, respond: tx });
    }
    ensure_worker(&app);
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv().unwrap_or_else(|_| Err("очередь анализа не ответила: воркер завершился".into()))
    })
    .await
    .unwrap_or_else(|e| Err(format!("Ошибка потока: {}", e)))
}

// ---------------------------------------------------------------------------
// Внешние операции, рулящие обходом (тесты профилей, диагностика).
// ---------------------------------------------------------------------------

/// Держать пока идёт внешняя операция; на выходе (Drop) очередь возобновляется.
pub struct ExternalGuard;

impl Drop for ExternalGuard {
    fn drop(&mut self) {
        state().lock().expect("analysis queue poisoned").external_busy = false;
    }
}

/// Пауза очереди на время внешней операции: текущий джоб дожимается,
/// новые воркер не берёт. Потолок ожидания [`EXTERNAL_WAIT`], дальше —
/// честный Err (кнопка не должна зависать навсегда).
pub fn begin_external() -> Result<ExternalGuard, String> {
    {
        let mut st = state().lock().expect("analysis queue poisoned");
        st.external_busy = true;
    }
    let deadline = std::time::Instant::now() + EXTERNAL_WAIT;
    loop {
        let running = state().lock().expect("analysis queue poisoned").running;
        if !running {
            return Ok(ExternalGuard);
        }
        if std::time::Instant::now() >= deadline {
            state().lock().expect("analysis queue poisoned").external_busy = false;
            return Err(
                "очередь анализа занята дольше 3 минут (идёт анализ/починка) — дождитесь её опустошения и повторите".into(),
            );
        }
        std::thread::sleep(POLL);
    }
}

// ---------------------------------------------------------------------------
// Применение решения (тело перенесено из main.rs::apply_solution без
// изменения логики): исполняется ТОЛЬКО через очередь, чтобы не пересекаться
// с окном «обход выключен» идущего анализа.
// ---------------------------------------------------------------------------
fn apply_solution_now(app: &AppHandle, solution: &SiteSolution) -> Result<String, String> {
    let mut report_lines: Vec<String> = Vec::new();
    let mut lists_changed: bool = false;

    for action in &solution.actions {
        match action {
            crate::site_solution::SolutionAction::AddToBypassList { domains } => {
                let r = crate::bypass_lists::add_domains(crate::bypass_lists::TargetList::Bypass, domains)?;
                report_lines.push(format!("🛡️ {}", r));
                lists_changed = true;
            }
            crate::site_solution::SolutionAction::AddToExcludeList { domains } => {
                let r = crate::bypass_lists::add_domains(crate::bypass_lists::TargetList::Exclude, domains)?;
                report_lines.push(format!("⛔ {}", r));
                lists_changed = true;
            }
            crate::site_solution::SolutionAction::RemoveFromExcludeList { domains } => {
                // Убираем точные записи из юзерского файла; если запись жила
                // только в дефолтах, remove_domains честно отчитается, что
                // убирать нечего (решение её не советует, но пачка могла).
                let r = crate::bypass_lists::remove_domains(crate::bypass_lists::TargetList::Exclude, domains)?;
                report_lines.push(format!("✂️ {}", r));
                lists_changed = true;
            }
            crate::site_solution::SolutionAction::WriteHosts { ip, domain } => {
                let r = crate::hosts::apply_hosts_entry(ip, domain)?;
                report_lines.push(format!("📄 {}", r));
            }
            crate::site_solution::SolutionAction::RemoveHosts { domain } => {
                let r = crate::hosts::remove_hosts_entry(domain)?;
                report_lines.push(format!("🧹 {}", r));
            }
        }
    }

    if lists_changed {
        // winws читает hostlist-файлы только при старте: чтобы решение
        // заработало сразу, перезапускаем обход тем же профилем
        // (логика SSOT — bypass_toggle, как в анализе).
        if crate::process::is_winws_running() {
            let saved = crate::bypass_toggle::capture_active();
            crate::bypass_toggle::stop_bypass();
            let note = crate::bypass_toggle::restore_bypass(app, &saved)
                .unwrap_or_else(|| "Обход не перезапускался: профиль не был активен.".to_string());
            report_lines.push(format!("♻️ Правки списков применены; {}", note));
        } else {
            report_lines.push("ℹ️ Обход сейчас выключен: правки вступят в силу при следующем старте профиля.".to_string());
        }
    }

    if report_lines.is_empty() {
        return Err("в решении нет ни одного действия — применять нечего".to_string());
    }
    Ok(report_lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Тесты: чистая логика очереди (без сети/воркера).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_jumps_ahead_of_mass() {
        let mut st = QueueState::new();
        let (mass_tx, mass_rx) = mpsc::channel::<Result<String, String>>();
        let (manual_tx, manual_rx) = mpsc::channel::<Result<DomainAnalysisOutcome, String>>();
        st.push_manual(Job::Mass { domains: vec!["a.com".into()], respond: mass_tx });
        st.push_manual(Job::Manual { url: "m.com".into(), respond: manual_tx });
        match st.pop_next() {
            Some(Job::Manual { url, .. }) => assert_eq!(url, "m.com"),
            _ => panic!("ручной джоб обязан быть первым"),
        }
        st.running = false; // воркер сбрасывает флаг после дожима джоба
        match st.pop_next() {
            Some(Job::Mass { domains, .. }) => assert_eq!(domains, vec!["a.com".to_string()]),
            _ => panic!("массовый джоб должен остаться в очереди"),
        }
        drop(mass_rx);
        drop(manual_rx);
    }

    #[test]
    fn pop_blocked_while_running_or_external() {
        let mut st = QueueState::new();
        let (tx, _rx) = mpsc::channel::<Result<String, String>>();
        st.push_manual(Job::Mass { domains: vec!["a.com".into()], respond: tx });
        st.running = true;
        assert!(st.pop_next().is_none(), "при работающем джобе новый не берётся");
        st.running = false;
        st.external_busy = true;
        assert!(st.pop_next().is_none(), "внешняя операция ставит очередь на паузу");
        st.external_busy = false;
        assert!(st.pop_next().is_some());
    }

    #[test]
    fn empty_queue_returns_none() {
        let mut st = QueueState::new();
        assert!(st.pop_next().is_none());
    }
}
