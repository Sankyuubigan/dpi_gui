use std::path::PathBuf;

use crate::analyzer_probe::Classification;
use crate::bypass_lists;
use crate::diagnostics_probe::{DnsState, HttpResult};
use crate::site_probe::{self, IpSource};
use crate::site_verdict::Verdict as SiteVerdict;

/// Дополнительная информация для отчёта, не связанная с классификацией доменов.
pub struct ReportMeta {
    pub target_url: String,
    pub discovered: Vec<String>,
    pub bypass_on: bool,
    /// Обход был временно выключен для повторной пробы (двухфазный анализ).
    pub bypass_toggled: bool,
    /// Сообщение о результате авто-восстановления обхода после анализа (если было).
    pub restore_note: Option<String>,
    /// В браузере фиксировались обрывы (LoadingFailed) — возможен трафик по IP/WebSocket.
    pub had_browser_failures: bool,
    /// Диагностика главного домена (DNS/рабочий IP/первопричина).
    pub main_probe: Option<site_probe::DomainProbe>,
    /// Автопроверка «подмены DNS» для главного домена (пусто, если сайт открывается).
    pub main_dns_sub: Vec<site_probe::DnsSubstitution>,
    /// Проверка подмены DNS для доменов из списка «не резолвится» (до 5).
    pub dns_fail_sub: Vec<(String, Vec<site_probe::DnsSubstitution>)>,
}

/// Путь к пользовательскому general-листу (для подсказок «добавьте в обход»).
fn general_list_path() -> String {
    crate::config::get_app_dir()
        .join("lists")
        .join("list-general.txt")
        .to_string_lossy()
        .replace("\\", "/")
}

fn is_builtin(p: &PathBuf) -> bool {
    p.to_string_lossy().replace("\\", "/").contains("default-bypass/")
}

pub fn build_report(meta: &ReportMeta, c: &Classification) -> String {
    let mut log = String::new();
    log.push_str(&format!("=== АНАЛИЗ ДОМЕНОВ: {} ===\n\n", meta.target_url));

    // Диагноз идёт ПЕРВЫМ: пользователь должен сразу понять причину, а не
    // продираться через детали, чтобы её найти.
    write_diagnosis(&mut log, meta);

    // Факты по главному домену (DNS, IP, матрица проб).
    write_main_domain(&mut log, meta);

    // Автопроверка подмены DNS — если обычный DNS отравлен и сайт не открывается.
    write_dns_substitution(&mut log, meta);

    log.push_str(&format!(
        "Обход (winws) активен: {}\n",
        if meta.bypass_on { "ДА" } else { "НЕТ" }
    ));
    if !meta.bypass_on {
        log.push_str("⚠️ Обход ВЫКЛЮЧЕН. Чтобы найти домены, которые ломает обход, ВКЛЮЧИТЕ профиль обхода и запустите анализ снова.\n");
    }
    if meta.bypass_toggled {
        log.push_str("ℹ️ Обход был временно выключен для повторной проверки (сравнение «с обходом / без обхода»).\n");
    }
    if let Some(note) = &meta.restore_note {
        log.push_str(&format!("{}\n", note));
    }
    log.push_str(&format!("🔎 Обнаружено доменов: {}\n\n", meta.discovered.len()));

    // === Домены, которые НУЖНО добавить в обход (general-лист) ===
    write_need_bypass(&mut log, c);

    // === Домены, которые ЛОМАЕТ обход (в исключения) ===
    write_bypass_breaks(&mut log, c);

    // === Домены, недоступные при выключенном обходе (причина не установлена) ===
    write_broken(&mut log, meta, c);

    // === Домены сайта, уже внесённые в обход ===
    write_already_in_bypass(&mut log, meta, c);

    // === Возможно заблокированы на уровне РФ (DNS) ===
    if !c.dns_fail.is_empty() {
        log.push_str("⚠️ ВОЗМОЖНО ЗАБЛОКИРОВАНЫ НА УРОВНЕ РФ (ошибка DNS):\n");
        for h in &c.dns_fail {
            log.push_str(&format!("  - {}\n", h));
        }
        if !meta.dns_fail_sub.is_empty() {
            log.push_str("  Проверка подмены DNS (DoH: xbox-dns.ru, geohide.ru):\n");
            for (h, subs) in &meta.dns_fail_sub {
                let ok = subs.iter().find(|s| s.http_ok);
                match ok {
                    Some(s) => log.push_str(&format!(
                        "    {} → подмена через {} НАШЛА домен (IP {} отвечает на TCP:443)\n",
                        h,
                        s.service,
                        s.working_ip.as_ref().unwrap_or(&"-".to_string())
                    )),
                    None => log.push_str(&format!(
                        "    {} → подмена IP не нашла (домен реально не резолвится)\n",
                        h
                    )),
                }
            }
        }
        log.push('\n');
    }

    log.push_str(&format!(
        "✅ Доступные (не требуют исключений): {}\n\n",
        c.ok.len()
    ));

    log.push_str("📋 Полный список обнаруженных доменов:\n");
    if meta.discovered.is_empty() {
        log.push_str("  - (не удалось обнаружить ни одного домена — возможно, сайт недоступен целиком)\n");
    } else {
        for h in &meta.discovered {
            log.push_str(&format!("  - {}\n", h));
        }
    }

    // Общая заметка про трафик по голым IP / WebSocket.
    if meta.had_browser_failures && c.need_bypass.is_empty() && c.bypass_breaks.is_empty() {
        log.push_str("\nℹ️ В браузере были обрывы соединений, но домены-кандидаты не выявлены. Часть трафика сайта может идти по прямым IP-адресам или WebSocket — такой трафик обход по списку доменов (hostlist) не покрывает.\n");
    }

    log.push_str("\n💡 СОВЕТ: домены из списка 🛡️ добавьте в список обхода (general-лист). Домены из списка ❌ («ломает обход») внесите в список исключений. Домены из списка 🗑️ удаляйте из обхода только если они помечены «ЛОМАЕТ САЙТ».");

    log
}

fn write_diagnosis(log: &mut String, meta: &ReportMeta) {
    let probe = match &meta.main_probe {
        Some(p) => p,
        None => return,
    };

    // Если сайт открыт — короткий подтверждающий блок, без шума.
    if probe.verdict == SiteVerdict::Open {
        log.push_str(&format!(
            "✅ САЙТ «{}» ДОСТУПЕН — домен и сеть в порядке ({}).\n\n",
            probe.host, probe.http_note
        ));
        return;
    }

    let diag = match &probe.diagnosis {
        Some(d) => d,
        None => return,
    };

    let icon = match probe.verdict {
        SiteVerdict::WwwOnly => "🌐",
        SiteVerdict::DnsBlocked => "🔒",
        SiteVerdict::IpReset => "🚫",
        SiteVerdict::TlsBroken | SiteVerdict::BadCert => "🔐",
        SiteVerdict::BlockPage => "⛔",
        _ => "⚠️",
    };

    log.push_str(&format!(
        "{} ВЕРОЯТНАЯ ПРИЧИНА ({}):\n",
        icon,
        probe.verdict.verdict_name()
    ));
    log.push_str(&format!("  {}\n", diag.probable_cause));

    // Что делать.
    if !diag.do_this.is_empty() {
        log.push_str("\n  ✅ ЧТО СДЕЛАТЬ:\n");
        for a in &diag.do_this {
            log.push_str(&format!("     • {}\n", a));
        }
    }

    // Что НЕ поможет — экономит юзеру время на бесполезные действия.
    if !diag.wont_help.is_empty() {
        log.push_str("\n  ❌ ЧТО НЕ ПОМОЖЕТ:\n");
        for a in &diag.wont_help {
            log.push_str(&format!("     • {}\n", a));
        }
    }
    log.push('\n');
}

fn write_main_domain(log: &mut String, meta: &ReportMeta) {
    let probe = match &meta.main_probe {
        Some(p) => p,
        None => return,
    };

    if probe.verdict == SiteVerdict::Open {
        return;
    }

    let icon = match probe.verdict {
        SiteVerdict::WwwOnly => "🌐",
        SiteVerdict::DnsBlocked => "🔒",
        SiteVerdict::IpReset => "🚫",
        SiteVerdict::TlsBroken => "🔐",
        SiteVerdict::BadCert => "🔐",
        SiteVerdict::BlockPage => "⛔",
        _ => "⚠️",
    };
    log.push_str(&format!(
        "{} ГЛАВНЫЙ ДОМЕН «{}» НЕ ОТКРЫВАЕТСЯ.\n",
        icon, probe.host
    ));

    // DNS-строка: различаем «NXDOMAIN», «резолвер не ответил» и реальный список IP,
    // иначе пустой публичный резолвер читается как отсутствие домена.
    //
    // Строки 1.1.1.1 / 8.8.8.8 идут ТОЖЕ по UDP:53, что и системный DNS, то есть
    // по тому же перехватываемому каналу. При доказанной подмене их ответ —
    // такой же подменённый, и показывать его без пометки значит выдать его за
    // ответ Cloudflare/Google.
    let untrusted = if probe.dns_spoofed.is_some() {
        "  (UDP:53 перехвачен — ответ недостоверен)"
    } else {
        ""
    };
    let sys = dns_label(&probe.dns.system, probe.dns.system_state);
    let cf = dns_label(&probe.dns.cloudflare, probe.dns.cloudflare_state);
    let gg = dns_label(&probe.dns.google, probe.dns.google_state);
    log.push_str(&format!("  DNS (система):      {}{}\n", sys, untrusted));
    log.push_str(&format!("  DNS (1.1.1.1):      {}{}\n", cf, untrusted));
    log.push_str(&format!("  DNS (8.8.8.8):      {}{}\n", gg, untrusted));
    // DNS-цензура. Раньше здесь стояло «не обнаружена», если системный DNS
    // что-то вернул, — но подменённый ответ неотличим от настоящего по форме,
    // и подмена проходила как норма. Теперь вывод опирается на сверку UDP:53
    // с DoH (probe.dns_spoofed), а если сверка невозможна — так и пишем.
    let dns_state = match &probe.dns_spoofed {
        Some(_) => "ОБНАРУЖЕНА ПОДМЕНА DNS (см. строку ниже)".to_string(),
        None => "расхождений системного DNS с DoH не найдено".to_string(),
    };
    log.push_str(&format!("  DNS-цензура:        {}\n", dns_state));
    if let Some(spoof) = &probe.dns_spoofed {
        log.push_str(&format!("  ⚠️ UDP:53 перехвачен: {}\n", spoof));
        log.push_str("     адреса из строки «DNS (система)» и из «IP apex» недостоверны\n");
    }

    // Подмена редиректа провайдером — самый точный признак блокировки.
    if let Some(isp) = &probe.isp_redirect {
        log.push_str(&format!("  🚫 Подмена ответа оператором: {}\n", isp));
    }

    // Apex и www — РАЗНЫЕ строки: их различие и есть главная подсказка.
    let prim = if probe.primary_ips.is_empty() {
        "(пусто)".to_string()
    } else {
        probe.primary_ips.join(", ")
    };
    log.push_str(&format!("  IP apex (системный DNS): {}\n", prim));
    // Проверенные адреса из защищённого канала — именно их имеет смысл
    // прописывать в hosts, и именно они отличают «подменённый адрес» от
    // настоящего.
    if !probe.doh_ips.is_empty() {
        log.push_str(&format!("  IP через DoH (проверенные): {}\n", probe.doh_ips.join(", ")));
    }
    if let Some(wh) = &probe.www_host {
        let www = if probe.www_ips.is_empty() {
            "(не резолвится)".to_string()
        } else {
            probe.www_ips.join(", ")
        };
        let status = match &probe.www_url {
            Some(u) => format!("ОТКРЫВАЕТСЯ: {}", u),
            None => "не отвечает".to_string(),
        };
        log.push_str(&format!("  IP www (системный DNS):  {} — {}\n", www, status));
        log.push_str(&format!("  Имя для доступа:        {}\n", wh));
    }

    log.push_str(&format!("  Соединение главного IP:    {}\n", probe.http_note));
    log.push_str(&working_ip_line(probe));
    if !probe.doh_failures.is_empty() {
        log.push_str(&format!(
            "  ℹ️ Не ответили DoH-сервисы: {}\n",
            probe.doh_failures.join("; ")
        ));
    }

    log.push('\n');
}

/// Строка про адрес, по которому удалось достучаться до сервера.
///
/// Название строки обязано соответствовать факту. Раньше адрес с живым TCP:443,
/// но рвущимся HTTPS печатался как «Рабочий IP (сайт открывается)» — это была
/// прямая ложь: при `BadCert`/`Rst`/таймауте сайт через этот адрес НЕ
/// открывается. Решение принимается по фактическому `HttpResult`, а не по
/// разбору текста примечания.
fn working_ip_line(probe: &site_probe::DomainProbe) -> String {
    let ip = match &probe.working_ip {
        Some(ip) => ip,
        None => return "  Рабочий IP:          не найден\n".to_string(),
    };
    let source = match probe.working_ip_source {
        Some(IpSource::Doh) => " (найден через DoH)",
        Some(IpSource::SystemDns) => " (из системного DNS)",
        None => "",
    };
    match &probe.working_http {
        // Единственный случай, когда адрес честно называется рабочим.
        Some(HttpResult::Ok(code)) => format!(
            "  Рабочий IP:          {}{} (сайт открывается, HTTP {})\n",
            ip, source, code
        ),
        Some(HttpResult::BadCert) => format!(
            "  IP с открытым TCP:443: {}{} (сертификат не совпадает с именем домена — сайт НЕ открывается)\n",
            ip, source
        ),
        Some(HttpResult::Rst) => format!(
            "  IP с открытым TCP:443: {}{} (HTTPS рвётся — сайт НЕ открывается)\n",
            ip, source
        ),
        Some(HttpResult::Tls) => format!(
            "  IP с открытым TCP:443: {}{} (TLS-рукопожатие рвётся — сайт НЕ открывается)\n",
            ip, source
        ),
        Some(HttpResult::Timeout) => format!(
            "  IP с открытым TCP:443: {}{} (таймаут — сайт не проверен)\n",
            ip, source
        ),
        Some(HttpResult::BlockPage) => format!(
            "  IP с открытым TCP:443: {}{} (отдаёт страницу блокировки)\n",
            ip, source
        ),
        Some(HttpResult::Dns) => format!(
            "  IP с открытым TCP:443: {}{} (DNS-ошибка при обращении)\n",
            ip, source
        ),
        Some(HttpResult::Other(m)) => format!(
            "  IP с открытым TCP:443: {}{} (ошибка: {} — сайт НЕ открывается)\n",
            ip, source, m
        ),
        // TCP отвечает, но HTTPS-запрос не выполнялся: утверждать нечего.
        None => format!(
            "  IP с открытым TCP:443: {}{} (HTTPS не проверен)\n",
            ip, source
        ),
    }
}

/// Текст состояния DNS-резолвера для отчёта.
fn dns_label(ips: &[std::net::IpAddr], state: DnsState) -> String {
    use std::net::IpAddr;
    match state {
        DnsState::Nxdomain => "NXDOMAIN — такого домена не существует".to_string(),
        DnsState::Unreachable => "резолвер не ответил (UDP:53 заблокирован или таймаут)".to_string(),
        DnsState::Ok if ips.is_empty() => "ответ пустой".to_string(),
        DnsState::Ok => ips.iter().map(|i: &IpAddr| i.to_string()).collect::<Vec<_>>().join(", "),
    }
}

fn write_dns_substitution(log: &mut String, meta: &ReportMeta) {
    if meta.main_dns_sub.is_empty() {
        return;
    }
    let probe = meta.main_probe.as_ref();

    log.push_str("🔁 ПРОВЕРКА ПОДМЕНЫ DNS (обход отравленного DNS через DoH):\n");
    for sub in &meta.main_dns_sub {
        if sub.http_ok {
            log.push_str(&format!("  ✅ {} — {}\n", sub.service, sub.http_note));
        } else if sub.resolved.is_empty() {
            log.push_str(&format!("  ❌ {} — {}\n", sub.service, sub.http_note));
        } else {
            log.push_str(&format!(
                "  ❌ {} — {}. IP {} реально не открывают HTTPS (RST/таймаут — блок по SNI, а не DNS)\n",
                sub.service,
                sub.http_note,
                sub.resolved.join(", ")
            ));
        }
    }

    // Строки hosts берём из ЕДИНОГО места — `site_probe::hosts_entries`, того же,
    // что использует блок «ВЕРОЯТНАЯ ПРИЧИНА». Раньше список собирался здесь
    // отдельно и всегда подставлял `www.<host>` — для домена, который сам
    // начинается с `www.`, это давало несуществующее имя `www.www.…`.
    let entries = probe.map(site_probe::hosts_entries).unwrap_or_default();
    let opens_by_name = probe
        .map(|p| !p.verdict.site_broken() || p.verdict.needs_address_fix())
        .unwrap_or(false);

    if !entries.is_empty() {
        log.push_str(&format!(
            "  → ПРОВЕРЕННЫЙ АДРЕС НАЙДЕН. {}\n",
            if opens_by_name {
                "Сайт открывается по нему — если в браузере всё ещё не открывается, пропишите адрес в hosts:"
            } else {
                "Добавьте в hosts (C:\\Windows\\System32\\drivers\\etc\\hosts):"
            }
        ));
        for line in &entries {
            log.push_str(&format!("      {}\n", line));
        }
        log.push_str("    Затем выполните: ipconfig /flushdns\n");
    } else {
        // Не советуем hosts, если ни один IP не дал валидного HTTPS: подсказка
        // «пропишите IP вручную» без доказанного рабочего адреса бесполезна.
        log.push_str("  → ПОДМЕНА DNS НЕ ПОМОГЛА: ни один из найденных IP не отдал валидный HTTPS-ответ для этого имени.\n");
        log.push_str("    Смена DNS и запись в hosts тут не помогут — ищите причину в блоке «ВЕРОЯТНАЯ ПРИЧИНА» выше.\n");
    }
    log.push('\n');
}

fn write_need_bypass(log: &mut String, c: &Classification) {
    log.push_str("🛡️ ДОМЕНЫ, КОТОРЫЕ НУЖНО ДОБАВИТЬ В ОБХОД (general-лист):\n");
    if c.need_bypass.is_empty() {
        log.push_str("  - (пусто) новых доменов для обхода не найдено\n");
    } else {
        let bypass_map = bypass_lists::load_bypass_domains();
        let path = general_list_path();
        let mut parent_suggestions: Vec<String> = Vec::new();
        for h in &c.need_bypass {
            // Если домен уже покрыт обходом (например, родителем) — не советуем дублировать.
            let already = !bypass_lists::find_bypass_matches(std::slice::from_ref(h), &bypass_map).is_empty();
            let parent = bypass_lists::parent_domain(h);
            let kind = if parent == h.to_lowercase() {
                "[корневой домен]".to_string()
            } else {
                format!("[субдомен, родитель: {}]", parent)
            };
            let action = if already {
                "уже покрыт обходом — не дублируйте".to_string()
            } else {
                if parent != h.to_lowercase() && !parent_suggestions.contains(&parent) {
                    parent_suggestions.push(parent.clone());
                }
                format!("добавьте в {}", path)
            };
            log.push_str(&format!("  - {}   {}   {}\n", h, kind, action));
        }
        if !parent_suggestions.is_empty() {
            parent_suggestions.sort();
            log.push_str(&format!(
                "  💡 Родительские домены (winws матчит поддомены, можно сократить список): {}\n",
                parent_suggestions.join(", ")
            ));
        }
    }
    log.push('\n');
}

fn write_bypass_breaks(log: &mut String, c: &Classification) {
    log.push_str("❌ ДОМЕНЫ, КОТОРЫЕ ЛОМАЕТ ОБХОД (добавьте в исключения):\n");
    if c.bypass_breaks.is_empty() {
        log.push_str("  - (пусто) обход не ломает ни один домен\n");
    } else {
        let exclude_set = bypass_lists::load_exclude_domains();
        let mut parent_suggestions: Vec<String> = Vec::new();
        for (h, err) in &c.bypass_breaks {
            let reason = err.lines().next().unwrap_or(err);
            let parent = bypass_lists::parent_domain(h);
            let kind = if parent == h.to_lowercase() {
                "[корневой домен]".to_string()
            } else {
                format!("[субдомен, родитель: {}]", parent)
            };
            let covered = bypass_lists::is_excluded(h, &exclude_set);
            let action = match covered {
                Some(entry) => format!("уже в исключениях: {} — не дублируйте", entry),
                None => {
                    if parent != h.to_lowercase() && !parent_suggestions.contains(&parent) {
                        parent_suggestions.push(parent.clone());
                    }
                    "добавьте в исключения".to_string()
                }
            };
            log.push_str(&format!(
                "  - {}   (причина: {})   {}   {}\n",
                h, reason, kind, action
            ));
        }
        if !parent_suggestions.is_empty() {
            parent_suggestions.sort();
            log.push_str(&format!(
                "  💡 Родительские домены (winws матчит поддомены, можно сократить список): {}\n",
                parent_suggestions.join(", ")
            ));
        }
    }
    log.push('\n');
}

/// Домены, которые не открылись при ВЫКЛЮЧЕННОМ обходе. Отличить «заблокирован
/// сам» от «обход его ломает» в этом прогоне нельзя, поэтому не советуем
/// исключения — а просим прогнать анализ с включённым профилем.
fn write_broken(log: &mut String, meta: &ReportMeta, c: &Classification) {
    if c.broken.is_empty() {
        return;
    }
    log.push_str("⛔ НЕДОСТУПНЫЕ ДОМЕНЫ (причина не установлена):\n");
    for h in &c.broken {
        let parent = bypass_lists::parent_domain(h);
        let kind = if parent == h.to_lowercase() {
            "[корневой домен]".to_string()
        } else {
            format!("[субдомен, родитель: {}]", parent)
        };
        log.push_str(&format!("  - {}   {}\n", h, kind));
    }
    if meta.bypass_on {
        log.push_str("  ℹ️ Не открываются даже с включённым обходом — но без обхода не проверялись.\n");
    } else {
        log.push_str("  ℹ️ Обход был ВЫКЛЮЧЕН, поэтому «ломает обход или домен сам» — непонятно. Включите профиль обхода и запустите анализ снова: тогда станет видно, что чинить (обход или исключения).\n");
    }
    log.push_str("  ℹ️ Если такие домены — поддомены вашего главного домена, сначала посмотрите блок «ВЕРОЯТНАЯ ПРИЧИНА» выше: возможно, у сайта просто не настроены адреса для этих имён.\n");
    log.push('\n');
}

/// Статус домена из списка обхода — строго по результатам проб.
///
/// Раньше здесь стояла константа «работает, трогать не обязательно»: она
/// печаталась всегда, стоило домену просто лежать в списке, и домены, которые
/// в момент анализа не открывались, отчитывались как исправные. Теперь
/// формулировка выводится из корзин реальной классификации, а непроверенный
/// домен честно помечается как непроверенный.
fn bypass_entry_verdict(domain: &str, c: &Classification) -> String {
    let broken = c
        .bypass_breaks
        .iter()
        .any(|(h, _)| h == domain)
        || c.broken.iter().any(|h| h == domain);
    let ok = c.ok.iter().any(|h| h == domain);
    let dns = c.dns_fail.iter().any(|h| h == domain);
    let need = c.need_bypass.iter().any(|h| h == domain);

    // Порядок важен: сначала «ломал сайт», потом «не открылся», и только
    // потом «работает» — иначе домен, сломанный обходом, был бы помечен
    // исправным.
    if broken {
        "ЛОМАЕТ САЙТ, проверьте обход для этого домена".to_string()
    } else if ok {
        "проверен, сайт открывается".to_string()
    } else if dns {
        "не резолвится (проверено, домен в обходе не поможет)".to_string()
    } else if need {
        "не открывается, остаётся в обходе".to_string()
    } else {
        "этим прогоном не проверялся".to_string()
    }
}

fn write_already_in_bypass(log: &mut String, meta: &ReportMeta, c: &Classification) {
    let bypass_map = bypass_lists::load_bypass_domains();
    let bypass_matches = bypass_lists::find_bypass_matches(&meta.discovered, &bypass_map);

    log.push_str("🗑️ ДОМЕНЫ САЙТА, УЖЕ ВНЕСЁННЫЕ В ОБХОД (проверьте, не ломают ли они сайт):\n");
    if bypass_matches.is_empty() {
        log.push_str("  - (пусто) ни один домен сайта не найден в списках обхода\n");
    } else {
        for (domain, files) in &bypass_matches {
            let mut labels: Vec<String> = Vec::new();
            for f in files {
                let path = f.to_string_lossy().replace("\\", "/");
                if is_builtin(f) {
                    labels.push(format!("встроенный список {}", path));
                } else {
                    labels.push(format!("список обхода {}", path));
                }
            }
            let builtin = if files.first().map(is_builtin).unwrap_or(false) {
                " (встроенный, перезаписывается при запуске)"
            } else {
                ""
            };
            let where_ = format!("{}{}", labels.join(", "), builtin);
            let verdict = bypass_entry_verdict(domain, c);

            log.push_str(&format!("  - {}   (в {} — {})\n", domain, where_, verdict));
        }
    }
    log.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer_probe::Classification;
    use crate::diagnostics_probe::{DnsInfo, DnsState};
    use crate::site_probe::{DomainProbe, IpSource};
    use crate::site_verdict::{CauseContext, Verdict};

    fn empty_classification() -> Classification {
        Classification {
            need_bypass: Vec::new(),
            bypass_breaks: Vec::new(),
            dns_fail: Vec::new(),
            ok: Vec::new(),
            broken: Vec::new(),
        }
    }

    fn meta_with(probe: DomainProbe) -> ReportMeta {
        ReportMeta {
            target_url: "https://cactuscompute.com/blog/whistle".to_string(),
            discovered: vec!["cactuscompute.com".to_string()],
            bypass_on: true,
            bypass_toggled: false,
            restore_note: None,
            had_browser_failures: false,
            main_probe: Some(probe),
            main_dns_sub: Vec::new(),
            dns_fail_sub: Vec::new(),
        }
    }

    /// Apex DNS points at a dead IP; the site answers only under `www`.
    fn www_only_probe() -> DomainProbe {
        let host = "cactuscompute.com";
        let www_url = "https://www.cactuscompute.com/";
        let verdict = Verdict::WwwOnly;
        let diagnosis = crate::site_verdict::explain(
            verdict,
            &CauseContext {
                host,
                www_url: Some(www_url),
                apex_ip: Some("216.150.1.1"),
                dns_spoofed: false,
                doh_working_ip: None,
                same_host_alt_ip_works: false,
                isp_redirect: None,
            },
        );
        let mut dns = DnsInfo::new();
        dns.system = vec!["216.150.1.1".parse().unwrap()];
        DomainProbe {
            host: host.to_string(),
            dns,
            primary_ips: vec!["216.150.1.1".to_string()],
            doh_ips: vec![],
            working_ip: None,
            working_ip_source: None,
            working_http: None,
            http_note: "ни один IP не ответил на TCP:443".to_string(),
            verdict,
            www_host: Some("www.cactuscompute.com".to_string()),
            www_ips: vec!["216.150.16.65".to_string()],
            www_url: Some(www_url.to_string()),
            isp_redirect: None,
            dns_spoofed: None,
            doh_failures: vec![],
            diagnosis: Some(diagnosis),
        }
    }

    /// The point of the change: the report must lead with the cause and must
    /// name the working `www` host instead of burying it.
    #[test]
    fn report_leads_with_cause_and_mentions_www() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        let cause_pos = log.find("ВЕРОЯТНАЯ ПРИЧИНА").expect(&log);
        let domains_pos = log.find("НЕ ОТКРЫВАЕТСЯ").expect(&log);
        assert!(cause_pos < domains_pos, "{}", log);
        assert!(log.contains("www.cactuscompute.com"), "{}", log);
        assert!(log.contains("https://www.cactuscompute.com/"), "{}", log);
        // The dead IP is named explicitly, so the user understands the cause.
        assert!(log.contains("216.150.1.1"), "{}", log);
        assert!(log.contains("ЧТО СДЕЛАТЬ"), "{}", log);
        assert!(log.contains("ЧТО НЕ ПОМОЖЕТ"), "{}", log);
    }

    /// The broken hosts advice must not survive anywhere in the report.
    #[test]
    fn report_does_not_advise_hosts_for_dead_apex_ip() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        assert!(!log.contains("System32\\drivers\\etc\\hosts"), "{}", log);
        assert!(!log.contains("ipconfig /flushdns"), "{}", log);
    }

    #[test]
    fn dead_domain_is_never_advised_for_bypass() {
        let c = Classification {
            broken: vec!["cactuscompute.com".to_string()],
            ..empty_classification()
        };
let log = build_report(&meta_with(www_only_probe()), &c);
        // The domain must not be pushed into the bypass list.
        assert!(
            !log.contains("list-general.txt"),
            "dead IP must not be advised for bypass: {}",
            log
        );
        assert!(log.contains("НЕДОСТУПНЫЕ ДОМЕНЫ"), "{}", log);
    }

    /// Unreachable public resolvers must be reported as such, not as "(empty)".
    #[test]
    fn unreachable_resolvers_are_not_empty_strings() {
        let mut p = www_only_probe();
        p.dns.cloudflare_state = DnsState::Unreachable;
        p.dns.google_state = DnsState::Unreachable;
let log = build_report(&meta_with(p), &empty_classification());
        // The DNS lines must explain the empty answer instead of showing "(пусто)".
        let line = log
            .lines()
            .find(|l| l.contains("DNS (1.1.1.1)"))
            .expect("no cloudflare DNS line");
        assert!(line.contains("не ответил"), "{}", line);
        assert!(!line.contains("(пусто)"), "{}", line);
    }

    #[test]
    fn nxdomain_is_reported_as_nxdomain() {
        let mut p = www_only_probe();
        p.dns.cloudflare_state = DnsState::Nxdomain;
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("NXDOMAIN"), "{}", log);
    }

    #[test]
    fn open_site_gets_short_confirmation() {
        let mut p = www_only_probe();
        p.verdict = Verdict::Open;
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("ДОСТУПЕН"), "{}", log);
        assert!(!log.contains("ВЕРОЯТНАЯ ПРИЧИНА"), "{}", log);
    }

    // --- Regression: the report must not claim "no censorship" when the
    //     system answer was proven to disagree with DoH. ---

    #[test]
    fn spoofed_dns_is_never_reported_as_clean() {
        let mut p = www_only_probe();
        p.dns_spoofed = Some("системный DNS вернул 188.186.154.88, DoH-резолверы — 104.21.95.93, 172.67.144.20 (пересечений нет)".to_string());
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("ОБНАРУЖЕНА ПОДМЕНА DNS"), "{}", log);
        assert!(!log.contains("не обнаружена"), "{}", log);
        assert!(log.contains("UDP:53 перехвачен"), "{}", log);
        // The untrusted addresses must be called out as untrusted.
        assert!(log.contains("недостоверны"), "{}", log);
    }

    /// Ответы 1.1.1.1 и 8.8.8.8 идут по тому же перехватываемому UDP:53.
    /// Показывать их без пометки — значит выдать подменённый ответ за
    /// ответ Cloudflare/Google.
    #[test]
    fn udp_dns_lines_are_marked_untrusted_when_spoofed() {
        let mut p = www_only_probe();
        p.dns.cloudflare = vec!["188.186.154.88".parse().unwrap()];
        p.dns.google = vec!["188.186.154.88".parse().unwrap()];
        p.dns_spoofed = Some("перехват доказан".to_string());
        let log = build_report(&meta_with(p), &empty_classification());
        for line in ["DNS (1.1.1.1)", "DNS (8.8.8.8)", "DNS (система)"] {
            let l = log
                .lines()
                .find(|l| l.contains(line))
                .unwrap_or_else(|| panic!("нет строки {}", line));
            assert!(
                l.contains("UDP:53 перехвачен"),
                "{} должен быть помечен как недостоверный: {}",
                line,
                l
            );
        }
    }

    #[test]
    fn udp_dns_lines_have_no_warning_when_clean() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        assert!(
            !log.contains("ответ недостоверен"),
            "при чистом DNS предупреждение неуместно: {}",
            log
        );
    }

    /// Главная регрессия задания: адрес с BadCert печатался как
    /// «Рабочий IP … (сайт открывается)». Через такой адрес сайт НЕ открывается.
    #[test]
    fn bad_cert_ip_is_never_called_working() {
        let mut p = www_only_probe();
        p.verdict = Verdict::BadCert;
        p.working_ip = Some("188.186.154.88".to_string());
        p.working_ip_source = Some(IpSource::SystemDns);
        p.working_http = Some(HttpResult::BadCert);
        p.http_note = "HTTPS через 188.186.154.88: SSL-сертификат невалиден".to_string();
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(!log.contains("сайт открывается)"), "{}", log);
        let line = log
            .lines()
            .find(|l| l.contains("188.186.154.88") && l.contains("открытым TCP:443"))
            .expect("нет строки про адрес");
        assert!(line.contains("НЕ открывается"), "{}", line);
    }

    /// Тот же запрет для RST и таймаута.
    #[test]
    fn rst_and_timeout_ips_are_not_called_working() {
        for (res, marker) in [
            (HttpResult::Rst, "HTTPS рвётся"),
            (HttpResult::Timeout, "таймаут"),
            (HttpResult::Tls, "TLS-рукопожатие рвётся"),
        ] {
            let mut p = www_only_probe();
            p.verdict = Verdict::IpReset;
            p.working_ip = Some("1.2.3.4".to_string());
            p.working_ip_source = Some(IpSource::SystemDns);
            p.working_http = Some(res.clone());
            let line = working_ip_line(&p);
            assert!(line.contains(marker), "{:?} -> {}", res, line);
            assert!(
                !line.contains("сайт открывается"),
                "{:?} must not be reported as working: {}",
                res,
                line
            );
        }
    }

    /// Обратный случай: реальный HTTP-ответ — единственное основание назвать
    /// адрес рабочим.
    #[test]
    fn ok_http_is_the_only_reason_to_call_ip_working() {
        let mut p = www_only_probe();
        p.verdict = Verdict::Open;
        p.working_ip = Some("104.21.95.93".to_string());
        p.working_ip_source = Some(IpSource::Doh);
        p.working_http = Some(HttpResult::Ok(200));
        let line = working_ip_line(&p);
        assert!(line.contains("Рабочий IP"), "{}", line);
        assert!(line.contains("сайт открывается"), "{}", line);
        assert!(line.contains("104.21.95.93"), "{}", line);
        assert!(line.contains("через DoH"), "{}", line);
    }

    #[test]
    fn missing_working_ip_is_stated_plainly() {
        let p = www_only_probe();
        assert!(working_ip_line(&p).contains("не найден"), "{}", working_ip_line(&p));
    }

    #[test]
    fn clean_dns_says_no_discrepancy_found() {
        let log = build_report(&meta_with(www_only_probe()), &empty_classification());
        assert!(log.contains("не найдено"), "{}", log);
        assert!(!log.contains("не обнаружена"), "{}", log);
    }

    #[test]
    fn isp_redirect_is_shown_in_report() {
        let mut p = www_only_probe();
        p.verdict = Verdict::IspBlockRedirect;
        p.isp_redirect = Some("cactuscompute.com -> lawfilter.ertelecom.ru".to_string());
        let log = build_report(&meta_with(p), &empty_classification());
        assert!(log.contains("lawfilter.ertelecom.ru"), "{}", log);
        assert!(log.contains("Подмена ответа оператором"), "{}", log);
    }

    /// Полный сценарий пользователя: отравленный DNS, проверенный адрес найден
    /// через DoH. Отчёт обязан назвать первопричину, дать готовые строки hosts
    /// и нигде не сказать «невалидный сертификат».
    #[test]
    fn poisoned_dns_report_names_cause_and_gives_hosts_lines() {
        let host = "nnmclub.to";
        let verdict = Verdict::DnsBlocked;
        let diagnosis = crate::site_verdict::explain(
            verdict,
            &CauseContext {
                host,
                www_url: None,
                apex_ip: Some("188.186.146.207"),
                dns_spoofed: true,
                doh_working_ip: Some("104.21.95.93"),
                same_host_alt_ip_works: true,
                isp_redirect: None,
            },
        );
        let mut dns = DnsInfo::new();
        dns.system = vec!["188.186.146.207".parse().unwrap()];
        dns.cloudflare = vec!["188.186.146.207".parse().unwrap()];
        let probe = DomainProbe {
            host: host.to_string(),
            dns,
            primary_ips: vec!["188.186.146.207".to_string()],
            doh_ips: vec!["104.21.95.93".to_string()],
            working_ip: Some("104.21.95.93".to_string()),
            working_ip_source: Some(IpSource::Doh),
            working_http: Some(HttpResult::Ok(200)),
            http_note: "HTTPS через 104.21.95.93: HTTP 200".to_string(),
            verdict,
            www_host: Some("www.nnmclub.to".to_string()),
            www_ips: vec![],
            www_url: None,
            isp_redirect: None,
            dns_spoofed: Some("системный DNS вернул 188.186.146.207, DoH-резолверы — 104.21.95.93 (пересечений нет)".to_string()),
            doh_failures: vec!["dns.dns-ai.ru: не ответил за 9 с (таймаут)".to_string()],
            diagnosis: Some(diagnosis),
        };
        let log = build_report(&meta_with(probe), &empty_classification());

        assert!(log.contains("DNS-ПОДМЕНА"), "{}", log);
        assert!(log.contains("104.21.95.93 nnmclub.to"), "{}", log);
        assert!(log.contains("104.21.95.93 www.nnmclub.to"), "{}", log);
        assert!(log.contains("ipconfig /flushdns"), "{}", log);
        // Подменённый адрес не должен быть назван рабочим.
        assert!(
            !log.contains("Рабочий IP:          188.186.146.207"),
            "{}",
            log
        );
        assert!(log.contains("Не ответили DoH-сервисы"), "{}", log);
    }

    /// Если проверенного адреса нет — отчёт не имеет права предлагать hosts.
    #[test]
    fn report_does_not_offer_hosts_without_verified_ip() {
        let host = "nnmclub.to";
        let verdict = Verdict::DnsBlocked;
        let diagnosis = crate::site_verdict::explain(
            verdict,
            &CauseContext {
                host,
                www_url: None,
                apex_ip: Some("188.186.146.207"),
                dns_spoofed: true,
                doh_working_ip: None,
                same_host_alt_ip_works: false,
                isp_redirect: None,
            },
        );
        let mut dns = DnsInfo::new();
        dns.system = vec!["188.186.146.207".parse().unwrap()];
        let probe = DomainProbe {
            host: host.to_string(),
            dns,
            primary_ips: vec!["188.186.146.207".to_string()],
            doh_ips: vec![],
            working_ip: None,
            working_ip_source: None,
            working_http: None,
            http_note: "ни один IP не ответил на TCP:443".to_string(),
            verdict,
            www_host: Some("www.nnmclub.to".to_string()),
            www_ips: vec![],
            www_url: None,
            isp_redirect: None,
            dns_spoofed: Some("расхождение доказано".to_string()),
            doh_failures: vec![],
            diagnosis: Some(diagnosis),
        };
        let log = build_report(&meta_with(probe), &empty_classification());
        assert!(
            !log.contains("System32\\drivers\\etc\\hosts"),
            "без проверенного адреса hosts предлагать нечего: {}",
            log
        );
        assert!(log.contains("Запись в hosts сейчас не поможет"), "{}", log);
    }

    /// Regression: "работает, трогать не обязательно" was printed unconditionally.
    /// A domain that did not open must never carry that verdict.
    #[test]
    fn broken_domain_in_bypass_is_not_called_working() {
        let mut c = empty_classification();
        c.broken = vec!["site.example".to_string()];
        let v = bypass_entry_verdict("site.example", &c);
        assert!(v.contains("ЛОМАЕТ САЙТ"), "{}", v);
        assert!(!v.contains("работает"), "{}", v);
    }

    #[test]
    fn bypass_breaks_domain_is_not_called_working() {
        let mut c = empty_classification();
        c.bypass_breaks = vec![("site.example".to_string(), "сломан обходом".to_string())];
        let v = bypass_entry_verdict("site.example", &c);
        assert!(v.contains("ЛОМАЕТ САЙТ"), "{}", v);
    }

    /// Broken wins over ok: if the same domain landed in both baskets, saying
    /// "works" would hide a real breakage.
    #[test]
    fn broken_wins_over_ok() {
        let mut c = empty_classification();
        c.ok = vec!["site.example".to_string()];
        c.broken = vec!["site.example".to_string()];
        let v = bypass_entry_verdict("site.example", &c);
        assert!(v.contains("ЛОМАЕТ САЙТ"), "{}", v);
    }

    #[test]
    fn probed_working_domain_is_reported_working() {
        let mut c = empty_classification();
        c.ok = vec!["site.example".to_string()];
        let v = bypass_entry_verdict("site.example", &c);
        assert!(v.contains("открывается"), "{}", v);
    }

    #[test]
    fn unverified_domain_in_bypass_is_not_called_working() {
        // Nothing was probed for this domain, so the report must not claim it
        // works — "не проверялся" is the only honest wording.
        let v = bypass_entry_verdict("site.example", &empty_classification());
        assert!(v.contains("не проверялся"), "{}", v);
        assert!(!v.contains("работает"), "{}", v);
    }
}