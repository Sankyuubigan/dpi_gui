use std::collections::HashSet;
use std::path::PathBuf;

use crate::analyzer_probe::Classification;
use crate::bypass_lists;
use crate::site_probe::{self, Verdict as SiteVerdict};

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

    // Самый важный блок — диагноз главного домена, если сайт не открывается.
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

fn write_main_domain(log: &mut String, meta: &ReportMeta) {
    let probe = match &meta.main_probe {
        Some(p) => p,
        None => return,
    };

    if probe.verdict == SiteVerdict::Open {
        log.push_str(&format!(
            "🌐 ГЛАВНЫЙ ДОМЕН «{}» ОТКРЫВАЕТСЯ ({}).\n",
            probe.host, probe.http_note
        ));
        log.push('\n');
        return;
    }

    let icon = match probe.verdict {
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

    let sys = if probe.dns.system.is_empty() {
        "(пусто)".to_string()
    } else {
        probe.dns.system.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
    };
    let cf = if probe.dns.cloudflare.is_empty() {
        "(пусто)".to_string()
    } else {
        probe.dns.cloudflare.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
    };
    let gg = if probe.dns.google.is_empty() {
        "(пусто)".to_string()
    } else {
        probe.dns.google.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
    };
    log.push_str(&format!("  DNS (система):      {}\n", sys));
    log.push_str(&format!("  DNS (1.1.1.1):      {}\n", cf));
    log.push_str(&format!("  DNS (8.8.8.8):      {}\n", gg));
    log.push_str(&format!("  DNS-цензура:        {}\n", if probe.dns_consistent { "не обнаружена" } else { "ПОДОЗРЕНИЕ НА ЦЕНЗУРУ" }));
    let prim = if probe.primary_ips.is_empty() { "(пусто)".to_string() } else { probe.primary_ips.join(", ") };
    let alt = if probe.alt_ips.is_empty() { "(пусто)".to_string() } else { probe.alt_ips.join(", ") };
    log.push_str(&format!("  IP (системный DNS): {}\n", prim));
    log.push_str(&format!("  IP (www + DoH):     {}\n", alt));
    log.push_str(&format!("  Соединение главного IP:    {}\n", probe.http_note));
    if let Some(ip) = &probe.working_ip {
        // «Рабочий IP» в probe_domain — это прошедший TCP:443, но это НЕ значит,
        // что HTTPS открывается. Даём честную формулировку.
        let status = if probe.http_note.contains("RST") {
            "TCP:443 жив, но HTTPS RST — блок по SNI/IP, подмена в hosts не поможет"
        } else if probe.http_note.contains("таймаут") || probe.http_note.contains("timeout") {
            "TCP:443 жив, HTTPS таймаут"
        } else {
            "TCP:443 жив"
        };
        log.push_str(&format!("  Рабочий IP:          {} ({})\n", ip, status));
    } else {
        log.push_str("  Рабочий IP:          не найден\n");
    }

    log.push_str("  → РЕКОМЕНДАЦИИ:\n");
    for r in &probe.recommendation {
        log.push_str(&format!("    {}\n", r));
    }
    log.push('\n');
}

fn write_dns_substitution(log: &mut String, meta: &ReportMeta) {
    if meta.main_dns_sub.is_empty() {
        return;
    }
    let host = meta.main_probe.as_ref().map(|p| p.host.clone()).unwrap_or_default();

    log.push_str("🔁 ПРОВЕРКА ПОДМЕНЫ DNS (обход отравленного DNS через DoH):\n");
    for sub in &meta.main_dns_sub {
        if sub.http_ok {
            log.push_str(&format!("  ✅ {} — {}\n", sub.service, sub.http_note));
        } else {
            if sub.resolved.is_empty() {
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
    }
    if let Some(sub) = meta.main_dns_sub.iter().find(|s| s.http_ok) {
        log.push_str("  → ПОДМЕНА DNS РАБОТАЕТ. Сайт открывается через рабочий IP.\n");
        if !host.is_empty() {
            if let Some(ip) = &sub.working_ip {
                log.push_str("    Добавьте в hosts (C:\\Windows\\System32\\drivers\\etc\\hosts):\n");
                log.push_str(&format!("      {} {}\n", ip, host));
                log.push_str(&format!("      {} www.{}\n", ip, host));
            }
        }
        log.push_str("    Затем выполните: ipconfig /flushdns\n");
    } else {
        log.push_str("  → Подмена DNS не помогла: даже через «живые» по TCP IP сайт на HTTPS рвётся (RST/страница блокировки). Это блок на уровне IP/SNI, а не DNS — решается обходом (winws), а не сменой DNS. hosts-подмена тут бесполезна.\n");
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
    log.push('\n');
}

fn write_already_in_bypass(log: &mut String, meta: &ReportMeta, c: &Classification) {
    let bypass_map = bypass_lists::load_bypass_domains();
    let bypass_matches = bypass_lists::find_bypass_matches(&meta.discovered, &bypass_map);
    let broken_set: HashSet<String> = c.bypass_breaks.iter().map(|(h, _)| h.clone()).collect();

    log.push_str("🗑️ ДОМЕНЫ САЙТА, УЖЕ ВНЕСЁННЫЕ В ОБХОД (проверьте, не ломают ли они сайт):\n");
    if bypass_matches.is_empty() {
        log.push_str("  - (пусто) ни один домен сайта не найден в списках обхода\n");
    } else {
        for (domain, files) in &bypass_matches {
            let also_broken = broken_set.contains(domain);
            let mut labels: Vec<String> = Vec::new();
            for f in files {
                let path = f.to_string_lossy().replace("\\", "/");
                if is_builtin(f) {
                    labels.push(format!("встроенный список {}", path));
                } else {
                    labels.push(format!("список обхода {}", path));
                }
            }
            if also_broken {
                log.push_str(&format!(
                    "  - {}   (в {} — ЛОМАЕТ САЙТ, удалите из обхода в приоритете!)\n",
                    domain,
                    labels.join(", ")
                ));
            } else if is_builtin(files.first().unwrap()) {
                log.push_str(&format!(
                    "  - {}   (в {} — встроенный, перезаписывается при запуске; работает, трогать не обязательно)\n",
                    domain,
                    labels.join(", ")
                ));
            } else {
                log.push_str(&format!(
                    "  - {}   (в {} — работает, трогать не обязательно)\n",
                    domain,
                    labels.join(", ")
                ));
            }
        }
    }
    log.push('\n');
}
