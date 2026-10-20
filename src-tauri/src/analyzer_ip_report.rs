//! Отчёт IP-режима для вкладки «Анализ сайта / IP».
//!
//! Модуль ничего не решает сам: факты собирает `ip_probe`, а здесь только
//! их сложение в текст. Правила честности (core rules §1.11, §2.2):
//!  - вердикты только из реальных проб: TCP двух фаз + SNI-эксперимент
//!    по кандидатам (HTTPS к домену, прибитый к целевому IP);
//!  - HTTPS-проба к самому IP (SNI=IP) в вердикты НЕ входит: фронт по такому
//!    SNI может не давать рукопожатие и в здоровой сети — из неё ничего
//!    не доказать (урок живого кейса 172.65.90.21);
//!  - кандидаты по SNI — «подозреваемые», а не «причина установлена»,
//!    пока они не подтверждены двухфазным SNI-экспериментом;
//!  - неполный резолв прямо называется неполным («перезапустите анализ»);
//!  - ipset/ipset-exclude вырезаются `resolve_args` при запуске winws,
//!    поэтому никаких советов вокруг ipset — только hostlist-исключения.

use std::net::IpAddr;

use crate::analyzer_probe::Probe;
use crate::config;
use crate::ip_probe::{IpFacts, TcpProbeResult, probe_is_ok};

/// Путь к hostlist-исключениям (тот же файл, что советует доменный отчёт).
fn exclude_list_path() -> String {
    config::get_app_dir()
        .join("lists")
        .join("list-exclude.txt")
        .to_string_lossy()
        .replace("\\", "/")
}

fn tcp_label(p: &TcpProbeResult) -> String {
    match p {
        TcpProbeResult::Ok => "TCP: OK".to_string(),
        TcpProbeResult::Broken(e) => format!("TCP: обрыв ({})", first_line(e)),
        TcpProbeResult::DeadIp => "TCP: сервер не отвечает".to_string(),
    }
}

/// Короткая метка SNI-пробы (Probe уже транспортная семантика).
fn sni_label(p: Option<&Probe>) -> String {
    match p {
        None => "не выполнялась".to_string(),
        Some(Probe::Ok) => "OK".to_string(),
        Some(Probe::Broken(e)) => format!("обрыв ({})", first_line(e)),
        Some(Probe::DeadIp) => "сервер молчит".to_string(),
        Some(Probe::Dns) => "DNS-ошибка".to_string(),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

/// SNI-эксперимент подтвердил виновника: без обхода путь цел, с обходом рвётся.
fn sni_confirmed(off: Option<&Probe>, on: Option<&Probe>) -> bool {
    matches!(off, Some(Probe::Ok)) && matches!(on, Some(Probe::Broken(_)))
}

/// SNI-путь прошёл в обеих фазах — кандидат исключается.
fn sni_survived(off: Option<&Probe>, on: Option<&Probe>) -> bool {
    matches!(off, Some(Probe::Ok)) && matches!(on, Some(Probe::Ok))
}

pub fn build_ip_report(ip: IpAddr, port: u16, f: &IpFacts) -> String {
    let mut log = String::new();
    log.push_str(&format!("=== АНАЛИЗ IP-АДРЕСА: {}:{} ===\n\n", ip, port));

    // Контекст обхода.
    if f.bypass_was_running {
        log.push_str("ℹ️ Обход (winws) в момент анализа: ВКЛЮЧЁН. На время проб он временно останавливался (чистый DNS + контрольные проба).\n");
    } else {
        log.push_str("⚠️ Обход (winws) в момент анализа: ВЫКЛЮЧЕН. Чтобы понять, ломает ли обход этот адрес, включите профиль обхода и запустите анализ снова.\n");
    }
    if f.toggled {
        log.push_str("ℹ️ Обход был временно остановлен для контрольных проб и вернулся после анализа.\n");
    }
    if let Some(note) = &f.restore_note {
        log.push_str(&format!("{}\n", note));
    }
    log.push('\n');

    // Матрица TCP (только TCP! HTTPS-проба к IP недоказательна — см. ниже).
    log.push_str(&format!("🔍 ПРОВЕРКА TCP-СОЕДИНЕНИЯ к {}:{}:\n", ip, port));
    if let Some(on) = &f.probe_on {
        log.push_str(&format!("  С обходом:    {}\n", tcp_label(&on.tcp)));
    }
    if let Some(off) = &f.probe_off {
        log.push_str(&format!("  Без обхода:   {}\n", tcp_label(&off.tcp)));
    }
    log.push_str(
        "  ℹ️ HTTPS-проба к самому IP (SNI=IP) в вердикты не входит: сервер-фронт по такому\n  SNI может не давать рукопожатие и в здоровой сети — из неё ничего не доказать.\n",
    );
    log.push('\n');

    // Вердикт — только из TCP-фактов и SNI-эксперимента.
    let confirmed: Option<&crate::ip_candidates::Candidate> = f
        .candidates
        .iter()
        .find(|c| sni_confirmed(c.sni_off.as_ref(), c.sni_on.as_ref()));
    match (&f.probe_on, &f.probe_off) {
        (Some(on), Some(off)) => {
            let on_ok = probe_is_ok(on);
            let off_ok = probe_is_ok(off);
            if !on_ok && off_ok {
                log.push_str(&format!("❌ ВЕРДИКТ: обход рвёт TCP-соединение к {}:{} (обрыв с обходом, живой без него). Причина — в обходе.\n\n", ip, port));
            } else if !on_ok && !off_ok {
                log.push_str(&format!("⛔ ВЕРДИКТ: к {}:{} нет TCP даже без обхода — сервер не принимает соединения (или он недоступен сам по себе). Причина не в обходе.\n\n", ip, port));
            } else if on_ok && !off_ok {
                log.push_str("❓ ВЕРДИКТ: неожиданное состояние (с обходом живо, без обхода рвётся) — возможно, сеть изменилась между пробами, повторите анализ.\n\n");
            } else {
                log.push_str(&format!("✅ TCP-УРОВЕНЬ: обход TCP к {}:{} не мешает.\n\n", ip, port));
                match confirmed {
                    Some(c) => {
                        log.push_str(&format!("❌ ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ: hostlist-домен «{}» — SNI-эксперимент подтвердил (без обхода путь цел, с обходом рвётся). Соединения с этим SNI попадают в hostlist-стратегию и рвутся.\n\n", c.domain));
                    }
                    None => {
                        if f.candidates.iter().any(|c| sni_survived(c.sni_off.as_ref(), c.sni_on.as_ref())) {
                            log.push_str("ℹ️ SNI-эксперимент: кандидаты с обходом прошли — они не виновники. Вероятные причины — вне SNI-профилей (UDP/QUIC-фильтры, глобальные приёмы профиля).\n\n");
                        } else if f.candidates.is_empty() {
                            // Полная честность про неполный резолв.
                            if f.resolve_failed > 0 || f.resolve_budget_hit {
                                log.push_str(&format!(
                                    "⚠️ АНАЛИЗ НЕПОЛНЫЙ: последнего виновника не видно, потому что резолв списка не доехал (проверено {} из {}{}). Перезапустите анализ для полной проверки.\n\n",
                                    f.resolve_done,
                                    f.resolve_total,
                                    if f.resolve_failed > 0 { format!(", не резолвнулось: {}", f.resolve_failed) } else { String::new() }
                                ));
                            } else {
                                log.push_str("ℹ️ Кандидатов в списках обхода не нашлось: hostlist-матч к этому IP невозможен. Вероятные причины — вне SNI-профилей.\n\n");
                            }
                        } else {
                            log.push_str("❓ SNI-эксперимент не дал однозначного ответа (соединение рвётся и без обхода у кандидатов либо фаза с обходом не завершилась).\n\n");
                        }
                    }
                }
            }
        }
        _ => {
            log.push_str("❓ ВЕРДИКТ: сравнение «с обходом / без обхода» не проводилось — обход был выключен. Включите профиль обхода и запустите анализ снова.\n\n");
        }
    }

    // SNI-эксперимент по кандидатам.
    if !f.candidates.is_empty() {
        log.push_str(&format!(
            "🔬 SNI-ЭКСПЕРИМЕНТ — HTTPS к «https://домен/» (реюз клиентского пути: SNI доменный, транспорт прибит к {}):\n",
            ip
        ));
        for c in &f.candidates {
            let files: Vec<String> = c
                .files
                .iter()
                .map(|p| p.to_string_lossy().replace("\\", "/"))
                .collect();
            let excl_note = match &c.already_excluded {
                Some(e) => format!(" [УЖЕ в list-exclude — \"{}\"]", e),
                None => String::new(),
            };
            log.push_str(&format!(
                "  - {}{}   (в {})\n",
                c.domain,
                excl_note,
                files.join(", ")
            ));
            log.push_str(&format!(
                "      без обхода: {} | с обходом: {} | DNS-адреса: {}\n",
                sni_label(c.sni_off.as_ref()),
                sni_label(c.sni_on.as_ref()),
                c.ips.join(", ")
            ));
            if sni_confirmed(c.sni_off.as_ref(), c.sni_on.as_ref()) {
                log.push_str("      🎯 ЛОМАЕТСЯ ОБХОДОМ — главный подозреваемый, подтверждено экспериментом.\n");
            } else if matches!(c.sni_off, Some(Probe::Ok)) && matches!(c.sni_on, Some(Probe::Ok)) {
                log.push_str("      не виновник: SNI-путь цел даже с обходом.\n");
            } else if !matches!(c.sni_off, Some(Probe::Ok) | None) {
                log.push_str("      домен и без обхода не отвечает (серверная сторона) — к обходу не относится.\n");
            } else if c.sni_on.is_none() {
                log.push_str("      фаза «с обходом» не выполнялась (обход не возвращался/был выключен) — эксперимент не завершён.\n");
            }
        }
        let new_candidates = f.candidates.iter().any(|c| c.already_excluded.is_none());
        let all_excluded = f.candidates.iter().all(|c| c.already_excluded.is_some());
        if new_candidates {
            log.push_str(&format!(
                "  💡 Если обход ломает соединения с SNI этих доменов — внесите их в {} (hostlist-исключения, они выводят соединения из-под стратегии).\n",
                exclude_list_path()
            ));
        }
        if all_excluded {
            log.push_str("  ⚠️ Все кандидаты уже в list-exclude — если обрыв продолжается, исключение не подхватилось (проверьте файл и перезапустите обход) либо виновник другой.\n");
        }
    }
    log.push('\n');

    // Абзац про ipset: честная цена текущей конфигурации.
    log.push_str("ℹ️ ipset/ipset-exclude не используются приложением: при запуске winws оба аргумента вырезаются (resolve_args), так что советы вокруг них ничего не изменят. Работающая механика исключений — hostlist (list-exclude.txt).\n");

    // IP-литералы в списках: winws hostlist их не матчит.
    if !f.ip_literals.is_empty() {
        log.push_str("🗑️ IP-ЗАПИСИ В СПИСКАХ ОБХОДА (hostlist по ним НЕ матчит — матч только по имени):\n");
        for (lit, files) in &f.ip_literals {
            let files: Vec<String> = files
                .iter()
                .map(|p| p.to_string_lossy().replace("\\", "/"))
                .collect();
            log.push_str(&format!("  - {}   (в {})\n", lit, files.join(", ")));
        }
        log.push_str("  Такие записи можно заменить/удалить вручную — автоматически списки не меняются.\n");
    }

    // Статистика резолва (честность: сколько успели проверить).
    if f.resolve_budget_hit {
        log.push_str(&format!(
            "⚠️ Фаза резолва списков прервана по бюджету: проверено {} из {} записей.\n",
            f.resolve_done, f.resolve_total
        ));
    }
    if f.resolve_failed > 0 {
        log.push_str(&format!(
            "⚠️ У {} записей резолв не удался (таймаут/ошибка DNS) — они остались НЕпроверенными, и среди них могут быть виновники. Перезапустите анализ, чтобы доделать проверку.\n",
            f.resolve_failed
        ));
    }

    log.push_str("\n💡 СОВЕТ: подтверждённого подозреваемого внесите в list-exclude.txt и повторите соединение с включённым обходом. Если кандидатов нет — смотрите варианты в блоке выше и перезапустите анализ при неполном резолве.\n");

    log
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_candidates::Candidate;
    use crate::ip_probe::IpFacts;
    use std::path::PathBuf;

    fn ip() -> IpAddr {
        "172.65.90.21".parse().unwrap()
    }

    fn probe(ok: bool) -> crate::ip_probe::IpProbe {
        crate::ip_probe::IpProbe {
            tcp: if ok { TcpProbeResult::Ok } else { TcpProbeResult::Broken("rst".to_string()) },
        }
    }

    fn facts(on: Option<bool>, off: Option<bool>) -> IpFacts {
        IpFacts {
            bypass_was_running: on.is_some(),
            probe_on: on.map(probe),
            probe_off: off.map(probe),
            toggled: on.is_some(),
            ..Default::default()
        }
    }

    fn cand(domain: &str, off: Option<Probe>, on: Option<Probe>) -> Candidate {
        Candidate {
            domain: domain.to_string(),
            files: vec![PathBuf::from("lists/list-general.txt")],
            ips: vec!["172.65.90.21".to_string()],
            already_excluded: None,
            sni_off: off,
            sni_on: on,
        }
    }

    #[test]
    fn bypass_breaks_tcp_verdict() {
        let log = build_ip_report(ip(), 443, &facts(Some(false), Some(true)));
        assert!(log.contains("обход рвёт TCP"), "{}", log);
    }

    #[test]
    fn tcp_dead_both_ways_is_not_bypass_fault() {
        let log = build_ip_report(ip(), 443, &facts(Some(false), Some(false)));
        assert!(log.contains("Причина не в обходе"), "{}", log);
    }

    #[test]
    fn healthy_tcp_confirmed_candidate_named() {
        let mut f = facts(Some(true), Some(true));
        f.candidates.push(cand(
            "example.org",
            Some(Probe::Ok),
            Some(Probe::Broken("rst".to_string())),
        ));
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ"), "{}", log);
        assert!(log.contains("example.org"), "{}", log);
        assert!(log.contains("ЛОМАЕТСЯ ОБХОДОМ"), "{}", log);
    }

    #[test]
    fn healthy_tcp_sni_survived_means_not_the_cause() {
        let mut f = facts(Some(true), Some(true));
        f.candidates.push(cand("example.org", Some(Probe::Ok), Some(Probe::Ok)));
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("не виновни"), "{}", log);
        assert!(!log.contains("ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ"), "{}", log);
    }

    #[test]
    fn incomplete_resolve_is_named_plainly() {
        let mut f = facts(Some(true), Some(true));
        f.resolve_done = 344;
        f.resolve_total = 1010;
        f.resolve_failed = 136;
        f.resolve_budget_hit = true;
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("АНАЛИЗ НЕПОЛНЫЙ"), "{}", log);
        assert!(log.contains("344 из 1010"), "{}", log);
        assert!(log.contains("136"), "{}", log);
    }

    #[test]
    fn no_candidates_and_complete_resolve_says_no_hostlist_match() {
        let mut f = facts(Some(true), Some(true));
        f.resolve_done = 1010;
        f.resolve_total = 1010;
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("hostlist-матч к этому IP невозможен"), "{}", log);
        assert!(!log.contains("АНАЛИЗ НЕПОЛНЫЙ"), "{}", log);
    }

    #[test]
    fn incomplete_experiment_when_bypass_was_off() {
        let mut f = facts(None, Some(true));
        f.toggled = false;
        f.candidates.push(cand("example.org", Some(Probe::Ok), None));
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("эксперимент не завершён"), "{}", log);
        assert!(log.contains("ВЫКЛЮЧЕН"), "{}", log);
    }

    #[test]
    fn candidate_off_broken_is_server_side() {
        let mut f = facts(Some(true), Some(true));
        f.candidates.push(cand(
            "dead.org",
            Some(Probe::DeadIp),
            Some(Probe::DeadIp),
        ));
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("серверная сторона"), "{}", log);
        assert!(!log.contains("ЛОМАЕТСЯ ОБХОДОМ"), "{}", log);
    }

    #[test]
    fn tls_to_ip_note_present_matrix_has_no_https_lines() {
        let log = build_ip_report(ip(), 443, &facts(Some(true), Some(true)));
        assert!(log.contains("SNI=IP"), "{}", log);
        assert!(!log.contains("HTTPS: обрыв"), "{}", log);
    }

    #[test]
    fn port_is_mentioned_and_exclude_advice_present() {
        let mut f = facts(Some(true), Some(true));
        f.candidates.push(cand("example.org", Some(Probe::Ok), Some(Probe::Broken("x".into()))));
        let log = build_ip_report(ip(), 8443, &f);
        assert!(log.contains(":8443"), "{}", log);
        assert!(log.contains("list-exclude.txt"), "{}", log);
    }

    #[test]
    fn never_recommends_ipset_exclude_or_www_ip() {
        let mut f = facts(Some(true), Some(true));
        f.candidates.push(cand("example.org", Some(Probe::Ok), Some(Probe::Broken("x".into()))));
        let log = build_ip_report(ip(), 443, &f);
        let low = log.to_lowercase();
        assert!(!low.contains("ipset-exclude —"), "{}", log);
        assert!(!low.contains("www.172.65.90.21"), "{}", log);
        assert!(!low.contains("родитель:"), "{}", log);
    }

    #[test]
    fn ip_literals_listed_with_do_not_match_note() {
        let mut f = facts(Some(true), Some(true));
        f.ip_literals.push(("1.2.3.4".to_string(), vec![PathBuf::from("lists/list-general.txt")]));
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("НЕ матчит"), "{}", log);
        assert!(log.contains("1.2.3.4"), "{}", log);
    }

    #[test]
    fn already_excluded_candidate_not_advised_again() {
        let mut f = facts(Some(true), Some(true));
        let mut c = cand("example.org", Some(Probe::Ok), Some(Probe::Ok));
        c.already_excluded = Some("example.org".to_string());
        f.candidates.push(c);
        let log = build_ip_report(ip(), 443, &f);
        assert!(log.contains("УЖЕ в list-exclude"), "{}", log);
        assert!(log.contains("не подхватилось"), "{}", log);
        assert!(!log.contains("💡 Если обход ломает"), "{}", log);
    }
}
