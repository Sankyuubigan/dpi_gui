use std::collections::BTreeSet;
use crate::diagnostics_probe::DnsInfo;
use crate::diagnostics_techniques::TechniqueSpec;

/// Компактный отпечаток соединения для разработчика (легко копировать/вставлять).
pub fn build_fingerprint(
    admin: bool,
    windivert_ok: bool,
    ipv6: bool,
    dns: &DnsInfo,
    connect: &str,
    tls: &str,
    quic: &str,
    passed: &[String],
) -> String {
    let join = |v: &[std::net::IpAddr]| -> String {
        v.iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "ADMIN={} WINDIVERT={} IPv6={} | DNS_SYS=[{}] DNS_1_1=[{}] DNS_8_8=[{}] | CONNECT_443={} TLS={} QUIC={} | TECH_PASS=[{}]",
        if admin { "1" } else { "0" },
        if windivert_ok { "OK" } else { "FAIL" },
        if ipv6 { "1" } else { "0" },
        join(&dns.system),
        join(&dns.cloudflare),
        join(&dns.google),
        connect,
        tls,
        quic,
        passed.join(",")
    )
}

/// Человекочитаемая рекомендация на основе собранных сигналов.
pub fn build_recommendation(
    admin: bool,
    winws_present: bool,
    windivert_ok: bool,
    windivert_detail: &str,
    ipv6: bool,
    dns: &DnsInfo,
    connect: &str,
    tls: &str,
    passed: &[String],
    profile_saved: bool,
    verified: Option<bool>,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    if !admin {
        lines.push("🔴 Запустите приложение от имени Администратора — WinDivert требует прав.".into());
    }
    if !winws_present {
        lines.push("🔴 Отсутствует bin/winws.exe рядом с приложением. Переустановите программу.".into());
    }
    if !windivert_ok {
        lines.push(format!(
            "🔴 Драйвер WinDivert не загружается ({}). Добавьте приложение/WinDivert в исключения антивируса, переустановите драйвер (перезапуск от админа).",
            windivert_detail
        ));
    }

    // DNS (сравниваем как МНОЖЕСТВА, а не покординатно — порядок не важен)
    let to_set = |v: &[std::net::IpAddr]| -> BTreeSet<std::net::IpAddr> {
        v.iter().copied().collect()
    };
    let sys_set = to_set(&dns.system);
    let cf_set = to_set(&dns.cloudflare);
    let g_set = to_set(&dns.google);
    let sys_ok = !sys_set.is_empty();
    let pub_ok = !cf_set.is_empty() || !g_set.is_empty();

    if sys_ok && pub_ok && sys_set == cf_set && cf_set == g_set {
        lines.push(
            "🟡 Все DNS-резолверы (системный и публичные) отдают ОДИНАКОВЫЙ набор IP. Вероятна подмена DNS (hijack) — даже 1.1.1.1/8.8.8.8 перенаправляются. DPI-профили могут не помочь, нужен DNS-over-HTTPS/TLS (DoH/DoT).".into(),
        );
    } else if sys_ok && pub_ok && sys_set != cf_set {
        lines.push(
            "🟡 Обнаружена DNS-цензура: системный DNS отдаёт отличающийся ответ от публичного. Пропишите DNS 1.1.1.1 / 8.8.8.8 в настройках сети. DPI-профили могут не помочь.".into(),
        );
    } else if !sys_ok && pub_ok {
        lines.push(
            "🟡 Системный DNS не резолвит домен (NXDOMAIN/пусто), публичный — резолвит. Признак DNS-блокировки. Используйте публичный DNS.".into(),
        );
    } else if sys_ok {
        lines.push("🟢 DNS резолвится штатно (признаков DNS-цензуры нет).".into());
    }

    // Connect / TLS
    if connect == "Success" && (tls.contains("RST") || tls.contains("Timeout") || tls.contains("Tls")) {
        lines.push("🟡 Блокировка на уровне DPI (TLS/SNI): соединение устанавливается, но HTTPS-запрос срезается. Подбор desync-техники должен помочь.".into());
    } else if connect.contains("RST") || connect.contains("REFUSED") {
        lines.push("🟠 Блокировка на уровне IP/connect (RST на порт 443). DPI-профили могут не сработать — возможно, требуется VPN или смена IP.".into());
    }

    if ipv6 {
        lines.push(
            "🟡 Обнаружен рабочий IPv6 до сайта. winws фильтрует только IPv4 — трафик может уходить по IPv6 в обход обхода. Отключите IPv6 или добавьте IPv6-обход.".into(),
        );
    }

    // Техники
    if passed.is_empty() {
        lines.push(
            "🔴 Ни одна desync-техника не пробила блок. Вероятно блокировка на IP/connect или DNS-уровне, либо нестандартный DPI. Пришлите отпечаток разработчику для ручного профиля.".into(),
        );
    } else {
        let verdict: String = match verified {
            Some(true) => "проверен и РАБОТАЕТ".to_string(),
            Some(false) => "сгенерирован, но проверка не прошла (возможно, сайт падает по другой причине)".to_string(),
            None => "сгенерирован".to_string(),
        };
        lines.push(format!(
            "🟢 Подобрана(ы) рабочая(ие) техника(и): {}. Авто-профиль {}{}",
            passed.join(", "),
            verdict,
            if profile_saved { " и сохранён в списке профилей." } else { "." }
        ));
    }

    lines.join("\n")
}

/// Генерация черновика профиля из прошедших техник.
/// Возвращает (имя, аргументы). Возвращает None, если техник нет.
pub fn generate_profile(
    domain: &str,
    techniques: &[TechniqueSpec],
    passed: &[String],
    lists_dir: &str,
    bin_dir: &str,
) -> Option<(String, String)> {
    if passed.is_empty() {
        return None;
    }
    let chosen = techniques.iter().find(|t| passed.contains(&t.name))?;
    let desync = chosen
        .desync
        .replace("{BIN_DIR}", bin_dir)
        .replace("{LISTS_DIR}", lists_dir);

    let name = format!("Авто-профиль ({})", domain);
    let diag_host = format!("{}/diag-autoprofile.txt", lists_dir);

    // Доменно-специфичный блок (для проверки и гарантированного покрытия домена)
    // + общие блоки по спискам, как в штатных профилях.
    let args = format!(
        "--wf-tcp=80,443 --wf-udp=443 \
         --filter-udp=443 --hostlist=\"{l}/list-general.txt\" --hostlist-exclude=\"{l}/default-exclude.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{b}/quic_initial_www_google_com.bin\" --new \
         --filter-tcp=443 --hostlist=\"{h}\" {d} --new \
         --filter-tcp=80,443 --hostlist=\"{l}/list-general.txt\" --hostlist-exclude=\"{l}/default-exclude.txt\" {d}",
        l = lists_dir,
        b = bin_dir,
        h = diag_host,
        d = desync
    );

    Some((name, args))
}

/// Клонирование рабочего профиля пользователя, если ни одна изолированная
/// техника не прошла. Берём аргументы исходного профиля и добавляем
/// доменно-специфичный блок (на тот же desync, что и в исходнике), чтобы
/// проверка по тестовому домену гарантированно прошла.
pub fn clone_profile(
    src_name: &str,
    src_args: &str,
    lists_dir: &str,
    bin_dir: &str,
) -> Option<(String, String)> {
    let diag_host = format!("{}/diag-autoprofile.txt", lists_dir);
    let bin_str = bin_dir.replace("\\", "/");

    // Вытаскиваем первый --dpi-desync=... из исходного профиля
    let desync = src_args
        .split("--dpi-desync=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .map(|d| d.to_string())
        .unwrap_or_else(|| {
            format!(
                "fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{}/tls_clienthello_www_google_com.bin\"",
                bin_str
            )
        });

    let name = format!("Авто-профиль (clone: {})", src_name);
    let args = format!(
        "{} --new --filter-tcp=443 --hostlist=\"{}\" --dpi-desync={}",
        src_args, diag_host, desync
    );

    Some((name, args))
}
