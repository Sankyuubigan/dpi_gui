//! Чистая логика вердиктов: классификация фактов проверки в первопричину и её
//! разбор для пользователя. Модуль не ходит в сеть — всё I/O живёт в
//! [`crate::site_probe`] (core rules §2.8: ядро ничего не знает о внешнем мире).
//!
//! Ключевой принцип, которого раньше не было: **факты из разных каналов
//! разрешения DNS нельзя смешивать**. Ответ системного DNS (UDP:53) может быть
//! подменён провайдером, а ответ DoH — нет. Поэтому вердикт строится из
//! отдельного результата пробы по каждому каналу, и «сертификат не совпал» на
//! подменённом адресе никогда не выдаётся за «сертификат не совпал у сайта».

use crate::diagnostics_probe::HttpResult;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    Open,
    /// Домен открывается только по имени с префиксом `www.`, без него не отвечает.
    WwwOnly,
    IpUnreachable,
    IpReset,
    TlsBroken,
    /// Сайт отвечает по TCP/TLS, но сертификат невалиден для имени домена
    /// (браузер: NET::ERR_CERT_COMMON_NAME_INVALID и т.п.).
    ///
    /// Ставится **только** когда адрес, на котором получен сертификат, не
    /// вызывает подозрения в подмене DNS. Иначе адрес принадлежит не сайту,
    /// и «невалидный сертификат» — это симптом подмены, а не свойство сайта.
    BadCert,
    /// Системный DNS отдаёт не те адреса, что защищённый канал (DoH).
    DnsBlocked,
    BlockPage,
    /// Оператор связи подменил ответ редиректом на страницу блокировки (РКН).
    /// Виден только на порту 80: запрос уходит, но ответ приходит не от
    /// сервера, а от провайдера. По HTTPS провайдер рвёт соединение.
    IspBlockRedirect,
    NoPath,
    Unknown,
}

impl Verdict {
    /// Реально недоступен пользователю — нужна диагностика и подсказка.
    pub fn site_broken(self) -> bool {
        !matches!(self, Verdict::Open)
    }

    /// Короткое техническое имя вердикта для заголовка отчёта.
    pub fn verdict_name(self) -> &'static str {
        match self {
            Verdict::Open => "САЙТ ОТКРЫВАЕТСЯ",
            Verdict::WwwOnly => "РАБОТАЕТ ТОЛЬКО С WWW",
            Verdict::IpUnreachable => "IP НЕ ОТВЕЧАЕТ",
            Verdict::IpReset => "СБРОС СОЕДИНЕНИЯ (DPI)",
            Verdict::TlsBroken => "TLS СЛОМАН",
            Verdict::BadCert => "НЕВАЛИДНЫЙ СЕРТИФИКАТ",
            Verdict::DnsBlocked => "DNS-ПОДМЕНА",
            Verdict::BlockPage => "СТРАНИЦА БЛОКИРОВКИ",
            Verdict::IspBlockRedirect => "БЛОКИРОВКА ОПЕРАТОРОМ (РКН)",
            Verdict::NoPath => "НЕТ ПУТИ",
            Verdict::Unknown => "ПРИЧИНА НЕ ЯСНА",
        }
    }

    /// Требует ли лечения подменой DNS или записью IP в hosts. Только эти
    /// вердикты означают «адрес не тот» — остальные лечатся иначе.
    pub fn needs_address_fix(self) -> bool {
        matches!(self, Verdict::DnsBlocked)
    }
}

/// Результаты проверки домена, разложенные по каналам разрешения адреса.
///
/// Каждое поле — результат пробы по СВОЕМУ набору адресов. Раньше существовал
/// один общий `http: Option<&HttpResult>` и один `alt_ok: bool`, из-за чего
/// результат пробы по подозрительному адресу неотличим от результата пробы по
/// проверенному: отсюда и ложный вывод «невалидный сертификат».
#[derive(Debug, Default, Clone)]
pub struct ProbeFacts {
    /// Системный DNS ответил, но его адреса не совпадают с ответами DoH.
    pub dns_spoofed: bool,
    /// HTTPS по адресам ИЗ СИСТЕМНОГО DNS (`None` — TCP:443 не ответил).
    pub system_http: Option<HttpResult>,
    /// HTTPS по адресам ИЗ DoH (`None` — ни один DoH-адрес не прошёл TCP:443).
    pub doh_http: Option<HttpResult>,
    /// Хотя бы один адрес ответил на TCP:443 (не важно, по какому каналу).
    pub any_tcp_ok: bool,
    /// Среди всех проб было RST — признак обрыва соединения.
    pub any_reset: bool,
    /// Сайт открывается только под именем с префиксом `www.`.
    pub www_ok: bool,
}

/// Классификация первопричины по фактам проверки. Чистая функция: без сети,
/// без часов, без скрытого состояния — покрыта юнит-тестами.
pub fn classify(f: &ProbeFacts) -> Verdict {
    // 1. Сайт открывается по адресу ИЗ СИСТЕМНОГО DNS. Только этот адрес
    //    использует браузер пользователя, поэтому только он означает «сайт
    //    доступен». Открытие по адресу из DoH не считается: в браузере без
    //    записи в hosts пользователь по-прежнему получит подменённый адрес.
    if is_open(&f.system_http) {
        return Verdict::Open;
    }

    // 2. Ответ сервера вместо сайта — это называемая причина, она важнее
    //    любых догадок о сети.
    if matches!(f.system_http, Some(HttpResult::BlockPage)) {
        return Verdict::BlockPage;
    }

    // 3. Системный DNS доказанно подменён. Любой неуспешный ответ получен по
    //    адресу, который сайту не принадлежит, — судить о сайте по нему нельзя,
    //    поэтому BadCert/Rst/Timeout здесь означают лишь одно: этот адрес чужой.
    //    Первопричина установлена точно, и лечение другое, чем при BadCert.
    if f.dns_spoofed {
        return match f.doh_http {
            // Проверенный адрес открывает сайт: им можно и нужно лечить.
            Some(HttpResult::Ok(_)) => Verdict::DnsBlocked,
            // Проверенных адресов нет: подмена доказана, но судить о сайте не о чем.
            _ => Verdict::Unknown,
        };
    }

    // 4. DNS не подменялся — дальше вердикт ставится по фактическим ответам.
    match (&f.system_http, &f.doh_http) {
        (Some(HttpResult::BadCert), _) | (_, Some(HttpResult::BadCert)) => Verdict::BadCert,
        (Some(HttpResult::Tls), _) | (_, Some(HttpResult::Tls)) => Verdict::TlsBroken,
        (Some(HttpResult::Rst), _) | (_, Some(HttpResult::Rst)) => Verdict::IpReset,
        _ => classify_without_poison(f),
    }
}

/// Разбор для случая, когда подмены DNS не доказано.
fn classify_without_poison(f: &ProbeFacts) -> Verdict {
    if f.www_ok {
        return Verdict::WwwOnly;
    }
    if matches!(f.system_http, Some(HttpResult::Dns)) {
        return Verdict::DnsBlocked;
    }
    // Адрес из DoH открывает сайт, а из системного DNS — нет. Подмены не
    // доказано (значения частично пересекаются — обычная картина для CDN), но
    // браузер использует системный адрес, поэтому для пользователя сайт
    // недоступен. `NoPath` («ни один адрес не ответил») здесь был бы ложью:
    // один адрес ответил, просто не тот.
    if is_open(&f.doh_http) {
        return Verdict::IpUnreachable;
    }
    match f.system_http {
        Some(HttpResult::Other(_)) => Verdict::Unknown,
        Some(HttpResult::Timeout) => {
            if f.any_reset {
                Verdict::IpReset
            } else {
                Verdict::IpUnreachable
            }
        }
        None => {
            if f.any_reset {
                Verdict::IpReset
            } else if f.any_tcp_ok {
                Verdict::NoPath
            } else {
                Verdict::IpUnreachable
            }
        }
        _ => Verdict::Unknown,
    }
}

fn is_open(r: &Option<HttpResult>) -> bool {
    matches!(r, Some(HttpResult::Ok(_)))
}

/// Уточнение вердикта по данным пробы порта 80. Чистая функция —
///
/// RST сам по себе означает «соединение рвут», и причину не называет. Если
/// при этом на 80-м порту приходит редирект на чужой домен, то причина
/// установлена точно: блокирует оператор связи, а не сеть в целом. Это и
/// более специфичный вердикт, и другое лечение — hosts и смена DNS тут
/// бесполезны, помогает только обход.
pub fn refine_with_isp_redirect(verdict: Verdict, isp_redirect: Option<&str>) -> Verdict {
    match (verdict, isp_redirect) {
        (Verdict::IpReset, Some(_)) => Verdict::IspBlockRedirect,
        _ => verdict,
    }
}

/// Контекст для разбора причины: всё, что известно о домене на момент проверки.
#[derive(Debug)]
pub struct CauseContext<'a> {
    pub host: &'a str,
    /// Рабочий адрес с префиксом www., если он найден.
    pub www_url: Option<&'a str>,
    /// Первый IP, который вернул системный DNS для apex-имени.
    pub apex_ip: Option<&'a str>,
    /// Системный DNS доказанно расходится с защищённым каналом (DoH).
    pub dns_spoofed: bool,
    /// Адрес, найденный через DoH, по которому сайт открывается.
    pub doh_working_ip: Option<&'a str>,
    /// Для того же домена нашёлся рабочий IP через DoH.
    pub same_host_alt_ip_works: bool,
    /// Хост, на который провайдер подменил редирект вместо ответа сервера.
    pub isp_redirect: Option<&'a str>,
}

/// Разбор причины: что, скорее всего, произошло и что с этим делать.
#[derive(Debug)]
pub struct Diagnosis {
    pub probable_cause: String,
    pub do_this: Vec<String>,
    pub wont_help: Vec<String>,
}

/// Короткое описание результата HTTPS-запроса — для строки в отчёте.
pub fn http_result_note(r: &HttpResult) -> String {
    match r {
        HttpResult::Ok(code) => format!("HTTP {}", code),
        HttpResult::Tls => "TLS сломан".to_string(),
        HttpResult::BadCert => "SSL-сертификат невалиден".to_string(),
        HttpResult::Rst => "RST".to_string(),
        HttpResult::Timeout => "таймаут".to_string(),
        HttpResult::Dns => "DNS-ошибка".to_string(),
        HttpResult::BlockPage => "страница блокировки".to_string(),
        HttpResult::Other(m) => m.clone(),
    }
}

/// Строки для файла hosts, если проверенный адрес реально открывает сайт.
/// Пустой список означает «писать нечего» — вызывающий код обязан это учесть,
/// а не выдумать адрес.
pub fn hosts_lines(host: &str, ip: Option<&str>) -> Vec<String> {
    let Some(ip) = ip else {
        return Vec::new();
    };
    if host.starts_with("www.") {
        vec![format!("{} {}", ip, host)]
    } else {
        vec![format!("{} {}", ip, host), format!("{} www.{}", ip, host)]
    }
}

/// Разбор первопричины по вердикту. Только логика, без обращения к сети.
pub fn explain(verdict: Verdict, ctx: &CauseContext) -> Diagnosis {
    let mut d = Diagnosis {
        probable_cause: probable_cause(verdict, ctx),
        do_this: Vec::new(),
        wont_help: Vec::new(),
    };
    collect_actions(verdict, ctx, &mut d);
    d
}

fn probable_cause(verdict: Verdict, ctx: &CauseContext) -> String {
    match verdict {
        Verdict::Open => {
            "Сайт открывается по тому же адресу, по которому он и должен работать.".to_string()
        }

        Verdict::WwwOnly => {
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.dns_spoofed {
                format!(
                    "Для «{}» системный DNS отдаёт подменённый адрес {}, поэтому имя без префикса www. не открывается.",
                    ctx.host, apex
                )
            } else {
                format!(
                    "Домен «{}» без префикса www. не отвечает, хотя DNS отдаёт для него адрес {}. Сайт открывается только по имени с www.",
                    ctx.host, apex
                )
            }
        }

        Verdict::IpReset => {
            "Соединение сбрасывается (RST) прямо во время TLS-рукопожатия — так выглядит блокировка по IP или по SNI."
                .to_string()
        }

        Verdict::TlsBroken => {
            "TCP-соединение устанавливается, но TLS-рукопожатие обрывается на шифровании. Сервер не принимает сертификат, который предъявляет браузер, либо сервер сам не готов работать с шифрованием."
                .to_string()
        }

        Verdict::BadCert => {
            "Имя домена не совпадает с тем, что записано в сертификате, выданном сервером. Обход по IP без передачи SNI не поможет."
                .to_string()
        }

        Verdict::DnsBlocked => dns_poisoned_cause(ctx),

        Verdict::IspBlockRedirect => match ctx.isp_redirect {
            Some(r) => format!(
                "Домен «{}» в списке блокировок: оператор связи отвечает редиректом на {} вместо сайта. Ответ приходит не от сервера — это подмена на стороне провайдера, а не проблема домена.",
                ctx.host, r
            ),
            None => "Домен заблокирован оператором связи: вместо сайта приходит подставленный ответ."
                .to_string(),
        },

        Verdict::BlockPage => {
            "Сервер отдаёт страницу блокировки вместо сайта — обычно это ответ с кодом 403 или 451."
                .to_string()
        }

        Verdict::IpUnreachable => {
            let apex = ctx.apex_ip.unwrap_or("?");
            if ctx.same_host_alt_ip_works {
                format!(
                    "DNS не подменялся, но до адреса {} не доходит. Тот же домен открывается по другому адресу — похоже на фильтрацию маршрута.",
                    apex
                )
            } else {
                format!(
                    "DNS не подменялся, но до адреса {} не доходит. Похоже на фильтрацию маршрута оператором связи.",
                    apex
                )
            }
        }

        Verdict::NoPath => {
            "Ни по одному из адресов связаться с сайтом не удалось. Проверьте общее подключение к интернету."
                .to_string()
        }

        Verdict::Unknown => {
            "Не удалось однозначно определить причину по результатам одной проверки.".to_string()
        }
    }
}

/// Текст первопричины для отравленного DNS. Различает два разных случая, потому
/// что лечение у них разное: при найденном рабочем адресе лечение — hosts, при
/// отсутствии — только смена DNS-сервера, и советовать hosts там нельзя.
fn dns_poisoned_cause(ctx: &CauseContext) -> String {
    let apex = ctx.apex_ip.unwrap_or("?");
    match ctx.doh_working_ip {
        Some(ip) => format!(
            "DNS подменён: системный DNS отдал для «{}» адрес {}, но настоящие адреса сайта лежат на другом сервере. Через подменённый адрес сайт не открывается, а через проверенный адрес {} — открывается. Лечение — записать этот адрес в файл hosts.",
            ctx.host, apex, ip
        ),
        None => format!(
            "DNS подменён: системный DNS отдал для «{}» адрес {}, который не принадлежит сайту. Настоящие адреса через защищённый канал найти не удалось, поэтому подсказать, что именно писать в hosts, нечем — сначала нужно сменить DNS-сервер на тот, что работает по HTTPS.",
            ctx.host, apex
        ),
    }
}

fn collect_actions(verdict: Verdict, ctx: &CauseContext, d: &mut Diagnosis) {
    match verdict {
        Verdict::Open => (),

        Verdict::WwwOnly => {
            if let Some(url) = ctx.www_url {
                d.do_this
                    .insert(0, format!("Откройте сайт по адресу {} — он точно работает.", url));
            }
            d.do_this.push(
                "Проверьте, какой из вариантов открывается у вас: с префиксом www. или без него."
                    .to_string(),
            );
            d.wont_help.push(
                "Проверка через hosts не даёт верного результата — включите системный DoH и повторите замер."
                    .to_string(),
            );
            d.wont_help.push(
                "Добавление домена в список обхода тут не поможет: apex-адрес недоступен независимо от обхода."
                    .to_string(),
            );
        }

        Verdict::DnsBlocked => dns_poisoned_actions(ctx, d),

        Verdict::BlockPage => {
            d.do_this.push(
                "Добавьте домен в список исключений для профиля обхода и перезапустите обход."
                    .to_string(),
            );
            d.wont_help.push(
                "Смена DNS не поможет: страницу блокировки отдаёт сам провайдер, и адрес у неё тот же."
                    .to_string(),
            );
        }

        Verdict::IspBlockRedirect => {
            d.do_this
                .insert(0, "Включите профиль обхода DPI_GUI и откройте сайт снова.".to_string());
            d.do_this.push(
                "Если обход уже включён — перезапустите его: блокировка в силе, а профиль не спас."
                    .to_string(),
            );
            d.wont_help.push(
                "Правка hosts и смена DNS не помогут: запрос вообще не доходит до сервера, ответ подставляет оператор связи."
                    .to_string(),
            );
        }

        Verdict::IpReset => {
            d.wont_help.push(
                "Правка hosts здесь не поможет: соединение обрывается ещё до обмена данными."
                    .to_string(),
            );
        }

        Verdict::TlsBroken => {
            d.wont_help.push(
                "Ни смена DNS, ни запись в hosts: TCP проходит, обрыв происходит уже на уровне TLS."
                    .to_string(),
            );
        }

        Verdict::BadCert => {
            d.wont_help.push(
                "Обход тут не поможет: блокировки на уровне сети нет, TCP/TLS работают."
                    .to_string(),
            );
            d.wont_help.push(
                "Ни смена DNS, ни hosts: сначала нужно устранить неверный сертификат на стороне сервера."
                    .to_string(),
            );
        }

        Verdict::IpUnreachable => {
            d.wont_help.push(
                "Обход winws тут не поможет: до сервера доходит RST, ответ не возвращается."
                    .to_string(),
            );
            d.wont_help.push(
                "Ни смена DNS, ни запись в hosts: DNS отдаёт верный адрес, но до него невозможно дойти."
                    .to_string(),
            );
        }

        Verdict::NoPath => {
            d.wont_help.push(
                "Обход тут не поможет: маршрут до адреса потерян не из-за блокировки.".to_string(),
            );
        }

        Verdict::Unknown => (),
    }

    if d.do_this.is_empty() && verdict != Verdict::Open {
        d.do_this
            .push("Попробуйте включить VPN или смените сеть.".to_string());
    }
}

fn dns_poisoned_actions(ctx: &CauseContext, d: &mut Diagnosis) {
    match ctx.doh_working_ip {
        Some(ip) => {
            let lines = hosts_lines(ctx.host, Some(ip));
            d.do_this.insert(
                0,
                format!("Добавьте в файл hosts строки:\n     {}", lines.join("\n     ")),
            );
            d.do_this
                .push("Затем выполните в командной строке: ipconfig /flushdns".to_string());
            d.do_this.push(
                "Надёжнее на постоянной основе — прописать в Windows DNS-сервер со схемой «Только шифрование (DNS через HTTPS)»."
                    .to_string(),
            );
            d.wont_help.push(
                "Обход winws по SNI тут не нужен: соединение с правильным адресом проходит нормально, ломается только подменённый адрес."
                    .to_string(),
            );
        }
        None => {
            d.do_this.push(
                "Смените DNS-сервер на работающий по HTTPS (шифрованный): обычный DNS-трафик в вашей сети перехватывается и подменяется."
                    .to_string(),
            );
            d.do_this
                .push("После смены DNS повторите анализ — адреса станут настоящими.".to_string());
            // Ключевая честность: без проверенного адреса писать в hosts нечего.
            d.wont_help.push(
                "Запись в hosts сейчас не поможет: подтверждённо рабочий адрес найти не удалось, а подменённый адрес точно не подходит."
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> ProbeFacts {
        ProbeFacts::default()
    }

    fn ctx<'a>(host: &'a str) -> CauseContext<'a> {
        CauseContext {
            host,
            www_url: None,
            apex_ip: Some("1.2.3.4"),
            dns_spoofed: false,
            doh_working_ip: None,
            same_host_alt_ip_works: false,
            isp_redirect: None,
        }
    }

    #[test]
    fn open_when_system_ip_works() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::Open);
    }

    /// Главный случай пользователя: подменённый адрес отдаёт чужой
    /// сертификат, настоящий адрес открывает сайт.
    #[test]
    fn poisoned_dns_badcert_system_good_doh_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::BadCert);
        f.doh_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    #[test]
    fn poisoned_dns_rst_system_good_doh_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::Rst);
        f.doh_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    #[test]
    fn poisoned_dns_timeout_system_good_doh_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::Timeout);
        f.doh_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

/// Открытие по проверенному адресу НЕ делает сайт доступным: браузер
/// продолжает получать подменённый адрес из системного DNS. Вердикт «открыт»
/// здесь означал бы, что пользователю не нужно ничего делать — а ему нужно.
#[test]
fn poisoned_dns_site_opens_via_doh_is_still_dns_blocked() {
    let mut f = facts();
    f.dns_spoofed = true;
    f.system_http = Some(HttpResult::BadCert);
    f.doh_http = Some(HttpResult::Ok(200));
    f.any_tcp_ok = true;
    assert_eq!(classify(&f), Verdict::DnsBlocked);
}

/// Без подмены DNS открытие по проверенному адресу не делает сайт доступным:
/// системный DNS отдал другой, нерабочий адрес. Для пользователя это
/// «адрес не отвечает», а не «сайт открыт».
#[test]
fn clean_dns_site_opens_via_doh_only_is_ip_unreachable() {
    let mut f = facts();
    f.system_http = None;
    f.doh_http = Some(HttpResult::Ok(200));
    f.any_tcp_ok = true;
    assert_eq!(classify(&f), Verdict::IpUnreachable);
}

/// Обратный случай: тот же расклад, но браузеру повезло с адресом из
/// системного DNS — сайт действительно открывается.
#[test]
fn clean_dns_site_opens_via_system_is_open() {
    let mut f = facts();
    f.system_http = Some(HttpResult::Ok(200));
    f.doh_http = Some(HttpResult::Ok(200));
    f.any_tcp_ok = true;
    assert_eq!(classify(&f), Verdict::Open);
}

    /// Подмена доказана, но проверенных адресов нет: о вердикте «сертификат
    /// невалиден» говорить нельзя — этот вывод сделан по подозрительному адресу.
    #[test]
    fn poisoned_dns_without_doh_ips_is_not_bad_cert() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::BadCert);
        f.doh_http = None;
        assert_eq!(classify(&f), Verdict::Unknown);
    }

    /// Без доказанной подмены BadCert остаётся BadCert — прежняя логика сохранена.
    #[test]
    fn bad_cert_without_poison_stays_bad_cert() {
        let mut f = facts();
        f.system_http = Some(HttpResult::BadCert);
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::BadCert);
    }

    #[test]
    fn block_page_wins_over_poison() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::BlockPage);
        assert_eq!(classify(&f), Verdict::BlockPage);
    }

    #[test]
    fn rst_is_dpi_block() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Rst);
        f.any_reset = true;
        assert_eq!(classify(&f), Verdict::IpReset);
    }

    #[test]
    fn tls_broken_verdict() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Tls);
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::TlsBroken);
    }

    #[test]
    fn apex_dead_but_www_ok_is_www_only() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Timeout);
        f.www_ok = true;
        assert_eq!(classify(&f), Verdict::WwwOnly);
    }

    #[test]
    fn www_ok_does_not_mask_block_page() {
        let mut f = facts();
        f.system_http = Some(HttpResult::BlockPage);
        f.www_ok = true;
        assert_eq!(classify(&f), Verdict::BlockPage);
    }

    #[test]
    fn nothing_answers_is_ip_unreachable() {
        assert_eq!(classify(&facts()), Verdict::IpUnreachable);
    }

    #[test]
    fn tcp_ok_but_no_https_is_no_path() {
        let mut f = facts();
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::NoPath);
    }

    // --- isp redirect ---

    #[test]
    fn isp_redirect_upgrades_rst_to_named_block() {
        assert_eq!(
            refine_with_isp_redirect(Verdict::IpReset, Some("host -> lawfilter.example")),
            Verdict::IspBlockRedirect
        );
    }

    #[test]
    fn rst_without_redirect_stays_generic() {
        assert_eq!(
            refine_with_isp_redirect(Verdict::IpReset, None),
            Verdict::IpReset
        );
    }

    #[test]
    fn isp_redirect_does_not_touch_working_site() {
        assert_eq!(
            refine_with_isp_redirect(Verdict::Open, Some("host -> lawfilter.example")),
            Verdict::Open
        );
    }

    // --- разбор причины ---

    #[test]
    fn dns_blocked_with_working_ip_gives_hosts_lines() {
        let mut c = ctx("example.com");
        c.dns_spoofed = true;
        c.apex_ip = Some("188.186.154.88");
        c.doh_working_ip = Some("104.21.95.93");
        let d = explain(Verdict::DnsBlocked, &c);
        assert!(d.probable_cause.contains("подмен"), "{}", d.probable_cause);
        assert!(
            d.do_this.iter().any(|a| a.contains("104.21.95.93 example.com")),
            "{:?}",
            d.do_this
        );
        assert!(d.do_this.iter().any(|a| a.contains("flushdns")), "{:?}", d.do_this);
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts сейчас не поможет")),
            "{:?}",
            d.do_this
        );
    }

    /// Без проверенного адреса советовать hosts нельзя — писать нечего.
    #[test]
    fn dns_blocked_without_working_ip_forbids_hosts() {
        let mut c = ctx("example.com");
        c.dns_spoofed = true;
        c.doh_working_ip = None;
        let d = explain(Verdict::DnsBlocked, &c);
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.do_this
        );
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
        assert!(
            d.do_this.iter().any(|a| a.contains("DNS-сервер")),
            "{:?}",
            d.do_this
        );
    }

    #[test]
    fn bad_cert_tells_hosts_wont_help() {
        let d = explain(Verdict::BadCert, &ctx("example.com"));
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
    }

    #[test]
    fn isp_block_redirect_says_hosts_wont_help_and_asks_for_bypass() {
        let mut c = ctx("example.com");
        c.isp_redirect = Some("example.com -> lawfilter.ertelecom.ru");
        let d = explain(Verdict::IspBlockRedirect, &c);
        assert!(
            d.probable_cause.contains("lawfilter.ertelecom.ru"),
            "{}",
            d.probable_cause
        );
        assert!(d.wont_help.iter().any(|a| a.contains("hosts")), "{:?}", d.wont_help);
        assert!(d.do_this.iter().any(|a| a.contains("обход")), "{:?}", d.do_this);
    }

    #[test]
    fn registrable_free_www_only_points_to_www_url() {
        let mut c = ctx("cactuscompute.com");
        c.apex_ip = Some("216.150.1.1");
        c.www_url = Some("https://www.cactuscompute.com/");
        let d = explain(Verdict::WwwOnly, &c);
        assert!(d.probable_cause.contains("216.150.1.1"), "{}", d.probable_cause);
        assert!(
            d.do_this.iter().any(|a| a.contains("https://www.cactuscompute.com/")),
            "{:?}",
            d.do_this
        );
        assert!(d.wont_help.iter().any(|a| a.contains("hosts")), "{:?}", d.wont_help);
    }

    #[test]
    fn unreachable_ip_says_bypass_wont_help() {
        let d = explain(Verdict::IpUnreachable, &ctx("example.com"));
        assert!(d.wont_help.iter().any(|a| a.contains("winws")), "{:?}", d.wont_help);
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts")),
            "hosts must not be advised for a dead IP: {:?}",
            d.do_this
        );
    }

    #[test]
    fn open_has_no_action_noise() {
        let d = explain(Verdict::Open, &ctx("example.com"));
        assert!(d.do_this.is_empty(), "{:?}", d.do_this);
        assert!(d.wont_help.is_empty(), "{:?}", d.wont_help);
    }

    #[test]
    fn verdict_names_are_unique() {
        let all = [
            Verdict::Open,
            Verdict::WwwOnly,
            Verdict::IpUnreachable,
            Verdict::IpReset,
            Verdict::TlsBroken,
            Verdict::BadCert,
            Verdict::DnsBlocked,
            Verdict::BlockPage,
            Verdict::IspBlockRedirect,
            Verdict::NoPath,
            Verdict::Unknown,
        ];
        let mut names: Vec<&str> = all.iter().map(|v| v.verdict_name()).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "duplicated verdict names: {:?}", names);
    }

    #[test]
    fn site_broken_flag() {
        assert!(!Verdict::Open.site_broken());
        assert!(Verdict::WwwOnly.site_broken());
        assert!(Verdict::IpReset.site_broken());
    }

    #[test]
    fn hosts_lines_avoid_duplicate_www() {
        assert_eq!(
            hosts_lines("www.example.com", Some("1.2.3.4")),
            vec!["1.2.3.4 www.example.com".to_string()]
        );
        assert_eq!(
            hosts_lines("example.com", Some("1.2.3.4")),
            vec![
                "1.2.3.4 example.com".to_string(),
                "1.2.3.4 www.example.com".to_string()
            ]
        );
        assert!(hosts_lines("example.com", None).is_empty());
    }
}