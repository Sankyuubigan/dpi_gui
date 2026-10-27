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
    /// Сервер отвечает голым отказом (403/451 без маркеров подмены) и на
    /// системном, и на проверенном адресе. Это ограничение самого сервиса
    /// (часто региональное) — лечится VPN/сменой сети, а не обходом,
    /// исключениями или hosts.
    GeoBlocked,
    /// Страница отдаётся живым HTTP (200/3xx), но в её теле сам сервис
    /// сообщает об ограничении доступа (регион источника/доступность).
    /// Формально сайт «открывается» — фактически сервис режет доступ по
    /// IP клиента. Лечится VPN/прокси; DNS и hosts не при чём.
    ServiceRestricted,
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
            Verdict::GeoBlocked => "РЕГИОНАЛЬНОЕ ОГРАНИЧЕНИЕ (НУЖЕН VPN)",
            Verdict::ServiceRestricted => "СЕРВИС ОГРАНИЧИВАЕТ (НУЖЕН VPN/ПРОКСИ)",
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

    /// Способен ли обход по hostlist-у изменить исход для этого вердикта.
    ///
    /// winws модифицирует TLS/SNI-поток — это помогает, когда цензор рвёт
    /// или подменяет соединение DPI-методами. Когда TCP до адреса не
    /// открывается вовсе (`IpUnreachable`, `NoPath`), причина на стороне
    /// адреса/маршрута, а не формата пакетов: обход оживить её не может.
    /// Причины «сайт закрыл сам» (`GeoBlocked`, `ServiceRestricted`,
    /// `BadCert`), «не там искали» (`Open`, `WwwOnly`, `DnsBlocked`) и
    /// «не разобрались» (`Unknown`) обходом тоже не лечатся.
    pub fn bypass_relevant(self) -> bool {
        matches!(
            self,
            Verdict::IpReset | Verdict::TlsBroken | Verdict::BlockPage | Verdict::IspBlockRedirect
        )
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
    /// DoH вернул только те же адреса, что системный DNS (проверять отдельно
    /// нечего — системный адрес тем самым проверен защищённым каналом).
    pub doh_agrees: bool,
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

    // 2. Подставленная страница блокировки (явные маркеры в теле ответа) —
    //    это называемая причина, она важнее любых догадок о сети.
    if matches!(f.system_http, Some(HttpResult::BlockPage)) {
        return Verdict::BlockPage;
    }

    // 2b. Голый отказ сервера (403/451) и на системном, и на проверенном
    //     адресе при чистом DNS — ограничение самого сервиса (гео-блок),
    //     а не цензура провайдера. Доказательство: VPN открывает сайт.
    if !f.dns_spoofed
        && matches!(f.system_http, Some(HttpResult::Forbidden(_)))
        && (matches!(f.doh_http, Some(HttpResult::Forbidden(_))) || f.doh_agrees)
    {
        return Verdict::GeoBlocked;
    }

    // 3. Системный DNS доказанно подменён. Любой неуспешный ответ получен по
    //    адресу, который сайту не принадлежит, — судить о сайте по нему нельзя,
    //    поэтому BadCert/Rst/Timeout здесь означают лишь одно: этот адрес чужой.
    //    Первопричина установлена точно — вердикт ВСЕГДА DnsBlocked. Отсутствие
    //    проверенного DoH-адреса меняет ЛЕЧЕНИЕ (текст причины и действий
    //    различает это по doh_working_ip), но не отменяет диагноз: Unknown тут
    //    был ложью (кейс turboimagehost — «причина не ясна» при доказанной
    //    подмене).
    if f.dns_spoofed {
        return Verdict::DnsBlocked;
    }

    // 3b. Сайт отдал живой HTTP-ответ (2xx/3xx), но в теле страницы сам сервис
    //     сообщает об ограничении доступа (регион источника, доступность).
    //     Сеть в порядке — ограничивает сам сервис по IP клиента; DNS/hosts на
    //     это не влияют (кейс AI-студий: «HTTP 200» не значит «сервис доступен»).
    //     Проверяется ПОСЛЕ ветки подмены: при доказанной подмене тело пришло
    //     с чужого адреса, и верить его маркерам нельзя.
    if matches!(f.system_http, Some(HttpResult::ServiceRestrict)) {
        return Verdict::ServiceRestricted;
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
    /// По HTTP-порту 80 у проверенных (DoH) адресов приходил осмысленный
    /// ответ сайта/CDN: транспорт до настоящего адреса жив, а TLS/SNI рвёт
    /// цензор. Меняет ТЕКСТ причины (совет включить обход), не вердикт.
    pub doh_http80_hint: bool,
    /// Найденные через DoH адреса, HTTPS-пробу по которым приложение
    /// не сумело подтвердить. Пустой список = кандидатов нет вовсе —
    /// тогда никакого «hosts-совета» по кандидатам не появляется.
    pub doh_candidates: Vec<String>,
    /// Причина, по которой HTTPS-проба по DoH-адресам не открыла сайт
    /// (текст из классификации ошибок reqwest, без выдумок).
    pub probe_fail_note: Option<String>,
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
        HttpResult::BadCert => "сервер отдал сертификат, не принадлежащий домену сайта".to_string(),
        HttpResult::Rst => "RST".to_string(),
        HttpResult::Timeout => "таймаут".to_string(),
        HttpResult::Dns => "DNS-ошибка".to_string(),
        HttpResult::BlockPage => "страница блокировки".to_string(),
        HttpResult::Forbidden(code) => format!("отказ сервера HTTP {}", code),
        HttpResult::ServiceRestrict => {
            "страница отдалась, но сервис сообщает об ограничении доступа (регион источника)"
                .to_string()
        }
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
            "Сайт открывается по тому же адресу, по которому он и должен работать. Проверено только открытие самой страницы: часть сервисов (AI-платформы, хостинги, соцсети) ограничивает доступ внутри страницы или по региону клиента — одним GET-запросом это не видно.".to_string()
        }

        Verdict::ServiceRestricted => {
            "Сайт отвечает живой страницей, но сам сервис сообщает в её тексте об ограничении доступа (регион источника или доступность). Сеть и DNS тут ни при чём: доступ режет сервер по IP клиента.".to_string()
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
            "Оператор связи подставляет страницу блокировки вместо сайта (в теле ответа — явные маркеры блокировки)."
                .to_string()
        }

        Verdict::GeoBlocked => {
            let apex = ctx.apex_ip.unwrap_or("?");
            format!(
                "Сам сервис отказывает в доступе (голый HTTP 403/451 без признаков подмены) и по системному адресу {}, и по проверенному адресу. DNS чистый — это ограничение самого сервиса, обычно региональное: из другой страны сайт открывается.",
                apex
            )
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

/// Текст первопричины для отравленного DNS. Различает три разных случая,
/// потому что лечение у них разное:
/// - найти рабочий адрес (лечится hosts);
/// - не найти адрес, но HTTP:80 подтвердил живой транспорт (лечится обходом);
/// - не найти адрес вообще (сначала смена DNS, hosts советовать нельзя).
fn dns_poisoned_cause(ctx: &CauseContext) -> String {
    let apex = ctx.apex_ip.unwrap_or("?");
    match ctx.doh_working_ip {
        Some(ip) => format!(
            "DNS подменён: системный DNS отдал для «{}» адрес {}, но настоящие адреса сайта лежат на другом сервере. Через подменённый адрес сайт не открывается, а через проверенный адрес {} — открывается. Лечение — записать этот адрес в файл hosts.",
            ctx.host, apex, ip
        ),
        None if ctx.doh_http80_hint => format!(
            "DNS подменён: системный DNS отдал для «{}» адрес {}, который сайту не принадлежит. Настоящий адрес через защищённый канал найден, но TLS до него обрывается (по обычному HTTP:80 сайт отвечает — транспорт до него жив, режется именно TLS/SNI). Такой режим лечится обходом DPI (winws) для этого домена либо записью настоящего адреса в hosts.",
            ctx.host, apex
        ),
        None => {
            let note = ctx
                .probe_fail_note
                .as_deref()
                .map(|n| format!(" (причина: {})", n))
                .unwrap_or_default();
            if ctx.doh_candidates.is_empty() {
                format!(
                    "DNS подменён: системный DNS отдал для «{}» адрес {}, который не принадлежит сайту. Настоящие адреса через защищённый канал найти не удалось, поэтому рабочую hosts-строку подсказать нечем — сначала смените DNS-сервер на тот, что работает по HTTPS.",
                    ctx.host, apex
                )
            } else {
                format!(
                    "DNS подменён: системный DNS отдал для «{}» адрес {}, который сайту не принадлежит. Настоящие адреса через защищённый канал найдены, но HTTPS-проба по ним не подтвердила ни один{} — заранее проверенной hosts-строки нет, кандидаты перечислены в блоке «ЧТО СДЕЛАТЬ» (это может быть цензор, а может и погрешность приложения). Сначала смените DNS-сервер на работающий по HTTPS.",
                    ctx.host, apex, note
                )
            }
        }
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
                "Смена DNS не поможет: страницу блокировки подставляет оператор связи, и адрес у неё тот же."
                    .to_string(),
            );
        }

        Verdict::GeoBlocked => {
            // Явное «доказательств нет»: лист исключения не наблюдался, но
            // голый отказ с обоих адресов при чистом DNS + открытие через VPN —
            // косвенный признак ограничения сервиса, а не провайдера.
            d.do_this.push(
                "Попробуйте VPN или смените сеть/страну: ограничение ставит сам сервис, обход DPI его не снимет."
                    .to_string(),
            );
            d.wont_help.push(
                "Обход winws не поможет: соединение доходит до сервера, отказывает сам сервер."
                    .to_string(),
            );
            d.wont_help.push(
                "Ни смена DNS, ни запись в hosts: адрес верный, но сервер отказывает этому региону."
                    .to_string(),
            );
            d.wont_help.push(
                "Исключения обхода не нужны: ломать тут нечего — обход ни при чём."
                    .to_string(),
            );
        }

        Verdict::ServiceRestricted => {
            d.do_this.push(
                "Попробуйте VPN или прокси-шлюз — смените исходный IP клиента: ограничение ставит сам сервис по региону источника."
                    .to_string(),
            );
            d.wont_help.push(
                "Ни смена DNS, ни запись в hosts: адреса верные, но сервис проверяет регион КЛИЕНТА — целевой IP не влияет."
                    .to_string(),
            );
            d.wont_help.push(
                "Обход winws не поможет: соединение доходит до сервера, и запрещает сам сервис."
                    .to_string(),
            );
            d.wont_help.push(
                "Исключения обхода не нужны: ломать тут нечего — обход ни при чём."
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
            // TLS рвётся цензором, а транспорт жив — обходим через winws.
            if ctx.doh_http80_hint {
                d.do_this.insert(
                    0,
                    "Включите профиль обхода и откройте сайт снова: TLS до настоящего адреса режется цензором, по обычному HTTP:80 сайт отвечает."
                        .to_string(),
                );
            }
            // Честность (core §2.2): найденные DoH-адреса нельзя прятать только
            // потому, что приложение само не сумело их проверить. Показываем
            // как КАНДИДАТОВ с реальной причиной неудачи.
            if !ctx.doh_candidates.is_empty() {
                let reason = ctx
                    .probe_fail_note
                    .as_deref()
                    .map(|n| format!(", причина неудачи пробы: {}", n))
                    .unwrap_or_else(|| ", HTTP-проба по ним результата не дала".to_string());
                d.do_this.push(format!(
                    "Кандидаты из защищённого DNS (приложение их работу не подтвердило{}): {}. Можно попробовать записью в hosts строкой «<адрес> <имя>» — если сайт не откроется, строку удалите.",
                    reason,
                    ctx.doh_candidates.join(", ")
                ));
            }
            d.do_this.push(
                "Смените DNS-сервер на работающий по HTTPS (шифрованный): обычный DNS-трафик в вашей сети перехватывается и подменяется."
                    .to_string(),
            );
            d.do_this
                .push("После смены DNS повторите анализ — адреса станут настоящими.".to_string());
            // Ключевая честность: без проверенного адреса запись в hosts —
            // риск вместо решения (точнее кандидатов только выше, с пометкой).
            d.wont_help.push(
                "Подтверждённо рабочей строки для hosts нет: приложение не сумело открыть сайт ни по одному найденному адресу, а подменённый адрес точно не подходит."
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
            doh_http80_hint: false,
            doh_candidates: Vec::new(),
            probe_fail_note: None,
        }
    }

    #[test]
    fn open_when_system_ip_works() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::Open);
    }

    /// Обход (модификация TLS-потока) имеет смысл только для DPI-вересков.
    /// Кейс vercel 27.10.26: IpUnreachable звали «в обход», а обход мёртвый
    /// маршрут оживить не может — совет был ложью.
    #[test]
    fn bypass_relevant_only_for_dpi_verdicts() {
        for v in [
            Verdict::IpReset,
            Verdict::TlsBroken,
            Verdict::BlockPage,
            Verdict::IspBlockRedirect,
        ] {
            assert!(v.bypass_relevant(), "{} должен допускать обход", v.verdict_name());
        }
        for v in [
            Verdict::Open,
            Verdict::WwwOnly,
            Verdict::IpUnreachable,
            Verdict::BadCert,
            Verdict::DnsBlocked,
            Verdict::GeoBlocked,
            Verdict::ServiceRestricted,
            Verdict::NoPath,
            Verdict::Unknown,
        ] {
            assert!(!v.bypass_relevant(), "{} обход не лечит", v.verdict_name());
        }
    }

    /// 200-ответ с маркером регионального ограничения в теле — НЕ «открыт»:
    /// сервис ограничивает сам (кейс AI-студий).
    #[test]
    fn region_marker_in_200_body_is_service_restricted() {
        let mut f = facts();
        f.system_http = Some(HttpResult::ServiceRestrict);
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::ServiceRestricted);
    }

    /// Под доказанной подменой DNS телу маркера верить нельзя — адрес чужой.
    #[test]
    fn spoofed_beats_region_marker() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::ServiceRestrict);
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    /// ServiceRestricted: VPN-советы, явный запрет hosts/обхода.
    #[test]
    fn service_restricted_advises_vpn_and_forbids_hosts() {
        let d = explain(Verdict::ServiceRestricted, &ctx("example.com"));
        assert!(d.do_this.iter().any(|a| a.contains("VPN")), "{:?}", d.do_this);
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
        assert!(
            d.probable_cause.contains("сам сервис"),
            "{}",
            d.probable_cause
        );
    }

    /// Оговорка при «Open»: одно открытие страницы не значит «сервис работоспособен».
    #[test]
    fn open_cause_has_page_level_caveat() {
        let d = explain(Verdict::Open, &ctx("example.com"));
        assert!(
            d.probable_cause.contains("Проверено только открытие самой страницы"),
            "{}",
            d.probable_cause
        );
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

    /// Подмена доказана, DoH ничего не дал: вердикт обязан быть DnsBlocked,
    /// а не Unknown — первопричина установлена точно даже без рабочего адреса.
    /// Раньше этот кейс выдавал «причину не ясна» (баг turboimagehost).
    #[test]
    fn spoofed_doh_failed_is_dns_blocked_not_unknown() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::Rst);
        f.doh_http = None;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    /// То же для чужого сертификата на подменённом адресе: судить о сайте
    /// по подозрительному адресу нельзя, вердикт — DnsBlocked.
    #[test]
    fn spoofed_badcert_doh_none_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::BadCert);
        f.doh_http = None;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
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

    /// HTTP:80 подтвердил живой транспорт: причина говорит об обходе/резке
    /// TLS, но НЕ декларирует, что сайт мёртв.
    #[test]
    fn spoofed_http80_hint_upgrades_tls_note() {
        let mut c = ctx("example.com");
        c.dns_spoofed = true;
        c.apex_ip = Some("188.186.154.88");
        c.doh_http80_hint = true;
        let d = explain(Verdict::DnsBlocked, &c);
        assert!(
            d.probable_cause.contains("подменён"),
            "{}",
            d.probable_cause
        );
        assert!(
            d.probable_cause.contains("TLS"),
            "{}",
            d.probable_cause
        );
        assert!(
            !d.probable_cause.contains("сайт мёртв"),
            "{}",
            d.probable_cause
        );
        assert!(
            d.do_this.iter().any(|a| a.contains("обхода")),
            "{:?}",
            d.do_this
        );
    }

    /// Скрыть DoH-адреса-кандидаты нельзя (core §2.2): они попадают в
    /// «ЧТО СДЕЛАТЬ» с честной пометкой «не подтверждено» и причиной.
    #[test]
    fn dns_blocked_candidates_shown_with_fail_note() {
        let mut c = ctx("example.com");
        c.dns_spoofed = true;
        c.doh_candidates = vec!["104.21.20.243".to_string(), "172.67.194.226".to_string()];
        c.probe_fail_note = Some("сервер отдал сертификат, не принадлежащий домену сайта".to_string());
        let d = explain(Verdict::DnsBlocked, &c);
        assert!(
            d.do_this.iter().any(|a| a.contains("104.21.20.243")),
            "{:?}",
            d.do_this
        );
        assert!(
            d.do_this
                .iter()
                .any(|a| a.contains("не подтвердило") && a.contains("сертификат")),
            "{:?}",
            d.do_this
        );
        // Но при пустом списке кандидатов никакой hosts-подсказки не появится.
        let mut empty = ctx("example.com");
        empty.dns_spoofed = true;
        let d = explain(Verdict::DnsBlocked, &empty);
        assert!(
            !d.do_this.iter().any(|a| a.contains("hosts")),
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

    /// Кейс cohere: голый 403 с системного и DoH-адреса при чистом DNS —
    /// региональное ограничение сервиса, а не страница провайдера.
    #[test]
    fn same_forbidden_on_both_channels_is_geo_blocked() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Forbidden(403));
        f.doh_http = Some(HttpResult::Forbidden(403));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::GeoBlocked);
    }

    /// DoH подтверждает тот же адрес (проверять отдельно нечего) — тоже гео-блок.
    #[test]
    fn forbidden_with_doh_agreeing_is_geo_blocked() {
        let mut f = facts();
        f.system_http = Some(HttpResult::Forbidden(403));
        f.doh_agrees = true;
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::GeoBlocked);
    }

    /// Подмена DNS важнее голого 403: по чужому адресу о сервере судить нельзя,
    /// но первопричина (подмена) установлена — вердикт DnsBlocked.
    #[test]
    fn spoofed_forbidden_without_doh_ok_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::Forbidden(403));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    /// Открытие по DoH при подмене — всё ещё DNS-подмена, не гео-блок.
    #[test]
    fn spoofed_forbidden_with_doh_ok_is_dns_blocked() {
        let mut f = facts();
        f.dns_spoofed = true;
        f.system_http = Some(HttpResult::Forbidden(403));
        f.doh_http = Some(HttpResult::Ok(200));
        f.any_tcp_ok = true;
        assert_eq!(classify(&f), Verdict::DnsBlocked);
    }

    /// GeoBlocked честно советует VPN и запрещает бесполезные действия.
    #[test]
    fn geo_blocked_advises_vpn_and_forbids_useless() {
        let d = explain(Verdict::GeoBlocked, &ctx("example.com"));
        assert!(d.do_this.iter().any(|a| a.contains("VPN")), "{:?}", d.do_this);
        assert!(
            d.wont_help.iter().any(|a| a.contains("hosts")),
            "{:?}",
            d.wont_help
        );
        assert!(
            !d.do_this.iter().any(|a| a.contains("исключен")),
            "исключения обхода при гео-блоке советовать нельзя: {:?}",
            d.do_this
        );
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
            Verdict::GeoBlocked,
            Verdict::ServiceRestricted,
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