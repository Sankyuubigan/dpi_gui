//! Фильтр собственных фейков winws для домен-детектора (инцидент 27.10.26).
//!
//! winws на каждый подменяемый пакет шлёт 8–11 подставных копий, чей payload
//! побайтно равен файлу-фейку (`--dpi-desync-fake-*=`), а перед первым сегментом
//! ClientHello — seqovl-паттерн (префикс того же файла, см.
//! `--dpi-desync-split-seqovl-pattern=`). Пассивный сниффер (`domain_monitor`)
//! эти пакеты видит: без фильтра они считались ретрансмиссиями и QUIC Initial'ами,
//! а SNI-коллектор лочил hostname по SNI ИЗ ФАЙЛА-ФЕЙКА (onetrust / google) —
//! список «Ошибки сети» заполнялся фантомами, а реальные сигналы тонули.
//!
//! Источник байтов — SSOT: аргументы, которыми winws реально запущен
//! (`spawn_winws` передаёт в монитор те же `final_args`; нет опроса процессов,
//! нет гонки, нет рассинхрона при смене профиля — монитор перезапускается
//! вместе с обходом).
//!
//! Правило классификации: исходящий payload — фейк, если общий префикс payload
//! и любого блоба ≥ [`MIN_FAKE_MATCH_LEN`] байт. Реальный ClientHello отличается
//! от статического фейка в Random (offset 11..43), поэтому его общий префикс
//! с фейком ≤ ~11 байт; короткие split-сегменты (< MIN) не фильтруются никогда.
//! Хвост не важен: seqovl-пакет может нести паттерн + байты реального сегмента —
//! префиксное сравнение это покрывает.

/// Минимальная длина общего префикса, считающая фейком. 32 байта: у TLS
/// ClientHello Random живёт на offset 11..43 — любой РЕАЛЬНЫЙ hello-сегмент
/// ≥ 32 байт гарантированно расходится с фиксированным фейком раньше, чем
/// префикс дорастёт до 32; при этом split-сегменты короче 32 байт (в т.ч.
/// классический split-pos=1) фильтр не трогает.
pub const MIN_FAKE_MATCH_LEN: usize = 32;

/// Байты одного фейка: содержимое файла + имя файла (для честного лога).
pub struct FakeBlob {
    pub source: String,
    pub bytes: Vec<u8>,
}

/// Загруженные байты фейков активной стратегии winws. Пустой набор — фильтр
/// инертен (все пакеты считаются реальными, поведение как до фильтра).
pub struct FakeBlobs {
    blobs: Vec<FakeBlob>,
    /// Фейк-хосты hostfakesplit из `--dpi-desync-hostfakesplit-mod=host=X`
    /// (тот же SSOT final_args, что у блобов). Zapret генерит подставной хост
    /// как `<случайные [a-z0-9]>.<X>` либо хвост `<X>` (та же длина слота), и
    /// сборка ClientHello у сниффера завершается на фейке — по этому списку
    /// SniCollector отличает фейк-хост от реального.
    fake_hosts: Vec<String>,
}

impl FakeBlobs {
    /// Собирает блобы и фейк-хосты из аргументов запуска winws. Возвращает
    /// набор и список человекочитаемых предупреждений (файл не прочитан /
    /// пуст / без пути) — молчаливых ошибок нет (core §2.2).
    pub fn from_winws_args(args: &[String]) -> (Self, Vec<String>) {
        let mut blobs: Vec<FakeBlob> = Vec::new();
        let mut fake_hosts: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        for arg in args {
            let Some(value) = arg.strip_prefix("--dpi-desync-hostfakesplit-mod=") else {
                continue;
            };
            for part in value.split(',') {
                if let Some(host) = part.strip_prefix("host=") {
                    let host = host.trim();
                    if !host.is_empty() && !fake_hosts.iter().any(|h| h == host) {
                        fake_hosts.push(host.to_string());
                    }
                }
            }
        }
        for arg in args {
            if !is_fake_payload_arg(arg) {
                continue;
            }
            let Some(path) = arg.split_once('=').map(|(_, p)| p.trim()) else {
                warnings.push(format!("аргумент фейка без пути: {}", arg));
                continue;
            };
            if path.is_empty() {
                warnings.push(format!("аргумент фейка с пустым путём: {}", arg));
                continue;
            }
            match std::fs::read(path) {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        warnings.push(format!("файл фейка пуст: {}", path));
                        continue;
                    }
                    // Один файл часто назначен и фейком, и seqovl-паттерном
                    // (и в нескольких секциях стратегии) — дубликаты бесполезны.
                    if blobs.iter().any(|b| b.bytes == bytes) {
                        continue;
                    }
                    let source = std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.to_string());
                    blobs.push(FakeBlob { source, bytes });
                }
                Err(e) => warnings.push(format!("фейк не прочитан {}: {}", path, e)),
            }
        }
        (Self { blobs, fake_hosts }, warnings)
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Суммарный размер блобов — для лога загрузки.
    pub fn total_len(&self) -> usize {
        self.blobs.iter().map(|b| b.bytes.len()).sum()
    }

    /// Имена файлов-фейков — для лога загрузки.
    pub fn source_names(&self) -> Vec<String> {
        self.blobs.iter().map(|b| b.source.clone()).collect()
    }

    /// Является ли исходящий payload подставным пакетом winws: общий префикс
    /// с любым блобом ≥ [`MIN_FAKE_MATCH_LEN`] байт.
    pub fn is_fake_payload(&self, payload: &[u8]) -> bool {
        if payload.len() < MIN_FAKE_MATCH_LEN {
            return false;
        }
        self.blobs
            .iter()
            .any(|b| has_common_prefix_at_least(&b.bytes, payload, MIN_FAKE_MATCH_LEN))
    }

    /// Похож ли hostname на подставной хост hostfakesplit (из конфига winws):
    /// сам хост модификатора или его «поддомен» — zapret генерит
    /// `<случайные [a-z0-9]>.<host>` либо хвост `<host>` (сохраняя длину
    /// слота хоста ClientHello), и сборка ClientHello у сниффера завершается
    /// на фейке: сборка завершается на фейке, реальный хост живёт в
    /// конфликтных перезаписях merge_at (см. SniCollector::candidate_hosts).
    pub fn is_fake_hostname(&self, host: &str) -> bool {
        self.fake_hosts
            .iter()
            .any(|f| host == f || host.ends_with(&format!(".{f}")))
    }
}

/// Аргумент winws, задающий файл с подставным payload. Префиксные проверки
/// покрывают все текущие `--dpi-desync-fake-*` (tls/http/quic/unknown-*/
/// discord/stun/…) и оба варианта seqovl-паттерна, а также будущие —
/// перечислять каждый по имени не нужно.
fn is_fake_payload_arg(arg: &str) -> bool {
    arg.starts_with("--dpi-desync-fake-")
        || arg.starts_with("--dpi-desync-split-seqovl-pattern=")
        || arg.starts_with("--dpi-desync-split2-seqovl-pattern=")
}

/// Общий префикс `a` и `b` достигает `need` байт (без построения префикса).
fn has_common_prefix_at_least(a: &[u8], b: &[u8], need: usize) -> bool {
    let limit = a.len().min(b.len());
    if limit < need {
        return false;
    }
    a[..need] == b[..need]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Синтетический TLS-фейк: record(5) + handshake(4) + version(2) +
    /// фиксированный Random(32) + добивка. Структура как у реальных файлов
    /// из bin/ (tls_clienthello_*.bin), без реальных данных пользователя.
    fn synthetic_tls_fake(random_byte: u8, total: usize) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x03];
        v.resize(43, random_byte);
        v.resize(total, 0xEE);
        v
    }

    /// Синтетический QUIC-фейк: long header (flags+version) + DCID(len+20).
    fn synthetic_quic_fake(dcid_byte: u8) -> Vec<u8> {
        let mut v = vec![0xC3, 0x00, 0x00, 0x00, 0x01, 0x14];
        v.resize(26, dcid_byte);
        v.resize(1200, 0x5A);
        v
    }

    /// Хостfakesplit-модификатор из final_args обязан попадать в фейк-хосты:
    /// по ним SniCollector отличает фейк-хост от реального (кейс слепоты
    /// Реаниматора 11.11.26: сборка ClientHello завершается на фейке
    /// `<случайные>.www.google.com`, реальный хост живёт в перезаписях).
    #[test]
    fn hostfakesplit_mod_args_yield_fake_hosts() {
        let (fakes, warns) = FakeBlobs::from_winws_args(&[
            "--filter-tcp=443".to_string(),
            "--dpi-desync-hostfakesplit-mod=host=www.google.com".to_string(),
            "--dpi-desync-hostfakesplit-mod=host=mail.ru,altorder=1".to_string(),
        ]);
        assert!(warns.is_empty(), "файловые аргументы отсутствуют — предупреждений нет");
        assert_eq!(
            fakes.fake_hosts,
            vec!["www.google.com".to_string(), "mail.ru".to_string()]
        );
        // Zapret-генерация: случайный префикс + точка + хост модификатора.
        assert!(fakes.is_fake_hostname("q7x2m9w4z1n5v8c3pd.www.google.com"));
        assert!(fakes.is_fake_hostname("www.google.com"));
        assert!(fakes.is_fake_hostname("qq22xx44zz66ww88yy00aa11b.mail.ru"));
        assert!(fakes.is_fake_hostname("mail.ru"));
        // Реальные хосты — не фейки.
        assert!(!fakes.is_fake_hostname("rr3---sn-ixh7yn7e.googlevideo.com"));
        assert!(!fakes.is_fake_hostname("youtube.com"));
        assert!(!fakes.is_fake_hostname("example.org"));
    }

    /// Без hostfakesplit-модификатора в конфиге фейк-хостов нет — селектор
    /// hostname инертен (старое поведение целиком).
    #[test]
    fn no_hostfakesplit_mod_yields_empty_fake_hosts() {
        let (fakes, warns) = FakeBlobs::from_winws_args(&[
            "--dpi-desync-fake-tls=C:/nonexistent/fake.bin".to_string(),
        ]);
        assert_eq!(fakes.fake_hosts.len(), 0);
        assert_eq!(warns.len(), 1, "файловый аргумент с несуществующим путём даёт предупреждение");
        assert!(!fakes.is_fake_hostname("www.google.com"));
    }

    #[test]
    fn full_fake_and_seqovl_prefixes_are_fake() {
        let fake = synthetic_tls_fake(0xAB, 664);
        let blobs = FakeBlobs { fake_hosts: Vec::new(), blobs: vec![FakeBlob { source: "t.bin".into(), bytes: fake.clone() }] };
        // Полная подставная копия (фейк-пакет).
        assert!(blobs.is_fake_payload(&fake));
        // Чистый seqovl-паттерн (префикс файла).
        assert!(blobs.is_fake_payload(&fake[..654]));
        // seqovl-паттерн + первый байт реального сегмента в одном пакете.
        let mut mixed = fake[..654].to_vec();
        mixed.push(0xAA);
        assert!(blobs.is_fake_payload(&mixed));
    }

    #[test]
    fn short_real_segments_and_real_hello_are_not_fake() {
        let fake = synthetic_tls_fake(0xAB, 664);
        let blobs = FakeBlobs { fake_hosts: Vec::new(), blobs: vec![FakeBlob { source: "t.bin".into(), bytes: fake }] };
        // Короткие split-сегменты (split-pos=1 и похожие) — не фильтруются.
        assert!(!blobs.is_fake_payload(&[0x16]));
        assert!(!blobs.is_fake_payload(&[0x16, 0x03, 0x01, 0x01, 0x00]));
        // Меньше MIN_FAKE_MATCH_LEN — никогда фейк.
        assert!(!blobs.is_fake_payload(&vec![0xAB; MIN_FAKE_MATCH_LEN - 1]));
        // Реальный hello: та же шапка, но СВОЙ Random на offset 11..43.
        let real = synthetic_tls_fake(0xCD, 517);
        assert!(!blobs.is_fake_payload(&real));
        // Совпадение ДЛИНЫ с фейком не делает payload фейком.
        let real_same_len = synthetic_tls_fake(0xCD, 664);
        assert!(!blobs.is_fake_payload(&real_same_len));
    }

    #[test]
    fn quic_fake_matches_real_initial_with_own_dcid_does_not() {
        let fake = synthetic_quic_fake(0x42);
        let blobs = FakeBlobs { fake_hosts: Vec::new(), blobs: vec![FakeBlob { source: "q.bin".into(), bytes: fake.clone() }] };
        assert!(blobs.is_fake_payload(&fake));
        // Реальный Initial: тот же flags/version/DCID-len, но свой DCID.
        let mut real = vec![0xC3, 0x00, 0x00, 0x00, 0x01, 0x14];
        real.resize(26, 0x77);
        real.resize(1200, 0x5A);
        assert!(!blobs.is_fake_payload(&real));
    }

    #[test]
    fn empty_blobs_never_filter() {
        let blobs = FakeBlobs { fake_hosts: Vec::new(), blobs: Vec::new() };
        assert!(blobs.is_empty());
        assert!(!blobs.is_fake_payload(&vec![0x16; 1200]));
    }

    #[test]
    fn extraction_reads_dedupes_and_warns() {
        let dir = std::env::temp_dir().join(format!("dpi_gui_fakepayloads_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("создание temp-папки");
        let tls_path = dir.join("tls.bin");
        let quic_path = dir.join("quic.bin");
        std::fs::write(&tls_path, synthetic_tls_fake(0xAB, 664)).expect("запись tls.bin");
        std::fs::write(&quic_path, synthetic_quic_fake(0x42)).expect("запись quic.bin");

        let args: Vec<String> = vec![
            "--filter-tcp=443".to_string(),
            format!("--dpi-desync-fake-tls={}", tls_path.display()),
            // Тот же файл как seqovl-паттерн и во второй секции — дедуп.
            format!("--dpi-desync-split-seqovl-pattern={}", tls_path.display()),
            format!("--dpi-desync-fake-quic={}", quic_path.display()),
            // Нечитаемый файл — честное предупреждение, не молчание.
            format!("--dpi-desync-fake-http={}/missing.bin", dir.display()),
            // Не фейк-аргумент — игнорируется.
            "--hostlist=x.txt".to_string(),
        ];
        let (blobs, warnings) = FakeBlobs::from_winws_args(&args);
        assert_eq!(blobs.len(), 2, "tls + quic, дубликат seqovl схлопнут");
        assert_eq!(blobs.total_len(), 664 + 1200);
        assert_eq!(blobs.source_names(), vec!["tls.bin", "quic.bin"]);
        assert_eq!(warnings.len(), 1, "одна читаемая причина: missing.bin");
        assert!(warnings[0].contains("missing.bin"), "{}", warnings[0]);
        // Загруженные блобы реально фильтруют.
        assert!(blobs.is_fake_payload(&synthetic_tls_fake(0xAB, 664)));
        assert!(!blobs.is_fake_payload(&synthetic_tls_fake(0xCD, 664)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
