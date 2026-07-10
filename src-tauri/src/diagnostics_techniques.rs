use std::fs;
use std::thread;
use std::time::Duration;
use tauri::AppHandle;
use crate::{config, process};
use crate::diagnostics_probe::{http_classify_with, HttpResult, normalize_host};

/// Одна desync-техника winws, изолированно проверяемая против заблокированного домена.
pub struct TechniqueSpec {
    pub name: String,
    /// Часть аргументов после `--filter-tcp=443 --hostlist=...` (без портов/хостлиста).
    pub desync: String,
}

/// Набор кандидатов. Порядок важен: первый подошедший используется для авто-профиля.
pub fn all_techniques() -> Vec<TechniqueSpec> {
    vec![
        TechniqueSpec {
            name: "fake-ts".into(),
            desync: "--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{BIN_DIR}/tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls-mod=none".into(),
        },
        TechniqueSpec {
            name: "multisplit-1".into(),
            desync: "--dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"{BIN_DIR}/tls_clienthello_www_google_com.bin\"".into(),
        },
        TechniqueSpec {
            name: "multisplit-2".into(),
            desync: "--dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"{BIN_DIR}/tls_clienthello_www_google_com.bin\"".into(),
        },
        TechniqueSpec {
            name: "hostfakesplit".into(),
            desync: "--dpi-desync=hostfakesplit --dpi-desync-fooling=ts --dpi-desync-hostfakesplit-mod=host=www.google.com".into(),
        },
        TechniqueSpec {
            name: "badseq".into(),
            desync: "--dpi-desync=fake --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2".into(),
        },
        TechniqueSpec {
            name: "fakedsplit".into(),
            desync: "--dpi-desync=fake,fakedsplit --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2 --dpi-desync-fakedsplit-pattern=0x00".into(),
        },
        TechniqueSpec {
            name: "autottl".into(),
            desync: "--dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12".into(),
        },
        TechniqueSpec {
            name: "rnd-sni".into(),
            desync: "--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=! --dpi-desync-fake-tls-mod=rnd,sni=www.google.com".into(),
        },
        TechniqueSpec {
            name: "syndata".into(),
            desync: "--dpi-desync=syndata,multidisorder".into(),
        },
    ]
}

/// Прогон одной техники: пишем временный хостлист с доменом, стартуем winws,
/// проверяем доступность сайта, останавливаем. Возвращает (прошла, деталь).
pub fn test_technique(app: &AppHandle, spec: &TechniqueSpec, domain: &str, game_filter: bool) -> (bool, String) {
    let lists_dir = config::get_app_dir().join("lists");
    let bin_dir = process::get_bin_dir();
    let safe = spec.name.replace(|c: char| !c.is_alphanumeric(), "_");
    let hostlist_name = format!("diag-{}.txt", safe);
    let hostlist_path = lists_dir.join(&hostlist_name);

    if let Err(e) = fs::write(&hostlist_path, format!("{}\n", domain)) {
        return (false, format!("ошибка записи хостлиста: {}", e));
    }

    let bin_str = bin_dir.to_string_lossy().replace("\\", "/");
    let lists_str = lists_dir.to_string_lossy().replace("\\", "/");
    let desync = spec
        .desync
        .replace("{BIN_DIR}", &bin_str)
        .replace("{LISTS_DIR}", &lists_str);

    let raw_args = format!(
        "--wf-tcp=443 --filter-tcp=443 --hostlist=\"{}/{}\" {}",
        lists_str, hostlist_name, desync
    );

    if let Err(e) = process::start_winws_custom(app.clone(), &raw_args, game_filter) {
        return (false, format!("запуск winws: {}", e));
    }

    // Даём WinDivert время на перехват
    thread::sleep(Duration::from_secs(3));

    let target = format!("https://{}/", domain);
    let res = http_classify_with(&target, 5);
    let _ = process::stop_winws();
    thread::sleep(Duration::from_millis(800));

    let passed = matches!(res, HttpResult::Ok(_));
    let detail = match res {
        HttpResult::Ok(s) => format!("OK ({})", s),
        other => format!("{:?}", other),
    };
    (passed, detail)
}

/// Вспомогательная нормализация (чтобы диагностика не дублировала логику).
pub fn norm(input: &str) -> String {
    normalize_host(input)
}
