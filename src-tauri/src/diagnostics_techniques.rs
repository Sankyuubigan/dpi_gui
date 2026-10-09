use std::fs;
use std::thread;
use std::time::Duration;
use tauri::AppHandle;
use crate::{config, process};
use crate::diagnostics_probe::{http_classify_with, HttpResult, normalize_host};

/// РћРґРЅР° desync-С‚РµС…РЅРёРєР° winws, РёР·РѕР»РёСЂРѕРІР°РЅРЅРѕ РїСЂРѕРІРµСЂСЏРµРјР°СЏ РїСЂРѕС‚РёРІ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅРЅРѕРіРѕ РґРѕРјРµРЅР°.
pub struct TechniqueSpec {
    pub name: String,
    /// Р§Р°СЃС‚СЊ Р°СЂРіСѓРјРµРЅС‚РѕРІ РїРѕСЃР»Рµ `--filter-tcp=443 --hostlist=...` (Р±РµР· РїРѕСЂС‚РѕРІ/С…РѕСЃС‚Р»РёСЃС‚Р°).
    pub desync: String,
}

/// РќР°Р±РѕСЂ РєР°РЅРґРёРґР°С‚РѕРІ. РџРѕСЂСЏРґРѕРє РІР°Р¶РµРЅ: РїРµСЂРІС‹Р№ РїРѕРґРѕС€РµРґС€РёР№ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РґР»СЏ Р°РІС‚Рѕ-РїСЂРѕС„РёР»СЏ.
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

/// РџСЂРѕРіРѕРЅ РѕРґРЅРѕР№ С‚РµС…РЅРёРєРё: РїРёС€РµРј РІСЂРµРјРµРЅРЅС‹Р№ С…РѕСЃС‚Р»РёСЃС‚ СЃ РґРѕРјРµРЅРѕРј, СЃС‚Р°СЂС‚СѓРµРј winws,
/// РїСЂРѕРІРµСЂСЏРµРј РґРѕСЃС‚СѓРїРЅРѕСЃС‚СЊ СЃР°Р№С‚Р°, РѕСЃС‚Р°РЅР°РІР»РёРІР°РµРј. Р’РѕР·РІСЂР°С‰Р°РµС‚ (РїСЂРѕС€Р»Р°, РґРµС‚Р°Р»СЊ).
pub fn test_technique(app: &AppHandle, spec: &TechniqueSpec, domain: &str, game_filter: bool) -> (bool, String) {
    let lists_dir = config::get_app_dir().join("lists");
    let bin_dir = process::get_bin_dir();
    let safe = spec.name.replace(|c: char| !c.is_alphanumeric(), "_");
    let hostlist_name = format!("diag-{}.txt", safe);
    let hostlist_path = lists_dir.join(&hostlist_name);

    if let Err(e) = fs::write(&hostlist_path, format!("{}\n", domain)) {
        return (false, format!("РѕС€РёР±РєР° Р·Р°РїРёСЃРё С…РѕСЃС‚Р»РёСЃС‚Р°: {}", e));
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

    if let Err(e) = process::start_winws_custom_quiet(app.clone(), &raw_args, game_filter) {
        return (false, format!("Р·Р°РїСѓСЃРє winws: {}", e));
    }

    // Р”Р°С‘Рј WinDivert РІСЂРµРјСЏ РЅР° РїРµСЂРµС…РІР°С‚
    thread::sleep(Duration::from_secs(3));

    let target = format!("https://{}/", domain);
    let res = http_classify_with(&target, 5);
    let _ = process::stop_winws();
    thread::sleep(Duration::from_millis(800));

    let passed = matches!(res, HttpResult::Ok(_));
    let detail = match res {
        HttpResult::Ok(s) => format!("OK ({})", s),
        HttpResult::BadCert => "SSL-СЃРµСЂС‚РёС„РёРєР°С‚ РЅРµРІР°Р»РёРґРµРЅ вЂ” desync-С‚РµС…РЅРёРєР° Р·РґРµСЃСЊ РЅРµ РїРѕРјРѕР¶РµС‚".to_string(),
        other => format!("{:?}", other),
    };
    (passed, detail)
}

/// Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅР°СЏ РЅРѕСЂРјР°Р»РёР·Р°С†РёСЏ (С‡С‚РѕР±С‹ РґРёР°РіРЅРѕСЃС‚РёРєР° РЅРµ РґСѓР±Р»РёСЂРѕРІР°Р»Р° Р»РѕРіРёРєСѓ).
pub fn norm(input: &str) -> String {
    normalize_host(input)
}
