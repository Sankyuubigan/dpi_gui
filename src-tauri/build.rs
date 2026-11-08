fn main() {
    let mut windows = tauri_build::WindowsAttributes::new();
    // Вшиваем манифест для запроса прав Администратора (необходимо для WinDivert)
    // ВАЖНО: Мы также обязаны добавить зависимость Common-Controls v6, 
    // иначе ядро отрисовки (wry/tao) не найдет функцию TaskDialogIndirect и прога крашнется.
    windows = windows.app_manifest(
        r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
      <security>
          <requestedPrivileges>
              <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
          </requestedPrivileges>
      </security>
  </trustInfo>
</assembly>
"#,
    );

    // AppManifest::commands задаёт ЯВНЫЙ список команд приложения: только
    // перечисленные здесь получают permission allow-<команда> (дефисы вместо
    // подчёркиваний) — неперечисленная команда запрещена ВСЕМ («Command
    // init_app not allowed by ACL», инцидент 08.11.26: список из одних
    // browser-команд убил автоген прав init_app/get_config/get_profiles —
    // «профили исчезли»). SSOT списка — generate_handler в main.rs: любая
    // новая команда добавляется СЮДА + allow-* в capabilities/default.json.
    // browser_ctx_action нужна внешним страницам (remote capability
    // browser.json), остальные — главному окну (default.json).
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(windows)
            .app_manifest(tauri_build::AppManifest::new().commands(&[
                "init_app",
                "get_config",
                "save_config",
                "get_profiles",
                "open_file",
                "start_bypass",
                "stop_bypass",
                "check_status",
                "run_domain_analysis",
                "cancel_operation",
                "run_mass_analysis",
                "pick_dns",
                "apply_solution",
                "apply_solutions_batch",
                "test_profile",
                "run_diagnostics",
                "apply_hosts_entry",
                "remove_hosts_entry",
                "hosts_entries_for_domains",
                "verify_site_via_ip",
                "browser_open",
                "browser_close",
                "browser_status",
                "browser_set_bounds",
                "browser_hide",
                "browser_show",
                "browser_apply_mapping",
                "browser_apply_pick",
                "browser_ctx_action",
                "get_doh_services",
                "grab_cookies",
                "cookies_status",
                "cookies_browsers",
            ])),
    )
    .expect("failed to run tauri-build");
}