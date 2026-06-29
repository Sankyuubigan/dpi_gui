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

    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run tauri-build");
}