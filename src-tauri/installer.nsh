; NSIS installer hooks for DPI_GUI.
; Перед копированием/удалением файлов гасим запущенное приложение и обход,
; иначе winws.exe и загруженная служба WinDivert держат bin/WinDivert64.sys
; заблокированным и установщик падает с "Error opening file for writing".

!macro StopDpiGui
  DetailPrint "Останавливаем DPI_GUI и WinDivert..."
  nsExec::Exec 'taskkill /F /IM winws.exe /T'
  nsExec::Exec 'taskkill /F /IM dpi_gui.exe /T'
  ; Останавливаем службу драйвера WinDivert (имя зависит от версии winws)
  nsExec::Exec 'sc stop WinDivert'
  nsExec::Exec 'sc stop WinDivert1.4'
  nsExec::Exec 'sc stop windivert'
  ; Даём ядру время выгрузить драйвер и освободить .sys
  Sleep 1500
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro StopDpiGui
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro StopDpiGui
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
