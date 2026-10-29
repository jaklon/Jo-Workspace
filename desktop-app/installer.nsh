!macro customInstall
  SetShellVarContext current
  CreateShortCut "$DESKTOP\Uninstall Jo Workspace.lnk" "$WINDIR\explorer.exe" "ms-settings:appsfeatures" "$INSTDIR\${UNINSTALL_FILENAME}" 0 SW_SHOWNORMAL "" "Buka Installed apps, pilih Jo Workspace lalu Uninstall"
!macroend

!macro customUnInit
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Hapus aplikasi Jo Workspace? Data lokal tetap disimpan." IDYES +2
    Quit
  ${EndIf}
!macroend

!macro customUnInstall
  SetShellVarContext current
  Delete "$DESKTOP\Uninstall Jo Workspace.lnk"
!macroend
