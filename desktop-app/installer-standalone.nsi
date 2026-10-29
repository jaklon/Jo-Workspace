Unicode true
!ifndef SOURCE_DIR
  !error "SOURCE_DIR is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif
!ifndef APP_VERSION
  !error "APP_VERSION is required"
!endif
!ifndef ICON_FILE
  !error "ICON_FILE is required"
!endif

Name "Jo Workspace"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\Jo Workspace"
RequestExecutionLevel user
SetCompressor /SOLID lzma
Icon "${ICON_FILE}"
UninstallIcon "${ICON_FILE}"
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File /r "${SOURCE_DIR}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall Jo Workspace.exe"
  CreateShortCut "$DESKTOP\Jo Workspace.lnk" "$INSTDIR\Jo Workspace.exe"
  CreateShortCut "$DESKTOP\Uninstall Jo Workspace.lnk" "$WINDIR\explorer.exe" "ms-settings:appsfeatures"
  CreateDirectory "$SMPROGRAMS\Jo Workspace"
  CreateShortCut "$SMPROGRAMS\Jo Workspace\Jo Workspace.lnk" "$INSTDIR\Jo Workspace.exe"
  CreateShortCut "$SMPROGRAMS\Jo Workspace\Uninstall Jo Workspace.lnk" "$INSTDIR\Uninstall Jo Workspace.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "DisplayName" "Jo Workspace"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "Publisher" "Jo Workspace"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "DisplayIcon" "$INSTDIR\Jo Workspace.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "UninstallString" "$\"$INSTDIR\Uninstall Jo Workspace.exe$\""
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace" "NoRepair" 1
SectionEnd

Function un.onInit
  StrCmp $INSTDIR "$LOCALAPPDATA\Programs\Jo Workspace" +2
  Abort "Lokasi instalasi tidak sesuai. Uninstall dibatalkan."
  IfSilent +3
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Hapus aplikasi Jo Workspace? Data lokal tetap disimpan." IDYES +2
  Abort
FunctionEnd

Section "Uninstall"
  StrCmp $INSTDIR "$LOCALAPPDATA\Programs\Jo Workspace" +2
  Abort "Lokasi instalasi tidak sesuai. Uninstall dibatalkan."
  Delete "$DESKTOP\Jo Workspace.lnk"
  Delete "$DESKTOP\Uninstall Jo Workspace.lnk"
  Delete "$SMPROGRAMS\Jo Workspace\Jo Workspace.lnk"
  Delete "$SMPROGRAMS\Jo Workspace\Uninstall Jo Workspace.lnk"
  RMDir "$SMPROGRAMS\Jo Workspace"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Jo Workspace"
  RMDir /r "$INSTDIR"
SectionEnd
