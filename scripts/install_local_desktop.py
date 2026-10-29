"""Per-user installation of the free source-based desktop. No admin or policy changes."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import winreg


def install():
    import win32com.client
    root = Path(__file__).resolve().parents[1]
    version = json.loads((root / "desktop-app/package.json").read_text(encoding="utf-8"))["version"]
    pythonw = root / "backend/venv/Scripts/pythonw.exe"
    candidates = [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
                  Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
                  Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
                  Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe"]
    browser = next((p for p in candidates if p.is_file()), None)
    if not pythonw.is_file() or browser is None or not (root / "desktop-app/out/renderer/index.html").is_file():
        raise RuntimeError("Python runtime, Chrome/Edge, atau aset tahap 7 belum tersedia.")
    data_dir = root / "data/runtime"
    data_dir.mkdir(parents=True, exist_ok=True)
    install_dir = Path(os.environ["LOCALAPPDATA"]) / "Programs/Agent OS Local"
    install_dir.mkdir(parents=True, exist_ok=True)
    (install_dir / "backups").mkdir(exist_ok=True)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
        desktop = Path(os.path.expandvars(winreg.QueryValueEx(key, "Desktop")[0]))
    shell = win32com.client.Dispatch("WScript.Shell")
    programs = Path(shell.SpecialFolders("Programs"))
    launcher = install_dir / "launcher.pyw"
    config_path = install_dir / "install.json"
    old = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    links = []
    for directory, prefix in [(desktop, "desktop"), (programs, "startmenu")]:
        for title, uninstall in [("Jo Workspace", False), ("Uninstall Jo Workspace", True)]:
            path = directory / (title + ".lnk")
            backup_name = f"{prefix}-jo-{'uninstall' if uninstall else 'app'}.lnk"
            backup = install_dir / "backups" / backup_name
            if path.is_file() and not old:
                shutil.copy2(path, backup)
            links.append({"path": str(path), "backup": backup_name})
            link = shell.CreateShortcut(str(path))
            link.TargetPath = str(pythonw)
            link.Arguments = subprocess.list2cmdline([str(launcher)] + (["--uninstall"] if uninstall else []))
            link.WorkingDirectory = str(root)
            icon = root / "desktop-app/build/agent-os.ico"
            link.IconLocation = str(icon) + ",0" if icon.is_file() else str(pythonw) + ",0"
            link.Description = "Uninstall Jo Workspace Local (memerlukan konfirmasi)" if uninstall else "Jo Workspace · Engagement, RoE, Runs Offline, Evidence, Findings, dan Reports, dan MCP Fixture dan Orkestrasi Tahap 7"
            link.Save()
    shutil.copy2(root / "scripts/local_desktop_launcher.pyw", launcher)
    config = {"format": "agent-os-local-desktop-v1", "version": version, "root": str(root), "pythonw": str(pythonw), "browser": str(browser), "port": 8010,
              "data_dir": str(data_dir), "workspace": str(root / "workspace"), "install_dir": str(install_dir), "shortcuts": links}
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    # Remove only former shortcuts owned by this exact launcher; leave other installations alone.
    for directory in (desktop, programs):
        for title in ('Agent OS', 'Uninstall Agent OS'):
            legacy = directory / (title + '.lnk')
            if legacy.is_file():
                previous = shell.CreateShortcut(str(legacy))
                if str(launcher).lower() in previous.Arguments.lower() and Path(previous.TargetPath).resolve() == pythonw.resolve():
                    legacy.unlink()
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AgentOSLocal") as key:
        for name, value in {"DisplayName": "Jo Workspace Local", "DisplayVersion": version, "Publisher": "Jo Workspace (local source)", "InstallLocation": str(install_dir),
                            "DisplayIcon": str(root / "desktop-app/build/agent-os.ico"), "UninstallString": subprocess.list2cmdline([str(pythonw), str(launcher), "--uninstall"])}.items():
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
    # Notify Explorer after replacing the desktop icons.
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    print(json.dumps({"installed_version": version, "mode": "local-browser-desktop", "install_dir": str(install_dir), "browser": str(browser), "shortcuts": links}, indent=2))


if __name__ == "__main__":
    install()
