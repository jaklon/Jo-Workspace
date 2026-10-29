"""Free local desktop: signed installed Python runtime + installed browser app mode."""
import ctypes
import json
import os
from pathlib import Path
import socket
import re
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def read_config(path=None):
    path = Path(path or Path(__file__).with_name("install.json"))
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("format") != "agent-os-local-desktop-v1" or config.get("port") != 8010:
        raise ValueError("Konfigurasi peluncur lokal tidak valid.")
    for field in ("root", "pythonw", "browser", "data_dir", "workspace", "install_dir"):
        if not Path(config[field]).is_absolute():
            raise ValueError("Konfigurasi harus memakai path absolut.")
    if Path(config["install_dir"]).resolve() != path.parent.resolve():
        raise ValueError("Direktori instalasi tidak sesuai konfigurasi.")
    return config


def assert_owned_backend(config):
    import psutil
    expected_script = str((Path(config["root"]) / "scripts/local_desktop_server.py").resolve()).lower()
    allowed_exes = {str(Path(config["pythonw"]).resolve()).lower(), str((Path(sys.base_prefix) / "pythonw.exe").resolve()).lower()}
    connections = [c for c in psutil.net_connections(kind="tcp") if c.status == "LISTEN" and c.laddr.ip == "127.0.0.1" and c.laddr.port == config["port"]]
    if not connections:
        raise URLError("Backend belum mendengarkan koneksi.")
    process = psutil.Process(connections[0].pid)
    command = process.cmdline()
    if process.username() != psutil.Process().username() or process.exe().lower() not in allowed_exes or expected_script not in [str(Path(arg).resolve()).lower() for arg in command if arg.endswith(".py")] or "--port" not in command or command[command.index("--port") + 1] != str(config["port"]):
        raise RuntimeError("Port desktop digunakan proses lain. Token tidak dikirim; peluncuran dibatalkan.")


def api(config, path, body=None):
    assert_owned_backend(config)
    token = (Path(config["data_dir"]) / "api-token").read_text(encoding="utf-8").strip()
    if len(token) < 24:
        raise RuntimeError("Token lokal tidak valid. Periksa konfigurasi Jo Workspace.")
    request = Request(f"http://127.0.0.1:{config['port']}" + path,
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                      data=json.dumps(body).encode() if body is not None else None)
    with urlopen(request, timeout=3) as response:
        return json.load(response)


def port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def verify_stage(config):
    caps = api(config, "/api/security/capabilities")
    pentest = api(config, "/api/pentest/capabilities")
    if caps.get("stage") != 7 or caps.get("execution_enabled") is not False or pentest.get("execution_enabled") is not False:
        raise RuntimeError("Backend bukan tahap 7 yang terkunci. Peluncuran dibatalkan.")


def start_backend(config):
    root = Path(config["root"])
    pythonw = Path(config["pythonw"])
    if not pythonw.is_file() or not (root / "scripts" / "local_desktop_server.py").is_file() or not (root / "desktop-app" / "out" / "renderer" / "index.html").is_file():
        raise RuntimeError("Runtime/aset aplikasi tidak lengkap. Pasang ulang peluncur dari folder project.")
    if port_available(config["port"]):
        logs = Path(config["install_dir"]) / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        log_path = logs / "backend.log"
        child_env = {key: value for key, value in os.environ.items() if key != "AGENT_API_TOKEN"}
        with log_path.open("a" if not log_path.exists() or log_path.stat().st_size < 2_000_000 else "w", encoding="utf-8") as log:
            subprocess.Popen([str(pythonw), "-B", str(root / "scripts" / "local_desktop_server.py"), "--port", str(config["port"])],
                             cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                             env={**child_env, "AGENT_DATA_DIR": config["data_dir"], "AGENT_WORKSPACE": config["workspace"],
                                  "AGENT_WEB_DIR": str(root / "desktop-app" / "out" / "renderer"), "AGENT_ALLOWED_ORIGINS": f"http://127.0.0.1:{config['port']}"})
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                verify_stage(config)
                return
            except (OSError, URLError, HTTPError):
                time.sleep(0.25)
        raise RuntimeError(f"Backend belum siap. Lihat log: {log_path}")
    # Never kill or take over an unknown service occupying the port.
    verify_stage(config)


def start_ollama():
    if os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") not in ("http://127.0.0.1:11434", "http://localhost:11434"):
        return
    try:
        with urlopen("http://127.0.0.1:11434/api/tags", timeout=1.5):
            return
    except (URLError, OSError):
        pass
    choices = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Ollama/ollama.exe", Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Ollama/ollama.exe"]
    executable = next((p for p in choices if p.is_file()), None)
    if executable:
        subprocess.Popen([str(executable), "serve"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def launch(config):
    browser = Path(config["browser"])
    if not browser.is_file() or browser.name.lower() not in ("chrome.exe", "msedge.exe"):
        raise RuntimeError("Browser Chrome/Edge tidak ditemukan. Pasang ulang peluncur lokal.")
    start_backend(config)
    start_ollama()
    ticket = api(config, "/api/desktop/session-ticket", {})
    path = ticket.get("path", "")
    if not re.fullmatch(r"/_desktop/connect/[A-Za-z0-9_-]{43}", path):
        raise RuntimeError("Tautan sesi desktop tidak valid.")
    # Same Chrome profile and same origin retain existing web Projects/chats.
    subprocess.Popen([str(browser), "--app=" + f"http://127.0.0.1:{config['port']}" + path, "--no-first-run"],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_idle_backend(config):
    """Only stop a backend managed by this launcher; a web server may have no stop route."""
    metrics = api(config, "/api/metrics")
    if metrics.get("active") or metrics.get("waiting"):
        raise RuntimeError("Pekerjaan masih berjalan. Tunggu sebelum uninstall.")
    try:
        api(config, "/api/desktop/stop", {})
    except HTTPError as exc:
        if exc.code != 404:
            raise


def remove_installation(config):
    """Called only AFTER the operator clicks Yes. User data and source stay intact."""
    import winreg
    import win32com.client
    try:
        stop_idle_backend(config)
    except HTTPError:
        raise RuntimeError("Backend menolak penghentian; uninstall dibatalkan.")
    except URLError:
        pass  # Already stopped.
    shell = win32com.client.Dispatch("WScript.Shell")
    install_dir = Path(config["install_dir"]).resolve()
    launcher = install_dir / "launcher.pyw"
    for item in config["shortcuts"]:
        path = Path(item["path"])
        if path.is_file():
            link = shell.CreateShortcut(str(path))
            if str(launcher).lower() not in link.Arguments.lower() or Path(link.TargetPath).resolve() != Path(config["pythonw"]).resolve():
                continue  # Preserve shortcuts the user has replaced since installation.
            backup = install_dir / "backups" / item["backup"]
            if backup.is_file():
                path.write_bytes(backup.read_bytes())
            else:
                path.unlink()
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AgentOSLocal")
    except FileNotFoundError:
        pass
    # Keep manifest/backups for repair, and all browser/backend data. No recursive deletes.


def main():
    import tkinter as tk
    from tkinter import messagebox, ttk
    root = tk.Tk()
    root.withdraw()
    try:
        config = read_config()
        if sys.argv[1:] == ["--uninstall"]:
            root.title("Uninstall Jo Workspace Local")
            root.geometry("460x160")
            root.resizable(False, False)
            ttk.Label(root, text="Uninstall Jo Workspace Local", font=("Segoe UI", 13)).pack(pady=(24, 10))
            ttk.Label(root, text="Konfirmasi diperlukan. Data lokal tetap disimpan.").pack()
            root.deiconify()
            root.lift()
            root.attributes("-topmost", True)
            root.update_idletasks()
            if messagebox.askyesno("Uninstall Jo Workspace Local", "Hapus peluncur Jo Workspace Local dari Desktop dan Start Menu?\n\nChat, Project, Engagement, RoE, dan folder project tetap disimpan.\n\nPilih Tidak untuk membatalkan.", default=messagebox.NO, icon=messagebox.WARNING, parent=root):
                remove_installation(config)
                messagebox.showinfo("Jo Workspace Local", "Peluncur dihapus. Data lokal tetap disimpan.", parent=root)
            return
        if sys.argv[1:]:
            raise ValueError("Argumen peluncur tidak dikenali.")
        root.title("Jo Workspace Local")
        root.geometry("440x150")
        root.resizable(False, False)
        ttk.Label(root, text="Membuka Jo Workspace · Tahap 7", font=("Segoe UI", 13)).pack(pady=(22, 8))
        ttk.Label(root, text="Menyiapkan backend lokal dan jendela desktop…").pack()
        progress = ttk.Progressbar(root, mode="indeterminate")
        progress.pack(fill="x", padx=30, pady=14)
        progress.start()
        root.deiconify()
        def finished(error=None):
            if error:
                messagebox.showerror("Jo Workspace Local", str(error), parent=root)
            root.destroy()
        def work():
            handle = None
            try:
                if os.name == "nt":
                    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel.CreateMutexW.restype = ctypes.c_void_p
                    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
                    handle = kernel.CreateMutexW(None, True, "Local\\AgentOSLocalLauncher-v1")
                    if not handle or ctypes.get_last_error() == 183:
                        raise RuntimeError("Jo Workspace sedang dibuka. Tunggu beberapa detik lalu coba lagi.")
                launch(config)
            except Exception as exc:
                root.after(0, finished, exc)
            else:
                root.after(0, finished)
            finally:
                if handle:
                    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                    kernel.CloseHandle(handle)
        threading.Thread(target=work, daemon=True).start()
        root.mainloop()
    except Exception as exc:
        messagebox.showerror("Jo Workspace Local", str(exc), parent=root)
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    main()
