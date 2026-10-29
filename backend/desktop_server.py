"""Standalone entry point bundled into the desktop installer."""
import argparse
import ctypes
import multiprocessing
import os
import threading


def watch_parent(parent_pid, server):
    if os.name != "nt" or not parent_pid:
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x00100000, False, parent_pid)
    if not handle:
        server.should_exit = True
        return
    try:
        kernel.WaitForSingleObject(handle, 0xFFFFFFFF)
        server.should_exit = True
    finally:
        kernel.CloseHandle(handle)


def run():
    parser = argparse.ArgumentParser(description="Jo Workspace private desktop backend")
    parser.add_argument("--port", type=int, default=18010)
    parser.add_argument("--parent-pid", type=int, default=0)
    args = parser.parse_args()
    import uvicorn
    from main import app
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port,
                                         access_log=False, timeout_graceful_shutdown=3))
    if args.parent_pid:
        threading.Thread(target=watch_parent, args=(args.parent_pid, server), daemon=True).start()
    server.run()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run()
