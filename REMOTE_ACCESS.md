# Akses Jo Workspace dari iPhone melalui Tailscale

## Sekali saat setup

1. Pasang Tailscale pada laptop dan iPhone.
2. Login ke akun Tailscale yang sama pada kedua perangkat.
3. Bangun frontend dan jalankan backend Web UI pada port 8010 (lihat bagian
   "Penggunaan berikutnya" di bawah).
4. Di PowerShell lain, jalankan `enable-tailscale-serve.ps1`.
5. Buka URL HTTPS `.ts.net` yang ditampilkan oleh Tailscale Serve dari Safari.
6. Salin token dari `data/runtime/api-token` di laptop lalu masukkan ke dialog
   koneksi. Jangan kirim token melalui kanal publik.

Tailscale Serve meneruskan HTTPS privat ke FastAPI pada
`http://127.0.0.1:8010`. Port FastAPI dan Ollama tidak perlu dibuka di router
atau Windows Firewall.

## Penggunaan berikutnya

Jalankan backend dari root project:

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8010
```

Konfigurasi Tailscale Serve berjalan di background dan dapat diperiksa dengan:

```powershell
tailscale serve status
```

Jika kode frontend berubah, jalankan `npm run build` di folder `desktop-app`
sebelum memulai backend agar aset web terbaru disajikan.

Riwayat chat disimpan di IndexedDB browser pada masing-masing perangkat; gambar
tidak disalin ke riwayat browser. Riwayat di Electron dan Safari tidak otomatis
tersinkronisasi. Lampiran disimpan terbatas pada backend dan dilepas melalui chip
lampiran pada sesi.
