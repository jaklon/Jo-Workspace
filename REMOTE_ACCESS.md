# Akses Jo Workspace dari iPhone melalui Tailscale

## Sekali saat setup

1. Pasang Tailscale pada laptop dan iPhone.
2. Login ke akun Tailscale yang sama pada kedua perangkat.
3. Jalankan `start-web.ps1` dari PowerShell di root project.
4. Di PowerShell lain, jalankan `enable-tailscale-serve.ps1`.
5. Buka URL HTTPS `.ts.net` yang ditampilkan oleh Tailscale Serve dari Safari.
6. Salin token dari `data/runtime/api-token` di laptop lalu masukkan ke dialog
   koneksi. Jangan kirim token melalui kanal publik.

Tailscale Serve meneruskan HTTPS privat ke FastAPI pada
`http://127.0.0.1:8010`. Port FastAPI dan Ollama tidak perlu dibuka di router
atau Windows Firewall.

## Penggunaan berikutnya

Jalankan:

```powershell
.\start-web.ps1 -SkipBuild
```

Konfigurasi Tailscale Serve berjalan di background dan dapat diperiksa dengan:

```powershell
tailscale serve status
```

Jika kode frontend berubah, jalankan `start-web.ps1` tanpa `-SkipBuild` untuk
membangun ulang frontend sebelum server dimulai.

Riwayat chat disimpan di IndexedDB browser pada masing-masing perangkat; gambar
tidak disalin ke riwayat browser. Riwayat di Electron dan Safari tidak otomatis
tersinkronisasi. Lampiran disimpan terbatas pada backend dan dilepas melalui chip
lampiran pada sesi.
