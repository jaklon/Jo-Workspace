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

Pada Jo Workspace, buka **Settings → Kesehatan & iPhone** dan pilih **Periksa
ulang**. Dashboard memisahkan layanan inti dan komponen opsional, serta memberi
petunjuk ketika suatu layanan tidak tersedia. Bagian iPhone menampilkan alamat
dan QR hanya jika Tailscale Serve terdeteksi mengarah ke backend yang sedang
digunakan; QR tidak memuat token. Pemeriksaan ini tidak membuktikan iPhone sudah
terhubung. Pindai QR atau buka alamatnya di Safari untuk memastikan akses.

Tombol **Ekspor diagnostik** menyimpan waktu dan status pemeriksaan saja, tanpa
token, isi chat, nama perangkat, alamat, atau lokasi file. Pemeriksaan browser
menguji penulisan IndexedDB lokal sementara dan tidak menggantikan backup.

Jalankan backend dari root project:

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8010
```

Konfigurasi Tailscale Serve berjalan di background dan dapat diperiksa dengan:

```powershell
tailscale serve status
```

Backend Electron yang dipaketkan dapat memakai runtime dan port berbeda dari
backend source. Alamat Serve hanya ditampilkan jika menunjuk ke backend yang
sedang dibuka; dua backend terpisah memiliki data dan token masing-masing.

Jika kode frontend berubah, jalankan `npm run build` di folder `desktop-app`
sebelum memulai backend agar aset web terbaru disajikan.

Riwayat chat dan project disimpan di IndexedDB perangkat dan disinkronkan ke
backend yang sama setelah login. Perubahan saat offline disimpan dan dicoba ulang
ketika koneksi kembali; status dan konflik ditampilkan di aplikasi. Tinjau kedua
versi sebelum memilih salah satunya. Gunakan hanya satu tab untuk setiap profil
browser agar data lokal tidak saling menimpa. Data yang belum dikirim tetap
bergantung pada penyimpanan perangkat, sehingga cadangan tetap diperlukan.

Sinkronisasi memakai backend yang sama dan token aksesnya, bukan layanan cloud
atau enkripsi ujung-ke-ujung. Gunakan koneksi privat HTTPS seperti Tailscale
Serve. Lampiran tetap berada pada backend dan referensinya ikut disinkronkan;
gambar sementara dan tindakan/proposal yang belum dieksekusi tidak disalin.
Lampiran tunduk pada masa penyimpanan backend dan bukan pengganti cadangan.
