# Cadangan dan pemulihan Jo Workspace dari source

Alur ini menggunakan snapshot browser dan perintah lokal. Cadangan ZIP tidak
dienkripsi dan dapat berisi teks pribadi, kode, evidence, atau rahasia dalam isi
file. Simpan di lokasi yang aksesnya dibatasi dan gunakan enkripsi penyimpanan
yang dikelola pengguna. SHA-256 mendeteksi kerusakan, bukan membuktikan asal.

Gambar asli dan dokumen asli yang sudah tidak disimpan oleh aplikasi tidak dapat
dipulihkan. Evidence asli dapat dipindahkan antar akun dengan opsi portabel dan
frasa sandi, selama backup dibuat oleh akun Windows yang dapat membuka evidence.
Isi ZIP lainnya tetap tidak dienkripsi.

## Membuat cadangan

1. Buka Jo Workspace pada profil browser yang memiliki seluruh project, lalu
   buka Settings → Kontrol data → **Snapshot browser**. Simpan JSON yang diunduh.
2. Tutup semua klien dan hentikan backend Jo Workspace. Pastikan tidak ada
   proses lain yang menulis data selama pembuatan cadangan; snapshot beberapa
   penyimpanan tidak menjadi satu transaksi global.
3. Dari root proyek jalankan, dengan mengganti path contoh:

   ```powershell
   backend\venv\Scripts\python.exe scripts\workspace_backup.py create --browser "C:\backup\jo-browser-recovery.json" --runtime "data\runtime" --workspace "workspace" --output "C:\backup\jo-recovery.zip" --portable-evidence
   ```

   Untuk Electron terpasang, gunakan runtime dan workspace milik instalasi itu,
   biasanya di `%APPDATA%\Agent OS\runtime` dan `%APPDATA%\Agent OS\workspace`.
   Periksa lokasi aktual sebelum menjalankan perintah. Sumber harus berada di
   luar direktori output. ZIP yang sudah ada tidak akan ditimpa.
   Ketik frasa sandi minimal 12 karakter ketika diminta; simpan dengan aman dan
   jangan menambahkannya ke command line. Bukti asli dienkripsi dengan AES-GCM
   menggunakan kunci yang diturunkan dari frasa sandi. Jika frasa sandi hilang,
   salinan portabel evidence asli tidak dapat dibuka. Jika evidence asli tidak
   ada, opsi portabel tetap boleh digunakan. Bila evidence asli ada, pembuatan
   backup tanpa opsi ini ditolak.

4. Perintah memeriksa ulang arsip sebelum menyimpannya dan menampilkan daftar
   file yang dikecualikan serta jumlah referensi lampiran yang sudah tidak ada.
   Token API, `.env`, `.env.*`, `.git`, `.ssh`, dan sidecar SQLite tidak
   disertakan. Pengecualian nama bukan pemindai rahasia dalam isi berkas.
5. Untuk memeriksa lagi: `backend\venv\Scripts\python.exe scripts\workspace_backup.py preview "C:\backup\jo-recovery.zip"`.

## Menyiapkan pemulihan terisolasi

```powershell
backend\venv\Scripts\python.exe scripts\workspace_backup.py restore "C:\backup\jo-recovery.zip" --destination "C:\backup\jo-restored" --portable-evidence
```

Tujuan harus belum ada. Hasil dibuat di `jo-restored\recovered` dengan folder
`runtime`, `workspace`, dan `browser`. Data aktif tidak diganti. Persetujuan RoE
yang sebelumnya aktif dicabut, job aktif dibatalkan, aksi chat/proposal tertunda
dinonaktifkan, dan worker lease dibersihkan pada salinan pemulihan. Riwayat
security tetap disimpan. Gunakan snapshot `browser\state.json` dengan tombol
**Impor** pada profil browser baru dan backend yang menggunakan runtime hasil
pemulihan. Jika ID sudah ada, impor menolak penggabungan agar tidak menimpa data.

Untuk mencoba hasil menggunakan mode source, dari PowerShell baru tetapkan
`AGENT_DATA_DIR` ke `jo-restored\recovered\runtime` dan `AGENT_WORKSPACE` ke
`jo-restored\recovered\workspace`, lalu jalankan backend pada port loopback yang
tidak dipakai sesuai README. Backend akan membuat token API baru. Masuk melalui
profil browser baru, impor `browser\state.json`, dan periksa chat, project,
lampiran serta evidence. Pengaktifan pada instalasi Electron yang sudah ada dan
penggantian data aktif belum diotomatisasi.

## Membuka hasil pemulihan pada Electron Windows

Pada rilis Electron yang dibangun dari kode ini, buka PowerShell baru dan isi
`$env:JO_WORKSPACE_DATA_DIR` dengan path absolut ke `jo-restored\recovered`.
Tutup seluruh proses Jo Workspace sebelumnya agar port desktop tersedia, lalu
jalankan executable Jo Workspace dari PowerShell tersebut. Electron membuat profil
terpisah pada direktori itu; runtime dan workspace lama tidak ditimpa. Buka
Settings → Kontrol data → Impor, lalu pilih `browser\state.json` dari direktori
yang sama. Kembali ke profil lama dengan menutup aplikasi dan membukanya tanpa
variabel tersebut. Installer yang sudah terpasang perlu dibangun ulang agar
mendukung pilihan profil ini.

## Menjadwalkan backup offline Windows

Simpan snapshot browser terbaru ke path tetap, tutup backend, lalu buat
konfigurasi dan daftarkan tugas untuk akun Windows yang sama:

```powershell
backend\venv\Scripts\python.exe scripts\workspace_backup.py schedule-config --config "C:\backup\schedule.json" --browser "C:\backup\jo-browser-recovery.json" --browser-store "C:\path\ke\profil\IndexedDB" --browser-store "C:\path\ke\profil\Local Storage" --runtime "data\runtime" --workspace "workspace" --destination "C:\backup\automatic" --retention 7
backend\venv\Scripts\python.exe scripts\workspace_backup.py schedule-register --config "C:\backup\schedule.json"
```

Perintah pertama meminta frasa sandi dan melindunginya dengan DPAPI akun Windows;
perintah kedua mendaftarkan tugas Task Scheduler per jam untuk pengguna yang
sedang login. Tidak ada tugas dibuat sebelum `schedule-register` dijalankan.
Tugas hanya mencoba backup ketika backend pada port standar berhenti dan lock
runtime tersedia. Snapshot browser harus berumur kurang dari 24 jam dan tidak
lebih lama daripada file runtime, workspace, atau direktori profil browser yang
diberikan; jika syarat tidak terpenuhi, backup dilewati. Berikan direktori
IndexedDB dan Local Storage dari profil yang benar (pada Electron biasanya di
`%APPDATA%\Agent OS`). Perbarui snapshot browser secara manual setelah ada
perubahan chat. Pemeriksaan waktu file konservatif, bukan transaksi lintas
browser dan backend; perubahan metadata browser dapat membuat backup dilewati.
Komputer harus aktif dan pengguna login. Status terakhir berada pada
`schedule.json.status.json`. Retensi hanya menghapus ZIP yang dibuat jadwal
yang sama. Path Python dan proyek harus tetap tersedia.
