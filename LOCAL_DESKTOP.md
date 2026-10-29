# Jo Workspace Local — desktop gratis pada laptop ini

Versi alternatif ini memakai Python dan Chrome/Edge yang sudah terpasang, dengan jendela
browser dalam mode aplikasi. Tidak memerlukan sertifikat, layanan signing,
langganan cloud, atau perubahan proteksi Windows. Peluncur ini terpisah dari
paket EXE NSIS 1.10.0. Bila shortcut Desktop menunjuk ke paket Electron,
jalankan
`desktop-app/dist/Install-Jo-Workspace-Local.cmd` bila ingin mengganti shortcut
Desktop kembali ke mode lokal berbasis sumber.

## Pemakaian

- Setelah memasang mode lokal, klik **Jo Workspace** di Desktop atau Start Menu. Backend mulai otomatis jika
  belum berjalan, sesi terhubung otomatis, dan jendela aplikasi terbuka.
- Buka **Security Workspace · Tahap 7**, pilih/buat Project, lalu kelola
  Engagement, RoE, validasi scope, policy, dan antrean validasi offline.
  Lihat [panduan Evidence, Findings, Reports](SECURITY_EVIDENCE.md) dan
  [panduan Runs offline](SECURITY_JOBS.md), serta
  [MCP fixture terisolasi](SECURITY_MCP.md), dan
  [orkestrasi satu model](SECURITY_ORCHESTRATION.md).
- Settings, Usage, Chat, Code, Vision, dan Dokumen memakai UI yang sama.
- Menutup jendela tidak menghentikan backend bersama web lokal. Saat Windows
  dimulai ulang, cukup klik ikon lagi; tidak perlu menjalankan PowerShell.
- Ollama lokal dicoba dijalankan otomatis bila belum aktif. Model yang sudah
  terpasang tetap dipakai. Tidak ada layanan AI berbayar baru yang diaktifkan.

Peluncur mengecek bahwa backend adalah tahap 7 dan `execution_enabled=false`.
Semua eksekusi pentest tetap terkunci dengan HTTP 423, termasuk setelah RoE
disetujui atau evaluasi policy lolos.

## Uninstall dan data

Klik **Uninstall Jo Workspace**. Konfirmasi **Yes/No** muncul dengan pilihan default
**No**. Menutup dialog atau memilih No membatalkan uninstall. Yes menghapus
registrasi/shortcut peluncur lokal dan menghentikan backend miliknya jika idle.
Pekerjaan AI yang masih berjalan menghalangi uninstall.

Jika instalasi mengganti shortcut versi lama, uninstall lokal mengembalikan
backup shortcut tersebut. Versi Electron lama dipertahankan untuk pemulihan;
peluncur lokal tidak menjalankan uninstaller Electron lama.

Chat dan Project disimpan pada profil Chrome/Edge di origin
`http://127.0.0.1:8010`. Peluncur memilih Chrome terlebih dahulu agar data web
yang sudah ada tetap dapat dibuka pada profil yang sama. Data profil Electron
lama terpisah; pemindahan chat antarprofil dapat dilakukan lewat ekspor/impor UI.
Database Engagement/RoE/policy/job/evidence/findings/laporan berada di `data/runtime` pada folder project.
Uninstall lokal tidak menghapus data tersebut, profil browser, model Ollama,
folder project, maupun data Electron lama.

## Lokasi dan ketergantungan lokal

- Peluncur: `%LOCALAPPDATA%\Programs\Agent OS Local\launcher.pyw`.
- Konfigurasi: `install.json` pada folder peluncur (berisi path, bukan token).
- Log backend: `logs\backend.log` pada folder peluncur.
- Registrasi Windows: HKCU Uninstall `AgentOSLocal`, versi 1.7.1.
- Source dan runtime: folder project ini, `backend/venv`, dan hasil build
  `desktop-app/out/renderer` harus tetap tersedia. Jangan pindahkan/hapus folder
  project atau virtual environment tanpa memasang ulang peluncur.

Ini instalasi lokal untuk laptop yang sudah memiliki dependensi. Bukan installer
EXE mandiri untuk dibagikan ke komputer lain. Rilis EXE yang dipercaya publik
tetap memerlukan signing tepercaya.

## Instalasi ulang oleh pengembang

```text
backend\venv\Scripts\python.exe -m pip install -r backend\requirements-local-desktop.txt
cd desktop-app
npm run build
cd ..
backend\venv\Scripts\python.exe scripts\install_local_desktop.py
```

Instalasi per pengguna membuat shortcut Desktop/Start Menu dan registrasi
Installed apps. Tidak memerlukan administrator, scheduled task, layanan sistem,
startup registry, root certificate baru, pengecualian Defender, atau perubahan
Application Control.

## Batas keamanan sesi

Peluncur memverifikasi pemilik proses, executable, script, dan port backend
sebelum mengirim bearer token. Port milik proses lain tidak diambil alih.
Login browser memakai nonce acak sekali pakai yang berlaku 45 detik, bukan API
token pada URL. Nonce disimpan sebagai hash dalam memori server, dibatasi
maksimal delapan aktif, dan hanya diterima dari alamat/host loopback yang tepat.
Cookie sesi bersifat HttpOnly dan SameSite=Strict. Route desktop dinonaktifkan
pada server web biasa dan backend Electron lama.

## Pengujian

Tes backend meliputi handoff satu kali, expiry, replay, origin/host/IP, bearer
yang salah, penolakan backend asing, shutdown ketika idle, pembatalan uninstall,
dan pentest terkunci. Pengujian UI memeriksa buka dari Desktop saat backend
berhenti, login otomatis, akses tahap 7, serta konfirmasi uninstall.


Tahap 7: [panduan Agents, izin, budget dan benchmark lab sintetis](SECURITY_AGENTS.md). Pentest tetap terkunci.

Folder instalasi, key registry AgentOSLocal, ID backup dan identitas enkripsi lama dipertahankan untuk kompatibilitas data; nama yang tampil adalah Jo Workspace.
