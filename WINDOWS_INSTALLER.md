# Jo Workspace untuk Windows

**Pilihan gratis:** installer Electron mandiri atau [peluncur lokal berbasis sumber](LOCAL_DESKTOP.md).
Keduanya menyediakan startup backend dan login otomatis. Installer tidak memerlukan
Python atau Node.js pada komputer tujuan. Chrome atau Edge yang sudah terpasang
diperlukan bila Chat membaca halaman yang memuat isi dengan JavaScript.

## Instalasi dan pemakaian

Installer: `desktop-app/dist/Jo-Workspace-1.14.0-Windows-x64-Setup.exe`.
Ditujukan untuk Windows 10/11 x64, dengan pemasangan per pengguna.

1. Buka installer dan ikuti wizard.
2. Setelah selesai, buka **Jo Workspace** dari Desktop atau Start Menu.
3. Backend dan sesi autentikasi disiapkan otomatis. Tidak perlu PowerShell,
   Python, Node.js, atau npm pada komputer pengguna.

Ollama dan model AI tidak disertakan karena ukurannya besar. Aplikasi menggunakan
instalasi/model Ollama yang sudah tersedia. Jika layanan belum aktif, aplikasi
mencoba menjalankan `ollama serve` dari lokasi instalasi Windows standar tanpa
membuka terminal. Jika belum terpasang, instal Ollama dari https://ollama.com
dan siapkan model melalui alur Ollama. Model yang dipakai dapat diganti di
**Settings → Model & inferensi**.

Installer ini belum ditandatangani dengan sertifikat code signing.

## Lokasi dan lifecycle

- Instalasi default: `%LOCALAPPDATA%\Programs\Jo Workspace`.
- Data aplikasi, riwayat, dan preferensi: `%APPDATA%\Agent OS`.
- Data backend dan token lokal: `%APPDATA%\Agent OS\runtime`.
- Folder kerja agent: `%APPDATA%\Agent OS\workspace`.
- Log startup backend: `%APPDATA%\Agent OS\logs\backend.log`.
- Backend desktop: loopback `127.0.0.1:18010`, terpisah dari web proyek di port 8010.
- Menutup aplikasi menghentikan backend miliknya. Ollama merupakan layanan bersama
  dan tidak dihentikan ketika jendela Jo Workspace ditutup.
- Peluncuran kedua memfokuskan jendela yang sudah ada.
- Aplikasi tidak menambahkan startup otomatis saat login Windows.
- Uninstall tersedia melalui pengaturan Installed apps Windows. Data pengguna
  dipertahankan saat uninstall.

Riwayat browser web sebelumnya tidak otomatis dipindahkan ke desktop. Gunakan
**Settings → Kontrol data → Ekspor/Impor** jika ingin membawa percakapan lama.
Port 18010 harus tersedia; jika sudah digunakan aplikasi lain, startup menampilkan
pesan kesalahan dan tidak mengambil alih layanan tersebut.

## Membuat ulang installer

Prasyarat mesin build: Python 3.11 x64, Node.js/npm, dependensi frontend, dan
virtual environment backend di `backend/venv`.

```powershell
backend\venv\Scripts\python.exe -m pip install -r backend\requirements-build.txt
cd desktop-app
npm ci
npm run build:win
```

Build memakai PyInstaller untuk membuat backend mandiri, electron-builder untuk
paket aplikasi, lalu NSIS untuk membuat installer dan uninstaller. Runtime Electron diambil dari instalasi paket
lokal. Bundel hanya berisi hasil build, dependensi aplikasi, backend beku, dan
aset web; `.env`, token proyek, model Ollama, workspace pribadi, dan runtime
proyek tidak dimasukkan.

## Pemeriksaan

```powershell
backend\venv\Scripts\python.exe scripts\smoke-windows-backend.py desktop-app\build\backend\agent-backend\agent-backend.exe desktop-app\out\renderer
backend\venv\Scripts\python.exe -m unittest discover -s backend\tests -q
cd desktop-app
npm run typecheck
npm run lint
npm test
```

Smoke test backend terbungkus memeriksa aset web, autentikasi, konfigurasi,
persistensi Settings, Usage, Engagement, zona waktu, validasi RoE, dan penolakan
pentest. Setelah pengguna mematikan Smart App Control, backend terbungkus dan
pemasangan EXE lulus. Uninstall interaktif belum dijalankan agar pemasangan tetap tersedia.
Pemasangan shortcut lokal dari CMD berhasil diuji pada versi 1.9.0.

## Uninstall dari Desktop

Pada pemasangan lokal, shortcut **Uninstall Jo Workspace** meminta konfirmasi
sebelum menghapus peluncur. Pada paket Electron, shortcut membuka Settings →
Installed apps; pilih **Jo Workspace**, lalu **Uninstall** dan konfirmasikan.
Data pengguna tetap dipertahankan.

Installer Electron versi 1.10.0 membuat shortcut ini saat pemasangan dan menghapusnya
saat uninstall. Uninstaller menampilkan konfirmasi eksplisit saat dibuka secara
interaktif. Mode silent `/S` dipakai hanya untuk pengujian otomatis.

Konfigurasi tetap mempertahankan AppData (chat, Project, Settings, dan database
Engagement/policy); penghapusan data aplikasi bukan bagian shortcut.

## Rilis 1.13.0

Tools & monitoring menambahkan profil Nuclei satu HEAD, ZAP passive headers
dalam container tanpa jaringan, Subfinder crt.sh, Amass build khusus crt.sh-only,
dan snapshot kesehatan Prometheus/Grafana lokal. Persetujuan per run, scope,
RoE aktif serta identitas binary/image wajib. Batas tiap profil dan dependensi
terpisah dijelaskan di [TOOL_INTEGRATIONS.md](TOOL_INTEGRATIONS.md).
Docker images dan executable Nuclei tidak dibundel dalam installer; pada laptop
ini dependensi profil telah disiapkan. Monitoring memakai stack Docker terpisah.
Di laptop ini stack Prometheus/Grafana sudah dijalankan. Paket distribusi memuat
Start-Jo-Monitoring.cmd untuk setup ulang melalui folder proyek sumber.

## Rilis 1.12.0 (arsip)

Tab TCP Scan menyediakan eksekusi koneksi TCP terhadap satu IP dan 1–16 port
yang disetujui. Nmap dapat digunakan jika sudah terpasang dengan hash executable
yang terikat rencana. Endpoint pentest menerima referensi job dan persetujuan
yang diverifikasi oleh policy. Target bebas dan exploit umum tetap ditolak.
Hasil disimpan sebagai evidence server dan tersedia untuk Deep Analisis.
Lihat [panduan scan](SECURITY_TCP_SCAN.md).

Nuclei, ZAP, Amass, Subfinder dan konektor monitoring masih berupa impor manual.
Paket ini belum menyelesaikan integrasi seluruh tools. Nmap tidak dibundel.

## Rilis 1.11.0 (arsip)

Deep Analisis tersedia dalam kategori VA WhiteBox, BlackBox dan GreyBox.
Model Ollama lokal meninjau evidence job yang disetujui, dengan pemeriksaan
scope/RoE, integritas dan persetujuan analisis. GreyBox memerlukan alias akun
uji dalam RoE. Laporan JSON dapat diunduh dan dibaca melalui chat Project.
Impor evidence tool merupakan deklarasi operator. Eksekusi Nmap, Nuclei, ZAP,
Amass, Subfinder dan konektor monitoring belum tersedia dari Jo Workspace;
status ini ditampilkan di panel tools. Lihat [panduan VA](DEEP_ANALYSIS.md).

## Rilis 1.10.0 (arsip)

Chat sekarang dapat merender satu URL HTTPS publik yang ditulis eksplisit ketika
HTML awalnya hanya kerangka JavaScript. Playwright menggunakan Chrome atau Edge
yang sudah terpasang, membuka konteks sementara, dan membatasi request GET ke
host yang sama. Redirect, download, request ke host lain, dan challenge Cloudflare
tidak dilewati. UI menandai sumber yang benar-benar dirender JavaScript secara
terpisah dari metadata. Halaman HemoForge pengguna telah diuji dan menghasilkan
teks UI yang dirender. Lihat [alur Search](SEARCH_CHAT.md) dan
[diagram arsitektur](ARCHITECTURE.md).

Build dan smoke test backend terbungkus 1.10.0 lulus. Hasil pengujian installer
tercatat di `desktop-app/dist/RELEASE-TESTS.txt`.

## Rilis 1.9.0 (arsip)

Chat kini memiliki Web Otomatis/Selalu/Mati. SearXNG lokal mengembalikan sumber
dan kandidat gambar, sedangkan Scrapling mengurai HTML yang bisa dibaca.
Jawaban menampilkan sitasi dan galeri. Sumber dibedakan sebagai isi halaman,
metadata halaman, atau cuplikan pencarian. URL HemoForge pengguna diuji:
HTTPS 200; HTML awal berisi metadata karena aplikasi memuat isi dengan JavaScript.
Jo Workspace menandainya sebagai metadata, tanpa mengklaim telah membaca isi UI.
Challenge dan penolakan akses tidak dilewati; tidak ada browser stealth.

Pada laptop ini pengguna telah mematikan Smart App Control, yang memang tidak
menyediakan pengecualian per aplikasi. EXE installer dan backend terbungkus
belum ditandatangani. Installer EXE sekarang berhasil dipasang, shortcut Desktop
menunjuk ke Electron versi 1.9.0, dan backend port 18010 berjalan. Autentikasi,
Search, Security tahap 7, dan pentest terkunci sudah diverifikasi.
209 tes backend dan 81 pemeriksaan frontend lulus. Lihat
`desktop-app/dist/RELEASE-TESTS.txt` untuk checksum dan batas tes.

## Rilis 1.8.0 (arsip)

Folder `desktop-app/dist` memuat dua pilihan:

- `Install-Jo-Workspace-Local.cmd`: klik dua kali untuk memasang peluncur gratis pada laptop ini, memakai Python/Chrome/Edge yang sudah ada. Folder proyek harus tetap tersedia di lokasi sekarang. Tidak perlu membuka PowerShell.
- `Jo-Workspace-1.8.0-Windows-x64-Setup.exe`: installer Electron mandiri. EXE belum ditandatangani sertifikat tepercaya, sehingga kebijakan Windows masih dapat memblokirnya. Jangan menonaktifkan proteksi Windows untuk memasang.

Branding, logo/ikon, tema terang/gelap, dan Security Workspace tahap 1-7 tersedia. Eksekusi pentest nyata tetap terkunci (HTTP 423). Runtime Python khusus fixture dan sumber fixture disertakan agar MCP AppContainer bekerja tanpa Python eksternal. Runner tetap dibatasi untuk fixture/lab sintetis.

Penyimpanan Electron tetap memakai `%APPDATA%\Agent OS` agar data lama kompatibel. Mode lokal memakai `data/runtime` di folder proyek; kedua mode mempunyai penyimpanan terpisah. Versi installer lama diarsipkan ke `desktop-app/dist/old-versions`.

Pengujian rilis: 201 tes backend, 81 pemeriksaan frontend, lint dan typecheck/build. Smoke test backend terbungkus telah lulus pada build sebelumnya, termasuk autentikasi, persistensi, scope/policy, handshake fixture terisolasi, katalog lima spesialis, endpoint pencarian, dan pentest terkunci. Build backend final belum dapat dijalankan ulang di laptop ini karena Windows Application Control memblokir executable baru yang belum ditandatangani. Tidak ada proteksi sistem yang diubah. Lihat `desktop-app/dist/RELEASE-TESTS.txt` untuk batas pengujian installer dan checksum.

## URL dan Search rilis 1.8.0

Tab **Pemeriksaan URL** berada di Security Workspace setiap Engagement. URL publik yang masuk scope RoE dan tindakan `http_headers` dapat dibuat sebagai job, ditinjau, lalu disetujui sebelum satu request HEAD. Adapter memverifikasi seluruh jawaban DNS publik, mengikat koneksi ke IP yang lolos, memvalidasi sertifikat HTTPS, membatasi header/waktu/output, menolak redirect dan menyimpan evidence serta laporan JSON. Target internal, metadata, dan eksekusi pentest tetap terkunci. Lingkungan `production_readonly` hanya menerima aksi dan batas read-only.

Menu **Cari web & gambar** memakai JSON API SearXNG lokal dan parser Scrapling untuk halaman yang dipilih. Browser stealth dan crawl tidak dipakai. Gambar diproksi backend setelah validasi DNS publik/HTTPS, tanpa redirect, tipe MIME terbatas, maksimal 2 MB. Aktifkan Docker Desktop lalu klik `desktop-app/dist/Start-Jo-Search.cmd` untuk memulai layanan SearXNG gratis. Lihat `deploy/searxng/README.md`. SearXNG adalah komponen terpisah dan memerlukan internet untuk pencarian serta unduhan image Docker pertama kali.
