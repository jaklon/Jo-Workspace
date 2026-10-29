# Chat-First Unified Orchestrator (Jo Workspace v2.0)

Seluruh interaksi berjalan di **satu Chat**. Pemilihan tool, Auto-RoE, pembuatan job, dan pencatatan
audit berlangsung di belakang layar, dengan **satu kartu konfirmasi** di Chat sebagai gerbangnya.
Security Workspace hanya berfungsi sebagai dashboard riwayat, evidence, dan laporan.

## Alur

1. **Routing intent** (`backend/chat_orchestrator.py` → `classify`): `chat`, `web`, `coding`, `security`.
   Router hanya mengklasifikasi dan tidak pernah menjalankan tool.
2. **Slot-filling** (`security_slots` + `auto_governance.prepare_plan`): jika target, port, lingkungan
   (`lab`/`development`/`staging`/`uat`/`production_readonly`), mode VA (BlackBox/WhiteBox/GreyBox),
   alias akun uji, atau dokumen belum ada, model bertanya balik di Chat. Nilai hanya diisi bila disebut
   eksplisit oleh pengguna; URL tidak pernah diperluas menjadi domain.
3. **Kartu konfirmasi** (`action_proposal` → `MessageDetails.tsx`): menampilkan target, port, lingkungan,
   tool/agen, batas waktu, dan pengungkapan (misalnya domain dikirim ke crt.sh). Tombolnya
   **Setuju & Jalankan** / **Batalkan**. Rencana terikat pada sesi dan hanya dapat dipakai sekali.
4. **Auto-RoE dalam satu transaksi SQLite** (`auto_governance.create_approved_jobs`): Engagement → submit →
   approve RoE → buka Gate → buat dan approve seluruh job. Jika ada langkah yang gagal, semuanya dibatalkan.
   Referensi otorisasi berupa `CHAT-APPROVED-<sesi>`; persetujuan lokal tidak memverifikasi izin pihak ketiga.
5. **Eksekusi dan progres**: runner yang sudah ada menjalankan job, dan statusnya di-stream ke Chat lewat SSE.
   Tombol **Stop** di Chat membatalkan semua job dalam rencana tersebut.
6. **Deep Analysis & spesialis**: evidence disensor, lalu dianalisis oleh model Security. Spesialis
   (`recon`, `web_api`, `auth_bola`, `llm_security`, `reporting`) hanya meninjau evidence yang tersimpan
   dan tidak membuka koneksi baru.
7. **Hasil di Chat** disertai ID Evidence, SHA-256, dan tombol **Lihat Detail di Security Workspace**.

## Paket VA URL dasar

Permintaan umum seperti `Jalankan vulnerabilities assessment pada https://example.test/` tidak harus
menyebut nama adapter. Permintaan umum tanpa URL, misalnya “cek celah keamanan website staging saya”,
juga dikenali; Chat menanyakan URL lengkap beserta lingkungan dan mode yang belum disebut dalam satu
pertanyaan, dan URL tidak pernah ditebak dari nama host atau kata lain. Chat menanyakan lingkungan dan mode yang belum disebut. Untuk BlackBox pada
lab, development, staging, atau UAT dengan HTTPS port 443, rencana menggabungkan `http-head` dan
`inventory-html` pada URL yang diberikan. Pada production read-only atau URL HTTP hanya `http-head`
yang direncanakan; port URL publik dibatasi pada 80 atau 443. Kartu konfirmasi
menjelaskan bahwa inventaris menggunakan satu GET tanpa login atau menjalankan JavaScript; kandidat
tautan tidak diakses. Paket ini bukan asesmen kerentanan menyeluruh dan tidak memperluas scope menjadi
scan port, subdomain, atau eksploitasi. WhiteBox dan GreyBox meminta evidence atau sesi uji yang relevan.
Pengguna tetap dapat memilih tool lain secara eksplisit. Tidak ada pemeriksaan yang berjalan sebelum
persetujuan kartu di Chat.

## Ingatan dalam sesi

Riwayat disimpan lokal per sesi dan sampai 100 pesan terakhir dikirim sebagai konteks. Saat riwayat
melebihi batas konteks model, sistem memilih pesan terbaru dan potongan pesan lama yang relevan;
potongan diberi penanda dan tidak diringkas menjadi fakta baru. Model tetap dapat melewatkan detail
dalam percakapan panjang, sehingga perlu menanyakan ulang bila konteks yang diperlukan tidak tersedia.
Rujukan eksplisit seperti “ulangi VA pada target yang sama” menggunakan target yang disebut dalam
riwayat sesi tersebut dan tetap menghasilkan kartu persetujuan baru sebelum pemeriksaan.

**Fakta sesi** (`backend/session_context.py` → `session_facts`): sebelum riwayat dipangkas, seluruh riwayat
sesi dibaca untuk menyusun blok ringkas `FAKTA SESI` di prompt sistem (chat, web, dan Coding Agent):
target URL/IP yang disebut pengguna, lingkungan dan mode terakhir yang dinyatakan pengguna, serta baris
fakta evidence dan ID Job/Evidence/SHA-256 dari dua laporan pemeriksaan terakhir. Isinya hanya disalin
dari teks pengguna dan baris laporan deterministik (bukan diringkas model), dibatasi ±1.800 karakter.
Dengan begitu angka dan target tetap tersedia walaupun pesan lama tidak muat di konteks model kecil.
Router dan ekstraksi parameter keamanan tidak memakai blok ini, sehingga target lama tidak pernah
dipakai tanpa rujukan eksplisit.

## Laporan dasar dari evidence

`backend/evidence_report.py` menyusun bagian laporan yang wajib ada langsung dari evidence terstruktur,
tanpa model: status HTTP, header keamanan yang ada/tidak ada, HTTPS/TLS dan masa berlaku sertifikat,
flag cookie, Cache-Control, CORS, redirect, serta port TCP terbuka/lainnya. Rekomendasi untuk header atau
flag yang tidak ada berasal dari basis pengetahuan statis (rujukan OWASP). Model hanya menambah narasi
(`Catatan model: …`) yang tetap melewati grounding; kalimat model yang mengulang atau menyangkal fakta
header/port/cookie dibuang karena fakta sudah dinyatakan dari evidence. Laporan tetap lengkap walaupun
model kecil gagal atau keluarannya kosong. Evidence impor operator tidak ditafsirkan.

## Grounding evidence (anti-halusinasi)

`backend/analysis_grounding.py` memeriksa setiap kalimat keluaran model sebelum disimpan:

- Setiap observasi wajib menyertakan `evidence_quote` yang benar-benar ada di evidence.
- Rujukan ke URL/host/IP/port/CVE/file/header `x-*` harus muncul secara literal di evidence.
- Konsep keamanan (cookie, CSP, HSTS, CORS, TLS, JWT, SQLi, XSS, CSRF, kredensial, …) memerlukan istilah
  pendukung di evidence, kecuali kalimatnya menyatakan hal itu *tidak teramati*.
- Jumlah dan klasifikasi origin kandidat (`inventory-html`, `js-bundle-inventory`) dihitung secara deterministik
  dari evidence, bukan dari teks model: origin unik dibandingkan dengan origin target; *eksternal* berarti host
  berbeda, sedangkan host yang sama dengan skema/port berbeda dihitung terpisah. Bila daftar mencapai batas adapter
  (40/30 entri), laporan menyebut bahwa jumlah sebenarnya bisa lebih besar. Klaim model tentang jumlah atau
  klasifikasi origin dihapus, termasuk dari analisis tool lain (mis. `http-head`) yang tidak mencatat kandidat.
- Kalimat yang dihapus dihitung dan dicantumkan di bagian **Keterbatasan**. Status hasil tetap `needs_human_review`.

## Konfirmasi wajib

Semua endpoint eksekusi di luar Chat mengembalikan `423` (`security.legacy_execution_blocked`):
endpoint agen/dokumen/vision/pencarian, approve/retry job, deep-analysis, orkestrasi, approve agen,
pemeriksaan MCP, dan `/api/pentest/run`. Endpoint baca, evidence, dan Stop tetap terbuka.

## Model per tugas

- **Settings → Model & inferensi**: model per peran `reasoning`, `coding`, `security`, `vision`.
- **Dropdown Model di Chat**: `Otomatis (sesuai tugas)` (chat → reasoning, kode → coding,
  keamanan → security), atau kunci satu model terpasang untuk sesi tersebut.
- WhiteRabbitNeo V3 7B: salin `WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf` ke
  `backend\models\security\`, lalu jalankan:

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\install-whiterabbitneo.ps1
  ```

  Model terdaftar sebagai `whiterabbitneo-v3-7b` (num_ctx 4096) tanpa mengubah model yang sudah ada.
  Periksa `ollama ps`: `100% GPU` berarti seluruh layer muat di VRAM.

## Batasan yang diketahui

- Lingkungan tidak disimpulkan dari URL/IP saja; pengguna harus menyebutkannya agar RoE tidak terisi asumsi.
- GreyBox dua sesi: dua JWT hanya dimasukkan di kolom kartu, disimpan sementara di memori, dan hanya diterima melalui HTTPS atau loopback.
- Grounding memakai pencocokan istilah, sehingga hasil analisis tetap memerlukan review manusia.
