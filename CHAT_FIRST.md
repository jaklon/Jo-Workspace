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

## Grounding evidence (anti-halusinasi)

`backend/analysis_grounding.py` memeriksa setiap kalimat keluaran model sebelum disimpan:

- Setiap observasi wajib menyertakan `evidence_quote` yang benar-benar ada di evidence.
- Rujukan ke URL/host/IP/port/CVE/file/header `x-*` harus muncul secara literal di evidence.
- Konsep keamanan (cookie, CSP, HSTS, CORS, TLS, JWT, SQLi, XSS, CSRF, kredensial, …) memerlukan istilah
  pendukung di evidence, kecuali kalimatnya menyatakan hal itu *tidak teramati*.
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
