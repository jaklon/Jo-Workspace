# Security Workspace tahap 6 — orkestrasi satu model lokal

Jo Workspace Local 1.6.0 menyediakan peran logis **Planner, Executor, Reviewer**
secara bergantian memakai satu model Ollama yang dipilih. State machine backend
menentukan perpindahan tahap. Pentest tetap terkunci (423), MCP eksternal tetap
dinonaktifkan, dan semua job hanya menggunakan fixture tahap 5 dalam AppContainer.
Tidak ada langganan, cloud inference, atau download model otomatis.

## Akses dan alur

**Ikon Jo Workspace → Security Workspace · Tahap 6 → Project → Engagement → Orkestrasi**.

1. Lengkapi/setujui RoE yang aktif dan mengizinkan `configuration_review`.
   Siapkan profil fixture MCP yang disetujui pada **MCP Integrations**.
2. Buat orkestrasi: nama/objektif, target scope, satu model yang sudah terpasang,
   playbook, profil MCP, batas langkah/panggilan/token/waktu. Konfirmasi pada
   formulir mengantrekan Planner lokal; belum ada job/tool yang dijalankan.
3. **Planner** mengusulkan struktur fixture dan dasar rencana. Backend menolak
   fixture di luar playbook, tool tanpa izin, rencana berulang/melebihi batas,
   perubahan binding RoE/profil, atau keluaran yang tidak sesuai schema.
4. **Tinjau & setujui rencana** mencatat deklarasi/note manusia serta checkpoint.
   **Executor** hanya dapat meminta indeks tindakan persis dari rencana yang
   ditinjau. Backend membuat job **Awaiting Approval**, tanpa menyetujuinya.
5. Buka **Runs & approval job** untuk review job terpisah. Mekanisme RoE/policy,
   katalog MCP, AppContainer, Stop Run, Stop Engagement dan evidence tahap 3–5
   tetap berlaku. Target tidak dihubungi atau dikirim ke subprocess fixture.
6. Setelah seluruh job selesai dan evidence tersimpan, **Reviewer** memakai
   ringkasan hasil fixture terstruktur. Referensi evidence diperiksa backend;
   ID buatan/tidak lengkap ditolak. Narasi dan ketidakpastian tetap interpretasi
   AI yang belum diverifikasi. `needs_human_review=true`,
   `finding_status=candidate_only`; tidak ada finding/severity yang diubah AI.
7. Ekspor checkpoint JSON mencakup request/hash, binding, keluaran tiap peran,
   budget, job batch, dan riwayat snapshot. Evidence tetap dikelola pada tahap 4.

## State dan checkpoint

Alur normal:

`queued_planner → planning → awaiting_approval → queued_executor → executing
→ waiting_jobs → queued_reviewer → reviewing → completed`.

**Hentikan orkestrasi** menghentikan panggilan model dan membatalkan job aktif
yang ditautkan, sambil mempertahankan checkpoint/evidence. Stop Engagement juga
menghentikan seluruh orkestrasi aktif pada engagement tersebut. Kontrol stop
tidak bergantung pada revisi UI yang mungkin sudah tertinggal.

Kegagalan schema/model, anggaran, policy/RoE, profil, atau job menyebabkan
**paused**, tanpa retry/replanning otomatis. Restart atau kehilangan lease worker
memerlukan **Lanjutkan dari checkpoint** secara eksplisit. Nama reviewer adalah
deklarasi operator lokal, bukan identitas terverifikasi atau RBAC.

- Tanpa checkpoint Planner, resume mengantrekan Planner kembali.
- Dengan rencana tetapi job belum semuanya selesai, resume kembali ke review
  rencana. Executor dapat membuat batch baru; approval job tetap terpisah.
  Job lama yang dibatalkan tidak dihidupkan kembali. Riwayat batch lama dipertahankan.
- Jika semua job selesai, resume dapat melanjutkan Reviewer dengan evidence yang
  sudah ada. Anggaran kumulatif tidak direset.
- RoE/profil/playbook yang berubah memerlukan orkestrasi baru. Model/digest yang
  berubah tidak diganti diam-diam; inferensi dihentikan.

## Model, sumber, dan budget

Hanya `http://127.0.0.1:11434` atau `http://localhost:11434` didukung. Daftar model
dibaca dari `/api/tags`; nama dan digest dipin pada request dan dicek sebelum tiap
peran. Tidak ada model pull atau fallback cloud. Model yang dipilih perlu mendukung
chat dan structured JSON; model embedding/vision tertentu mungkin menolak schema.
Uji langsung menggunakan `qwen2.5:3b-instruct` yang sudah terpasang.

Inferensi memakai antrean GPU yang sama dengan chat Jo Workspace, sehingga tidak ada
tiga model/peran yang dijalankan serentak. Keluaran memakai `format` JSON Schema
dan validasi Pydantic, mengikuti
[structured outputs Ollama](https://docs.ollama.com/capabilities/structured-outputs).
Tool calls dari model tidak dieksekusi; permintaan indeks Executor divalidasi
terhadap rencana sebelum backend membuat job.

Playbook lokal disimpan dalam `backend/security_playbooks.py`, dengan ID, versi,
instruksi, daftar fixture, referensi sumber dan hash. Playbook header mencantumkan
[OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project)
sebagai referensi; runtime tidak mengunduh halaman atau menjalankan alat OWASP.
Materi playbook adalah panduan fixture, bukan bukti kerentanan target. Versi
snapshot dipin pada request; perubahan isi playbook membatalkan kelanjutan lama.

| Batas | Nilai |
| --- | --- |
| Orkestrasi per engagement | 30 |
| Panggilan model kumulatif | 3–6, default 6 |
| Langkah Planner | 1–3, default 2 |
| Budget token konservatif | 6.000–60.000, default 30.000 |
| Output per panggilan | 128–768; tetap dibatasi setting output global |
| Waktu aktif kumulatif | 30–900 detik, default 300; tidak melampaui durasi RoE |
| Checkpoint | Maksimal 100; keputusan baru ditolak mendekati batas |
| Worker orkestrasi | 1 global; lease 15 detik |

Sebelum model dipanggil, backend mereservasi batas byte UTF-8 input + schema +
overhead + maksimum output. Reservasi kumulatif ini konservatif, bukan jumlah
token aktual. Metrik token terukur dari Ollama dicatat terpisah dan masuk Usage
melalui runtime yang sama. Panggilan gagal/dibatalkan tetap menghabiskan reservasi;
resume tidak menambah budget. Input/schema yang melampaui konteks global ditolak
sebelum inferensi. Tidak ada pemotongan prompt atau perbaikan JSON berulang otomatis.

Budget waktu aktif mencakup antrean/inferensi model, bukan waktu menunggu review
manusia atau job fixture. Setiap panggilan juga dibatasi timeout model/antrean
global. Validitas jadwal RoE tetap diperiksa selama pekerjaan berlangsung.

## Penyimpanan dan batas kepercayaan

Migrasi SQLite aditif membuat `security_orchestrations`,
`orchestration_checkpoints`, `orchestration_jobs`, dan `orchestration_worker` pada
`engagements.sqlite3`. Request immutable, status/revisi, snapshot dan riwayat
memakai hash integritas serta transaksi. Catatan rusak ditolak dan dikarantina
oleh worker; job aktif terkait dibatalkan. Hash bukan tanda tangan digital atau
perlindungan melawan administrator yang memodifikasi database/hash sekaligus.

Objektif/nama dapat disensor sebelum penyimpanan; jangan masukkan kredensial/PII.
Model hanya menerima objektif, instruksi playbook, tindakan terkurasi, dan hasil
fixture terstruktur beserta ID/hash evidence. Arsip asli DPAPI atau isi file privat
tidak dimasukkan ke prompt. Keluaran AI ditampilkan sebagai teks, bukan HTML aktif.
Model dapat keliru menafsirkan fixture; analis tetap harus meninjau bukti asli dan
dasar penilaian. Tidak ada instruksi dari output model yang dapat membuka pentest.

## API

Seluruh endpoint memakai autentikasi/sesi Jo Workspace dan schema ketat.

| Metode | Path | Fungsi |
| --- | --- | --- |
| GET | `/api/security/orchestration/catalog` | Model lokal dan playbook/sumber/versi |
| GET / POST | `{engagement_prefix}/orchestrations` | Daftar atau buat tugas Planner |
| GET | `{engagement_prefix}/orchestrations/{id}` | Detail/hash/riwayat checkpoint |
| POST | `{engagement_prefix}/orchestrations/{id}/approve` | Review rencana, antrekan Executor |
| POST | `{engagement_prefix}/orchestrations/{id}/pause` | Stop dan pertahankan checkpoint |
| POST | `{engagement_prefix}/orchestrations/{id}/resume` | Lanjutkan dengan review dan budget tersisa |

`engagement_prefix` adalah
`/api/security/projects/{project_id}/engagements/{engagement_id}`.

## Verifikasi

Tes backend mencakup state machine, auth/project binding, schema, approval
terpisah, scope/RoE/profil, anggaran, pembatalan stream, model drift, restart,
integritas, referensi evidence, dan ketiadaan finding otomatis. Tes render UI
memeriksa escaping input AI yang menyerupai HTML/tautan/script serta label
human review. Uji langsung Ollama lokal menyelesaikan tiga peran dengan satu
fixture AppContainer dan evidence tersimpan. Bukti QA: `output/security-stage6/`.

Kontrol browser dinonaktifkan di pengaturan Work pada sesi implementasi ini;
verifikasi klik/visual interaktif belum dapat dijalankan. Build/typecheck/lint,
tes render komponen, dan alur API lokal digunakan sebagai verifikasi yang tersedia.
Tahap 7 multi-agent belum diaktifkan.

Verifikasi akhir: **164 tes backend** (18 tes orkestrasi dan regresi kompatibilitas peluncur), **65 assertion
frontend** (8 untuk render/batas kepercayaan Reviewer), lint, typecheck, dan
build lulus. Uji langsung `qwen2.5:3b-instruct` menyelesaikan 3 panggilan peran,
1 job fixture AppContainer dan 1 evidence, dengan reviewer tetap memerlukan
tinjauan manusia. Uji restart/resume mempertahankan checkpoint dan reservasi
budget tanpa replay otomatis. Desktop 1.6.0 dan pentest HTTP 423 diverifikasi.

```text
backend\venv\Scripts\python.exe -m unittest discover -s backend/tests -v
cd desktop-app
npm test
npm run lint
npm run build
```
