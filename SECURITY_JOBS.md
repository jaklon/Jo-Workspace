# Security Workspace tahap 3 — antrean validasi offline

Tahap 3 menyediakan job persisten, review rencana, batas sumber daya, dan
penghentian darurat. Sesuai permintaan pengguna, **eksekusi pentest tetap
dinonaktifkan**. Worker hanya menghitung ulang policy tahap 2 secara offline.
Nama tindakan TCP/HTTP adalah isi rencana, bukan operasi jaringan.

## Menggunakan UI

1. Buka **Security Workspace · Tahap 3**, pilih Project dan Engagement.
2. Lengkapi dan setujui RoE pada **Scope, RoE & Policy**.
3. Pada **Runs · offline**, buat rencana bernama dengan 1–20 langkah. Pilih
   jenis target, tindakan, port, batas rencana, dan alias akun uji jika relevan.
4. Simpan: job mendapat UUID dan status **Awaiting Approval**. Rencana tidak
   dapat diedit; hash SHA-256 mengikat langkah dan snapshot RoE.
5. Tinjau rencana, isi nama deklarasi peninjau dan catatan, lalu centang
   pernyataan review. Server memeriksa RoE, jadwal, scope, pengecualian, dan
   anggaran sebelum menerima job ke **Queued**.
6. Worker memproses **Running** sampai **Completed**, **Failed**, atau
   **Cancelled**. Lihat progres, hasil per langkah, riwayat, dan **Ekspor job**.

**Completed berarti validasi policy selesai**, bukan pemindaian berhasil.
Semua hasil mencatat `tool_executed=false`; job tidak memberi izin eksekusi.
Tidak ada request ke target, resolusi DNS, scanner, subprocess, model, MCP,
atau delegasi agen. `POST /api/pentest/run` tetap HTTP 423.

## Penghentian dan pemulihan

- **Stop Run** membatalkan satu job yang menunggu review, mengantre, atau
  berjalan. Penghentian idempoten; worker tidak dapat menimpa status Cancelled.
- **Stop Engagement** membatalkan seluruh job aktif pada engagement dan
  menyimpan gerbang penghentian. Pembuatan serta approval baru ditolak (423).
- **Buka kembali engagement** memerlukan review eksplisit, revisi gerbang
  terkini, dan RoE terkini yang lengkap, disetujui, serta sedang aktif.
  Job yang dibatalkan tetap berhenti.
- Saat worker berhenti/restart, Running menjadi Failed (`INTERRUPTED`) dan
  Queued kembali Awaiting Approval. Hasil yang sudah tersimpan dipertahankan.
  Tidak ada pelanjutan atau retry otomatis.
- **Ulangi validasi offline** menyalin job Failed/Cancelled ke job baru dengan
  snapshot RoE terkini dan approval baru. Satu job hanya dapat disalin sekali;
  maksimal tiga percobaan dalam satu rantai. Job Completed tidak diulang.

## Batas dan konsistensi

- Concurrency worker global: **1**; FIFO menurut waktu pembuatan dan ID.
- Maksimal **100 job per engagement**, **20 langkah per job**.
- Batas waktu job **1–300 detik**, default 60; tidak boleh melampaui RoE.
- Batas hasil policy tersimpan **1–64 KiB**, default 64. Ketika batas tercapai,
  job gagal dan hasil sebelumnya dipertahankan. Metadata/riwayat terpisah.
- Anggaran setiap langkah memakai batas tahap 2 (RPS, concurrency, durasi,
  port, dan alias), diperiksa saat approval dan sebelum setiap langkah.
- Lease worker SQLite berlaku **10 detik**. Hanya pemilik lease aktif boleh
  mengambil atau memajukan job; worker pengganti memulihkan status tanpa replay.
- Transaksi dan revisi mencegah double approval, replay retry, persetujuan
  terhadap snapshot lama, serta race antara worker dan tombol penghentian.
- Pergantian/pencabutan RoE, jadwal kedaluwarsa, atau policy yang menolak
  menyebabkan job gagal sebelum langkah berikutnya diproses.

Nama peninjau adalah deklarasi operator lokal, bukan identitas terverifikasi
atau RBAC. Hash bukan tanda tangan digital atau audit tahan manipulasi.
Jangan masukkan kredensial ke nama, catatan, target, atau alias akun.

## Penyimpanan dan API

Migrasi aditif memakai database Engagement `engagements.sqlite3` yang sama.
Tabel baru: `security_jobs`, `security_job_results`, `security_job_events`,
`security_engagement_gates`, dan `security_job_worker`. Instalasi desktop lokal
gratis menggunakan `data/runtime` pada source project. Tidak ada layanan
berbayar atau dependensi runner eksternal baru.

Semua endpoint memakai autentikasi API yang sudah ada. Prefix:
`/api/security/projects/{project_id}/engagements/{engagement_id}`.

| Metode | Path setelah prefix | Fungsi |
| --- | --- | --- |
| GET / POST | `/jobs` | Daftar job/gerbang/worker/batas atau buat rencana |
| GET | `/jobs/{job_id}` | Detail rencana, hasil, dan riwayat |
| POST | `/jobs/{job_id}/approve` | Review dengan revisi dan acknowledgement |
| POST | `/jobs/{job_id}/stop` | Hentikan job |
| POST | `/jobs/{job_id}/retry` | Salinan untuk approval baru |
| POST | `/stop` | Hentikan engagement |
| POST | `/resume` | Buka gerbang secara eksplisit |

Tahap 4 evidence/findings/reporting, tahap 5 MCP, tahap 6 orkestrasi model,
dan tahap 7 multi-agent belum diaktifkan. Penghentian proses scanner nyata
belum relevan karena tahap ini tidak membuat proses tool sama sekali.

## Verifikasi

`backend/tests/test_security_jobs.py` mencakup API/auth/schema, approval,
snapshot lama, policy dan budget, FIFO/lease, penghentian/race, hasil parsial,
timeout, restart, batas retry, integritas hash, migrasi, serta shutdown worker.
Tes melarang pemanggilan socket, DNS, subprocess, dan scanner pada alur job.
Pengujian UI menggunakan data sintetis terpisah: dua langkah selesai,
ekspor tanpa eksekusi tool, Stop Run, retry menunggu approval, Stop Engagement,
dan pembukaan kembali tanpa menghidupkan job Cancelled.

Verifikasi 27 Oktober 2026: **101 tes backend** (18 tes job baru), **57 assertion
frontend**, lint, typecheck, dan build lulus. Pengujian browser juga memeriksa
persistensi setelah reload/restart serta akses dari ikon Jo Workspace Local 1.3.0.
Backend desktop melaporkan tahap 3 dan endpoint pentest mengembalikan 423.

```text
backend\venv\Scripts\python.exe -m unittest discover -s backend/tests -v
cd desktop-app
npm test
npm run lint
npm run build
```

Bukti QA sintetis lokal tersedia di `output/security-stage3/` (diabaikan Git).
