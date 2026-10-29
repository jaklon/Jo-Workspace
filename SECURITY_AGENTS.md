# Security Workspace tahap 7 — agent spesialis lokal

Versi desktop 1.7.1. Tahap ini menambahkan **Recon, Web/API, Auth/BOLA,
LLM Security dan Reporting**. Semua memakai satu model Ollama lokal yang dipilih,
secara bergantian. Tidak ada model diunduh, layanan berbayar, scanner, DNS,
request ke target, shell, MCP eksternal atau delegasi model yang bebas.
`POST /api/pentest/run` tetap HTTP **423**.

## Menggunakan UI

1. Buka Jo Workspace dari Desktop → Security Workspace → Project → Engagement → **Agents**.
2. Gunakan Engagement **Lab sintetis** dengan RoE terkini disetujui, jadwal aktif,
   scope IP privat, port eksplisit dan tindakan sesuai agent yang dipilih.
   Contoh target label `10.30.0.25`, port `443`. Label ini tidak dihubungi.
3. Daftarkan bundled lab. Untuk Auth/BOLA pilih **dua alias berbeda** yang
   sudah ada di `test_account_refs` RoE. Tidak ada password, token atau login nyata.
4. Buat tim: pilih model terpasang, lab, subset spesialis, serta anggaran tim
   dan masing-masing agent. Izin tetap sesuai profil; tidak dapat diperluas
   lewat prompt/API. Reporting memerlukan spesialis observasi.
5. Tinjau dan setujui rencana tim: target IP/URL, tindakan, port dan anggaran
   tersimpan. Setiap agent kemudian meminta **job terpisah** di Runs. Tinjau
   dan setujui job tersebut secara manual; tidak ada approval otomatis.
6. Setelah policy job selesai, backend mengevaluasi kontrol lab murni di memori,
   menyimpan evidence, lalu meminta interpretasi JSON dari model lokal.
   Reporting hanya menerima klasifikasi terstruktur dan referensi evidence
   agent yang selesai, tanpa narasi instruksi peer, chat, workspace atau arsip asli.
7. Lihat indikator mentah, interpretasi, metrik dan checkpoint; ekspor JSON.
   Evidence juga muncul pada tab Evidence dan dapat ditautkan oleh analis
   ke Finding/Report tahap 4. AI tidak membuat atau memvalidasi finding.

Untuk IP, Web/API dan Auth memakai label URL HTTPS pada port RoE pertama
(HTTP jika port 80). Recon dari URL memakai host eksplisit. Setiap bentuk target
melewati policy yang sama; pemetaan tidak memperluas scope URL-only menjadi IP.
Nama domain untuk rencana jaringan tetap ditolak tanpa DNS pinning terpercaya.

## Izin dan konteks

| Agent | Izin tetap | Izin RoE | Konteks observasi |
|---|---|---|---|
| Recon | `lab.recon` | `tcp_discovery` | Dua inventori sintetis public-admin/private |
| Web/API | `lab.web` | `http_headers` | Dua fixture header hilang/ada |
| Auth/BOLA | `lab.auth` | `authenticated_api_review` | Objek milik dua akun, sesi dictionary terpisah; own/cross/reverse status 200/403 |
| LLM Security | `lab.llm` | `configuration_review` | Toy target terdaftar, input injection inert, indikator pengungkapan canary positif/negatif |
| Reporting | `report.compose` | `document_review` | Klasifikasi dan ID/hash evidence dari agent selesai; tidak menjalankan lab |

LLM Security adalah benchmark **toy target deterministik**, bukan pengujian
kerentanan model eksternal. Auth juga simulasi otorisasi dalam memori, bukan
integrasi sesi HTTP. Keduanya sengaja dibatasi selama pentest dikunci.

Profil dan lab mempunyai versi serta SHA-256. Model dipasang dan dipin dengan
nama/digest; perubahan digest menunda run tanpa fallback. Lab didaftarkan per
Engagement, terikat scope dan hash RoE. Penonaktifan lab menunda seluruh tim
terkait dan membatalkan job aktif. Registrasi/disable mempunyai catatan audit.

## Batas resource

| Batas | Tiap agent | Seluruh tim |
|---|---|---|
| Panggilan model | 1–3; default 1 | Maksimal 15; default 5 |
| Reservasi token | 4.000–24.000; default 12.000 | Maksimal 120.000; default 60.000 |
| Konteks | 3.000–12.000; default 6.000 | Diperketat oleh Settings context window global |
| Output per panggilan | 128–768; default 512 | Diperketat oleh Settings output global |
| Waktu aktif | 30–180 detik; default 120 | Maksimal 900 detik dan durasi RoE; default 600 |
| Paralelisme | Satu agent | Satu inferensi lewat antrean ModelRuntime bersama fitur lain |

Jumlah alokasi agent tidak boleh melebihi anggaran tim. Reservasi konservatif
mencakup byte UTF-8 prompt + schema + output + overhead; dicatat **sebelum**
inferensi, termasuk percobaan gagal/dibatalkan. Token input/output aktual
tersedia untuk panggilan yang selesai divalidasi dan UsageLedger global.
Kegagalan parsing tetap menghabiskan reservasi; tidak ada retry otomatis.
Waktu aktif meliputi antrean/inferensi, bukan waktu menunggu manusia atau job.
Settings global dan RoE hanya memperketat batas tersebut.

Tidak ada akun cloud atau API berbayar. Penggunaan CPU/GPU/listrik laptop tetap
ada. Model dipilih operator dari instalasi Ollama yang sudah tersedia.

## Checkpoint, stop dan restart

`awaiting_approval → running → completed`, atau `paused`.
Setiap agent: `pending → waiting_job → running → completed`.
Koordinator backend menentukan giliran; model tidak mengatur transisi atau
memanggil tool. Reporting dijalankan terakhir.

**Stop semua agent**, **Stop Engagement**, disable lab, RoE berubah, batas habis
atau keluaran tidak valid menghentikan kemajuan. Inferensi dibatalkan dan job
aktif dibatalkan; evidence yang sudah tersimpan tetap ada. Resume memerlukan
review eksplisit, tidak mereset anggaran, dan tidak mengulang agent selesai.
Job yang dibatalkan dibuat ulang dengan approval baru. Restart memulihkan
run yang sedang berjalan menjadi paused; tidak ada replay otomatis.

SQLite menambah tabel lab, audit lab, tim, checkpoint penuh dengan hash,
relasi job dan lease worker. Rencana/request immutable dipisahkan oleh hash.
Maksimal 20 lab, 20 tim per Engagement, 5 agent per tim, 150 checkpoint; operasi
approval/resume ditolak mendekati batas checkpoint. Data lama dipertahankan.
Hash mendeteksi perubahan tidak konsisten; bukan audit tahan penyerang yang
memiliki akses tulis penuh database. Identitas reviewer tetap deklarasi lokal.

## Metrik kualitas

Delapan kontrol tetap (empat positif/empat negatif) memungkinkan perbandingan
satu spesialis (2/8) dengan empat spesialis (8/8). Backend menghitung cakupan,
TP/FP/TN/FN, inconclusive, akurasi, kelengkapan evidence, token dan waktu.
Kasus, jumlah dan referensi evidence harus cocok tepat dengan izin agent.
Evidence buatan, kasus peer atau status finding selain candidate_only ditolak.

Keterulangan membandingkan klasifikasi, mengabaikan urutan keluaran kasus,
hanya pada run selesai dengan model/digest, lab, target/alias, tujuan, RoE,
profil dan anggaran yang sama. Tanpa run pembanding, UI menyatakan belum terukur.
Ini evaluasi fixture sintetis; tidak membuktikan peningkatan hasil atau
false-positive rate pada target riil. Narasi AI tetap perlu tinjauan analis.

## API

Semua endpoint memerlukan sesi/bearer yang sama seperti Security Workspace.
UUID Project/Engagement diperiksa; input ekstra dan resource di luar batas ditolak.

- `GET /api/security/agents/catalog`
- `GET/POST /api/security/projects/{project}/engagements/{engagement}/agents`
- `GET .../agents/{team}`
- `POST .../agents/{team}/{approve|pause|resume}`
- `POST .../agent-labs`
- `POST .../agent-labs/{lab}/disable`

Model tidak memperoleh bearer token aplikasi. Inferensi hanya ke Ollama
loopback dengan proxy environment nonaktif, tanpa redirects/fallback.
Evidence disensor sebelum disimpan/ditampilkan. Custom redaction terms
tidak disimpan. Arsip asli mengikuti DPAPI tahap 4; tidak dikirim ke model.

## Pengujian

- `backend/venv/Scripts/python.exe -m unittest discover -s backend/tests -v`
- `cd desktop-app` lalu `npm test`, `npm run lint`, `npm run build`.
- `backend/tests/test_security_agents.py`: izin, scope, anggaran, model/schema,
  konteks terpisah, canary/isolasi sesi, evidence, stop/restart, FP dan keterulangan.
- `scripts/test-agents-ui.mjs`: render state, anggaran/target dan escaping output.
- Hasil QA integrasi lokal disimpan dalam `output/security-stage7/` (diabaikan Git).
