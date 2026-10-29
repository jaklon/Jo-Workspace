# Security Workspace — Engagement dan RoE

**Versi saat ini: tahap 7.** Lihat [Agent spesialis dan benchmark sintetis](SECURITY_AGENTS.md). Lihat [Orkestrasi satu model](SECURITY_ORCHESTRATION.md). Lihat [MCP gateway dan runner fixture terisolasi](SECURITY_MCP.md). Lihat [Evidence, Findings, Reports](SECURITY_EVIDENCE.md). Lihat [Runs offline dan penghentian darurat](SECURITY_JOBS.md). Lihat [Scope dan Policy Guard](SECURITY_SCOPE_POLICY.md)
untuk aturan containment, pengecualian, dan evaluasi rencana.

Modul ini menyimpan rencana Engagement dan Rules of Engagement (RoE) di dalam
Project. Tidak ada eksekusi pentest, koneksi target, pemanggilan scanner, atau
delegasi bebas ke agen spesialis. Tab Agents menyediakan lima spesialis terbatas pada lab sintetis terdaftar, dengan izin/konteks/budget sendiri. Tahap 6 menambahkan Planner/Executor/Reviewer logis pada satu model lokal; review manusia tetap diperlukan. Tahap 5 hanya menambahkan panggilan MCP fixture dalam AppContainer. Endpoint lama `POST /api/pentest/run` selalu menolak dengan
HTTP 423, termasuk setelah RoE disetujui.

## Cara menggunakan

1. Buka Jo Workspace, pilih atau buat **Project**.
2. Klik **Security Workspace · Tahap 7** di sidebar dan pilih Project tersebut.
3. Buat Engagement. Nama wajib; draft boleh disimpan sebelum data lengkap.
4. Lengkapi tujuan, pemilik, PIC, lingkungan, referensi otorisasi, scope,
   pengecualian, tindakan rencana, jadwal, batas rencana, kontak darurat,
   kondisi penghentian, dan alias akun uji bila diperlukan.
5. Klik **Ajukan RoE**. Daftar persyaratan menunjukkan data yang belum lengkap.
6. Tinjau snapshot dan catat persetujuan lokal atau permintaan perbaikan.
   Keputusan peninjauan memerlukan nama deklarasi, catatan, dan pernyataan review.
7. Gunakan **Buat revisi baru** untuk mengubah RoE yang sudah diajukan. Versi
   lama dipertahankan, persetujuan lama dicabut, dan versi baru menjadi draft.

Status yang ditampilkan mencakup draft, menunggu persetujuan, disetujui secara
lokal, dicabut, kedaluwarsa, dan versi terdahulu. Persetujuan boleh dicatat
sebelum jadwal mulai; status itu tidak menyatakan bahwa jadwal sudah dimulai
atau bahwa eksekusi boleh dijalankan. Masa berlaku dicek server ketika meninjau
dan membaca data; UI memperbarui tampilan kedaluwarsa selama halaman terbuka.

## Validasi dan batas tahap ini

- Lingkungan: lab, development, staging, atau UAT. Production ditolak.
- Scope: IP, CIDR dengan alamat jaringan yang tepat, domain eksplisit, atau URL
  HTTP(S). Nilai dinormalisasi; wildcard, kredensial URL, query, fragment,
  duplikat, dan target identik di scope serta pengecualian ditolak.
- Port berupa daftar bilangan bulat 1–65535; wajib untuk rencana discovery TCP.
- Jadwal harus memiliki zona waktu, akhir setelah awal, dan belum berakhir
  saat diajukan. Form memakai zona IANA dan menyimpan timestamp UTC.
- Batas rencana: 1–15 HTTP RPS, concurrency 1–4, durasi 1–240 menit.
- Review API terautentikasi memerlukan alias akun uji. Jangan masukkan password,
  token, atau kredensial ke alias maupun kolom teks lainnya.
- Maksimal 100 Engagement per Project, 100 versi per Engagement, dan 100 target
  pada masing-masing daftar scope/pengecualian.

Validasi scope tahap 2 memeriksa containment IP/CIDR, batas host/path URL, dan
pengecualian. Policy guard memeriksa batas rencana terhadap RoE. DNS, kepemilikan
target, serta enforcement pada jaringan belum tersedia karena runner tool tetap
dinonaktifkan; worker tahap 3 hanya memvalidasi policy secara offline. Lihat panduan tahap 2 untuk semantik lengkap.

Persetujuan adalah **deklarasi lokal oleh operator sesi yang sama**. Nama
peninjau bukan identitas terverifikasi, belum ada RBAC atau pemisahan tugas,
dan referensi otorisasi bukan verifikasi dokumen izin. SHA-256 mengidentifikasi
isi snapshot; bukan tanda tangan digital atau audit tahan manipulasi.

## Penyimpanan dan pemulihan

Data disimpan pada `engagements.sqlite3` di `AGENT_DATA_DIR`. Default development
adalah `data/runtime/`; aplikasi Windows memakai `%APPDATA%\Jo Workspace\runtime\`.
Tabel: `engagements`, `roe_versions`, dan `engagement_events`. ID Project berupa
UUID dari penyimpanan Project lokal. Data Project/chat tetap berada di browser
atau profil Electron; layanan ini bukan sistem ACL multiuser.

Transaksi SQLite dan nomor revisi mencegah penimpaan draft maupun dua keputusan
bersamaan dari data lama (HTTP 409). Konten versi yang sudah diajukan tidak
dapat diedit melalui API; revisi menghasilkan snapshot baru. Riwayat keputusan,
timestamp, catatan, dan hash tetap tersedia setelah aplikasi dimulai ulang.

**Ekspor riwayat** menghasilkan JSON satu Engagement beserta ID/nama Project,
semua versi, dan peristiwa. Ekspor chat dari Settings belum mencakup database
ini; impor persetujuan belum tersedia. Untuk backup lengkap, tutup aplikasi
dan backend, lalu salin seluruh folder runtime bersama backup Project/chat.
Project yang mempunyai Engagement dilindungi dari Hapus Project dan Hapus
semua data melalui UI agar riwayat tidak menjadi yatim. Penghapusan Engagement
dan kebijakan retensi terjadwal belum tersedia pada tahap ini.

## Pengujian

```powershell
backend\venv\Scripts\python.exe -m unittest discover -s backend\tests -q
cd desktop-app
npm test
npm run lint
npm run build
```

Tes mencakup autentikasi, isolasi ID Project, validasi scope/jadwal/batas,
kelengkapan pengajuan, snapshot terkunci, persetujuan dan pencabutan, revisi,
kedaluwarsa, konflik penulisan bersamaan, pembukaan ulang SQLite, serta
penolakan eksekusi bahkan setelah persetujuan. Tes frontend memeriksa konversi
zona waktu/DST, port, status efektif, path API, dan pesan validasi.

Semua data QA memakai fixture sintetis. Tidak ada target pentest yang diakses
oleh pengujian fitur tahap 1.


Tahap 7: [panduan Agents, izin, budget dan benchmark lab sintetis](SECURITY_AGENTS.md). Pentest tetap terkunci.
