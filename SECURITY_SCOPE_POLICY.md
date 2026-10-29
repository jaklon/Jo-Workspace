# Security Workspace — Tahap 2: Scope dan Policy Guard

Versi 1.2.0 menambahkan validasi scope dan evaluasi policy offline pada
Engagement/RoE. Tidak ada DNS lookup, request ke target, scanner, MCP, atau
multi-agent. `POST /api/pentest/run` tetap menolak dengan HTTP 423.

## Alur UI

1. Pilih Project → Security Workspace → Engagement.
2. Saat mengedit draft, klik **Validasi scope draft**. Koreksi temuan berlabel
   Blokir. Temuan Catatan menjelaskan overlap atau keterbatasan DNS.
3. Simpan draft. Pengajuan dan persetujuan selalu memvalidasi lagi di server.
4. Isi target, tindakan, port, batas rencana, dan alias akun uji di **Policy
   guard**. Klik **Evaluasi policy tanpa eksekusi**.
5. Hasil menunjukkan alasan penolakan terlebih dahulu. Pemeriksaan yang lolos
   bisa dibuka terpisah. Perubahan input menyembunyikan hasil sebelumnya.
6. Ekspor satu hasil atau seluruh riwayat dari bagian Riwayat evaluasi policy.

Hasil Lolos evaluasi statis adalah catatan pada waktu server saat itu, bukan
izin eksekusi atau jaminan keamanan target. Server membaca ulang versi terbaru
pada setiap evaluasi. UI untuk versi terdahulu tidak menyediakan form evaluasi.

## Semantik scope

| Jenis izin | Target yang tercakup |
| --- | --- |
| IP | IP identik atau URL dengan IP literal identik |
| CIDR | IP, CIDR yang seluruhnya di dalam jaringan tersebut, atau URL dengan IP literal di dalamnya |
| Domain | Host identik, termasuk URL pada host tersebut; tidak otomatis mencakup subdomain |
| URL | Scheme, host, dan port harus identik; path identik atau turunannya pada batas segmen |

`https://uat.example.test/api` mencakup `/api/users`, tetapi tidak `/apix`,
HTTP, port lain, atau subdomain. Case path dipertahankan. Target harus tercakup
satu entri izin; beberapa izin terpisah tidak otomatis digabung untuk memenuhi
permintaan CIDR lebih besar.

Pengecualian selalu menang. IP yang dikecualikan memblokir IP itu, URL dengan
IP tersebut, dan seluruh permintaan CIDR yang menyentuhnya. Scope luas yang
beririsan dengan pengecualian boleh disimpan dengan catatan; target harus
dipersempit saat dievaluasi. Scope yang seluruhnya ditutup satu atau gabungan
pengecualian CIDR tidak dapat diajukan. Pengecualian URL sempit juga memblokir
permintaan host/IP yang lebih luas pada host yang sama secara konservatif.

URL percent-encoded, dot segment, double slash, titik koma pada path, path
non-ASCII, serta penulisan host numerik ambigu ditolak policy. Gunakan bentuk
eksplisit. Pengecualian yang mencakup alias/transisi IPv6 juga harus diganti
dengan rentang alamat langsung yang tidak ambigu. Snapshot lama tetap terbaca, tetapi dinilai ulang dengan aturan baru.

Alamat metadata/link-local, multicast, unspecified, rentang IPv4 240/4, serta
beberapa rentang pemetaan/transisi IPv6 diblokir. Daftar persis ada pada
`backend/security_policy.py`. Loopback IPv4 memerlukan lingkungan lab; IPv6
loopback diblokir. Ini bukan inventaris lengkap semua alamat layanan internal
atau pemeriksaan kepemilikan target.

## Pemeriksaan guard

- Revisi Engagement, versi RoE, dan SHA-256 harus sesuai snapshot terkini.
  Isi snapshot juga dibandingkan dengan hash yang tersimpan.
- RoE harus lengkap, memenuhi policy terbaru, dan berstatus approved.
- Waktu server harus berada dalam `[starts_at, ends_at)`, serta durasi rencana
  harus selesai sebelum atau tepat saat periode berakhir.
- Tindakan harus termasuk izin eksplisit RoE. TCP memakai IP/CIDR/domain;
  HTTP/API memakai URL. Tindakan lain yang tidak dikenal ditolak.
- Port TCP wajib eksplisit dan subset port RoE. Port HTTP diturunkan dari URL
  (default 80/443) dan tidak dapat ditimpa dengan port lain.
- RPS, concurrency, dan durasi harus berada di bawah batas RoE dan batas global.
  Review API memerlukan alias akun uji yang terdaftar.
- Permintaan jaringan maksimal 256 alamat per evaluasi; tanpa enumerasi CIDR.
- Tindakan jaringan berbasis nama ditolak karena DNS/pinning belum tersedia.
  Permintaan IP juga ditolak bila ada pengecualian berbasis nama yang belum
  dapat dibandingkan dengan IP tersebut. Tidak menerima IP hasil resolve dari
  klien sebagai bukti. Review dokumen/konfigurasi offline tetap dapat dinilai
  menggunakan domain exact-host.

`decision=pass`, `execution_enabled=false`, dan `grants_execution=false` dapat
muncul bersama. Tidak ada token/kapabilitas eksekusi yang diterbitkan. Belum ada
redirect handling, DNS pinning, rebinding protection pada koneksi, atau
enforcement RPS pada runner karena semua eksekusi tetap terkunci.

## Penyimpanan dan API

Tabel tambahan `policy_checks` dibuat otomatis pada SQLite Engagement yang
sudah ada tanpa mengubah snapshot lama. Evaluasi dan pembacaan versi saat itu
berada dalam transaksi yang sama. Evaluasi tidak mengubah revisi/persetujuan.
Maksimal 500 hasil per Engagement; setelah batas tercapai API menolak pencatatan
baru dengan 409 dan mempertahankan riwayat. UI menampilkan 20 terbaru; ekspor
seluruh riwayat menyertakan hingga 500 catatan. Backup runtime mencakup tabel ini.
Ekspor RoE dan ekspor policy adalah berkas terpisah.

Endpoint terautentikasi:

- `POST /api/security/scope-validation` menerima `{content: ...}` untuk draft.
- `POST /api/security/projects/{project_id}/engagements/{id}/policy-checks`
  menerima proposal dengan revisi, versi RoE, hash, target, tindakan, dan batas.
- `GET` pada path policy-checks menampilkan 20 terbaru; `?all_records=true`
  mengekspor semua catatan yang dipertahankan.

Penolakan policy mengembalikan HTTP 200 dengan `decision=deny` dan alasan per
pemeriksaan. Kesalahan bentuk input memakai 422; Project/Engagement yang tidak
cocok 404. Hasil bukan audit tahan manipulasi dan persetujuan masih deklarasi
lokal, tanpa RBAC atau pemisahan identitas peninjau.

## Verifikasi

Jalankan tes backend, `npm test`, `npm run lint`, dan `npm run build` sebagaimana
dijelaskan pada panduan Security Workspace. Tes tahap 2 mencakup containment
IP/CIDR/IPv6, batas domain/URL, pengecualian, jadwal, port/budget, status dan
snapshot lama, integritas hash, autentikasi, persistensi dan ekspor riwayat,
serta bukti bahwa evaluasi tidak memanggil DNS/socket/subprocess/scanner.
