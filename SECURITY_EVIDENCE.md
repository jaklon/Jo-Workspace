# Security Workspace tahap 4 — Evidence, Findings, Reports

Jo Workspace Local 1.4.0 menambahkan pengelolaan bukti dan laporan lokal. Seluruh
eksekusi pentest tetap terkunci (HTTP 423). Tidak ada scanner, HTTP/DNS ke target,
model, MCP, atau layanan berbayar baru yang dipanggil tahap ini.

## Akses dan alur

Klik ikon Jo Workspace, buka **Security Workspace · Tahap 4**, pilih Project dan
Engagement. Tab **Evidence**, **Findings**, dan **Reports** berada setelah Runs.
Catatan engagement dapat dibaca juga ketika melihat RoE lama, dicabut, atau
kedaluwarsa; laporan mencatat versi historis bukti dan snapshot RoE saat dibuat.

1. Selesaikan job validasi offline pada Runs. Buka **Evidence → Tambah evidence**.
2. Pilih run terminal dan langkah yang memiliki hasil policy. Target dan binding
   RoE diambil dari rencana server, bukan diketik ulang sebagai klaim asal bukti.
3. Pilih asal: **Policy offline**, **Fixture sintetis**, atau **Impor eksternal**.
   Policy diambil langsung dari hasil tersimpan. Impor memerlukan teks, waktu
   dengan zona, nama/versi tool, parameter, dan acknowledgement operator.
4. Periksa hasil sensor. Detail dan ekspor mencatat UUID, engagement/run/langkah,
   target, waktu pengambilan/penerimaan, tool/versi, parameter, keputusan policy
   historis, RoE/hash, hash asli, hash artefak tersensor, dan hash record.
5. Buat **Finding baru**. Deskripsi, interpretasi AI, dan keputusan analis adalah
   kolom terpisah. Isi target/kategori, tautkan bukti, severity/dasarnya, remediasi,
   penanggung jawab, dan duplikat semantik bila ada.
6. Gunakan **Keputusan analis** untuk review. Nama dan acknowledgement adalah
   deklarasi lokal, bukan identitas terverifikasi atau pemisahan approver/operator.
7. Buat **snapshot laporan** dengan judul, ringkasan, dan deklarasi penyusun.
   Pratinjau serta ekspor Markdown/JSON tersedia. Perubahan berikutnya tidak
   menimpa laporan lama; buat snapshot baru untuk revisi laporan.

## Status, dasar penilaian, dan retest

- Finding baru selalu **Candidate**, termasuk ketika narasi AI mengatakan
  "confirmed". Tidak ada model AI dipanggil; interpretasi dapat dicatat manual.
- **Validated** memerlukan setidaknya satu bukti observasi/fixture dengan target
  yang sama, policy historis lolos, integritas sesuai, severity beserta dasarnya,
  dan review analis eksplisit. Bukti policy saja tidak cukup. Validated pada
  fixture hanya berarti hasil review fixture, bukan kerentanan target nyata.
- **False Positive** dan **Inconclusive** menyimpan alasan keputusan manusia.
- **Retest Passed** hanya mengikuti Validated. Wajib bukti observasi baru dari
  job berbeda, diambil setelah review sebelumnya; target harus sama. Tidak ada
  pengujian retest otomatis. Fixture retest tetap ditandai sintetis.
- Setiap edit konten mengembalikan status ke Candidate, menghapus keputusan
  aktif, dan membuat snapshot revisi baru. Keputusan lama tetap di riwayat.
- Judul/kategori yang sama setelah normalisasi case/spasi pada target yang sama
  ditolak sebagai duplikat persis dengan ID existing. Duplikat semantik dapat
  ditautkan ke finding utama pada target yang sama; rantai/siklus dilarang dan
  finding duplikat tidak dapat menjadi Validated/Retest Passed.

CVSS bersifat opsional. Backend menghitung **CVSS 3.1 Base** dari delapan metrik
lengkap, sesuai [spesifikasi FIRST](https://www.first.org/cvss/v3.1/specification-document).
Dasar metrik wajib bila vektor diisi. Metrik duplikat, skor buatan client, vektor
parsial, Temporal/Environmental, dan CVSS 4.0 tidak diterima. Severity tetap
penilaian analis terpisah yang membutuhkan alasan; tidak ditentukan narasi AI.

## Sensor dan integritas

Teks maksimum **64 KiB UTF-8** per evidence. UI menerima .txt/.json/.md/.log/.csv
atau teks tempel. Binary/karakter kontrol ditolak. Tidak ada path berkas server
atau URL yang diunduh, diparsing menjadi perintah, maupun dijalankan.

Header Authorization/Cookie, key password/token/API key yang dikenali, JWT,
private key PEM lengkap, email, dan pola angka sensitif disensor sebelum
penyimpanan. Gunakan istilah sensor tambahan (3–200 karakter, maksimal 20) untuk
isi formulir yang tidak dikenali. Istilah itu sendiri tidak disimpan. Nama target
scope dipertahankan exact untuk binding; target yang memerlukan sensor ditolak.
Error schema API tidak mengembalikan input bukti/rahasia.

**Sensor adalah best effort**, bukan detektor seluruh PII/rahasia. Periksa
keluaran sebelum berbagi. Tampilan, API biasa, serta laporan hanya menyertakan
artefak tersensor. Pada desktop Windows, teks asli evidence baru disimpan dalam
arsip **DPAPI untuk akun Windows saat ini**, memakai entropy ID/hash evidence.
Tidak ada kunci/password baru yang perlu dikelola. Lihat
[dokumentasi Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

**Unduh asli · konfirmasi khusus** memerlukan deklarasi analis, alasan, dan
acknowledgement bahwa unduhan dapat berisi rahasia tanpa sensor. Ekspor dicatat,
memakai `Cache-Control: no-store`, serta memeriksa dekripsi dan hash sebelum
merespons. File hasil unduhan adalah plaintext; arsip terenkripsi tidak pernah
disertakan dalam laporan. Proteksi akun Windows tidak membatasi aplikasi lain
yang berjalan sebagai pengguna yang sama. Backup hanya database ke komputer
atau akun lain tidak menjamin arsip dapat didekripsi.

Record lama tanpa arsip asli tetap dapat dibaca; hash tidak dapat memulihkan
isinya. Runtime tanpa DPAPI/pywin32 menyatakan `unavailable_redacted_only`;
tidak ada penyimpanan plaintext sebagai fallback. Kegagalan enkripsi pada
runtime DPAPI membatalkan penyimpanan evidence. SHA-256 asli dihitung dari byte
UTF-8 isi impor yang diterima; UI mempertahankan BOM saat membaca file UTF-8.
Hash artefak mengacu pada teks setelah sensor. Hash bukan tanda tangan digital
atau audit tahan administrator yang dapat mengubah database.

Evidence, riwayat finding, dan laporan memakai hash integritas. Ketidaksesuaian
ditolak pada pembacaan/review/pelaporan. Isi tidak dirender sebagai HTML aktif;
ekspor Markdown menaruh input dalam fence yang aman. Policy historis tidak
menyatakan RoE saat ini masih aktif dan tidak memberi izin eksekusi.

## Penyimpanan dan batas

Migrasi aditif pada `engagements.sqlite3` membuat `security_evidence`,
`security_findings`, `security_finding_versions`, `security_reports`,
`security_evidence_originals`, dan `security_evidence_access`.
Desktop lokal gratis memakai `data/runtime` pada source project. Batas per
engagement: 100 evidence, 100 findings, 100 revisi per finding, 30 laporan;
30 tautan bukti per finding/keputusan retest, dan snapshot laporan maksimal
2 MiB JSON. Tidak ada penghapusan riwayat otomatis. Backup database saat server
berhenti, atau gunakan backup SQLite yang menyertakan transaksi WAL.

## API dan pengujian

Prefix seluruh endpoint terautentikasi:
`/api/security/projects/{project_id}/engagements/{engagement_id}`.

| Metode | Path | Kegunaan |
| --- | --- | --- |
| GET | `/records` | Daftar metadata evidence, findings, laporan |
| POST | `/evidence` | Simpan artefak tersensor immutable |
| GET | `/evidence/{id}` | Artefak dan provenance/integritas |
| POST | `/evidence/{id}/original` | Ekspor asli dengan konfirmasi khusus; tidak tersensor |
| POST | `/findings` | Candidate baru |
| GET / PUT | `/findings/{id}` | Detail/riwayat atau edit dengan expected_revision |
| POST | `/findings/{id}/review` | Keputusan analis dan tautan retest |
| POST | `/reports` | Snapshot lengkap yang tetap |
| GET | `/reports/{id}` | Snapshot, hash, Markdown |

Tes `backend/tests/test_security_evidence.py` meliputi auth dan batas Project,
schema/ukuran, sensor sebelum persistence, provenance, deduplikasi, review CAS,
revisi/riwayat, pemalsuan integritas, retest, laporan tetap, CVSS, migrasi, batas,
dan ketiadaan panggilan tool. Tes arsip memeriksa enkripsi DPAPI, konfirmasi,
audit ekspor, korupsi cipher, dan fallback legacy yang eksplisit.
Seluruh 124 tes backend serta 57 assertion frontend
lulus; lint/typecheck/build diverifikasi terpisah. Fixture UI memakai direktori
`output/security-stage4/` yang terpisah dari data desktop.

Tahap 5 MCP, tahap 6 orkestrasi model, dan tahap 7 multi-agent belum diaktifkan.
