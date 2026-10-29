# Scan TCP yang disetujui

Di Security Workspace, pilih Project dan Engagement, lalu buka **TCP Scan**.
RoE harus aktif, disetujui, memuat IP dan port eksplisit serta tindakan
`tcp_discovery`. Production read-only tidak mengizinkan tindakan ini.

1. Masukkan satu IP dan maksimal 16 port yang diizinkan.
2. Pilih TCP connect bawaan atau Nmap bila terpasang pada mesin backend.
3. Siapkan rencana, periksa IP, port, tool dan versi RoE.
4. Masukkan peninjau dan catatan, centang otorisasi, lalu setujui run.
5. Hasil dan evidence tersimpan. Gunakan tab Deep Analisis untuk interpretasi
   model lokal dengan kategori BlackBox. WhiteBox/GreyBox tetap memerlukan
   evidence internal atau akun uji sesuai kategori.

Runner hanya menerima satu IP tanpa DNS, CIDR, command, opsi atau NSE dari pengguna.
Nmap memakai connect scan, tanpa deteksi versi, script atau exploit. Hash binary
terikat ke rencana dan diperiksa ulang. Binary Nmap tidak disertakan installer.
TCP bawaan tersedia tanpa dependensi scanner eksternal; tidak menyatakan hasilnya
sebagai hasil Nmap. Maksimal concurrency 1, jeda 1 detik dan waktu run 60 detik.

Scope, pengecualian, jadwal, status RoE, persetujuan, hash rencana dan gate stop
diperiksa sebelum run dan setiap pemeriksaan berjalannya task. Stop membatalkan
task dan menghentikan proses Nmap milik run. Hasil tidak disimpan sebagai sukses
jika izin berubah. Satu koneksi yang sudah dikirim tidak dapat ditarik kembali.

`POST /api/pentest/run` menerima referensi `project_id`, `engagement_id`, `job_id`,
`expected_revision`, `actor_label`, `note`, `acknowledge`. Endpoint ini meninjau dan
mengantrekan rencana scan melalui mekanisme persetujuan yang sama. Permintaan
legacy berbasis target bebas tetap ditolak. Tidak ada switch global tanpa scope.

Profil terbatas Nuclei, ZAP, Amass, Subfinder dan monitoring lokal tersedia pada
tab yang sama. Lihat [panduan integrasi](TOOL_INTEGRATIONS.md). Profil tersebut
tidak membuka eksekusi exploit umum atau template/perintah bebas.
