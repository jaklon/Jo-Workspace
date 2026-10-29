# Circular Sync: panduan fitur awal di Jo Workspace

Project `Circular Sync Staging` telah dibuat. Pemeriksaan awal HEAD menggunakan
Nuclei dan ZAP yang sudah dijalankan sebelumnya tersimpan pada Engagement
`Circular Sync Staging - Deep Analisis HEAD`; pemeriksaan itu tidak menguji login.

## Membuat Engagement baru

1. Buka Jo Workspace → Security Workspace → Project `Circular Sync Staging`.
2. Buat Engagement baru untuk staging, isi pihak yang berwenang, kontak,
   jadwal, tujuan, kondisi stop, dan referensi izin.
3. Tentukan URL HTTPS milik Anda yang masuk scope dan port 443. Untuk mencakup
   beberapa path pada host yang sama, gunakan URL root yang memang Anda miliki;
   cantumkan pengecualian jika ada. Host API, Firebase, atau pihak ketiga yang
   berbeda tidak otomatis masuk scope.
4. Pilih tindakan `Inventaris tautan HTML tanpa sesi`, `Pemeriksaan GET tanpa
   sesi`, dan bila memakai dua akun `Review API dengan akun uji`. Isi dua alias
   akun yang berbeda pada RoE, serta batas 1 request/detik dan concurrency 1.
   Submit dan approve RoE.
5. Buka `Tools & monitoring` dan pilih `Inventaris tautan HTML · GET terbatas`.
   Masukkan satu URL yang ada dalam scope, port 443, siapkan rencana, review,
   lalu setujui run. Aplikasi mencatat hingga 40 origin kandidat dari HTML;
   kandidat tidak dihubungi dan tidak otomatis masuk scope. JavaScript tidak
   dijalankan atau dibaca sehingga hasil bisa tidak lengkap untuk aplikasi SPA.
6. Untuk URL HTTPS lain yang jelas berada dalam scope, pilih `Akses tanpa sesi ·
   GET terbatas`, siapkan rencana dan setujui. Aplikasi mengirim satu GET tanpa
   cookie/token, tidak menyimpan body, dan tidak mengikuti redirect. Hindari
   endpoint dengan efek samping; tidak ada submit form atau percobaan password.
7. Untuk membandingkan dua akun, pilih `Perbandingan akses · dua akun uji`,
   pilih alias A dan B yang tercatat di RoE, dan masukkan URL API yang sama
   dalam scope. Setelah review rencana, masukkan token ID sementara kedua akun
   di formulir lokal Jo Workspace dan setujui. Jangan gunakan password. Token
   dikirim hanya ke origin URL disetujui, tanpa redirect; tidak masuk rencana,
   evidence, atau LLM. Antrean token berada di memori maksimal 2 menit dan
   hilang setelah dipakai, dibatalkan, kedaluwarsa, atau aplikasi ditutup.
   Login manual untuk mengambil token belum terintegrasi; token staging perlu
   disediakan melalui alur autentikasi Anda sendiri.
   Jika JSON memiliki field ID pemilik yang diketahui, isi JSON Pointer seperti
   `/data/ownerId`. Hasil boolean dibandingkan dengan klaim `sub` dua token
   dalam urutan alias A lalu B, tanpa menyimpan nilai field. Jo Workspace tidak
   memverifikasi tanda tangan token: kecocokan adalah indikasi untuk peninjauan,
   bukan bukti kepemilikan atau bypass. JSON Pointer tersimpan dalam rencana.
8. Evidence disimpan pada Engagement dan dapat dipilih pada Deep Analisis.
   LLM meninjau evidence yang disimpan; hasil harus direview manusia.

Perbandingan dua akun mencatat status, kesamaan byte, nilai JSON yang
dinormalisasi, dan struktur JSON HTTP 200 berukuran maksimal 32 KiB dengan
Content-Length. Urutan kunci objek diabaikan dalam perbandingan nilai, sedangkan
urutan dan panjang array tetap diperhatikan. Ini bukan penilaian semantik atau
penentuan kepemilikan data. Isi dan hash diproses sementara dalam
memori dan tidak disimpan. JSON chunked, terkompresi atau lebih besar tidak
dibandingkan. Perbedaan atau kesamaan status/isi tidak membuktikan bypass. Status 401/403 adalah indikasi akses
ditolak pada request itu. Status 200 atau
redirect saja belum membuktikan login bypass: halaman SPA dan endpoint publik
bisa mengembalikan 200. Satu request juga tidak membuktikan semua akses aman.

## Belum tersedia

Login manual terintegrasi, analisis semantik atau kepemilikan isi lintas dua
akun, active scan Nuclei/ZAP, dan eksploitasi kerentanan belum tersedia.
Perbandingan terbatas nilai dan struktur JSON serta inventaris statis bundle sudah tersedia. Dua akun staging dan data dummy tetap perlu disiapkan sebelum
pengujian otorisasi; jangan memasukkan password atau token dalam chat.

Adapter ini diuji dengan fixture lokal. Pengguna menjalankan setiap run melalui
Jo Workspace dengan RoE dan persetujuan; tidak ada pengujian target otomatis
ketika aplikasi dipasang atau dibuka.

## Spider dan pemeriksaan aktif terbatas

- Tambahkan `Spider terbatas dalam scope` atau `Uji aktif marker aman` pada RoE
  staging, lalu buat dan setujui run terpisah pada Tools & monitoring.
- Spider mengambil maksimal lima halaman HTML HTTPS pada host yang sama, satu
  request per detik; scope dan pengecualian diperiksa ulang sebelum setiap
  koneksi. Tidak mengikuti redirect, form, query, atau menjalankan JavaScript.
  Beberapa path tindakan umum seperti logout dan delete diblokir, tetapi GET
  bisa memiliki efek samping lain; pilih scope staging dan pengecualian dengan
  cermat. Mulai dari path yang tidak mencakup pengecualian menurut policy.
- Scan aktif mengirim satu GET dengan marker alfanumerik pada `jo_probe` dan
  melaporkan apakah marker muncul pada body. Body dan marker tidak disimpan.
  Refleksi bukan bukti XSS atau bypass; ini bukan ZAP active scan atau Nuclei
  vulnerability scan menyeluruh. Setiap run butuh persetujuan.
- Semua pengujian implementasi dilakukan pada fixture lokal. Tidak ada run ke
  Circular Sync dari implementasi atau pemasangan.

## Inventaris bundle JavaScript

Pilih `Inventaris bundle JavaScript` pada Tools & monitoring dan berikan URL
bundle HTTPS eksplisit yang termasuk RoE `service_inventory`. Aplikasi membaca
satu bundle maksimal 1 MiB tanpa mengeksekusinya dan mencatat origin serta path
API statis sebagai kandidat yang belum diverifikasi. Kandidat tidak dihubungi
dan tidak otomatis masuk scope. Bundle berukuran lebih besar ditolak.
