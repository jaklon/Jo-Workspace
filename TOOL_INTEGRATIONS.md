# Integrasi adapter · Jo Workspace

Semua adapter berada pada **Project → Security Workspace → Engagement → Tools &
monitoring**. Rencana terikat hash RoE dan identitas binary/image. Persetujuan
per run wajib, policy diperiksa ulang selama task berjalan, dan stop membatalkan
proses/container milik run. Evidence server tersimpan untuk Deep Analisis.

| Adapter | Profil yang dijalankan | Kebutuhan RoE |
| --- | --- | --- |
| Nuclei | Satu template HEAD observasi CSP, tanpa template pengguna/redirect/OAST | URL domain atau IP, http_headers, port URL, 1 menit |
| ZAP | Satu HEAD diambil adapter, header terpilih disensor dan diimpor sebagai HAR ke container network=none. ZAP passive rules saja | URL domain atau IP, http_headers, port URL, 3 menit |
| Subfinder | Recon pasif crt.sh saja, tanpa active resolution atau probe target | Domain exact, passive_recon, port 443, 2 menit, pengungkapan domain disetujui |
| Amass | Build khusus crt.sh-only, semaphore jaringan satu, tanpa plugin aktif/DNS/WHOIS lainnya | Domain exact, passive_recon, port 443, 4 menit, pengungkapan domain disetujui |
| Monitoring lokal | Readiness Prometheus, query up, database health Grafana | lab, 127.0.0.1, port 3000/9090, monitoring_read |

Profil Nuclei dan ZAP merupakan pemeriksaan header terbatas, bukan full scan
kerentanan aplikasi. CSP absen belum membuktikan exploit. Empty output Nuclei
atau Subfinder dapat berarti tidak ada match/data atau sumber gagal. Nama yang
ditemukan Subfinder tidak otomatis mendapat izin scan atau masuk scope baru.
Domain dikirim ke crt.sh; kuota/ketersediaan sumber eksternal bukan jaminan aplikasi.

Nuclei menggunakan executable terpasang di PATH atau USERPROFILE/go/bin. ZAP dan
Subfinder memerlukan Docker Desktop dan image resmi yang disiapkan pada mesin:

```
docker pull ghcr.io/zaproxy/zaproxy:stable
docker pull projectdiscovery/subfinder:latest
```

Image ID aktual diikat ke rencana; perubahan image memerlukan rencana/persetujuan
baru. Tidak ada mount direktori pengguna atau credential provider ke container.
Nuclei memakai HOME/config sementara tanpa kredensial pengguna. Image dan tool
tidak dibundel ke EXE installer. Tidak ada download otomatis ketika run disetujui.

Monitoring: lihat [panduan stack gratis](deploy/monitoring/README.md).

Amass memakai image profil khusus `jo-workspace/amass-crtsh:1`, dibangun dari source
resmi pada commit `a284d25a890cbb561a53410080a3fd96bbaa7312`. Image resmi awal gagal
bootstrap tanpa jaringan karena plugin BGPTools; profil khusus mendaftarkan hanya
plugin crt.sh dan memakai SQLite/engine sementara di dalam container. Tidak ada
database/port engine yang dibuka ke host. Nama seed root dikeluarkan dari daftar hasil.

Untuk membuat ulang profil pada mesin build:

```
git clone https://github.com/owasp-amass/amass.git output/amass-source
git -C output/amass-source checkout a284d25a890cbb561a53410080a3fd96bbaa7312
backend/venv/Scripts/python.exe scripts/prepare_amass_profile.py
docker build -f deploy/amass/Dockerfile -t jo-workspace/amass-crtsh:1 output/amass-source
```

Simpan atribusi lisensi Apache-2.0 source upstream saat mendistribusikan image.
Image ini adalah profil Jo Workspace, bukan distribusi resmi Amass tanpa perubahan.
Wazuh, ELK, CrowdSec dan Cloudflare belum menjadi konektor aplikasi; stack gratis
yang disediakan adalah Prometheus/Grafana untuk kesehatan layanan lokal.

Untuk menjaga konteks model lokal, daftar recon di atas 8 nama dan alert ZAP di
atas 4 alert memakai sampel eksplisit. Jumlah yang tidak dibaca model ditampilkan
di laporan/chat. Source/evidence lengkap tetap disimpan dan diekspor dalam JSON.
Impor teks terlalu besar ditolak oleh batas konteks; tidak dipotong diam-diam.

## Mencoba dari desktop

1. Buka Jo Workspace 1.13.0 dari shortcut Desktop. Nyalakan Docker Desktop untuk
   profil ZAP, Subfinder, Amass, dan monitoring. Pada laptop build ini dependensi
   tersebut sudah disiapkan; installer tidak memuat image Docker atau Nuclei.
2. Buka atau buat Project, lalu buka Security Workspace dan buat Engagement.
   Pilih lingkungan lab/staging yang sesuai, isi pemilik izin, jadwal aktif,
   scope exact, pengecualian, tindakan, port, serta RPS/concurrency 1. Gunakan
   durasi minimum pada tabel di atas. Submit dan approve RoE.
3. Buka tab **Tools & monitoring**, pilih adapter. Isi target yang persis masuk
   scope dan port yang diizinkan. Profil Nuclei/ZAP menerima URL domain atau IP. DNS domain diperiksa dan
   terikat ke satu IP publik; ZAP memvalidasi sertifikat HTTPS untuk hostname.
   Nuclei menggunakan Host dan SNI domain, dengan URL transport ke IP terikat.
4. Untuk Subfinder/Amass, masukkan domain milik Anda yang diizinkan pada RoE.
   Centang persetujuan pengiriman domain ke crt.sh. Root scope ini tidak berarti
   seluruh subdomain otomatis boleh dipindai. Jangan memakai domain pihak lain.
5. Siapkan rencana. Review target, tindakan, port, durasi, hash RoE/rencana dan
   identitas binary/image. Setujui run hanya jika semuanya sesuai. Run yang
   belum disetujui tidak menjalankan tool. Perubahan RoE/image memerlukan
   rencana dan persetujuan baru.
6. Tunggu status selesai atau gunakan Stop. Lihat hasil/evidence pada Engagement.
   Status proses selesai tidak menjamin sumber eksternal menghasilkan data;
   hasil kosong diberi batasan eksplisit. Review alert sebelum menjadi finding.
7. Pada Deep Analisis pilih kategori VA dan evidence hasil tool, lalu jalankan
   analisis dengan model Ollama yang tersedia. WhiteBox memerlukan evidence
   internal; GreyBox memerlukan alias akun uji pada RoE. Tidak ada kredensial
   yang otomatis dikirim ke tool ini.
8. Pada Chat di Project yang sama, minta `Deep analisis domain:domain-anda.com`
   atau `Deep analisis ip:127.0.0.1` untuk membaca laporan yang sudah dibuat.
   Sertakan kategori bila perlu. Chat memakai laporan/evidence tersimpan dan
   tidak melewati persetujuan untuk menjalankan scan baru.

Uji rilis menggunakan fixture HEAD loopback untuk Nuclei/ZAP, monitoring lokal
nyata, serta domain cadangan `example.invalid` untuk menguji proses dan alur izin
Subfinder/Amass. Tes domain cadangan tidak membuktikan kelengkapan data crt.sh
untuk domain nyata. Tidak ada pemindaian target perusahaan tanpa RoE pada uji ini.
