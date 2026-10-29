# Deep Analisis dan kategori VA · 1.13.0

VA di Jo Workspace dibagi berdasarkan informasi dan akses yang dimiliki peninjau:

| Kategori | Sumber yang diterima | Pemeriksaan tambahan |
| --- | --- | --- |
| BlackBox | HEAD atau impor observasi eksternal | Job selesai, persetujuan, scope dan RoE aktif |
| WhiteBox | Impor kode sumber, konfigurasi, dokumentasi API atau monitoring | Izin document_review dan deklarasi jenis evidence |
| GreyBox | Impor dokumentasi API, konfigurasi atau observasi akun uji | Izin document_review dan alias akun uji dalam RoE |

Kategori tersimpan di laporan dan disertakan ke konteks model. Jenis evidence
merupakan deklarasi peninjau; sistem tidak membuktikan isi sesuai kategori.
GreyBox memakai alias saja dan tidak melakukan login. Password/token tidak diperlukan.
Pilihan kategori tidak menambah hak jaringan atau menyalakan scanner.
Laporan VA dapat diunduh sebagai JSON dari tab Deep Analisis.

Fitur awal ini meninjau evidence hasil pemeriksaan URL yang telah disetujui pada
Engagement yang sama. Ia menggunakan model Ollama lokal dan menyimpan ringkasan,
observasi, keterbatasan, rekomendasi, identitas model, hash RoE, dan hash evidence.
Hasil berstatus memerlukan review manusia dan tidak otomatis menjadi finding.

1. Di Project, buat Engagement dan setujui RoE yang mencakup URL, port, waktu,
   dan tindakan `http_headers`.
2. Pada **Pemeriksaan URL**, buat rencana, periksa target, dan setujui satu HEAD.
   Tunggu hingga selesai dan evidence tersedia.
3. Pada **Deep Analisis**, pilih pemeriksaan dan model Ollama lokal, masukkan nama
   peninjau, konfirmasikan analisis evidence, lalu klik **Analisis evidence**.
   Backend memeriksa gate, scope, versi RoE, job yang disetujui, serta integritas
   evidence sebelum dan setelah inferensi. Jika pemeriksaan gagal, hasil tidak disimpan.
   Untuk hasil tool yang Anda jalankan sendiri, impor teks tersensor melalui tab
   Evidence dan tautkan ke job yang telah disetujui dan selesai. Pilih evidence
   impor pada tab Deep Analisis. RoE juga harus mengizinkan `document_review`.
   Impor dinyatakan oleh operator dan asal maupun pelaksanaan tool tidak diverifikasi.
   Persetujuan analisis tidak memberi izin untuk menjalankan tool terhadap target.
4. Di chat yang terhubung ke Project yang sama, tulis misalnya
   `Deep analisis https://project.example/`. Chat menampilkan laporan tersimpan
   beserta ID dan hash evidence. Jika belum ada laporan, chat menunjukkan langkah
   yang diperlukan. Chat tidak menjalankan scanner baru secara otomatis.

Eksekusi pemeriksaan yang saat ini terintegrasi adalah satu HEAD publik yang sudah ada;
serta [scan TCP dengan persetujuan](SECURITY_TCP_SCAN.md) melalui adapter bawaan
atau Nmap terpasang. Hasil TCP hanya menunjukkan konektivitas port.
hasilnya tidak membuktikan XSS, SQL injection, SSRF, RCE, atau kelemahan lain.
Profil eksekusi Nuclei HEAD, ZAP passive headers, Subfinder crt.sh, Amass crt.sh-only,
dan snapshot monitoring lokal kini tersedia melalui tab Tools & monitoring.
Lihat [batas dan kebutuhan tiap profil](TOOL_INTEGRATIONS.md). Ini bukan full scan
aplikasi atau konektor semua layanan SIEM. Burp, layanan intelijen lain serta
review frontend/API otomatis belum tersedia. Eksekusi exploit umum tetap terkunci;
semua adapter memerlukan persetujuan per job dan dependensi yang tersedia.

Model memproses data sebagai masukan tidak tepercaya, tanpa akses tool atau shell.
Output mengikuti schema dan disensor secara best effort; pengguna tetap harus
memeriksa kecukupan bukti dan kebenaran semua kesimpulan.

Panel **Status tools dan monitoring** menampilkan deteksi executable/image dan profil
adapter. Deteksi saja tidak mengizinkan run; persetujuan dan pemeriksaan policy
tetap wajib. Monitoring yang disediakan adalah kesehatan Prometheus/Grafana lokal.
Wazuh, ELK, CrowdSec dan Cloudflare masih berupa impor manual.
