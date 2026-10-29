# Pencarian web dan gambar di chat Jo Workspace

Di tab **Chat**, pilih mode **Web: Otomatis**, **Selalu cari**, atau **Mati** di atas kotak pesan. Mode otomatis meminta model menentukan kebutuhan sumber eksternal dan langsung mencari untuk permintaan yang jelas tentang informasi terkini, sumber, tautan, atau gambar. Mode **Selalu cari** memaksa pencarian untuk pesan itu; **Mati** memakai alur model biasa. Chat dengan lampiran tetap memakai sumber lampiran.

Alur pencarian: SearXNG lokal mengembalikan hasil JSON; Jo Workspace memilih maksimal lima URL HTTPS publik beserta cuplikan. Bila pertanyaan meminta analisis halaman, tautan spesifik, atau cuplikan terlalu singkat, backend mengambil maksimal tiga halaman dengan satu GET per URL, tanpa redirect, login, atau bypass proteksi situs. Scrapling mem-parsing teks utama dan gambar; konteks dipotong sesuai anggaran model. Jawaban menampilkan nomor sumber dan tautan yang dapat dibuka. Permintaan gambar menampilkan galeri di bawah jawaban. Isi web diperlakukan sebagai data tidak tepercaya, bukan instruksi untuk model.

SearXNG harus berjalan di Docker Desktop. Jalankan `desktop-app/dist/Start-Jo-Search.cmd`, lalu buka Jo Workspace melalui shortcut Desktop agar sesi lokal dibuat otomatis. Halaman preview pada port lain dapat memakai token yang berbeda. Server lokal sumber memakai `data/runtime/api-token` kecuali prosesnya diatur dengan `AGENT_API_TOKEN` atau `AGENT_DATA_DIR`; token tidak dikirim di URL.

Jika halaman menolak akses atau menampilkan challenge, Jo Workspace tidak melewati proteksi itu. Untuk hasil pencarian, chat menandai sumber yang hanya memiliki cuplikan; URL eksplisit yang tidak dapat dibaca menghasilkan pesan kesalahan. SearXNG menyediakan hasil pencarian, bukan izin untuk melewati pembatasan situs tujuan. Eksekusi pentest nyata tetap terkunci.

Untuk URL HTTPS eksplisit yang HTML awalnya hanya berisi metadata dan script, Jo Workspace mencoba merender JavaScript memakai Playwright dan Chrome/Edge yang sudah terpasang. Renderer memakai sesi sementara, mengizinkan maksimal 20 GET pada host yang sama, membatasi ukuran respons, menolak redirect dan subresource lain, lalu menutup browser. Isi web tetap data tidak tepercaya. Jika browser gagal, chat tetap memakai metadata dengan label yang jelas. Hasil pencarian umum tidak otomatis membuka browser.

Contoh `https://hemoforge.vercel.app/`: HTML awal berisi metadata, sedangkan perenderan browser membaca isi UI. Fitur ini tidak memecahkan challenge Cloudflare.
