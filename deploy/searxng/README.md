# SearXNG lokal untuk Jo Workspace

Jalankan `Start-Jo-Search.cmd` dari `desktop-app/dist` sesudah Docker Desktop menyala. Skrip membuat secret lokal di `deploy/searxng/runtime/settings.yml`, lalu menjalankan image resmi SearXNG dengan port 8080 hanya pada `127.0.0.1`. Pertama kali memerlukan internet untuk menarik image. Buka menu **Cari web & gambar** di Jo Workspace. JSON API diaktifkan pada konfigurasi ini.

Scrapling 0.5 sudah menjadi dependensi backend Jo Workspace. Ia hanya mem-parse HTML halaman hasil yang Anda pilih; browser stealth, login otomatis, crawl masif, dan bypass bot tidak digunakan. Gambar diproksi oleh backend dengan batas 2 MB, MIME tertentu, DNS publik, HTTPS, tanpa redirect.

Untuk menghentikan layanan: `docker compose -f deploy/searxng/docker-compose.yml down` dari folder proyek. Data pengaturan lokal tetap ada untuk penggunaan berikutnya.
