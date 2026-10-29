# Jo Workspace — panduan workspace desktop

Jalankan `start-web.ps1 -SkipBuild` dari root proyek, lalu buka
http://127.0.0.1:8010. Untuk aplikasi Electron, jalankan backend terlebih dahulu
dan gunakan `npm run dev` dari folder `desktop-app`.

## Percakapan dan project

- Gunakan **Chat baru** atau **Ctrl+Shift+O** untuk membuat percakapan.
- Pilih Chat, Code, Vision, Dokumen, atau Security melalui pemilih mode di header.
- **Ctrl+K** membuka pencarian seluruh judul dan isi chat; filter project dan arsip tetap berlaku.
- **Tanpa project** menampilkan percakapan pribadi yang tidak dikelompokkan.
- Buat project melalui ikon folder tambah. Project memiliki nama dan instruksi khusus.
- Saat sidebar difilter ke suatu project, chat baru dibuat dalam project tersebut.
  Breadcrumb di atas percakapan selalu menunjukkan project dari chat yang sedang dibuka.
- **Kelola chat** menyediakan ubah judul, pindah project, pin, arsip/pulihkan,
  ekspor Markdown, dan hapus dengan konfirmasi.
- Menghapus project memindahkan chat di dalamnya ke **Tanpa project**.
- Project hanya mengelompokkan chat dan menyertakan instruksi pada pesan berikutnya.
  Riwayat, lampiran, dan akses berkas tidak dibagikan otomatis antarpercakapan.

## Settings

Buka melalui ikon di header, profil di sidebar, atau **Ctrl+,**.

| Kategori | Pengaturan dan tindakan |
| --- | --- |
| Umum | Nama panggilan, mode awal, Enter untuk mengirim, saran pertanyaan, gulir otomatis, reset preferensi perangkat |
| Tampilan | Tema gelap/terang/sistem, ukuran teks jawaban, kurangi animasi |
| Personalisasi | Bahasa jawaban, gaya ringkas/seimbang/terperinci, instruksi pribadi |
| Model & inferensi | Model Chat/Dokumen, Coding, Vision, Security; context window; batas token jawaban; temperature; timeout model dan antrean |
| Koneksi | Status backend/Ollama, daftar model yang belum tersedia, uji koneksi, keluar/ganti token |
| Kontrol data | Ekspor JSON, impor gabungan, arsipkan semua, hapus chat/project lokal beserta lampiran yang dirujuk, reset usage backend |
| Privasi & keamanan | Lokasi workspace, batas lampiran, retensi, status persetujuan kode dan pembatasan shell |
| Pintasan | Daftar pintasan keyboard, disesuaikan dengan preferensi Enter |
| Tentang | Versi dan teknologi aplikasi |

Preferensi pribadi tersimpan otomatis pada perangkat/browser ini. Pengaturan model
harus disimpan secara eksplisit dan berlaku pada **semua klien backend yang sama**.
Penyimpanan model berada di `AGENT_DATA_DIR/settings.json` dan dimuat saat server
dimulai, menggantikan nilai awal dari environment. Tombol **Isi nilai bawaan**
mengisi formulir berdasarkan konfigurasi awal server; klik **Simpan konfigurasi**
untuk menerapkannya.

Perubahan konfigurasi model ditolak selama inferensi/antrean aktif. Model tidak
diunduh otomatis. Context window dibatasi 2048–32768, jawaban 128–8192 token
dan maksimal sepertiga context window, temperature 0–2, timeout model 30–600
detik, dan timeout antrean 5–120 detik. Gunakan model vision yang mendukung gambar.

Alamat backend mengikuti origin web atau konfigurasi build desktop; alamat Ollama
mengikuti `OLLAMA_URL` saat backend dimulai. Keduanya ditampilkan sebagai informasi,
bukan formulir penggantian alamat langsung. Batas akses workspace dan kewajiban
persetujuan perubahan kode tetap dikelola backend.

## Usage

Usage mencatat inferensi selesai, gagal, dihentikan, token input/output, durasi
termasuk antrean, dan aktivitas per model. Statistik memakai laporan token Ollama;
permintaan yang tidak menyediakan jumlah token tidak diberi angka perkiraan.
Satu pesan dapat memicu beberapa inferensi, terutama Vision dan agent coding.
Inferensi selesai juga mencakup jawaban yang mencapai batas token.

Catatan disimpan pada `AGENT_DATA_DIR/usage.json`, maksimal 90 hari,
menggunakan tanggal **UTC**. Angka mencakup seluruh klien backend tersebut,
mulai sejak fitur pencatatan aktif, dan tetap tersedia setelah backend dimulai ulang.
Isi chat dan ID percakapan tidak dicatat di Usage. Biaya listrik atau kuota
layanan cloud tidak dihitung. Statistik dapat difilter dan diekspor sebagai JSON.

## Penyimpanan dan cadangan

Riwayat dan project disimpan pada IndexedDB browser, preferensi pada localStorage.
Data tidak otomatis tersinkron ke perangkat lain. Batas riwayat adalah 500 chat
per mode dan 100 pesan terbaru per chat. Gambar asli tidak disimpan dalam riwayat.

Ekspor JSON menyertakan teks chat, metadata project, dan preferensi. Token akses,
gambar asli, ID lampiran, dan proposal perubahan kode tidak disertakan. Impor
memvalidasi format, membuat ID baru, dan menggabungkan chat/project tanpa menimpa
data lama. Preferensi perangkat saat ini tetap dipakai; lampiran perlu diunggah ulang.
Batas ukuran impor 10 MB. Simpan cadangan dengan aman karena teks chat dapat
berisi informasi pribadi.

## Validasi pengembangan

```powershell
backend\venv\Scripts\python.exe -m unittest discover -s backend\tests -v
cd desktop-app
npm run typecheck
npm run lint
npm test
npm run build
```

Pengujian mencakup autentikasi Settings/Usage, validasi dan persistensi konfigurasi,
akuntansi token, kegagalan/pembatalan inferensi, pelepasan antrean GPU, migrasi chat,
keamanan cadangan, serta pemetaan project saat impor.
