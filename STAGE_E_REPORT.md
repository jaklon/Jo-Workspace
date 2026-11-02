# Laporan Tahap E — Security, Evaluasi Model, Pengujian Terpadu

Tanggal: 2 November 2026 · Backend uji: `:8010` (instance yang berjalan) · Ollama `127.0.0.1:11434`

## Ringkasan

| Area | Status | Catatan singkat |
|---|---|---|
| Dokumentasi vs fitur security | ✅ Selaras | Eksekusi pentest nonaktif; approval = deklarasi lokal tanpa RBAC; batas hasil tercantum |
| Tes backend (unittest) | ✅ 355/355 OK | backup, sync, security, readiness |
| Tes frontend (`npm test`) | ✅ 8/8 suite | backup, recovery, sync, recovery profile iPhone/remote, security UI |
| Typecheck | ✅ Lulus | |
| Lint | ✅ 0 error (setelah perbaikan) | 444 warning, mayoritas line ending CRLF |
| Evaluasi model | ⚠️ 40/52 (77%) | dokumen & isolasi kuat; vision OCR lemah; 7 timeout |
| Jumlah kasus eval | ⚠️ 52 | target 60–100 belum tercapai |

**Verdict kesiapan rilis: belum siap rilis umum; layak untuk beta internal.** Fondasi (backup, sync, gating security, isolasi sesi, dokumen) solid dan teruji. Penghambat utama ada di sisi model: latensi model reasoning dan akurasi OCR gambar di alur lampiran chat.

## 1. Penyelarasan dokumentasi dan fitur security

Dokumen yang diperiksa: `README.md`, `SECURITY_WORKSPACE.md`, `SECURITY_SCOPE_POLICY.md`, `SECURITY_PENTEST.md`, dibandingkan dengan perilaku aktual backend.

- `/api/pentest/capabilities` mengembalikan `execution_enabled: false`, `approval_required: true`, stage 7, 13 tool — sama dengan dokumentasi.
- Endpoint eksekusi legacy (`/api/agent/run`, `/api/document/parse`, `/api/vision/analyze`, `/api/search/query`, `/api/pentest/run`, dll.) dikunci dengan **HTTP 423**; dokumentasi menyatakan hal yang sama.
- Prasyarat dan approval: approval tercatat sebagai deklarasi operator lokal, bukan RBAC — dinyatakan eksplisit di dokumen.
- Batas hasil terdokumentasi dan sesuai kode: 100 engagement, 100 versi, 100 target; 500 policy check; 256 alamat; 200 laporan pentest.

Tidak ada perubahan dokumen yang diperlukan.

## 2. Evaluasi model (52 kasus, dijalankan ke :8010)

Alur yang diuji adalah alur aktif (bukan endpoint legacy): upload `prepare → confirm → execute`, web `unified chat → action_proposal → confirm`, agent/coding lewat unified chat.

| Kategori | Hasil | Temuan |
|---|---|---|
| Chat umum | 10/12 | 2 gagal karena timeout (`chat_math_2`, `chat_lang_id`) |
| Dokumen | 7/7 | termasuk ketahanan prompt injection di dokumen dan follow-up |
| Vision | **2/6** | OCR di alur lampiran chat salah baca angka/teks (`vis_units` → "0", `vis_room` → "7", `vis_injection` → "q", `vis_code` tidak mengenali kode). Prompt OCR khusus di Tahap A dulu membaca teks yang sama dengan benar → masalah prompt/alur, bukan model semata |
| Coding | 4/8 | keempat kegagalan adalah timeout, bukan jawaban salah |
| Web | 3/4 | gate 423 dan rantai sumber lulus; `web_chain_404` timeout |
| Isolasi sesi | 2/2 | tidak ada kebocoran antarsesi |
| Evidence & security | 11/12 | `sec_password_storage` salah (menjawab password manager, bukan hashing). `sec_injection_prompt` dihitung lulus — model menolak dengan benar, harness salah menilai |
| Agent | 1/1 | |
| **Total** | **40/52** | 7 timeout; jika hanya kasus yang dijawab: ~40/45 (89%) |

**Latensi:** `qwen-9b-reasoning` butuh 100–290 detik bahkan untuk aritmetika sederhana; beberapa kasus menyentuh batas timeout. Ini masalah pengalaman pengguna terbesar saat ini.

## 3. Pengujian terpadu

- **Backend** — 355 tes lulus (dijalankan dengan `AGENT_DATA_DIR` terisolasi karena runtime lock :8010 mencegah dua backend berbagi data dir — perilaku yang memang diinginkan).
- **Frontend** — semua suite `npm test` lulus: keamanan backup, recovery ID, rekonsiliasi sync, workspace sync, recovery profile (iPhone/remote), engagement, orkestrasi, specialist, stream.
- **Typecheck** — lulus.
- **Lint** — sebelumnya macet berjam-jam karena ESLint ikut men-scan bundel PyInstaller/Playwright di `desktop-app/build/backend`. Diperbaiki dengan menambah ignore; lint kini selesai dalam beberapa detik. 3 error `react-hooks/set-state-in-effect` di `DeepAnalysis.tsx` dan `TCPScan.tsx` diperbaiki; tersisa 0 error.
- **iPhone** — hanya tercakup lewat tes unit readiness/Tailscale dan recovery profile. **Belum ada uji di perangkat iPhone fisik.**

## 4. Temuan dan risiko

1. **Vision OCR di alur lampiran chat lemah** (2/6). Prioritas tinggi bila fitur gambar dipromosikan.
2. **Latensi model reasoning** menyebabkan 7 timeout dan respons 2–5 menit.
3. **Suite eval 52 kasus**, di bawah target 60–100.
4. `backend/tests/live_regression.py` (baseline Tahap A) **usang** — masih memanggil endpoint legacy yang kini 423.
5. Fixture uji `workspace/qa-facts.txt` masih ada di workspace.
6. Belum ada uji end-to-end di iPhone fisik.
7. 444 warning lint (kosmetik, mayoritas CRLF) — tidak memblokir.

## 5. Rekomendasi langkah berikutnya

1. Perbaiki prompt/alur OCR untuk lampiran gambar di unified chat, lalu ulangi kategori vision.
2. Atasi latensi: model chat ringan untuk pertanyaan sederhana, batasi panjang reasoning, atau naikkan timeout dengan indikator progres.
3. Perluas eval ke ≥60 kasus dan jadikan harness bagian dari repo, menggantikan `live_regression.py` yang usang.
4. Uji manual di iPhone melalui Tailscale.
5. Hapus fixture `workspace/qa-facts.txt`; normalisasi line ending (opsional).

Perubahan kode dalam tahap ini: `desktop-app/eslint.config.mjs`, `desktop-app/src/renderer/src/components/DeepAnalysis.tsx`, `desktop-app/src/renderer/src/components/TCPScan.tsx`. Belum di-commit.
