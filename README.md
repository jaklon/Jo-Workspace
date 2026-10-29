# Jo Workspace (Local AI Workspace & Agentic OS)

**Jo Workspace** adalah platform asisten kecerdasan buatan (*AI Agent*) berbasis *local-first* yang terintegrasi dengan ekosistem model LLM lokal via **Ollama**. Proyek ini menyediakan antarmuka modern (Web UI & Desktop Electron) serta ekstensi resmi untuk Visual Studio Code, yang berfokus pada privasi data 100%, performa inferensi lokal, pemantauan GPU secara *real-time*, dan eksekusi agen coding berbasis persetujuan (*human-in-the-loop*).

---

## Daftar Isi
- [Gambaran Umum & Arsitektur](#gambaran-umum--arsitektur)
- [Fitur Utama](#fitur-utama)
- [Prasyarat Sistem](#prasyarat-sistem)
- [Konfigurasi Lingkungan (.env)](#konfigurasi-lingkungan-env)
- [Instalasi & Persiapan](#instalasi--persiapan)
- [Cara Menjalankan](#cara-menjalankan)
  - [1. Menjalankan Web UI (Rekomendasi)](#1-menjalankan-web-ui-rekomendasi)
  - [2. Menjalankan Desktop App (Electron)](#2-menjalankan-desktop-app-electron)
  - [3. Menjalankan Ekstensi VS Code](#3-menjalankan-ekstensi-vs-code)
  - [4. Akses Jarak Jauh (iPhone/Mobile via Tailscale)](#4-akses-jarak-jauh-iphonemobile-via-tailscale)
- [Arsitektur Keamanan & Batasan](#arsitektur-keamanan--batasan)
- [Pemeriksaan Kualitas & Pengujian](#pemeriksaan-kualitas--pengujian)
- [Struktur Direktori](#struktur-direktori)

---

## Gambaran Umum & Arsitektur

Diagram alur aplikasi saat ini tersedia di [ARCHITECTURE.md](ARCHITECTURE.md).

Deep Analisis VA dan kategori WhiteBox, BlackBox, GreyBox dijelaskan dalam
[DEEP_ANALYSIS.md](DEEP_ANALYSIS.md), termasuk persyaratan evidence, scope,
RoE, persetujuan, laporan, serta status tool yang belum dapat dieksekusi.

Inferensi model, dokumen, dan data workspace diproses secara lokal melalui Ollama. Saat fitur pencarian web diaktifkan, kueri diteruskan oleh SearXNG ke mesin pencari dan URL sumber yang dipilih dihubungi untuk dibaca. Lihat [alur dan batas data](ARCHITECTURE.md).

Arsitektur terdiri dari tiga komponen utama:
1. **Backend (FastAPI & Python 3.11+)**:
   - Menangani autentikasi berbasis token dengan cookie `HttpOnly` berdurasi 12 jam.
   - Manajemen antrean inferensi (*queue lock* dan batas waktu eksekusi).
   - Streaming *Server-Sent Events* (SSE) bertipe untuk respons interaktif.
   - Ekstraksi dokumen server-side dan penelusuran (*chunk retrieval*).
   - Telemetri VRAM & GPU NVIDIA *real-time* via `pynvml`.
   - Sandbox eksekusi agen yang dibatasi ke folder `workspace`.
2. **Frontend UI (React 19, TypeScript, Tailwind CSS, Vite & Electron)**:
   - Antarmuka responsif dan modern dengan dukungan tema gelap, manajemen sesi IndexedDB lokal, rendering Markdown kaya, tampilan status GPU, dan multi-tab (Chat, Code, Vision, Dokumen, Security Pentest).
   - Dapat diakses langsung melalui browser (Web mode) atau dijalankan sebagai aplikasi desktop *native* (Electron).
3. **Ekstensi VS Code (`ai-agent-vscode`)**:
   - Memungkinkan analisis kode dan refactoring langsung dari editor VS Code dengan hasil streaming terintegrasi dan penyimpanan token aman di `SecretStorage`.

---

## Workspace desktop, Settings, Projects, dan Usage

Antarmuka menyediakan sidebar percakapan terpadu, pencarian isi chat, project opsional
dengan instruksi khusus, pin/arsip, dan ekspor percakapan. Settings memiliki sembilan
kategori dengan preferensi tersimpan, konfigurasi model/inferensi, serta kontrol data.
Usage menampilkan statistik token dan durasi aktual dari Ollama yang disimpan pada backend.

Lihat [panduan workspace desktop](WORKSPACE_GUIDE.md) untuk rincian pengaturan,
cakupan penyimpanan, cadangan, batasan, dan pintasan.

## Fitur Utama

- 🧭 **Chat-First Unified Orchestrator**: satu Chat untuk teks, lampiran, coding, web, dan pemeriksaan keamanan. LLM memilih tool, bertanya balik bila parameter kurang, lalu menampilkan kartu **Setuju & Jalankan**; Auto-RoE, job, evidence, dan Deep Analysis berjalan otomatis setelah konfirmasi (lihat [CHAT_FIRST.md](CHAT_FIRST.md)).
- 💬 **Multi-Turn Reasoning & Chat**: Percakapan berbasis LLM lokal berbobot tinggi untuk konsultasi logika kompleks dan pemecahan masalah.
- 💻 **Autonomous Coding Agent (Human-in-the-Loop)**:
  - Agen mampu membaca struktur dan berkas di dalam direktori `workspace`.
  - Agen **tidak dapat menimpa berkas secara sepihak**. Perubahan disajikan dalam format *Unified Diff proposal*.
  - Perubahan berkas baru diterapkan setelah pengguna menekan tombol **Setujui** (*hash validation* dilakukan sebelum penulisan untuk mencegah penimpaan berkas yang kedaluwarsa).
  - Eksekusi perintah shell arbitrer sepenuhnya dinonaktifkan demi keamanan sistem operasi host.
- 👁️ **Vision & Grounded Image Analysis**:
  - Menganalisis gambar, diagram arsitektur, tangkapan layar, dan OCR menggunakan model vision lokal (misal `minicpm-v:latest`).
- 📄 **Document Ingestion & Analysis**:
  - Dukungan dokumen luas: PDF, DOCX, XLSX, TXT, CSV, JSON, Markdown, Python, TypeScript, dan JavaScript.
  - Dokumen diparsing sekali dan disimpan di server runtime; pesan berikutnya mereferensikan ID lampiran dengan pencarian bagian paling relevan (*in-memory retrieval*).
- 🛡️ **Security Workspace — Tahap 7**:
  - Engagement dan RoE per Project: scope, jadwal, batas rencana, pengajuan, persetujuan lokal, pencabutan, dan revisi.
  - Penyimpanan SQLite, snapshot terkunci setelah pengajuan, riwayat versi, dan ekspor JSON.
  - [Validasi scope dan policy guard](SECURITY_SCOPE_POLICY.md) dengan pengecualian, jadwal, port, dan batas rencana.
  - [Agent spesialis](SECURITY_AGENTS.md): Recon, Web/API, Auth/BOLA, LLM Security dan Reporting dengan izin, konteks, budget terpisah dan benchmark lab sintetis.
  - [Orkestrasi satu model](SECURITY_ORCHESTRATION.md): Planner, Executor, Reviewer bergantian, checkpoint, budget, dan approval job terpisah.
  - [MCP gateway](SECURITY_MCP.md): katalog/izin terkurasi, review, handshake stdio, AppContainer tanpa jaringan, dan evidence fixture otomatis.
  - [Evidence, Findings, Reports](SECURITY_EVIDENCE.md): artefak tersensor, review analis, CVSS Base, deduplikasi, retest, dan snapshot laporan.
  - [Runs offline](SECURITY_JOBS.md): antrean persisten, review, batas waktu/output, Stop Run dan Stop Engagement.
  - Eksekusi pentest dinonaktifkan, termasuk setelah persetujuan (lihat [SECURITY_WORKSPACE.md](SECURITY_WORKSPACE.md)).
- 📱 **Akses Jarak Jauh Aman**:
  - Dukungan resmi Tailscale Serve untuk mengakses antarmuka dari iPhone/iPad/laptop lain via jaringan privat HTTPS terenkripsi tanpa membuka port router (lihat [REMOTE_ACCESS.md](REMOTE_ACCESS.md)).

---

## Prasyarat Sistem

Pastikan perangkat Anda telah memenuhi spesifikasi dan dependensi berikut:

1. **Sistem Operasi**: Windows 10/11 (disarankan dengan PowerShell), macOS, atau Linux.
2. **Python**: Versi 3.11 atau lebih baru.
3. **Node.js**: Versi 18+ atau 20+ LTS beserta `npm`.
4. **Ollama**: Terpasang dan berjalan secara lokal (`http://127.0.0.1:11434`).
   - Unduh model yang diinginkan melalui CLI Ollama:
     ```bash
     ollama pull qwen-9b-reasoning
     ollama pull qwen3.8-heretic-q4
     ollama pull minicpm-v:latest
     ```
   - *(Opsional)* Model security **WhiteRabbitNeo V3 7B** dari file GGUF lokal:
     `powershell -ExecutionPolicy Bypass -File scripts\install-whiterabbitneo.ps1` (lihat [CHAT_FIRST.md](CHAT_FIRST.md#model-per-tugas)).
5. **Security Workspace tahap 7** tidak memerlukan Nmap; seluruh eksekusi pentest dinonaktifkan.
6. *(Opsional)* **Tailscale**: Jika ingin mengakses Web UI dari perangkat lain melalui jaringan privat.

---

## Konfigurasi Lingkungan (.env)

Salin berkas contoh atau buat variabel lingkungan proses sebelum menjalankan aplikasi:

```powershell
# Contoh konfigurasi di PowerShell
$env:OLLAMA_URL="http://127.0.0.1:11434"
$env:REASONING_MODEL="qwen-9b-reasoning"
$env:CODING_MODEL="qwen-9b-reasoning"
$env:SECURITY_MODEL="qwen3.8-heretic-q4"
$env:VISION_MODEL="minicpm-v:latest"
$env:CONTEXT_TOKENS="4096"
$env:OUTPUT_TOKENS="768"
$env:MODEL_TIMEOUT="120"
$env:QUEUE_TIMEOUT="30"
```

Daftar variabel yang dapat dikonfigurasi:
| Variabel | Default | Keterangan |
| :--- | :--- | :--- |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Alamat instans server Ollama lokal. |
| `REASONING_MODEL` | `qwen-9b-reasoning` | Model untuk tab Chat umum & penalaran. |
| `CODING_MODEL` | `qwen-9b-reasoning` | Model untuk agen coding dan pembuatan diff. |
| `SECURITY_MODEL` | `qwen3.8-heretic-q4` | Model untuk analisis lab keamanan & pentest. |
| `VISION_MODEL` | `minicpm-v:latest` | Model multimodal untuk inspeksi visual. |
| `AGENT_WORKSPACE` | `./workspace` | Direktori kerja yang boleh dibaca/ditulis oleh agen. |
| `AGENT_DATA_DIR` | `./data/runtime` | Direktori penyimpanan berkas runtime, token, dan lampiran. |
| `AGENT_API_TOKEN` | *Otomatis digenerate* | Token akses statis (minimal 24 karakter acak). Jika tidak diset, token acak dibuat di `data/runtime/api-token`. |
| `AGENT_ALLOWED_ORIGINS` | `http://localhost:5173,...` | Daftar origin CORS yang diizinkan (tanpa wildcard `*`). |

> [!IMPORTANT]
> Jangan pernah melakukan *commit* token, data folder `data/runtime`, lampiran dokumen, atau berkas pribadi di dalam `workspace/` ke repository Git.

---

## Instalasi & Persiapan

### 1. Setup Backend (Python Virtual Environment)

Buka PowerShell di direktori *root* proyek:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
```

### 2. Setup Frontend & Desktop App (Node Dependencies)

Pasang paket dependensi untuk aplikasi desktop/web:

```powershell
cd desktop-app
npm install
cd ..
```

---

## Cara Menjalankan

### 1. Menjalankan Web UI

Cara yang disarankan untuk pemakaian sehari-hari adalah installer Windows
(`desktop-app/dist/Jo-Workspace-<versi>-Windows-x64-Setup.exe`, lihat
[WINDOWS_INSTALLER.md](WINDOWS_INSTALLER.md)). Untuk menjalankan Web UI langsung
dari source:

1. Bangun aset web frontend (lewati jika tidak ada perubahan kode frontend):
   ```powershell
   cd desktop-app
   npm run build
   cd ..
   ```
2. Jalankan backend FastAPI; backend otomatis menyajikan `desktop-app/out/renderer`:
   ```powershell
   cd backend
   .\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8010
   ```
   Ganti `--port` untuk memakai port lain.

**Langkah Masuk (Login):**
1. Buka browser di `http://127.0.0.1:8010`.
2. Saat pertama kali dijalankan, salin token akses dari berkas:
   ```
   data\runtime\api-token
   ```
3. Tempelkan token tersebut pada dialog koneksi di antarmuka web.
4. Token akan divalidasi dan disimpan dalam bentuk cookie `HttpOnly` yang aman selama 12 jam.

---

### 2. Menjalankan Desktop App (Electron)

Jika Anda ingin menjalankan atau mengembangkan Jo Workspace sebagai aplikasi desktop berbasis Electron:

1. **Jalankan Backend terlebih dahulu**:
   ```powershell
   cd backend
   .\venv\Scripts\Activate.ps1
   python -m uvicorn main:app --host 127.0.0.1 --port 8010
   ```
2. **Jalankan Electron Desktop App (Mode Pengembang)**:
   ```powershell
   cd desktop-app
   npm run dev
   ```
3. **Membuat Paket Installer / Binary Windows (Build)**:
   ```powershell
   cd desktop-app
   npm run build:win
   ```
   Hasil installer akan tersedia di direktori `desktop-app/dist`.

---

### 3. Menjalankan Ekstensi VS Code

Untuk mengintegrasikan model Jo Workspace langsung ke dalam alur kerja editor Visual Studio Code:

1. Pastikan backend Jo Workspace sedang berjalan pada `http://127.0.0.1:8010`.
2. Masuk ke folder ekstensi dan compile berkas sumber:
   ```powershell
   cd ai-agent-vscode
   npm install
   npm run compile
   ```
3. Buka folder `ai-agent-vscode` di VS Code, lalu tekan `F5` untuk menjalankan jendela *Extension Development Host*.
4. Pada jendela baru:
   - Buka Command Palette (`Ctrl+Shift+P`).
   - Jalankan perintah **Jo Workspace: Set API Token**, lalu masukkan token dari `data\runtime\api-token`.
   - Sorot (*highlight*) potongan kode yang ingin diperiksa, lalu pilih perintah **Jo Workspace: Review Selection**.

---

### 4. Akses Jarak Jauh (iPhone/Mobile via Tailscale)

Anda dapat mengakses antarmuka Web UI dari perangkat seluler (seperti iPhone atau Android) tanpa perlu mengekspos port ke internet publik:

1. Pastikan Tailscale telah terpasang dan aktif di komputer host serta perangkat mobile Anda.
2. Jalankan Web UI di laptop/PC pada port 8010 (lihat bagian 1 di atas).
3. Di jendela PowerShell terpisah, aktifkan penerusan Tailscale Serve:
   ```powershell
   .\enable-tailscale-serve.ps1
   ```
4. Buka URL HTTPS privat `.ts.net` yang ditampilkan di browser mobile Anda (misal Safari).
5. Masukkan token dari `data/runtime/api-token` untuk memulai sesi.
6. Untuk panduan lengkap, lihat [REMOTE_ACCESS.md](REMOTE_ACCESS.md).

---

## Arsitektur Keamanan & Batasan

- **Isolasi Workspace**: Semua interaksi pembacaan dan pembuatan berkas oleh agen dibatasi secara ketat di dalam path direktori `AGENT_WORKSPACE` (`./workspace`). Akses ke luar workspace dicegah.
- **Persetujuan Intervensi Manusia (*Human-in-the-Loop*)**: Agen hanya membuat proposal *diff*. Perubahan tidak pernah langsung ditulis ke disk tanpa persetujuan eksplisit pengguna.
- **Perlindungan Overwrite**: Validasi SHA-256 berkas awal diperiksa kembali saat pengguna menyetujui perubahan untuk mencegah konflik pengeditan bersamaan.
- **Anti-Arbitrary Execution**: Eksekusi perintah sistem/shell acak oleh model dinonaktifkan.
- **Batasan Security Workspace**: Tahap 7 menambahkan lima spesialis dengan batas izin dan budget pada lab sintetis, melengkapi orkestrasi satu model lokal pada Engagement/RoE, MCP fixture terisolasi, evidence, findings, dan laporan. Endpoint eksekusi pentest dinonaktifkan; persetujuan lokal hanya mengantrekan validasi policy atau fixture MCP terisolasi yang diizinkan.
- **Otentikasi & Cookie Ketat**: Token dibandingkan menggunakan `hmac.compare_digest` untuk mencegah serangan *timing attack*, dan sesi browser dilindungi cookie `HttpOnly`, `SameSite=Strict`.

---

## Pemeriksaan Kualitas & Pengujian

Sebelum merilis perubahan kode, pastikan semua rangkaian pengujian lulus validasi:

```powershell
# 1. Unit Test Backend
backend\venv\Scripts\python.exe -m unittest discover -s backend\tests -v

# 2. Typecheck, Linting & Uji Aliran Stream Frontend
cd desktop-app
npm run typecheck
npm run lint
npm test
npm run build
cd ..

# 3. Kompilasi Ekstensi VS Code
cd ai-agent-vscode
npm run compile
cd ..
```

**Pengujian Regresi Model Nyata (Live Regression):**
Untuk menguji model lokal secara langsung dengan backend aktif di port tertentu:
```powershell
$env:AGENT_TEST_URL = "http://127.0.0.1:8010"
$env:AGENT_API_TOKEN = (Get-Content data\runtime\api-token -Raw).Trim()
backend\venv\Scripts\python.exe backend\tests\live_regression.py
```
*(Opsional: set `$env:LIVE_CASE="vision_compare"` untuk mengevaluasi modul perbandingan latensi vision secara spesifik).*

---

## Struktur Direktori

Security Workspace tahap 7 tersedia di dalam Project untuk Engagement dan RoE.
Lihat [panduan Security Workspace](SECURITY_WORKSPACE.md). Seluruh eksekusi
pentest melalui API dinonaktifkan pada tahap ini, termasuk setelah persetujuan.

```plaintext
ai-agent-workspace/
├── backend/                  # Server FastAPI, perutean model, dan logika agen
│   ├── tests/                # Unit test dan evaluasi live model
│   ├── agent.py              # Siklus kerja agen coding (diff generation)
│   ├── config.py             # Konfigurasi aplikasi dan variabel lingkungan
│   ├── doc_engine.py         # Ekstraktor dokumen (PDF, DOCX, XLSX, TXT, dll.)
│   ├── main.py               # Endpoint API, SSE stream, dan penyedia static web
│   ├── model_runtime.py      # Integrasi runtime Ollama & streaming handler
│   ├── pentest.py            # Runner lab keamanan & discovery probe
│   ├── requirements.txt      # Dependensi Python
│   ├── security.py           # Validasi token, otentikasi cookie, & boundary
│   ├── store.py              # Penyimpanan state runtime & proposal file
│   └── tools.py              # Utilitas pembacaan workspace & parser diff
├── desktop-app/              # Antarmuka React 19 + Electron + Tailwind CSS
│   ├── src/
│   │   ├── main/             # Proses utama Electron
│   │   ├── preload/          # Skrip preload IPC Electron
│   │   └── renderer/         # Komponen React (Chat, Code, Vision, Pentest, dll.)
│   └── package.json          # Konfigurasi skrip & dependensi npm
├── ai-agent-vscode/          # Ekstensi resmi untuk Visual Studio Code
├── data/runtime/             # Direktori data sementara, token, dan lampiran (diabaikan Git)
├── workspace/                # Direktori kerja aman yang dikelola agen
├── scripts/                  # Skrip pembantu verifikasi stream SSE
├── enable-tailscale-serve.ps1# Skrip konfigurasi akses jarak jauh Tailscale
├── REMOTE_ACCESS.md          # Panduan akses jarak jauh dari perangkat seluler
└── SECURITY_PENTEST.md       # Panduan detail pengujian lab keamanan
```


## Desktop lokal gratis

[Jo Workspace Local 1.7.1](LOCAL_DESKTOP.md) membuka tahap 7 dari ikon Desktop,
dengan backend dan login otomatis menggunakan Python/Chrome yang sudah
terpasang. Uninstall meminta konfirmasi; eksekusi pentest tetap terkunci.


Tahap 7: [panduan Agents, izin, budget dan benchmark lab sintetis](SECURITY_AGENTS.md). Pentest tetap terkunci.
