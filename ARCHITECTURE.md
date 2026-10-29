# Arsitektur Jo Workspace 1.14.0

Diagram ini menunjukkan komponen yang benar-benar dipakai aplikasi pada laptop Windows. Electron membundel UI dan backend; mode lokal berbasis sumber memakai Chrome dan backend Python dari folder proyek. Keduanya menyimpan data di lokasi berbeda.

```mermaid
flowchart LR
    U[Pengguna] --> D[Jo Workspace Desktop<br/>Electron + React]
    U --> W[Jo Workspace Local<br/>Chrome + React]
    D --> A[FastAPI lokal<br/>token / sesi / SSE]
    W --> A2[FastAPI lokal<br/>token / sesi / SSE]
    A --> C[Chat, Code, Vision, Dokumen]
    A2 --> C
    A --> S[Security Workspace]
    A2 --> S
    C --> O[Ollama lokal<br/>model LLM]
    C --> Q[Search dan pembacaan web]
    Q --> X[SearXNG di Docker<br/>hasil web dan gambar]
    Q --> H[GET HTTPS terbatasi<br/>HTML publik]
    H --> P[Playwright + Chrome/Edge<br/>URL eksplisit yang perlu JavaScript]
    H --> T[Scrapling<br/>teks dan gambar]
    P --> T
    T --> C
    S --> R[Engagement dan RoE<br/>scope, jadwal, izin]
    R --> G[Policy guard dan approval]
    G --> J[Runs dan MCP fixture<br/>AppContainer tanpa jaringan]
    G --> TCP[TCP Scan disetujui<br/>1 IP, port eksplisit, stop dan timeout]
    TCP --> E
    G --> TOOLS[Tools disetujui per job<br/>hash binary/image, timeout, stop]
    TOOLS --> NZ[Nuclei HEAD / ZAP passive<br/>domain dengan DNS terikat]
    TOOLS --> RECON[Subfinder / Amass profil khusus<br/>crt.sh saja, domain disetujui]
    TOOLS --> MON[Snapshot monitoring lokal<br/>Prometheus + Grafana di Docker]
    NZ --> E
    RECON --> E
    MON --> E
    G --> M[Orkestrasi dan agent spesialis<br/>satu model Ollama bergantian]
    J --> E[Evidence, Findings, Reports]
    M --> E
    E --> VA[Deep Analisis VA<br/>WhiteBox / BlackBox / GreyBox]
    VA --> O
    VA --> C
    A --> DB[(SQLite + file runtime<br/>AppData Electron)]
    A2 --> DB2[(SQLite + file runtime<br/>folder proyek)]
    S --> DB
    S --> DB2
```

## Alur chat dengan URL

```mermaid
flowchart TD
    A[Prompt di Chat] --> B{Butuh web?}
    B -- Tidak --> L[Ollama menjawab langsung]
    B -- Ya --> C{URL eksplisit?}
    C -- Tidak --> D[SearXNG lokal mengambil hasil dan cuplikan]
    C -- Ya --> E[Validasi HTTPS publik + DNS]
    D --> F[Ambil hingga 3 halaman bila cuplikan kurang]
    E --> F
    F --> G{HTML berisi teks?}
    G -- Ya --> H[Scrapling ekstrak teks/gambar]
    G -- Shell JavaScript --> I[Playwright render sekali<br/>Chrome/Edge, host sama, GET terbatasi]
    I --> H
    I -- Gagal --> K[Metadata atau cuplikan diberi label]
    H --> N[Konteks dibatasi sesuai anggaran model]
    K --> N
    D --> N
    N --> O[Ollama menyusun jawaban + sitasi]
    O --> P[UI menampilkan sumber dan galeri gambar]
    L --> P
```

Perenderan JavaScript hanya dicoba untuk URL HTTPS eksplisit dengan HTML awal berupa shell aplikasi. Browser memakai konteks sementara tanpa login, cookie lama, download, POST, redirect, atau akses subresource ke host lain. Proses ini tidak memecahkan CAPTCHA atau challenge Cloudflare. Jika gagal, jawaban tetap membedakan metadata dari isi halaman yang benar-benar dibaca. Pencarian web dan gambar mengirim kueri ke SearXNG, yang meneruskannya ke mesin pencari; pembacaan URL menghubungi situs tujuan. Inferensi LLM tetap melalui Ollama lokal.

## Batas Security Workspace

Engagement dan RoE disimpan per Project. Sebelum Runs yang diizinkan, backend memeriksa versi RoE, scope, pengecualian, waktu, tindakan, port, anggaran, dan persetujuan manusia. URL check production hanya melakukan satu HEAD yang disetujui. Tab Tools & monitoring menjalankan profil terbatas Nuclei HEAD, ZAP passive dari HAR tanpa jaringan, Subfinder/Amass crt.sh-only, dan pembacaan kesehatan Prometheus/Grafana lokal. Binary/image terikat rencana; perubahan scope atau RoE diperiksa kembali selama run. Domain recon dikirim ke crt.sh hanya setelah persetujuan pengungkapan. Penemuan subdomain tidak memperluas scope otomatis.

MCP dan agent spesialis bekerja pada fixture lab sintetis; seluruh hasil harus direview sebelum menjadi finding atau laporan. Endpoint pentest menerima ID job yang disetujui, sedangkan target bebas legacy tetap ditolak (`HTTP 423`). Evidence adapter tersimpan dan dapat dibaca Deep Analisis dengan model Ollama serta ditampilkan dalam Chat Project. Pencarian dan pembacaan halaman di Chat adalah alur terpisah dari Runs keamanan. Lihat [profil dan batas integrasi](TOOL_INTEGRATIONS.md).

## Penyimpanan dan operasi

- Electron terpasang: `%APPDATA%\Agent OS` untuk data runtime dan workspace; executable berada di `%LOCALAPPDATA%\Programs\Jo Workspace`.
- Mode lokal berbasis sumber: `data/runtime` di folder proyek dan shortcut Chrome; riwayat UI mengikuti profil browser yang dipakai.
- `engagements.sqlite3` menyimpan RoE, policy, job, evidence, dan checkpoint. `agent.sqlite3` menyimpan lampiran dan proposal. Usage dan preferensi disimpan di runtime masing-masing.
- SearXNG berjalan di Docker Desktop pada `127.0.0.1:8080`. Chrome atau Edge diperlukan untuk render JavaScript; Playwright memakai browser yang sudah terpasang.
- Monitoring gratis memakai Prometheus `127.0.0.1:9090` dan Grafana `127.0.0.1:3000`, melalui gateway Docker yang hanya dipublikasikan ke loopback. Data ada pada named volume Docker. Dashboard mengukur kesehatan layanan lokal; belum menjadi deteksi login gagal, abuse API, atau DDoS. Lihat [panduan monitoring](deploy/monitoring/README.md).
