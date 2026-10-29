# Security Workspace tahap 5 — MCP gateway dan runner terisolasi

Jo Workspace Local 1.5.0 menyediakan gateway MCP lokal untuk **fixture sintetis**.
Seluruh pentest tetap dinonaktifkan; `POST /api/pentest/run` tetap 423. Tidak ada
layanan cloud/signing berbayar atau perubahan Defender/Application Control.

## Cakupan yang dapat digunakan

**Project → Security Workspace · Tahap 5 → Engagement → MCP Integrations**.
Profil katalog berlaku global pada workspace lokal; setiap job tetap terikat
Project/Engagement/RoE dan approval sendiri. Nama reviewer adalah deklarasi
operator lokal, bukan identitas terverifikasi atau pemisahan tugas multiuser.

Adapter terkurasi `bundled_fixture`, server `agentos-fixture` versi 1.0.0,
menawarkan `fixture.inspect` dan `fixture.compare`. Input hanya memilih fixture
`headers_missing`, `headers_present`, `config_insecure`, `config_hardened`.
Tidak ada parameter command, URL server, target jaringan, file path, environment,
atau kredensial eksternal. Profile baru dimulai Draft dengan izin tool eksplisit.

Gateway memakai JSON-RPC stdio dan mempin protokol **2025-11-25**:
`initialize → notifications/initialized → tools/list → tools/call`. Handshake
versi/capability, nama/versi server, schema, dan hasil diverifikasi terhadap
descriptor serta hash source adapter. Tidak ada instalasi SDK dari jaringan.
Referensi: [lifecycle MCP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/lifecycle.mdx).

Server MCP pihak ketiga, Streamable HTTP, OAuth/API key eksternal, container/VM
jarak jauh, dan tool pentest belum diaktifkan. Pembatasan ini mengikuti permintaan
untuk mempertahankan kunci pentest. Mode autentikasi yang tersedia adalah
**managed local stdio**: backend membuat proses dan handle transport sendiri;
API gateway tetap memakai sesi/token Jo Workspace yang sudah ada. Token API itu
tidak diteruskan ke proses fixture.

## Alur UI dan kontrol

1. Tambah profil, pilih izin per tool, dan tetapkan batas waktu/output.
2. Tinjau descriptor/schema, versi, hash, izin dan batas; isi deklarasi/note/ack.
   Server yang masih Draft/Disabled tidak dapat diperiksa atau dipanggil.
3. **Periksa koneksi MCP** menjalankan initialize/tools/list di AppContainer.
   Tidak ada tools/call, model, atau request target pada pemeriksaan ini.
4. Buat rencana job fixture: target scope dan RoE tetap diwajibkan, tetapi target
   tidak dikirim ke subprocess. Tindakan hanya `configuration_review` offline.
   Job masuk Awaiting Approval; buka **Runs** untuk review kedua.
5. Review job menampilkan server/revisi, tool, argumen, hash schema, scope dan
   batas. Seluruh binding ini termasuk dalam hash rencana yang immutable.
6. Worker melewati policy/RoE terkini sebelum runner dan sebelum setiap pesan.
   Setelah fixture selesai dan proses ditutup, evidence disimpan otomatis;
   hasil MCP diberi label output tool tidak dipercaya sebagai instruksi.
7. **Stop Run**, **Stop Engagement**, perubahan profil atau penonaktifan server
   membatalkan pekerjaan terkait. Edit profil mencabut approval dan memerlukan
   review ulang; perubahan adapter/schema/versi memerlukan profil baru.

Approval tidak berlaku untuk parameter/revisi lain. Salah schema, server/tool
tanpa izin, scope ditolak, jadwal/RoE dicabut/kedaluwarsa, kegagalan isolasi,
output berlebih, atau kegagalan menyimpan evidence tidak menghasilkan Completed.
Tidak ada retry otomatis atau fallback proses tanpa sandbox. Setelah restart,
Queued membutuhkan approval ulang, Running menjadi Interrupted/Failed, hasil
sebelumnya tetap tersedia. Retry manual mempertahankan binding MCP; jika profil
berubah, buat rencana baru dengan revisi terkini.

## Isolasi Windows

Runner memakai [Windows AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
tanpa capability jaringan. Identitas profil dibedakan menurut direktori runtime
Jo Workspace sehingga QA dan desktop tidak mendapat akses silang melalui SID yang sama.
Runtime Python disalin dari instalasi lokal yang sudah ada; binary tetap memakai
tanda tangan vendor. Library standar dikemas lokal, tanpa site-packages, user
site atau PYTHONPATH. Tidak ada download Python, Docker, VM, atau layanan baru.

- Proses mendapat akses baca/eksekusi hanya ke salinan runtime dan fixture;
  folder kerja sementara per proses dapat ditulis. ACL dan label integrity
  hanya diterapkan pada folder sandbox tersebut, bukan workspace pribadi.
- Token AppContainer diverifikasi backend sebelum thread dimulai. Tidak ada
  privilege/capability jaringan, mount workspace, token aplikasi atau Docker socket.
- Hanya tiga handle stdin/stdout/stderr yang diwariskan secara eksplisit.
  Environment berupa allowlist SystemRoot/windir, LOCALAPPDATA untuk startup
  profil Windows, dan TEMP/TMP folder kerja. Mengetahui path LOCALAPPDATA tidak
  memberi hak membaca file pribadi di dalamnya; AppContainer tetap membatasi ACL.
- Job Object membatasi satu proses aktif, memori 256 MiB, CPU 3 detik, serta
  kill-on-job-close. Waktu wall maksimum 15 detik termasuk persiapan pada job;
  output/stdout/stderr dibatasi maksimum 64 KiB termasuk anggaran policy job.
- Stop/cancel/timeout/shutdown menutup Job Object dan proses. Jika backend crash,
  handle OS ditutup dan child ikut dihentikan. Direktori kerja yatim dibersihkan
  pada persiapan berikutnya setelah PID pemiliknya sudah tidak hidup.
- Satu lease runner SQLite membatasi proses fixture/check aktif menjadi satu.
  Isolasi yang tidak tersedia atau integritas runtime tidak cocok menolak proses.

Ini pembatasan proses Windows, bukan VM atau jaminan melawan administrator/kernel
yang telah dikuasai. Direktori sistem/profil khusus yang secara normal tersedia
bagi AppContainer tetap dikelola Windows. Jangan menganggap output MCP tepercaya
atau memberikan akses tambahan secara manual pada profil sandbox.

## Evidence dan persistence

Hasil fixture dicatat sebagai `synthetic_fixture` dengan provenance
`server_mcp_fixture`, `tool_executed_by_agent_os=true`, `pentest_executed=false`.
Metadata mencatat binding/hash rencana dan adapter, keputusan policy, identitas
run, serta pemeriksaan token/isolasi. Hasil structured JSON tersedia di Runs;
evidence lengkap/tersensor dan arsip asli DPAPI mengikuti tahap 4. Tidak ada AI
yang dipanggil atau finding yang otomatis menjadi Validated.

Pencatatan hasil, evidence, dan status Completed berada dalam satu transaksi.
Kegagalan evidence membatalkan transaksi keberhasilan. Tabel aditif pada
`engagements.sqlite3`: `mcp_servers`, `mcp_server_events`,
`mcp_connection_checks`, `mcp_job_results`, `mcp_runner_lease`.

Batas: 20 profil, 100 revisi profil, 100 connection check per profil (UI menampilkan
20 terakhir); batas job/evidence tahap 3–4 tetap berlaku. Runtime sandbox berada
di `AGENT_DATA_DIR/mcp-sandbox`; database/arsip tetap berada pada data lokal.

## API

Seluruh endpoint terautentikasi dan schema ketat; error schema baru tidak
mengembalikan input yang mungkin berisi rahasia.

| Metode | Path | Fungsi |
| --- | --- | --- |
| GET / POST | `/api/security/mcp/servers` | Katalog/profil atau Draft baru |
| GET / PUT | `/api/security/mcp/servers/{id}` | Detail/riwayat atau edit CAS |
| POST | `/api/security/mcp/servers/{id}/decisions` | Approve/disable dengan review |
| POST | `/api/security/mcp/servers/{id}/check` | Handshake terisolasi, tanpa tools/call |

Pembuatan/review/stop MCP job memakai API `/jobs` yang sudah ada pada Engagement.
`plan.mcp` mengikat server/revisi/hash/tool/argumen; tidak ada endpoint bypass
yang langsung menjalankan tool. Data lama tanpa binding tetap hanya validasi policy.

## Pengujian

`backend/tests/test_mcp_gateway.py` mencakup schema/auth, profil Draft/Disabled,
izin tool, scope/RoE, review/revisi, perubahan profil saat berjalan, pembatalan,
output, kegagalan evidence, runtime/protokol tidak cocok, lease dan persistence.
Uji AppContainer nyata membuktikan penolakan berkas canary privat, write runtime,
koneksi loopback sintetis, proses turunan, dan pewarisan token; write folder kerja
tetap diizinkan. Tes crash induk membuktikan child tidak tertinggal.

Fixture, log, screenshot dan hasil verifikasi lokal: `output/security-stage5/`
(diabaikan Git). Tahap 6 orkestrasi model dan tahap 7 multi-agent belum diaktifkan.

Verifikasi akhir 28 Oktober 2026: **145 tes backend** (21 tes MCP baru),
**57 assertion frontend**, lint, typecheck, dan build lulus. UI profil/review,
handshake, job fixture.compare hingga Completed, binding approval, serta
evidence otomatis diverifikasi sebelum kontrol browser dinonaktifkan pada
pengaturan Work. Uji penonaktifan, persistensi restart, shortcut desktop 1.5.0,
dan handshake AppContainer runtime desktop diselesaikan lewat API/CLI lokal.
Pemeriksaan UI desktop setelah update tidak tersedia pada saat itu.

```text
backend\venv\Scripts\python.exe -m unittest discover -s backend/tests -v
cd desktop-app
npm test
npm run lint
npm run build
```
