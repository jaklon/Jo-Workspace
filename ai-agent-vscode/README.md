# Jo Workspace untuk VS Code

Ekstensi ini mengirim seleksi aktif ke pipeline coding Jo Workspace dan menampilkan
hasil streaming di panel output.

## Pemakaian

1. Jalankan backend Jo Workspace.
2. Atur `agentOS.apiBaseUrl` bila backend tidak memakai
   `http://127.0.0.1:8010`.
3. Jalankan perintah **Jo Workspace: Set API Token**. Token disimpan di
   `SecretStorage` VS Code.
4. Pilih kode lalu jalankan **Jo Workspace: Review Selection**.

Perintah dapat dibatalkan dari progress notification. Ekstensi memvalidasi
content-type SSE, status HTTP, error event, UTF-8 multi-byte, dan timeout.

Untuk pengembangan:

```powershell
npm install
npm run compile
```
