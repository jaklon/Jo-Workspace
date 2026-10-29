# Jo Workspace desktop

Klien React/Electron untuk backend FastAPI Jo Workspace. Secara default Electron
menghubungi `http://127.0.0.1:8010`; mode development memakai proxy Vite ke URL
yang sama.

```powershell
npm install
npm run dev
```

Jalankan backend dari root project lebih dahulu. Masukkan token API ketika dialog
koneksi muncul. Untuk validasi sebelum packaging:

```powershell
npm run typecheck
npm run lint
npm test
npm run build
```

Build produksi: `npm run build:win`, `npm run build:mac`, atau
`npm run build:linux`. Renderer berjalan dengan context isolation dan sandbox;
Node integration tidak tersedia di halaman web.
