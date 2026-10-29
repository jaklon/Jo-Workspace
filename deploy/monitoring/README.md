# Monitoring lokal gratis

Stack ini memakai Prometheus dan Grafana OSS. Ia memantau kesehatan layanannya
sendiri; belum mengumpulkan failed-login, API abuse, DDoS atau log aplikasi Anda.

1. Nyalakan Docker Desktop.
2. Dari folder proyek jalankan `backend/venv/Scripts/python.exe scripts/prepare_monitoring.py`.
3. Jalankan `docker compose -f deploy/monitoring/docker-compose.yml up -d`.
4. Dashboard viewer: http://127.0.0.1:3000/d/jo-health
5. Prometheus: http://127.0.0.1:9090

Port hanya terikat loopback. Prometheus dan Grafana berada di jaringan internal;
gateway lokal meneruskan akses browser. Admin Grafana bernama `admin` dengan
password acak pada `runtime/grafana-admin-password`. Jangan kirim nilainya ke chat.
Konfigurasi datasource dan dashboard disediakan otomatis. Metrik disimpan 7 hari.

Dalam Jo Workspace buat RoE lingkungan **lab**, IP `127.0.0.1`, port `3000,9090`,
tindakan `monitoring_read`, concurrency/RPS 1 dan jadwal aktif. Pada **Tools &
monitoring**, pilih **Monitoring lokal**, siapkan rencana, lalu setujui run.
Snapshot dan evidence tersimpan. Deep Analisis dapat meninjau hasilnya. Chat
Project dapat membaca laporan dengan `Deep analisis ip:127.0.0.1` setelah analisis dibuat.

`docker compose -f deploy/monitoring/docker-compose.yml stop` menghentikan stack
tanpa menghapus data. Menutup Jo Workspace tidak menghentikan Docker bersama.
