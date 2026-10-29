"""Prepare a local Grafana secret; never print its value."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1] / 'deploy' / 'monitoring' / 'runtime'
root.mkdir(parents=True, exist_ok=True)
target = root / 'grafana-admin-password'
if not target.exists():
    with target.open('x', encoding='utf-8') as file:
        file.write(secrets.token_urlsafe(32))
print('Monitoring secret ready. Password file:', target)
