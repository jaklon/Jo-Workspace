"""Generate a local-only SearXNG secret outside tracked source."""
from pathlib import Path
import secrets

root=Path(__file__).resolve().parents[1]
settings=root/'deploy/searxng/runtime/settings.yml'
settings.parent.mkdir(parents=True,exist_ok=True)
if not settings.exists():
    settings.write_text('use_default_settings: true\nserver:\n  secret_key: "'+secrets.token_urlsafe(48)+'"\n  limiter: false\nsearch:\n  formats:\n    - html\n    - json\n',encoding='utf-8')
print('SearXNG local settings ready:',settings)
