"""Versioned local playbooks. Content is data supplied to one model, never executable code."""
import hashlib
import json

PLAYBOOKS=[
    {'id':'fixture-header-review','version':'1.0.0','title':'Review header fixture sintetis',
     'instructions':'Compare headers_missing with headers_present using fixture.compare. Explain differences and uncertainty. These are bundled fixtures, not responses from a real target. Never claim a confirmed vulnerability.',
     'allowed_fixtures':['headers_missing','headers_present'],
     'sources':[{'title':'Agent OS reviewed MCP fixture','ref':'repo:backend/mcp_fixture_server.py','version':'1.0.0'},
                {'title':'OWASP Secure Headers Project','ref':'https://owasp.org/www-project-secure-headers/','version':'reference-only; no live retrieval'}]},
    {'id':'fixture-config-review','version':'1.0.0','title':'Review konfigurasi fixture sintetis',
     'instructions':'Inspect config_insecure or config_hardened using fixture.inspect, or compare these fixtures using fixture.compare if permitted. Report debug configuration only as a synthetic observation; leave findings and severity to a human.',
     'allowed_fixtures':['config_insecure','config_hardened'],
     'sources':[{'title':'Agent OS reviewed MCP fixture','ref':'repo:backend/mcp_fixture_server.py','version':'1.0.0'}]},
]


def playbooks():
    return [{**p,'hash':hashlib.sha256(json.dumps(p,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()} for p in PLAYBOOKS]


def playbook(identity):
    return next((p for p in playbooks() if p['id']==identity),None)
