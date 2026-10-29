"""Bounded read-only snapshots from the bundled loopback monitoring stack."""
import asyncio
import json
import httpx


async def snapshot(guard):
    async def get(path):
        await guard()
        async with httpx.AsyncClient(timeout=5, trust_env=False, follow_redirects=False) as client:
            async with client.stream('GET', path) as response:
                if response.status_code != 200:
                    raise ValueError('Monitoring service not ready')
                parts=[]; size=0
                async for part in response.aiter_bytes():
                    size+=len(part)
                    if size>32768:raise ValueError('Monitoring response limit')
                    parts.append(part)
        await asyncio.sleep(1)
        return b''.join(parts)
    await get('http://127.0.0.1:9090/-/ready')
    query=json.loads(await get('http://127.0.0.1:9090/api/v1/query?query=up'))
    if query.get('status')!='success':raise ValueError('Monitoring query failed')
    services=[]
    for row in query.get('data',{}).get('result',[])[:20]:
        job=row.get('metric',{}).get('job')
        if job in ('prometheus','grafana'):
            value=row.get('value',[0,'0'])[1]
            if value not in ('0','1'):raise ValueError('Unexpected up metric')
            services.append({'service':job,'up':value=='1'})
    health=json.loads(await get('http://127.0.0.1:3000/api/health'))
    return {'tool':'monitoring-local','target':'127.0.0.1','services':services,
            'grafana_database_ok':health.get('database')=='ok',
            'limitation':'Snapshot monitoring layanan lokal; bukan monitoring serangan URL, login, atau DDoS.'}
