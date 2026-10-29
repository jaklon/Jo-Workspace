"""Exercise installed engines with local fixtures and optional reserved-domain OSINT."""
import argparse
import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from nuclei_adapter import binary_hash as nuclei_hash
from zap_adapter import image_hash, inspect_headers
from subfinder_adapter import fingerprint, amass_fingerprint
from bounded_scan import validate_scan, run_scan
from local_monitoring import snapshot

parser=argparse.ArgumentParser()
parser.add_argument('--include-passive-sources',action='store_true')
args=parser.parse_args()


async def guard():pass


async def main():
    results=[]
    requests=[]
    async def handler(reader,writer):
        try:
            data=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
            requests.append(data.split(b'\r\n')[0].decode())
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
        finally:writer.close()
    server=await asyncio.start_server(handler,'127.0.0.1',0)
    try:
        port=server.sockets[0].getsockname()[1]
        plan={'scan':{'tool':'nuclei-head','binary_sha256':nuclei_hash()},'wall_timeout_seconds':60,
              'steps':[{'target':{'kind':'url','value':f'http://127.0.0.1:{port}/'},'action':'http_headers','ports':[port],
                        'max_concurrency':1,'max_http_rps':1,'max_duration_minutes':1}]}
        validate_scan(plan)
        row=await asyncio.wait_for(run_scan(plan,guard),60)
        assert row['csp_observation']=='missing_header_candidate'
        assert requests==['HEAD / HTTP/1.1'],requests
        results.append({'tool':'nuclei-head','fixture_head_count':len(requests),'status':'passed'})
        zap_plan={**plan,'scan':{'tool':'zap-head','binary_sha256':image_hash()},'wall_timeout_seconds':180,
                  'steps':[{**plan['steps'][0],'max_duration_minutes':3}]}
        validate_scan(zap_plan)
        zap=await asyncio.wait_for(run_scan(zap_plan,guard),180)
        assert requests==['HEAD / HTTP/1.1','HEAD / HTTP/1.1'],requests
        assert zap['passive']['network']=='none' and zap['passive']['requests_replayed'] is False
        assert zap['passive']['alerts'],zap
        results.append({'tool':'zap-head','status':'passed','fixture_head_count':1,'passive_alerts':len(zap['passive']['alerts']),'network':'none'})
    finally:
        server.close()
        await server.wait_closed()
    monitor=await snapshot(guard)
    assert monitor['grafana_database_ok'] and len(monitor['services'])==2
    assert all(service['up'] for service in monitor['services'])
    results.append({'tool':'monitoring-local','status':'passed','services':monitor['services']})
    if args.include_passive_sources:
        for tool,identity,duration in [('subfinder-passive',fingerprint,2),('amass-passive',amass_fingerprint,4)]:
            plan={'scan':{'tool':tool,'binary_sha256':identity(),'provider_disclosure':True},'wall_timeout_seconds':duration*60,
                  'steps':[{'target':{'kind':'domain','value':'example.invalid'},'action':'passive_recon','ports':[443],
                            'max_concurrency':1,'max_http_rps':1,'max_duration_minutes':duration}]}
            validate_scan(plan)
            row=await asyncio.wait_for(run_scan(plan,guard),duration*60)
            assert not row['authorization_extended'] and row['active_resolution'] is False
            assert row['discovered_names']==[],row
            results.append({'tool':tool,'status':'passed_reserved_domain_run','source_data_verified':False})
    print(json.dumps({'results':results},indent=2))


asyncio.run(main())
