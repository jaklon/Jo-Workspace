"""Capture one scoped HEAD; inspect selected headers offline with ZAP passive rules."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

IMAGE='ghcr.io/zaproxy/zaproxy:stable'


def image_hash(image=IMAGE):
    docker=shutil.which('docker')
    if not docker:return None
    try:
        row=subprocess.run([docker,'image','inspect',image,'--format','{{.Id}}'],capture_output=True,
            timeout=3,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        value=row.stdout.decode().strip()
        if row.returncode==0 and value.startswith('sha256:') and len(value)==71:return value[7:]
    except (OSError,subprocess.TimeoutExpired):pass
    return None


async def inspect_headers(url,status,headers,image):
    docker=shutil.which('docker')
    if not docker or image_hash()!=image:raise ValueError('ZAP image unavailable or changed')
    name='jo-zap-'+uuid4().hex
    with tempfile.TemporaryDirectory(prefix='jo-zap-') as directory:
        root=Path(directory)
        har={'log':{'version':'1.2','creator':{'name':'Jo Workspace','version':'1'},'entries':[{
            'startedDateTime':'2026-01-01T00:00:00.000Z','time':0,
            'request':{'method':'HEAD','url':url,'httpVersion':'HTTP/1.1','headers':[],'queryString':[],'cookies':[],'headersSize':-1,'bodySize':0},
            'response':{'status':status,'statusText':'Observed','httpVersion':'HTTP/1.1','headers':[{'name':k,'value':v} for k,v in headers.items()],
                        'cookies':[],'content':{'size':0,'mimeType':'text/html','text':''},'redirectURL':'','headersSize':-1,'bodySize':0},
            'cache':{},'timings':{'send':0,'wait':0,'receive':0}}]}}
        (root/'input.har').write_text(json.dumps(har),encoding='utf-8')
        driver=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))/'zap_driver.py'
        args=[docker,'run','--rm','--name',name,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges',
              '--memory','1g','--cpus','1','--pids-limit','128','--read-only','--tmpfs','/tmp:rw,size=384m',
              '--mount',f'type=bind,src={root},dst=/work,readonly',
              '--mount',f'type=bind,src={driver},dst=/driver.py,readonly',
              '--entrypoint','python3','sha256:'+image,'/driver.py']
        process=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            output=await asyncio.wait_for(process.stdout.read(64001),130)
            if len(output)>64000:raise ValueError('ZAP output limit')
            await asyncio.wait_for(process.wait(),5)
            if process.returncode:raise ValueError('ZAP passive container failed')
            data=json.loads(output)
            if data.get('network')!='none' or data.get('requests_replayed') is not False:raise ValueError('Unexpected ZAP output')
            return data
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            cleanup=await asyncio.create_subprocess_exec(docker,'rm','-f',name,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            await asyncio.wait_for(cleanup.wait(),10)


async def run(plan,guard,exclusions=()):
    from web_checks import probe
    step=plan['steps'][0]
    result=await probe(step['target']['value'],exclusions,guard,for_analysis=True,allow_loopback=True)
    await guard()
    data=await inspect_headers(step['target']['value'],result['http_status'],result.pop('analysis_headers'),plan['scan']['binary_sha256'])
    return {'tool':'zap-head','target':step['target']['value'],'head':result,'passive':data,
            'limitation':'ZAP passive review of selected captured HEAD headers only; no spider, active scan or body inspection.'}
