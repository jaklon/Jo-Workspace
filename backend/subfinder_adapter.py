"""One passive crt.sh source, no active resolution or subsequent target probing."""
import asyncio
import json
import os
import shutil
import subprocess
from uuid import uuid4
from engagements import domain_name
from zap_adapter import image_hash

IMAGE='projectdiscovery/subfinder:latest'
AMASS_IMAGE='jo-workspace/amass-crtsh:1'


def fingerprint():return image_hash(IMAGE)


def amass_fingerprint():return image_hash(AMASS_IMAGE)


async def run(plan,guard):
    amass=plan['scan']['tool']=='amass-passive'
    if (amass_fingerprint() if amass else fingerprint())!=plan['scan']['binary_sha256']:raise ValueError('Passive recon image changed')
    await guard()
    domain=plan['steps'][0]['target']['value']
    name='jo-subfinder-'+uuid4().hex
    docker=shutil.which('docker')
    args=[docker,'run','--rm','--name',name,'--cap-drop','ALL','--security-opt','no-new-privileges',
          '--memory','768m' if amass else '256m','--cpus','1','--pids-limit','128' if amass else '64','--read-only',
          '--tmpfs','/tmp:rw,size=256m' if amass else '/tmp:rw,size=32m',
          '-e','HOME=/tmp','-e','XDG_CONFIG_HOME=/tmp']
    if amass:
        script='set -e; /bin/amass enum -passive -rigid -include crt.sh -d "$JO_DOMAIN" -timeout 1 -nocolor -dir /tmp/amass >/tmp/enum.log 2>&1; /bin/amass subs -names -nocolor -d "$JO_DOMAIN" -dir /tmp/amass 2>/dev/null'
        args+=['-e','JO_DOMAIN='+domain,'--entrypoint','/bin/sh','sha256:'+plan['scan']['binary_sha256'],'-c',script]
    else:
        args+=['--entrypoint','subfinder','sha256:'+plan['scan']['binary_sha256'],
               '-d',domain,'-s','crtsh','-silent','-nc','-duc','-rl','1','-timeout','10','-max-time','1','-rsr','1048576']
    process=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        output=await process.stdout.read(64001)
        if len(output)>64000:raise ValueError('Subfinder output limit')
        await process.wait()
        if process.returncode:raise ValueError('Subfinder failed')
        domains=[]
        for line in output.decode('utf-8').splitlines():
            found=domain_name(line.strip())
            if found!=domain and not found.endswith('.'+domain):raise ValueError('Unexpected Subfinder domain')
            if found!=domain:domains.append(found)
        return {'tool':'amass-passive' if amass else 'subfinder-passive','target':domain,'source':'crtsh','discovered_names':sorted(set(domains))[:256],
                'source_status':'unverified','active_resolution':False,'authorization_extended':False,
                'limitation':'Names are passive observations, not authorized scan targets. Empty output may mean source failure or no data.'}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        cleanup=await asyncio.create_subprocess_exec(docker,'rm','-f',name,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        await asyncio.wait_for(cleanup.wait(),10)
