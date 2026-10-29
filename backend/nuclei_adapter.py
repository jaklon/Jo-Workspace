"""Fixed single-HEAD Nuclei profile; no user templates, workflows or command options."""
import asyncio
import hashlib
import json
import ipaddress
from urllib.parse import urlsplit, urlunsplit
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


TEMPLATE = '''id: jo-csp-head-1
info:
  name: Jo Workspace CSP HEAD observation
  author: jo-workspace
  severity: info
http:
  - method: HEAD
    path:
      - "{{BaseURL}}"
    redirects: false
    max-redirects: 0
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 100 && !contains(tolower(all_headers), 'content-security-policy:')"
'''


def executable():
    path=shutil.which('nuclei')
    if not path:
        candidate=Path(os.environ.get('USERPROFILE',''))/'go'/'bin'/'nuclei.exe'
        if candidate.is_file():path=str(candidate)
    return path


def binary_hash():
    path=executable()
    if not path:return None
    try:
        with open(path,'rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()
    except OSError:return None


async def run(plan, guard, exclusions=()):
    target=plan['steps'][0]['target']['value']
    if binary_hash()!=plan['scan']['binary_sha256']:raise ValueError('Nuclei executable changed')
    await guard()
    parsed=urlsplit(target)
    try: ipaddress.ip_address(parsed.hostname); domain=False
    except ValueError: domain=True
    transport_target=target
    domain_args=[]
    if domain:
        from web_checks import resolve
        address=await resolve(parsed.hostname, parsed.port or (443 if parsed.scheme=='https' else 80), exclusions)
        await guard()
        host_ip='['+address+']' if ':' in address else address
        authority=host_ip+(':'+str(parsed.port) if parsed.port else '')
        transport_target=urlunsplit((parsed.scheme,authority,parsed.path,parsed.query,''))
        domain_args=['-H','Host: '+parsed.netloc,'-sni',parsed.hostname]
    with tempfile.TemporaryDirectory(prefix='jo-nuclei-') as directory:
        root=Path(directory)
        template=root/'csp.yaml'
        template.write_text(TEMPLATE,encoding='utf-8')
        config=root/'empty.yaml'
        config.write_text('{}',encoding='utf-8')
        env={key:os.environ[key] for key in ('SystemRoot','WINDIR','TEMP','TMP') if key in os.environ}
        env.update(HOME=directory,USERPROFILE=directory,APPDATA=directory,XDG_CONFIG_HOME=directory)
        args=[executable(),'-u',transport_target,'-t',str(template),'-config',str(config),'-type','http',
              '-dr','-ni','-duc','-no-stdin','-nh','-or','-ot','-j','-silent','-nc',
              '-rl','1','-c','1','-bs','1','-retries','0','-timeout','5','-rsr','32768','-rss','32768']+domain_args
        process=await asyncio.create_subprocess_exec(*args,cwd=directory,env=env,stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            parts=[]; size=0
            while True:
                part=await process.stdout.read(4096)
                if not part:break
                size+=len(part)
                if size>64000:raise ValueError('Nuclei output limit')
                parts.append(part)
            await process.wait()
            if process.returncode:raise ValueError('Nuclei failed')
            count=0
            for line in b''.join(parts).splitlines():
                row=json.loads(line)
                if row.get('template-id')!='jo-csp-head-1' or row.get('matched-at')!=transport_target:
                    raise ValueError('Nuclei output does not match fixed profile')
                count+=1
            return {'tool':'nuclei-head','target':target,'template_id':'jo-csp-head-1',
                    'template_sha256':hashlib.sha256(TEMPLATE.encode()).hexdigest(),
                    'binary_sha256':plan['scan']['binary_sha256'], 'dns_pinned':domain,
                    'csp_observation':'missing_header_candidate' if count else 'no_match_or_inconclusive',
                    'limitation':'Fixed HEAD template only. No match may mean inaccessible target; missing CSP is not proof of exploit.'}
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
