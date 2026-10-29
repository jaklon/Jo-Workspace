"""One approved JS bundle GET; extract bounded, unverified endpoint candidates."""
import re
from urllib.parse import urlsplit, urlunsplit
from active_web_adapter import fetch

MAX_BUNDLE=1024*1024
URLS=re.compile(r'https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9_./~-]*)?')
PATHS=re.compile(r'["\x27`](/api/(?:[A-Za-z][A-Za-z0-9_-]{0,39}/?){1,5})["\x27`]')

async def run(plan,guard,exclusions):
    target=plan['steps'][0]['target']['value']
    status,body=await fetch(target,guard,exclusions,media_types=('application/javascript','text/javascript','application/x-javascript','text/plain'),max_bytes=MAX_BUNDLE)
    if status!=200 or not body:raise ValueError('JAVASCRIPT_UNAVAILABLE_OR_EMPTY')
    source=body.decode('utf-8','replace');origins=[];paths=[]
    for match in URLS.finditer(source):
        parsed=urlsplit(match.group(0));origin=urlunsplit((parsed.scheme,parsed.netloc,'/','',''))
        if origin not in origins:origins.append(origin)
        if len(origins)>=30:break
    for match in PATHS.finditer(source):
        path=match.group(1)
        if len(path)<=160 and all(len(part)<=24 for part in path.split('/')) and path not in paths:paths.append(path)
        if len(paths)>=30:break
    return {'tool':'js-bundle-inventory','target':target,'status_code':status,'candidate_origins':origins,'candidate_api_paths':paths,
            'limitation':'Satu bundle JavaScript eksplisit dalam scope. Kandidat berasal dari teks statis, belum diverifikasi, tidak dihubungi, dan tidak otomatis masuk scope. URL, query, dan nilai secret tidak dikumpulkan.'}
