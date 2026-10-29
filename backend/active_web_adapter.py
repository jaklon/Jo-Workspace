"""Bounded same-origin spider and benign reflected-input check for approved staging."""
import asyncio
import re
import secrets
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
from web_checks import resolve

MAX_BODY=65536

class Anchors(HTMLParser):
    def __init__(self,base):super().__init__();self.base=base;self.links=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()!='a' or len(self.links)>=50:return
        for key,value in attrs:
            if key.lower()!='href' or not value:continue
            try:
                p=urlsplit(urljoin(self.base,value))
                # Queries, encoded paths, fragments, and userinfo are never followed.
                if p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment or '%' in p.path or '\\' in p.path:continue
                if not re.fullmatch(r'/[A-Za-z0-9_./~-]*',p.path or '/'):continue
                if re.search(r'(?:^|[/_-])(logout|signout|delete|remove|destroy|reset|unsubscribe)(?:$|[/_.-])',p.path,re.I):continue
                candidate=urlunsplit((p.scheme,p.netloc,p.path or '/', '', ''))
                if candidate not in self.links:self.links.append(candidate)
            except ValueError:continue

async def fetch(url,guard,exclusions,query='', *, media_types=None, max_bytes=MAX_BODY):
    p=urlsplit(url);await guard(url)
    address=await resolve(p.hostname,443,exclusions);await guard(url)
    reader,writer=await asyncio.wait_for(asyncio.open_connection(address,443,ssl=ssl.create_default_context(),server_hostname=p.hostname,limit=32768),5)
    try:
        await guard(url)
        path=(p.path or '/')+query
        writer.write(('GET '+path+' HTTP/1.1\r\nHost: '+p.netloc+'\r\nUser-Agent: JoWorkspace-ScopedTest/1.0\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii'))
        await writer.drain();raw=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
        if len(raw)>32768:raise ValueError('HEADER_LIMIT')
        lines=raw.decode('iso-8859-1').split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?',lines[0]):raise ValueError('INVALID_HTTP')
        status=int(lines[0].split()[1]);headers={}
        for line in lines[1:]:
            if line:
                key,sep,value=line.partition(':')
                if not sep:raise ValueError('INVALID_HEADER')
                headers[key.lower()]=value.strip()
        if status!=200:return status,b''
        allowed=media_types or ('text/html','application/xhtml+xml')
        if headers.get('content-type','').split(';')[0].lower() not in allowed:return status,b''
        if headers.get('content-encoding','identity').lower()!='identity':raise ValueError('ENCODING_UNSUPPORTED')
        body=bytearray()
        if headers.get('transfer-encoding','').lower()=='chunked':
            while True:
                size=int((await asyncio.wait_for(reader.readline(),5)).split(b';')[0],16)
                if not size:break
                if size>max_bytes-len(body):raise ValueError('BODY_LIMIT')
                body.extend(await asyncio.wait_for(reader.readexactly(size),5))
                if await reader.readexactly(2)!=b'\r\n':raise ValueError('INVALID_CHUNK')
        elif 'content-length' in headers:
            size=int(headers['content-length'])
            if size<0 or size>max_bytes:raise ValueError('BODY_LIMIT')
            body.extend(await asyncio.wait_for(reader.readexactly(size),8))
        else:
            while True:
                part=await asyncio.wait_for(reader.read(min(16384,max_bytes+1-len(body))),8)
                if not part:break
                body.extend(part)
                if len(body)>max_bytes:raise ValueError('BODY_LIMIT')
        return status,bytes(body)
    finally:
        writer.close()
        try:await asyncio.wait_for(writer.wait_closed(),1)
        except (OSError,TimeoutError):pass

async def run(plan,guard,exclusions):
    root=plan['steps'][0]['target']['value'];tool=plan['scan']['tool']
    if re.search(r'(?:^|[/_-])(logout|signout|delete|remove|destroy|reset|unsubscribe)(?:$|[/_.-])',urlsplit(root).path,re.I):raise ValueError('ACTION_PATH_BLOCKED')
    if tool=='active-reflection':
        marker='joworkspace'+secrets.token_hex(8)
        status,body=await fetch(root,guard,exclusions,'?jo_probe='+marker)
        return {'tool':tool,'target':root,'status_code':status,'marker_reflected':marker.encode() in body,
                'limitation':'Satu GET dengan marker alfanumerik; refleksi bukan bukti XSS atau bypass login. Body dan marker tidak disimpan.'}
    origin=urlsplit(root);queue=[root];seen=set();pages=[]
    while queue and len(seen)<5:
        current=queue.pop(0)
        if re.search(r'(?:^|[/_-])(logout|signout|delete|remove|destroy|reset|unsubscribe)(?:$|[/_.-])',urlsplit(current).path,re.I):raise ValueError('ACTION_PATH_BLOCKED')
        if current in seen:continue
        try:await guard(current)
        except ValueError:continue
        seen.add(current);status,body=await fetch(current,guard,exclusions)
        pages.append({'url':current,'status_code':status})
        if body:
            parser=Anchors(current);parser.feed(body.decode('utf-8','replace'))
            for link in parser.links:
                p=urlsplit(link)
                if (p.scheme,p.hostname,p.port or 443)!=(origin.scheme,origin.hostname,origin.port or 443):continue
                if link not in seen and link not in queue and len(queue)<20:queue.append(link)
        if queue and len(seen)<5:await asyncio.sleep(1)
    return {'tool':tool,'target':root,'pages':pages,'limitation':'Maksimal 5 GET same-origin, tanpa sesi, form, JavaScript, query, atau redirect; setiap URL diperiksa ulang terhadap RoE. Bukan inventaris lengkap.'}
