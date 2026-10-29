"""One approved GET; collect only link and form URL candidates, never fetch them."""
import asyncio
import hashlib
from html.parser import HTMLParser
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit
from web_checks import resolve

LIMIT=131072

class Links(HTMLParser):
    def __init__(self,base):
        super().__init__(convert_charrefs=True); self.base=base; self.items=[]
    def handle_starttag(self,tag,attrs):
        if len(self.items)>=40:return
        for name,value in attrs:
            if not value or not ((tag in ('a','link') and name=='href') or (tag=='script' and name=='src') or (tag=='form' and name=='action')):continue
            try:
                parsed=urlsplit(urljoin(self.base,value))
                parsed.port  # Raises ValueError for an invalid port so it is never recorded.
                if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:continue
                # Paths and queries can carry credentials or personal data; record origins only.
                clean=urlunsplit((parsed.scheme,parsed.netloc,'/', '', ''))
                if len(clean)<=500 and clean not in [item['url'] for item in self.items]:
                    self.items.append({'kind':tag,'url':clean,'contacted':False})
            except ValueError:continue
            if len(self.items)>=40:return

async def run(plan,guard,exclusions):
    url=plan['steps'][0]['target']['value']; parsed=urlsplit(url)
    await guard(); address=await resolve(parsed.hostname,443,exclusions); await guard()
    reader,writer=await asyncio.wait_for(asyncio.open_connection(address,443,ssl=ssl.create_default_context(),server_hostname=parsed.hostname,limit=32768),5)
    try:
        await guard()
        path=(parsed.path or '/').encode('ascii')
        writer.write(b'GET '+path+b' HTTP/1.1\r\nHost: '+parsed.netloc.encode('ascii')+b'\r\nUser-Agent: JoWorkspace-Inventory/1.0\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n')
        await writer.drain(); raw=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
        if len(raw)>32768:raise ValueError('HEADER_LIMIT')
        lines=raw.decode('iso-8859-1').split('\r\n'); status=int(lines[0].split()[1]); headers={}
        for line in lines[1:]:
            if line:
                k,sep,v=line.partition(':')
                if not sep:raise ValueError('INVALID_HEADER')
                headers[k.lower()]=v.strip()
        if status!=200: return {'tool':'inventory-html','target':url,'http_status':status,'candidates':[], 'limitation':'Tidak membaca body non-200 atau mengikuti redirect.'}
        if headers.get('content-type','').split(';')[0].lower() not in ('text/html','application/xhtml+xml'):raise ValueError('NOT_HTML')
        if headers.get('content-encoding','identity').lower()!='identity':raise ValueError('ENCODING_UNSUPPORTED')
        data=bytearray()
        if headers.get('transfer-encoding','').lower()=='chunked':
            while True:
                size=int((await asyncio.wait_for(reader.readline(),5)).split(b';')[0],16)
                if size==0:break
                if size>LIMIT-len(data):raise ValueError('BODY_LIMIT')
                data.extend(await asyncio.wait_for(reader.readexactly(size),5))
                if await reader.readexactly(2)!=b'\r\n':raise ValueError('INVALID_CHUNK')
        else:
            length=headers.get('content-length')
            if length is not None:
                size=int(length)
                if size<0 or size>LIMIT:raise ValueError('BODY_LIMIT')
                data.extend(await asyncio.wait_for(reader.readexactly(size),8))
            else:
                while True:
                    part=await asyncio.wait_for(reader.read(min(32768,LIMIT+1-len(data))),8)
                    if not part:break
                    data.extend(part)
                    if len(data)>LIMIT:raise ValueError('BODY_LIMIT')
        links=Links(url);links.feed(bytes(data).decode('utf-8','replace'))
        return {'tool':'inventory-html','target':url,'http_status':status,'body_sha256':hashlib.sha256(data).hexdigest(),
                'candidates':links.items[:40],'limitation':'Satu HTML GET tanpa sesi; URL kandidat tidak dihubungi dan tidak otomatis masuk scope. JavaScript tidak dijalankan atau dibaca.'}
    finally:
        writer.close()
        try:await asyncio.wait_for(writer.wait_closed(),1)
        except (OSError,TimeoutError):pass
