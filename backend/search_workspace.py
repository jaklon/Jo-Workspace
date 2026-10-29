"""Local SearXNG JSON adapter and bounded Scrapling image extraction."""
import asyncio
import ipaddress
import os
import re
import ssl
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import Field
from scrapling import Selector

from engagements import StrictModel
from security import SafeValidationRoute
from web_checks import resolve

router = APIRouter(prefix='/api/search', tags=['SearXNG and Scrapling'], route_class=SafeValidationRoute)


class SearchQuery(StrictModel):
    query: str = Field(min_length=2, max_length=200)
    category: str = Field(default='general', pattern='^(general|images)$')


class ExtractQuery(StrictModel):
    url: str = Field(min_length=8, max_length=1000)


def searx_url():
    value = os.getenv('SEARXNG_BASE_URL', 'http://127.0.0.1:8080').rstrip('/')
    parsed = urlsplit(value)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1') or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise RuntimeError('SEARXNG_BASE_URL harus http://127.0.0.1:<port> atau http://[::1]:<port>.')
    return value


def public_url(value):
    if not isinstance(value, str) or len(value) > 1000 or any(ord(c) < 33 or ord(c) > 126 for c in value) or '\\' in value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or (parsed.port and parsed.port != 443):
            return None
        host = parsed.hostname.encode('idna').decode('ascii')
        ip = ipaddress.ip_address(host) if re.fullmatch(r'[0-9.]+', host) or ':' in host else None
        if ip and not ip.is_global:
            return None
        if host.endswith(('.local', '.internal', '.localhost', '.test')):
            return None
        return urlunsplit(('https', parsed.netloc, parsed.path or '/', parsed.query, ''))
    except (ValueError, UnicodeError):
        return None


async def get_public(url, limit, image=False):
    safe = public_url(url)
    if not safe:
        raise HTTPException(422, 'URL publik HTTPS diperlukan.')
    parsed = urlsplit(safe)
    try:
        address = await resolve(parsed.hostname, 443, [])
    except (ValueError, OSError) as exc:
        raise HTTPException(422, 'Alamat tujuan harus publik dan dapat diresolusi.') from exc
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 443, ssl=ssl.create_default_context(), server_hostname=parsed.hostname, limit=32768), 5)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise HTTPException(502, 'Sambungan HTTPS ke alamat tujuan gagal.') from exc
    try:
        path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
        writer.write(('GET ' + path + ' HTTP/1.1\r\nHost: ' + parsed.netloc + '\r\nUser-Agent: JoWorkspace-Search/1.0\r\nAccept: ' +
                      ('image/avif,image/webp,image/png,image/jpeg,image/gif' if image else 'text/html') +
                      '\r\nConnection: close\r\n\r\n').encode('ascii'))
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        if len(header) > 32768:
            raise HTTPException(413, 'Header terlalu besar.')
        lines = header.decode('iso-8859-1').split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] 200(?: [^\r\n]*)?', lines[0]):
            raise HTTPException(422, 'Halaman tidak tersedia tanpa redirect.')
        fields = {}
        for line in lines[1:]:
            if not line:continue
            name, sep, value = line.partition(':')
            if not sep:raise HTTPException(422, 'Header HTTP tidak valid.')
            fields[name.lower()] = value.strip()
        media = fields.get('content-type','').split(';')[0].lower()
        if image and media not in ('image/png','image/jpeg','image/webp','image/gif','image/avif'):
            raise HTTPException(415, 'Jenis gambar tidak didukung.')
        if not image and media not in ('text/html','application/xhtml+xml'):
            raise HTTPException(415, 'Konten HTML diperlukan.')
        if fields.get('content-encoding','identity').lower() != 'identity':
            raise HTTPException(415, 'Encoding halaman tidak didukung.')
        if int(fields.get('content-length','0')) > limit:
            raise HTTPException(413, 'Konten terlalu besar.')
        if fields.get('transfer-encoding','').lower() == 'chunked':
            chunks=[]; total=0
            while True:
                line=await asyncio.wait_for(reader.readline(),5)
                size=int(line.split(b';')[0],16)
                if size==0:break
                total+=size
                if total>limit:raise HTTPException(413,'Konten terlalu besar.')
                chunks.append(await asyncio.wait_for(reader.readexactly(size),5))
                await reader.readexactly(2)
            body=b''.join(chunks)
        else:
            length=fields.get('content-length')
            if length is not None:
                body=await asyncio.wait_for(reader.readexactly(int(length)),8)
            else:
                chunks=[];total=0
                while True:
                    part=await asyncio.wait_for(reader.read(min(65536,limit+1-total)),8)
                    if not part:break
                    total+=len(part)
                    if total>limit:raise HTTPException(413,'Konten terlalu besar.')
                    chunks.append(part)
                body=b''.join(chunks)
        if len(body)>limit:raise HTTPException(413,'Konten terlalu besar.')
        return body, media
    finally:
        writer.close()
        try:await asyncio.wait_for(writer.wait_closed(),1)
        except (OSError,TimeoutError):pass


def extract_images(html, page_url):
    page=Selector(html, url=page_url)
    items=[];seen=set()
    for node in page.css('img')[:40]:
        candidate=node.attrib.get('src') or node.attrib.get('data-src')
        safe=public_url(urljoin(page_url,candidate or ''))
        if safe and safe not in seen:
            seen.add(safe)
            items.append({'url':safe,'alt':str(node.attrib.get('alt',''))[:160]})
        if len(items)>=12:break
    return items


@router.get('/capabilities')
async def capabilities():
    return {'provider':'SearXNG','configured_url':searx_url(),'parser':'Scrapling 0.5',
            'images_supported':True,'json_required':True}


@router.post('/query')
async def query(payload:SearchQuery):
    try:
        async with httpx.AsyncClient(timeout=8,follow_redirects=False,trust_env=False) as client:
            response=await client.get(searx_url()+'/search',params={'q':payload.query,'categories':payload.category,'format':'json','safesearch':1})
            response.raise_for_status()
            if len(response.content)>512_000:raise HTTPException(413,'Hasil pencarian terlalu besar.')
            data=response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(503,'SearXNG lokal tidak tersedia atau JSON belum diaktifkan.') from exc
    results=[]
    for row in data.get('results',[])[:30]:
        target=public_url(row.get('url'))
        if not target:continue
        image=public_url(row.get('img_src')) or public_url(row.get('thumbnail'))
        results.append({'title':str(row.get('title',''))[:200], 'url':target,
                        'snippet':str(row.get('content',''))[:500], 'image_url':image,
                        'engine':str(row.get('engine',''))[:60]})
    return {'query':payload.query,'category':payload.category,'results':results,'count':len(results)}


@router.post('/extract-images')
async def extract(payload:ExtractQuery):
    body,_=await get_public(payload.url,512_000)
    images=extract_images(body,payload.url)
    rendered=False
    marker=body[:120_000].lower()
    challenge=any(value in marker for value in (b'cf-chl-',b'cf_chl_',b'cdn-cgi/challenge-platform',b'cf-browser-verification'))
    if not images and b'<script' in marker and not challenge:
        try:
            from browser_render import render_public
            body=await asyncio.wait_for(render_public(payload.url),timeout=25)
            images=extract_images(body,payload.url)
            rendered=True
        except Exception:
            pass
    return {'page_url':public_url(payload.url),'images':images,'rendered':rendered}


@router.get('/image')
async def image(url:str):
    body,media=await get_public(url,2_000_000,image=True)
    return Response(body,media_type=media,headers={'Cache-Control':'private, max-age=300','X-Content-Type-Options':'nosniff'})
