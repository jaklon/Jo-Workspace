"""One approved HEAD request to a pinned public IP. No redirects, credentials or body."""
import asyncio
import hashlib
from contextlib import closing
from datetime import timedelta
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit

from fastapi import HTTPException
from pydantic import Field
from engagements import StrictModel, ScopeAsset, EngagementContent, utc_now
from security_policy import evaluate, network

VERSION = 'public-head-1.0'


class WebBinding(StrictModel):
    adapter: str = Field(default=VERSION, pattern='^public-head-1\\.0$')


def validate_plan(plan):
    if not plan.get('web'):
        return
    steps = plan['steps']
    if plan.get('mcp') or len(steps) != 1:
        raise ValueError('Pemeriksaan URL memerlukan satu langkah tanpa MCP.')
    step = steps[0]
    parsed = urlsplit(step['target']['value'])
    if step['action'] != 'http_headers' or step['target']['kind'] != 'url':
        raise ValueError('Pemeriksaan URL hanya mendukung http_headers pada URL eksplisit.')
    if (parsed.port or (443 if parsed.scheme == 'https' else 80)) not in (80, 443):
        raise ValueError('Pemeriksaan URL publik dibatasi port 80/443.')
    if step['max_http_rps'] != 1 or step['max_concurrency'] != 1 or plan['wall_timeout_seconds'] > 20:
        raise ValueError('Batas URL: satu request, concurrency 1, maksimal 20 detik.')
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not public(ip):
            raise ValueError('URL harus memakai alamat publik, bukan internal/loopback/metadata.')


def public(ip):
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified and not getattr(ip, 'ipv4_mapped', None)


async def resolve(host, port, exclusions):
    rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), 3)
    addresses = sorted({row[4][0] for row in rows})
    if not addresses or len(addresses) > 32:
        raise ValueError('DNS_EMPTY_OR_LIMIT')
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not public(ip):
            raise ValueError('DNS_NON_PUBLIC_ADDRESS')
        for asset in exclusions:
            net = network(asset)
            if net and ip.version == net.version and ip in net:
                raise ValueError('DNS_ADDRESS_EXCLUDED')
    return addresses[0]  # Connect to this IP only; do not resolve the hostname a second time.


def http_configuration(headers):
    """Summarize response configuration without storing header or cookie values."""
    cache = ','.join(headers.get('cache-control', [])).lower()
    allow_origin = headers.get('access-control-allow-origin', [])
    credentials = headers.get('access-control-allow-credentials', [])
    return {
        'cache': {'header_present': 'cache-control' in headers,
                  'no_store': bool(re.search(r'(?:^|,)\s*no-store\s*(?:,|$)', cache)),
                  'private': bool(re.search(r'(?:^|,)\s*private(?:\s*=|\s*(?:,|$))', cache))},
        'cors': {'allow_origin_present': bool(allow_origin),
                 'wildcard_origin_observed': any(v.strip() == '*' for v in allow_origin),
                 'allow_credentials_true': any(v.strip().lower() == 'true' for v in credentials),
                 'limitation': 'HEAD tanpa Origin; bukan uji CORS lintas origin atau preflight.'},
    }


async def probe(url, exclusions, guard, *, for_analysis=False, allow_loopback=False, method='HEAD', bearer=None, compare_body=False, owner_pointer=''):
    if method not in ('HEAD','GET'):raise ValueError('Unsupported method')
    parsed = urlsplit(url)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)
    try: literal=ipaddress.ip_address(host)
    except ValueError: literal=None
    address = host if allow_loopback and literal and literal.is_loopback else await resolve(host, port, exclusions)
    await guard()
    context = ssl.create_default_context() if parsed.scheme == 'https' else None
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        address, port, ssl=context, server_hostname=host if context else None, limit=32768), 5)
    try:
        await guard()
        authority = parsed.netloc
        path = (parsed.path or '/').encode('ascii')
        if bearer is not None and not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}',bearer):raise ValueError('INVALID_SESSION')
        authorization=(b'Authorization: Bearer '+bearer.encode('ascii')+b'\r\n') if bearer else b''
        writer.write(method.encode('ascii') + b' ' + path + b' HTTP/1.1\r\nHost: ' + authority.encode('ascii') +
                     b'\r\nUser-Agent: JoWorkspace-URLCheck/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\n'+authorization+b'Connection: close\r\n\r\n')
        await writer.drain()
        raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        if len(raw) > 32768:
            raise ValueError('HEADER_LIMIT')
        lines = raw.decode('iso-8859-1').split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?', lines[0]):
            raise ValueError('INVALID_HTTP_RESPONSE')
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            name, sep, value = line.partition(':')
            if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError('INVALID_HTTP_HEADER')
            headers.setdefault(name.lower(), []).append(value.strip())
        body_digest=None
        semantic_digest=None
        shape_digest=None
        owner_digest=None
        if compare_body and method=='GET' and int(lines[0].split()[1])==200:
            content_type=headers.get('content-type',[''])[0].split(';')[0].lower()
            lengths=headers.get('content-length',[])
            encoding=headers.get('content-encoding',['identity'])[0].lower()
            if content_type=='application/json' and len(lengths)==1 and lengths[0].isdigit() and int(lengths[0])<=32768 and encoding=='identity' and 'transfer-encoding' not in headers:
                await guard()
                body=await asyncio.wait_for(reader.readexactly(int(lengths[0])),5)
                body_digest=hashlib.sha256(body).digest()
                from json_comparison import fingerprints
                compared=fingerprints(body,owner_pointer)
                semantic_digest,shape_digest=compared[:2]
                if owner_pointer:owner_digest=compared[2]
                del body
        tls = writer.get_extra_info('ssl_object')
        result = {'adapter': VERSION, 'url': url, 'method': method, 'requests': 1,
                  'http_status': int(lines[0].split()[1]), 'redirect_followed': False,
                  'body_collected': False, 'credentials_sent': bool(bearer),
                  'tls': {'verified': bool(tls), 'version': tls.version() if tls else None,
                          'certificate_expires': tls.getpeercert().get('notAfter') if tls else None},
                  'checks': [], 'limitations': 'Satu respons HEAD. Header absen bukan bukti exploit; tidak ada crawling, login, body, atau uji TLS legacy.'}
        for header in ('strict-transport-security', 'content-security-policy', 'x-content-type-options',
                       'x-frame-options', 'referrer-policy', 'permissions-policy'):
            result['checks'].append({'check': header, 'status': 'present' if header in headers else 'missing',
                                     'severity': 'info', 'review_required': True})
        result['checks'].append({'check': 'https_transport', 'status': 'verified' if tls else 'unencrypted', 'review_required': True})
        # Never persist Set-Cookie values or arbitrary response headers, including Location queries.
        result['cookie_flags'] = [{'secure': bool(re.search(r';\s*secure(?:;|$)', c, re.I)),
                                  'httponly': bool(re.search(r';\s*httponly(?:;|$)', c, re.I)),
                                  'samesite': bool(re.search(r';\s*samesite=', c, re.I))}
                                 for c in headers.get('set-cookie', [])[:20]]
        result['redirect_observed'] = 300 <= result['http_status'] < 400
        result['head_supported'] = result['http_status'] not in (405, 501)
        result['http_configuration'] = http_configuration(headers)
        if compare_body:
            result['_transient_body_digest']=body_digest
            result['_transient_semantic_digest']=semantic_digest
            result['_transient_shape_digest']=shape_digest
            if owner_pointer:result['_transient_owner_digest']=owner_digest
        if for_analysis:
            from security_evidence import redactor
            scrub,_=redactor()
            allowed=('content-type','content-security-policy','strict-transport-security','x-content-type-options','x-frame-options','referrer-policy','permissions-policy','cache-control')
            result['analysis_headers']={key:scrub(', '.join(headers[key])[:1500]) for key in allowed if key in headers}
        return result
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, TimeoutError):
            pass


class WebRunner:
    def __init__(self, jobs, evidence):
        self.jobs, self.evidence = jobs, evidence
        with closing(jobs.engagements.connect()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS web_check_results (job_id TEXT PRIMARY KEY, payload TEXT NOT NULL, payload_hash TEXT NOT NULL)')
            db.commit()

    def live(self, db, owner, jid):
        from security_jobs import digest, LEASE_SECONDS
        row = db.execute('SELECT * FROM security_jobs WHERE id=?', (jid,)).fetchone()
        if not row or row['status'] != 'running' or row['worker'] != owner or not self.jobs.owned(db, owner):
            raise ValueError('RUN_STOPPED_OR_LEASE_LOST')
        self.jobs.open_gate(db, row['engagement_id'])
        plan = json.loads(row['plan'])
        validate_plan(plan)
        if not plan.get('web') or digest(plan) != row['plan_hash']:
            raise ValueError('PLAN_INTEGRITY')
        engagement, head = self.jobs.engagements.head(db, row['project_id'], row['engagement_id'])
        content = EngagementContent.model_validate_json(head['content'])
        if evaluate(content, head, engagement, self.jobs.proposals(plan)[0], utc_now(), dns_pinning=True)['decision'] != 'pass':
            raise ValueError('POLICY_DENIED')
        db.execute('UPDATE security_job_worker SET expires_at=? WHERE id=1 AND owner=?',
                   ((utc_now() + timedelta(seconds=LEASE_SECONDS)).isoformat(), owner))
        return row, plan, content

    def result(self, db, jid):
        from security_jobs import digest
        row = db.execute('SELECT * FROM web_check_results WHERE job_id=?', (jid,)).fetchone()
        if not row:
            return None
        payload = json.loads(row['payload'])
        if digest(payload) != row['payload_hash']:
            raise HTTPException(409, 'Integritas laporan URL tidak sesuai.')
        return payload

    async def execute(self, owner, jid):
        from security_jobs import encode, digest
        from security_evidence import EvidenceInput
        pending = None
        async def guard():
            with self.jobs.engagements.transaction() as db:
                self.live(db, owner, jid)
        try:
            with self.jobs.engagements.transaction() as db:
                row, plan, content = self.live(db, owner, jid)
            pending = asyncio.create_task(probe(plan['steps'][0]['target']['value'], content.out_of_scope, guard))
            while not pending.done():
                await asyncio.wait({pending}, timeout=0.25)
                await guard()
            result = await pending
            raw = encode(result)
            with self.jobs.engagements.transaction() as db:
                row, plan, _ = self.live(db, owner, jid)
                if len(raw.encode()) + row['output_bytes'] > plan['max_output_kb'] * 1024:
                    raise ValueError('OUTPUT_LIMIT')
                body = EvidenceInput(job_id=jid, step_ordinal=1, source='external_import',
                    title='Pemeriksaan URL · HEAD/HTTPS', captured_at=utc_now(), tool_name='Jo Workspace URL Check',
                    tool_version=VERSION, parameters=encode(plan['steps'][0]), content=raw, acknowledge=True)
                evidence = self.evidence.add_evidence(row['project_id'], row['engagement_id'], body, db=db,
                    web_provenance={'adapter': VERSION, 'method': 'HEAD', 'requests': 1})
                result.update(evidence_id=evidence['id'], observed_at=utc_now().isoformat(), roe_hash=plan['content_hash'],
                              roe_version=plan['roe_version'], plan_hash=row['plan_hash'])
                db.execute('INSERT INTO web_check_results VALUES (?,?,?)', (jid, encode(result), digest(result)))
                db.execute('UPDATE security_jobs SET output_bytes=output_bytes+? WHERE id=?', (len(raw.encode()), jid))
                self.jobs.event(db, jid, 'web_check_completed', note='Satu HEAD selesai; TLS diverifikasi untuk HTTPS, redirect tidak diikuti, evidence tersimpan.')
                self.jobs.finish(db, row, 'completed', message='Pemeriksaan URL selesai; hasil memerlukan review analis.')
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            code = 'TLS_VERIFICATION_FAILED' if isinstance(exc, ssl.SSLCertVerificationError) else 'WEB_CHECK_FAILED'
            self.jobs.fail(owner, jid, code, 'Pemeriksaan URL dihentikan: ' + type(exc).__name__ + '. Tidak ada retry, redirect, atau fallback TLS tidak aman.')
        finally:
            if pending and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
