"""Approved single-IP TCP connectivity and fixed Nmap connect scans."""
import asyncio
import base64
from contextlib import closing
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import subprocess
from typing import Literal
from uuid import UUID
import xml.etree.ElementTree as ET

from fastapi import HTTPException
from pydantic import Field, StrictBool
from engagements import StrictModel, EngagementContent, utc_now
from pentest import nmap_path
from security_policy import evaluate


class ScanBinding(StrictModel):
    tool: Literal['tcp-connect','nmap','monitoring-local','nuclei-head','zap-head','auth-unauthenticated-get','auth-two-session','inventory-html','js-bundle-inventory','scoped-spider','active-reflection','subfinder-passive','amass-passive']
    binary_sha256: str = Field(default='', max_length=64)
    provider_disclosure: StrictBool = False
    account_refs: list[str] = Field(default_factory=list, max_length=2)
    owner_json_pointer: str = Field(default='', max_length=256)


class ApprovedScanExecution(StrictModel):
    project_id: UUID
    engagement_id: UUID
    job_id: UUID
    expected_revision: int = Field(ge=1, strict=True)
    actor_label: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=1, max_length=1000)
    acknowledge: StrictBool


def binary_hash():
    path = nmap_path()
    if not path:
        return None
    try:
        with open(path, 'rb') as file:
            return hashlib.file_digest(file, 'sha256').hexdigest()
    except OSError:
        return None


def validate_scan(plan, check_binary=True):
    if not plan.get('scan'):
        return
    steps = plan['steps']
    if plan.get('web') or plan.get('mcp') or len(steps) != 1:
        raise ValueError('Scan memerlukan satu langkah tanpa adapter lain.')
    step = steps[0]
    from json_comparison import valid_owner_pointer
    pointer=plan['scan'].get('owner_json_pointer','')
    if not valid_owner_pointer(pointer) or (pointer and plan['scan']['tool']!='auth-two-session'):
        raise ValueError('Pointer pemilik hanya untuk perbandingan dua sesi dan harus berupa JSON Pointer yang valid.')
    if plan['scan']['tool'] in ('subfinder-passive','amass-passive'):
        from subfinder_adapter import fingerprint,amass_fingerprint
        amass=plan['scan']['tool']=='amass-passive'
        if step['target']['kind']!='domain' or step['action']!='passive_recon' or step['ports']!=[443] or not plan['scan'].get('provider_disclosure'):
            raise ValueError('Subfinder memerlukan domain, passive_recon, port 443 dan persetujuan pengungkapan domain ke crt.sh.')
        if step['max_http_rps']!=1 or step['max_concurrency']!=1 or step['max_duration_minutes']!=(4 if amass else 2) or plan['wall_timeout_seconds']>(240 if amass else 120):
            raise ValueError('Batas Subfinder tidak sesuai.')
        current=(amass_fingerprint() if amass else fingerprint()) if check_binary else plan['scan']['binary_sha256']
        if not current or current!=plan['scan']['binary_sha256']:raise ValueError('Subfinder image unavailable or changed')
        return
    if plan['scan']['tool'] in ('auth-unauthenticated-get','auth-two-session','inventory-html','js-bundle-inventory','scoped-spider','active-reflection'):
        from urllib.parse import urlsplit
        step=plan['steps'][0]
        if step['target']['kind']!='url' or step['action']!=({'inventory-html':'service_inventory','js-bundle-inventory':'service_inventory','auth-two-session':'authenticated_api_review','scoped-spider':'scoped_spider','active-reflection':'active_reflection'}.get(plan['scan']['tool'],'unauthenticated_access_check')):raise ValueError('Pemeriksaan memerlukan URL dan izin tindakan terkait.')
        parsed=urlsplit(step['target']['value'])
        if parsed.scheme!='https' or (parsed.port or 443)!=443 or step['ports']!=[443]:raise ValueError('Pemeriksaan publik dibatasi HTTPS port 443.')
        if step['max_concurrency']!=1 or step['max_http_rps']!=1 or step['max_duration_minutes']!=1 or plan['wall_timeout_seconds']>60 or plan['scan']['binary_sha256']:
            raise ValueError('Batas pemeriksaan GET tidak sesuai.')
        refs=plan['scan'].get('account_refs',[])
        if plan['scan']['tool']=='auth-two-session':
            if len(refs)!=2 or len(set(refs))!=2 or any(not ref.strip() or len(ref)>120 for ref in refs) or step['test_account_ref']!=refs[0]:raise ValueError('Dua alias akun uji berbeda diperlukan.')
        elif refs:raise ValueError('Alias sesi hanya untuk perbandingan dua akun.')
        return
    if plan['scan']['tool'] in ('nuclei-head','zap-head'):
        from urllib.parse import urlsplit
        from nuclei_adapter import binary_hash as nuclei_hash
        if step['target']['kind']!='url' or step['action']!='http_headers':
            raise ValueError('Nuclei HEAD memerlukan URL dan http_headers.')
        parsed=urlsplit(step['target']['value'])
        try: address=ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address=None
            if (parsed.port or (443 if parsed.scheme=='https' else 80)) not in (80,443):
                raise ValueError('URL domain dibatasi ke port 80/443.')
        if address and (address.is_multicast or address.is_unspecified or address.is_link_local):
            raise ValueError('Alamat Nuclei tidak diizinkan.')
        if parsed.scheme not in ('http','https') or set(step['ports'])!={parsed.port or (443 if parsed.scheme=='https' else 80)}:
            raise ValueError('Port Nuclei harus sesuai URL IP eksplisit.')
        zap=plan['scan']['tool']=='zap-head'
        if step['max_concurrency']!=1 or step['max_http_rps']!=1 or step['max_duration_minutes']!=(3 if zap else 1) or plan['wall_timeout_seconds']>(180 if zap else 60):
            raise ValueError('Batas Nuclei tidak sesuai.')
        if zap:
            from zap_adapter import image_hash
            fingerprint=image_hash() if check_binary else plan['scan']['binary_sha256']
        else:
            fingerprint=nuclei_hash() if check_binary else plan['scan']['binary_sha256']
        if not fingerprint or fingerprint!=plan['scan']['binary_sha256']:
            raise ValueError('Nuclei tidak tersedia atau executable berubah.')
        return
    if plan['scan']['tool']=='monitoring-local':
        if step['target']!={'kind':'ip','value':'127.0.0.1'} or step['action']!='monitoring_read' or set(step['ports'])!={3000,9090}:
            raise ValueError('Monitoring lokal hanya 127.0.0.1 port 3000/9090 dan monitoring_read.')
        if step['max_concurrency']!=1 or step['max_http_rps']!=1 or step['max_duration_minutes']!=1 or plan['wall_timeout_seconds']>60 or plan['scan']['binary_sha256']:
            raise ValueError('Batas monitoring lokal tidak sesuai.')
        return
    if step['action'] != 'tcp_discovery' or step['target']['kind'] != 'ip':
        raise ValueError('Scan hanya menerima satu IP eksplisit dan tindakan tcp_discovery.')
    ipaddress.ip_address(step['target']['value'])
    if not 1 <= len(step['ports']) <= 16 or step['max_concurrency'] != 1 or step['max_http_rps'] != 1 or step['max_duration_minutes'] != 1 or plan['wall_timeout_seconds'] > 60:
        raise ValueError('Scan dibatasi 1 IP, 1–16 port, concurrency 1 dan 60 detik.')
    if plan['scan']['tool'] == 'nmap':
        current = binary_hash() if check_binary else plan['scan']['binary_sha256']
        if not current or current != plan['scan']['binary_sha256']:
            raise ValueError('Nmap tidak tersedia atau hash executable berubah. Buat rencana baru.')
    elif plan['scan']['binary_sha256']:
        raise ValueError('TCP bawaan tidak menerima executable eksternal.')


def uses_pinned_url(plan):
    return bool(plan.get('web') or (plan.get('scan') or {}).get('tool') in ('nuclei-head','zap-head','auth-unauthenticated-get','auth-two-session','inventory-html','js-bundle-inventory','scoped-spider','active-reflection'))


async def run_scan(plan, guard, exclusions=(), sessions=None, target_guard=None):
    step = plan['steps'][0]
    target, ports = step['target']['value'], step['ports']
    validate_scan(plan)
    await guard()
    if plan['scan']['tool'] in ('scoped-spider','active-reflection','js-bundle-inventory'):
        if target_guard is None:raise ValueError('Target guard wajib untuk pemeriksaan aktif.')
        if plan['scan']['tool']=='js-bundle-inventory':
            from js_inventory_adapter import run
        else:
            from active_web_adapter import run
        return await run(plan,target_guard,exclusions)
    if plan['scan']['tool']=='auth-two-session':
        from web_checks import probe
        if not sessions or len(sessions)!=2:raise ValueError('Dua sesi uji tidak tersedia.')
        results=[]; digests=[]; semantic=[]; shapes=[]; owners=[]
        pointer=plan['scan'].get('owner_json_pointer','')
        subjects=[]
        if pointer:
            for token in sessions:
                payload=token.split('.')[1]
                claims=json.loads(base64.urlsafe_b64decode(payload+'='*((-len(payload))%4)))
                subjects.append(hashlib.sha256(claims['sub'].encode('utf-8')).digest())
        for label,token in [('tanpa sesi',None),*zip(plan['scan']['account_refs'],sessions)]:
            await guard()
            response=await probe(target,exclusions,guard,method='GET',bearer=token,compare_body=True,**({'owner_pointer':pointer} if pointer else {}))
            digests.append(response.pop('_transient_body_digest',None))
            semantic.append(response.pop('_transient_semantic_digest',None))
            shapes.append(response.pop('_transient_shape_digest',None))
            owners.append(response.pop('_transient_owner_digest',None))
            results.append({'account':label,'status_code':response['http_status'],'redirect_observed':response['redirect_observed']})
            if len(results)<3:await asyncio.sleep(1)
        comparisons=[]
        for left,right in ((0,1),(0,2),(1,2)):
            same=hmac.compare_digest(digests[left],digests[right]) if digests[left] is not None and digests[right] is not None else None
            equal=lambda values: hmac.compare_digest(values[left],values[right]) if values[left] is not None and values[right] is not None else None
            comparisons.append({'left':results[left]['account'],'right':results[right]['account'],'json_body_equal':same,
                                'json_values_equal':equal(semantic),'json_structure_equal':equal(shapes)})
        if pointer:
            for index,observation in enumerate(results):
                owner=owners[index]
                observation['owner_matches_test_subject']=[hmac.compare_digest(owner,subject) for subject in subjects] if owner is not None else None
        return {'tool':'auth-two-session','target':target,'observations':results,'body_comparisons':comparisons,
                'limitation':'Tiga GET. Hanya JSON 200 dengan Content-Length maksimal 32 KiB dibandingkan byte, nilai JSON dan struktur di memori; body, nilai field dan hash tidak disimpan. Jika pointer dipilih, field pemilik dibandingkan dengan sub token yang belum diverifikasi; urutan hasil sesuai alias akun. Kecocokan tidak membuktikan bypass atau kepemilikan. Tidak ada redirect.'}
    if plan['scan']['tool']=='inventory-html':
        from inventory_adapter import run
        return await run(plan,guard,exclusions)
    if plan['scan']['tool']=='auth-unauthenticated-get':
        from web_checks import probe
        response=await probe(target,exclusions,guard,method='GET')
        return {'tool':'auth-unauthenticated-get','target':target,'status_code':response['http_status'],
                'redirect_observed':response['redirect_observed'],'tls':response['tls'],
                'limitation':'Satu GET tanpa cookie atau token; status 200 saja bukan bukti bypass. Tidak membaca body atau mengikuti redirect.'}
    if plan['scan']['tool']=='nuclei-head':
        from nuclei_adapter import run
        return await run(plan,guard,exclusions)
    if plan['scan']['tool']=='zap-head':
        from zap_adapter import run
        return await run(plan,guard,exclusions)
    if plan['scan']['tool'] in ('subfinder-passive','amass-passive'):
        from subfinder_adapter import run
        return await run(plan,guard)
    if plan['scan']['tool']=='monitoring-local':
        from local_monitoring import snapshot
        return await snapshot(guard)
    if plan['scan']['tool'] == 'tcp-connect':
        results = []
        for port in ports:
            await guard()
            writer = None
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(target, port), 1)
                status = 'connected'
            except ConnectionRefusedError:
                status = 'refused'
            except (OSError, TimeoutError):
                status = 'inconclusive'
            finally:
                if writer:
                    writer.close()
                    try: await asyncio.wait_for(writer.wait_closed(), 1)
                    except (OSError, TimeoutError): pass
            results.append({'port':port,'status':status})
            await asyncio.sleep(1)
        return {'tool':'tcp-connect','target':target,'ports':results,'limitation':'Konektivitas TCP saja; tidak mengidentifikasi layanan atau kerentanan.'}
    args = [nmap_path(), '-sT', '-n', '-Pn', '--max-retries','0','--max-parallelism','1',
            '--scan-delay','1s','--host-timeout','45s','-p',','.join(map(str,ports)),'-oX','-',target]
    if ipaddress.ip_address(target).version == 6:
        args.insert(1,'-6')
    env = {key:os.environ[key] for key in ('SystemRoot','WINDIR','TEMP','TMP') if key in os.environ}
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, env=env, cwd=str(Path(nmap_path()).resolve().parent),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    try:
        parts=[]; size=0
        while True:
            part=await process.stdout.read(4096)
            if not part:break
            size+=len(part)
            if size>64000:raise ValueError('Output Nmap melebihi batas.')
            parts.append(part)
        await process.wait()
        if process.returncode:raise ValueError('Nmap gagal; tidak ada fallback otomatis.')
        raw=b''.join(parts)
        if b'<!ENTITY' in raw:raise ValueError('XML entity tidak diizinkan.')
        root=ET.fromstring(raw)
        done=root.find('runstats/finished')
        if done is None or done.get('exit')!='success':raise ValueError('Nmap tidak menyelesaikan scan.')
        rows=[]
        for host in root.findall('host'):
            addresses=[item.get('addr') for item in host.findall('address') if item.get('addrtype') in ('ipv4','ipv6')]
            if addresses != [target]:raise ValueError('Target output Nmap berbeda dari rencana.')
            for item in host.findall('ports/port'):
                port=int(item.get('portid'))
                if port not in ports:raise ValueError('Port output tidak disetujui.')
                state=item.find('state')
                rows.append({'port':port,'status':state.get('state') if state is not None else 'unknown'})
        return {'tool':'nmap','target':target,'ports':rows,'binary_sha256':plan['scan']['binary_sha256'],
                'limitation':'TCP connect scan, tanpa NSE, deteksi versi, exploit, atau DNS.'}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


class ScanRunner:
    def __init__(self,jobs,evidence):
        self.jobs,self.evidence=jobs,evidence
        with closing(jobs.engagements.connect()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS bounded_scan_results (job_id TEXT PRIMARY KEY,payload TEXT NOT NULL,payload_hash TEXT NOT NULL)')
            db.commit()

    def live(self,db,owner,jid):
        from security_jobs import digest, LEASE_SECONDS
        from datetime import timedelta
        row=db.execute('SELECT * FROM security_jobs WHERE id=?',(jid,)).fetchone()
        if not row or row['status']!='running' or row['worker']!=owner or not self.jobs.owned(db,owner) or not row['approved_at']:
            raise ValueError('Scan dihentikan atau belum disetujui.')
        self.jobs.open_gate(db,row['engagement_id'])
        plan=json.loads(row['plan'])
        validate_scan(plan,check_binary=False)
        if not plan.get('scan') or digest(plan)!=row['plan_hash']:raise ValueError('Integritas rencana scan gagal.')
        engagement,head=self.jobs.engagements.head(db,row['project_id'],row['engagement_id'])
        content=EngagementContent.model_validate_json(head['content'])
        if content.environment=='production_readonly':
            if plan['scan']['tool'] not in ('nuclei-head','zap-head'):
                raise ValueError('Production hanya mengizinkan pemeriksaan header.')
            from urllib.parse import urlsplit
            from web_checks import public
            try: literal=ipaddress.ip_address(urlsplit(plan['steps'][0]['target']['value']).hostname)
            except ValueError: literal=None
            if literal and not public(literal):raise ValueError('Production hanya mengizinkan IP publik.')
        if plan['scan']['tool']=='auth-two-session' and any(ref not in content.test_account_refs for ref in plan['scan']['account_refs']):raise ValueError('Alias akun tidak ada pada RoE.')
        if evaluate(content,head,engagement,self.jobs.proposals(plan)[0],utc_now(),dns_pinning=uses_pinned_url(plan))['decision']!='pass':
            raise ValueError('Policy tidak mengizinkan scan.')
        db.execute('UPDATE security_job_worker SET expires_at=? WHERE id=1 AND owner=?',((utc_now()+timedelta(seconds=LEASE_SECONDS)).isoformat(),owner))
        return row,plan

    def result(self,db,jid):
        from security_jobs import digest
        row=db.execute('SELECT * FROM bounded_scan_results WHERE job_id=?',(jid,)).fetchone()
        if not row:return None
        payload=json.loads(row['payload'])
        if digest(payload)!=row['payload_hash']:raise HTTPException(409,'Integritas scan gagal.')
        return payload

    async def execute(self,owner,jid):
        from security_jobs import digest,encode
        from security_evidence import EvidenceInput
        task=None
        async def guard():
            with self.jobs.engagements.transaction() as db:self.live(db,owner,jid)
        async def target_guard(target):
            from engagements import ScopeAsset
            with self.jobs.engagements.transaction() as db:
                row,current=self.live(db,owner,jid)
                eng,head=self.jobs.engagements.head(db,row['project_id'],row['engagement_id'])
                content=EngagementContent.model_validate_json(head['content'])
                proposal=self.jobs.proposals(current)[0].model_copy(update={'target':ScopeAsset(kind='url',value=target)})
                if evaluate(content,head,eng,proposal,utc_now(),dns_pinning=True)['decision']!='pass':raise ValueError('TARGET_OUT_OF_SCOPE')
        try:
            with self.jobs.engagements.transaction() as db:
                row,plan=self.live(db,owner,jid)
                _,head=self.jobs.engagements.head(db,row['project_id'],row['engagement_id'])
                exclusions=EngagementContent.model_validate_json(head['content']).out_of_scope
            sessions=self.jobs.sessions.take(jid) if plan['scan']['tool']=='auth-two-session' else None
            if plan['scan']['tool'] in ('scoped-spider','active-reflection','js-bundle-inventory'):
                task=asyncio.create_task(run_scan(plan,guard,exclusions,target_guard=target_guard))
            else:
                task=asyncio.create_task(run_scan(plan,guard,exclusions,sessions) if sessions else run_scan(plan,guard,exclusions))
            while not task.done():
                await asyncio.wait({task},timeout=.2)
                await guard()
            result=await task
            raw=encode(result)
            with self.jobs.engagements.transaction() as db:
                row,plan=self.live(db,owner,jid)
                if row['output_bytes']+len(raw.encode())>plan['max_output_kb']*1024:raise ValueError('Batas output scan tercapai.')
                evidence=self.evidence.add_evidence(row['project_id'],row['engagement_id'],EvidenceInput(
                    job_id=jid,step_ordinal=1,source='external_import',title='Approved tool run · '+result['tool'],captured_at=utc_now(),
                    tool_name=result['tool'],tool_version='adapter-bounded-tool-1',parameters=encode(plan['steps'][0]),content=raw,acknowledge=True),
                    db=db,scan_provenance={'adapter':'bounded-tool-1','tool':result['tool']})
                result.update(evidence_id=evidence['id'])
                db.execute('INSERT INTO bounded_scan_results VALUES (?,?,?)',(jid,encode(result),digest(result)))
                db.execute('UPDATE security_jobs SET output_bytes=output_bytes+? WHERE id=?',(len(raw.encode()),jid))
                self.jobs.finish(db,row,'completed',message='Run adapter disetujui selesai; evidence tersimpan.')
        except asyncio.CancelledError:raise
        except Exception as exc:
            self.jobs.fail(owner,jid,'SCAN_FAILED',type(exc).__name__+': scan dihentikan; periksa RoE, tool dan batas run.')
        finally:
            if task and not task.done():
                task.cancel()
                await asyncio.gather(task,return_exceptions=True)
