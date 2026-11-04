"""Reviewed MCP fixture catalog and gateway. No network/custom server execution."""
import asyncio
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import time
from uuid import UUID,uuid4

from fastapi import APIRouter,HTTPException,Request
from pydantic import Field,StrictBool,model_validator
import config
from engagements import StrictModel,EngagementContent,utc_now
from security_jobs import encode,digest,LEASE_SECONDS,ACTIVE
from security_policy import evaluate,ScopeDriftError
from security_evidence import SafeValidationRoute,EvidenceInput,redactor
from mcp_contracts import ExternalMCPConfig
from mcp_fixture_server import PROTOCOL,VERSION,TOOLS,FIXTURES,inspect_arguments
from mcp_sandbox import SandboxRuntime,SandboxError,supported,exchange,sha_file


def descriptor():
    return {'adapter':'bundled_fixture','server_name':'agentos-fixture','version':VERSION,'protocol':PROTOCOL,
            'tools':TOOLS,'authentication':'managed_stdio_no_external_credentials','isolation':'windows_appcontainer_zero_capabilities',
            'source_hash':sha_file(Path(__file__).with_name('mcp_fixture_server.py')),'pentest_execution_enabled':False}


def external_descriptor(cfg):
    """Stable descriptor derived from an external server's config (secrets never
    included). Clearly marked as running outside the AppContainer fixture sandbox."""
    transport=cfg.get('transport') or {}
    return {'adapter':cfg['adapter'],'server_name':cfg.get('name',''),'protocol':PROTOCOL,
            'transport':{'kind':transport.get('transport'),'command':transport.get('command',''),
                         'args':transport.get('args',[]),'env_keys':transport.get('env_keys',[]),'url':transport.get('url','')},
            'allowed_tools':cfg.get('allowed_tools',[]),'authentication':'external_operator_managed',
            'isolation':'external_no_appcontainer','pentest_execution_enabled':False}


def descriptor_for(cfg):
    return descriptor() if cfg.get('adapter','bundled_fixture')=='bundled_fixture' else external_descriptor(cfg)


class ServerConfig(StrictModel):
    name:str=Field(min_length=1,max_length=120)
    adapter:str=Field(default='bundled_fixture',pattern=r'^(bundled_fixture|external_stdio|external_http)$')
    allowed_tools:list[str]=Field(min_length=1,max_length=8)
    max_wall_seconds:int=Field(default=10,ge=1,le=30,strict=True)
    max_output_kb:int=Field(default=32,ge=1,le=64,strict=True)
    transport:ExternalMCPConfig|None=None

    @model_validator(mode='after')
    def consistent(self):
        if self.adapter=='bundled_fixture':
            if self.transport is not None:
                raise ValueError('Adapter fixture tidak memakai transport eksternal.')
            if len(self.allowed_tools)>2 or len(set(self.allowed_tools))!=len(self.allowed_tools) or any(t not in {x['name'] for x in TOOLS} for t in self.allowed_tools):
                raise ValueError('Only unique reviewed fixture tools are allowed.')
            if self.max_wall_seconds>15:
                raise ValueError('Fixture dibatasi maksimal 15 detik.')
        else:
            # Gated opt-in: external servers are refused unless the operator turned them on.
            if not config.EXTERNAL_MCP_ENABLED:
                raise ValueError('Server MCP eksternal dinonaktifkan. Setel AGENT_ALLOW_EXTERNAL_MCP=1 (default aman: hanya fixture terisolasi).')
            if self.transport is None:
                raise ValueError('Server eksternal memerlukan konfigurasi transport.')
            expected='external_stdio' if self.transport.transport=='stdio' else 'external_http'
            if self.adapter!=expected:
                raise ValueError('Adapter harus sesuai transport (stdio→external_stdio, http→external_http).')
            if len(set(self.allowed_tools))!=len(self.allowed_tools) or any(not t.strip() or len(t)>120 for t in self.allowed_tools):
                raise ValueError('Daftar tool eksternal harus unik dan valid.')
        return self


class EditServer(StrictModel):
    expected_revision:int=Field(ge=1,strict=True)
    config:ServerConfig


class ServerDecision(StrictModel):
    expected_revision:int=Field(ge=1,strict=True)
    action:str=Field(pattern=r'^(approve|disable)$')
    actor_label:str=Field(min_length=1,max_length=120)
    note:str=Field(min_length=1,max_length=1000)
    acknowledge:StrictBool


class CheckServer(StrictModel):
    expected_revision:int=Field(ge=1,strict=True)


class MCPGateway:
    def __init__(self,engagements,jobs,evidence,directory):
        self.engagements,self.jobs,self.evidence=engagements,jobs,evidence
        self.runtime=SandboxRuntime(directory)
        with closing(engagements.connect()) as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    id TEXT PRIMARY KEY, revision INTEGER NOT NULL, state TEXT NOT NULL,
                    config TEXT NOT NULL, config_hash TEXT NOT NULL, descriptor TEXT NOT NULL, descriptor_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, review TEXT
                );
                CREATE TABLE IF NOT EXISTS mcp_server_events (
                    id INTEGER PRIMARY KEY, server_id TEXT NOT NULL REFERENCES mcp_servers(id), revision INTEGER NOT NULL,
                    at TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mcp_connection_checks (
                    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES mcp_servers(id), server_revision INTEGER NOT NULL,
                    at TEXT NOT NULL, result TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mcp_job_results (
                    job_id TEXT PRIMARY KEY REFERENCES security_jobs(id), evidence_id TEXT NOT NULL REFERENCES security_evidence(id),
                    result TEXT NOT NULL, result_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mcp_runner_lease (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT, expires_at TEXT);
            ''')

    def event(self,db,sid,revision,action,actor,note):
        scrub,_=redactor()
        db.execute('INSERT INTO mcp_server_events(server_id,revision,at,action,actor,note) VALUES (?,?,?,?,?,?)',
                   (sid,revision,utc_now().isoformat(),action,scrub(actor),scrub(note)))

    def row(self,db,sid,revision=None,approved=False):
        row=db.execute('SELECT * FROM mcp_servers WHERE id=?',(str(sid),)).fetchone()
        if not row:raise HTTPException(404,'Profil MCP tidak ditemukan.')
        if revision is not None and row['revision']!=revision:raise HTTPException(409,'Revisi profil MCP berubah. Tinjau ulang.')
        if digest(json.loads(row['config']))!=row['config_hash'] or digest(json.loads(row['descriptor']))!=row['descriptor_hash']:
            raise HTTPException(409,'Integritas profil MCP tidak sesuai.')
        if row['descriptor_hash']!=digest(descriptor_for(json.loads(row['config']))):raise HTTPException(409,'Adapter/schema/versi berubah. Buat profil baru dan tinjau ulang.')
        if approved and row['state']!='approved':raise HTTPException(423,'Server MCP belum disetujui atau dinonaktifkan.')
        return row

    def serialize(self,row):
        return {**dict(row),'config':json.loads(row['config']),'descriptor':json.loads(row['descriptor']),
                'review':json.loads(row['review']) if row['review'] else None,'execution_enabled':False}

    def listing(self):
        with closing(self.engagements.connect()) as db:
            servers=[self.serialize(r) for r in db.execute('SELECT * FROM mcp_servers ORDER BY created_at DESC,id')]
        return {'servers':servers,'catalog':descriptor(),'descriptor_hash':digest(descriptor()),'runner_supported':supported(),
                'limits':{'max_servers':20,'max_checks_per_server':100,'concurrency':1,'max_wall_seconds':15,'max_output_kb':64},
                'external_servers_enabled':config.EXTERNAL_MCP_ENABLED,'pentest_execution_enabled':False,'authentication':'managed_local_stdio',
                'approval_mode':'local_attestation'}

    def detail(self,sid):
        with closing(self.engagements.connect()) as db:
            db.execute('BEGIN')
            data=self.serialize(self.row(db,sid))
            data['events']=[dict(r) for r in db.execute('SELECT * FROM mcp_server_events WHERE server_id=? ORDER BY id',(sid,))]
            data['checks']=[{**dict(r),'result':json.loads(r['result'])} for r in db.execute('SELECT * FROM mcp_connection_checks WHERE server_id=? ORDER BY at DESC LIMIT 20',(sid,))]
            return data

    def create(self,body):
        config=body.model_dump(mode='json');scrub,_=redactor();config['name']=scrub(config['name'])
        sid,now=str(uuid4()),utc_now().isoformat();pin=descriptor_for(config)
        with self.engagements.transaction() as db:
            if db.execute('SELECT COUNT(*) FROM mcp_servers').fetchone()[0]>=20:raise HTTPException(409,'Batas 20 profil MCP tercapai.')
            db.execute("INSERT INTO mcp_servers VALUES (?,1,'draft',?,?,?,?,?,?,NULL)",(sid,encode(config),digest(config),encode(pin),digest(pin),now,now))
            self.event(db,sid,1,'created','operator-lokal','Profil baru; tidak ada koneksi atau tool yang dipanggil.')
        return self.detail(sid)

    def cancel_bound(self,db,sid,note):
        for row in db.execute("SELECT * FROM security_jobs WHERE status IN ('awaiting_approval','queued','running')").fetchall():
            binding=json.loads(row['plan']).get('mcp')
            if binding and binding['server_id']==sid:self.jobs.finish(db,row,'cancelled','MCP_PROFILE_CHANGED',note)

    def edit(self,sid,body):
        config=body.config.model_dump(mode='json');scrub,_=redactor();config['name']=scrub(config['name'])
        with self.engagements.transaction() as db:
            row=self.row(db,sid,body.expected_revision)
            if row['revision']>=100:raise HTTPException(409,'Batas 100 revisi profil MCP tercapai.')
            db.execute("UPDATE mcp_servers SET config=?,config_hash=?,state='draft',revision=revision+1,updated_at=?,review=NULL WHERE id=?",(encode(config),digest(config),utc_now().isoformat(),sid))
            self.cancel_bound(db,sid,'Profil MCP berubah; job dibatalkan dan memerlukan rencana/persetujuan baru.')
            self.event(db,sid,row['revision']+1,'edited','operator-lokal','Persetujuan dicabut; parameter baru harus ditinjau ulang.')
        return self.detail(sid)

    def decide(self,sid,body):
        if not body.acknowledge:raise HTTPException(422,'Konfirmasi review profil MCP wajib.')
        with self.engagements.transaction() as db:
            row=self.row(db,sid,body.expected_revision)
            if row['revision']>=100:raise HTTPException(409,'Batas revisi profil tercapai.')
            state='approved' if body.action=='approve' else 'disabled'
            if row['state']==state:raise HTTPException(409,'Status profil tidak berubah.')
            scrub,_=redactor()
            review={'actor_label':scrub(body.actor_label),'note':scrub(body.note),'at':utc_now().isoformat(),'mode':'local_attestation'}
            db.execute('UPDATE mcp_servers SET state=?,revision=revision+1,updated_at=?,review=? WHERE id=?',(state,utc_now().isoformat(),encode(review),sid))
            if state=='disabled':self.cancel_bound(db,sid,'Server MCP dinonaktifkan oleh operator.')
            self.event(db,sid,row['revision']+1,body.action,body.actor_label,body.note)
        return self.detail(sid)

    def validate(self,db,plan):
        binding=plan['mcp']
        row=self.row(db,binding['server_id'],binding['server_revision'],approved=True)
        config=json.loads(row['config'])
        if config.get('adapter','bundled_fixture')!='bundled_fixture':
            raise HTTPException(422,'Hanya fixture terisolasi yang dapat dijalankan sebagai job. Server eksternal hanya untuk health-check/hot-reload.')
        if binding['descriptor_hash']!=row['descriptor_hash']:raise HTTPException(409,'Hash adapter MCP berubah.')
        if binding['tool'] not in config['allowed_tools']:raise HTTPException(403,'Tool MCP tidak diizinkan pada profil ini.')
        try:inspect_arguments(binding['tool'],binding['arguments'])
        except ValueError:raise HTTPException(422,'Argumen MCP tidak sesuai schema terkurasi.') from None
        if len(plan['steps'])!=1 or plan['steps'][0]['action']!='configuration_review':raise HTTPException(422,'MCP fixture hanya untuk satu rencana review konfigurasi offline.')
        if plan['wall_timeout_seconds']>config['max_wall_seconds'] or plan['max_output_kb']>config['max_output_kb']:
            raise HTTPException(422,'Batas job melampaui batas profil MCP.')
        if not supported():raise HTTPException(503,'AppContainer Windows tidak tersedia; tidak ada fallback proses biasa.')
        return row

    def runner_lease(self,db,owner,initial=False):
        now=utc_now();row=db.execute('SELECT * FROM mcp_runner_lease WHERE id=1').fetchone()
        if initial:
            if row and row['owner']!=owner and row['expires_at'] and row['expires_at']>now.isoformat():raise HTTPException(409,'Runner MCP sedang dipakai. Coba setelah selesai.')
            db.execute('INSERT INTO mcp_runner_lease VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at',(owner,(now+timedelta(seconds=10)).isoformat()))
        else:
            if not row or row['owner']!=owner or row['expires_at']<=now.isoformat():raise SandboxError('MCP runner lease lost.')
            db.execute('UPDATE mcp_runner_lease SET expires_at=? WHERE id=1 AND owner=?',((now+timedelta(seconds=10)).isoformat(),owner))

    def release_runner(self,owner):
        with self.engagements.transaction() as db:db.execute('UPDATE mcp_runner_lease SET owner=NULL,expires_at=NULL WHERE id=1 AND owner=?',(owner,))

    async def handshake(self,process,guard,deadline,limit):
        initialized=await exchange(process,'initialize',{'protocolVersion':PROTOCOL,'capabilities':{},'clientInfo':{'name':'Jo Workspace','version':'1.5.0'}},1,guard,deadline,limit)
        expected={'protocolVersion':PROTOCOL,'capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'agentos-fixture','version':VERSION}}
        if initialized!=expected:raise SandboxError('MCP version/capability mismatch.')
        await guard()
        process.send({'jsonrpc':'2.0','method':'notifications/initialized'})
        tools=await exchange(process,'tools/list',{},2,guard,deadline,limit)
        if tools!={'tools':TOOLS}:raise SandboxError('MCP tool catalog/schema mismatch.')
        return {'initialize':initialized,'tools_list':tools}

    def _store_check(self,sid,revision,result):
        with self.engagements.transaction() as db:
            self.row(db,sid,revision,approved=True)
            db.execute('INSERT INTO mcp_connection_checks VALUES (?,?,?,?,?)',(str(uuid4()),sid,revision,utc_now().isoformat(),encode(result)))
            self.event(db,sid,revision,'connection_check','system',result['status'])
        return result

    async def external_health(self,sid,revision):
        """Health-check an approved external MCP server via the bounded external runner
        (NOT the AppContainer fixture sandbox). Records the result like a fixture check."""
        with closing(self.engagements.connect()) as db:
            row=self.row(db,sid,revision,approved=True)
            server=json.loads(row['config'])
        from mcp_external_runner import health_check
        try:
            result=await health_check(server['transport'],server['max_wall_seconds'],server['max_output_kb'])
        except asyncio.CancelledError:raise
        except Exception as exc:
            result={'status':'failed','message':str(exc)[:300],'isolation':'external_no_appcontainer','tool_called':False}
        result['adapter']=server['adapter']
        return self._store_check(sid,revision,result)

    async def check(self,sid,revision):
        with closing(self.engagements.connect()) as db:
            row=self.row(db,sid,revision,approved=True)
            if db.execute('SELECT COUNT(*) FROM mcp_connection_checks WHERE server_id=?',(sid,)).fetchone()[0]>=100:raise HTTPException(409,'Batas 100 pemeriksaan koneksi tercapai.')
            external=json.loads(row['config']).get('adapter','bundled_fixture')!='bundled_fixture'
        if external:
            return await self.external_health(sid,revision)
        owner='check:'+str(uuid4());process=None;leased=False
        try:
            await asyncio.to_thread(self.runtime.prepare)
            with self.engagements.transaction() as db:
                self.row(db,sid,revision,approved=True);self.runner_lease(db,owner,initial=True);leased=True
            async def guard():
                with self.engagements.transaction() as db:self.row(db,sid,revision,approved=True);self.runner_lease(db,owner)
            await guard();process=self.runtime.start()
            transcript=await self.handshake(process,guard,time.monotonic()+5,65536)
            result={'status':'passed','handshake':transcript,'isolation':self.attestation(process.pid),'tool_called':False,'pentest_executed':False}
        except asyncio.CancelledError:raise
        except Exception as exc:
            if isinstance(exc,HTTPException):raise
            result={'status':'failed','message':str(exc)[:300],'tool_called':False,'pentest_executed':False}
        finally:
            if process:process.close()
            if leased:self.release_runner(owner)
        with self.engagements.transaction() as db:
            self.row(db,sid,revision,approved=True)
            db.execute('INSERT INTO mcp_connection_checks VALUES (?,?,?,?,?)',(str(uuid4()),sid,revision,utc_now().isoformat(),encode(result)))
            self.event(db,sid,revision,'connection_check','system',result['status'])
        return result

    async def reload(self,sid,body):
        """Hot-reload: refresh a server's config/ENV and re-run its health check at
        runtime without stopping FastAPI (servers are spawned per-use, not persistent)."""
        with self.engagements.transaction() as db:
            row=self.row(db,sid,body.expected_revision)
            server=json.loads(row['config']);state=row['state']
            external=server.get('adapter','bundled_fixture')!='bundled_fixture'
            if external and not config.EXTERNAL_MCP_ENABLED:
                raise HTTPException(409,'Server eksternal dinonaktifkan oleh kebijakan runtime; hot-reload tidak tersedia.')
            self.event(db,sid,row['revision'],'reloaded','operator-lokal','Konfigurasi dimuat ulang saat runtime; proses FastAPI tidak dihentikan.')
        if external and state=='approved':
            return await self.external_health(sid,body.expected_revision)
        return self.detail(sid)

    def attestation(self,pid):
        return {'backend':'windows_appcontainer','appcontainer_token_verified':True,'capabilities':[], 'network_allowed':False,
                'private_workspace_mounted':False,'credentials_inherited':False,'max_processes':1,'memory_mb':256,
                'kill_tree_on_job_close':True,'pid':pid}

    def live(self,db,owner,jid):
        row=db.execute('SELECT * FROM security_jobs WHERE id=?',(jid,)).fetchone()
        if not row or row['status']!='running' or row['worker']!=owner or not self.jobs.owned(db,owner):raise SandboxError('Job stopped or worker lease lost.')
        plan=json.loads(row['plan'])
        if digest(plan)!=row['plan_hash']:raise SandboxError('PLAN_INTEGRITY')
        self.jobs.open_gate(db,row['engagement_id']);self.validate(db,plan)
        engagement,head=self.engagements.head(db,row['project_id'],row['engagement_id'])
        # Scope-drift interceptor: hard-block if any target hidden in the MCP tool
        # arguments leaves the approved scope before the fixture is executed.
        self.engagements.assert_in_scope(db,row['project_id'],row['engagement_id'],plan['mcp']['arguments'])
        policy=evaluate(EngagementContent.model_validate_json(head['content']),head,engagement,self.jobs.proposals(plan)[0],utc_now())
        if policy['decision']!='pass':raise SandboxError('POLICY_DENIED')
        db.execute('UPDATE security_job_worker SET expires_at=? WHERE id=1 AND owner=?',((utc_now()+timedelta(seconds=LEASE_SECONDS)).isoformat(),owner))
        return row,plan

    async def execute(self,owner,jid):
        process=None;leased=False;lease_owner='job:'+jid
        try:
            await asyncio.to_thread(self.runtime.prepare)
            with self.engagements.transaction() as db:
                row,plan=self.live(db,owner,jid);self.runner_lease(db,lease_owner,initial=True);leased=True
            async def guard():
                with self.engagements.transaction() as db:self.live(db,owner,jid);self.runner_lease(db,lease_owner)
            await guard();process=self.runtime.start()
            limit=plan['max_output_kb']*1024-row['output_bytes']
            deadline=time.monotonic()+plan['wall_timeout_seconds']
            transcript=await self.handshake(process,guard,deadline,limit)
            binding=plan['mcp']
            result=await exchange(process,'tools/call',{'name':binding['tool'],'arguments':binding['arguments']},3,guard,deadline,limit)
            expected_data={'fixture_only':True,'pentest_executed':False,'tool':binding['tool'],'fixtures':{k:FIXTURES[v] for k,v in binding['arguments'].items()}}
            expected={'content':[{'type':'text','text':json.dumps(expected_data,separators=(',',':'))}],'structuredContent':expected_data,'isError':False}
            if result!=expected:raise SandboxError('MCP result schema/content mismatch.')
            transcript['tools_call']=result
            raw=encode(transcript)
            if len(raw.encode())>limit:raise SandboxError('OUTPUT_LIMIT')
            attestation=self.attestation(process.pid)
            # Close/kill all child handles before recording successful completion.
            process.close();process=None
            with self.engagements.transaction() as db:
                row,plan=self.live(db,owner,jid)
                body=EvidenceInput(job_id=jid,step_ordinal=1,source='synthetic_fixture',title='MCP fixture · '+binding['tool'],
                    captured_at=utc_now(),tool_name='agentos-fixture/'+binding['tool'],tool_version=VERSION,
                    parameters=encode(binding),content=raw,acknowledge=True)
                evidence=self.evidence.add_evidence(row['project_id'],row['engagement_id'],body,db=db,
                    mcp_provenance={'binding':binding,'isolation':attestation,'fixture_only':True,'pentest_executed':False})
                payload={'structured_result':result,'isolation':attestation,'binding':binding,'evidence_id':evidence['id'],
                         'fixture_only':True,'pentest_executed':False,'trust':'untrusted_tool_output','model_called':False}
                db.execute('INSERT INTO mcp_job_results VALUES (?,?,?,?)',(jid,evidence['id'],encode(payload),digest(payload)))
                db.execute('UPDATE security_jobs SET output_bytes=output_bytes+? WHERE id=?',(len(raw.encode()),jid))
                self.jobs.event(db,jid,'mcp_fixture_completed',note='MCP fixture selesai dalam AppContainer; bukti otomatis tersimpan. Tidak ada pentest.')
                self.jobs.finish(db,row,'completed')
        except asyncio.CancelledError:raise
        except ScopeDriftError as drift:
            try:
                with closing(self.engagements.connect()) as audit:
                    found=audit.execute('SELECT engagement_id FROM security_jobs WHERE id=?',(jid,)).fetchone()
                if found:self.engagements.record_scope_violation(found['engagement_id'],'mcp_fixture',drift.report)
            except Exception:pass
            self.jobs.fail(owner,jid,'MCP_SCOPE_DRIFT','Target di luar scope terdeteksi sebelum eksekusi; fixture dihentikan dan pelanggaran dicatat.')
        except Exception as exc:
            code='MCP_OUTPUT_LIMIT' if 'OUTPUT_LIMIT' in str(exc) else 'MCP_POLICY_DENIED' if 'POLICY_DENIED' in str(exc) else 'MCP_GUARD_DENIED' if isinstance(exc,HTTPException) else 'MCP_RUNNER_FAILED'
            messages={'MCP_OUTPUT_LIMIT':'Output fixture melampaui anggaran; hasil policy sebelumnya dipertahankan.',
                      'MCP_POLICY_DENIED':'Policy/RoE berubah atau kedaluwarsa; fixture dihentikan, tidak ada pentest.',
                      'MCP_GUARD_DENIED':'Gerbang katalog/RoE atau penyimpanan evidence menolak penyelesaian fixture.',
                      'MCP_RUNNER_FAILED':'Runner/protokol/isolation fixture gagal. Tidak ada fallback atau retry otomatis.'}
            self.jobs.fail(owner,jid,code,messages[code])
        finally:
            if process:process.close()
            if leased:self.release_runner(lease_owner)

    def result(self,project,eid,jid):
        with closing(self.engagements.connect()) as db:
            self.jobs.job(db,project,eid,jid)
            row=db.execute('SELECT * FROM mcp_job_results WHERE job_id=?',(jid,)).fetchone()
            if not row:return None
            payload=json.loads(row['result'])
            if digest(payload)!=row['result_hash']:raise HTTPException(409,'Integritas hasil MCP tidak sesuai.')
            return {**payload,'hash':row['result_hash']}


router=APIRouter(prefix='/api/security/mcp',tags=['MCP — isolated fixture only'],route_class=SafeValidationRoute)


@router.get('/servers')
async def servers(request:Request):return request.app.state.mcp.listing()


@router.post('/servers',status_code=201)
async def create_server(body:ServerConfig,request:Request):return request.app.state.mcp.create(body)


@router.get('/servers/{server_id}')
async def server(server_id:UUID,request:Request):return request.app.state.mcp.detail(str(server_id))


@router.put('/servers/{server_id}')
async def edit_server(server_id:UUID,body:EditServer,request:Request):return request.app.state.mcp.edit(str(server_id),body)


@router.post('/servers/{server_id}/decisions')
async def decide_server(server_id:UUID,body:ServerDecision,request:Request):return request.app.state.mcp.decide(str(server_id),body)


@router.post('/servers/{server_id}/check')
async def check_server(server_id:UUID,body:CheckServer,request:Request):return await request.app.state.mcp.check(str(server_id),body.expected_revision)


@router.post('/servers/{server_id}/reload')
async def reload_server(server_id:UUID,body:CheckServer,request:Request):return await request.app.state.mcp.reload(str(server_id),body)
