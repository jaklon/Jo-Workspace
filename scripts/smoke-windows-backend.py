"""Exercise the frozen backend from a clean working directory, without Python on PATH."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
from datetime import datetime, timedelta, timezone
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

parser = argparse.ArgumentParser()
parser.add_argument("executable", type=Path)
parser.add_argument("web", type=Path)
args = parser.parse_args()
executable, web = args.executable.resolve(), args.web.resolve()
token = secrets.token_urlsafe(32)
LEGACY_OPTIONS = [name for name in ('JO_SMOKE_AUTH_GUARDS', 'JO_SMOKE_MONITORING', 'JO_SMOKE_HEAD_TOOLS', 'JO_SMOKE_RECON',
                                    'JO_SMOKE_DOMAIN', 'JO_SMOKE_SPIDER', 'JO_SMOKE_LLM') if os.environ.get(name) == '1']
if LEGACY_OPTIONS:
    raise SystemExit('Opsi smoke v1 (' + ', '.join(LEGACY_OPTIONS) + ') memakai endpoint eksekusi langsung yang di v2.0 '
                     'dikunci (423) dan hanya berjalan lewat konfirmasi chat. Gunakan scripts/live_chat_first_check.py.')


def sse_events(response):
    return [json.loads(line[5:]) for line in response.read().decode('utf-8').splitlines() if line.startswith('data:')]


def expect_locked(call):
    try:
        call()
    except HTTPError as error:
        assert error.code == 423, error.code
        return
    raise AssertionError('Endpoint eksekusi langsung tidak dikunci')
with tempfile.TemporaryDirectory(prefix="agent-frozen-smoke-") as directory:
    root = Path(directory)
    environment = {**os.environ, "AGENT_DATA_DIR": str(root / "runtime"),
                   "AGENT_WORKSPACE": str(root / "workspace"), "AGENT_WEB_DIR": str(web),
                   "AGENT_API_TOKEN": token, "PATH": str(Path(os.environ["SystemRoot"]) / "System32")}
    if os.environ.get('JO_SMOKE_HEAD_TOOLS')=='1' or os.environ.get('JO_SMOKE_RECON')=='1' or os.environ.get('JO_SMOKE_DOMAIN')=='1':
        docker=shutil.which('docker')
        assert docker,'Docker required for integration smoke'
        environment['PATH']+=os.pathsep+str(Path(docker).resolve().parent)
    with (root / "backend.log").open("w+") as log:
        process = subprocess.Popen([str(executable), "--port", "18011", "--parent-pid", str(os.getpid())],
                                   cwd=root, env=environment, stdout=log, stderr=log,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        def request(path, data=None, authenticated=True, timeout=20):
            headers = {"Authorization": "Bearer " + token} if authenticated else {}
            if data is not None:
                headers["Content-Type"] = "application/json"
            return urlopen(Request("http://127.0.0.1:18011" + path, data=json.dumps(data).encode() if data is not None else None, headers=headers), timeout=timeout)
        try:
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with request("/api/metrics") as response:
                        assert response.status == 200
                    break
                except URLError:
                    if time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError("Frozen backend startup timed out: " + log.read())
                    time.sleep(0.25)
            with request("/", authenticated=False) as response:
                assert b'Jo Workspace' in response.read()
            with request("/api/settings") as response:
                settings = json.load(response)
                assert settings["workspace"] == str(root / "workspace")
                assert settings["max_upload_mb"] == 8
            with request("/api/settings", settings["settings"]) as response:
                assert response.status == 200
            assert (root / "runtime" / "settings.json").is_file()
            with request("/api/usage") as response:
                assert json.load(response)["rows"] == []
            with request("/api/session", {"token": token}, authenticated=False) as response:
                assert "HttpOnly" in response.headers["Set-Cookie"]
            try:
                request("/api/settings", authenticated=False)
                raise AssertionError("Unauthenticated settings accepted")
            except HTTPError as error:
                assert error.code == 401
            with request("/api/security/capabilities") as response:
                security = json.load(response)
                assert security["stage"] == 7 and security["execution_enabled"] is False
            expect_locked(lambda: request('/api/pentest/capabilities'))
            with request('/api/security/mcp/servers') as response:
                assert json.load(response)['runner_supported'] is True
            with request('/api/security/mcp/servers',{'name':'Frozen fixture QA','allowed_tools':['fixture.inspect']}) as response:
                profile=json.load(response)
            with request('/api/security/mcp/servers/'+profile['id']+'/decisions',{'expected_revision':profile['revision'],'action':'approve','actor_label':'QA','note':'Bundled fixture handshake only','acknowledge':True}) as response:
                profile=json.load(response)
            expect_locked(lambda: request('/api/security/mcp/servers/'+profile['id']+'/check',{'expected_revision':profile['revision']}))
            with request('/api/security/agents/catalog') as response:
                assert len(json.load(response)['profiles'])==5
            with request('/api/search/capabilities') as response:
                search=json.load(response)
                assert search['provider']=='SearXNG' and search['images_supported'] is True
            try:
                request('/api/search/image?url=http%3A%2F%2F127.0.0.1%2Fsecret')
                raise AssertionError('Unsafe image URL accepted')
            except HTTPError as error:
                assert error.code==422
            project = "/api/security/projects/00000000-0000-4000-8000-000000000001/engagements"
            with request(project, {"content": {"name": "Frozen QA", "timezone": "Asia/Jakarta"}}) as response:
                engagement = json.load(response)
                assert response.status == 201 and engagement["versions"][0]["status"] == "draft"
            with request(project + "/" + engagement["id"]) as response:
                assert json.load(response)["id"] == engagement["id"]
            expect_locked(lambda: request(project + "/" + engagement["id"] + '/deep-analysis/capabilities'))
            with request(project + "/" + engagement["id"] + '/deep-analysis') as response:
                assert json.load(response)['items'] == []
            assert (root / "runtime" / "engagements.sqlite3").is_file()
            with request("/api/security/scope-validation", {"content": {"name": "Frozen policy", "in_scope": [{"kind": "ip", "value": "10.10.0.25"}], "out_of_scope": [{"kind": "cidr", "value": "10.10.0.0/24"}]}}) as response:
                assert json.load(response)["valid"] is False
            proposal = {"expected_revision": engagement["revision"], "roe_version": 1, "content_hash": engagement["versions"][0]["content_hash"], "target": {"kind": "ip", "value": "10.10.0.25"}, "action": "tcp_discovery", "ports": [443]}
            with request(project + "/" + engagement["id"] + "/policy-checks", proposal) as response:
                policy = json.load(response)
                assert policy["decision"] == "deny" and policy["grants_execution"] is False
            with request(project + "/" + engagement["id"] + "/policy-checks") as response:
                assert json.load(response)["items"][0]["id"] == policy["id"]

            for path, payload, expected in [
                (project + "/" + engagement["id"] + "/decisions", {"expected_revision": 1, "action": "submit", "actor_label": "QA"}, 422),
                ("/api/pentest/run", {}, 423),
            ]:
                try:
                    request(path, payload)
                    raise AssertionError("Unsafe or incomplete action accepted")
                except HTTPError as error:
                    assert error.code == expected, (path, error.code)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0))
                listener.listen(2)
                port=listener.getsockname()[1]
                now=datetime.now(timezone.utc)
                content={'name':'Frozen TCP QA','objective':'Single fixture TCP connection','owner':'QA','contact':'QA',
                    'environment':'lab','authorization_ref':'Local synthetic fixture','in_scope':[{'kind':'ip','value':'127.0.0.1'}],
                    'out_of_scope':[],'ports':[port],'allowed_actions':['tcp_discovery'],
                    'starts_at':(now-timedelta(minutes=1)).isoformat(),'ends_at':(now+timedelta(minutes=10)).isoformat(),
                    'timezone':'Asia/Jakarta','max_http_rps':1,'max_concurrency':1,'max_duration_minutes':1,
                    'emergency_contact':'QA','stop_conditions':'Operator stop','test_account_refs':[]}
                with request(project,{'content':content}) as response:eng=json.load(response)
                path=project+'/'+eng['id']
                for action in ('submit','approve'):
                    with request(path+'/decisions',{'expected_revision':eng['revision'],'action':action,
                        'actor_label':'QA','note':'Local fixture only','acknowledge':True}) as response:eng=json.load(response)
                head=eng['versions'][0]
                expect_locked(lambda: request(path+'/jobs',{'name':'Frozen TCP scan'}))
                expect_locked(lambda: request('/api/pentest/run',{'project_id':eng['project_id'],'engagement_id':eng['id']}))
            if os.environ.get('JO_SMOKE_SKIP_CHAT') == '1':
                print('Chat-First TCP dilewati (JO_SMOKE_SKIP_CHAT=1).', flush=True)
            else:
                # Chat-First: proposal -> confirmation -> Auto-RoE -> real loopback TCP job -> evidence.
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(4)
                    port = listener.getsockname()[1]
                    chat_project = '00000000-0000-4000-8000-000000000002'
                    prompt = f'Jalankan tcp-connect ke IP 127.0.0.1 port {port} di lab dengan mode blackbox'
                    with request('/api/chat', {'prompt': prompt, 'session_id': 'frozen-smoke', 'project_id': chat_project,
                                               'unified': True}, timeout=600) as response:
                        rows = sse_events(response)
                    actions = [row['action'] for row in rows if row['type'] == 'action_proposal']
                    assert actions, ('Kartu konfirmasi tidak muncul (Ollama/model reasoning aktif?)', rows)
                    base = '/api/security/projects/' + chat_project + '/engagements'
                    with request(base) as response:
                        assert json.load(response)['items'] == [], 'Engagement dibuat sebelum konfirmasi'
                    with request('/api/chat/actions/' + actions[0]['id'] + '/confirm',
                                 {'session_id': 'frozen-smoke', 'approve': True}, timeout=900) as response:
                        rows = sse_events(response)
                    errors = [row for row in rows if row['type'] == 'error']
                    assert not errors, errors
                    report = next(row.get('result', '') for row in rows if row['type'] == 'result')
                    assert 'Evidence:' in report, report
                    with request(base) as response:
                        engagements = json.load(response)['items']
                    assert len(engagements) == 1
                    with request(base + '/' + engagements[0]['id'] + '/jobs') as response:
                        jobs = json.load(response)['items']
                    assert jobs and all(job['status'] == 'completed' for job in jobs), jobs
                    with request(base + '/' + engagements[0]['id'] + '/jobs/' + jobs[0]['id']) as response:
                        done = json.load(response)
                    assert done['scan_result']['ports'][0]['status'] == 'connected', done
                    with request(base + '/' + engagements[0]['id'] + '/evidence/' + done['scan_result']['evidence_id']) as response:
                        assert json.load(response)['provenance'] == 'server_approved_tcp_scan'
                    print('Frozen Chat-First TCP passed; Deep Analysis ' +
                          ('gagal: ' + report.split('Deep Analysis gagal:')[1][:200] if 'Deep Analysis gagal' in report else 'selesai'),
                          flush=True)
            if os.environ.get('JO_SMOKE_AUTH_GUARDS') == '1':
                now=datetime.now(timezone.utc)
                target={'kind':'url','value':'https://127.0.0.1/private'}
                content.update(name='Frozen auth guard QA',environment='lab',in_scope=[target],out_of_scope=[],ports=[443],
                    allowed_actions=['authenticated_api_review'],test_account_refs=['fixture-a','fixture-b'],max_duration_minutes=1,
                    starts_at=(now-timedelta(minutes=1)).isoformat(),ends_at=(now+timedelta(minutes=10)).isoformat())
                with request(project,{'content':content}) as response:eng=json.load(response)
                path=project+'/'+eng['id']
                for decision in ('submit','approve'):
                    with request(path+'/decisions',{'expected_revision':eng['revision'],'action':decision,'actor_label':'QA',
                        'note':'Synthetic guard fixture only','acknowledge':True}) as response:eng=json.load(response)
                head=eng['versions'][0]
                with request(path+'/jobs',{'name':'Frozen session guard','expected_roe_revision':eng['revision'],
                    'roe_version':head['version'],'content_hash':head['content_hash'],
                    'scan':{'tool':'auth-two-session','binary_sha256':'','account_refs':['fixture-a','fixture-b']},
                    'wall_timeout_seconds':60,'max_output_kb':64,
                    'steps':[{'target':target,'action':'authenticated_api_review','ports':[443],
                        'max_http_rps':1,'max_concurrency':1,'max_duration_minutes':1,'test_account_ref':'fixture-a'}]}) as response:job=json.load(response)
                approval={'expected_revision':job['revision'],'actor_label':'QA','note':'No network target','acknowledge':True}
                try:
                    request(path+'/jobs/'+job['id']+'/approve',approval)
                    raise AssertionError('Sessions required')
                except HTTPError as error:assert error.code==422
                def fake_token(subject):
                    payload=base64.urlsafe_b64encode(json.dumps({'sub':subject,'aud':'fixture'}).encode()).decode().rstrip('=')
                    return 'e30.'+payload+'.signature'
                tokens=[fake_token('a'),fake_token('b')]
                with request(path+'/jobs/'+job['id']+'/approve',{**approval,'session_tokens':tokens}) as response:queued=json.load(response)
                assert queued['status']=='queued' and all(token not in json.dumps(queued) for token in tokens)
                deadline=time.monotonic()+20
                while True:
                    with request(path+'/jobs/'+job['id']) as response:done=json.load(response)
                    if done['status'] in ('completed','failed','cancelled'):break
                    assert time.monotonic()<deadline
                    time.sleep(.3)
                assert done['status']=='failed' and 'ValueError' in done['error_message'],done
                assert all(token not in json.dumps(done) for token in tokens)
                print('Frozen session guard passed: rejects no-session approval and non-public DNS without target request.',flush=True)
            if os.environ.get('JO_SMOKE_MONITORING') == '1':
                now=datetime.now(timezone.utc)
                content.update(name='Frozen monitoring QA',ports=[3000,9090],allowed_actions=['monitoring_read'],
                    starts_at=(now-timedelta(minutes=1)).isoformat(),ends_at=(now+timedelta(minutes=10)).isoformat())
                with request(project,{'content':content}) as response:eng=json.load(response)
                path=project+'/'+eng['id']
                for action in ('submit','approve'):
                    with request(path+'/decisions',{'expected_revision':eng['revision'],'action':action,
                        'actor_label':'QA','note':'Local monitoring stack only','acknowledge':True}) as response:eng=json.load(response)
                head=eng['versions'][0]
                with request(path+'/jobs',{'name':'Frozen monitoring read','expected_roe_revision':eng['revision'],
                    'roe_version':head['version'],'content_hash':head['content_hash'],
                    'scan':{'tool':'monitoring-local','binary_sha256':''},'wall_timeout_seconds':60,'max_output_kb':64,
                    'steps':[{'target':{'kind':'ip','value':'127.0.0.1'},'action':'monitoring_read','ports':[3000,9090],
                              'max_http_rps':1,'max_concurrency':1,'max_duration_minutes':1,'test_account_ref':''}]}) as response:scan=json.load(response)
                with request('/api/pentest/run',{'project_id':eng['project_id'],'engagement_id':eng['id'],'job_id':scan['id'],
                    'expected_revision':scan['revision'],'actor_label':'QA','note':'Approved monitoring snapshot','acknowledge':True}) as response:
                    assert json.load(response)['status']=='queued'
                deadline=time.monotonic()+20
                while True:
                    with request(path+'/jobs/'+scan['id']) as response:done=json.load(response)
                    if done['status'] in ('completed','failed','cancelled'):break
                    assert time.monotonic()<deadline,'Monitoring timeout'
                    time.sleep(.2)
                assert done['status']=='completed',done
                assert done['scan_result']['grafana_database_ok'],done
                with request(path+'/evidence/'+done['scan_result']['evidence_id']) as response:
                    assert json.load(response)['provenance']=='server_approved_tool_run'
                if os.environ.get('JO_SMOKE_LLM') == '1':
                    model=os.environ.get('JO_SMOKE_MODEL','qwen2.5:3b-instruct')
                    with request(path+'/deep-analysis',{'job_id':scan['id'],'model':model,
                        'actor_label':'QA','acknowledge':True,'assessment_mode':'blackbox',
                        'evidence_kind':'external_observation'},timeout=240) as response:analysis=json.load(response)
                    assert analysis['tool_execution']=='approved_tool_run'
                    assert analysis['source']['result']['tool']=='monitoring-local'
                    assert analysis['output']['summary'] and analysis['status']=='needs_human_review'
                    with request(path+'/deep-analysis') as response:
                        assert json.load(response)['items'][0]['id']==analysis['id']
                    with request('/api/chat',{'prompt':'Deep analisis ip:127.0.0.1 BlackBox',
                        'project_id':eng['project_id'],'target':'reasoning','web_mode':'off'}) as response:
                        events=[json.loads(line[6:]) for line in response.read().decode().splitlines() if line.startswith('data: ')]
                    assert not any(row['type']=='error' for row in events),events
                    answer=next(row['result'] for row in events if row['type']=='result')
                    assert analysis['output']['summary'] in answer and analysis['source']['evidence_id'] in answer
                    print('Frozen local LLM + persisted monitoring report + Project chat passed:',model,flush=True)
            if os.environ.get('JO_SMOKE_HEAD_TOOLS') == '1' or os.environ.get('JO_SMOKE_RECON') == '1':
                methods=[]
                class Fixture(BaseHTTPRequestHandler):
                    def do_HEAD(self):
                        methods.append('HEAD')
                        self.send_response(200)
                        self.send_header('Content-Type','text/html')
                        self.send_header('Content-Length','0')
                        self.end_headers()
                    def log_message(self,*args):pass
                fixture=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
                thread=Thread(target=fixture.serve_forever,daemon=True)
                thread.start()
                cases=[]
                if os.environ.get('JO_SMOKE_HEAD_TOOLS') == '1':
                    cases.extend([('nuclei-head','nuclei_binary_sha256',1),('zap-head','zap_image_sha256',3)])
                if os.environ.get('JO_SMOKE_RECON') == '1':
                    cases.extend([('subfinder-passive','subfinder_image_sha256',2),('amass-passive','amass_image_sha256',4)])
                try:
                    for tool,key,minutes in cases:
                        assert execution_catalog.get(key),tool+' dependency missing'
                        recon=tool.endswith('-passive')
                        target={'kind':'domain','value':'example.invalid'} if recon else {'kind':'url','value':f'http://127.0.0.1:{fixture.server_port}/'}
                        action='passive_recon' if recon else 'http_headers'
                        ports=[443] if recon else [fixture.server_port]
                        now=datetime.now(timezone.utc)
                        content.update(name='Frozen '+tool+' QA',in_scope=[target],ports=ports,allowed_actions=[action],max_duration_minutes=minutes,
                            starts_at=(now-timedelta(minutes=1)).isoformat(),ends_at=(now+timedelta(minutes=10)).isoformat())
                        with request(project,{'content':content}) as response:eng=json.load(response)
                        path=project+'/'+eng['id']
                        for decision in ('submit','approve'):
                            with request(path+'/decisions',{'expected_revision':eng['revision'],'action':decision,
                                'actor_label':'QA','note':'Synthetic fixture or reserved domain only','acknowledge':True}) as response:eng=json.load(response)
                        head=eng['versions'][0]
                        with request(path+'/jobs',{'name':'Frozen '+tool,'expected_roe_revision':eng['revision'],
                            'roe_version':head['version'],'content_hash':head['content_hash'],
                            'scan':{'tool':tool,'binary_sha256':execution_catalog[key],'provider_disclosure':recon},
                            'wall_timeout_seconds':minutes*60,'max_output_kb':64,
                            'steps':[{'target':target,'action':action,'ports':ports,'max_http_rps':1,
                                      'max_concurrency':1,'max_duration_minutes':minutes,'test_account_ref':''}]}) as response:scan=json.load(response)
                        with request('/api/pentest/run',{'project_id':eng['project_id'],'engagement_id':eng['id'],'job_id':scan['id'],
                            'expected_revision':scan['revision'],'actor_label':'QA','note':'Approved synthetic integration run','acknowledge':True}) as response:
                            assert json.load(response)['status']=='queued'
                        deadline=time.monotonic()+minutes*60+10
                        while True:
                            with request(path+'/jobs/'+scan['id']) as response:done=json.load(response)
                            if done['status'] in ('completed','failed','cancelled'):break
                            assert time.monotonic()<deadline,tool+' timeout'
                            time.sleep(.5)
                        assert done['status']=='completed',done
                        assert done['scan_result']['tool']==tool,done
                        with request(path+'/evidence/'+done['scan_result']['evidence_id']) as response:
                            assert json.load(response)['provenance']=='server_approved_tool_run'
                        print('Frozen approved adapter passed:',tool,flush=True)
                    if os.environ.get('JO_SMOKE_HEAD_TOOLS')=='1':assert methods==['HEAD','HEAD'],methods
                finally:
                    fixture.shutdown()
                    fixture.server_close()
                    thread.join(timeout=3)
            if os.environ.get('JO_SMOKE_DOMAIN')=='1':
                target={'kind':'url','value':'https://hemoforge.vercel.app/'}
                for tool,key,minutes in [('nuclei-head','nuclei_binary_sha256',1),('zap-head','zap_image_sha256',3)]:
                    assert execution_catalog.get(key),tool+' dependency missing'
                    now=datetime.now(timezone.utc)
                    content.update(name='Approved HemoForge '+tool,environment='production_readonly',
                        authorization_ref='Owner requested URL test',in_scope=[target],out_of_scope=[],ports=[443],
                        allowed_actions=['http_headers'],max_duration_minutes=minutes,
                        starts_at=(now-timedelta(minutes=1)).isoformat(),ends_at=(now+timedelta(minutes=10)).isoformat())
                    with request(project,{'content':content}) as response:eng=json.load(response)
                    path=project+'/'+eng['id']
                    for decision in ('submit','approve'):
                        with request(path+'/decisions',{'expected_revision':eng['revision'],'action':decision,
                            'actor_label':'Owner-authorized QA','note':'One HEAD to owned HemoForge URL','acknowledge':True}) as response:eng=json.load(response)
                    head=eng['versions'][0]
                    with request(path+'/jobs',{'name':'Domain '+tool,'expected_roe_revision':eng['revision'],
                        'roe_version':head['version'],'content_hash':head['content_hash'],
                        'scan':{'tool':tool,'binary_sha256':execution_catalog[key]},'wall_timeout_seconds':minutes*60,'max_output_kb':64,
                        'steps':[{'target':target,'action':'http_headers','ports':[443],'max_http_rps':1,
                                  'max_concurrency':1,'max_duration_minutes':minutes,'test_account_ref':''}]}) as response:scan=json.load(response)
                    with request('/api/pentest/run',{'project_id':eng['project_id'],'engagement_id':eng['id'],'job_id':scan['id'],
                        'expected_revision':scan['revision'],'actor_label':'Owner-authorized QA','note':'One approved HEAD','acknowledge':True}) as response:
                        assert json.load(response)['status']=='queued'
                    deadline=time.monotonic()+minutes*60+10
                    while True:
                        with request(path+'/jobs/'+scan['id']) as response:done=json.load(response)
                        if done['status'] in ('completed','failed','cancelled'):break
                        assert time.monotonic()<deadline,tool+' timeout'
                        time.sleep(.5)
                    assert done['status']=='completed',done
                    assert done['scan_result']['target']==target['value']
                    with request(path+'/evidence/'+done['scan_result']['evidence_id']) as response:
                        assert json.load(response)['provenance']=='server_approved_tool_run'
                    if tool=='zap-head':
                        assert done['scan_result']['head']['tls']['verified'] is True,done
                        print('Frozen HemoForge HTTPS status:',done['scan_result']['head']['http_status'],flush=True)
                    else:
                        print('Frozen HemoForge CSP observation:',done['scan_result']['csp_observation'],flush=True)
                    print('Frozen approved HemoForge domain adapter passed:',tool,flush=True)
            print("Frozen backend smoke passed: auth, settings, evidence, RoE, scope policy, MCP fixture, model catalogs, Search, private image denial, VA categories, adapter catalog, legacy execution endpoints locked (423), Chat-First loopback TCP scan with Auto-RoE and persisted evidence.")
        finally:
            process.terminate()
            process.wait(timeout=10)
