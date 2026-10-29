import asyncio
from contextlib import closing
import copy
from datetime import timedelta
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_security_jobs as jobtests
from engagements import utc_now
from security_jobs import Approval,Stop,OfflineJobRunner,JobStore,digest
from mcp_gateway import MCPGateway,ServerConfig,ServerDecision,descriptor
from mcp_sandbox import SandboxRuntime,SandboxError,exchange,supported
from mcp_fixture_server import PROTOCOL

ROOT=Path(__file__).resolve().parents[2]
SHARED_RUNTIME=ROOT/'output/security-stage5/test-runtime'


@unittest.skipUnless(supported(),'Windows AppContainer unavailable')
class MCPApiTests(unittest.TestCase):
    setUpFixture=jobtests.JobApiTests.setUpFixture
    tearDown=jobtests.JobApiTests.tearDown
    create_engagement=jobtests.JobApiTests.create_engagement
    decide=jobtests.JobApiTests.decide
    approval=jobtests.JobApiTests.approval

    def setUp(self):
        self.setUpFixture()
        self.client.portal.call(self.client.app.state.job_runner.stop)
        self.store=self.client.app.state.jobs;self.gateway=self.client.app.state.mcp
        self.gateway.runtime=SandboxRuntime(SHARED_RUNTIME)
        self.owner='deterministic-mcp-test-worker';self.store.acquire(self.owner)
        content=jobtests.content();content['allowed_actions'].append('configuration_review')
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        self.url=self.base+'/'+self.engagement['id']
        self.server=self.create_server()
        self.server=self.server_decision(self.server,'approve')

    def create_server(self,**changes):
        response=self.client.post('/api/security/mcp/servers',headers=self.headers,json={'name':'QA fixture server','allowed_tools':['fixture.inspect'],**changes})
        self.assertEqual(response.status_code,201,response.text);return response.json()

    def server_decision(self,row,action,status=200,**changes):
        response=self.client.post('/api/security/mcp/servers/'+row['id']+'/decisions',headers=self.headers,json={'expected_revision':row['revision'],'action':action,'actor_label':'QA local','note':'Reviewed fixture schema, limits, isolation.','acknowledge':True,**changes})
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def plan(self,**changes):
        return jobtests.plan(self.engagement,steps=[{**jobtests.step(),'action':'configuration_review','ports':[]}],wall_timeout_seconds=10,max_output_kb=32,
            mcp={'server_id':self.server['id'],'server_revision':self.server['revision'],'descriptor_hash':self.server['descriptor_hash'],'tool':'fixture.inspect','arguments':{'fixture':'headers_missing'}},**changes)

    def create_job(self,body=None,status=201):
        response=self.client.post(self.url+'/jobs',headers=self.headers,json=body or self.plan())
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def approve(self,row,status=200):
        response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def detail(self,row):return self.client.get(self.url+'/jobs/'+row['id'],headers=self.headers).json()

    def execute(self,row):
        self.store.claim(self.owner)
        runner=OfflineJobRunner(self.store);runner.owner=self.owner
        self.client.portal.call(runner.execute,row['id'])
        return self.detail(row)

    def test_auth_unknown_servers_tools_schema_and_no_arbitrary_commands(self):
        self.assertEqual(self.client.get('/api/security/mcp/servers').status_code,401)
        self.assertEqual(self.client.post('/api/security/mcp/servers',json={}).status_code,401)
        for extra in ({'url':'http://example.test'},{'command':'cmd.exe'},{'env':{'AGENT_API_TOKEN':'synthetic-secret'}},{'adapter':'nmap'},{'allowed_tools':['shell']},{'allowed_tools':[]},{'max_wall_seconds':16},{'max_output_kb':65}):
            response=self.client.post('/api/security/mcp/servers',headers=self.headers,json={'name':'bad','allowed_tools':['fixture.inspect'],**extra})
            self.assertEqual(response.status_code,422,extra)
            self.assertNotIn('synthetic-secret',response.text)
        for binding in ({'server_id':str(uuid4())},{'server_revision':1},{'descriptor_hash':'0'*64},{'tool':'nmap'},{'arguments':{'fixture':'headers_missing','url':'http://example.test'}},{'arguments':{'fixture':'../../api-token'}},{'arguments':{'fixture':True}}):
            body=self.plan();body['mcp'].update(binding)
            self.create_job(body,status=404 if 'server_id' in binding else 409 if 'server_revision' in binding or 'descriptor_hash' in binding else 422)

    def test_draft_disabled_and_unpermitted_tool_are_never_called(self):
        draft=self.create_server(name='Unapproved')
        with patch.object(self.gateway.runtime,'start') as spawn:
            response=self.client.post('/api/security/mcp/servers/'+draft['id']+'/check',headers=self.headers,json={'expected_revision':draft['revision']})
            self.assertEqual(response.status_code,423)
            body=self.plan();body['mcp'].update(server_id=draft['id'],server_revision=draft['revision']);self.create_job(body,423)
            body=self.plan();body['mcp'].update(tool='fixture.compare',arguments={'before':'headers_missing','after':'headers_present'});self.create_job(body,403)
            disabled=self.server_decision(self.server,'disable')
            body=self.plan();body['mcp']['server_revision']=disabled['revision'];self.create_job(body,423)
            spawn.assert_not_called()

    def test_job_schema_errors_do_not_echo_pasted_credentials(self):
        body=self.plan();body['mcp']['arguments']['api_key']='synthetic-private-job-input'
        response=self.client.post(self.url+'/jobs',headers=self.headers,json=body)
        self.assertEqual(response.status_code,422)
        self.assertNotIn('synthetic-private-job-input',response.text)
        self.assertNotIn('"input"',response.text)

    def test_connection_handshake_version_schema_and_no_tool_call(self):
        response=self.client.post('/api/security/mcp/servers/'+self.server['id']+'/check',headers=self.headers,json={'expected_revision':self.server['revision']})
        self.assertEqual(response.status_code,200,response.text)
        report=response.json();self.assertEqual(report['status'],'passed');self.assertFalse(report['tool_called'])
        self.assertEqual(report['handshake']['initialize']['protocolVersion'],PROTOCOL)
        self.assertTrue(report['isolation']['appcontainer_token_verified'])
        detail=self.client.get('/api/security/mcp/servers/'+self.server['id'],headers=self.headers).json()
        self.assertEqual(len(detail['checks']),1)

    def test_review_required_immutable_plan_and_automatic_evidence(self):
        row=self.create_job();self.assertEqual(row['status'],'awaiting_approval')
        self.assertEqual(self.store.claim(self.owner),None)
        row=self.approve(row)
        with patch('main.assess') as scanner,patch('socket.create_connection') as network:
            done=self.execute(row);scanner.assert_not_called();network.assert_not_called()
        self.assertEqual(done['status'],'completed',done)
        self.assertEqual(done['mode'],'isolated_mcp_fixture');self.assertFalse(done['execution_enabled'])
        self.assertEqual(done['plan_hash'],row['plan_hash'])
        result=done['mcp_result'];self.assertFalse(result['pentest_executed']);self.assertFalse(result['model_called'])
        e=self.client.get(self.url+'/evidence/'+result['evidence_id'],headers=self.headers).json()
        self.assertEqual(e['provenance'],'server_mcp_fixture');self.assertTrue(e['tool_executed_by_agent_os'])
        self.assertFalse(e['pentest_executed']);self.assertEqual(e['job_id'],row['id'])
        self.assertEqual(e['source'],'synthetic_fixture')
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={}).status_code,423)

    def test_server_review_ack_stale_revision_and_limits(self):
        draft=self.create_server(name='Review')
        self.server_decision(draft,'approve',422,acknowledge=False)
        approved=self.server_decision(draft,'approve')
        self.server_decision(draft,'disable',409)
        self.assertEqual(approved['state'],'approved')
        body=self.plan();body['wall_timeout_seconds']=11;self.create_job(body,422)
        body=self.plan();body['max_output_kb']=33;self.create_job(body,422)
        body=self.plan();body['steps'][0]['action']='tcp_discovery';self.create_job(body,422)

    def test_wrong_scope_expired_roe_and_approval_never_spawn(self):
        body=self.plan();body['steps'][0]['target']['value']='10.30.0.99'
        row=self.create_job(body)
        with patch.object(self.gateway.runtime,'start') as spawn:self.approve(row,422);spawn.assert_not_called()
        row=self.create_job();self.decide(self.engagement,'revoke')
        self.approve(row,422)

    def test_profile_edit_revokes_approval_and_cancels_bound_jobs(self):
        row=self.approve(self.create_job())
        response=self.client.put('/api/security/mcp/servers/'+self.server['id'],headers=self.headers,json={'expected_revision':self.server['revision'],'config':{**self.server['config'],'name':'Changed'}})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['state'],'draft')
        self.assertEqual(self.detail(row)['status'],'cancelled')
        self.assertIsNone(self.store.claim(self.owner))

    def test_revoked_roe_between_handshake_and_call_fails_and_stops_child(self):
        row=self.approve(self.create_job());self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        original=self.gateway.handshake
        async def revoke(process,guard,deadline,limit):
            transcript=await original(process,guard,deadline,limit)
            from engagements import Decision
            self.store.engagements.decide(self.project,self.engagement['id'],Decision(expected_revision=self.engagement['revision'],action='revoke',actor_label='QA',note='Stop during MCP',acknowledge=True))
            return transcript
        with patch.object(self.gateway,'handshake',side_effect=revoke):self.client.portal.call(self.gateway.execute,self.owner,row['id'])
        done=self.detail(row)
        self.assertEqual(done['status'],'failed');self.assertEqual(done['error_code'],'MCP_POLICY_DENIED')
        self.assertIsNone(done['mcp_result']);self.assertFalse(list(self.gateway.runtime.requests.iterdir()))

    def test_failure_to_save_evidence_rolls_back_success(self):
        row=self.approve(self.create_job())
        with patch.object(self.gateway.evidence,'add_evidence',side_effect=RuntimeError('synthetic persistence error')):done=self.execute(row)
        self.assertEqual(done['status'],'failed');self.assertIsNone(done['mcp_result'])
        self.assertEqual(len(self.client.get(self.url+'/records',headers=self.headers).json()['evidence']),0)

    def test_stop_run_and_engagement_prevent_fixture_and_preserve_policy(self):
        for stop_engagement in (False,True):
            row=self.approve(self.create_job())
            self.store.claim(self.owner);self.store.step(self.owner,row['id'])
            if stop_engagement:self.store.stop_engagement(self.project,self.engagement['id'],Stop())
            else:self.store.cancel(self.project,self.engagement['id'],row['id'],Stop())
            with patch.object(self.gateway.runtime,'start') as spawn:
                self.client.portal.call(self.gateway.execute,self.owner,row['id']);spawn.assert_not_called()
            done=self.detail(row);self.assertEqual(done['status'],'cancelled');self.assertEqual(len(done['results']),1)

    def test_live_roe_recheck_before_tool_call_kills_process(self):
        row=self.approve(self.create_job());self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        async def changed(process,guard,deadline,limit):
            self.store.cancel(self.project,self.engagement['id'],row['id'],Stop())
            return {}
        with patch.object(self.gateway,'handshake',side_effect=changed):
            self.client.portal.call(self.gateway.execute,self.owner,row['id'])
        self.assertEqual(self.detail(row)['status'],'cancelled')
        self.assertFalse(list(self.gateway.runtime.requests.iterdir()))
        self.assertEqual(len(self.client.get(self.url+'/records',headers=self.headers).json()['evidence']),0)

    def test_disable_while_running_closes_job_object(self):
        row=self.approve(self.create_job());self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        async def disabled(process,guard,deadline,limit):
            from mcp_gateway import ServerDecision
            self.gateway.decide(self.server['id'],ServerDecision(expected_revision=self.server['revision'],action='disable',actor_label='QA',note='Emergency stop',acknowledge=True))
            return {}
        with patch.object(self.gateway,'handshake',side_effect=disabled):self.client.portal.call(self.gateway.execute,self.owner,row['id'])
        self.assertEqual(self.detail(row)['status'],'cancelled')
        self.assertFalse(list(self.gateway.runtime.requests.iterdir()))

    def test_schema_drift_or_fake_initialize_response_fails_closed(self):
        row=self.approve(self.create_job())
        async def wrong(process,method,*args,**kwargs):return {'protocolVersion':'bad'}
        with patch('mcp_gateway.exchange',side_effect=wrong):done=self.execute(row)
        self.assertEqual(done['status'],'failed');self.assertIsNone(done['mcp_result'])
        self.assertFalse(list(self.gateway.runtime.requests.iterdir()))

    def test_output_limit_retains_policy_and_does_not_claim_success(self):
        row=self.approve(self.create_job())
        async def flood(process,guard,deadline,limit):raise SandboxError('OUTPUT_LIMIT')
        with patch.object(self.gateway,'handshake',side_effect=flood):done=self.execute(row)
        self.assertEqual(done['status'],'failed');self.assertEqual(done['error_code'],'MCP_OUTPUT_LIMIT')
        self.assertEqual(len(done['results']),1);self.assertIsNone(done['mcp_result'])

    def test_isolation_failure_never_falls_back_to_subprocess(self):
        row=self.approve(self.create_job())
        with patch.object(self.gateway.runtime,'start',side_effect=SandboxError('Isolation unavailable')),patch('subprocess.Popen') as ordinary:
            done=self.execute(row);ordinary.assert_not_called()
        self.assertEqual(done['status'],'failed');self.assertIsNone(done['mcp_result'])

    def test_restart_and_result_integrity_are_persistent(self):
        row=self.approve(self.create_job());done=self.execute(row)
        reopened=MCPGateway(self.store.engagements,self.store,self.client.app.state.evidence,self.data)
        self.assertEqual(reopened.result(self.project,self.engagement['id'],row['id']),done['mcp_result'])
        self.assertEqual(reopened.detail(self.server['id'])['state'],'approved')
        with self.store.engagements.transaction() as db:db.execute('UPDATE mcp_job_results SET result=? WHERE job_id=?',(json.dumps({'tampered':True}),row['id']))
        self.assertEqual(self.client.get(self.url+'/jobs/'+row['id'],headers=self.headers).status_code,409)

    def test_runner_lease_rejects_parallel_handshakes(self):
        with self.store.engagements.transaction() as db:self.gateway.runner_lease(db,'other',initial=True)
        with patch.object(self.gateway.runtime,'start') as spawn:
            response=self.client.post('/api/security/mcp/servers/'+self.server['id']+'/check',headers=self.headers,json={'expected_revision':self.server['revision']})
            self.assertEqual(response.status_code,409);spawn.assert_not_called()
        self.gateway.release_runner('other')


@unittest.skipUnless(supported(),'Windows AppContainer unavailable')
class RealIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime=await asyncio.to_thread(SandboxRuntime(SHARED_RUNTIME).prepare)

    async def test_os_enforces_private_file_network_environment_and_child_boundaries(self):
        root=ROOT/'output/security-stage5';root.mkdir(exist_ok=True)
        canary=root/'private-canary.txt';canary.write_text('synthetic-private-canary',encoding='utf-8')
        with patch.dict(os.environ,{'AGENT_API_TOKEN':'synthetic-token-must-not-be-inherited'}):process=self.runtime.start()
        try:
            async def guard():pass
            deadline=time.monotonic()+5
            await exchange(process,'initialize',{'protocolVersion':PROTOCOL,'capabilities':{},'clientInfo':{'name':'QA','version':'1'}},1,guard,deadline)
            process.send({'jsonrpc':'2.0','method':'notifications/initialized'})
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen()
                checks=await exchange(process,'agentos/isolation-probe',{'private_path':str(canary),'port':listener.getsockname()[1]},2,guard,deadline)
            self.assertTrue(all(checks.values()),checks)
        finally:process.close()
        self.assertFalse(process.alive());self.assertFalse(process.directory.exists())

    async def test_timeout_and_task_cancellation_kill_process(self):
        async def guard():await asyncio.sleep(.1)
        process=self.runtime.start()
        try:
            with self.assertRaises(SandboxError):await exchange(process,'initialize',{'protocolVersion':PROTOCOL},1,guard,time.monotonic()-.1)
        finally:process.close()
        self.assertFalse(process.alive())
        process=self.runtime.start()
        try:
            async def waiting():await asyncio.Event().wait()
            task=asyncio.create_task(exchange(process,'initialize',{},1,waiting,time.monotonic()+10))
            await asyncio.sleep(.05);task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        finally:process.close()
        self.assertFalse(process.alive())

    async def test_parent_crash_closes_job_and_leaves_no_child(self):
        import psutil
        helper=ROOT/'output/security-stage5/crash-helper.py'
        helper.write_text("import sys,time\nfrom pathlib import Path\nsys.path.insert(0,"+repr(str(ROOT/'backend'))+")\nfrom mcp_sandbox import SandboxRuntime\np=SandboxRuntime(Path("+repr(str(SHARED_RUNTIME))+" )).prepare().start()\nprint(p.pid,flush=True)\ntime.sleep(30)\n",encoding='utf-8')
        parent=subprocess.Popen([sys.executable,str(helper)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        child=None
        try:
            line=await asyncio.wait_for(asyncio.to_thread(parent.stdout.readline),10)
            self.assertTrue(line.strip().isdigit(),line)
            child=psutil.Process(int(line.strip()))
            parent.terminate();await asyncio.to_thread(parent.wait,5)
            try:await asyncio.to_thread(child.wait,5)
            except psutil.NoSuchProcess:pass
            self.assertFalse(child.is_running())
            await asyncio.to_thread(self.runtime.prepare)
            self.assertFalse(list(self.runtime.requests.iterdir()))
        finally:
            if parent.poll() is None:parent.kill();parent.wait(timeout=5)
            parent.stdout.close();parent.stderr.close()


if __name__=='__main__':unittest.main()
