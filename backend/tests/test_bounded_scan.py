import asyncio
import base64
import json
import hashlib
import unittest
from unittest.mock import patch, AsyncMock

import test_security_jobs as base
from bounded_scan import validate_scan, run_scan
import finding_correlation


class ScanTests(base.JobApiTests):
    def scan_plan(self, address='10.30.0.25', ports=None):
        return base.plan(self.engagement, scan={'tool':'tcp-connect','binary_sha256':''},
                         steps=[{**base.step(),'target':{'kind':'ip','value':address},'ports':ports or [443]}])

    def test_real_connect_approval_evidence_and_model(self):
        async def start():
            async def handle(reader,writer):
                writer.close()
            return await asyncio.start_server(handle,'127.0.0.1',0)
        server=self.client.portal.call(start)
        try:
            port=server.sockets[0].getsockname()[1]
            content=base.content()
            content.update(environment='lab',in_scope=[{'kind':'ip','value':'127.0.0.1'}],out_of_scope=[],ports=[port],allowed_actions=['tcp_discovery'])
            self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
            self.url=self.base+'/'+self.engagement['id']
            made=self.client.post(self.url+'/jobs',headers=self.headers,json=self.scan_plan('127.0.0.1',[port]))
            self.assertEqual(made.status_code,201,made.text)
            row=made.json()
            with patch('bounded_scan.run_scan') as execution:
                self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
                execution.assert_not_called()
            approved=self.client.post('/api/pentest/run',headers=self.headers,json={
                'project_id':self.engagement['project_id'],'engagement_id':self.engagement['id'],'job_id':row['id'],
                **self.approval(row)})
            self.assertEqual(approved.status_code,200,approved.text)
            self.assertEqual(self.store.claim(self.owner),row['id'])
            self.assertFalse(self.store.step(self.owner,row['id']))
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
            done=self.detail(row)
            self.assertEqual(done['status'],'completed',done)
            self.assertEqual(done['scan_result']['ports'][0]['status'],'connected')
            evidence=self.client.get(self.url+'/evidence/'+done['scan_result']['evidence_id'],headers=self.headers).json()
            self.assertEqual(evidence['provenance'],'server_approved_tcp_scan')
            with patch('deep_analysis.installed_models',new=AsyncMock(return_value=[{'name':'local','digest':'qa'}])), \
                 patch('deep_analysis.runtime.chat',new=AsyncMock(return_value={'content':json.dumps({'summary':'Connected','observations':['One TCP connection succeeded.'],'limitations':['Not a vulnerability test.'],'recommendations':[]}), 'tool_calls':[]})):
                result=self.client.post(self.url+'/deep-analysis',headers=self.headers,json={'job_id':row['id'],'model':'local','actor_label':'QA','acknowledge':True})
                self.assertEqual(result.status_code,201,result.text)
                self.assertEqual(result.json()['tool_execution'],'approved_tcp_scan')
        finally:
            server.close()
            self.client.portal.call(server.wait_closed)

    def test_domain_url_requires_approval_and_enforces_scope_in_production(self):
        content=base.content()
        content.update(environment='production_readonly',in_scope=[{'kind':'domain','value':'owned.example'}],
                       out_of_scope=[],ports=[443],allowed_actions=['http_headers'],max_http_rps=1,max_concurrency=1,max_duration_minutes=3)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        self.url=self.base+'/'+self.engagement['id']
        def make(host):
            return base.plan(self.engagement, scan={'tool':'zap-head','binary_sha256':'a'*64},wall_timeout_seconds=180,
                steps=[{**base.step(),'target':{'kind':'url','value':'https://'+host+'/'},'action':'http_headers',
                        'ports':[443],'max_duration_minutes':3,'max_concurrency':1,'max_http_rps':1}])
        with patch('zap_adapter.image_hash',return_value='a'*64):
            denied=self.client.post(self.url+'/jobs',headers=self.headers,json=make('outside.example')).json()
            response=self.client.post(self.url+'/jobs/'+denied['id']+'/approve',headers=self.headers,json=self.approval(denied))
            self.assertEqual(response.status_code,422,response.text)
            row=self.client.post(self.url+'/jobs',headers=self.headers,json=make('owned.example')).json()
            with patch('bounded_scan.run_scan',new=AsyncMock()) as execute:
                self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
                execute.assert_not_awaited()
            response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(self.store.claim(self.owner),row['id'])
            self.store.step(self.owner,row['id'])
            with patch('bounded_scan.run_scan',new=AsyncMock(return_value={'tool':'zap-head','target':'https://owned.example/'})):
                self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
            self.assertEqual(self.detail(row)['status'],'completed')
            output={'summary':'Domain ditinjau','observations':['HEAD ditinjau'],
                    'limitations':['Hanya header'], 'recommendations':['Review manual']}
            with patch('deep_analysis.installed_models',new=AsyncMock(return_value=[{'name':'local','digest':'qa'}])), \
                 patch('deep_analysis.runtime.chat',new=AsyncMock(return_value={'content':json.dumps(output),'tool_calls':[]})) as model, \
                 patch('config.OUTPUT_TOKENS',1536), patch('config.CONTEXT_TOKENS',8192):
                result=self.client.post(self.url+'/deep-analysis',headers=self.headers,json={
                    'job_id':row['id'],'model':'local','actor_label':'QA','acknowledge':True})
                self.assertEqual(result.status_code,201,result.text)
                self.assertEqual(model.await_args.kwargs['output_tokens'],1536)
                chat=self.client.post('/api/chat',headers=self.headers,json={
                    'prompt':'Deep analisis https://owned.example/','project_id':self.engagement['project_id']})
                self.assertIn('Domain ditinjau',chat.text)

    def test_unauthenticated_get_requires_scope_and_approval(self):
        content=base.content()
        content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/api/'}],
            out_of_scope=[],ports=[443],allowed_actions=['unauthenticated_access_check'],max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        self.url=self.base+'/'+self.engagement['id']
        def make(url):
            return base.plan(self.engagement,scan={'tool':'auth-unauthenticated-get','binary_sha256':''},
                steps=[{**base.step(),'target':{'kind':'url','value':url},'action':'unauthenticated_access_check','ports':[443]}])
        wrong=self.client.post(self.url+'/jobs',headers=self.headers,json=make('https://owned.example/other')).json()
        self.assertEqual(self.client.post(self.url+'/jobs/'+wrong['id']+'/approve',headers=self.headers,json=self.approval(wrong)).status_code,422)
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=make('https://owned.example/api/private')).json()
        with patch('bounded_scan.run_scan',new=AsyncMock()) as execute:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
            execute.assert_not_awaited()
        approved=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
        self.assertEqual(approved.status_code,200,approved.text)
        self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        observed={'http_status':401,'redirect_observed':False,'tls':{'verified':True}}
        with patch('web_checks.probe',new=AsyncMock(return_value=observed)) as probe:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        self.assertEqual(self.detail(row)['status'],'completed')
        self.assertEqual(self.detail(row)['scan_result']['status_code'],401)
        self.assertEqual(probe.await_args.kwargs['method'],'GET')

    def test_two_session_comparison_keeps_tokens_ephemeral(self):
        content=base.content()
        content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/api/'}],out_of_scope=[],ports=[443],
            allowed_actions=['authenticated_api_review'],test_account_refs=['qa-a','qa-b'],max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve');self.url=self.base+'/'+self.engagement['id']
        plan=base.plan(self.engagement,scan={'tool':'auth-two-session','binary_sha256':'','account_refs':['qa-a','qa-b'],'owner_json_pointer':'/ownerId'},
            steps=[{**base.step(),'target':{'kind':'url','value':'https://owned.example/api/private'},'action':'authenticated_api_review','ports':[443],'test_account_ref':'qa-a'}])
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=plan).json()
        approval=self.approval(row)
        self.assertEqual(self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=approval).status_code,422)
        def token(subject,audience='staging'):
            payload=base64.urlsafe_b64encode(json.dumps({'sub':subject,'aud':audience}).encode()).decode().rstrip('=')
            return 'e30.'+payload+'.signature'
        mixed=[token('a','staging'),token('b','production')]
        rejected_mixed=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={**approval,'session_tokens':mixed})
        self.assertEqual(rejected_mixed.status_code,422);self.assertNotIn(mixed[0],rejected_mixed.text)
        same=[token('a'),token('a')]
        rejected=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={**approval,'session_tokens':same})
        self.assertEqual(rejected.status_code,422);self.assertNotIn(same[0],rejected.text)
        tokens=[token('a'),token('b')]
        result=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={**approval,'session_tokens':tokens})
        self.assertEqual(result.status_code,200,result.text)
        self.assertNotIn(tokens[0],result.text)
        self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        results=[{'http_status':401,'redirect_observed':False},{'http_status':200,'redirect_observed':False,'_transient_body_digest':b'same','_transient_semantic_digest':b'value','_transient_shape_digest':b'shape','_transient_owner_digest':hashlib.sha256(b'a').digest()},{'http_status':200,'redirect_observed':False,'_transient_body_digest':b'same','_transient_semantic_digest':b'value','_transient_shape_digest':b'shape','_transient_owner_digest':hashlib.sha256(b'a').digest()}]
        async def fake_probe(*args,**kwargs):return results.pop(0)
        with patch('web_checks.probe',new=AsyncMock(side_effect=fake_probe)) as probe:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        self.assertEqual(probe.await_count,3)
        self.assertEqual([call.kwargs['bearer'] for call in probe.await_args_list],[None,*tokens])
        done=self.detail(row);self.assertEqual(done['status'],'completed',done)
        self.assertEqual([o['status_code'] for o in done['scan_result']['observations']],[401,200,200])
        self.assertTrue(done['scan_result']['body_comparisons'][2]['json_body_equal'])
        self.assertTrue(done['scan_result']['body_comparisons'][2]['json_values_equal'])
        self.assertTrue(done['scan_result']['body_comparisons'][2]['json_structure_equal'])
        self.assertEqual(done['scan_result']['observations'][1]['owner_matches_test_subject'],[True,False])
        self.assertEqual(done['scan_result']['observations'][2]['owner_matches_test_subject'],[True,False])
        self.assertNotIn('_transient_body_digest',json.dumps(done))
        self.assertNotIn('_transient_semantic_digest',json.dumps(done))
        self.assertNotIn('_transient_owner_digest',json.dumps(done))
        self.assertNotIn(tokens[0],json.dumps(done));self.assertNotIn(tokens[1],json.dumps(done))
        evidence=self.client.get(self.url+'/evidence/'+done['scan_result']['evidence_id'],headers=self.headers).text
        self.assertNotIn(tokens[0],evidence);self.assertNotIn(tokens[1],evidence)
        self.assertNotIn(row['id'],self.store.sessions.entries)

    def test_two_session_denies_unlisted_alias_and_clears_cancelled_sessions(self):
        content=base.content();content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/'}],
            out_of_scope=[],ports=[443],allowed_actions=['authenticated_api_review'],test_account_refs=['qa-a','qa-b'],
            max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve');self.url=self.base+'/'+self.engagement['id']
        def token(subject):
            data=base64.urlsafe_b64encode(json.dumps({'sub':subject,'aud':'staging'}).encode()).decode().rstrip('=')
            return 'e30.'+data+'.signature'
        tokens=[token('a'),token('b')]
        def make(refs):
            return base.plan(self.engagement,scan={'tool':'auth-two-session','binary_sha256':'','account_refs':refs},
                steps=[{**base.step(),'target':{'kind':'url','value':'https://owned.example/private'},'action':'authenticated_api_review','ports':[443],'test_account_ref':'qa-a'}])
        wrong=self.client.post(self.url+'/jobs',headers=self.headers,json=make(['qa-a','not-approved'])).json()
        denied=self.client.post(self.url+'/jobs/'+wrong['id']+'/approve',headers=self.headers,json={**self.approval(wrong),'session_tokens':tokens})
        self.assertEqual(denied.status_code,422);self.assertNotIn(wrong['id'],self.store.sessions.entries)
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=make(['qa-a','qa-b'])).json()
        accepted=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={**self.approval(row),'session_tokens':tokens})
        self.assertEqual(accepted.status_code,200,accepted.text);self.assertIn(row['id'],self.store.sessions.entries)
        self.client.post(self.url+'/jobs/'+row['id']+'/stop',headers=self.headers,json={})
        self.assertNotIn(row['id'],self.store.sessions.entries)

    def test_active_spider_checks_every_descendant_scope(self):
        content=base.content();content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/'}],
            out_of_scope=[{'kind':'url','value':'https://owned.example/private'}],ports=[443],allowed_actions=['scoped_spider'],
            max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve');self.url=self.base+'/'+self.engagement['id']
        plan=base.plan(self.engagement,scan={'tool':'scoped-spider','binary_sha256':''},
            steps=[{**base.step(),'target':{'kind':'url','value':'https://owned.example/public'},'action':'scoped_spider','ports':[443]}])
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=plan).json();approved=self.approve(row)
        self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        async def fake_run(plan,guard,exclusions):
            await guard('https://owned.example/public/page')
            with self.assertRaises(ValueError):await guard('https://owned.example/private')
            with self.assertRaises(ValueError):await guard('https://elsewhere.example/')
            return {'tool':'scoped-spider','target':'https://owned.example/public','pages':[{'url':'https://owned.example/public/page','status_code':200}]}
        with patch('active_web_adapter.run',new=AsyncMock(side_effect=fake_run)):
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        done=self.detail(row);self.assertEqual(done['status'],'completed',done)
        self.assertTrue(done['scan_result']['evidence_id'])

    def test_js_bundle_guard_approval_and_evidence(self):
        content=base.content();content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/assets/'}],
            out_of_scope=[],ports=[443],allowed_actions=['service_inventory'],max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve');self.url=self.base+'/'+self.engagement['id']
        plan=base.plan(self.engagement,scan={'tool':'js-bundle-inventory','binary_sha256':''},
            steps=[{**base.step(),'target':{'kind':'url','value':'https://owned.example/assets/app.js'},'action':'service_inventory','ports':[443]}])
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=plan).json()
        with patch('bounded_scan.run_scan',new=AsyncMock()) as execute:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id']);execute.assert_not_awaited()
        self.approve(row);self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        async def fake_run(plan,guard,exclusions):
            await guard('https://owned.example/assets/app.js')
            with self.assertRaises(ValueError):await guard('https://other.example/app.js')
            return {'tool':'js-bundle-inventory','target':'https://owned.example/assets/app.js','candidate_origins':['https://api.example/']}
        with patch('js_inventory_adapter.run',new=AsyncMock(side_effect=fake_run)):
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        done=self.detail(row);self.assertEqual(done['status'],'completed',done)
        self.assertTrue(done['scan_result']['evidence_id'])

    def test_inventory_requires_scope_approval_and_saves_evidence(self):
        content=base.content()
        content.update(environment='staging',in_scope=[{'kind':'url','value':'https://owned.example/'}],out_of_scope=[],ports=[443],
            allowed_actions=['service_inventory'],max_http_rps=1,max_concurrency=1,max_duration_minutes=1)
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve');self.url=self.base+'/'+self.engagement['id']
        def make(host):
            return base.plan(self.engagement,scan={'tool':'inventory-html','binary_sha256':''},
                steps=[{**base.step(),'target':{'kind':'url','value':'https://'+host+'/'},'action':'service_inventory','ports':[443]}])
        wrong=self.client.post(self.url+'/jobs',headers=self.headers,json=make('outside.example')).json()
        self.assertEqual(self.client.post(self.url+'/jobs/'+wrong['id']+'/approve',headers=self.headers,json=self.approval(wrong)).status_code,422)
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=make('owned.example')).json()
        with patch('bounded_scan.run_scan',new=AsyncMock()) as execute:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id']);execute.assert_not_awaited()
        self.approve(row);self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        with patch('inventory_adapter.run',new=AsyncMock(return_value={'tool':'inventory-html','target':'https://owned.example/','candidates':[]})):
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        done=self.detail(row);self.assertEqual(done['status'],'completed')
        evidence=self.client.get(self.url+'/evidence/'+done['scan_result']['evidence_id'],headers=self.headers).json()
        self.assertEqual(evidence['provenance'],'server_approved_tool_run')

    def test_validation_and_stop_block_execution(self):
        for change in [{'mcp':{'tool':'x'}},{'web':{'adapter':'x'}},{'wall_timeout_seconds':61},
                       {'steps':[{**base.step(),'target':{'kind':'domain','value':'example.com'}}]},
                       {'steps':[{**base.step(),'ports':list(range(1,18))}]}]:
            with self.assertRaises(ValueError):validate_scan({**self.scan_plan(),**change})
        row=self.create_job(scan={'tool':'tcp-connect','binary_sha256':''})
        self.approve(row)
        self.store.claim(self.owner)
        self.store.step(self.owner,row['id'])
        self.client.post(self.url+'/jobs/'+row['id']+'/stop',headers=self.headers,json={})
        with patch('bounded_scan.run_scan') as execute:
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
            execute.assert_not_called()

    def test_nmap_hash_change_rejected(self):
        plan={**self.scan_plan(),'scan':{'tool':'nmap','binary_sha256':'a'*64}}
        with patch('bounded_scan.binary_hash',return_value='b'*64):
            with self.assertRaises(ValueError):validate_scan(plan)

    def test_stop_during_adapter_cancels_task_without_evidence(self):
        from security_jobs import Stop
        row=self.create_job(scan={'tool':'tcp-connect','binary_sha256':''})
        self.approve(row)
        self.store.claim(self.owner)
        self.store.step(self.owner,row['id'])
        cancelled=[]
        async def pending(plan,guard,exclusions):
            self.store.stop_engagement(self.engagement['project_id'],self.engagement['id'],Stop())
            try:await asyncio.sleep(30)
            finally:cancelled.append(True)
        with patch('bounded_scan.run_scan',new=pending):
            self.client.portal.call(self.client.app.state.scan_runner.execute,self.owner,row['id'])
        done=self.detail(row)
        self.assertEqual(done['status'],'cancelled')
        self.assertIsNone(done['scan_result'])
        self.assertEqual(cancelled,[True])


class NmapArgsTests(unittest.IsolatedAsyncioTestCase):
    async def test_fixed_args_and_output_target(self):
        process=AsyncMock()
        process.returncode=0
        process.stdout.read=AsyncMock(side_effect=[b'<nmaprun><host><address addr="10.30.0.25" addrtype="ipv4"/><ports><port portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>',b''])
        plan={'scan':{'tool':'nmap','binary_sha256':'a'*64},'steps':[base.step()], 'wall_timeout_seconds':60}
        with patch('bounded_scan.nmap_path',return_value='C:/Nmap/nmap.exe'),patch('bounded_scan.binary_hash',return_value='a'*64),patch('bounded_scan.asyncio.create_subprocess_exec',return_value=process) as launch:
            result=await run_scan(plan,AsyncMock())
            args=launch.call_args.args
            self.assertEqual(args[-1],'10.30.0.25')
            self.assertNotIn('-sV',args)
            self.assertNotIn('--script',args)
            self.assertNotIn('shell',launch.call_args.kwargs)
            self.assertEqual(result['ports'][0]['status'],'open')


class SastScaValidateTests(unittest.TestCase):
    """SAST/SCA plans are workspace-confined, offline, and bounded (no AppContainer)."""
    def sast_plan(self, tool='bandit-sast', target='backend', action=None, **step_over):
        action = action or ('dependency_review' if tool == 'trivy-sca' else 'source_review')
        step = {'target': {'kind': 'repo', 'value': target}, 'action': action, 'ports': [],
                'max_http_rps': 1, 'max_concurrency': 1, 'max_duration_minutes': 1, 'test_account_ref': ''}
        step.update(step_over)
        return {'steps': [step], 'wall_timeout_seconds': 60, 'web': None, 'mcp': None,
                'scan': {'tool': tool, 'binary_sha256': 'a' * 64, 'provider_disclosure': False,
                         'account_refs': [], 'owner_json_pointer': ''}}

    def test_valid_sast_and_sca_plans_pass(self):
        for tool in ('semgrep-sast', 'bandit-sast', 'trivy-sca'):
            validate_scan(self.sast_plan(tool=tool), check_binary=False)  # no raise

    def test_rejects_bad_action_ports_limits_and_traversal(self):
        from engagements import repo_path
        with self.assertRaises(ValueError):
            validate_scan(self.sast_plan(tool='trivy-sca', action='source_review'), check_binary=False)
        with self.assertRaises(ValueError):
            validate_scan(self.sast_plan(ports=[443]), check_binary=False)
        with self.assertRaises(ValueError):
            validate_scan(self.sast_plan(max_duration_minutes=5), check_binary=False)
        plan = self.sast_plan(); plan['wall_timeout_seconds'] = 200
        with self.assertRaises(ValueError):
            validate_scan(plan, check_binary=False)
        plan = self.sast_plan(); plan['scan']['account_refs'] = ['x']
        with self.assertRaises(ValueError):
            validate_scan(plan, check_binary=False)
        with self.assertRaises(ValueError):
            repo_path('../etc/passwd')

    def test_resolve_repo_path_confines_to_workspace(self):
        import tempfile
        from pathlib import Path
        import config
        from sast_adapter import resolve_repo_path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app').mkdir()
            with patch.object(config, 'WORKSPACE_DIR', root):
                result_root, target = resolve_repo_path('app')
                self.assertEqual(target, (root / 'app').resolve())
                with self.assertRaises(ValueError):
                    resolve_repo_path('missing-subdir')


class CorrelationTests(unittest.TestCase):
    def test_dast_correlates_to_sast_and_never_fabricates(self):
        results = [
            {'tool': 'bandit-sast', 'findings': [{'tool': 'bandit-sast', 'rule_id': 'B-CSP', 'severity': 'medium',
                'file': 'app/headers.py', 'line_start': 10, 'line_end': 10, 'message': 'missing content-security-policy'}]},
            {'tool': 'trivy-sca', 'findings': [{'tool': 'trivy-sca', 'pkg': 'flask', 'installed_version': '1.0',
                'fixed_version': '2.3.2', 'vuln_id': 'CVE-2023-1', 'severity': 'high', 'file': 'requirements.txt', 'title': 'x'}]},
            {'tool': 'nuclei-head', 'target': 'https://app.test/login', 'csp_observation': 'missing_header_candidate'},
            {'tool': 'zap-head', 'target': 'https://app.test/x', 'head': {'checks': [{'check': 'strict-transport-security', 'status': 'missing'}]}},
        ]
        out = finding_correlation.diagnostics(results)
        self.assertEqual(out['counts'], {'dast': 2, 'sast': 1, 'sca': 1, 'diagnostics': len(out['diagnostics'])})
        csp = [c for c in out['correlations'] if c['runtime'].get('header') == 'content-security-policy'][0]
        self.assertEqual(csp['source']['file'], 'app/headers.py')
        self.assertEqual(csp['confidence'], 'medium')
        hsts = [c for c in out['correlations'] if c['runtime'].get('header') == 'strict-transport-security'][0]
        self.assertIsNone(hsts['source'])
        self.assertTrue(any(d['source_tool'] == 'trivy-sca' and d['file'] == 'requirements.txt' for d in out['diagnostics']))
