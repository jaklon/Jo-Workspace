import json
import unittest
from unittest.mock import AsyncMock, patch

from test_web_checks import WebCheckTests


class DeepAnalysisTests(unittest.TestCase):
    setUp = WebCheckTests.setUp
    tearDown = WebCheckTests.tearDown
    setUpFixture = WebCheckTests.setUpFixture
    tearDownFixture = WebCheckTests.tearDownFixture
    create_engagement = WebCheckTests.create_engagement
    decide = WebCheckTests.decide
    plan = WebCheckTests.plan

    def test_approved_evidence_model_and_gate(self):
        job = self.client.post(self.url + '/jobs', headers=self.headers, json=self.plan()).json()
        endpoint = self.url + '/deep-analysis'
        payload = {'job_id': job['id'], 'model': 'local', 'actor_label': 'QA', 'acknowledge': True}
        self.assertEqual(self.client.post(endpoint, headers=self.headers, json=payload).status_code, 409)
        self.assertEqual(self.client.post(endpoint, headers=self.headers, json={**payload, 'acknowledge': False}).status_code, 422)
        approved = self.client.post(self.url + '/jobs/' + job['id'] + '/approve', headers=self.headers,
            json={'expected_revision':job['revision'], 'actor_label':'QA', 'note':'Review HEAD', 'acknowledge':True})
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(self.jobs.claim(self.owner), job['id'])
        self.assertFalse(self.jobs.step(self.owner, job['id']))
        synthetic = {'adapter':'public-head-1.0', 'url':'https://project.example/', 'method':'HEAD',
                     'requests':1, 'http_status':200, 'checks':[{'check':'content-security-policy','status':'missing'}]}
        with patch('web_checks.probe', return_value=synthetic):
            self.client.portal.call(self.client.app.state.web_runner.execute, self.owner, job['id'])
        output = {'summary':'Header tidak terlihat.', 'observations':['CSP tidak terlihat pada HEAD.'],
                  'limitations':['Satu HEAD tidak membuktikan kerentanan.'], 'recommendations':['Tinjau konfigurasi.']}
        with patch('deep_analysis.installed_models', new=AsyncMock(return_value=[{'name':'local','digest':'abc'}])), \
             patch('deep_analysis.runtime.chat', new=AsyncMock(return_value={'content':json.dumps(output),'tool_calls':[]})) as model:
            response = self.client.post(endpoint, headers=self.headers, json=payload)
            self.assertEqual(response.status_code, 201, response.text)
            report = response.json()
            self.assertEqual(report['status'], 'needs_human_review')
            self.assertEqual(report['source']['job_id'], job['id'])
            self.assertTrue(report['source']['evidence_id'])
            self.assertTrue(model.call_args.kwargs['local_only'])
            from analysis_grounding import GROUNDING_VERSION
            self.assertEqual(report['grounding_version'], GROUNDING_VERSION)
            listed = self.client.get(endpoint, headers=self.headers).json()['items']
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]['grounding_status'], 'current')
            chat = self.client.post('/api/chat', headers=self.headers, json={
                'prompt':'Deep analisis https://project.example/', 'project_id':self.engagement['project_id']})
            self.assertEqual(chat.status_code, 200)
            self.assertIn(report['source']['evidence_id'], chat.text)
            self.assertIn('Header tidak terlihat', chat.text)
            without_project = self.client.post('/api/chat', headers=self.headers,
                json={'prompt':'Deep analisis https://project.example/'})
            self.assertIn('Pilih Project', without_project.text)
            model.return_value = {'content':'not json', 'tool_calls':[]}
            invalid = self.client.post(endpoint, headers=self.headers, json=payload)
            self.assertEqual(invalid.status_code, 422)
            self.assertEqual(len(self.client.get(endpoint, headers=self.headers).json()['items']), 1)
            from engagements import utc_now
            external = self.client.post(self.url+'/evidence', headers=self.headers, json={
                'job_id':job['id'], 'step_ordinal':1, 'source':'external_import', 'title':'Imported',
                'captured_at':utc_now().isoformat(), 'tool_name':'ZAP', 'tool_version':'test',
                'parameters':'operator', 'content':'example evidence', 'acknowledge':True})
            self.assertEqual(external.status_code, 201, external.text)
            denied = self.client.post(endpoint, headers=self.headers, json={**payload,'evidence_id':external.json()['id']})
            self.assertEqual(denied.status_code, 409)
            self.assertIn('document_review', denied.text)
            self.client.post(self.url + '/stop', headers=self.headers, json={'actor_label':'QA','note':'Stop'})
            self.assertEqual(self.client.post(endpoint, headers=self.headers, json=payload).status_code, 423)
            self.assertEqual(model.call_count, 2)
        self.assertEqual(self.client.get(endpoint).status_code, 401)

    def test_chat_selects_inventory_and_auth_reports(self):
        from deep_analysis import chat_report
        from security_jobs import digest
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        reports=[]
        for tool in ('inventory-html','auth-two-session'):
            source={'target':{'value':'https://project.example/'},'job_id':tool,'evidence_id':tool,'artifact_hash':'hash','result':{'tool':tool}}
            reports.append({'engagement_id':'e','source':source,'model':'local','created_at':'now',
                'assessment_mode':'blackbox','output':{'summary':tool,'observations':['o'],'limitations':['l'],'recommendations':[]}})
        db=MagicMock();db.execute.return_value.fetchall.return_value=[{'payload':json.dumps(item),'payload_hash':digest(item)} for item in reports]
        state=SimpleNamespace(engagements=SimpleNamespace(connect=lambda:db))
        with patch('deep_analysis.checked_source',side_effect=lambda state,db,project,engagement,jid,evidence:next(x['source'] for x in reports if x['source']['job_id']==jid)):
            text=chat_report(state,'project','Deep analisis https://project.example/ inventaris dan login')
        self.assertIn('inventory-html',text);self.assertIn('auth-two-session',text)

    def test_chat_report_rechecks_legacy_report_against_structured_facts(self):
        from deep_analysis import chat_report
        from security_jobs import digest
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        source={'target':{'value':'https://project.example/'},'job_id':'j','evidence_id':'ev','artifact_hash':'hash',
                'result':{'checks':[{'check':'content-security-policy','status':'missing'}]}}
        legacy={'engagement_id':'e','source':source,'model':'local','created_at':'then','assessment_mode':'blackbox',
                'output':{'summary':'CSP tersedia dan aman.','observations':['Header CSP diterapkan.','Status 200.'],
                          'limitations':['l'],'recommendations':[]}}
        db=MagicMock();db.execute.return_value.fetchall.return_value=[{'payload':json.dumps(legacy),'payload_hash':digest(legacy)}]
        state=SimpleNamespace(engagements=SimpleNamespace(connect=lambda:db))
        with patch('deep_analysis.checked_source',return_value=source):
            text=chat_report(state,'project','Deep analisis https://project.example/')
        self.assertNotIn('tersedia dan aman',text);self.assertNotIn('diterapkan',text)
        self.assertIn('Laporan lama',text);self.assertIn('2 pernyataan',text);self.assertIn('Status 200.',text)

    def test_unknown_job_rejected_before_model(self):
        # A nonexistent job is rejected before any model call.
        from uuid import uuid4
        with patch('deep_analysis.runtime.chat', new=AsyncMock()) as model:
            response = self.client.post(self.url+'/deep-analysis', headers=self.headers,
                json={'job_id':str(uuid4()),'model':'local','actor_label':'QA','acknowledge':True})
            self.assertEqual(response.status_code,404)
            model.assert_not_called()

    def test_catalog_never_grants_execution(self):
        endpoint = self.url + '/deep-analysis/capabilities'
        self.assertEqual(self.client.get(endpoint).status_code, 401)
        with patch('deep_analysis.shutil.which', return_value='C:/test/nuclei.exe'), \
             patch('zap_adapter.image_hash', return_value=None), \
             patch('subfinder_adapter.fingerprint', return_value=None), \
             patch('subfinder_adapter.amass_fingerprint', return_value=None), \
             patch('subprocess.Popen') as popen:
            result = self.client.get(endpoint,headers=self.headers)
            self.assertEqual(result.status_code,200,result.text)
            self.assertTrue(all(not tool['execution_enabled'] for tool in result.json()['tools']))
            self.assertFalse(result.json()['execution_pentest_enabled'])
            popen.assert_not_called()

    def test_external_import_is_declared_and_bound_to_job(self):
        from engagements import utc_now
        import test_security_jobs as base
        content = base.content()
        content.update(environment='staging', in_scope=[{'kind':'domain','value':'project.example'}],
                       out_of_scope=[], ports=[443], allowed_actions=['http_headers','document_review'],
                       max_http_rps=1, max_concurrency=1, test_account_refs=['qa-reader'])
        self.engagement = self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        self.url = self.base + '/' + self.engagement['id']
        job = self.client.post(self.url+'/jobs', headers=self.headers, json=self.plan()).json()
        approved = self.client.post(self.url+'/jobs/'+job['id']+'/approve', headers=self.headers,
            json={'expected_revision':job['revision'],'actor_label':'QA','note':'Approved HEAD','acknowledge':True})
        self.assertEqual(approved.status_code,200,approved.text)
        self.jobs.claim(self.owner)
        self.jobs.step(self.owner,job['id'])
        with patch('web_checks.probe',return_value={'adapter':'public-head-1.0','url':'https://project.example/','method':'HEAD','requests':1,'http_status':200,'checks':[]}):
            self.client.portal.call(self.client.app.state.web_runner.execute,self.owner,job['id'])
        imported = self.client.post(self.url+'/evidence',headers=self.headers,json={
            'job_id':job['id'],'step_ordinal':1,'source':'external_import','title':'ZAP report excerpt',
            'captured_at':utc_now().isoformat(),'tool_name':'ZAP','tool_version':'test',
            'parameters':'operator reviewed','content':'Observation: CSP absent.','acknowledge':True})
        self.assertEqual(imported.status_code,201,imported.text)
        evidence=imported.json()
        output={'summary':'Perlu review.','observations':['CSP dilaporkan absen.'],
                'limitations':['Impor belum diverifikasi.'],'recommendations':['Tinjau ulang.']}
        payload={'job_id':job['id'],'evidence_id':evidence['id'],'model':'local','actor_label':'QA','acknowledge':True}
        with patch('deep_analysis.installed_models',new=AsyncMock(return_value=[{'name':'local','digest':'abc'}])), \
             patch('deep_analysis.runtime.chat',new=AsyncMock(return_value={'content':json.dumps(output),'tool_calls':[]})) as model:
            response=self.client.post(self.url+'/deep-analysis',headers=self.headers,json=payload)
            self.assertEqual(response.status_code,201,response.text)
            report=response.json()
            self.assertEqual(report['tool_execution'],'operator_declared_import')
            self.assertEqual(report['source']['evidence_id'],evidence['id'])
            self.assertIn('not been independently verified',model.call_args.args[1][0]['content'])
            chat=self.client.post('/api/chat',headers=self.headers,json={'project_id':self.engagement['project_id'],
                'prompt':'Deep analisis https://project.example/'})
            self.assertIn('pelaksanaan tool tidak diverifikasi',chat.text)
            for mode, kind, account in [('whitebox','source_code',''),('greybox','authenticated_observation','qa-reader')]:
                response=self.client.post(self.url+'/deep-analysis',headers=self.headers,
                    json={**payload,'assessment_mode':mode,'evidence_kind':kind,'test_account_ref':account})
                self.assertEqual(response.status_code,201,response.text)
                self.assertEqual(response.json()['assessment_mode'],mode)
                self.assertIn(mode,model.call_args.args[1][1]['content'])
                chat=self.client.post('/api/chat',headers=self.headers,json={'project_id':self.engagement['project_id'],
                    'prompt':f'Deep analisis {mode} https://project.example/'})
                self.assertIn(mode.capitalize(),chat.text.replace('WhiteBox','Whitebox').replace('GreyBox','Greybox'))
            for changes in [
                {'assessment_mode':'greybox','evidence_kind':'authenticated_observation','test_account_ref':'unknown'},
                {'assessment_mode':'whitebox','evidence_kind':'external_observation'},
                {'assessment_mode':'whitebox','evidence_kind':'source_code','evidence_id':None},
                {'assessment_mode':'blackbox','test_account_ref':'qa-reader'},
            ]:
                calls=model.call_count
                denied=self.client.post(self.url+'/deep-analysis',headers=self.headers,json={**payload,**changes})
                self.assertEqual(denied.status_code,422,denied.text)
                self.assertEqual(calls,model.call_count)
            payload['evidence_id']=job['id']
            self.assertEqual(self.client.post(self.url+'/deep-analysis',headers=self.headers,json=payload).status_code,404)

