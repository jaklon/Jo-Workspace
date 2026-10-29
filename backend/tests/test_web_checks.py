import asyncio
import ipaddress
import json
import socket
import ssl
import unittest
from unittest.mock import patch

import test_security_jobs as base
from engagements import utc_now
from security_jobs import Approval
from web_checks import validate_plan, resolve, probe, http_configuration


class WebCheckTests(unittest.TestCase):
    setUpFixture = base.JobApiTests.setUpFixture
    tearDownFixture = base.JobApiTests.tearDown
    create_engagement = base.JobApiTests.create_engagement
    decide = base.JobApiTests.decide

    def setUp(self):
        self.setUpFixture()
        self.client.portal.call(self.client.app.state.job_runner.stop)
        self.jobs = self.client.app.state.jobs
        self.owner = 'web-test-worker'
        self.jobs.acquire(self.owner)
        content = base.content()
        content.update(environment='production_readonly', in_scope=[{'kind':'domain','value':'project.example'}],
                       out_of_scope=[], ports=[443], allowed_actions=['http_headers'], max_http_rps=1,
                       max_concurrency=1)
        self.engagement = self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        self.url = self.base + '/' + self.engagement['id']

    def tearDown(self):
        self.jobs.release(self.owner)
        self.tearDownFixture()

    def plan(self, url='https://project.example/'):
        head=self.engagement['versions'][0]
        return {'name':'Public URL HEAD', 'expected_roe_revision':self.engagement['revision'],
                'roe_version':head['version'], 'content_hash':head['content_hash'],
                'steps':[{'target':{'kind':'url','value':url},'action':'http_headers','ports':[],
                          'max_http_rps':1,'max_concurrency':1,'max_duration_minutes':1,'test_account_ref':''}],
                'web':{'adapter':'public-head-1.0'},'wall_timeout_seconds':20,'max_output_kb':64}

    def test_scope_approval_evidence_report_and_lock(self):
        for url in ('http://project.example/', 'https://other.example/', 'https://127.0.0.1/',
                    'https://169.254.169.254/', 'https://project.example:8443/'):
            response=self.client.post(self.url+'/jobs',headers=self.headers,json=self.plan(url))
            if response.status_code==201:
                approval=Approval(expected_revision=response.json()['revision'],actor_label='QA',note='Reviewed',acknowledge=True)
                self.assertEqual(self.client.post(self.url+'/jobs/'+response.json()['id']+'/approve',headers=self.headers,json=approval.model_dump()).status_code,422)
            else:self.assertEqual(response.status_code,422,response.text)
        made=self.client.post(self.url+'/jobs',headers=self.headers,json=self.plan())
        self.assertEqual(made.status_code,201,made.text)
        row=made.json()
        self.assertEqual(row['status'],'awaiting_approval')
        self.assertEqual(self.client.get(self.url+'/jobs/'+row['id']).status_code,401)
        approved=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,
                                  json={'expected_revision':row['revision'],'actor_label':'QA','note':'One HEAD approved','acknowledge':True})
        self.assertEqual(approved.status_code,200,approved.text)
        self.assertEqual(self.jobs.claim(self.owner),row['id'])
        self.assertFalse(self.jobs.step(self.owner,row['id']))
        synthetic={'adapter':'public-head-1.0','url':'https://project.example/','method':'HEAD','requests':1,
                   'http_status':200,'redirect_followed':False,'body_collected':False,'credentials_sent':False,
                   'tls':{'verified':True},'checks':[{'check':'content-security-policy','status':'present'}]}
        with patch('web_checks.probe',return_value=synthetic):
            self.client.portal.call(self.client.app.state.web_runner.execute,self.owner,row['id'])
        detail=self.client.get(self.url+'/jobs/'+row['id'],headers=self.headers).json()
        self.assertEqual(detail['status'],'completed')
        self.assertEqual(detail['web_result']['http_status'],200)
        self.assertTrue(detail['web_result']['evidence_id'])
        evidence=self.client.get(self.url+'/records',headers=self.headers).json()
        self.assertTrue(any(e['id']==detail['web_result']['evidence_id'] for e in evidence['evidence']))
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={'target_id':'builtin-lab'}).status_code,423)

    def test_adapter_bounds_and_dns_fail_closed(self):
        for change in ({'wall_timeout_seconds':21}, {'mcp':{'server_id':'invalid'}},
                       {'steps':self.plan()['steps']*2}):
            with self.assertRaises((ValueError,KeyError)):
                validate_plan({**self.plan(),**change})
        async def dns():
            loop=asyncio.get_running_loop()
            def fake(host,port,**kwargs):
                return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',port)),
                        (socket.AF_INET,socket.SOCK_STREAM,6,'',('169.254.169.254',port))]
            with patch.object(loop,'getaddrinfo',side_effect=fake):
                with self.assertRaisesRegex(ValueError,'DNS_NON_PUBLIC_ADDRESS'):
                    await resolve('project.example',443,[])
            with patch.object(loop,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]):
                with self.assertRaisesRegex(ValueError,'DNS_ADDRESS_EXCLUDED'):
                    from engagements import ScopeAsset
                    await resolve('project.example',443,[ScopeAsset(kind='cidr',value='8.8.8.0/24')])
        asyncio.run(dns())

    def test_http_configuration_does_not_include_sensitive_values(self):
        result = http_configuration({'cache-control':['private, no-store'],
            'access-control-allow-origin':['*'], 'access-control-allow-credentials':['true'],
            'set-cookie':['session=secret; Secure']})
        self.assertTrue(result['cache']['no_store'])
        self.assertTrue(result['cache']['private'])
        self.assertTrue(result['cors']['wildcard_origin_observed'])
        self.assertTrue(result['cors']['allow_credentials_true'])
        self.assertIn('bukan uji CORS', result['cors']['limitation'])
        self.assertNotIn('secret',json.dumps(result))
        self.assertFalse(http_configuration({})['cors']['allow_origin_present'])

    def test_stop_and_roe_change_prevent_network(self):
        row=self.client.post(self.url+'/jobs',headers=self.headers,json=self.plan()).json()
        response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={
            'expected_revision':row['revision'],'actor_label':'QA','note':'Reviewed','acknowledge':True})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(self.jobs.claim(self.owner),row['id'])
        self.assertFalse(self.jobs.step(self.owner,row['id']))
        self.client.post(self.url+'/jobs/'+row['id']+'/stop',headers=self.headers,json={})
        with patch('web_checks.probe') as network:
            self.client.portal.call(self.client.app.state.web_runner.execute,self.owner,row['id'])
            network.assert_not_called()
        self.assertEqual(self.client.get(self.url+'/jobs/'+row['id'],headers=self.headers).json()['status'],'cancelled')
