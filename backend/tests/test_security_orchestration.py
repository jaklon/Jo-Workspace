import asyncio
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock,patch
from uuid import uuid4

import test_security_jobs as jobtests
from engagements import utc_now
from security_jobs import Approval,OfflineJobRunner,Stop
from security_orchestration import OrchestrationWorker,OrchestrationStore,PlannerOutput,ExecutorOutput,ReviewerOutput,installed_models
from mcp_gateway import ServerConfig,ServerDecision
from mcp_sandbox import SandboxRuntime,supported

MODELS=[{'name':'qa-local:latest','digest':'synthetic-model-digest'}]


class OrchestrationTests(unittest.TestCase):
    setUpFixture=jobtests.JobApiTests.setUpFixture
    tearDownFixture=jobtests.JobApiTests.tearDown
    create_engagement=jobtests.JobApiTests.create_engagement
    decide=jobtests.JobApiTests.decide

    def setUp(self):
        self.setUpFixture()
        self.client.portal.call(self.client.app.state.orchestration_worker.stop)
        self.client.portal.call(self.client.app.state.job_runner.stop)
        self.store=self.client.app.state.orchestrations;self.jobs=self.client.app.state.jobs
        self.worker=OrchestrationWorker(self.store);self.store.acquire(self.worker.owner)
        self.job_owner='qa-orchestration-job-worker';self.jobs.acquire(self.job_owner)
        self.models=patch('security_orchestration.installed_models',new=AsyncMock(return_value=MODELS));self.models.start()
        content=jobtests.content();content['allowed_actions'].append('configuration_review')
        self.engagement=self.decide(self.decide(self.create_engagement(content),'submit'),'approve')
        gateway=self.client.app.state.mcp
        self.server=gateway.create(ServerConfig(name='Orchestration QA',allowed_tools=['fixture.inspect','fixture.compare']))
        self.server=gateway.decide(self.server['id'],ServerDecision(expected_revision=1,action='approve',actor_label='QA',note='Fixtures only',acknowledge=True))
        gateway.runtime=SandboxRuntime(Path(__file__).resolve().parents[2]/'output/security-stage6/test-runtime')
        self.url=self.base+'/'+self.engagement['id'];self.runs=self.url+'/orchestrations'

    def tearDown(self):
        self.store.release(self.worker.owner);self.jobs.release(self.job_owner)
        self.models.stop();self.tearDownFixture()

    def body(self,**changes):
        head=self.engagement['versions'][0]
        return {'name':'Synthetic fixture workflow','objective':'Compare bundled header fixtures only.','model':MODELS[0]['name'],
            'playbook_id':'fixture-header-review','target':jobtests.step()['target'],
            'server_id':self.server['id'],'server_revision':self.server['revision'],'descriptor_hash':self.server['descriptor_hash'],
            'expected_roe_revision':self.engagement['revision'],'roe_version':head['version'],'content_hash':head['content_hash'],'acknowledge':True,**changes}

    def create(self,status=201,**changes):
        response=self.client.post(self.runs,headers=self.headers,json=self.body(**changes))
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def detail(self,row):return self.client.get(self.runs+'/'+row['id'],headers=self.headers).json()

    def decision(self,row,action,status=200,**changes):
        response=self.client.post(self.runs+'/'+row['id']+'/'+action,headers=self.headers,json={'expected_revision':row['revision'],'actor_label':'QA declared analyst','note':'Reviewed checkpoint and local fixture restrictions.','acknowledge':True,**changes})
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def role(self):
        data=self.store.advance(self.worker.owner)
        self.assertIsNotNone(data)
        async def response(data,role,messages,limit):
            if role=='planner':result={'rationale':'Use synthetic header fixtures only.','actions':[{'fixture':'headers_missing','compare_to':'headers_present'}]}
            elif role=='executor':result={'action_indices':[0],'reason':'Request the exact reviewed fixture action.'}
            else:result={'summary':'Synthetic fixture difference; not a target vulnerability.','evidence_ids':[e['evidence_id'] for e in self.store.reviewer_context(data)],'uncertainties':['No real target was tested.'],'needs_human_review':True,'finding_status':'candidate_only'}
            return result,{'prompt_eval_count':100,'eval_count':50}
        with patch.object(self.worker,'invoke',side_effect=response):self.client.portal.call(self.worker.execute,data)
        return self.detail(data)

    def waiting(self):
        row=self.create();row=self.role();self.assertEqual(row['status'],'awaiting_approval')
        self.decision(row,'approve');row=self.role();self.assertEqual(row['status'],'waiting_jobs');return row

    def test_catalog_auth_local_models_playbooks_and_no_auto_calls(self):
        self.assertEqual(self.client.get('/api/security/orchestration/catalog').status_code,401)
        catalog=self.client.get('/api/security/orchestration/catalog',headers=self.headers).json()
        self.assertEqual(catalog['roles'],['planner','executor','reviewer'])
        self.assertTrue(all(b['sources'] and b['version'] and len(b['hash'])==64 for b in catalog['playbooks']))
        with patch.object(self.worker,'invoke') as model:
            row=self.create();model.assert_not_called()
        self.assertEqual(row['status'],'queued_planner');self.assertEqual(row['model_calls'],0)

    def test_schema_limits_unknown_model_secret_errors_and_project_boundary(self):
        for changes in ({'max_calls':7},{'max_steps':4},{'max_tokens':60001},{'active_seconds':901},{'output_tokens':True},
                        {'playbook_id':'unknown'},{'acknowledge':False},{'model':'not-installed:cloud'},{'execution_enabled':True}):
            self.create(422,**changes)
        row=self.create()
        wrong=self.runs.replace(self.project,str(uuid4()))
        self.assertEqual(self.client.get(wrong+'/'+row['id'],headers=self.headers).status_code,404)
        response=self.client.post(self.runs,headers=self.headers,json={**self.body(),'private_key':'synthetic-secret-input'})
        self.assertNotIn('synthetic-secret-input',response.text)
        self.assertNotIn('"input"',response.text)

    def test_scope_roe_and_profile_guards_block_creation(self):
        self.create(422,target={'kind':'ip','value':'10.30.0.99'})
        self.create(409,content_hash='0'*64)
        self.client.app.state.mcp.decide(self.server['id'],ServerDecision(expected_revision=self.server['revision'],action='disable',actor_label='QA',note='Disabled',acknowledge=True))
        self.create(409)

    def test_planner_review_then_executor_creates_only_unapproved_jobs(self):
        self.create();planned=self.role()
        self.assertEqual(planned['model_calls'],1)
        self.assertEqual(planned['request']['playbook']['id'],'fixture-header-review')
        self.assertIsNone(self.store.advance(self.worker.owner))
        self.decision(planned,'approve',422,acknowledge=False)
        self.decision(planned,'approve')
        self.decision(planned,'approve',409)
        row=self.role();self.assertEqual(row['status'],'waiting_jobs')
        for jid in row['jobs']:
            job=self.jobs.detail(self.project,self.engagement['id'],jid)
            self.assertEqual(job['status'],'awaiting_approval');self.assertIsNone(job['approver'])
            self.assertEqual(job['plan']['mcp']['tool'],'fixture.compare')
        self.assertIsNone(self.store.advance(self.worker.owner))

    @unittest.skipUnless(supported(),'Windows AppContainer unavailable')
    def test_full_three_roles_evidence_reviewer_cannot_confirm_findings(self):
        row=self.waiting()
        for jid in row['jobs']:
            job=self.jobs.detail(self.project,self.engagement['id'],jid)
            self.jobs.approve(self.project,self.engagement['id'],jid,Approval(expected_revision=job['revision'],actor_label='QA human',note='Reviewed job separately',acknowledge=True))
            self.jobs.claim(self.job_owner);runner=OfflineJobRunner(self.jobs);runner.owner=self.job_owner
            self.client.portal.call(runner.execute,jid)
        done=self.role();self.assertEqual(done['status'],'completed')
        self.assertEqual(done['model_calls'],3);self.assertTrue(done['reviewer']['needs_human_review'])
        self.assertEqual(done['reviewer']['finding_status'],'candidate_only')
        records=self.client.get(self.url+'/records',headers=self.headers).json()
        self.assertEqual(records['findings'],[]);self.assertEqual(len(records['evidence']),1)
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={}).status_code,423)
        self.assertTrue(all(c['snapshot']['request']['model']==MODELS[0]['name'] for c in done['checkpoints']))

    def test_stop_engagement_pauses_orchestration_and_cancels_linked_jobs(self):
        row=self.waiting();self.jobs.stop_engagement(self.project,self.engagement['id'],Stop())
        paused=self.detail(row);self.assertEqual(paused['status'],'paused')
        self.assertEqual(self.jobs.detail(self.project,self.engagement['id'],row['jobs'][0])['status'],'cancelled')
        self.decision(paused,'resume',423)

    def test_pause_resume_preserves_budgets_and_checkpoint_requires_reapproval(self):
        row=self.waiting();paused=self.decision(row,'pause');cost=paused['token_reserved']
        resumed=self.decision(paused,'resume')
        self.assertEqual(resumed['status'],'awaiting_approval')
        self.assertEqual(resumed['model_calls'],2);self.assertEqual(resumed['token_reserved'],cost)
        self.assertEqual(self.jobs.detail(self.project,self.engagement['id'],row['jobs'][0])['status'],'cancelled')
        self.decision(resumed,'approve');new=self.role()
        self.assertNotEqual(new['jobs'],row['jobs']);self.assertEqual(new['batch'],2)
        self.assertEqual(self.jobs.detail(self.project,self.engagement['id'],new['jobs'][0])['status'],'awaiting_approval')

    def test_restart_pauses_does_not_replay_model_or_jobs(self):
        row=self.waiting();self.store.release(self.worker.owner)
        reopened=OrchestrationStore(self.store.engagements,self.jobs,self.store.gateway,self.store.evidence)
        reopened.acquire('replacement')
        paused=reopened.detail(self.project,self.engagement['id'],row['id'])
        self.assertEqual(paused['status'],'paused');self.assertEqual(paused['model_calls'],2)
        self.assertIsNone(reopened.advance('replacement'));reopened.release('replacement')

    def test_model_failure_preserves_planner_no_auto_retry(self):
        self.create();planned=self.role();self.decision(planned,'approve')
        data=self.store.advance(self.worker.owner)
        with patch.object(self.worker,'invoke',new=AsyncMock(side_effect=ValueError('Synthetic model failure'))):self.client.portal.call(self.worker.execute,data)
        paused=self.detail(data);self.assertEqual(paused['status'],'paused');self.assertEqual(paused['planner'],planned['planner'])
        self.assertEqual(paused['jobs'],[]);self.assertIsNone(self.store.advance(self.worker.owner))

    def test_invalid_model_action_and_executor_extra_steps_fail_closed(self):
        self.create();data=self.store.advance(self.worker.owner)
        bad={'rationale':'Try forbidden fixture','actions':[{'fixture':'shell','compare_to':None}]}
        with patch.object(self.worker,'invoke',new=AsyncMock(return_value=(bad,{}))):self.client.portal.call(self.worker.execute,data)
        self.assertEqual(self.detail(data)['status'],'paused')
        self.create();planned=self.role();self.decision(planned,'approve');data=self.store.advance(self.worker.owner)
        with patch.object(self.worker,'invoke',new=AsyncMock(return_value=({'action_indices':[0,1],'reason':'Extra'},{}))):self.client.portal.call(self.worker.execute,data)
        row=self.detail(data);self.assertEqual(row['status'],'paused');self.assertEqual(row['jobs'],[])

    def test_model_digest_drift_never_calls_another_model(self):
        self.create();data=self.store.advance(self.worker.owner)
        with patch('security_orchestration.installed_models',new=AsyncMock(return_value=[{'name':MODELS[0]['name'],'digest':'changed'}])),patch.object(self.worker,'invoke') as invoke:
            self.client.portal.call(self.worker.execute,data);invoke.assert_not_called()
        self.assertEqual(self.detail(data)['status'],'paused')

    def test_token_call_and_time_limits_do_not_reset_on_resume(self):
        row=self.create();data=self.store.advance(self.worker.owner)
        with self.store.engagements.transaction() as db:
            d=self.store.row(db,self.project,self.engagement['id'],row['id']);d['token_reserved']=d['request']['max_tokens'];self.store.save(db,d,'test_budget')
        with patch.object(self.worker,'invoke') as invoke:self.client.portal.call(self.worker.execute,data);invoke.assert_not_called()
        paused=self.detail(row);self.assertEqual(paused['status'],'paused')
        self.decision(paused,'resume',409)
        row=self.create();data=self.store.advance(self.worker.owner)
        with self.store.engagements.transaction() as db:
            d=self.store.row(db,self.project,self.engagement['id'],row['id']);d['active_seconds']=d['request']['active_seconds'];self.store.save(db,d,'test_time')
        self.client.portal.call(self.worker.execute,data)
        paused=self.detail(row);self.decision(paused,'resume',409)

    @unittest.skipUnless(supported(),'Windows AppContainer unavailable')
    def test_reviewer_fabricated_evidence_is_rejected_and_real_evidence_retained(self):
        row=self.waiting()
        for jid in row['jobs']:
            job=self.jobs.detail(self.project,self.engagement['id'],jid)
            self.jobs.approve(self.project,self.engagement['id'],jid,Approval(expected_revision=job['revision'],actor_label='QA',note='Separate job review',acknowledge=True))
            self.jobs.claim(self.job_owner);runner=OfflineJobRunner(self.jobs);runner.owner=self.job_owner;self.client.portal.call(runner.execute,jid)
        data=self.store.advance(self.worker.owner)
        fake={'summary':'Invalid reference','evidence_ids':[str(uuid4())],'uncertainties':['Synthetic only'],'needs_human_review':True,'finding_status':'candidate_only'}
        with patch.object(self.worker,'invoke',new=AsyncMock(return_value=(fake,{}))):self.client.portal.call(self.worker.execute,data)
        result=self.detail(row);self.assertEqual(result['status'],'paused');self.assertIsNone(result['reviewer'])
        self.assertEqual(len(self.client.get(self.url+'/records',headers=self.headers).json()['evidence']),1)

    def test_call_budget_is_reserved_before_model_and_never_bypassed(self):
        row=self.create();data=self.store.advance(self.worker.owner)
        with self.store.engagements.transaction() as db:
            d=self.store.row(db,self.project,self.engagement['id'],row['id']);d['model_calls']=d['request']['max_calls'];self.store.save(db,d,'test_calls')
        with patch.object(self.worker,'invoke') as invoke:self.client.portal.call(self.worker.execute,data);invoke.assert_not_called()
        self.decision(self.detail(row),'resume',409)

    def test_integrity_hash_tampering_blocks_reads(self):
        row=self.create()
        with self.store.engagements.transaction() as db:db.execute('UPDATE security_orchestrations SET payload=? WHERE id=?',(json.dumps({'tampered':True}),row['id']))
        self.assertEqual(self.client.get(self.runs+'/'+row['id'],headers=self.headers).status_code,409)
        self.jobs.stop_engagement(self.project,self.engagement['id'],Stop())
        with closing(self.store.engagements.connect()) as db:
            self.assertEqual(db.execute('SELECT status FROM security_orchestrations WHERE id=?',(row['id'],)).fetchone()[0],'quarantined')

    def test_model_stream_enforces_schema_and_rejects_tool_calls(self):
        row=self.create()
        async def fake(*args,**kwargs):
            self.assertTrue(kwargs['local_only']);self.assertIsNotNone(kwargs['format_schema'])
            yield {'message':{'content':'{"rationale":"Only fixtures","actions":[{"fixture":"headers_missing","compare_to":"headers_present"}]}'}}
            yield {'done':True,'done_reason':'stop','prompt_eval_count':20,'eval_count':30}
        with patch('model_runtime.runtime.chunks',new=fake):
            result,metrics=self.client.portal.call(self.worker.invoke,row,'planner',[],512)
        self.assertEqual(result['actions'][0]['fixture'],'headers_missing');self.assertEqual(metrics['eval_count'],30)
        async def forbidden(*args,**kwargs):yield {'message':{'tool_calls':[{'function':{'name':'shell'}}]}}
        with patch('model_runtime.runtime.chunks',new=forbidden):
            with self.assertRaises(ValueError):self.client.portal.call(self.worker.invoke,row,'planner',[],512)

    def test_cancel_during_model_call_closes_task(self):
        self.create();data=self.store.advance(self.worker.owner)
        async def scenario():
            entered=asyncio.Event();cancelled=asyncio.Event()
            async def blocked(*args):
                entered.set()
                try:await asyncio.Event().wait()
                finally:cancelled.set()
            with patch.object(self.worker,'invoke',side_effect=blocked):
                task=asyncio.create_task(self.worker.execute(data));await asyncio.wait_for(entered.wait(),2)
                current=self.store.detail(self.project,self.engagement['id'],data['id'])
                # Direct store mutation avoids a synchronous HTTP call into the same portal.
                from security_orchestration import RunDecision
                self.store.decide(self.project,self.engagement['id'],data['id'],'pause',RunDecision(expected_revision=current['revision'],actor_label='QA',note='Stop model',acknowledge=True))
                await asyncio.wait_for(task,2);self.assertTrue(cancelled.is_set())
        self.client.portal.call(scenario)
        self.assertEqual(self.detail(data)['status'],'paused')


class LocalModelBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_remote_ollama_is_rejected_before_http(self):
        from fastapi import HTTPException
        with patch('model_runtime.OLLAMA_URL','https://remote.example.test'),patch('httpx.AsyncClient') as client:
            with self.assertRaises(HTTPException):await installed_models()
            client.assert_not_called()


if __name__=='__main__':unittest.main()
