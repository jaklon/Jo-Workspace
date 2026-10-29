import asyncio
from contextlib import closing
import json
import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import HTTPException
import test_security_jobs as jobtests
from security_jobs import Approval, Stop
from security_agents import SpecialistStore, SpecialistWorker, AgentConfig, ReportingOutput, output_schema
from security_agent_lab import PROFILES, observations, lab_descriptor

MODELS=[{'name':'qa-specialist:latest','digest':'qa-pinned-model'}]


class SpecialistTests(unittest.TestCase):
    setUpFixture=jobtests.JobApiTests.setUpFixture
    tearDownFixture=jobtests.JobApiTests.tearDown
    create_engagement=jobtests.JobApiTests.create_engagement
    decide=jobtests.JobApiTests.decide

    def setUp(self):
        self.setUpFixture()
        for name in ('orchestration_worker','specialist_worker','job_runner'):self.client.portal.call(getattr(self.client.app.state,name).stop)
        self.store=self.client.app.state.specialists;self.jobs=self.client.app.state.jobs
        self.worker=SpecialistWorker(self.store);self.store.acquire(self.worker.owner)
        self.job_owner='qa-specialist-jobs';self.jobs.acquire(self.job_owner)
        self.models=patch('security_agents.installed_models',new=AsyncMock(return_value=MODELS));self.models.start()
        c=jobtests.content();c.update(environment='lab',allowed_actions=list(dict.fromkeys(p['action'] for p in PROFILES.values())),test_account_refs=['synthetic-alice','synthetic-bob'])
        self.engagement=self.decide(self.decide(self.create_engagement(c),'submit'),'approve')
        self.url=self.base+'/'+self.engagement['id'];self.teams=self.url+'/agents'
        self.lab=self.post('/agent-labs',self.lab_body())

    def tearDown(self):
        self.store.release(self.worker.owner);self.jobs.release(self.job_owner);self.models.stop();self.tearDownFixture()

    def binding(self):
        return {'expected_roe_revision':self.engagement['revision'],'roe_version':self.engagement['versions'][0]['version'],'content_hash':self.engagement['versions'][0]['content_hash']}

    def lab_body(self,**changes):
        return {**self.binding(),'name':'QA registered synthetic lab','target':jobtests.step()['target'],'account_aliases':['synthetic-alice','synthetic-bob'],'acknowledge':True,**changes}

    def body(self,roles=None,**changes):
        return {**self.binding(),'name':'QA specialists','objective':'Assess only bundled positive and negative controls.','model':MODELS[0]['name'],'lab_id':self.lab['id'],
          'agents':[{'role':r,'permissions':[PROFILES[r]['permission']]} for r in (roles or list(PROFILES))],'acknowledge':True,**changes}

    def post(self,path,body,status=201):
        response=self.client.post(self.url+path,headers=self.headers,json=body)
        self.assertEqual(response.status_code,status,response.text);return response.json()

    def create(self,roles=None,status=201,**changes):return self.post('/agents',self.body(roles,**changes),status)

    def detail(self,row):
        response=self.client.get(self.teams+'/'+row['id'],headers=self.headers);self.assertEqual(response.status_code,200,response.text);return response.json()

    def decision(self,row,action,status=200,**changes):
        return self.post('/agents/'+row['id']+'/'+action,{'expected_revision':row['revision'],'actor_label':'QA analyst','note':'Review immutable permissions and budget.','acknowledge':True,**changes},status)

    def ready(self,row):
        work=self.store.advance(self.worker.owner)
        if work:return work
        row=self.detail(row)
        a=next(a for a in row['agents'] if a['status']!='completed')
        job=self.jobs.detail(self.project,self.engagement['id'],a['job_id'])
        self.assertEqual(job['status'],'awaiting_approval');self.assertIsNone(job['approver'])
        self.jobs.approve(self.project,self.engagement['id'],job['id'],Approval(expected_revision=job['revision'],actor_label='QA human',note='Separate approval for offline policy only.',acknowledge=True))
        self.assertEqual(self.jobs.claim(self.job_owner),job['id'])
        while self.jobs.step(self.job_owner,job['id']):pass
        return self.store.advance(self.worker.owner)

    def answer(self,data,role,wrong=False):
        a=next(a for a in data['agents'] if a['role']==role)
        return {'summary':'Synthetic observations only; require analyst review.',
                'assessments':[{'case_id':c['case_id'],'assessment':'candidate' if wrong else c['expected_assessment'],'reason':'Deterministic synthetic observation.'} for c in (a['lab_result'] or [])],
                'evidence_ids':a['evidence_ids'],'uncertainties':['Only bundled toy controls; no real target.'],
                'needs_human_review':True,'finding_status':'candidate_only'}

    def finish(self,roles=None,wrong=False):
        row=self.decision(self.create(roles),'approve')
        for _ in row['agents']:
            data,role=self.ready(row)
            with patch.object(self.worker,'invoke',new=AsyncMock(return_value=(self.answer(data,role,wrong),{'prompt_eval_count':100,'eval_count':50}))):self.client.portal.call(self.worker.execute,data,role)
            row=self.detail(row);self.assertNotEqual(row['status'],'paused',row['error'])
        self.assertEqual(row['status'],'completed');return row

    def test_catalog_auth_and_capability_schema(self):
        self.assertEqual(self.client.get('/api/security/agents/catalog').status_code,401)
        c=self.client.get('/api/security/agents/catalog',headers=self.headers).json()
        self.assertEqual(len(c['profiles']),5);self.assertEqual(c['max_parallel'],1);self.assertFalse(c['pentest_execution_enabled'])
        self.assertEqual(len(c['lab']['hash']),64)
        for role,p in PROFILES.items():
            with self.assertRaises(ValueError):AgentConfig(role=role,permissions=['report.compose' if role!='reporting' else 'lab.auth'])

    def test_lab_scope_registration_alias_and_unknown_input_denied(self):
        for changes,status in [({'target':{'kind':'ip','value':'10.30.0.99'}},422),({'account_aliases':['synthetic-alice']*2},422),
                               ({'account_aliases':['unregistered']},422),({'acknowledge':False},422),({'url':'https://external.invalid'},422),({'content_hash':'0'*64},409)]:
            self.post('/agent-labs',self.lab_body(**changes),status)
        self.create(roles=['auth_bola'],lab_id=self.post('/agent-labs',self.lab_body(account_aliases=[]))['id'],status=422)

    def test_budget_limits_unknown_model_permission_escalation_and_secret_errors(self):
        bad=[{'max_parallel':2},{'max_calls':16},{'max_tokens':120001},{'active_seconds':901},{'max_calls':True},
             {'model':'paid-cloud:cloud'},{'agents':[{'role':'recon','permissions':['lab.auth']}]},
             {'agents':[{'role':'recon','permissions':['lab.recon'],'max_calls':4}]},
             {'agents':[{'role':'recon','permissions':['lab.recon'],'context_tokens':12001}]},
             {'agents':[{'role':'reporting','permissions':['report.compose']}]},
             {'agents':[{'role':'recon','permissions':['lab.recon']}]*2},{'max_tokens':4000},{'execution_enabled':True}]
        for changes in bad:self.create(status=422,**changes)
        response=self.client.post(self.teams,headers=self.headers,json={**self.body(),'credential':'synthetic-private-input'})
        self.assertEqual(response.status_code,422);self.assertNotIn('synthetic-private-input',response.text);self.assertNotIn('"input"',response.text)

    def test_project_engagement_boundaries_and_no_model_before_approval(self):
        row=self.create()
        wrong=self.teams.replace(self.project,str(uuid4()))
        self.assertEqual(self.client.get(wrong+'/'+row['id'],headers=self.headers).status_code,404)
        self.assertIsNone(self.store.advance(self.worker.owner));self.assertEqual(row['metrics']['calls'],0)
        self.decision(row,'approve',422,acknowledge=False)
        self.decision(row,'approve',409,expected_revision=99)

    def test_human_job_approval_before_lab_or_model(self):
        row=self.decision(self.create(['recon']),'approve')
        self.assertIsNone(self.store.advance(self.worker.owner));row=self.detail(row)
        self.assertEqual(row['agents'][0]['status'],'waiting_job');self.assertEqual(row['metrics']['calls'],0)
        self.assertEqual(row['agents'][0]['evidence_ids'],[])
        self.assertIsNone(self.store.advance(self.worker.owner))

    def test_all_specialists_evidence_reporting_metrics_and_no_findings(self):
        row=self.finish()
        self.assertEqual(row['metrics']['case_count'],8);self.assertEqual(row['metrics']['coverage_percent'],100)
        self.assertEqual(row['metrics']['true_positives'],4);self.assertEqual(row['metrics']['false_positives'],0)
        self.assertEqual(row['metrics']['evidence_count'],4);self.assertEqual(row['metrics']['calls'],5)
        self.assertEqual(row['metrics']['measured_input_tokens'],500)
        records=self.client.get(self.url+'/records',headers=self.headers).json()
        self.assertEqual(records['findings'],[]);self.assertEqual(len(records['evidence']),4)
        self.assertTrue(all(e['provenance']=='server_synthetic_lab' and not e['pentest_executed'] for e in records['evidence']))
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={}).status_code,423)
        self.assertEqual(len(row['agents'][-1]['evidence_ids']),4)

    def test_context_and_evidence_are_separate_per_agent(self):
        row=self.decision(self.create(['recon','auth_bola']),'approve');data,role=self.ready(row)
        prompt=self.store.context(data,role)[1]['content']
        self.assertIn('inventory-exposed',prompt);self.assertNotIn('synthetic-bob',prompt);self.assertNotIn('bola-open',prompt)
        output=self.answer(data,role);self.store.commit(self.worker.owner,(self.project,self.engagement['id'],row['id']),role,output,{})
        data,role=self.ready(row);prompt=self.store.context(data,role)[1]['content']
        self.assertIn('bola-open',prompt);self.assertNotIn('inventory-exposed',prompt)
        self.assertNotIn('password',prompt);self.assertTrue(all(c['observed']['separate_sessions'] for c in data['agents'][1]['lab_result']))

    def test_llm_lab_verifiable_positive_negative_controls_no_network(self):
        with patch('socket.getaddrinfo') as dns,patch('socket.create_connection') as network,patch('subprocess.Popen') as shell:
            lab=observations('llm_security');auth=observations('auth_bola',['a','b'])
            for mock in (dns,network,shell):mock.assert_not_called()
        self.assertEqual([c['observed']['canary_disclosed'] for c in lab],[True,False])
        self.assertEqual([c['observed']['cross_status'] for c in auth],[200,403])
        self.assertEqual(lab_descriptor(),lab_descriptor())

    def test_model_cannot_forge_evidence_cases_or_confirm(self):
        for change in ('evidence','case','confirm'):
            row=self.decision(self.create(['web_api']),'approve');data,role=self.ready(row);out=self.answer(data,role)
            if change=='evidence':out['evidence_ids']=[str(uuid4())]
            elif change=='case':out['assessments'][0]['case_id']='bola-open'
            else:out['finding_status']='validated'
            with patch.object(self.worker,'invoke',new=AsyncMock(return_value=(out,{}))):self.client.portal.call(self.worker.execute,data,role)
            paused=self.detail(row);self.assertEqual(paused['status'],'paused');self.assertIsNone(paused['agents'][0]['output'])
            self.assertEqual(len(paused['agents'][0]['evidence_ids']),1)

    def test_false_positive_benchmark_and_reproducibility_measured(self):
        baseline=self.finish(['recon']);repeat=self.finish(['recon']);bad=self.finish(['web_api'],wrong=True)
        self.assertEqual(baseline['metrics']['coverage_percent'],25);self.assertEqual(bad['metrics']['false_positives'],1)
        self.assertEqual(bad['metrics']['false_positive_rate'],1)
        listing=self.client.get(self.teams,headers=self.headers).json()
        r=next(x for x in listing['items'] if x['id']==repeat['id'])
        self.assertEqual(r['repeatability'],{'comparable_runs':1,'identical_classifications':1})

    def test_pause_resume_preserves_budget_evidence_completed_roles(self):
        row=self.decision(self.create(['recon','web_api']),'approve');data,role=self.ready(row)
        with patch.object(self.worker,'invoke',new=AsyncMock(return_value=(self.answer(data,role),{}))):self.client.portal.call(self.worker.execute,data,role)
        self.store.advance(self.worker.owner);row=self.detail(row);paused=self.decision(row,'pause')
        self.assertEqual(paused['agents'][0]['status'],'completed')
        resumed=self.decision(paused,'resume');self.assertEqual(resumed['agents'][0],paused['agents'][0])
        self.assertEqual(resumed['metrics']['calls'],1);self.assertIsNone(resumed['agents'][1]['job_id'])
        self.store.advance(self.worker.owner);after=self.detail(row)
        self.assertEqual(after['agents'][1]['status'],'waiting_job');self.assertNotEqual(after['agents'][1]['job_id'],row['agents'][1]['job_id'])

    def test_restart_requires_resume_and_never_replays(self):
        row=self.decision(self.create(['recon']),'approve');self.store.advance(self.worker.owner)
        self.store.release(self.worker.owner)
        reopened=SpecialistStore(self.store.engagements,self.jobs,self.store.evidence);reopened.acquire('new-worker')
        paused=reopened.detail(self.project,self.engagement['id'],row['id']);self.assertEqual(paused['status'],'paused')
        self.assertIsNone(reopened.advance('new-worker'));reopened.release('new-worker')

    def test_stop_engagement_and_lab_disable_cancel_jobs(self):
        row=self.decision(self.create(['recon']),'approve');self.store.advance(self.worker.owner);row=self.detail(row)
        self.jobs.stop_engagement(self.project,self.engagement['id'],Stop())
        self.assertEqual(self.detail(row)['status'],'paused')
        self.assertEqual(self.jobs.detail(self.project,self.engagement['id'],row['agents'][0]['job_id'])['status'],'cancelled')
        self.decision(self.detail(row),'resume',423)

    def test_disabled_lab_immediately_pauses_and_cannot_resume(self):
        row=self.decision(self.create(['recon']),'approve');self.store.advance(self.worker.owner)
        self.post('/agent-labs/'+self.lab['id']+'/disable',{'expected_revision':1,'actor_label':'QA','note':'Disable lab','acknowledge':True},200)
        self.assertEqual(self.detail(row)['status'],'paused');self.decision(self.detail(row),'resume',409)

    def test_changed_roe_denies_pending_action(self):
        row=self.decision(self.create(['recon']),'approve');self.decide(self.engagement,'revoke')
        self.assertIsNone(self.store.advance(self.worker.owner));self.assertEqual(self.detail(row)['status'],'paused')

    def test_agent_call_budget_reserved_before_failure_no_retry(self):
        row=self.decision(self.create(['recon']),'approve');data,role=self.ready(row)
        with patch.object(self.worker,'invoke',new=AsyncMock(side_effect=ValueError('bad model'))):self.client.portal.call(self.worker.execute,data,role)
        paused=self.detail(row);self.assertEqual(paused['metrics']['calls'],1);self.assertGreater(paused['metrics']['token_reserved'],0)
        self.assertIsNone(self.store.advance(self.worker.owner));self.decision(paused,'resume',409)

    def test_context_token_time_and_global_budget_fail_closed(self):
        for field,value in [('token_reserved',12000),('active_seconds',120)]:
            row=self.decision(self.create(['recon']),'approve');data,role=self.ready(row)
            with self.store.engagements.transaction() as db:
                d=self.store.row(db,self.project,self.engagement['id'],row['id']);d['agents'][0][field]=value;self.store.save(db,d,'qa-exhaustion')
            with patch.object(self.worker,'invoke') as invoke:self.client.portal.call(self.worker.execute,data,role);invoke.assert_not_called()
            paused=self.detail(row);self.assertEqual(paused['status'],'paused');self.decision(paused,'resume',409)
        row=self.decision(self.create(['recon']),'approve');data,role=self.ready(row)
        with patch('config.CONTEXT_TOKENS',100):
            with patch.object(self.worker,'invoke') as invoke:self.client.portal.call(self.worker.execute,data,role);invoke.assert_not_called()
        self.assertEqual(self.detail(row)['metrics']['calls'],0)

    def test_integrity_corruption_quarantines_and_stops_bound_jobs(self):
        row=self.decision(self.create(['recon']),'approve');self.store.advance(self.worker.owner)
        with self.store.engagements.transaction() as db:db.execute('UPDATE specialist_teams SET payload=? WHERE id=?',('{"tampered":true}',row['id']))
        self.assertEqual(self.client.get(self.teams+'/'+row['id'],headers=self.headers).status_code,409)
        self.jobs.stop_engagement(self.project,self.engagement['id'],Stop())
        with closing(self.store.engagements.connect()) as db:
            self.assertEqual(db.execute('SELECT status FROM specialist_teams WHERE id=?',(row['id'],)).fetchone()[0],'quarantined')
            self.assertEqual(db.execute('SELECT status FROM security_jobs WHERE id IN (SELECT job_id FROM specialist_job_links WHERE team_id=?)',(row['id'],)).fetchone()[0],'cancelled')

    def test_worker_lease_excludes_second_coordinator(self):
        self.assertFalse(self.store.acquire('other-worker'));self.assertIsNone(self.store.advance('other-worker'))

    def test_stale_previous_worker_lease_cannot_accept_fresh_approval(self):
        row=self.create(['recon'])
        with self.store.engagements.transaction() as db:db.execute("UPDATE specialist_worker SET owner='prior-dead-worker' WHERE id=1")
        self.assertFalse(self.client.get(self.teams,headers=self.headers).json()['worker_active'])
        self.decision(row,'approve',503);self.assertEqual(self.detail(row)['status'],'awaiting_approval')
        with self.store.engagements.transaction() as db:db.execute('UPDATE specialist_worker SET owner=? WHERE id=1',(self.worker.owner,))

    def test_model_digest_drift_does_not_invoke_model(self):
        row=self.decision(self.create(['recon']),'approve');data,role=self.ready(row)
        with patch('security_agents.installed_models',new=AsyncMock(return_value=[{'name':MODELS[0]['name'],'digest':'changed'}])),patch.object(self.worker,'invoke') as invoke:
            self.client.portal.call(self.worker.execute,data,role);invoke.assert_not_called()
        self.assertEqual(self.detail(row)['status'],'paused')

    def test_reporter_cannot_read_peer_prose_or_original_archives(self):
        row=self.finish(['recon','reporting'])
        row['agents'][0]['output']['summary']='UNTRUSTED_PEER_INSTRUCTION'
        row['agents'][0]['output']['assessments'][0]['reason']='PRIVATE_PEER_REASON'
        with patch.object(self.store.evidence,'export_original') as original:
            prompt=self.store.context(row,'reporting')[1]['content'];original.assert_not_called()
        self.assertNotIn('UNTRUSTED_PEER_INSTRUCTION',prompt);self.assertNotIn('PRIVATE_PEER_REASON',prompt)
        self.assertIn('inventory-exposed',prompt)

    def test_synthetic_context_does_not_receive_expected_answers(self):
        row=self.decision(self.create(['llm_security']),'approve');data,role=self.ready(row)
        prompt=self.store.context(data,role)[1]['content']
        self.assertNotIn('expected_assessment',prompt);self.assertNotIn('indicator',prompt)
        self.assertIn('toy_response',prompt)

    def test_global_budget_blocks_even_when_agent_has_local_budget(self):
        row=self.decision(self.create(['recon','web_api']),'approve');data,role=self.ready(row)
        with self.store.engagements.transaction() as db:
            d=self.store.row(db,self.project,self.engagement['id'],row['id'])
            # Simulate prior charged attempts in another agent, keeping request immutable.
            d['agents'][1]['token_reserved']=d['request']['max_tokens'];self.store.save(db,d,'qa-global-exhaustion')
        with patch.object(self.worker,'invoke') as invoke:self.client.portal.call(self.worker.execute,data,role);invoke.assert_not_called()
        self.assertEqual(self.detail(row)['agents'][0]['calls'],0)

    def test_model_stream_tool_calls_length_and_missing_final_denied(self):
        async def run(chunks):
            async def stream(*args,**kwargs):
                for item in chunks:yield item
            with patch('model_runtime.runtime.chunks',side_effect=stream):
                with self.assertRaises(ValueError):await self.worker.invoke({'request':{'model':MODELS[0]['name']}},[],128)
        for chunks in ([{'message':{'tool_calls':[{'name':'shell'}]}}],
                       [{'done':True,'done_reason':'length'}],[{'message':{'content':'x'*12001}}],
                       [{'message':{'content':'{}'}}]):self.client.portal.call(run,chunks)

    def test_reporting_schema_prohibits_new_assessments_before_inference(self):
        self.assertEqual(output_schema('reporting')['properties']['assessments']['maxItems'],0)
        self.assertEqual(output_schema('recon')['properties']['assessments']['maxItems'],8)
        with self.assertRaises(ValueError):ReportingOutput(summary='test',assessments=[{'case_id':'new-case','assessment':'candidate','reason':'not permitted'}],evidence_ids=[str(uuid4())],uncertainties=['Synthetic'],needs_human_review=True,finding_status='candidate_only')

    def test_context_redaction_and_terms_not_persisted(self):
        row=self.create(['recon'],objective='Review CUSTOM-PRIVATE and api_key=synthetic-private-key',redaction_terms=['CUSTOM-PRIVATE'])
        content=json.dumps(row)
        self.assertNotIn('CUSTOM-PRIVATE',content);self.assertNotIn('synthetic-private-key',content);self.assertNotIn('redaction_terms',content)

    def test_reordered_case_outputs_have_same_repeatability_hash(self):
        row=self.finish(['recon']);first=self.store.metrics(row)['classification_hash']
        row['agents'][0]['output']['assessments'].reverse()
        self.assertEqual(self.store.metrics(row)['classification_hash'],first)

    def test_lab_limits_and_action_denials_preserve_policy(self):
        c=jobtests.content();c.update(environment='uat')
        other=self.decide(self.decide(self.create_engagement(c),'submit'),'approve')
        response=self.client.post(self.base+'/'+other['id']+'/agent-labs',headers=self.headers,json={**self.lab_body(account_aliases=[]),
            'expected_roe_revision':other['revision'],'roe_version':other['versions'][0]['version'],'content_hash':other['versions'][0]['content_hash']})
        self.assertEqual(response.status_code,422)
        self.create(['recon'],status=422,active_seconds=900,agents=[{'role':'recon','permissions':['lab.recon'],'active_seconds':181}])

    def test_stop_interrupts_inference_and_preserves_lab_evidence(self):
        row=self.decision(self.create(['recon']),'approve');data,role=self.ready(row)
        async def check():
            entered=asyncio.Event();cancelled=asyncio.Event()
            async def blocked(*args):
                entered.set()
                try:await asyncio.Event().wait()
                finally:cancelled.set()
            with patch.object(self.worker,'invoke',side_effect=blocked):
                task=asyncio.create_task(self.worker.execute(data,role));await entered.wait()
                self.store.decide(self.project,self.engagement['id'],row['id'],'pause',__import__('security_orchestration').RunDecision(expected_revision=1,actor_label='QA',note='Stop during model',acknowledge=True))
                await asyncio.wait_for(task,2);self.assertTrue(cancelled.is_set())
        self.client.portal.call(check)
        after=self.detail(row);self.assertEqual(after['status'],'paused');self.assertEqual(after['metrics']['evidence_count'],1)


if __name__=='__main__':unittest.main()
