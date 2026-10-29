import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_engagements as fixtures
from fastapi import HTTPException
from engagements import EngagementContent, EngagementStore, Decision, utc_now
from security_jobs import JobStore, OfflineJobRunner, CreateJob, Approval, Stop, GateDecision, RetryJob


def content():
    return {**fixtures.complete_content(), 'in_scope':[{'kind':'cidr','value':'10.30.0.0/24'}], 'out_of_scope':[{'kind':'ip','value':'10.30.0.99'}],
            'starts_at':(utc_now()-timedelta(minutes=1)).isoformat(), 'ends_at':(utc_now()+timedelta(hours=2)).isoformat()}


def step():
    return {'target':{'kind':'ip','value':'10.30.0.25'},'action':'tcp_discovery','ports':[443], 'max_http_rps':1,'max_concurrency':1,'max_duration_minutes':1,'test_account_ref':''}


def plan(engagement, **changes):
    return {'name':'Offline QA job', 'expected_roe_revision':engagement['revision'],'roe_version':engagement['versions'][0]['version'],
            'content_hash':engagement['versions'][0]['content_hash'], 'steps':[step()], 'wall_timeout_seconds':60,'max_output_kb':64, **changes}


class JobApiTests(unittest.TestCase):
    setUpFixture=fixtures.EngagementApiTests.setUp
    tearDown=fixtures.EngagementApiTests.tearDown
    create_engagement=fixtures.EngagementApiTests.create
    decide=fixtures.EngagementApiTests.decide

    def setUp(self):
        self.setUpFixture()
        self.client.portal.call(self.client.app.state.job_runner.stop)
        self.store=self.client.app.state.jobs
        self.owner='deterministic-api-test-worker'
        self.store.acquire(self.owner)
        self.engagement=self.decide(self.decide(self.create_engagement(content()),'submit'),'approve')
        self.url=self.base+'/'+self.engagement['id']

    def create_job(self, **changes):
        response=self.client.post(self.url+'/jobs',headers=self.headers,json=plan(self.engagement,**changes))
        self.assertEqual(response.status_code,201,response.text)
        return response.json()

    def approval(self,row):
        return {'expected_revision':row['revision'],'actor_label':'QA local reviewer','note':'Reviewed offline validation only.','acknowledge':True}

    def approve(self,row):
        response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def detail(self,row):
        response=self.client.get(self.url+'/jobs/'+row['id'],headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def test_immutable_plan_state_lifecycle_and_no_tools(self):
        created=self.create_job()
        self.assertEqual(created['status'],'awaiting_approval')
        self.assertEqual(len(created['plan_hash']),64)
        queued=self.approve(created)
        self.assertEqual(queued['status'],'queued')
        with patch('socket.getaddrinfo') as dns, patch('socket.create_connection') as network, patch('subprocess.Popen') as processes, patch('main.assess') as scanner:
            self.assertEqual(self.store.claim(self.owner),created['id'])
            self.assertFalse(self.store.step(self.owner,created['id']))
            for mock in (dns,network,processes,scanner):mock.assert_not_called()
        done=self.detail(created)
        self.assertEqual(done['status'],'completed')
        self.assertEqual(done['progress'],1)
        self.assertEqual(done['plan_hash'],created['plan_hash'])
        self.assertFalse(done['execution_enabled'])
        self.assertFalse(done['grants_execution'])
        self.assertFalse(done['results'][0]['result']['tool_executed'])
        self.assertEqual(done['results'][0]['result']['decision'],'pass')
        self.assertEqual([e['action'] for e in done['events']],['created','approved','running','step_validated','completed'])
        response=self.client.post(self.url+'/jobs/'+created['id'],headers=self.headers,json={'status':'running','steps':[step()]})
        self.assertEqual(response.status_code,405)
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={'target_id':'builtin-lab'}).status_code,423)

    def test_auth_project_boundary_and_schema_limits(self):
        created=self.create_job()
        self.assertEqual(self.client.get(self.url+'/jobs').status_code,401)
        self.assertEqual(self.client.post(self.url+'/stop',json={}).status_code,401)
        wrong='/api/security/projects/'+str(uuid4())+'/engagements/'+self.engagement['id']
        self.assertEqual(self.client.get(wrong+'/jobs',headers=self.headers).status_code,404)
        self.assertEqual(self.client.get(wrong+'/jobs/'+created['id'],headers=self.headers).status_code,404)
        self.assertEqual(self.client.post(wrong+'/jobs/'+created['id']+'/stop',headers=self.headers,json={}).status_code,404)
        for change in ({'steps':[]},{'steps':[step()]*21},{'wall_timeout_seconds':301},{'max_output_kb':65},{'wall_timeout_seconds':True},{'execution_enabled':True},{'steps':[{**step(),'action':'shell'}]},{'steps':[{**step(),'ports':[True]}]}):
            response=self.client.post(self.url+'/jobs',headers=self.headers,json=plan(self.engagement,**change))
            self.assertEqual(response.status_code,422,change)

    def test_stale_roe_create_or_approve_is_rejected(self):
        response=self.client.post(self.url+'/jobs',headers=self.headers,json=plan(self.engagement,content_hash='0'*64))
        self.assertEqual(response.status_code,409)
        row=self.create_job()
        self.decide(self.engagement,'revoke')
        response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
        self.assertEqual(response.status_code,422)
        self.assertIn('CURRENT_REVISION',response.text)
        self.assertEqual(self.detail(row)['status'],'awaiting_approval')

    def test_draft_roe_policy_scope_and_budget_cannot_be_queued(self):
        for changes in ({'steps':[{**step(),'target':{'kind':'ip','value':'10.30.0.99'}}]}, {'steps':[{**step(),'ports':[22]}]}, {'steps':[{**step(),'max_http_rps':6}]}, {'steps':[{**step(),'target':{'kind':'domain','value':'example.test'}}]}):
            row=self.create_job(**changes)
            response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
            self.assertEqual(response.status_code,422,response.text)
            self.assertEqual(self.detail(row)['status'],'awaiting_approval')
        draft=self.create_engagement(content())
        response=self.client.post(self.base+'/'+draft['id']+'/jobs',headers=self.headers,json=plan(draft))
        row=response.json()
        response=self.client.post(self.base+'/'+draft['id']+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(row))
        self.assertEqual(response.status_code,422)
        self.assertIn('APPROVED_ROE',response.text)

    def test_approval_acknowledgement_and_concurrent_compare_swap(self):
        row=self.create_job()
        for change in ({'acknowledge':False},{'note':''},{'actor_label':''}):
            response=self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json={**self.approval(row),**change})
            self.assertEqual(response.status_code,422)
        payload=Approval.model_validate(self.approval(row))
        def attempt():
            try:
                self.store.approve(self.project,self.engagement['id'],row['id'],payload)
                return 200
            except HTTPException as exc:return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(lambda _:attempt(),range(2))),[200,409])
        self.assertEqual(sum(e['action']=='approved' for e in self.detail(row)['events']),1)

    def test_fifo_global_concurrency_and_second_worker_cannot_claim(self):
        first=self.approve(self.create_job(name='First'))
        second=self.approve(self.create_job(name='Second'))
        self.assertFalse(self.store.acquire('other-worker'))
        self.assertEqual(self.store.claim(self.owner),first['id'])
        self.assertIsNone(self.store.claim(self.owner))
        self.assertIsNone(self.store.claim('other-worker'))
        self.store.step(self.owner,first['id'])
        self.assertEqual(self.store.claim(self.owner),second['id'])

    def test_cancel_at_each_state_retains_partial_results(self):
        for state in ('awaiting_approval','queued','running'):
            row=self.create_job(steps=[step(),step(),step()])
            if state!='awaiting_approval':row=self.approve(row)
            if state=='running':
                self.store.claim(self.owner)
                self.assertTrue(self.store.step(self.owner,row['id']))
            response=self.client.post(self.url+'/jobs/'+row['id']+'/stop',headers=self.headers,json={})
            self.assertEqual(response.status_code,200,response.text)
            cancelled=response.json()
            self.assertEqual(cancelled['status'],'cancelled')
            self.assertEqual(cancelled['progress'],1 if state=='running' else 0)
            self.assertFalse(self.store.step(self.owner,row['id']))
            self.assertEqual(len(self.detail(row)['results']),cancelled['progress'])
            repeated=self.client.post(self.url+'/jobs/'+row['id']+'/stop',headers=self.headers,json={}).json()
            self.assertEqual(repeated['revision'],cancelled['revision'])

    def test_stop_engagement_is_persistent_blocks_new_jobs_and_resume_is_explicit(self):
        running=self.approve(self.create_job(steps=[step(),step()]))
        self.store.claim(self.owner);self.store.step(self.owner,running['id'])
        queued=self.approve(self.create_job())
        waiting=self.create_job()
        response=self.client.post(self.url+'/stop',headers=self.headers,json={'note':'Emergency QA stop'})
        self.assertEqual(response.status_code,200,response.text)
        gate=response.json()['gate']
        self.assertTrue(gate['stopped'])
        for row in (running,queued,waiting):self.assertEqual(self.detail(row)['status'],'cancelled')
        self.assertEqual(len(self.detail(running)['results']),1)
        self.assertEqual(self.client.post(self.url+'/jobs',headers=self.headers,json=plan(self.engagement)).status_code,423)
        reopened=JobStore(EngagementStore(self.data))
        self.assertTrue(reopened.listing(self.project,self.engagement['id'])['gate']['stopped'])
        body={**{k:v for k,v in plan(self.engagement).items() if k in ('expected_roe_revision','roe_version','content_hash')},'expected_gate_revision':gate['revision'],'actor_label':'local reviewer','note':'Reopen planning only','acknowledge':True}
        self.assertEqual(self.client.post(self.url+'/resume',headers=self.headers,json={**body,'acknowledge':False}).status_code,422)
        self.assertEqual(self.client.post(self.url+'/resume',headers=self.headers,json={**body,'expected_gate_revision':1}).status_code,409)
        self.assertEqual(self.client.post(self.url+'/resume',headers=self.headers,json=body).status_code,200)
        self.assertFalse(self.store.listing(self.project,self.engagement['id'])['gate']['stopped'])
        self.assertEqual(self.detail(queued)['status'],'cancelled')
        self.assertEqual(self.create_job()['status'],'awaiting_approval')
        self.assertEqual(self.client.post(self.url+'/resume',headers=self.headers,json=body).status_code,409)

    def test_policy_is_checked_again_between_steps(self):
        row=self.approve(self.create_job(steps=[step(),step()]))
        self.store.claim(self.owner)
        self.assertTrue(self.store.step(self.owner,row['id']))
        self.decide(self.engagement,'revoke')
        self.assertFalse(self.store.step(self.owner,row['id']))
        failed=self.detail(row)
        self.assertEqual(failed['status'],'failed')
        self.assertEqual(failed['error_code'],'POLICY_DENIED')
        self.assertEqual(failed['results'][0]['result']['decision'],'pass')
        self.assertEqual(failed['results'][1]['result']['decision'],'deny')
        self.assertTrue(all(not result['result']['tool_executed'] for result in failed['results']))

    def test_output_limit_never_discards_prior_results_or_claims_completion(self):
        sample=self.approve(self.create_job(steps=[step(),step()]))
        self.store.claim(self.owner);self.store.step(self.owner,sample['id'])
        size=self.detail(sample)['output_bytes']
        self.store.cancel(self.project,self.engagement['id'],sample['id'],Stop())
        row=self.approve(self.create_job(steps=[step(),step()],max_output_kb=size//1024+1))
        self.store.claim(self.owner)
        self.assertTrue(self.store.step(self.owner,row['id']))
        self.assertFalse(self.store.step(self.owner,row['id']))
        result=self.detail(row)
        self.assertEqual(result['error_code'],'OUTPUT_LIMIT')
        self.assertEqual(result['progress'],1)
        self.assertEqual(len(result['results']),1)
        self.assertLessEqual(result['output_bytes'],result['plan']['max_output_kb']*1024)

    def test_time_limit_and_expired_worker_recovery(self):
        row=self.approve(self.create_job(wall_timeout_seconds=2))
        self.store.claim(self.owner)
        now=utc_now()
        with patch.object(self.store,'clock',return_value=now+timedelta(seconds=3)):
            self.assertFalse(self.store.step(self.owner,row['id']))
        self.assertEqual(self.detail(row)['error_code'],'TIME_LIMIT')
        running=self.approve(self.create_job(steps=[step(),step()]))
        self.store.claim(self.owner);self.store.step(self.owner,running['id'])
        queued=self.approve(self.create_job())
        self.store.acquire(self.owner)
        self.assertEqual(self.detail(queued)['status'],'queued')
        with patch.object(self.store,'clock',return_value=utc_now()+timedelta(seconds=11)):
            self.assertTrue(self.store.acquire('replacement-worker'))
        self.assertEqual(self.detail(running)['error_code'],'INTERRUPTED')
        self.assertEqual(len(self.detail(running)['results']),1)
        paused=self.detail(queued)
        self.assertEqual(paused['status'],'awaiting_approval')
        self.assertIsNone(paused['approver'])
        self.assertFalse(self.store.step(self.owner,running['id']))
        self.assertIsNone(self.store.claim('replacement-worker'))

    def test_restart_needs_reapproval_and_retry_is_bounded(self):
        row=self.approve(self.create_job())
        self.store.release(self.owner)
        paused=self.detail(row)
        self.assertEqual(paused['status'],'awaiting_approval')
        self.assertEqual(self.client.post(self.url+'/jobs/'+row['id']+'/approve',headers=self.headers,json=self.approval(paused)).status_code,503)
        self.store.acquire(self.owner)
        row=self.approve(paused)
        for attempt in (1,2,3):
            cancelled=self.store.cancel(self.project,self.engagement['id'],row['id'],Stop())
            self.assertEqual(cancelled['attempt'],attempt)
            payload={**{k:v for k,v in plan(self.engagement).items() if k in ('expected_roe_revision','roe_version','content_hash')},'expected_revision':cancelled['revision']}
            response=self.client.post(self.url+'/jobs/'+row['id']+'/retry',headers=self.headers,json=payload)
            if attempt==3:
                self.assertEqual(response.status_code,409)
            else:
                self.assertEqual(response.status_code,201,response.text)
                old=row;row=response.json()
                self.assertEqual(row['status'],'awaiting_approval')
                self.assertEqual(row['retry_of'],old['id'])
                self.assertIsNone(row['approver'])
                self.assertEqual(self.client.post(self.url+'/jobs/'+old['id']+'/retry',headers=self.headers,json=payload).status_code,409)

    def test_plan_integrity_tamper_and_migration(self):
        original=self.engagement['versions'][0]['content_hash']
        reopened=JobStore(EngagementStore(self.data))
        self.assertEqual(self.store.engagements.detail(self.project,self.engagement['id'])['versions'][0]['content_hash'],original)
        row=self.approve(self.create_job())
        with reopened.engagements.transaction() as db:
            altered={**row['plan'],'wall_timeout_seconds':300}
            db.execute('UPDATE security_jobs SET plan=? WHERE id=?',(json.dumps(altered),row['id']))
        self.store.claim(self.owner);self.store.step(self.owner,row['id'])
        self.assertEqual(self.detail(row)['error_code'],'PLAN_INTEGRITY')


class OfflineRunnerAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.engagements=EngagementStore(Path(self.directory.name))
        self.project=str(uuid4())
        row=self.engagements.create(self.project,EngagementContent.model_validate(content()))
        for action in ('submit','approve'):
            row=self.engagements.decide(self.project,row['id'],Decision(expected_revision=row['revision'],action=action,actor_label='local',note='offline QA',acknowledge=True))
        self.engagement=row
        self.store=JobStore(self.engagements)

    async def asyncTearDown(self):
        self.directory.cleanup()

    def job(self,runner,**changes):
        self.store.acquire(runner.owner)
        row=self.store.create(self.project,self.engagement['id'],CreateJob.model_validate(plan(self.engagement,**changes)))
        return self.store.approve(self.project,self.engagement['id'],row['id'],Approval(expected_revision=row['revision'],actor_label='local',note='offline only',acknowledge=True))

    async def test_cancel_during_running_is_not_overwritten_by_worker(self):
        entered,release=asyncio.Event(),asyncio.Event()
        async def before():entered.set();await release.wait()
        runner=OfflineJobRunner(self.store,before_step=before)
        row=self.job(runner)
        self.store.claim(runner.owner)
        task=asyncio.create_task(runner.execute(row['id']))
        await asyncio.wait_for(entered.wait(),1)
        self.store.cancel(self.project,self.engagement['id'],row['id'],Stop())
        release.set();await asyncio.wait_for(task,1)
        self.assertEqual(self.store.detail(self.project,self.engagement['id'],row['id'])['status'],'cancelled')

    async def test_monotonic_timeout_interrupts_awaiting_step(self):
        async def blocked():await asyncio.Event().wait()
        runner=OfflineJobRunner(self.store,before_step=blocked)
        row=self.job(runner,wall_timeout_seconds=1)
        self.store.claim(runner.owner)
        await asyncio.wait_for(runner.execute(row['id']),2)
        detail=self.store.detail(self.project,self.engagement['id'],row['id'])
        self.assertEqual(detail['error_code'],'TIME_LIMIT')
        self.assertEqual(detail['progress'],0)

    async def test_worker_error_is_failed_without_automatic_retry(self):
        runner=OfflineJobRunner(self.store)
        row=self.job(runner)
        self.store.claim(runner.owner)
        with patch('security_jobs.evaluate',side_effect=RuntimeError('synthetic worker failure')) as evaluator:
            await runner.execute(row['id'])
            evaluator.assert_called_once()
        detail=self.store.detail(self.project,self.engagement['id'],row['id'])
        self.assertEqual(detail['error_code'],'VALIDATION_ERROR')
        self.assertEqual(detail['status'],'failed')
        self.assertIsNone(detail['retry_job_id'])

    async def test_lifespan_loop_finishes_job_and_shuts_down_cleanly(self):
        runner=OfflineJobRunner(self.store)
        runner.start()
        try:
            row=self.job(runner)
            for _ in range(40):
                detail=self.store.detail(self.project,self.engagement['id'],row['id'])
                if detail['status']=='completed':break
                await asyncio.sleep(0.05)
            self.assertEqual(detail['status'],'completed')
            waiting=self.job(runner)
        finally:
            await runner.stop()
        self.assertTrue(runner.task.done())
        self.assertEqual(self.store.detail(self.project,self.engagement['id'],waiting['id'])['status'],'awaiting_approval')

    async def test_stop_flag_handles_completion_cancellation_race(self):
        entered=asyncio.Event()
        runner=OfflineJobRunner(self.store)
        async def completion_race(jid):
            entered.set()
            try:await asyncio.Event().wait()
            except asyncio.CancelledError:return
        with patch.object(runner,'execute',side_effect=completion_race):
            runner.start()
            self.job(runner)
            await asyncio.wait_for(entered.wait(),2)
            await asyncio.wait_for(runner.stop(),2)
        self.assertTrue(runner.task.done())


if __name__=='__main__':unittest.main()
