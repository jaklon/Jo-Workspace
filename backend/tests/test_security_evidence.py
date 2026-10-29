import copy
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_security_jobs as jobtests
from engagements import utc_now
from security_evidence import EvidenceStore, cvss_base, redactor
import evidence_archive


class EvidenceApiTests(unittest.TestCase):
    setUpFixture = jobtests.JobApiTests.setUpFixture
    tearDown = jobtests.JobApiTests.tearDown
    create_engagement = jobtests.JobApiTests.create_engagement
    decide = jobtests.JobApiTests.decide
    create_job = jobtests.JobApiTests.create_job
    approve = jobtests.JobApiTests.approve
    approval = jobtests.JobApiTests.approval

    def setUp(self):
        jobtests.JobApiTests.setUp(self)
        self.records = self.client.app.state.evidence
        self.completed = self.complete_job()

    def complete_job(self, **changes):
        row = self.approve(self.create_job(**changes))
        self.assertEqual(self.store.claim(self.owner), row['id'])
        while self.store.step(self.owner, row['id']): pass
        return self.store.detail(self.project,self.engagement['id'],row['id'])

    def post(self, suffix, body, status=201):
        response = self.client.post(self.url+suffix,headers=self.headers,json=body)
        self.assertEqual(response.status_code,status,response.text)
        return response.json()

    def get(self, suffix, status=200):
        response = self.client.get(self.url+suffix,headers=self.headers)
        self.assertEqual(response.status_code,status,response.text)
        return response.json()

    def evidence(self, source='synthetic_fixture', job=None, **changes):
        body = {'job_id':(job or self.completed)['id'],'step_ordinal':1,'source':source,'title':'Synthetic observation','acknowledge':True}
        if source != 'offline_policy':
            body.update(captured_at=utc_now().isoformat(),tool_name='fixture-generator',tool_version='1.0',parameters='case=header-check',content='Fixture: missing synthetic security header.')
        return self.post('/evidence',{**body,**changes})

    def finding(self, evidence_ids=None, **changes):
        return self.post('/findings',{'title':'Missing header in fixture','target':jobtests.step()['target'],'category':'CWE-693',
            'description':'Synthetic evidence only.','ai_interpretation':'Unverified interpretation.','severity':'medium','severity_reason':'Fixture impact rationale.',
            'evidence_ids':evidence_ids or [],'assignee':'QA owner','remediation':'Apply header in fixture.',**changes})

    def review(self, finding, status='validated', expected=200, **changes):
        return self.post('/findings/'+finding['id']+'/review',{'expected_revision':finding['revision'],'status':status,
            'actor_label':'Declared local analyst','analyst_assessment':'Reviewed artifact and scope; synthetic observation.','acknowledge':True,**changes},expected)

    def report(self, **changes):
        return self.post('/reports',{'title':'QA report','summary':'Local fixture assessment.','actor_label':'Declared local author','acknowledge':True,**changes})

    def test_offline_evidence_provenance_hash_and_immutable_api(self):
        with patch('socket.getaddrinfo') as dns, patch('socket.create_connection') as network, patch('subprocess.Popen') as process, patch('main.assess') as scanner:
            e = self.evidence('offline_policy')
            for m in (dns,network,process,scanner): m.assert_not_called()
        self.assertEqual(e['source'],'offline_policy')
        self.assertEqual(e['policy']['decision'],'pass')
        self.assertFalse(e['tool_executed_by_agent_os'])
        self.assertEqual(e['integrity'],'verified')
        self.assertEqual(len(e['original_hash']),64)
        self.assertEqual(len(e['artifact_hash']),64)
        self.assertEqual(e['target'],jobtests.step()['target'])
        self.assertEqual(self.client.put(self.url+'/evidence/'+e['id'],headers=self.headers,json={'content':'changed'}).status_code,405)
        self.post('/evidence',{'job_id':self.completed['id'],'step_ordinal':1,'source':'offline_policy','title':'Forgery','content':'forged','acknowledge':True},422)

    def test_redaction_before_persistence_including_metadata_and_original_hash(self):
        secret='synthetic-super-secret'
        raw='Authorization: Bearer '+secret+'\nCookie: session=synthetic-cookie\n{"password":"synthetic-password", "token":"synthetic-token"}\nqa@example.test\nNIK 1234567890123456\nCUSTOM-PRIVATE\n'
        e = self.evidence(content=raw,title='Evidence qa@example.test',parameters='api_key=synthetic-api-key',redaction_terms=['CUSTOM-PRIVATE'])
        result=json.dumps(e)
        for value in (secret,'synthetic-cookie','synthetic-password','synthetic-token','qa@example.test','1234567890123456','CUSTOM-PRIVATE','synthetic-api-key'):
            self.assertNotIn(value,result)
        self.assertNotEqual(e['original_hash'],e['artifact_hash'])
        self.assertGreaterEqual(e['redactions'],8)
        with closing(self.records.engagements.connect()) as db:
            persisted='\n'.join(r[0] for r in db.execute('SELECT payload FROM security_evidence'))
        self.assertNotIn(secret,persisted)
        self.assertNotIn('CUSTOM-PRIVATE',persisted)
        self.assertNotIn('redaction_terms',persisted)

    def test_auth_and_project_engagement_boundaries(self):
        e=self.evidence(); f=self.finding([e['id']]); r=self.report()
        for suffix in ('/records','/evidence/'+e['id'],'/findings/'+f['id'],'/reports/'+r['snapshot']['id']):
            self.assertEqual(self.client.get(self.url+suffix).status_code,401)
            wrong=self.url.replace(self.project,str(uuid4()))
            self.assertEqual(self.client.get(wrong+suffix,headers=self.headers).status_code,404)
        other=self.decide(self.decide(self.create_engagement(jobtests.content()),'submit'),'approve')
        other_url=self.base+'/'+other['id']
        self.assertEqual(self.client.post(other_url+'/evidence',headers=self.headers,json={'job_id':self.completed['id'],'step_ordinal':1,'source':'offline_policy','title':'Wrong','acknowledge':True}).status_code,404)

    def test_schema_bounds_and_errors_never_echo_sensitive_input(self):
        base={'job_id':self.completed['id'],'step_ordinal':1,'source':'external_import','title':'Import','captured_at':utc_now().isoformat(),
              'tool_name':'fixture','tool_version':'1','content':'synthetic-secret','acknowledge':True}
        for changes in ({'title':' '},{'source':'scanner'},{'content':'x\0secret'},{'content':'é'*40000},{'content':''},{'tool_version':''},
                        {'captured_at':(utc_now()+timedelta(days=1)).isoformat()},{'captured_at':'2026-01-01T00:00:00'},
                        {'redaction_terms':['']},{'redaction_terms':['ab']},{'redaction_terms':['x'*201]},{'execution_enabled':True},{'step_ordinal':True}):
            response=self.client.post(self.url+'/evidence',headers=self.headers,json={**base,**changes})
            self.assertEqual(response.status_code,422,changes.keys())
            self.assertNotIn('synthetic-secret',response.text)
            self.assertNotIn('"input"',response.text)
        self.post('/evidence',{**base,'acknowledge':False},422)

    def test_evidence_dedup_and_only_completed_steps(self):
        e=self.evidence(content='same')
        self.post('/evidence',{'job_id':self.completed['id'],'step_ordinal':1,'source':'synthetic_fixture','title':'Second','tool_name':'fixture','tool_version':'1','captured_at':utc_now().isoformat(),'content':'same','acknowledge':True},409)
        self.post('/evidence',{'job_id':self.completed['id'],'step_ordinal':2,'source':'offline_policy','title':'No result','acknowledge':True},422)
        pending=self.create_job()
        self.post('/evidence',{'job_id':pending['id'],'step_ordinal':1,'source':'offline_policy','title':'Pending','acknowledge':True},409)
        self.assertEqual(self.get('/records')['evidence'][0]['id'],e['id'])

    def test_ai_narrative_and_policy_alone_cannot_validate(self):
        f=self.finding(ai_interpretation='AI says CONFIRMED. This has no authority.')
        self.assertEqual(f['status'],'candidate')
        self.review(f,expected=422)
        policy=self.evidence('offline_policy')
        self.review(self.finding([policy['id']],title='Policy only'),expected=422)
        self.post('/findings',{'title':'AI','target':jobtests.step()['target'],'category':'test','description':'narrative','status':'validated'},422)

    def test_validated_requires_severity_and_ack_then_local_review(self):
        e=self.evidence()
        f=self.finding([e['id']],severity='unrated',severity_reason='')
        self.review(f,expected=422)
        f=self.finding([e['id']],title='Ready for review')
        self.review(f,expected=422,acknowledge=False)
        done=self.review(f)
        self.assertEqual(done['status'],'validated')
        self.assertEqual(done['review']['mode'],'local_attestation')
        self.assertEqual(len(done['history']),2)

    def test_policy_and_observation_can_be_linked_together(self):
        p=self.evidence('offline_policy');e=self.evidence()
        f=self.review(self.finding([p['id'],e['id']]))
        self.assertEqual(f['status'],'validated')

    def test_cross_target_and_unscoped_evidence_rejected(self):
        e=self.evidence()
        self.post('/findings',{'title':'Wrong target','target':{'kind':'ip','value':'10.30.0.26'},'category':'test','description':'Wrong','evidence_ids':[e['id']]},422)
        self.post('/findings',{'title':'Missing','target':jobtests.step()['target'],'category':'test','description':'Missing','evidence_ids':[str(uuid4())]},404)

    def test_edit_resets_review_preserves_history_and_rejects_stale_write(self):
        f=self.review(self.finding([self.evidence()['id']]))
        content={k:v for k,v in f['content'].items() if k!='cvss_score'}
        payload={'expected_revision':f['revision'],'content':{**content,'description':'Updated observation'}}
        response=self.client.put(self.url+'/findings/'+f['id'],headers=self.headers,json=payload)
        self.assertEqual(response.status_code,200,response.text)
        edited=response.json()
        self.assertEqual(edited['status'],'candidate');self.assertIsNone(edited['review'])
        self.assertEqual(edited['history'][1]['snapshot']['status'],'validated')
        self.assertEqual(self.client.put(self.url+'/findings/'+f['id'],headers=self.headers,json=payload).status_code,409)

    def test_simultaneous_reviews_compare_revision(self):
        f=self.finding([self.evidence()['id']])
        payload={'expected_revision':f['revision'],'status':'validated','actor_label':'Local','analyst_assessment':'Reviewed','acknowledge':True}
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda _:self.client.post(self.url+'/findings/'+f['id']+'/review',headers=self.headers,json=payload).status_code,range(2)))
        self.assertEqual(sorted(responses),[200,409])

    def test_dedup_semantic_link_and_cycle_prevention(self):
        e=self.evidence(); f=self.finding([e['id']])
        self.post('/findings',{'title':' MISSING   HEADER IN FIXTURE ','target':jobtests.step()['target'],'category':'cwe-693','description':'Duplicate'},409)
        child=self.finding([e['id']],title='Semantic duplicate',duplicate_of=f['id'])
        self.review(child,expected=422)
        self.review(child,'false_positive')
        body={k:v for k,v in f['content'].items() if k!='cvss_score'}
        response=self.client.put(self.url+'/findings/'+f['id'],headers=self.headers,json={'expected_revision':f['revision'],'content':{**body,'duplicate_of':child['id']}})
        self.assertEqual(response.status_code,422)

    def test_retest_requires_new_job_later_observation(self):
        e=self.evidence();f=self.review(self.finding([e['id']]))
        self.review(f,'retest_passed',expected=422,retest_evidence_ids=[e['id']])
        newer=self.complete_job(name='Retest plan')
        old=self.evidence(job=newer,content='Old fixture',captured_at=(utc_now()-timedelta(hours=1)).isoformat())
        self.review(f,'retest_passed',expected=422,retest_evidence_ids=[old['id']])
        after=self.evidence(job=newer,content='Retest fixture now passes.')
        done=self.review(f,'retest_passed',retest_evidence_ids=[after['id']])
        self.assertEqual(done['status'],'retest_passed')
        self.assertEqual(done['retest_evidence_ids'],[after['id']])
        self.assertEqual(done['history'][1]['snapshot']['status'],'validated')

    def test_report_is_frozen_redacted_separates_ai_and_human(self):
        e=self.evidence(content='Authorization: Bearer synthetic-secret\nFixture response')
        f=self.finding([e['id']],ai_interpretation='AI interpretation qa@example.test')
        f=self.review(f,analyst_assessment='Human decision password=private-test')
        r=self.report(summary='Summary qa@example.test\n~~~\n<script>example</script>')
        self.assertNotIn('synthetic-secret',json.dumps(r))
        self.assertNotIn('qa@example.test',json.dumps(r))
        self.assertNotIn('private-test',json.dumps(r))
        self.assertIn('Interpretasi AI',r['markdown']);self.assertIn('Keputusan analis',r['markdown'])
        original=copy.deepcopy(r)
        self.review(f,'inconclusive')
        self.assertEqual(self.get('/reports/'+r['snapshot']['id']),original)
        self.assertEqual(r['snapshot']['findings'][0]['status'],'validated')
        self.assertFalse(r['snapshot']['execution_enabled'])

    def test_integrity_tamper_blocks_reads_review_and_report(self):
        e=self.evidence();f=self.finding([e['id']]);r=self.report()
        with self.records.engagements.transaction() as db:
            altered={**e,'content':'tampered'}
            altered.pop('integrity');altered.pop('record_hash')
            db.execute('UPDATE security_evidence SET payload=? WHERE id=?',(json.dumps(altered),e['id']))
        self.get('/evidence/'+e['id'],409);self.review(f,expected=409)
        self.post('/reports',{'title':'Blocked','summary':'Tampered','actor_label':'Local','acknowledge':True},409)
        with self.records.engagements.transaction() as db:
            db.execute('UPDATE security_reports SET payload=? WHERE id=?',(json.dumps({'invalid':'report'}),r['snapshot']['id']))
        self.get('/reports/'+r['snapshot']['id'],409)

    def test_limits_reopen_migration_and_no_execution(self):
        with patch('security_evidence.MAX_EVIDENCE',1):
            e=self.evidence()
            self.post('/evidence',{'job_id':self.completed['id'],'step_ordinal':1,'source':'offline_policy','title':'Over limit','acknowledge':True},409)
        with patch('security_evidence.MAX_FINDINGS',1):
            f=self.finding([e['id']])
            self.post('/findings',{'title':'Over limit','category':'test','target':jobtests.step()['target'],'description':'x'},409)
        with patch('security_evidence.MAX_REPORTS',1):
            self.report();self.post('/reports',{'title':'Over limit','summary':'x','actor_label':'local','acknowledge':True},409)
        reopened=EvidenceStore(self.records.engagements,self.store)
        self.assertEqual(reopened.get_finding(self.project,self.engagement['id'],f['id'])['status'],'candidate')
        self.assertEqual(reopened.get_evidence(self.project,self.engagement['id'],e['id'])['integrity'],'verified')
        self.assertEqual(self.client.post('/api/pentest/run',headers=self.headers,json={}).status_code,423)

    def test_cvss_server_computes_score_and_requires_reason(self):
        vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        self.post('/findings',{'title':'Bad CVSS','category':'test','target':jobtests.step()['target'],'description':'x','cvss_vector':vector},422)
        f=self.finding([self.evidence()['id']],cvss_vector=vector,cvss_reason='All impacts high in fixture.')
        self.assertEqual(f['content']['cvss_score'],9.8)

    @unittest.skipUnless(evidence_archive.available(),'Windows DPAPI unavailable')
    def test_original_is_encrypted_and_export_requires_explicit_ack(self):
        raw='  Fixture original\r\nAuthorization: Bearer synthetic-original-secret\r\n'
        e=self.evidence(content=raw)
        self.assertTrue(e['original_available'])
        self.assertEqual(e['original_archive'],'windows_dpapi_current_user')
        with closing(self.records.engagements.connect()) as db:
            cipher=db.execute('SELECT cipher FROM security_evidence_originals WHERE evidence_id=?',(e['id'],)).fetchone()[0]
        self.assertNotIn(b'synthetic-original-secret',cipher)
        self.assertNotIn('synthetic-original-secret',json.dumps(e))
        body={'actor_label':'QA local','note':'Hash verification only','acknowledge_sensitive_export':False}
        self.assertEqual(self.client.post(self.url+'/evidence/'+e['id']+'/original',json={**body,'acknowledge_sensitive_export':True}).status_code,401)
        self.post('/evidence/'+e['id']+'/original',body,422)
        response=self.client.post(self.url+'/evidence/'+e['id']+'/original',headers=self.headers,json={**body,'acknowledge_sensitive_export':True})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(response.json()['content'],raw)
        self.assertEqual(response.json()['original_hash'],e['original_hash'])
        with closing(self.records.engagements.connect()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM security_evidence_access WHERE evidence_id=?',(e['id'],)).fetchone()[0],1)
        self.assertNotIn('synthetic-original-secret',json.dumps(self.report()))

    @unittest.skipUnless(evidence_archive.available(),'Windows DPAPI unavailable')
    def test_original_cipher_corruption_is_rejected_without_plaintext(self):
        e=self.evidence(content='token=synthetic-original-private')
        with self.records.engagements.transaction() as db:
            db.execute('UPDATE security_evidence_originals SET cipher=? WHERE evidence_id=?',(b'invalid-archive',e['id']))
        response=self.post('/evidence/'+e['id']+'/original',{'actor_label':'QA','note':'Verify','acknowledge_sensitive_export':True},409)
        self.assertNotIn('synthetic-original-private',json.dumps(response))
        self.assertEqual(self.get('/evidence/'+e['id'])['integrity'],'verified')

    def test_legacy_redacted_only_and_failed_archive_are_explicit(self):
        with patch('evidence_archive.available',return_value=False):
            e=self.evidence(content='Legacy redacted-only artifact')
        self.assertFalse(e['original_available'])
        self.assertEqual(e['original_archive'],'unavailable_redacted_only')
        self.post('/evidence/'+e['id']+'/original',{'actor_label':'QA','note':'Legacy','acknowledge_sensitive_export':True},404)
        with patch('evidence_archive.available',return_value=True),patch('evidence_archive.protect',side_effect=RuntimeError('synthetic failure')):
            self.post('/evidence',{'job_id':self.completed['id'],'step_ordinal':1,'source':'offline_policy','title':'Encryption failure','acknowledge':True},503)
        self.assertEqual(len(self.get('/records')['evidence']),1)


class CvssAndRedactionTests(unittest.TestCase):
    def test_custom_terms_cannot_disable_automatic_secret_detection(self):
        scrub,_=redactor(['token','Cookie','password'])
        output=scrub('token=synthetic-private-token\nCookie: session=synthetic-cookie-value\n{"password":"synthetic-private-password"}\ncookie=synthetic-query-cookie')
        for value in ('synthetic-private-token','synthetic-cookie-value','synthetic-private-password','synthetic-query-cookie'):
            self.assertNotIn(value,output)

    def test_cvss_known_vectors_and_rejection(self):
        for vector,expected in [
            ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',9.8),
            ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',10),
            ('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N',3.8),
            ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0),
            ('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',1.6)]:
            self.assertEqual(cvss_base(vector),expected)
        for bad in ('CVSS:4.0/AV:N','CVSS:3.1/AV:N','CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F'):
            with self.assertRaises(ValueError): cvss_base(bad)

    def test_nested_redaction_private_key_jwt_and_custom(self):
        scrub,count=redactor(['private-value'])
        output=scrub({'text':'-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----\nBearer synthetic-bearer\nprivate-value',
                      'nested':['eyJhbGci.eyJzdWIi.c2ln','{"password":"synthetic pass word"}', '{"Cookie":"session=synthetic-cookie-json"}']})
        text=json.dumps(output)
        for secret in ('synthetic-key','synthetic-bearer','private-value','eyJhbGci','synthetic pass word','synthetic-cookie-json'): self.assertNotIn(secret,text)
        self.assertGreaterEqual(count[0],5)


if __name__ == '__main__': unittest.main()
