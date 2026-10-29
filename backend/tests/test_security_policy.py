from datetime import timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_engagements as fixtures
complete_content = fixtures.complete_content
from engagements import EngagementContent, EngagementStore, ScopeAsset, utc_now
from security_policy import contains, overlaps, scope_report


def asset(kind, value):
    return ScopeAsset(kind=kind, value=value)


class ScopeRelationsTests(unittest.TestCase):
    def test_ip_cidr_and_ipv6_containment_without_enumeration(self):
        self.assertTrue(contains(asset('cidr', '10.10.0.0/24'), asset('ip', '10.10.0.1')))
        self.assertTrue(contains(asset('cidr', '10.10.0.0/24'), asset('cidr', '10.10.0.128/25')))
        self.assertFalse(contains(asset('cidr', '10.10.0.0/25'), asset('cidr', '10.10.0.0/24')))
        self.assertTrue(contains(asset('cidr', '2001:db8::/64'), asset('url', 'https://[2001:db8::1]/api')))
        self.assertFalse(overlaps(asset('cidr', '10.10.0.0/24'), asset('ip', '2001:db8::1')))

    def test_domain_exact_host_and_url_authority_boundaries(self):
        parent = asset('domain', 'Example.test')
        self.assertTrue(contains(parent, asset('url', 'https://example.test:8443/api')))
        for value in ['sub.example.test', 'example.test.evil.test', 'evilexample.test']:
            self.assertFalse(contains(parent, asset('domain', value)))
        url = asset('url', 'https://example.test/api')
        self.assertTrue(contains(url, asset('url', 'https://example.test/api/users')))
        for value in ['https://example.test/apix', 'http://example.test/api', 'https://example.test:8443/api', 'https://sub.example.test/api']:
            self.assertFalse(contains(url, asset('url', value)))
        self.assertFalse(contains(url, parent))

    def test_exclusion_overrides_and_combined_full_exclusion(self):
        content = EngagementContent.model_validate({**complete_content(), 'in_scope': [{'kind':'cidr','value':'10.10.0.0/24'}], 'out_of_scope': [{'kind':'cidr','value':'10.10.0.0/25'}]})
        report = scope_report(content)
        self.assertTrue(report['valid'])
        self.assertIn('EXCLUSION_OVERRIDES', [f['code'] for f in report['findings']])
        content.out_of_scope.append(asset('cidr', '10.10.0.128/25'))
        self.assertFalse(scope_report(content)['valid'])
        self.assertIn('FULLY_EXCLUDED', [f['code'] for f in scope_report(content)['findings']])

    def test_partial_exclusion_on_url_paths(self):
        self.assertTrue(overlaps(asset('domain','example.test'), asset('url','https://example.test/admin')))
        self.assertFalse(overlaps(asset('url','https://example.test/public'), asset('url','https://example.test/admin')))
        self.assertFalse(overlaps(asset('url','https://example.test/admin'), asset('url','https://example.test/administer')))


# Reuse fixture helpers without inheriting/rerunning every stage 1 test.
class PolicyApiTests(unittest.TestCase):
    setUp = fixtures.EngagementApiTests.setUp
    tearDown = fixtures.EngagementApiTests.tearDown
    create = fixtures.EngagementApiTests.create
    decide = fixtures.EngagementApiTests.decide

    def content(self, **changes):
        return {**complete_content(), 'in_scope':[{'kind':'cidr','value':'10.10.0.0/24'}], 'out_of_scope':[{'kind':'ip','value':'10.10.0.99'}], 'starts_at':(utc_now()-timedelta(minutes=1)).isoformat(), 'ends_at':(utc_now()+timedelta(hours=2)).isoformat(), **changes}

    def approved(self, **changes):
        return self.decide(self.decide(self.create(self.content(**changes)), 'submit'), 'approve')

    def proposal(self, row, **changes):
        return {'expected_revision':row['revision'], 'roe_version':row['versions'][0]['version'], 'content_hash':row['versions'][0]['content_hash'], 'target':{'kind':'ip','value':'10.10.0.25'}, 'action':'tcp_discovery', 'ports':[443], 'max_http_rps':1, 'max_concurrency':1, 'max_duration_minutes':1, **changes}

    def evaluate(self, row, body=None, status=200):
        response = self.client.post(self.base+'/'+row['id']+'/policy-checks', headers=self.headers, json=body or self.proposal(row))
        self.assertEqual(response.status_code, status, response.text)
        return response.json()

    def denied_by(self, result, code):
        self.assertEqual(result['decision'], 'deny')
        self.assertIn(code, [c['code'] for c in result['checks'] if not c['passed']])
        self.assertFalse(result['execution_enabled'])
        self.assertFalse(result['grants_execution'])

    def test_pass_is_persisted_bound_snapshot_and_does_not_enable_execution(self):
        row = self.approved()
        with patch('socket.getaddrinfo') as dns, patch('socket.create_connection') as connect, patch('subprocess.Popen') as process, patch('main.assess') as scanner:
            result = self.evaluate(row)
            self.assertEqual(result['decision'], 'pass')
            self.assertEqual(result['content_hash'], row['versions'][0]['content_hash'])
            self.assertEqual(result['execution_blockers'], ['STAGE_2_PLANNING_ONLY'])
            self.assertFalse(result['grants_execution'])
            denied = self.client.post('/api/pentest/run', headers=self.headers, json={'target_id':'builtin-lab'})
            self.assertEqual(denied.status_code, 423)
            for mock in (dns,connect,process,scanner): mock.assert_not_called()
        history = EngagementStore(self.data).policy_history(self.project,row['id'])
        self.assertEqual(history['items'][0], result)
        self.assertEqual(self.client.get(self.base+'/'+row['id'],headers=self.headers).json()['revision'],row['revision'])

    def test_authentication_project_isolation_and_extra_fields(self):
        row = self.approved()
        path = self.base+'/'+row['id']+'/policy-checks'
        self.assertEqual(self.client.post(path,json=self.proposal(row)).status_code,401)
        self.assertEqual(self.client.get(path).status_code,401)
        wrong='/api/security/projects/'+str(uuid4())+'/engagements/'+row['id']+'/policy-checks'
        self.assertEqual(self.client.get(wrong,headers=self.headers).status_code,404)
        self.assertEqual(self.client.post(wrong,headers=self.headers,json=self.proposal(row)).status_code,404)
        self.evaluate(row,self.proposal(row,execution_enabled=True),422)
        self.evaluate(row,self.proposal(row,ports=[True]),422)
        self.evaluate(row,self.proposal(row,max_http_rps=16),422)
        self.assertEqual(self.client.post('/api/security/scope-validation',json={'content':self.content()}).status_code,401)

    def test_stale_revision_version_or_hash_cannot_pass(self):
        row = self.approved()
        for changes in ({'expected_revision':row['revision']-1},{'roe_version':2},{'content_hash':'0'*64}):
            self.denied_by(self.evaluate(row,self.proposal(row,**changes)),'CURRENT_REVISION')

    def test_draft_pending_revoked_and_superseded_cannot_pass(self):
        draft=self.create(self.content())
        self.denied_by(self.evaluate(draft),'APPROVED_ROE')
        pending=self.decide(draft,'submit')
        self.denied_by(self.evaluate(pending),'APPROVED_ROE')
        approved=self.decide(pending,'approve')
        revised=self.decide(approved,'revise')
        self.denied_by(self.evaluate(revised),'APPROVED_ROE')
        self.denied_by(self.evaluate(approved),'CURRENT_REVISION')
        revoked=self.decide(revised,'revoke')
        self.denied_by(self.evaluate(revoked),'APPROVED_ROE')

    def test_server_window_start_end_and_duration(self):
        now=utc_now()
        row=self.approved(starts_at=(now+timedelta(minutes=10)).isoformat(),ends_at=(now+timedelta(minutes=20)).isoformat())
        self.denied_by(self.evaluate(row),'ACTIVE_WINDOW')
        with patch('engagements.utc_now',return_value=now+timedelta(minutes=10)):
            self.assertEqual(self.evaluate(row)['decision'],'pass')
        with patch('engagements.utc_now',return_value=now+timedelta(minutes=19,seconds=1)):
            self.denied_by(self.evaluate(row),'WINDOW_FITS')
        with patch('engagements.utc_now',return_value=now+timedelta(minutes=20)):
            self.denied_by(self.evaluate(row),'ACTIVE_WINDOW')

    def test_exclusion_precedence_and_entire_cidr_denial(self):
        row=self.approved()
        for target in ({'kind':'ip','value':'10.10.0.99'},{'kind':'cidr','value':'10.10.0.0/24'}):
            self.denied_by(self.evaluate(row,self.proposal(row,target=target)),'NOT_EXCLUDED')
        self.denied_by(self.evaluate(row,self.proposal(row,target={'kind':'ip','value':'10.11.0.25'})),'IN_SCOPE')

    def test_action_port_budget_and_target_shape(self):
        row=self.approved()
        for changes, code in [({'action':'shell'},'ACTION_ALLOWED'),({'ports':[22]},'PORTS_ALLOWED'),({'ports':[]},'PORTS_ALLOWED'),({'max_http_rps':6},'BUDGET_ALLOWED'),({'max_concurrency':2},'BUDGET_ALLOWED'),({'max_duration_minutes':61},'BUDGET_ALLOWED'),({'target':{'kind':'url','value':'https://10.10.0.25/'}},'ACTION_TARGET_TYPE')]:
            self.denied_by(self.evaluate(row,self.proposal(row,**changes)),code)

    def test_http_derives_port_path_boundary_and_account(self):
        row=self.approved(in_scope=[{'kind':'url','value':'https://10.10.0.25/api'}],out_of_scope=[{'kind':'url','value':'https://10.10.0.25/api/admin'}],allowed_actions=['http_headers','authenticated_api_review'],test_account_refs=['qa-reader'])
        proposal=self.proposal(row,target={'kind':'url','value':'https://10.10.0.25/api/users'},action='http_headers',ports=[])
        self.assertEqual(self.evaluate(row,proposal)['decision'],'pass')
        self.denied_by(self.evaluate(row,{**proposal,'ports':[8443]}),'PORTS_ALLOWED')
        self.denied_by(self.evaluate(row,{**proposal,'target':{'kind':'url','value':'https://10.10.0.25/apix'}}),'IN_SCOPE')
        self.denied_by(self.evaluate(row,{**proposal,'target':{'kind':'url','value':'https://10.10.0.25/api/admin/users'}}),'NOT_EXCLUDED')
        self.denied_by(self.evaluate(row,{**proposal,'action':'authenticated_api_review'}),'TEST_ACCOUNT')
        self.assertEqual(self.evaluate(row,{**proposal,'action':'authenticated_api_review','test_account_ref':'qa-reader'})['decision'],'pass')

    def test_dns_ambiguity_fails_closed_even_for_ip_with_named_exclusions(self):
        named=self.approved(in_scope=[{'kind':'domain','value':'uat.example.test'}],out_of_scope=[])
        self.denied_by(self.evaluate(named,self.proposal(named,target={'kind':'url','value':'https://uat.example.test/api'},action='http_headers',ports=[])),'DNS_REQUIREMENTS')
        row=self.approved(out_of_scope=[{'kind':'domain','value':'excluded.example.test'}])
        self.denied_by(self.evaluate(row),'DNS_REQUIREMENTS')
        local=self.approved(in_scope=[{'kind':'domain','value':'uat.example.test'}],out_of_scope=[],allowed_actions=['document_review'])
        self.assertEqual(self.evaluate(local,self.proposal(local,target={'kind':'domain','value':'uat.example.test'},action='document_review',ports=[]))['decision'],'pass')

    def test_unsafe_addresses_and_ambiguous_url_spelling(self):
        row=self.approved()
        for kind,value in [('ip','169.254.169.254'),('cidr','0.0.0.0/0'),('ip','224.0.0.1'),('ip','::ffff:10.10.0.25'),('ip','fe80::1'),('ip','64:ff9b::a0a:19'),('url','https://10.10.0.25/api/../admin'),('url','https://10.10.0.25/api/%2e%2e/admin'),('url','https://127.1/'),('url','https://0x7f000001/')]:
            self.denied_by(self.evaluate(row,self.proposal(row,target={'kind':kind,'value':value})),'TARGET_SAFE')

    def test_network_target_count_is_bounded(self):
        row=self.approved(in_scope=[{'kind':'cidr','value':'10.10.0.0/16'}],out_of_scope=[])
        self.denied_by(self.evaluate(row,self.proposal(row,target={'kind':'cidr','value':'10.10.0.0/16'})),'TARGET_SIZE')
        self.assertEqual(self.evaluate(row,self.proposal(row,target={'kind':'cidr','value':'10.10.0.0/24'}))['decision'],'pass')

    def test_scope_validation_blocks_submission_not_draft_save(self):
        content=self.content(in_scope=[{'kind':'ip','value':'10.10.0.25'}],out_of_scope=[{'kind':'cidr','value':'10.10.0.0/24'}])
        response=self.client.post('/api/security/scope-validation',headers=self.headers,json={'content':content})
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['valid'])
        row=self.create(content)
        self.decide(row,'submit',422)
        self.assertEqual(row['versions'][0]['status'],'draft')

    def test_legacy_snapshots_stay_readable_but_new_policy_rechecks_them(self):
        row=self.approved()
        # Simulate a historical approval made before the stage 2 rules existed.
        with self.client.app.state.engagements.transaction() as db:
            content=self.content(in_scope=[{'kind':'url','value':'https://10.10.0.25/%2fadmin'}])
            db.execute('UPDATE roe_versions SET content=? WHERE engagement_id=? AND version=1',(json.dumps(content),row['id']))
        legacy=self.client.get(self.base+'/'+row['id'],headers=self.headers)
        self.assertEqual(legacy.status_code,200)
        self.assertFalse(legacy.json()['versions'][0]['scope_report']['valid'])
        self.denied_by(self.evaluate(row),'VALID_ROE')

    def test_history_is_bounded_and_does_not_mutate_engagement(self):
        row=self.approved()
        for _ in range(21): self.evaluate(row)
        response=self.client.get(self.base+'/'+row['id']+'/policy-checks',headers=self.headers)
        self.assertEqual(response.json()['total'],21)
        self.assertEqual(len(response.json()['items']),20)
        exported=self.client.get(self.base+'/'+row['id']+'/policy-checks?all_records=true',headers=self.headers)
        self.assertEqual(len(exported.json()['items']),21)
        self.assertEqual(len(self.client.get(self.base+'/'+row['id'],headers=self.headers).json()['events']),3)

    def test_corrupt_snapshot_cannot_pass_integrity_check(self):
        row=self.approved()
        with self.client.app.state.engagements.transaction() as db:
            content=self.content(name='Changed stored content')
            db.execute('UPDATE roe_versions SET content=? WHERE engagement_id=? AND version=1',(json.dumps(content),row['id']))
        self.denied_by(self.evaluate(row),'SNAPSHOT_INTEGRITY')

    def test_pending_legacy_invalid_scope_cannot_be_approved(self):
        row=self.decide(self.create(self.content()),'submit')
        with self.client.app.state.engagements.transaction() as db:
            content=self.content(in_scope=[{'kind':'ip','value':'169.254.169.254'}])
            db.execute('UPDATE roe_versions SET content=? WHERE engagement_id=? AND version=1',(json.dumps(content),row['id']))
        self.decide(row,'approve',422)

    def test_unsafe_scope_and_http_without_ports_block_submission(self):
        for changes in ({'in_scope':[{'kind':'url','value':'https://10.10.0.25/api/%2e%2e/admin'}]}, {'ports':[], 'allowed_actions':['http_headers']}, {'in_scope':[{'kind':'ip','value':'169.254.169.254'}]}, {'in_scope':[{'kind':'url','value':'https://127.1/api'}]}, {'in_scope':[{'kind':'url','value':'https://10.10.0.25/api;admin'}]}):
            row=self.create(self.content(**changes))
            self.assertFalse(row['versions'][0]['scope_report']['valid'])
            self.decide(row,'submit',422)

    def test_stage_one_database_upgrade_keeps_existing_snapshot(self):
        row=self.approved()
        with self.client.app.state.engagements.transaction() as db:
            db.execute('DROP TABLE policy_checks')
        reopened=EngagementStore(self.data)
        self.assertEqual(reopened.detail(self.project,row['id'])['versions'][0]['content_hash'],row['versions'][0]['content_hash'])
        self.assertEqual(reopened.policy_history(self.project,row['id'])['total'],0)
        self.assertEqual(self.evaluate(row)['decision'],'pass')

    def test_ambiguous_exclusion_aliases_cannot_hide_ipv4_target(self):
        row=self.create(self.content(out_of_scope=[{'kind':'ip','value':'::ffff:10.10.0.25'}]))
        self.assertFalse(row['versions'][0]['scope_report']['valid'])
        self.decide(row,'submit',422)


if __name__ == '__main__':
    unittest.main()
