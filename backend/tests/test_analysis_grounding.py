import unittest

from analysis_grounding import GROUNDING_VERSION, fact_conflicts, grounded_output, reviewed_report, structured_facts


def head_source(**statuses):
    checks = [{'check': name.replace('_', '-'), 'status': status} for name, status in statuses.items()]
    return {'evidence_id': 'e1', 'target': {'value': 'https://owned.example/'},
            'result': {'tool': 'zap-head', 'head': {'http_status': 200, 'checks': checks, 'cookie_flags': []}}}


class StructuredFactGroundingTests(unittest.TestCase):
    def test_reported_case_csp_missing_rejects_available_and_secure_claim(self):
        source = head_source(content_security_policy='missing')
        result = grounded_output({
            'summary': 'CSP tersedia dan aman. Respons HEAD berstatus 200.',
            'observations': [{'statement': 'Header CSP tersedia dan aman.', 'evidence_quote': 'content-security-policy'},
                             {'statement': 'Header CSP tidak ada pada respons.', 'evidence_quote': 'content-security-policy'}],
            'limitations': ['Hanya satu HEAD.'], 'recommendations': ['Terapkan CSP yang ketat.']}, source)
        self.assertNotIn('tersedia dan aman', str(result))
        self.assertEqual(result['summary'], 'Respons HEAD berstatus 200.')
        self.assertEqual(len(result['observations']), 1)
        self.assertIn('tidak ada', result['observations'][0])
        self.assertEqual(result['recommendations'], ['Terapkan CSP yang ketat.'])
        self.assertIn('CSP bertentangan dengan evidence (tidak ada)', ' '.join(result['limitations']))

    def test_present_header_rejects_absence_and_unverifiable_quality(self):
        facts = structured_facts(head_source(content_security_policy='present', strict_transport_security='missing'))
        self.assertEqual(fact_conflicts('CSP tidak ditemukan pada respons.', facts), ['CSP bertentangan dengan evidence (ada)'])
        self.assertEqual(fact_conflicts('Header CSP tersedia.', facts), [])
        self.assertEqual(fact_conflicts('Status CSP: tersedia.', facts), [])
        self.assertIn('kualitas CSP tidak dapat diverifikasi (nilai header tidak disimpan)',
                      fact_conflicts('CSP dikonfigurasi dengan kuat.', facts))
        self.assertEqual(fact_conflicts('HSTS tidak ada, tetapi CSP tersedia.', facts), [])
        self.assertEqual(fact_conflicts('HSTS tersedia dan CSP juga ada.', facts), ['HSTS bertentangan dengan evidence (tidak ada)'])
        self.assertEqual(fact_conflicts('CSP tidak ada sehingga respons kurang aman.', facts),
                         ['CSP bertentangan dengan evidence (ada)'])

    def test_scope_statements_and_unknown_facts_stay_neutral(self):
        facts = structured_facts(head_source(content_security_policy='present'))
        self.assertEqual(fact_conflicts('CSP tidak diuji terhadap bypass.', facts), [])
        self.assertEqual(fact_conflicts('Konfigurasi TLS legacy tidak diuji.', facts), [])
        self.assertEqual(fact_conflicts('X-Frame-Options tidak ada.', facts), [])  # not recorded: other checks decide
        self.assertEqual(fact_conflicts('Periksa header CSP secara manual.', facts), [])

    def test_other_evidence_shapes(self):
        nuclei = {'result': {'tool': 'nuclei-head', 'csp_observation': 'missing_header_candidate'}}
        self.assertEqual(fact_conflicts('Content-Security-Policy diterapkan.', structured_facts(nuclei)),
                         ['CSP bertentangan dengan evidence (tidak ada)'])
        compact = {'result': {'tool': 'zap-head', 'head': {'headers': {'content-security-policy': 'missing'},
                   'http_configuration': {'cache': {'header_present': True}, 'cors': {'allow_origin_present': False}}}}}
        facts = structured_facts(compact)
        self.assertEqual(facts, {'CSP': False, 'Cache-Control': True, 'CORS': False})
        self.assertTrue(fact_conflicts('Header Access-Control-Allow-Origin dikirim.', facts))
        self.assertTrue(fact_conflicts('Cache-Control tidak ada.', facts))
        plain = {'result': {'checks': [{'check': 'https_transport', 'status': 'unencrypted'}], 'tls': {'verified': False}}}
        self.assertTrue(fact_conflicts('Koneksi memakai HTTPS.', structured_facts(plain)))

    def test_cookie_flags_and_conflicting_records(self):
        protected = {'result': {'cookie_flags': [{'httponly': True, 'secure': True, 'samesite': False}] * 2}}
        facts = structured_facts(protected)
        self.assertTrue(fact_conflicts('Cookie tanpa flag HttpOnly ditemukan.', facts))
        self.assertTrue(fact_conflicts('Cookie memakai SameSite.', facts))
        self.assertEqual(fact_conflicts('Cookie tanpa SameSite.', facts), [])
        mixed = {'result': {'cookie_flags': [{'httponly': True}, {'httponly': False}]}}
        self.assertEqual(fact_conflicts('Ada cookie tanpa HttpOnly.', structured_facts(mixed)), [])
        conflicting = {'result': {'a': {'checks': [{'check': 'csp', 'status': 'present'}]},
                                  'b': {'checks': [{'check': 'csp', 'status': 'missing'}]}}}
        self.assertNotIn('CSP', structured_facts(conflicting))

    def test_structured_key_value_quotes_from_real_models_are_matched(self):
        source = head_source(content_security_policy='missing', strict_transport_security='present')
        source['result']['head'].update(tls={'verified': True, 'version': 'TLSv1.3'},
                                        http_configuration={'cors': {'allow_origin_present': False}})
        observations = [  # quotes as produced by whiterabbitneo-v3-7b and qwen-9b-reasoning on this evidence
            {'statement': 'Header CSP tidak ditemukan dalam respons.', 'evidence_quote': 'content-security-policy: missing'},
            {'statement': 'HSTS hadir dalam respons.', 'evidence_quote': 'strict-transport-security: present'},
            {'statement': 'Versi TLS yang digunakan adalah TLSv1.3.', 'evidence_quote': 'tls: {verified: true, version: TLSv1.3}'},
            {'statement': 'Header CORS tidak hadir.', 'evidence_quote': 'cors: {allow_origin_present: false}'},
            {'statement': 'Header CSP tersedia dan aman.', 'evidence_quote': 'content-security-policy: missing'},
            {'statement': 'CSP hadir.', 'evidence_quote': 'content-security-policy: present'},
            {'statement': 'Status 500.', 'evidence_quote': 'http_status: 500'},
        ]
        result = grounded_output({'summary': 'Ringkas.', 'observations': observations, 'limitations': [], 'recommendations': []}, source)
        self.assertEqual(len(result['observations']), 4, result['observations'])
        self.assertTrue(result['observations'][0].startswith('Header CSP tidak ditemukan'))
        self.assertIn('3 pernyataan model dihapus', ' '.join(result['limitations']))

    def test_legacy_report_is_rechecked_and_marked_without_rewriting_storage(self):
        stored = {'id': 'r1', 'source': head_source(content_security_policy='missing'), 'output': {
            'summary': 'CSP tersedia dan aman. Respons berstatus 200.',
            'observations': ['Header CSP tersedia dan aman (bukti: “content-security-policy”)', 'Status 200 diterima.'],
            'limitations': ['Hanya satu HEAD.'], 'recommendations': ['Tambahkan CSP.']}}
        snapshot = repr(stored)
        view = reviewed_report(stored)
        self.assertEqual(repr(stored), snapshot)
        self.assertEqual(view['grounding_status'], 'legacy_rechecked')
        self.assertEqual(view['legacy_statements_hidden'], 2)
        self.assertEqual(view['output']['summary'], 'Respons berstatus 200.')
        self.assertEqual(view['output']['observations'], ['Status 200 diterima.'])
        self.assertTrue(view['output']['limitations'][0].startswith('Laporan lama'))
        self.assertEqual(view['output']['recommendations'], ['Tambahkan CSP.'])
        clean = reviewed_report({**stored, 'output': {**stored['output'], 'summary': 'Status 200.', 'observations': ['x']}})
        self.assertEqual(clean['legacy_statements_hidden'], 0)
        self.assertTrue(clean['output']['limitations'][0].startswith('Laporan lama'))
        current = reviewed_report({**stored, 'grounding_version': GROUNDING_VERSION})
        self.assertEqual(current['grounding_status'], 'current')
        self.assertEqual(current['output'], stored['output'])

    def test_operator_imports_have_no_structured_facts(self):
        imported = {'result': {'kind': 'operator_import', 'content': '{"checks":[{"check":"csp","status":"missing"}]}'}}
        self.assertEqual(structured_facts(imported), {})


if __name__ == '__main__':
    unittest.main()
