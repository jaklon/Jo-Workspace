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
        self.assertTrue(result['summary'].startswith('Respons HEAD menghasilkan HTTP 200.'))
        self.assertTrue(result['summary'].endswith('Catatan model: Respons HEAD berstatus 200.'))
        # Evidence facts come first; model lines that restate a fact are not repeated.
        self.assertEqual(result['observations'], ['Status HTTP: 200.', 'Header tidak ada: CSP.', 'Cookie tercatat: tidak ada Set-Cookie pada respons ini.'])
        self.assertTrue(result['recommendations'][0].startswith('Susun Content-Security-Policy'))
        self.assertIn('Terapkan CSP yang ketat.', result['recommendations'])
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
        self.assertIn('Header tidak ada: CSP.', result['observations'])
        self.assertIn('Header ada: HSTS.', result['observations'])
        self.assertIn('HTTPS: terverifikasi (TLSv1.3).', result['observations'])
        self.assertNotIn('tersedia dan aman', str(result['observations']))
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
        self.assertTrue(view['output']['summary'].endswith('Catatan model: Respons berstatus 200.'))
        self.assertNotIn('tersedia dan aman', str(view['output']))
        self.assertEqual(view['output']['observations'][-1], 'Status 200 diterima.')
        self.assertIn('Header tidak ada: CSP.', view['output']['observations'])
        self.assertTrue(view['output']['limitations'][0].startswith('Laporan lama'))
        self.assertIn('Tambahkan CSP.', view['output']['recommendations'])
        clean = reviewed_report({**stored, 'output': {**stored['output'], 'summary': 'Status 200.', 'observations': ['x']}})
        self.assertEqual(clean['legacy_statements_hidden'], 0)
        self.assertTrue(clean['output']['limitations'][0].startswith('Laporan lama'))
        current = reviewed_report({**stored, 'grounding_version': GROUNDING_VERSION})
        self.assertEqual(current['grounding_status'], 'current')
        self.assertEqual(current['output'], stored['output'])

    def test_operator_imports_have_no_structured_facts(self):
        imported = {'result': {'kind': 'operator_import', 'content': '{"checks":[{"check":"csp","status":"missing"}]}'}}
        self.assertEqual(structured_facts(imported), {})



class EvidenceBaselineTests(unittest.TestCase):
    def head(self, **extra):
        checks = [{'check': name, 'status': 'missing'} for name in ('strict-transport-security', 'content-security-policy',
                  'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy')]
        return {'evidence_id': 'e9', 'target': {'value': 'http://owned.example/'}, 'result': {
            'adapter': 'public-head-1.0', 'http_status': 200, 'checks': checks + [{'check': 'https_transport', 'status': 'unencrypted'}],
            'tls': {'verified': False}, 'cookie_flags': [], 'redirect_observed': False, 'head_supported': True, **extra}}

    def test_facts_survive_an_empty_or_wrong_model_answer(self):
        empty = {'summary': '', 'observations': [], 'limitations': [], 'recommendations': []}
        result = grounded_output(empty, self.head())
        self.assertIn('Header tidak ada: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.',
                      result['observations'])
        self.assertIn('HTTPS: tidak digunakan; respons diterima tanpa enkripsi.', result['observations'])
        self.assertTrue(result['recommendations'][0].startswith('Layani situs melalui HTTPS'))
        self.assertEqual(len(result['recommendations']), 7)
        self.assertNotIn('Catatan model', result['summary'])
        wrong = grounded_output({**empty, 'summary': 'Semua header keamanan tersedia.', 'limitations': ['CSP tidak ada.']}, self.head())
        self.assertNotIn('tersedia', wrong['summary'])
        self.assertNotIn('CSP tidak ada.', wrong['limitations'])  # a fact is not reported as a limitation

    def test_redirect_cookie_and_cors_details(self):
        result = grounded_output({'summary': '', 'observations': [], 'limitations': [], 'recommendations': []}, self.head(
            http_status=301, redirect_observed=True,
            cookie_flags=[{'secure': True, 'httponly': True, 'samesite': True}, {'secure': False, 'httponly': True, 'samesite': False}],
            http_configuration={'cache': {'header_present': True, 'no_store': True},
                                'cors': {'allow_origin_present': True, 'wildcard_origin_observed': True}}))
        self.assertIn('Redirect: respons adalah pengalihan dan tidak diikuti.', result['observations'])
        self.assertEqual(result['limitations'][0], 'Header di atas milik respons pengalihan; header halaman tujuan belum diperiksa.')
        self.assertIn('Cookie tercatat: 2 Set-Cookie (1 tanpa Secure, 1 tanpa SameSite).', result['observations'])
        self.assertIn('Cache-Control: ada (no-store).', result['observations'])
        self.assertIn('CORS: Access-Control-Allow-Origin ada, bernilai *.', result['observations'])

    def test_tcp_and_operator_import(self):
        tcp = {'evidence_id': 't1', 'target': {'value': '192.0.2.4'}, 'result': {'tool': 'nmap', 'target': '192.0.2.4',
               'ports': [{'port': 22, 'status': 'open'}, {'port': 443, 'status': 'open'}, {'port': 8080, 'status': 'filtered'}]}}
        result = grounded_output({'summary': 'Port 3306 terbuka.', 'observations': [], 'limitations': [], 'recommendations': []}, tcp)
        self.assertEqual(result['summary'], 'Scan nmap terhadap 192.0.2.4: 2 dari 3 port terbuka (22, 443).')
        self.assertEqual(result['observations'], ['Port terbuka: 22, 443.', 'Port lain: 8080 (filtered).'])
        imported = {'evidence_id': 'i1', 'result': {'kind': 'operator_import', 'content': 'Port terbuka: 1'}}
        from evidence_report import baseline
        self.assertIsNone(baseline(imported))

    def test_fact_lines_survive_the_evidence_redactor(self):
        # deep_analysis scrubs the whole output; a fact line shaped like "Cookie: ..." was once redacted.
        from security_evidence import redactor
        scrub, _ = redactor()
        result = grounded_output({'summary': '', 'observations': [], 'limitations': [], 'recommendations': []}, self.head(
            http_status=302, redirect_observed=True, cookie_flags=[{'secure': False, 'httponly': False, 'samesite': False}],
            http_configuration={'cache': {'header_present': True}, 'cors': {'allow_origin_present': True, 'allow_credentials_true': True}}))
        for key in ('summary', 'observations', 'limitations', 'recommendations'):
            self.assertEqual(scrub(result[key]), result[key], key)


if __name__ == '__main__':
    unittest.main()
