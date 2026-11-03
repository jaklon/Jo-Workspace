import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from auto_governance import create_approved_job, create_approved_jobs, prepare_plan
from chat_orchestrator import VA_REQUEST, SecuritySlots, ToolSelection, complete_explicit_slots, domain_disambiguation, security_slots, without_urls
from contracts import HistoryMessage
from deep_analysis import grounded_output
from engagements import EngagementStore
from security_jobs import JobStore
from store import Store


class ChatActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_decision_is_session_bound_and_single_use(self):
        store = Store(self.directory)
        action = store.propose_chat_action("one", {"intent": "coding", "prompt": "test"})
        with self.assertRaises(ValueError):
            store.decide_chat_action(action["id"], "other", True)
        self.assertEqual(store.decide_chat_action(action["id"], "one", False)["intent"], "coding")
        with self.assertRaises(ValueError):
            store.decide_chat_action(action["id"], "one", True)

    def test_slot_filling_and_plan_are_bounded(self):
        plan, question = prepare_plan(SecuritySlots(tool="tcp-connect"))
        self.assertIsNone(plan)
        self.assertIn("port", question)
        slots = SecuritySlots(tool="tcp-connect", target="192.0.2.4", ports=[443, 22],
                              environment="lab", assessment_mode="blackbox")
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertEqual(plan["ports"], [22, 443])

    def test_bare_domain_in_analysis_context_offers_concrete_commands(self):
        # A bare domain with an analysis cue is ambiguous: offer URL check, recon and
        # the stored-report command instead of guessing web search.
        hint = domain_disambiguation('deep analysis jascon.my.id')
        self.assertIsNotNone(hint)
        self.assertIn('http-head https://jascon.my.id', hint)
        self.assertIn('subfinder-passive jascon.my.id', hint)
        self.assertIn('deep analysis https://jascon.my.id', hint)
        self.assertIsNotNone(domain_disambiguation('cek keamanan example.co.id'))

    def test_domain_disambiguation_stays_out_of_the_way(self):
        # No trigger with an explicit URL, a qualified target, a named tool, no cue,
        # or no domain at all.
        self.assertIsNone(domain_disambiguation('deep analysis https://jascon.my.id'))
        self.assertIsNone(domain_disambiguation('deep analysis domain:jascon.my.id'))
        self.assertIsNone(domain_disambiguation('subfinder-passive jascon.my.id staging blackbox'))
        self.assertIsNone(domain_disambiguation('cari berita terbaru tentang jascon.my.id'))
        self.assertIsNone(domain_disambiguation('jelaskan apa itu REST API'))
        self.assertIsNone(domain_disambiguation('cek keamanan akun saya'))

    def test_unsupported_tool_reply_guides_the_user(self):
        # A request the chat flow cannot turn into a check (e.g. "buatkan RoE")
        # must name the supported checks, the needed parameters, and where to
        # build an RoE manually — not just say the tool is unavailable.
        plan, question = prepare_plan(SecuritySlots(tool="unsupported"))
        self.assertIsNone(plan)
        self.assertIn("http-head", question)
        self.assertIn("document-review", question)
        self.assertIn("Security Workspace", question)
        self.assertIn("staging.example", question)

    def test_explicit_slots_never_invent_greybox_alias(self):
        slots = SecuritySlots(tool="document-review")
        complete_explicit_slots(slots, "GreyBox lab example.test configuration, alias akun uji")
        self.assertEqual(slots.test_account_ref, "")
        _, question = prepare_plan(slots)
        self.assertIn("alias", question)
        complete_explicit_slots(slots, "GreyBox lab example.test configuration, alias akun uji: user-a")
        self.assertEqual(slots.test_account_ref, "user-a")
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertEqual(plan["test_account_ref"], "user-a")

    def test_unsupported_model_claims_never_enter_grounded_report(self):
        source = {"evidence_id":"evidence-1", "result":{"kind":"operator_import", "content":"def check(x): return x == 1"}}
        candidate = {"summary":"Cookie is unsafe", "observations":["Cookie is unsafe", "return x == 1"],
                     "limitations":[], "recommendations":["Disable cookie protection"]}
        result = grounded_output(candidate, source)
        self.assertIn("return x == 1", result["observations"][0])
        self.assertNotIn("Cookie", str(result))
        self.assertNotIn("Disable cookie", str(result))
        empty = grounded_output({**candidate, "observations":["Cookie is unsafe"]}, source)
        self.assertIn("Tidak ada observasi model yang dapat dicocokkan", empty["observations"][0])
        self.assertIn("dihapus", " ".join(empty["limitations"]))

    def test_grounding_keeps_supported_claims_and_quotes(self):
        source = {"evidence_id":"e2", "target":{"value":"https://owned.example/"},
                  "result":{"tool":"zap-head", "head":{"checks":[{"check":"content-security-policy","status":"missing"}],
                            "cookie_flags":[], "http_status":200}}}
        candidate = {"summary":"CSP tidak terlihat pada respons. Cookie tanpa flag HttpOnly ditemukan di https://other.example/.",
                     "observations":[{"statement":"Header CSP berstatus missing.", "evidence_quote":"content-security-policy"},
                                     {"statement":"Server memakai nginx 1.24.", "evidence_quote":"nginx/1.24"},
                                     "Port 8080 terbuka."],
                     "limitations":["Hanya satu HEAD."], "recommendations":["Tambahkan Content-Security-Policy.", "Aktifkan HSTS."]}
        result = grounded_output(candidate, source)
        self.assertNotIn("Catatan model", result["summary"])  # restates a fact already rendered from evidence
        self.assertIn("Header tidak ada: CSP.", result["observations"])
        self.assertNotIn("nginx", str(result["observations"]))
        self.assertIn("Tambahkan Content-Security-Policy.", result["recommendations"])
        self.assertNotIn("Aktifkan HSTS.", result["recommendations"])
        removed = " ".join(result["limitations"])
        self.assertIn("4 pernyataan model dihapus", removed)
        for term in ("cookie", "HSTS", "port 8080"):
            self.assertIn(term, removed)
        no_cookie = grounded_output({"summary":"Tidak ada cookie yang teramati.", "observations":["Respons diterima."],
                                     "limitations":["l"], "recommendations":[]}, source)
        self.assertNotIn("Catatan model", no_cookie["summary"])
        self.assertIn("Cookie tercatat: tidak ada Set-Cookie pada respons ini.", no_cookie["observations"])

    def test_inventory_counts_are_derived_from_distinct_origins_and_legacy_reports(self):
        from analysis_grounding import grounded_output, reviewed_report, inventory_origin_counts
        source = {"evidence_id":"inventory-1", "target":{"value":"https://example.test/path"},
                  "result":{"tool":"inventory-html", "target":"https://example.test/path", "candidates":[
                      {"url":"https://EXAMPLE.test:443/", "contacted":False},
                      {"url":"https://fonts.example/", "contacted":False},
                      {"url":"https://cdn.example/", "contacted":False},
                      {"url":"https://cdn.example:443/a", "contacted":False}]}}
        self.assertEqual(inventory_origin_counts(source), {"total":3, "same_origin":1, "same_host_other_origin":0, "external":2,
                                                           "external_hosts":2, "recorded":4, "truncated":False})
        candidate = {"summary":"Tiga kandidat URL eksternal teridentifikasi.",
                     "observations":[{"statement":"Ada 3 kandidat eksternal.", "evidence_quote":"https://cdn.example/"}],
                     "limitations":["Satu GET."], "recommendations":[]}
        output = grounded_output(candidate, source)
        self.assertNotIn("Tiga kandidat URL eksternal", output['summary'])
        self.assertIn("3 origin kandidat unik: 1 sama dengan origin target, dan 2 origin eksternal (di 2 host selain host target).", output['summary'])
        self.assertNotIn("Ada 3 kandidat eksternal", str(output['observations']))
        legacy = reviewed_report({"grounding_version":2, "source":source, "output":candidate})
        self.assertEqual(legacy['grounding_status'], 'legacy_rechecked')
        self.assertNotIn("Tiga kandidat URL eksternal", legacy['output']['summary'])
        self.assertIn("1 sama dengan origin target, dan 2 origin eksternal", legacy['output']['summary'])
        source['result']['candidates'].append({'url':'not-a-url'})
        self.assertIsNone(inventory_origin_counts(source))

    def test_same_host_other_scheme_is_not_external_and_truncation_is_disclosed(self):
        from analysis_grounding import grounded_output, inventory_origin_counts
        urls = ["https://example.test/", "http://example.test/", "https://example.test:8443/",
                "https://cdn.example/", "http://cdn.example/", "https://www.example.test/"]
        source = {"evidence_id":"inventory-2", "target":{"value":"https://example.test/"},
                  "result":{"tool":"inventory-html", "target":"https://example.test/",
                            "candidates":[{"url":url, "contacted":False} for url in urls]}}
        counts = inventory_origin_counts(source)
        self.assertEqual((counts["total"], counts["same_origin"], counts["same_host_other_origin"], counts["external"],
                          counts["external_hosts"]), (6, 1, 2, 3, 2))
        summary = grounded_output({"summary":"x", "observations":[], "limitations":[], "recommendations":[]}, source)["summary"]
        self.assertIn("6 origin kandidat unik: 1 sama dengan origin target, 2 pada host target dengan skema/port berbeda, "
                      "dan 3 origin eksternal (di 2 host selain host target).", summary)
        self.assertNotIn("dibatasi", summary)
        source["result"]["candidates"] = [{"url":f"https://h{i}.example/", "contacted":False} for i in range(40)]
        summary = grounded_output({"summary":"x", "observations":[], "limitations":[], "recommendations":[]}, source)["summary"]
        self.assertIn("40 origin eksternal (di 40 host", summary)
        self.assertIn("dibatasi 40 entri oleh adapter", summary)

    def test_origin_claims_are_grounded_for_js_bundle_and_rejected_for_head(self):
        from analysis_grounding import grounded_output
        bundle = {"evidence_id":"js-1", "target":{"value":"https://example.test/app.js"},
                  "result":{"tool":"js-bundle-inventory", "target":"https://example.test/app.js", "status_code":200,
                            "candidate_origins":["https://example.test/", "https://api.example.test/", "https://cdn.example/"],
                            "candidate_api_paths":["/api/users"]}}
        output = grounded_output({"summary":"Bundle memuat 5 origin eksternal.",
                                  "observations":[{"statement":"Path /api/users tercatat.", "evidence_quote":"/api/users"}],
                                  "limitations":[], "recommendations":[]}, bundle)
        self.assertNotIn("5 origin eksternal", output["summary"])
        self.assertIn("3 origin kandidat unik: 1 sama dengan origin target, dan 2 origin eksternal (di 2 host selain host target).", output["summary"])
        head = {"evidence_id":"head-1", "target":{"value":"https://example.test/"},
                "result":{"http_status":200, "headers":{"content-security-policy":"missing"}}}
        output = grounded_output({"summary":"Situs memuat 4 origin eksternal. Respons HTTP 200 diterima.",
                                  "observations":["Terdapat domain pihak ketiga pada halaman.", "CORS tidak teramati."],
                                  "limitations":[], "recommendations":[]}, head)
        self.assertNotIn("origin eksternal", output["summary"])
        self.assertIn("HTTP 200", output["summary"])
        self.assertNotIn("pihak ketiga", str(output["observations"]))
        self.assertIn("CORS tidak teramati.", output["observations"])

    def test_confirmed_plan_uses_existing_policy_and_creates_job(self):
        engagements = EngagementStore(self.directory)
        jobs = JobStore(engagements)
        jobs.acquire("test-worker")
        state = SimpleNamespace(engagements=engagements, jobs=jobs)
        slots = SecuritySlots(tool="tcp-connect", target="192.0.2.4", ports=[443],
                              environment="lab", assessment_mode="blackbox")
        plan, _ = prepare_plan(slots)
        project = "89de83d0-8729-4b0a-b21d-9fcafc444095"
        project, engagement, job = create_approved_job(state, project, "session", plan)
        detail = jobs.detail(project, engagement, job)
        self.assertEqual(detail["status"], "queued")
        self.assertEqual(detail["plan"]["scan"]["tool"], "tcp-connect")
        self.assertEqual(detail["plan"]["steps"][0]["ports"], [443])
        self.assertFalse(jobs.listing(project, engagement)["gate"]["stopped"])
        self.assertTrue(any(event["action"] == "gate_opened" for event in engagements.detail(project, engagement)["events"]))
        jobs.release("test-worker")

    def test_governance_rolls_back_every_record_on_job_failure(self):
        engagements = EngagementStore(self.directory)
        jobs = JobStore(engagements)
        jobs.acquire("test-worker")
        state = SimpleNamespace(engagements=engagements, jobs=jobs)
        plan, _ = prepare_plan(SecuritySlots(tool="tcp-connect", target="192.0.2.4", ports=[443],
                                             environment="lab", assessment_mode="blackbox"))
        project = "89de83d0-8729-4b0a-b21d-9fcafc444095"
        with patch.object(jobs, "approve_in", side_effect=ValueError("synthetic failure")):
            with self.assertRaisesRegex(ValueError, "synthetic failure"):
                create_approved_job(state, project, "session", plan)
        self.assertEqual(engagements.list(project), [])
        with closing(engagements.connect()) as db:
            for table in ("engagements", "roe_versions", "engagement_events", "security_engagement_gates", "security_jobs", "security_job_events"):
                self.assertEqual(db.execute(f"select count(*) from {table}").fetchone()[0], 0, table)
        jobs.release("test-worker")

    def test_multi_tool_creates_all_jobs_in_one_transaction(self):
        engagements = EngagementStore(self.directory)
        jobs = JobStore(engagements)
        jobs.acquire("test-worker")
        state = SimpleNamespace(engagements=engagements, jobs=jobs)
        slots = SecuritySlots(environment="lab", assessment_mode="blackbox", selections=[
            ToolSelection(tool="tcp-connect", target="192.0.2.4", ports=[443]),
            ToolSelection(tool="http-head", target="https://example.test/"),
        ])
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        project = "89de83d0-8729-4b0a-b21d-9fcafc444095"
        _, eid, ids = create_approved_jobs(state, project, "session", plan)
        self.assertEqual(len(ids), 2)
        self.assertTrue(all(jobs.detail(project, eid, jid)["status"] == "queued" for jid in ids))
        content = engagements.detail(project, eid)["versions"][0]["content"]
        self.assertEqual(set(content["allowed_actions"]), {"tcp_discovery", "http_headers"})
        jobs.release("test-worker")

    def test_multi_tool_failure_rolls_back_first_job_too(self):
        engagements = EngagementStore(self.directory)
        jobs = JobStore(engagements)
        jobs.acquire("test-worker")
        state = SimpleNamespace(engagements=engagements, jobs=jobs)
        slots = SecuritySlots(environment="lab", assessment_mode="blackbox", selections=[
            ToolSelection(tool="tcp-connect", target="192.0.2.4", ports=[443]),
            ToolSelection(tool="http-head", target="https://example.test/"),
        ])
        plan, _ = prepare_plan(slots)
        original = jobs.approve_in
        calls = 0
        def fail_second(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("second job failure")
            return original(*args)
        project = "89de83d0-8729-4b0a-b21d-9fcafc444095"
        with patch.object(jobs, "approve_in", side_effect=fail_second):
            with self.assertRaisesRegex(ValueError, "second job failure"):
                create_approved_jobs(state, project, "session", plan)
        self.assertEqual(engagements.list(project), [])
        jobs.release("test-worker")

    def test_supported_adapters_create_bounded_approved_plans(self):
        engagements = EngagementStore(self.directory)
        jobs = JobStore(engagements)
        jobs.acquire("test-worker")
        state = SimpleNamespace(engagements=engagements, jobs=jobs)
        project = "89de83d0-8729-4b0a-b21d-9fcafc444095"
        cases = [("http-head", "https://example.test/"), ("tcp-connect", "192.0.2.4"),
                 ("nmap", "192.0.2.4"), ("nuclei-head", "https://example.test/"),
                 ("zap-head", "https://example.test/"), ("subfinder-passive", "example.test"),
                 ("amass-passive", "example.test"), ("inventory-html", "https://example.test/"),
                 ("js-bundle-inventory", "https://example.test/bundle.js"),
                 ("auth-unauthenticated-get", "https://example.test/"),
                 ("scoped-spider", "https://example.test/"), ("active-reflection", "https://example.test/")]
        with patch("bounded_scan.binary_hash", return_value="a" * 64), \
             patch("nuclei_adapter.binary_hash", return_value="a" * 64), \
             patch("zap_adapter.image_hash", return_value="a" * 64), \
             patch("subfinder_adapter.fingerprint", return_value="a" * 64), \
             patch("subfinder_adapter.amass_fingerprint", return_value="a" * 64):
            for tool, target in cases:
                with self.subTest(tool=tool):
                    slots = SecuritySlots(tool=tool, target=target, ports=[443], environment="lab", assessment_mode="blackbox")
                    plan, _ = prepare_plan(slots)
                    _, eid, jid = create_approved_job(state, project, "session", plan)
                    job = jobs.detail(project, eid, jid)
                    self.assertEqual(job["status"], "queued")
                    self.assertEqual(job["plan"]["steps"][0]["target"]["value"], target)
        jobs.release("test-worker")

    def test_monitoring_plan_is_restricted_to_whitebox_loopback_lab(self):
        slots = SecuritySlots(tool="monitoring-local", target="127.0.0.1", environment="lab", assessment_mode="whitebox")
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertEqual(plan["ports"], [3000, 9090])
        self.assertEqual(plan["evidence_kind"], "monitoring")
        _, question = prepare_plan(slots.model_copy(update={"environment":"staging"}))
        self.assertIn("lab", question)


class SessionFactTests(unittest.TestCase):
    REPORT = ("**Ringkasan**\nModel menulis 9 origin.\n\n**Observasi**\n- Status HTTP: 200.\n- Header tidak ada: CSP.\n"
              "- Model: ada 9 origin eksternal.\n\nJob: j1 · Analisis: a1\nEvidence: e1 · SHA-256: abc\n\n---\n\n"
              "**Observasi**\n- Evidence inventaris mencatat 5 origin kandidat unik: 1 sama dengan origin target, dan 4 origin eksternal (di 4 host selain host target).\n\n"
              "Job: j2 · Analisis: a2\nEvidence: e2 · SHA-256: def\n\nEngagement: g1 · Analisis memerlukan review manusia.")

    def test_facts_are_copied_from_user_text_and_report_lines_only(self):
        from session_context import session_facts
        history = [{"role": "user", "content": "Jalankan VA pada https://a.test/ dan 192.0.2.4"},
                   {"role": "assistant", "content": "Untuk menyiapkan pemeriksaan, mohon sebutkan lingkungan dan mode."},
                   {"role": "user", "content": "staging, BlackBox"},
                   {"role": "assistant", "content": self.REPORT},
                   {"role": "assistant", "content": "Jawaban biasa: Evidence: palsu tanpa penanda laporan."}]
        facts = session_facts(history)
        self.assertIn("Target yang disebut pengguna: https://a.test/, 192.0.2.4 (terakhir: 192.0.2.4)", facts)
        self.assertIn("lingkungan staging · mode BlackBox", facts)
        self.assertIn("Evidence inventaris mencatat 5 origin kandidat unik", facts)
        self.assertIn("Evidence: e2 · SHA-256: def", facts)
        self.assertNotIn("9 origin", facts)
        self.assertNotIn("palsu", facts)
        self.assertEqual(session_facts([{"role": "user", "content": "Halo"}]), "")
        ambiguous = session_facts([{"role": "user", "content": "staging"}, {"role": "user", "content": "lab atau staging?"}])
        self.assertIn("lingkungan staging", ambiguous)

    def test_facts_reach_the_model_when_old_turns_do_not_fit(self):
        from model_runtime import bounded_messages
        history = [{"role": "user", "content": "Jalankan VA pada https://a.test/ staging BlackBox"},
                   {"role": "assistant", "content": self.REPORT}]
        history += [{"role": role, "content": "Catatan rutin " + "x" * 1500} for _ in range(20) for role in ("user", "assistant")]
        # No word overlap with the report, so relevance-based selection cannot recover it.
        plain = bounded_messages("sistem", "Sebutkan angkanya tadi.", history)
        self.assertNotIn("5 origin kandidat unik", str(plain))
        remembered = bounded_messages("sistem", "Sebutkan angkanya tadi.", history, facts=True)
        self.assertIn("5 origin kandidat unik", remembered[0]["content"])
        self.assertIn("https://a.test/", remembered[0]["content"])


class ExtractionTests(unittest.IsolatedAsyncioTestCase):
    async def test_general_url_va_profile_requires_explicit_mode_and_environment(self):
        answer = {"content": '{"tool":"unsupported","environment":"staging","assessment_mode":"blackbox"}', "tool_calls": []}
        request = "Jalankan Vulnerabilities Assessment pada url ini https://circular-sync-staging.web.app/"
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots(request, [], "model")
            self.assertEqual(slots.environment, "")
            self.assertEqual(slots.assessment_mode, "")
            self.assertEqual([x.tool for x in slots.selections], ["http-head", "inventory-html"])
            _, question = prepare_plan(slots)
            self.assertIn("lingkungan", question)
            self.assertIn("BlackBox", question)
            domain_only = await security_slots("VA circular-sync-staging.example.test", [], "model")
            self.assertEqual(domain_only.environment, "")
            history = [HistoryMessage(role="user", content=request)]
            slots = await security_slots("Lingkungan staging, mode BlackBox", history, "model")
            plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertTrue(plan["url_va_profile"])
        self.assertEqual([job["tool"] for job in plan["jobs"]], ["http-head", "inventory-html"])
        self.assertTrue(all(job["target"]["value"] == "https://circular-sync-staging.web.app/" for job in plan["jobs"]))
        self.assertTrue(all(job["ports"] == [443] for job in plan["jobs"]))

    async def test_vague_security_check_without_url_asks_for_target(self):
        answer = {"content": '{"tool":"unsupported","environment":"staging"}', "tool_calls": []}
        request = "Tolong cek celah keamanan website staging saya."
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots(request, [], "model")
            self.assertEqual([x.tool for x in slots.selections], ["http-head", "inventory-html"])
            self.assertTrue(all(not x.target for x in slots.selections))
            _, question = prepare_plan(slots)
            self.assertNotIn("belum tersedia", question)
            self.assertIn("URL HTTP(S) lengkap", question)
            self.assertIn("mode analisis", question)
            self.assertNotIn("lingkungan (", question)  # "staging" was stated outside any URL.
            history = [HistoryMessage(role="user", content=request), HistoryMessage(role="assistant", content=question)]
            slots = await security_slots("https://staging.example.test/ mode BlackBox", history, "model")
            plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertEqual([job["tool"] for job in plan["jobs"]], ["http-head", "inventory-html"])
        self.assertTrue(all(job["target"]["value"] == "https://staging.example.test/" for job in plan["jobs"]))
        for phrase in ("cek keamanan https://a.test/", "periksa kerentanan https://a.test/", "scan celah keamanan https://a.test/",
                       "check security https://a.test/", "ada celah keamanan di https://a.test/?"):
            self.assertTrue(VA_REQUEST.search(without_urls(phrase)), phrase)
        for phrase in ("Jelaskan apa itu XSS", "cek kode auth.py", "Apa kabar?"):
            self.assertFalse(VA_REQUEST.search(phrase), phrase)

    async def test_va_profile_respects_explicit_tools_modes_and_production(self):
        answer = {"content": '{"tool":"unsupported"}', "tool_calls": []}
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("VA https://example.test/ production read-only BlackBox", [], "model")
            plan, question = prepare_plan(slots)
            self.assertIsNone(question)
            self.assertEqual([job["tool"] for job in plan["jobs"]], ["http-head"])
            slots = await security_slots("VA http://example.test/ staging BlackBox", [], "model")
            plan, question = prepare_plan(slots)
            self.assertIsNone(question)
            self.assertEqual([job["tool"] for job in plan["jobs"]], ["http-head"])
            slots = await security_slots("VA https://example.test:8443/ staging BlackBox", [], "model")
            _, question = prepare_plan(slots)
            self.assertIn("80 atau 443", question)
            slots = await security_slots("VA https://example.test/ staging GreyBox", [], "model")
            _, question = prepare_plan(slots)
            self.assertIn("auth-two-session", question)
            slots = await security_slots("VA https://example.test/ staging BlackBox tanpa GET", [], "model")
            self.assertFalse(slots.selections)
            invented = {"content": '{"tool":"nuclei-head"}', "tool_calls": []}
            with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=invented)):
                slots = await security_slots("VA https://example.test/ staging BlackBox jangan nuclei-head", [], "model")
            self.assertEqual(slots.tool, "unsupported")
            self.assertFalse(slots.selections)
            _, clarification = prepare_plan(slots)
            history = [HistoryMessage(role="user", content="VA https://example.test/ staging BlackBox jangan nuclei-head"),
                       HistoryMessage(role="assistant", content=clarification)]
            slots = await security_slots("http-head https://example.test/ staging BlackBox", history, "model")
            plan, question = prepare_plan(slots)
            self.assertIsNone(question)
            self.assertEqual(plan["tool"], "http-head")
            slots = await security_slots("VA https://example.test/ staging BlackBox dengan nuclei-head", [], "model")
            self.assertFalse(slots._url_va_profile)

    async def test_va_profile_never_selects_between_multiple_urls(self):
        answer = {"content": '{"tool":"unsupported"}', "tool_calls": []}
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("VA https://a.example/ dan https://b.example/ lab blackbox", [], "model")
        _, question = prepare_plan(slots)
        self.assertIn("URL", question)
        history = [HistoryMessage(role="user", content="VA https://a.example/ dan https://b.example/ lab blackbox"),
                   HistoryMessage(role="assistant", content=question)]
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("Gunakan https://b.example/", history, "model")
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertTrue(all(job["target"]["value"] == "https://b.example/" for job in plan["jobs"]))

    async def test_new_va_ignores_previous_target_environment_and_tools(self):
        answer = {"content": '{"tool":"nmap","target":"192.0.2.4","ports":[443],"environment":"lab","assessment_mode":"blackbox"}', "tool_calls": []}
        history = [HistoryMessage(role="user", content="Jalankan nmap 192.0.2.4 port 443 di lab BlackBox"),
                   HistoryMessage(role="assistant", content="Selesai.")]
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("VA https://new-staging.example.test/", history, "model")
        self.assertEqual(slots.environment, "")
        self.assertEqual(slots.assessment_mode, "")
        self.assertEqual([selection.tool for selection in slots.selections], ["http-head", "inventory-html"])
        self.assertTrue(all(selection.target == "https://new-staging.example.test/" for selection in slots.selections))

    async def test_explicit_reference_reuses_va_scope_from_same_conversation(self):
        answer = {"content": '{"tool":"unsupported"}', "tool_calls": []}
        history = [HistoryMessage(role="user", content="VA https://example.test/"),
                   HistoryMessage(role="assistant", content="Sebutkan lingkungan dan mode."),
                   HistoryMessage(role="user", content="staging BlackBox"),
                   HistoryMessage(role="assistant", content="Laporan selesai.")]
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("Ulangi VA pada target yang sama", history, "model")
        plan, question = prepare_plan(slots)
        self.assertIsNone(question)
        self.assertEqual(plan['environment'], 'staging')
        self.assertTrue(all(job['target']['value'] == 'https://example.test/' for job in plan['jobs']))

    async def test_model_cannot_invent_target_or_ports(self):
        answer = {"content": '{"tool":"tcp-connect","target":"192.0.2.4","ports":[22,443],"environment":"lab","assessment_mode":"blackbox"}', "tool_calls": []}
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("Scan port 22", [HistoryMessage(role="user", content="lab blackbox")], "model")
        self.assertEqual(slots.target, "")
        self.assertEqual(slots.ports, [22])
