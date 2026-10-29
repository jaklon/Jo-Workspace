import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from auto_governance import create_approved_job, create_approved_jobs, prepare_plan
from chat_orchestrator import SecuritySlots, ToolSelection, complete_explicit_slots, security_slots
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
        self.assertEqual(result["summary"], "CSP tidak terlihat pada respons.")
        self.assertEqual(len(result["observations"]), 1)
        self.assertIn("content-security-policy", result["observations"][0])
        self.assertEqual(result["recommendations"], ["Tambahkan Content-Security-Policy."])
        removed = " ".join(result["limitations"])
        self.assertIn("4 pernyataan model dihapus", removed)
        for term in ("cookie", "HSTS", "port 8080"):
            self.assertIn(term, removed)
        no_cookie = grounded_output({"summary":"Tidak ada cookie yang teramati.", "observations":["Respons diterima."],
                                     "limitations":["l"], "recommendations":[]}, source)
        self.assertEqual(no_cookie["summary"], "Tidak ada cookie yang teramati.")

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


class ExtractionTests(unittest.IsolatedAsyncioTestCase):
    async def test_model_cannot_invent_target_or_ports(self):
        answer = {"content": '{"tool":"tcp-connect","target":"192.0.2.4","ports":[22,443],"environment":"lab","assessment_mode":"blackbox"}', "tool_calls": []}
        with patch("chat_orchestrator.runtime.chat", new=AsyncMock(return_value=answer)):
            slots = await security_slots("Scan port 22", [HistoryMessage(role="user", content="lab blackbox")], "model")
        self.assertEqual(slots.target, "")
        self.assertEqual(slots.ports, [22])
