import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AGENT_DATA_DIR", tempfile.mkdtemp(prefix="engagement-api-"))
os.environ.setdefault("AGENT_API_TOKEN", "synthetic-test-key-not-a-production-secret")
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import engagements
from engagements import EngagementContent, EngagementStore, ScopeAsset, Decision, utc_now
from main import app


def complete_content():
    return {"name": "UAT review", "objective": "Review synthetic environment", "owner": "Local owner", "contact": "PIC test", "environment": "uat", "authorization_ref": "LOA-TEST-001", "in_scope": [{"kind": "domain", "value": "UAT.example.test"}], "out_of_scope": [{"kind": "domain", "value": "production.example.test"}], "ports": [443, 8443], "allowed_actions": ["tcp_discovery", "http_headers"], "starts_at": (utc_now() + timedelta(days=1)).isoformat(), "ends_at": (utc_now() + timedelta(days=2)).isoformat(), "timezone": "Asia/Jakarta", "max_http_rps": 5, "max_concurrency": 1, "max_duration_minutes": 60, "emergency_contact": "SOC test", "stop_conditions": "STOP request or degradation", "test_account_refs": []}


class EngagementApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="roe-tests-")
        self.data = Path(self.directory.name)
        self.override = patch("main.DATA_DIR", self.data)
        self.override.start()
        self.client = TestClient(app).__enter__()
        self.headers = {"Authorization": "Bearer " + os.environ["AGENT_API_TOKEN"]}
        self.project = str(uuid4())
        self.base = "/api/security/projects/" + self.project + "/engagements"

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.override.stop()
        self.directory.cleanup()

    def create(self, content=None):
        response = self.client.post(self.base, headers=self.headers, json={"content": content or complete_content()})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def decide(self, row, action, expected=200, **extra):
        response = self.client.post(self.base + "/" + row["id"] + "/decisions", headers=self.headers, json={"expected_revision": row["revision"], "action": action, "actor_label": "Reviewer (declared)", "note": "Synthetic decision", "acknowledge": True, **extra})
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def test_authentication_and_hostile_origin(self):
        self.assertEqual(self.client.get(self.base).status_code, 401)
        self.assertEqual(self.client.post(self.base, json={"content": {"name": "x"}}).status_code, 401)
        self.assertEqual(self.client.post("/api/security/project-retention", json={"project_ids": []}).status_code, 401)
        self.assertEqual(self.client.get(self.base, headers={**self.headers, "Origin": "https://evil.example"}).status_code, 403)

    def test_partial_draft_and_submission_validation(self):
        row = self.create({"name": "  Initial draft  "})
        self.assertEqual(row["versions"][0]["content"]["name"], "Initial draft")
        self.assertEqual(row["versions"][0]["status"], "draft")
        errors = self.decide(row, "submit", 422)["detail"]["errors"]
        self.assertTrue(any("otorisasi" in message for message in errors))
        current = self.client.get(self.base + "/" + row["id"], headers=self.headers).json()
        self.assertEqual(current["revision"], 1)

    def test_scope_validation(self):
        for kind, value in [("domain", "*.example.test"), ("ip", "127.0.0.999"), ("cidr", "10.1.2.3/24"), ("domain", "x;echo-bad"), ("url", "file:///etc/passwd"), ("url", "https://user:password@example.test/"), ("url", "https://example.test/?token=x"), ("url", "https://example.test/#x"), ("url", "https://example.test:99999/"), ("domain", "127.0.0.1")]:
            with self.subTest(kind=kind, value=value), self.assertRaises(ValidationError):
                ScopeAsset(kind=kind, value=value)
        self.assertEqual(ScopeAsset(kind="url", value="https://EXAMPLE.test:443/api").value, "https://example.test/api")
        self.assertEqual(ScopeAsset(kind="ip", value="2001:0db8::1").value, "2001:db8::1")

    def test_rejects_production_extra_fields_and_invalid_limits(self):
        for changes in [{"environment": "production"}, {"max_http_rps": 16}, {"max_concurrency": 5}, {"max_duration_minutes": 0}, {"ports": [True]}, {"ports": ["443"]}, {"timezone": "Mars/Olympus"}, {"execution_enabled": True}, {"credentials": {"password": "test"}}]:
            content = {**complete_content(), **changes}
            response = self.client.post(self.base, headers=self.headers, json={"content": content})
            self.assertEqual(response.status_code, 422, changes)

    def test_duplicate_conflicting_scope_and_dates(self):
        content = complete_content()
        for change in [{"out_of_scope": content["in_scope"]}, {"in_scope": content["in_scope"] * 2}, {"ends_at": content["starts_at"]}, {"starts_at": "2030-01-01T12:00:00"}]:
            with self.assertRaises(ValidationError):
                EngagementContent.model_validate({**content, **change})
        expired = {**content, "starts_at": (utc_now()-timedelta(days=2)).isoformat(), "ends_at": (utc_now()-timedelta(days=1)).isoformat()}
        self.decide(self.create(expired), "submit", 422)

    def test_project_boundary_and_invalid_ids(self):
        row = self.create()
        wrong = "/api/security/projects/" + str(uuid4()) + "/engagements/" + row["id"]
        self.assertEqual(self.client.get(wrong, headers=self.headers).status_code, 404)
        self.assertEqual(self.client.post(wrong + "/decisions", headers=self.headers, json={"expected_revision": 1, "action": "submit", "actor_label": "test"}).status_code, 404)
        self.assertEqual(self.client.get("/api/security/projects/not-a-uuid/engagements", headers=self.headers).status_code, 422)

    def test_draft_edit_and_stale_update(self):
        row = self.create()
        body = {"content": {**complete_content(), "name": "Edited"}, "expected_revision": row["revision"]}
        url = self.base + "/" + row["id"]
        first = self.client.post(url, headers=self.headers, json=body)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["revision"], 2)
        self.assertEqual(self.client.post(url, headers=self.headers, json=body).status_code, 409)
        self.assertEqual(len(first.json()["versions"]), 1)

    def test_review_immutable_snapshot_and_approval(self):
        row = self.create()
        self.decide(row, "approve", 409)
        pending = self.decide(row, "submit")
        edit = self.client.post(self.base + "/" + row["id"], headers=self.headers, json={"content": complete_content(), "expected_revision": pending["revision"]})
        self.assertEqual(edit.status_code, 409)
        self.decide(pending, "approve", 422, acknowledge=False)
        self.decide(pending, "approve", 422, note="")
        approved = self.decide(pending, "approve")
        head = approved["versions"][0]
        self.assertEqual(head["effective_status"], "approved")
        self.assertEqual(head["content_hash"], pending["versions"][0]["content_hash"])
        encoded = json.dumps(head["content"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), head["content_hash"])
        self.assertFalse(approved["execution_enabled"])
        self.assertEqual(approved["approval_mode"], "local_attestation")

    def test_revision_invalidates_approval_preserving_history(self):
        approved = self.decide(self.decide(self.create(), "submit"), "approve")
        old = copy.deepcopy(approved["versions"][0])
        revised = self.decide(approved, "revise")
        self.assertEqual(revised["versions"][0]["version"], 2)
        self.assertEqual(revised["versions"][0]["status"], "draft")
        self.assertIsNone(revised["versions"][0]["reviewer"])
        self.assertEqual(revised["versions"][1]["status"], "revoked")
        self.assertEqual(revised["versions"][1]["content"], old["content"])
        self.assertEqual(revised["versions"][1]["content_hash"], old["content_hash"])
        self.decide(approved, "revoke", 409)

    def test_expiry_is_effective_and_blocks_approval(self):
        pending = self.decide(self.create(), "submit")
        future = utc_now() + timedelta(days=3)
        with patch.object(engagements, "utc_now", return_value=future):
            row = self.client.get(self.base + "/" + pending["id"], headers=self.headers).json()
            self.assertEqual(row["versions"][0]["effective_status"], "expired")
            self.assertEqual(row["revision"], pending["revision"])
            self.decide(pending, "approve", 409)

    def test_rejection_revocation_and_new_review_required(self):
        pending = self.decide(self.create(), "submit")
        returned = self.decide(pending, "request_changes")
        self.assertEqual(returned["versions"][0]["status"], "revoked")
        revised = self.decide(returned, "revise")
        self.decide(revised, "approve", 409)
        self.decide(revised, "revise", 409)
        self.decide(revised, "revoke", 422, note="")
        revoked = self.decide(revised, "revoke")
        self.decide(revoked, "revoke", 409)

    def test_durable_storage_and_project_retention(self):
        row = self.create()
        reopened = EngagementStore(self.data)
        self.assertEqual(reopened.detail(self.project, row["id"])["versions"][0]["content"]["name"], "UAT review")
        other = str(uuid4())
        retention = self.client.post("/api/security/project-retention", headers=self.headers, json={"project_ids": [self.project, other]}).json()
        self.assertEqual(retention["protected_project_ids"], [self.project])
        listing = self.client.get(self.base, headers=self.headers).json()
        self.assertEqual(len(listing["items"]), 1)
        self.assertEqual(listing["items"][0]["events"], [])

    def test_concurrent_decisions_are_serialized(self):
        row = self.decide(self.create(), "submit")
        store = EngagementStore(self.data)
        def attempt():
            try:
                store.decide(self.project, row["id"], Decision(expected_revision=row["revision"], action="approve", actor_label="local", note="review", acknowledge=True))
                return 200
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sorted(results), [200, 409])
        self.assertEqual(sum(e["action"] == "approve" for e in store.detail(self.project, row["id"])["events"]), 1)

    def test_execution_remains_locked_after_approval(self):
        self.decide(self.decide(self.create(), "submit"), "approve")
        with patch("main.assess") as assess, patch("pentest.scan") as scan:
            response = self.client.post("/api/pentest/run", headers=self.headers, json={"target_id": "builtin-lab"})
            self.assertEqual(response.status_code, 423)
            assess.assert_not_called()
            scan.assert_not_called()
        self.assertFalse(self.client.get("/api/security/capabilities", headers=self.headers).json()["execution_enabled"])
        self.assertFalse(self.client.get("/api/pentest/capabilities", headers=self.headers).json()["execution_enabled"])


if __name__ == "__main__":
    unittest.main()
