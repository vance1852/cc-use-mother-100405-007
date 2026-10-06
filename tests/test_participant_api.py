"""研究参与者权益域的 HTTP/JSON 边界测试。"""

import json
import unittest

from science_strategy_foundation.api import route
from science_strategy_foundation.participant_service import ParticipantService
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database

from tests.biobank_fixture import BioBankFixture

BASIC = "basic_research"
AI = "ai_analysis"


class ParticipantApiTest(unittest.TestCase):
    def setUp(self):
        self.ctx = BioBankFixture()
        self.db = self.ctx.database
        self.svc = self.ctx.service
        self.ps = self.ctx.participants

    def tearDown(self):
        self.ctx.close()

    def call(self, method, path, body=None, actor="op1"):
        return route(self.svc, method, path, body or {},
                     {"X-Actor-Id": actor}, participant_service=self.ps)

    def prepare(self):
        self.call("POST", "/subject-links",
                  {"request_id": "link-a", "site_id": "siteA", "local_code": "A-001"})
        participant_id = self.db.connection.execute(
            "SELECT participant_id FROM subject_links WHERE site_id='siteA'").fetchone()["participant_id"]
        self.call("POST", "/consents", {"request_id": "c1", "participant_id": participant_id,
                                        "version_tag": "v1", "purposes": [BASIC],
                                        "document_hash": "h", "signed_at": "2026-01-01T00:00:00Z"})
        self.call("POST", "/protocols", {"request_id": "p1", "protocol_id": "proto1",
                                         "title": "队列", "owner_organization_id": "o1",
                                         "purposes": [BASIC, AI]}, actor="rev1")
        self.call("POST", "/irb-approvals",
                  {"request_id": "i1", "approval_id": "irb1", "protocol_id": "proto1",
                   "purposes": [BASIC], "valid_from": "2026-01-01T00:00:00Z",
                   "valid_to": "2027-01-01T00:00:00Z"}, actor="rev1")
        self.call("POST", "/samples", {"request_id": "s1", "sample_id": "s1",
                                       "participant_id": participant_id, "site_id": "siteA",
                                       "material_type": "blood", "quantity": 6.0})
        self.call("POST", "/datasets", {"request_id": "d1", "dataset_id": "d1", "title": "数据集"})
        self.call("POST", "/dataset-participants",
                  {"request_id": "dp1", "dataset_id": "d1", "participant_id": participant_id})
        return participant_id

    def test_full_decision_explanation_release_conservation_chain(self):
        participant_id = self.prepare()
        status, body = self.call("POST", "/access-applications",
                                 {"request_id": "a1", "application_id": "app1",
                                  "protocol_id": "proto1", "purpose": BASIC,
                                  "items": [{"sample_id": "s1", "quantity": 2.0}],
                                  "dataset_id": "d1"}, actor="res1")
        self.assertEqual(201, status)

        status, body = self.call("POST", "/access-applications/app1/decide",
                                 {"decision": "approve"}, actor="rev1")
        self.assertEqual(200, status)
        self.assertEqual("approved", body["decision"])
        self.assertTrue(body["basis_hash"])

        status, body = self.call("GET", "/access-applications/app1/explanation", actor="rev1")
        self.assertEqual(200, status)
        self.assertEqual("approved", body["status"])
        self.assertFalse(body["prospective"])
        self.assertEqual(BASIC, body["basis"]["purpose"])
        self.assertIn(participant_id, body["basis"]["consents"])

        status, body = self.call("POST", "/access-applications/app1/release", actor="rev1")
        self.assertEqual(200, status)
        text = json.dumps(body, ensure_ascii=False)
        self.assertNotIn(participant_id, text)
        self.assertNotIn('"s1"', text)
        entry = body["manifest"]["entries"][0]
        self.assertTrue(entry["pseudonym"].startswith("P-"))

        status, body = self.call("GET", "/sample-conservation", actor="op1")
        self.assertEqual(200, status)
        self.assertTrue(body["balanced"])

    def test_ai_request_denied_with_explicit_checks(self):
        self.prepare()
        self.call("POST", "/access-applications",
                  {"request_id": "a1", "application_id": "app-ai", "protocol_id": "proto1",
                   "purpose": AI, "items": [{"sample_id": "s1", "quantity": 1.0}],
                   "dataset_id": "d1"}, actor="res1")
        status, body = self.call("POST", "/access-applications/app-ai/decide",
                                 {"decision": "approve"}, actor="rev1")
        self.assertEqual(200, status)
        self.assertEqual("denied", body["decision"])
        failed = {c["code"] for c in body["checks"] if not c["passed"]}
        self.assertIn("consent_covers_purpose", failed)

    def test_withdraw_impact_endpoint_lists_pending_and_obligations(self):
        participant_id = self.prepare()
        self.call("POST", "/access-applications",
                  {"request_id": "a1", "application_id": "app1", "protocol_id": "proto1",
                   "purpose": BASIC, "items": [{"sample_id": "s1", "quantity": 1.0}],
                   "dataset_id": "d1"}, actor="res1")
        self.call("POST", "/access-applications/app1/decide", {}, actor="rev1")
        self.call("POST", "/access-applications/app1/release", actor="rev1")
        self.call("POST", "/access-applications",
                  {"request_id": "a2", "application_id": "app2", "protocol_id": "proto1",
                   "purpose": BASIC, "items": [{"sample_id": "s1", "quantity": 1.0}],
                   "dataset_id": "d1"}, actor="res2")
        status, body = self.call("POST", "/withdrawals",
                                 {"request_id": "w1", "participant_id": participant_id})
        self.assertEqual(201, status)
        withdrawal_id = body["resource_id"]
        status, impact = self.call("GET", f"/withdrawals/{withdrawal_id}/impact", actor="rev1")
        self.assertEqual(200, status)
        self.assertEqual(["app2"], [a["application_id"] for a in impact["pending_applications"]])
        self.assertEqual(2, len(impact["open_obligations"]))
        self.assertEqual("closed", self.db.connection.execute(
            "SELECT status FROM access_applications WHERE application_id='app1'").fetchone()["status"])

    def test_researcher_cannot_reach_reviewer_endpoint(self):
        self.prepare()
        status, body = self.call("GET", "/sample-conservation", actor="res1")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", body["error"])

    def test_split_and_conservation_endpoint(self):
        self.prepare()
        status, body = self.call("POST", "/sample-splits",
                                 {"request_id": "sp1", "parent_sample_id": "s1",
                                  "child_sample_id": "s1a", "quantity": 2.0})
        self.assertEqual(201, status)
        status, body = self.call("GET", "/samples/s1", actor="op1")
        self.assertEqual(200, status)
        self.assertEqual(4.0, body["quantity_available"])


if __name__ == "__main__":
    unittest.main()
