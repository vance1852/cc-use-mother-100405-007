"""参与者权益与样本使用域的端到端业务规则测试。"""

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from science_strategy_foundation.errors import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    RuleViolation,
    ValidationError,
)
from science_strategy_foundation.clock import FixedClock
from science_strategy_foundation.participant_service import ParticipantService
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database

from tests.biobank_fixture import BioBankFixture

BASIC = "basic_research"
AI = "ai_analysis"
AT = "2026-10-01T00:00:00Z"


class ParticipantDomainTest(unittest.TestCase):
    def setUp(self):
        self.ctx = BioBankFixture()
        self.ps = self.ctx.participants
        self.svc = self.ctx.service
        self.db = self.ctx.database

    def tearDown(self):
        self.ctx.close()

    # ------------------------------------------------------------- 辅助建档

    def enroll_duplicate_subject(self):
        """模拟同一受试者被两个中心以不同编号纳入，返回规范参与者。"""

        first = self.ps.link_subject_code(request_id="link-a", actor_id="op1",
                                          site_id="siteA", local_code="A-001")
        participant_id = first.resource_id
        second = self.ps.link_subject_code(request_id="link-b", actor_id="op2",
                                           site_id="siteB", local_code="B-999",
                                           participant_id=participant_id)
        # 新中心编号是首次登记，但必须挂到同一个参与者，而不是新建第二人。
        self.assertEqual(participant_id, second.resource_id)
        return participant_id

    def prepare_study(self, participant_id, *, consent_purposes=(BASIC,),
                      irb_purposes=(BASIC,), irb_site=None, sample_id="s1",
                      site_id="siteA", quantity=10.0, dataset_id="d1"):
        self.ps.record_consent(request_id=f"consent-{sample_id}", actor_id="op1",
                               participant_id=participant_id, version_tag="v1",
                               purposes=list(consent_purposes), document_hash="doc-v1",
                               signed_at="2026-01-01T00:00:00Z")
        self.ps.register_protocol(request_id="proto-1", actor_id="rev1", protocol_id="proto1",
                                  title="重大疾病队列", owner_organization_id="o1",
                                  purposes=[BASIC, AI])
        self.ps.record_irb_approval(request_id="irb-1", actor_id="rev1", approval_id="irb1",
                                    protocol_id="proto1", purposes=list(irb_purposes),
                                    site_id=irb_site, valid_from="2026-01-01T00:00:00Z",
                                    valid_to="2027-01-01T00:00:00Z")
        self.ps.register_sample(request_id=f"sample-{sample_id}", actor_id="op1"
                                if site_id == "siteA" else "op2", sample_id=sample_id,
                                participant_id=participant_id, site_id=site_id,
                                material_type="blood", quantity=quantity, unit="mL",
                                collected_at="2026-01-05T00:00:00Z")
        self.ps.register_dataset(request_id="dataset-1", actor_id="op1", dataset_id=dataset_id,
                                 title="队列数据集")
        self.ps.add_dataset_participant(request_id="dp-1", actor_id="op1",
                                        dataset_id=dataset_id, participant_id=participant_id)

    def submit_and_decide(self, application_id, purpose, items, *, decision="approve",
                          dataset_id="d1", researcher="res1"):
        self.ps.submit_application(request_id=f"req-{application_id}", actor_id=researcher,
                                   application_id=application_id, protocol_id="proto1",
                                   purpose=purpose, items=items, dataset_id=dataset_id)
        return self.ps.decide_application(actor_id="rev1", application_id=application_id,
                                          decision=decision)

    # --------------------------------------------------------------- 身份映射

    def test_same_local_code_is_idempotent_and_never_creates_second_person(self):
        first = self.ps.link_subject_code(request_id="link-a", actor_id="op1",
                                          site_id="siteA", local_code="A-001")
        repeat = self.ps.link_subject_code(request_id="link-a", actor_id="op1",
                                           site_id="siteA", local_code="A-001")
        self.assertTrue(repeat.replayed)
        self.assertEqual(first.resource_id, repeat.resource_id)
        self.assertEqual(1, self.db.connection.execute(
            "SELECT COUNT(*) AS c FROM participants").fetchone()["c"])

    def test_local_code_is_not_stored_in_plaintext(self):
        self.ps.link_subject_code(request_id="link-a", actor_id="op1",
                                  site_id="siteA", local_code="A-001")
        rows = self.db.connection.execute("SELECT site_id, code_hash FROM subject_links").fetchall()
        self.assertEqual(1, len(rows))
        self.assertNotIn("A-001", rows[0]["code_hash"])
        self.assertEqual(64, len(rows[0]["code_hash"]))

    def test_participant_merge_migrates_samples_consents_and_links(self):
        first = self.ps.link_subject_code(request_id="link-a", actor_id="op1",
                                          site_id="siteA", local_code="A-001")
        other = self.ps.link_subject_code(request_id="link-b", actor_id="op2",
                                          site_id="siteB", local_code="B-999")
        canonical = first.resource_id
        duplicate = other.resource_id
        self.ps.record_consent(request_id="consent-dup", actor_id="op2",
                               participant_id=duplicate, version_tag="v1",
                               purposes=[BASIC], document_hash="d")
        self.ps.register_sample(request_id="sample-dup", actor_id="op2", sample_id="sd",
                                participant_id=duplicate, site_id="siteB",
                                material_type="blood", quantity=3.0)
        self.ps.merge_participants(request_id="merge-1", actor_id="rev1",
                                   canonical_participant_id=canonical,
                                   duplicate_participant_id=duplicate)
        # 样本、链接、同意都归并到规范身份。
        owner = self.db.connection.execute(
            "SELECT participant_id FROM samples WHERE sample_id='sd'").fetchone()["participant_id"]
        self.assertEqual(canonical, owner)
        link_owner = self.db.connection.execute(
            "SELECT participant_id FROM subject_links WHERE site_id='siteB'").fetchone()["participant_id"]
        self.assertEqual(canonical, link_owner)
        consent_owner = self.db.connection.execute(
            "SELECT participant_id FROM consents").fetchone()["participant_id"]
        self.assertEqual(canonical, consent_owner)
        # 重复身份被标记合并，后续引用自动解析到规范身份。
        resolved = self.ps._canonical(self.db.connection, duplicate)
        self.assertEqual(canonical, resolved)

    # ------------------------------------------------------- 同意版本与用途

    def test_ai_purpose_blocked_when_consent_only_covers_basic(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        result = self.submit_and_decide("app-ai", AI, [{"sample_id": "s1", "quantity": 2.0}])
        self.assertEqual("denied", result["decision"])
        failed = {c["code"] for c in result["checks"] if not c["passed"]}
        self.assertIn("consent_covers_purpose", failed)
        self.assertIn("irb_approval_valid", failed)
        # 阻断时没有任何预留发生。
        self.assertEqual(0.0, self.db.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) AS q FROM reservations").fetchone()["q"])

    def test_reconsent_only_affects_future_applications(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        denied_ai = self.submit_and_decide("app-ai-old", AI,
                                           [{"sample_id": "s1", "quantity": 1.0}])
        self.assertEqual("denied", denied_ai["decision"])
        # 补签：新版本包含 AI 分析，伦理许可同步扩展。
        self.ps.record_consent(request_id="consent-v2", actor_id="op1",
                               participant_id=participant_id, version_tag="v2",
                               purposes=[BASIC, AI], document_hash="doc-v2")
        self.ps.record_irb_approval(request_id="irb-2", actor_id="rev1", approval_id="irb2",
                                    protocol_id="proto1", purposes=[BASIC, AI],
                                    valid_from="2026-10-01T00:00:00Z",
                                    valid_to="2027-10-01T00:00:00Z")
        approved_ai = self.submit_and_decide("app-ai-new", AI,
                                             [{"sample_id": "s1", "quantity": 1.0}])
        self.assertEqual("approved", approved_ai["decision"])
        # 旧决定不被追溯改写。
        old = self.db.connection.execute(
            "SELECT status FROM access_applications WHERE application_id='app-ai-old'"
        ).fetchone()["status"]
        self.assertEqual("denied", old)

    def test_narrowing_consent_does_not_retract_prior_approval(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        approved = self.submit_and_decide("app-basic", BASIC,
                                          [{"sample_id": "s1", "quantity": 2.0}])
        self.assertEqual("approved", approved["decision"])
        basis_hash = approved["basis_hash"]
        # 新版本同意收窄到只剩 AI，基础研究不再被覆盖。
        self.ps.record_consent(request_id="consent-v2", actor_id="op1",
                               participant_id=participant_id, version_tag="v2",
                               purposes=[AI], document_hash="doc-v2")
        explanation = self.ps.explain_application(actor_id="rev1",
                                                  application_id="app-basic")
        self.assertEqual("approved", explanation["status"])
        self.assertEqual(basis_hash, explanation["basis"]["basis_hash"])
        self.assertEqual(["basic_research"],
                         list(explanation["basis"]["consents"].values())[0]["purposes"])
        # 新的基础研究申请会被阻断。
        later = self.submit_and_decide("app-basic-2", BASIC,
                                       [{"sample_id": "s1", "quantity": 1.0}])
        self.assertEqual("denied", later["decision"])

    def test_expired_and_site_scoped_irb_approvals(self):
        participant_id = self.enroll_duplicate_subject()
        # 同意覆盖，但伦理许可只在 2025 年有效。
        self.prepare_study(participant_id, irb_purposes=(BASIC,))
        self.db.connection.execute(
            "UPDATE irb_approvals SET valid_from='2025-01-01T00:00:00Z',"
            "valid_to='2025-12-31T00:00:00Z' WHERE approval_id='irb1'")
        result = self.submit_and_decide("app-expired", BASIC,
                                        [{"sample_id": "s1", "quantity": 1.0}])
        self.assertEqual("denied", result["decision"])
        self.assertIn("irb_approval_valid",
                      {c["code"] for c in result["checks"] if not c["passed"]})
        # 中心专属许可不覆盖另一中心样本。
        self.db.connection.execute(
            "UPDATE irb_approvals SET valid_from='2026-01-01T00:00:00Z',"
            "valid_to='2027-01-01T00:00:00Z', site_id='siteB' WHERE approval_id='irb1'")
        result = self.submit_and_decide("app-other-site", BASIC,
                                        [{"sample_id": "s1", "quantity": 1.0}])
        self.assertEqual("denied", result["decision"])
        self.assertIn("irb_approval_valid",
                      {c["code"] for c in result["checks"] if not c["passed"]})

    # ----------------------------------------------------- 预留、去重与并发

    def test_duplicate_application_fingerprint_is_rejected(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1", "quantity": 2.0}])
        with self.assertRaises(ConflictError):
            self.submit_and_decide("app2", BASIC, [{"sample_id": "s1", "quantity": 2.0}])

    def test_overlapping_applications_cannot_oversell_stock(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=5.0)
        self.ps.register_sample(request_id="sample-s2", actor_id="op1", sample_id="s2",
                                participant_id=participant_id, site_id="siteA",
                                material_type="blood", quantity=5.0)
        # 两份申请都要拿走 s1 的 4.0；用不同的附加项区分申请指纹。
        first = self.submit_and_decide("app-big-1", BASIC,
                                       [{"sample_id": "s1", "quantity": 4.0}])
        second = self.submit_and_decide("app-big-2", BASIC,
                                        [{"sample_id": "s1", "quantity": 4.0},
                                         {"sample_id": "s2", "quantity": 1.0}],
                                        researcher="res2")
        self.assertEqual("approved", first["decision"])
        self.assertEqual("denied", second["decision"])
        failed = [c for c in second["checks"]
                  if not c["passed"] and c["code"] == "sample_available"]
        self.assertEqual(1, len(failed))
        self.assertAlmostEqual(1.0, failed[0]["detail"]["available"])
        sample = self.ps.get_sample(actor_id="op1", sample_id="s1")
        self.assertEqual(4.0, sample["quantity_reserved"])
        self.assertEqual(1.0, sample["quantity_available"])

    def test_concurrent_approvals_never_double_allocate(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=3.0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "concurrency.sqlite3"
            results: list[str] = []

            def worker(application_id: str) -> None:
                database = Database(path)
                service = ParticipantService(
                    database, FixedClock(datetime(2026, 10, 1, tzinfo=timezone.utc)))
                try:
                    decision = service.decide_application(
                        actor_id="rev1", application_id=application_id)
                    results.append(decision["decision"])
                finally:
                    database.close()

            # 两个互斥申请，各要全部余量。
            self.ps.submit_application(request_id="req-c1", actor_id="res1",
                                       application_id="app-c1", protocol_id="proto1",
                                       purpose=BASIC, items=[{"sample_id": "s1", "quantity": 3.0}],
                                       dataset_id="d1")
            self.ps.submit_application(request_id="req-c2", actor_id="res2",
                                       application_id="app-c2", protocol_id="proto1",
                                       purpose=BASIC, items=[{"sample_id": "s1", "quantity": 3.0}],
                                       dataset_id="d1")
            # 把含两个待审批申请的内存库备份到文件库，供两个线程各自打开连接竞争。
            target = Database(path)
            self.db.connection.backup(target.connection)
            target.close()

            threads = [threading.Thread(target=worker, args=("app-c1",)),
                       threading.Thread(target=worker, args=("app-c2",))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(results), ["approved", "denied"])
            verifier = Database(path)
            reserved = verifier.connection.execute(
                "SELECT quantity_reserved, quantity_total, quantity_consumed FROM samples "
                "WHERE sample_id='s1'").fetchone()
            self.assertEqual(3.0, reserved["quantity_reserved"])
            self.assertEqual(3.0, reserved["quantity_total"])
            self.assertEqual(0.0, reserved["quantity_consumed"])
            verifier.close()

    def test_approval_cannot_be_decided_twice(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1", "quantity": 2.0}])
        with self.assertRaises(ConflictError):
            self.ps.decide_application(actor_id="rev1", application_id="app1")

    # --------------------------------------------------- 消耗、分装与守恒

    def test_partial_consumption_and_close_returns_remaining(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=5.0)
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1", "quantity": 4.0}])
        self.ps.record_consumption(actor_id="op1", application_id="app1",
                                   items=[{"sample_id": "s1", "quantity": 1.5}])
        sample = self.ps.get_sample(actor_id="op1", sample_id="s1")
        self.assertEqual(2.5, sample["quantity_reserved"])
        self.assertEqual(1.5, sample["quantity_consumed"])
        self.assertEqual(1.0, sample["quantity_available"])
        # 不能超额消耗。
        with self.assertRaises(RuleViolation):
            self.ps.record_consumption(actor_id="op1", application_id="app1",
                                       items=[{"sample_id": "s1", "quantity": 9.0}])
        closed = self.ps.close_application(actor_id="op1", application_id="app1")
        returned = sum(item["quantity"] for item in closed["released"])
        self.assertAlmostEqual(2.5, returned)
        sample = self.ps.get_sample(actor_id="op1", sample_id="s1")
        self.assertEqual(0.0, sample["quantity_reserved"])
        self.assertEqual(3.5, sample["quantity_available"])
        report = self.ps.sample_conservation(actor_id="op1", sample_id="s1")
        self.assertTrue(report["balanced"])

    def test_split_preserves_family_total(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=10.0)
        self.ps.split_sample(request_id="split-1", actor_id="op1", parent_sample_id="s1",
                             child_sample_id="s1a", quantity=4.0)
        self.ps.split_sample(request_id="split-2", actor_id="op1", parent_sample_id="s1",
                             child_sample_id="s1b", quantity=3.0)
        report = self.ps.sample_conservation(actor_id="op1")
        self.assertTrue(report["balanced"])
        totals = {item["sample_id"]: item for item in report["samples"]}
        self.assertEqual(3.0, totals["s1"]["total"])
        self.assertEqual(4.0, totals["s1a"]["total"])
        self.assertEqual(3.0, totals["s1b"]["total"])
        # 不能从已预留余量中再分装。
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1a", "quantity": 4.0}])
        with self.assertRaises(RuleViolation):
            self.ps.split_sample(request_id="split-3", actor_id="op1",
                                 parent_sample_id="s1a", child_sample_id="s1a1", quantity=1.0)

    # ------------------------------------------------------------- 撤回级联

    def test_withdraw_releases_future_holds_but_keeps_prior_analysis(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=5.0)
        self.submit_and_decide("app-done", BASIC, [{"sample_id": "s1", "quantity": 2.0}])
        self.ps.record_consumption(actor_id="op1", application_id="app-done",
                                   items=[{"sample_id": "s1", "quantity": 2.0}])
        release = self.ps.release_application(actor_id="rev1", application_id="app-done")
        self.ps.record_output(request_id="output-1", actor_id="rev1",
                              application_id="app-done", kind="paper", title="基线分析",
                              citation="J 2026;1:1", published_at="2026-10-02T00:00:00Z")
        # 第二份批准（不同样本）尚未消耗。
        self.ps.register_sample(request_id="sample-s2", actor_id="op1", sample_id="s2",
                                participant_id=participant_id, site_id="siteA",
                                material_type="blood", quantity=4.0)
        self.submit_and_decide("app-open", BASIC, [{"sample_id": "s2", "quantity": 2.0}])
        # 还有一个待审批申请会被撤回波及。
        self.ps.submit_application(request_id="req-pending", actor_id="res1",
                                   application_id="app-pending", protocol_id="proto1",
                                   purpose=BASIC, items=[{"sample_id": "s2", "quantity": 1.0}],
                                   dataset_id="d1")

        receipt = self.ps.withdraw_participant(request_id="wd-1", actor_id="op1",
                                               participant_id=participant_id)
        impact = self.ps.withdrawal_impact(actor_id="rev1",
                                           withdrawal_id=receipt.resource_id)
        pending_ids = {item["application_id"] for item in impact["pending_applications"]}
        self.assertIn("app-pending", pending_ids)
        open_app = self.db.connection.execute(
            "SELECT status FROM access_applications WHERE application_id='app-open'"
        ).fetchone()["status"]
        self.assertEqual("closed", open_app)
        # 已发放数据产生销毁/停用义务。
        kinds = {o["kind"] for o in impact["open_obligations"]}
        self.assertEqual({"destroy_data", "cease_use"}, kinds)
        # 既有分析与论文保留授权依据。
        self.assertEqual(1, len(impact["retained_prior_use"]))
        retained = impact["retained_prior_use"][0]
        self.assertEqual("app-done", retained["application_id"])
        self.assertEqual(1, len(retained["outputs"]))
        self.assertTrue(retained["basis_hash"])
        # 已消耗样本不退回，未消耗预留退回样本池。
        sample = self.ps.get_sample(actor_id="op1", sample_id="s1")
        self.assertEqual(0.0, sample["quantity_reserved"])
        self.assertEqual(2.0, sample["quantity_consumed"])
        self.assertEqual(3.0, sample["quantity_available"])
        # 撤回后待审批申请被阻断。
        decision = self.ps.decide_application(actor_id="rev1",
                                              application_id="app-pending")
        self.assertEqual("denied", decision["decision"])
        self.assertIn("not_withdrawn",
                      {c["code"] for c in decision["checks"] if not c["passed"]})
        # 发放载荷哈希与本次撤回无关，保持可审计。
        self.assertTrue(release["payload_hash"])

    def test_purpose_scoped_withdraw_leaves_other_purpose_intact(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, consent_purposes=(BASIC, AI),
                           irb_purposes=(BASIC, AI), quantity=8.0)
        self.submit_and_decide("app-basic", BASIC, [{"sample_id": "s1", "quantity": 2.0}])
        self.submit_and_decide("app-ai", AI, [{"sample_id": "s1", "quantity": 2.0}])
        self.ps.withdraw_participant(request_id="wd-ai", actor_id="op1",
                                     participant_id=participant_id, purposes=[AI])
        basic = self.db.connection.execute(
            "SELECT status FROM access_applications WHERE application_id='app-basic'"
        ).fetchone()["status"]
        ai = self.db.connection.execute(
            "SELECT status FROM access_applications WHERE application_id='app-ai'"
        ).fetchone()["status"]
        self.assertEqual("approved", basic)
        self.assertEqual("closed", ai)

    def test_obligation_can_be_discharged(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1", "quantity": 1.0}])
        self.ps.release_application(actor_id="rev1", application_id="app1")
        receipt = self.ps.withdraw_participant(request_id="wd-1", actor_id="op1",
                                               participant_id=participant_id)
        impact = self.ps.withdrawal_impact(actor_id="rev1",
                                           withdrawal_id=receipt.resource_id)
        obligation_ids = [o["obligation_id"] for o in impact["open_obligations"]]
        self.assertEqual(2, len(obligation_ids))
        for obligation_id in obligation_ids:
            discharged = self.ps.discharge_obligation(actor_id="rev1",
                                                      obligation_id=obligation_id)
            self.assertEqual("discharged", discharged["status"])
        impact = self.ps.withdrawal_impact(actor_id="rev1",
                                           withdrawal_id=receipt.resource_id)
        self.assertEqual(0, len(impact["open_obligations"]))
        self.assertEqual(2, len(impact["discharged_obligations"]))

    # ------------------------------------------------------------- 解释与权限

    def test_explain_lists_every_atomic_check(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        self.ps.submit_application(request_id="req-pending", actor_id="res1",
                                   application_id="app-pending", protocol_id="proto1",
                                   purpose=BASIC, items=[{"sample_id": "s1", "quantity": 1.0}],
                                   dataset_id="d1")
        explanation = self.ps.explain_application(actor_id="rev1",
                                                  application_id="app-pending")
        self.assertTrue(explanation["prospective"])
        codes = {c["code"] for c in explanation["checks"]}
        self.assertEqual({"protocol_active", "purpose_within_protocol", "dataset_membership",
                          "consent_covers_purpose", "not_withdrawn", "irb_approval_valid",
                          "sample_available"}, codes)
        self.assertTrue(explanation["passed"])

    def test_researcher_cannot_approve_or_view_explanation(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        self.ps.submit_application(request_id="req1", actor_id="res1",
                                   application_id="app1", protocol_id="proto1",
                                   purpose=BASIC, items=[{"sample_id": "s1", "quantity": 1.0}],
                                   dataset_id="d1")
        with self.assertRaises(PermissionDenied):
            self.ps.decide_application(actor_id="res1", application_id="app1")
        with self.assertRaises(PermissionDenied):
            self.ps.explain_application(actor_id="res1", application_id="app1")

    def test_auditor_can_read_conservation_and_audit(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id)
        report = self.ps.sample_conservation(actor_id="au1")
        self.assertTrue(report["balanced"])
        valid, count = self.svc.verify_audit()
        self.assertTrue(valid)
        self.assertGreater(count, 0)

    def test_dataset_membership_is_enforced(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, dataset_id="d1")
        # 第二数据集不包含该参与者。
        self.ps.register_dataset(request_id="dataset-2", actor_id="op1", dataset_id="d2",
                                 title="外部数据集")
        self.ps.submit_application(request_id="req-out", actor_id="res1",
                                   application_id="app-out", protocol_id="proto1",
                                   purpose=BASIC, items=[{"sample_id": "s1", "quantity": 1.0}],
                                   dataset_id="d2")
        decision = self.ps.decide_application(actor_id="rev1", application_id="app-out")
        self.assertEqual("denied", decision["decision"])
        self.assertIn("dataset_membership",
                      {c["code"] for c in decision["checks"] if not c["passed"]})

    def test_minimal_release_cannot_be_correlated_back(self):
        participant_id = self.enroll_duplicate_subject()
        self.prepare_study(participant_id, quantity=5.0)
        self.submit_and_decide("app1", BASIC, [{"sample_id": "s1", "quantity": 2.0}],
                               researcher="res1")
        self.submit_and_decide("app2", BASIC, [{"sample_id": "s1", "quantity": 1.0}],
                               researcher="res2")
        release1 = self.ps.release_application(actor_id="rev1", application_id="app1")
        release2 = self.ps.release_application(actor_id="rev1", application_id="app2")
        pseudo1 = release1["manifest"]["entries"][0]["pseudonym"]
        pseudo2 = release2["manifest"]["entries"][0]["pseudonym"]
        self.assertNotEqual(pseudo1, pseudo2)
        # 清单不含参与者主键、中心编号或内部样本编号。
        participant = self.db.connection.execute(
            "SELECT participant_id FROM subject_links WHERE site_id='siteA'").fetchone()["participant_id"]
        for release in (release1, release2):
            text = json.dumps(release, ensure_ascii=False)
            self.assertNotIn(participant, text)
            self.assertNotIn("s1", release["manifest"]["entries"][0]["aliquot_code"])
        # 重复发放被阻止。
        with self.assertRaises(ConflictError):
            self.ps.release_application(actor_id="rev1", application_id="app1")


if __name__ == "__main__":
    unittest.main()
