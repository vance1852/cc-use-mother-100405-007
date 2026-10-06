"""运行基础服务与研究参与者权益域的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .participant_service import ParticipantService
from .service import DomainService
from .storage import Database

BASIC = "basic_research"
AI = "ai_analysis"


def _build_biobank_scenario(service: DomainService, participants: ParticipantService) -> dict[str, object]:
    """覆盖身份映射、时点同意、原子预留、最小披露与撤回级联的完整场景。"""

    service.register_site(request_id="req-site-b", actor_id="operator-001", site_id="site-002",
                          organization_id="org-001", name="二号中心", timezone_name="Asia/Shanghai")
    service.register_actor(request_id="req-ethics", actor_id="admin-001", new_actor_id="ethics-001",
                           display_name="联盟伦理委员", role="reviewer", organization_id="org-001")
    service.register_actor(request_id="req-researcher", actor_id="admin-001", new_actor_id="researcher-001",
                           display_name="合作研究员", role="researcher", organization_id="org-001")

    # 同一受试者被两个中心以不同编号纳入。
    first = participants.link_subject_code(request_id="req-link-a", actor_id="operator-001",
                                           site_id="site-001", local_code="A-001")
    participant_id = first.resource_id
    second = participants.link_subject_code(request_id="req-link-b", actor_id="operator-001",
                                            site_id="site-002", local_code="B-999",
                                            participant_id=participant_id)
    assert second.resource_id == participant_id

    # 早期同意只含基础研究。
    participants.record_consent(request_id="req-consent-v1", actor_id="operator-001",
                                participant_id=participant_id, version_tag="consent-2025",
                                purposes=[BASIC], document_hash="hash-consent-2025",
                                signed_at="2025-06-01T00:00:00Z")
    participants.register_protocol(request_id="req-protocol", actor_id="ethics-001",
                                   protocol_id="protocol-001", title="重大疾病队列研究",
                                   owner_organization_id="org-001", purposes=[BASIC, AI])
    participants.record_irb_approval(request_id="req-irb", actor_id="ethics-001",
                                     approval_id="irb-001", protocol_id="protocol-001",
                                     purposes=[BASIC], valid_from="2026-01-01T00:00:00Z",
                                     valid_to="2027-01-01T00:00:00Z")
    participants.register_sample(request_id="req-sample", actor_id="operator-001",
                                 sample_id="sample-001", participant_id=participant_id,
                                 site_id="site-001", material_type="blood",
                                 quantity=8.0, unit="mL", collected_at="2026-02-01T00:00:00Z")
    participants.split_sample(request_id="req-split", actor_id="operator-001",
                              parent_sample_id="sample-001", child_sample_id="sample-001-a",
                              quantity=3.0)
    participants.register_dataset(request_id="req-dataset", actor_id="operator-001",
                                  dataset_id="dataset-001", title="队列基线数据集")
    participants.add_dataset_participant(request_id="req-dataset-member",
                                         actor_id="operator-001", dataset_id="dataset-001",
                                         participant_id=participant_id)

    # AI 分析超出当时同意与伦理许可，被原子阻断。
    participants.submit_application(request_id="req-app-ai", actor_id="researcher-001",
                                    application_id="app-ai", protocol_id="protocol-001",
                                    purpose=AI, items=[{"sample_id": "sample-001", "quantity": 2.0}],
                                    dataset_id="dataset-001")
    ai_decision = participants.decide_application(actor_id="ethics-001",
                                                  application_id="app-ai")
    assert ai_decision["decision"] == "denied"

    # 基础研究申请在当时有效的同意与许可下获准并原子预留。
    participants.submit_application(request_id="req-app-basic", actor_id="researcher-001",
                                    application_id="app-basic", protocol_id="protocol-001",
                                    purpose=BASIC, items=[{"sample_id": "sample-001", "quantity": 2.0}],
                                    dataset_id="dataset-001")
    basic_decision = participants.decide_application(actor_id="ethics-001",
                                                     application_id="app-basic")
    assert basic_decision["decision"] == "approved"
    participants.record_consumption(actor_id="operator-001", application_id="app-basic",
                                    items=[{"sample_id": "sample-001", "quantity": 1.0}])
    release = participants.release_application(actor_id="operator-001",
                                               application_id="app-basic")
    release_text = json.dumps(release, ensure_ascii=False)
    assert participant_id not in release_text
    assert "sample-001" not in release_text
    participants.record_output(request_id="req-output", actor_id="operator-001",
                               application_id="app-basic", kind="paper",
                               title="队列基线结果", citation="J Med 2026;1:1",
                               published_at="2026-09-01T00:00:00Z")

    # 参与者撤回：未消耗预留退回、已发放数据生义务、既有论文保留授权依据。
    withdrawal = participants.withdraw_participant(request_id="req-withdraw",
                                                   actor_id="operator-001",
                                                   participant_id=participant_id)
    impact = participants.withdrawal_impact(actor_id="ethics-001",
                                            withdrawal_id=withdrawal.resource_id)
    conservation = participants.sample_conservation(actor_id="operator-001")

    return {
        "duplicate_centers_unified": second.resource_id == participant_id,
        "ai_blocked_without_consent": ai_decision["decision"] == "denied",
        "basic_approved": basic_decision["decision"] == "approved",
        "basis_hash_preserved": len(basic_decision["basis_hash"]) == 64,
        "release_uses_pseudonym": release["manifest"]["entries"][0]["pseudonym"].startswith("P-"),
        "withdrawal_obligations": len(impact["open_obligations"]),
        "prior_output_retained": len(impact["retained_prior_use"]) == 1
        and len(impact["retained_prior_use"][0]["outputs"]) == 1,
        "conservation_balanced": conservation["balanced"],
    }


def run() -> dict[str, object]:
    """执行一条完整登记链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = DomainService(database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
        participants = ParticipantService(
            database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})
        biobank = _build_biobank_scenario(service, participants)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed, "biobank": biobank}
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    biobank = result["biobank"]
    biobank_ok = all(value is True or (isinstance(value, int) and value >= 0)
                     for value in biobank.values())
    return 0 if result["status"] == "ok" and result["audit_valid"] and biobank_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
