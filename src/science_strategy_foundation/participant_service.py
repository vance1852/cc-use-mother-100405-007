"""研究参与者权益与样本使用协作域。

把知情同意版本、研究方案、伦理许可、样本分装与余量、数据集、访问申请、
撤回通知和成果引用串到同一个参与者主键上，提供：

- 不可逆身份映射：中心编号只以加盐 HMAC 落库，研究化名按申请隔离；
- 时点授权：审批按“当时有效”的同意与伦理许可逐项判定并固化授权依据；
- 原子预留：审批事务内重算样本余量，重复申请与并发批准都不能二次发放；
- 前瞻效力：补签、用途变更、部分消耗、中心合并与撤回只影响尚未发生的
  使用，既有的预留、分析与论文保留当时的授权依据并生成处置义务；
- 可解释：伦理人员可通过 API 查看每次访问逐项判定与撤回波及范围，样本
  管理员可核对跨分装的数量守恒。
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, RuleViolation, ValidationError
from .models import WriteReceipt
from .privacy import generate_pepper, release_fingerprint, research_pseudonym, subject_code_hash
from .storage import Database

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")

BIOBANK_ROLES = frozenset({"admin", "operator"})
ETHICS_ROLES = frozenset({"admin", "reviewer"})
STAFF_ROLES = frozenset({"admin", "operator", "reviewer"})
RESEARCH_ROLES = frozenset({"admin", "researcher"})

_EPS = 1e-9


class ParticipantService:
    """实现参与者权益与样本使用的全部业务规则。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------ 基础

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 300) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _timestamp(self, value: str | None, field: str) -> str:
        if value is None:
            return self._now()
        value = str(value).strip()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", value):
            raise ValidationError(f"{field} 必须是 UTC ISO-8601 时间")
        return value.replace("+00:00", "Z") if value.endswith("+00:00") else value

    def _purposes(self, value: Any, field: str = "purposes") -> list[str]:
        if not isinstance(value, list) or not value:
            raise ValidationError(f"{field} 必须是非空字符串数组")
        cleaned: list[str] = []
        for item in value:
            item = str(item).strip()
            if not item or len(item) > 80:
                raise ValidationError(f"{field} 中存在无效用途")
            cleaned.append(item)
        if len(set(cleaned)) != len(cleaned):
            raise ValidationError(f"{field} 不能包含重复用途")
        return cleaned

    def _actor(self, connection, actor_id: str):
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        if not row["active"]:
            raise PermissionDenied("操作者已停用")
        return row

    def _require(self, actor, *roles: str) -> None:
        if actor["role"] not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _site(self, connection, site_id: str):
        row = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFoundError("场所不存在")
        return row

    def _require_site_org(self, actor, site) -> None:
        if actor["role"] != "admin" and actor["organization_id"] != site["organization_id"]:
            raise PermissionDenied("不能操作其他机构场所的资源")

    def _pepper(self, connection) -> str:
        row = connection.execute("SELECT value FROM service_meta WHERE key='identity_pepper'").fetchone()
        if row is not None:
            return row["value"]
        pepper = generate_pepper()
        connection.execute(
            "INSERT OR IGNORE INTO service_meta(key,value) VALUES('identity_pepper',?)", (pepper,)
        )
        row = connection.execute("SELECT value FROM service_meta WHERE key='identity_pepper'").fetchone()
        return row["value"]

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any], create: Callable[[], tuple[str, str, dict[str, Any]]]) -> WriteReceipt:
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute("SELECT * FROM request_receipts WHERE request_id=?", (request_id,)).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return WriteReceipt(request_id, row["resource_type"], row["resource_id"], True)
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return WriteReceipt(request_id, resource_type, resource_id, False)

    def _audit(self, connection, *, actor_id: str, action: str, resource_type: str,
               resource_id: str, detail: dict[str, Any]) -> None:
        append_event(connection, actor_id=actor_id, action=action, resource_type=resource_type,
                     resource_id=resource_id, detail=detail, occurred_at=self._now())

    def _ledger(self, connection, *, sample_id: str, delta_total: float = 0.0,
                delta_reserved: float = 0.0, delta_consumed: float = 0.0,
                reason: str, ref_type: str | None = None, ref_id: str | None = None,
                actor_id: str) -> None:
        connection.execute(
            "INSERT INTO sample_ledger(sample_id,delta_total,delta_reserved,delta_consumed,reason,"
            "ref_type,ref_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (sample_id, delta_total, delta_reserved, delta_consumed, reason, ref_type, ref_id,
             actor_id, self._now()),
        )

    def _canonical(self, connection, participant_id: str) -> str:
        seen: set[str] = set()
        current = participant_id
        while True:
            if current in seen:
                raise ConflictError("参与者合并关系存在环")
            seen.add(current)
            row = connection.execute(
                "SELECT participant_id, status, merged_into FROM participants WHERE participant_id=?",
                (current,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"参与者不存在: {current}")
            if row["status"] != "merged" or row["merged_into"] is None:
                return row["participant_id"]
            current = row["merged_into"]

    def _get_participant(self, connection, participant_id: str):
        row = connection.execute("SELECT * FROM participants WHERE participant_id=?", (participant_id,)).fetchone()
        if row is None:
            raise NotFoundError("参与者不存在")
        return row

    # ----------------------------------------------------------- 身份与映射

    def link_subject_code(self, *, request_id: str, actor_id: str, site_id: str,
                          local_code: str, participant_id: str | None = None) -> WriteReceipt:
        """把一个中心本地编号登记为不可逆链接，必要时新建参与者。"""

        payload = {"actor_id": actor_id, "site_id": site_id, "local_code": local_code,
                   "participant_id": participant_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            site_id = self._identifier(site_id, "site_id")
            site = self._site(connection, site_id)
            self._require_site_org(actor, site)
            local_code = self._text(local_code, "local_code", 120)
            if participant_id is not None:
                participant_id = self._identifier(participant_id, "participant_id")
            pepper = self._pepper(connection)
            code_hash = subject_code_hash(pepper, site_id, local_code)

            existing = connection.execute(
                "SELECT participant_id FROM subject_links WHERE site_id=? AND code_hash=?",
                (site_id, code_hash),
            ).fetchone()
            if existing:
                # 同一编号重复登记：幂等返回既有参与者，绝不产生第二人。
                return WriteReceipt(request_id, "participant", existing["participant_id"], True)

            def create() -> tuple[str, str, dict[str, Any]]:
                if participant_id is None:
                    participant_id_new = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO participants(participant_id,status,created_by,created_at) "
                        "VALUES(?,'active',?,?)",
                        (participant_id_new, actor_id, self._now()),
                    )
                else:
                    participant_id_new = participant_id
                    target = self._get_participant(connection, participant_id_new)
                    if target["status"] != "active":
                        raise ConflictError("不能向已合并的参与者挂载编号")
                connection.execute(
                    "INSERT INTO subject_links(site_id,code_hash,participant_id,created_by,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (site_id, code_hash, participant_id_new, actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="subject.linked",
                            resource_type="participant", resource_id=participant_id_new,
                            detail={"site_id": site_id, "code_hash": code_hash})
                return "participant", participant_id_new, {"participant_id": participant_id_new}

            return self._idempotent(connection, request_id=request_id, action="biobank.link_subject",
                                    payload=payload, create=create)

    def merge_participants(self, *, request_id: str, actor_id: str,
                           canonical_participant_id: str, duplicate_participant_id: str) -> WriteReceipt:
        """声明两个参与者实为同一人，把资源不可逆地归并到规范身份。"""

        payload = {"actor_id": actor_id, "canonical_participant_id": canonical_participant_id,
                   "duplicate_participant_id": duplicate_participant_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            canonical_id = self._identifier(canonical_participant_id, "canonical_participant_id")
            duplicate_id = self._identifier(duplicate_participant_id, "duplicate_participant_id")
            if canonical_id == duplicate_id:
                raise ValidationError("不能把参与者合并到自身")
            canonical = self._get_participant(connection, canonical_id)
            duplicate = self._get_participant(connection, duplicate_id)
            if canonical["status"] != "active" or duplicate["status"] != "active":
                raise ConflictError("只能合并两个未合并的参与者")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE samples SET participant_id=? WHERE participant_id=?",
                                   (canonical_id, duplicate_id))
                connection.execute(
                    "INSERT OR IGNORE INTO dataset_participants(dataset_id,participant_id) "
                    "SELECT dataset_id,? FROM dataset_participants WHERE participant_id=?",
                    (canonical_id, duplicate_id),
                )
                connection.execute("DELETE FROM dataset_participants WHERE participant_id=?", (duplicate_id,))
                connection.execute("UPDATE subject_links SET participant_id=? WHERE participant_id=?",
                                   (canonical_id, duplicate_id))
                # 同意版本按 (参与者,版本标签) 去重归并，冲突时保留规范身份既有版本。
                for row in connection.execute("SELECT * FROM consents WHERE participant_id=?", (duplicate_id,)):
                    clash = connection.execute(
                        "SELECT 1 FROM consents WHERE participant_id=? AND version_tag=?",
                        (canonical_id, row["version_tag"]),
                    ).fetchone()
                    if clash:
                        connection.execute("DELETE FROM consents WHERE consent_id=?", (row["consent_id"],))
                    else:
                        connection.execute("UPDATE consents SET participant_id=? WHERE consent_id=?",
                                           (canonical_id, row["consent_id"]))
                connection.execute("UPDATE reservations SET participant_id=? WHERE participant_id=?",
                                   (canonical_id, duplicate_id))
                connection.execute("UPDATE withdrawals SET participant_id=? WHERE participant_id=?",
                                   (canonical_id, duplicate_id))
                connection.execute("UPDATE obligations SET participant_id=? WHERE participant_id=?",
                                   (canonical_id, duplicate_id))
                merge_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO participant_merges(merge_id,canonical_participant_id,"
                    "duplicate_participant_id,created_by,created_at) VALUES(?,?,?,?,?)",
                    (merge_id, canonical_id, duplicate_id, actor_id, self._now()),
                )
                connection.execute(
                    "UPDATE participants SET status='merged', merged_into=? WHERE participant_id=?",
                    (canonical_id, duplicate_id),
                )
                self._audit(connection, actor_id=actor_id, action="participant.merged",
                            resource_type="participant", resource_id=canonical_id,
                            detail={"merge_id": merge_id, "duplicate_participant_id": duplicate_id})
                return "participant_merge", merge_id, {"merge_id": merge_id,
                                                        "participant_id": canonical_id}

            return self._idempotent(connection, request_id=request_id, action="biobank.merge_participant",
                                    payload=payload, create=create)

    # ------------------------------------------------------- 同意、方案、许可

    def record_consent(self, *, request_id: str, actor_id: str, participant_id: str,
                       version_tag: str, purposes: list[str], document_hash: str,
                       signed_at: str | None = None) -> WriteReceipt:
        """登记一个知情同意版本；新版本在签署时点取代旧版本。"""

        payload = {"actor_id": actor_id, "participant_id": participant_id, "version_tag": version_tag,
                   "purposes": purposes, "document_hash": document_hash, "signed_at": signed_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            participant_id = self._identifier(participant_id, "participant_id")
            participant_id = self._canonical(connection, participant_id)
            version_tag = self._text(version_tag, "version_tag", 80)
            purposes = self._purposes(purposes)
            document_hash = self._text(document_hash, "document_hash", 128)
            signed_at = self._timestamp(signed_at, "signed_at")

            def create() -> tuple[str, str, dict[str, Any]]:
                consent_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO consents(consent_id,participant_id,version_tag,purposes_json,signed_at,"
                    "document_hash,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (consent_id, participant_id, version_tag, canonical_json(purposes), signed_at,
                     document_hash, actor_id, self._now()),
                )
                # 旧版本自新版本签署时点起失效；已经作出的审批通过授权依据快照保留旧版本。
                connection.execute(
                    "UPDATE consents SET superseded_at=? WHERE participant_id=? AND superseded_at IS NULL "
                    "AND consent_id<>?",
                    (signed_at, participant_id, consent_id),
                )
                self._audit(connection, actor_id=actor_id, action="consent.recorded",
                            resource_type="consent", resource_id=consent_id,
                            detail={"participant_id": participant_id, "version_tag": version_tag,
                                    "purposes": purposes, "signed_at": signed_at,
                                    "document_hash": document_hash})
                return "consent", consent_id, {"consent_id": consent_id, "participant_id": participant_id,
                                               "version_tag": version_tag}

            return self._idempotent(connection, request_id=request_id, action="biobank.record_consent",
                                    payload=payload, create=create)

    def register_protocol(self, *, request_id: str, actor_id: str, protocol_id: str,
                          title: str, owner_organization_id: str,
                          purposes: list[str]) -> WriteReceipt:
        payload = {"actor_id": actor_id, "protocol_id": protocol_id, "title": title,
                   "owner_organization_id": owner_organization_id, "purposes": purposes}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES)
            protocol_id = self._identifier(protocol_id, "protocol_id")
            title = self._text(title, "title")
            owner_organization_id = self._identifier(owner_organization_id, "owner_organization_id")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (owner_organization_id,)).fetchone() is None:
                raise NotFoundError("所属机构不存在")
            purposes = self._purposes(purposes)

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO protocols(protocol_id,title,owner_organization_id,purposes_json,status,"
                    "created_by,created_at) VALUES(?,?,?,?,'active',?,?)",
                    (protocol_id, title, owner_organization_id, canonical_json(purposes),
                     actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="protocol.registered",
                            resource_type="protocol", resource_id=protocol_id,
                            detail={"title": title, "purposes": purposes})
                return "protocol", protocol_id, {"protocol_id": protocol_id}

            return self._idempotent(connection, request_id=request_id, action="biobank.register_protocol",
                                    payload=payload, create=create)

    def amend_protocol_purposes(self, *, request_id: str, actor_id: str, protocol_id: str,
                                add_purposes: list[str]) -> WriteReceipt:
        """修订研究方案用途范围。

        修订只扩展用途集且只对修订之后的审批可见；既往批准/拒绝的授权依据
        已经随决定固化，不被追溯改写。
        """

        payload = {"actor_id": actor_id, "protocol_id": protocol_id, "add_purposes": add_purposes}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES)
            protocol_id = self._identifier(protocol_id, "protocol_id")
            row = connection.execute("SELECT * FROM protocols WHERE protocol_id=?",
                                     (protocol_id,)).fetchone()
            if row is None:
                raise NotFoundError("研究方案不存在")
            if row["status"] != "active":
                raise ConflictError("方案已关闭，不能修订用途")
            add_purposes = self._purposes(add_purposes, "add_purposes")
            current = json.loads(row["purposes_json"])
            merged = sorted(set(current) | set(add_purposes))

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE protocols SET purposes_json=? WHERE protocol_id=?",
                                   (canonical_json(merged), protocol_id))
                self._audit(connection, actor_id=actor_id, action="protocol.purposes_amended",
                            resource_type="protocol", resource_id=protocol_id,
                            detail={"added": add_purposes, "purposes": merged})
                return "protocol", protocol_id, {"protocol_id": protocol_id, "purposes": merged}

            return self._idempotent(connection, request_id=request_id,
                                    action="biobank.amend_protocol_purposes",
                                    payload=payload, create=create)

    def record_irb_approval(self, *, request_id: str, actor_id: str, approval_id: str,
                            protocol_id: str, purposes: list[str], valid_from: str, valid_to: str,
                            site_id: str | None = None, conditions: list[Any] | None = None) -> WriteReceipt:
        """登记伦理许可。site_id 为空表示联盟通用许可，否则限单中心。"""

        payload = {"actor_id": actor_id, "approval_id": approval_id, "protocol_id": protocol_id,
                   "purposes": purposes, "valid_from": valid_from, "valid_to": valid_to,
                   "site_id": site_id, "conditions": conditions or []}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES)
            approval_id = self._identifier(approval_id, "approval_id")
            protocol_id = self._identifier(protocol_id, "protocol_id")
            if connection.execute("SELECT 1 FROM protocols WHERE protocol_id=?",
                                  (protocol_id,)).fetchone() is None:
                raise NotFoundError("研究方案不存在")
            purposes = self._purposes(purposes)
            valid_from = self._timestamp(valid_from, "valid_from")
            valid_to = self._timestamp(valid_to, "valid_to")
            if not valid_from < valid_to:
                raise ValidationError("伦理许可有效期开始必须早于结束")
            if site_id is not None:
                site_id = self._identifier(site_id, "site_id")
                self._site(connection, site_id)
            conditions = conditions or []
            if not isinstance(conditions, list):
                raise ValidationError("conditions 必须是数组")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO irb_approvals(approval_id,protocol_id,site_id,purposes_json,valid_from,"
                    "valid_to,conditions_json,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (approval_id, protocol_id, site_id, canonical_json(purposes), valid_from, valid_to,
                     canonical_json(conditions), actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="irb_approval.recorded",
                            resource_type="irb_approval", resource_id=approval_id,
                            detail={"protocol_id": protocol_id, "site_id": site_id, "purposes": purposes,
                                    "valid_from": valid_from, "valid_to": valid_to})
                return "irb_approval", approval_id, {"approval_id": approval_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="biobank.record_irb_approval", payload=payload, create=create)

    # ------------------------------------------------------------- 样本与分装

    def register_sample(self, *, request_id: str, actor_id: str, sample_id: str,
                        participant_id: str, site_id: str, material_type: str,
                        quantity: float, unit: str = "mL", collected_at: str | None = None) -> WriteReceipt:
        payload = {"actor_id": actor_id, "sample_id": sample_id, "participant_id": participant_id,
                   "site_id": site_id, "material_type": material_type, "quantity": quantity,
                   "unit": unit, "collected_at": collected_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *BIOBANK_ROLES)
            sample_id = self._identifier(sample_id, "sample_id")
            participant_id = self._identifier(participant_id, "participant_id")
            participant_id = self._canonical(connection, participant_id)
            site_id = self._identifier(site_id, "site_id")
            site = self._site(connection, site_id)
            self._require_site_org(actor, site)
            material_type = self._text(material_type, "material_type", 80)
            unit = self._text(unit, "unit", 20)
            quantity = self._positive_quantity(quantity)
            collected_at = self._timestamp(collected_at, "collected_at")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO samples(sample_id,participant_id,parent_sample_id,site_id,material_type,"
                    "unit,quantity_total,quantity_reserved,quantity_consumed,status,collected_at,"
                    "created_by,created_at) VALUES(?,?,NULL,?,?,?,? ,0,0,'available',?,?,?)",
                    (sample_id, participant_id, site_id, material_type, unit, quantity,
                     collected_at, actor_id, self._now()),
                )
                self._ledger(connection, sample_id=sample_id, delta_total=quantity,
                             reason="registered", ref_type="sample", ref_id=sample_id, actor_id=actor_id)
                self._audit(connection, actor_id=actor_id, action="sample.registered",
                            resource_type="sample", resource_id=sample_id,
                            detail={"participant_id": participant_id, "site_id": site_id,
                                    "material_type": material_type, "quantity": quantity, "unit": unit})
                return "sample", sample_id, {"sample_id": sample_id, "quantity_total": quantity}

            return self._idempotent(connection, request_id=request_id, action="biobank.register_sample",
                                    payload=payload, create=create)

    def split_sample(self, *, request_id: str, actor_id: str, parent_sample_id: str,
                     child_sample_id: str, quantity: float) -> WriteReceipt:
        """从未被预留/消耗的可用余量中分出一个子样本，总量跨父子守恒。"""

        payload = {"actor_id": actor_id, "parent_sample_id": parent_sample_id,
                   "child_sample_id": child_sample_id, "quantity": quantity}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *BIOBANK_ROLES)
            parent_sample_id = self._identifier(parent_sample_id, "parent_sample_id")
            child_sample_id = self._identifier(child_sample_id, "child_sample_id")
            quantity = self._positive_quantity(quantity)
            parent = connection.execute("SELECT * FROM samples WHERE sample_id=?",
                                        (parent_sample_id,)).fetchone()
            if parent is None:
                raise NotFoundError("母本不存在")
            site = self._site(connection, parent["site_id"])
            self._require_site_org(actor, site)
            available = parent["quantity_total"] - parent["quantity_reserved"] - parent["quantity_consumed"]
            if quantity > available + _EPS:
                raise RuleViolation("分装数量超过未预留可用余量", [
                    {"code": "split_within_available", "passed": False,
                     "detail": {"sample_id": parent_sample_id, "requested": quantity,
                                "available": available}}])

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE samples SET quantity_total=quantity_total-?, "
                    "status=CASE WHEN quantity_total-?-quantity_reserved-quantity_consumed<=0 "
                    "THEN 'depleted' ELSE 'available' END WHERE sample_id=?",
                    (quantity, quantity, parent_sample_id),
                )
                self._ledger(connection, sample_id=parent_sample_id, delta_total=-quantity,
                             reason="split_out", ref_type="sample", ref_id=child_sample_id,
                             actor_id=actor_id)
                connection.execute(
                    "INSERT INTO samples(sample_id,participant_id,parent_sample_id,site_id,material_type,"
                    "unit,quantity_total,quantity_reserved,quantity_consumed,status,collected_at,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,0,0,'available',?,?,?)",
                    (child_sample_id, parent["participant_id"], parent_sample_id, parent["site_id"],
                     parent["material_type"], parent["unit"], quantity, parent["collected_at"],
                     actor_id, self._now()),
                )
                self._ledger(connection, sample_id=child_sample_id, delta_total=quantity,
                             reason="split_in", ref_type="sample", ref_id=parent_sample_id,
                             actor_id=actor_id)
                self._audit(connection, actor_id=actor_id, action="sample.split",
                            resource_type="sample", resource_id=child_sample_id,
                            detail={"parent_sample_id": parent_sample_id, "quantity": quantity})
                return "sample", child_sample_id, {"sample_id": child_sample_id,
                                                   "parent_sample_id": parent_sample_id,
                                                   "quantity_total": quantity}

            return self._idempotent(connection, request_id=request_id, action="biobank.split_sample",
                                    payload=payload, create=create)

    @staticmethod
    def _positive_quantity(value: Any) -> float:
        try:
            quantity = float(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("数量必须是正数") from exc
        if quantity <= 0:
            raise ValidationError("数量必须是正数")
        return quantity

    # ----------------------------------------------------------------- 数据集

    def register_dataset(self, *, request_id: str, actor_id: str, dataset_id: str,
                         title: str) -> WriteReceipt:
        payload = {"actor_id": actor_id, "dataset_id": dataset_id, "title": title}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            dataset_id = self._identifier(dataset_id, "dataset_id")
            title = self._text(title, "title")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO datasets(dataset_id,title,created_by,created_at) VALUES(?,?,?,?)",
                    (dataset_id, title, actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="dataset.registered",
                            resource_type="dataset", resource_id=dataset_id, detail={"title": title})
                return "dataset", dataset_id, {"dataset_id": dataset_id}

            return self._idempotent(connection, request_id=request_id, action="biobank.register_dataset",
                                    payload=payload, create=create)

    def add_dataset_participant(self, *, request_id: str, actor_id: str,
                                dataset_id: str, participant_id: str) -> WriteReceipt:
        payload = {"actor_id": actor_id, "dataset_id": dataset_id, "participant_id": participant_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            dataset_id = self._identifier(dataset_id, "dataset_id")
            participant_id = self._identifier(participant_id, "participant_id")
            participant_id = self._canonical(connection, participant_id)
            if connection.execute("SELECT 1 FROM datasets WHERE dataset_id=?",
                                  (dataset_id,)).fetchone() is None:
                raise NotFoundError("数据集不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT OR IGNORE INTO dataset_participants(dataset_id,participant_id) VALUES(?,?)",
                    (dataset_id, participant_id),
                )
                self._audit(connection, actor_id=actor_id, action="dataset.participant_added",
                            resource_type="dataset", resource_id=dataset_id,
                            detail={"participant_id": participant_id})
                return ("dataset_participant", f"{dataset_id}:{participant_id}",
                        {"dataset_id": dataset_id, "participant_id": participant_id})

            return self._idempotent(connection, request_id=request_id,
                                    action="biobank.add_dataset_participant", payload=payload, create=create)

    # ------------------------------------------------------------- 访问申请

    def _normalize_items(self, items: Any) -> list[dict[str, float]]:
        if not isinstance(items, list) or not items:
            raise ValidationError("items 必须是非空数组")
        normalized: list[dict[str, float]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict) or "sample_id" not in item or "quantity" not in item:
                raise ValidationError("items 每项必须包含 sample_id 与 quantity")
            sample_id = self._identifier(item["sample_id"], "sample_id")
            if sample_id in seen:
                raise ValidationError(f"同一申请中样本 {sample_id} 出现多次")
            seen.add(sample_id)
            normalized.append({"sample_id": sample_id,
                               "quantity": self._positive_quantity(item["quantity"])})
        return normalized

    def submit_application(self, *, request_id: str, actor_id: str, application_id: str | None = None,
                           protocol_id: str, purpose: str, items: list[dict[str, Any]],
                           dataset_id: str | None = None) -> WriteReceipt:
        purpose = str(purpose).strip()
        payload = {"actor_id": actor_id, "application_id": application_id, "protocol_id": protocol_id,
                   "purpose": purpose, "items": items, "dataset_id": dataset_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *RESEARCH_ROLES)
            protocol_id = self._identifier(protocol_id, "protocol_id")
            if connection.execute("SELECT 1 FROM protocols WHERE protocol_id=?",
                                  (protocol_id,)).fetchone() is None:
                raise NotFoundError("研究方案不存在")
            purpose = self._text(purpose, "purpose", 80)
            items = self._normalize_items(items)
            if dataset_id is not None:
                dataset_id = self._identifier(dataset_id, "dataset_id")
                if connection.execute("SELECT 1 FROM datasets WHERE dataset_id=?",
                                      (dataset_id,)).fetchone() is None:
                    raise NotFoundError("数据集不存在")
            for item in items:
                if connection.execute("SELECT 1 FROM samples WHERE sample_id=?",
                                      (item["sample_id"],)).fetchone() is None:
                    raise NotFoundError(f"样本不存在: {item['sample_id']}")
            fingerprint = digest({"researcher_actor_id": actor_id, "protocol_id": protocol_id,
                                  "purpose": purpose, "dataset_id": dataset_id,
                                  "items": sorted((i["sample_id"], i["quantity"]) for i in items)})
            duplicate = connection.execute(
                "SELECT application_id,status FROM access_applications WHERE fingerprint=? "
                "AND status IN ('pending','approved')",
                (fingerprint,),
            ).fetchone()
            if duplicate:
                raise ConflictError(
                    f"相同内容的访问申请已经存在且未结案: {duplicate['application_id']}"
                )

            def create() -> tuple[str, str, dict[str, Any]]:
                new_application_id = self._identifier(application_id, "application_id") \
                    if application_id else uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO access_applications(application_id,request_id,researcher_actor_id,"
                    "protocol_id,purpose,dataset_id,items_json,fingerprint,status,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,'pending',?,?)",
                    (new_application_id, request_id, actor_id, protocol_id, purpose, dataset_id,
                     canonical_json(items), fingerprint, actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="application.submitted",
                            resource_type="access_application", resource_id=new_application_id,
                            detail={"protocol_id": protocol_id, "purpose": purpose,
                                    "dataset_id": dataset_id, "items": items})
                return ("access_application", new_application_id,
                        {"application_id": new_application_id, "status": "pending"})

            return self._idempotent(connection, request_id=request_id,
                                    action="biobank.submit_application", payload=payload, create=create)

    def _evaluate(self, connection, app, at: str) -> dict[str, Any]:
        """按 at 时点有效的同意、伦理许可与样本余量逐项评估。"""

        checks: list[dict[str, Any]] = []
        protocol_id = app["protocol_id"]
        purpose = app["purpose"]
        items = json.loads(app["items_json"])
        dataset_id = app["dataset_id"]

        protocol = connection.execute("SELECT * FROM protocols WHERE protocol_id=?",
                                      (protocol_id,)).fetchone()
        checks.append({
            "code": "protocol_active",
            "passed": protocol is not None and protocol["status"] == "active",
            "detail": {"protocol_id": protocol_id,
                       "status": protocol["status"] if protocol else "missing"},
        })
        if protocol is not None:
            checks.append({
                "code": "purpose_within_protocol",
                "passed": purpose in json.loads(protocol["purposes_json"]),
                "detail": {"purpose": purpose, "declared_purposes": json.loads(protocol["purposes_json"])},
            })

        # 逐样本解析规范参与者与中心。
        resolved: list[dict[str, Any]] = []
        participant_ids: set[str] = set()
        site_ids: set[str] = set()
        for item in items:
            sample = connection.execute("SELECT * FROM samples WHERE sample_id=?",
                                        (item["sample_id"],)).fetchone()
            if sample is None:
                checks.append({"code": "sample_exists", "passed": False,
                               "detail": {"sample_id": item["sample_id"]}})
                continue
            participant_id = self._canonical(connection, sample["participant_id"])
            resolved.append({**item, "sample": sample, "participant_id": participant_id,
                             "site_id": sample["site_id"]})
            participant_ids.add(participant_id)
            site_ids.add(sample["site_id"])

        # 数据集成员资格（最小披露：只放行数据集覆盖的参与者）。
        if dataset_id is not None:
            for participant_id in sorted(participant_ids):
                member = connection.execute(
                    "SELECT 1 FROM dataset_participants WHERE dataset_id=? AND participant_id=?",
                    (dataset_id, participant_id),
                ).fetchone() is not None
                checks.append({"code": "dataset_membership", "passed": member,
                               "detail": {"dataset_id": dataset_id, "participant_id": participant_id}})

        consent_snapshot: dict[str, Any] = {}
        withdrawal_snapshot: dict[str, Any] = {}
        for participant_id in sorted(participant_ids):
            consent = connection.execute(
                "SELECT * FROM consents WHERE participant_id=? AND signed_at<=? "
                "AND (superseded_at IS NULL OR superseded_at>?) ORDER BY signed_at DESC LIMIT 1",
                (participant_id, at, at),
            ).fetchone()
            if consent is None:
                checks.append({"code": "consent_exists", "passed": False,
                               "detail": {"participant_id": participant_id, "at": at}})
                consent_snapshot[participant_id] = None
            else:
                allowed_purposes = json.loads(consent["purposes_json"])
                checks.append({
                    "code": "consent_covers_purpose",
                    "passed": purpose in allowed_purposes,
                    "detail": {"participant_id": participant_id,
                               "consent_id": consent["consent_id"],
                               "version_tag": consent["version_tag"],
                               "requested_purpose": purpose,
                               "consented_purposes": allowed_purposes},
                })
                consent_snapshot[participant_id] = {
                    "consent_id": consent["consent_id"], "version_tag": consent["version_tag"],
                    "signed_at": consent["signed_at"], "purposes": allowed_purposes,
                    "document_hash": consent["document_hash"],
                }
            withdrawals = []
            for wd in connection.execute(
                "SELECT * FROM withdrawals WHERE participant_id=? AND effective_at<=?",
                (participant_id, at),
            ):
                scope = json.loads(wd["scope_json"])
                if scope.get("all") or purpose in scope.get("purposes", []):
                    withdrawals.append({"withdrawal_id": wd["withdrawal_id"], "scope": scope,
                                        "effective_at": wd["effective_at"]})
            withdrawal_snapshot[participant_id] = withdrawals
            checks.append({
                "code": "not_withdrawn",
                "passed": not withdrawals,
                "detail": {"participant_id": participant_id, "purpose": purpose,
                           "withdrawals": withdrawals},
            })

        # 伦理许可：逐中心寻找当时在有效期内且覆盖用途的许可（中心专属优先于通用）。
        irb_snapshot: dict[str, Any] = {}
        for site_id in sorted(site_ids):
            candidates = connection.execute(
                "SELECT * FROM irb_approvals WHERE protocol_id=? AND valid_from<=? AND valid_to>? "
                "AND (site_id IS NULL OR site_id=?) "
                "ORDER BY CASE WHEN site_id IS NULL THEN 1 ELSE 0 END, valid_from DESC",
                (protocol_id, at, at, site_id),
            ).fetchall()
            approval = next((row for row in candidates
                             if purpose in json.loads(row["purposes_json"])), None)
            passed = approval is not None
            checks.append({
                "code": "irb_approval_valid",
                "passed": passed,
                "detail": {"site_id": site_id, "protocol_id": protocol_id, "purpose": purpose,
                           "approval_id": approval["approval_id"] if approval else None},
            })
            if approval is not None:
                irb_snapshot[site_id] = {"approval_id": approval["approval_id"],
                                         "site_id": approval["site_id"],
                                         "valid_from": approval["valid_from"],
                                         "valid_to": approval["valid_to"],
                                         "purposes": json.loads(approval["purposes_json"]),
                                         "conditions": json.loads(approval["conditions_json"])}

        # 样本余量：在调用方持有的写事务内重算，因此并发审批不会重复预留。
        availability: list[dict[str, Any]] = []
        for entry in resolved:
            sample = entry["sample"]
            requested = entry["quantity"]
            held = connection.execute(
                "SELECT COALESCE(SUM(quantity-consumed_qty),0) AS held FROM reservations "
                "WHERE sample_id=? AND state='held'",
                (sample["sample_id"],),
            ).fetchone()["held"]
            available = sample["quantity_total"] - sample["quantity_consumed"] - held
            ok = requested <= available + _EPS
            checks.append({
                "code": "sample_available",
                "passed": ok,
                "detail": {"sample_id": sample["sample_id"], "requested": requested,
                           "available": available, "unit": sample["unit"]},
            })
            availability.append({"sample_id": sample["sample_id"], "participant_id": entry["participant_id"],
                                 "requested": requested, "available": available, "passed": ok})

        return {"evaluated_at": at, "passed": all(c["passed"] for c in checks),
                "checks": checks, "consents": consent_snapshot, "irb": irb_snapshot,
                "withdrawals": withdrawal_snapshot, "availability": availability}

    def decide_application(self, *, actor_id: str, application_id: str,
                           decision: str = "approve",
                           expires_at: str | None = None) -> dict[str, Any]:
        """伦理审批：全量原子检查通过才预留，否则阻断并保留逐项理由。"""

        if decision not in ("approve", "deny"):
            raise ValidationError("decision 只能是 approve 或 deny")
        application_id = self._identifier(application_id, "application_id")
        if expires_at is not None:
            expires_at = self._timestamp(expires_at, "expires_at")
        self._auto_apply_due(actor_id)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES)
            app = connection.execute("SELECT * FROM access_applications WHERE application_id=?",
                                     (application_id,)).fetchone()
            if app is None:
                raise NotFoundError("访问申请不存在")
            if app["status"] != "pending":
                raise ConflictError(f"申请已处于 {app['status']} 状态，不能重复审批")
            now = self._now()
            if expires_at is not None and expires_at <= now:
                raise ValidationError("expires_at 必须晚于当前时间")
            evaluation = self._evaluate(connection, app, now)
            approve = decision == "approve" and evaluation["passed"]
            if approve:
                for entry in evaluation["availability"]:
                    reservation_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO reservations(reservation_id,application_id,sample_id,participant_id,"
                        "quantity,consumed_qty,state,created_at) VALUES(?,?,?,?,?,0,'held',?)",
                        (reservation_id, application_id, entry["sample_id"], entry["participant_id"],
                         entry["requested"], now),
                    )
                    connection.execute(
                        "UPDATE samples SET quantity_reserved=quantity_reserved+? WHERE sample_id=?",
                        (entry["requested"], entry["sample_id"]),
                    )
                    self._ledger(connection, sample_id=entry["sample_id"],
                                 delta_reserved=entry["requested"], reason="reserved",
                                 ref_type="access_application", ref_id=application_id, actor_id=actor_id)
                basis = {
                    "application_id": application_id,
                    "decided_at": now,
                    "researcher_actor_id": app["researcher_actor_id"],
                    "protocol_id": app["protocol_id"],
                    "purpose": app["purpose"],
                    "dataset_id": app["dataset_id"],
                    "fingerprint": app["fingerprint"],
                    "items": json.loads(app["items_json"]),
                    "consents": evaluation["consents"],
                    "irb": evaluation["irb"],
                    "withdrawals": evaluation["withdrawals"],
                    "checks": evaluation["checks"],
                }
                basis_hash = digest(basis)
                connection.execute(
                    "INSERT INTO authorization_basis(application_id,basis_version,basis_json,basis_hash,"
                    "decided_at) VALUES(?,1,?,?,?)",
                    (application_id, canonical_json(basis), basis_hash, now),
                )
                connection.execute(
                    "UPDATE access_applications SET status='approved', decided_by=?, decided_at=?, "
                    "expires_at=?, decision_reason_json=? WHERE application_id=?",
                    (actor_id, now, expires_at, canonical_json(evaluation["checks"]), application_id),
                )
                self._audit(connection, actor_id=actor_id, action="application.approved",
                            resource_type="access_application", resource_id=application_id,
                            detail={"basis_hash": basis_hash,
                                    "reservations": len(evaluation["availability"])})
                return {"application_id": application_id, "decision": "approved",
                        "checks": evaluation["checks"], "basis_hash": basis_hash}

            connection.execute(
                "UPDATE access_applications SET status='denied', decided_by=?, decided_at=?, "
                "decision_reason_json=? WHERE application_id=?",
                (actor_id, now, canonical_json(evaluation["checks"]), application_id),
            )
            self._audit(connection, actor_id=actor_id, action="application.denied",
                        resource_type="access_application", resource_id=application_id,
                        detail={"passed": evaluation["passed"], "requested_decision": decision,
                                "failed_checks": [c["code"] for c in evaluation["checks"]
                                                  if not c["passed"]]})
            return {"application_id": application_id, "decision": "denied",
                    "checks": evaluation["checks"]}

    def release_application(self, *, actor_id: str, application_id: str) -> dict[str, Any]:
        """发放批准的访问：生成不含任何内部标识的最小披露清单。"""

        application_id = self._identifier(application_id, "application_id")
        self._auto_apply_due(actor_id)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            app = connection.execute("SELECT * FROM access_applications WHERE application_id=?",
                                     (application_id,)).fetchone()
            if app is None:
                raise NotFoundError("访问申请不存在")
            if app["status"] != "approved":
                raise ConflictError("只有已批准且未结案的申请可以发放")
            if app["expires_at"] is not None and app["expires_at"] <= self._now():
                raise ConflictError("批准已过期")
            if connection.execute("SELECT 1 FROM dataset_releases WHERE application_id=?",
                                  (application_id,)).fetchone():
                raise ConflictError("该申请已经发放，不能重复发放")
            pepper = self._pepper(connection)
            entries = []
            for reservation in connection.execute(
                "SELECT r.*, s.material_type, s.unit FROM reservations r JOIN samples s "
                "ON r.sample_id=s.sample_id WHERE r.application_id=? AND r.state='held' ORDER BY r.sample_id",
                (application_id,),
            ):
                entries.append({
                    "pseudonym": research_pseudonym(pepper, application_id, reservation["participant_id"]),
                    "aliquot_code": "A-" + digest({"application_id": application_id,
                                                   "sample_id": reservation["sample_id"]})[:16].upper(),
                    "material_type": reservation["material_type"],
                    "unit": reservation["unit"],
                    "quantity": reservation["quantity"] - reservation["consumed_qty"],
                })
            manifest = {"application_id": application_id, "dataset_id": app["dataset_id"],
                        "released_at": self._now(), "entries": entries}
            payload_hash = release_fingerprint(pepper, manifest)
            release_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO dataset_releases(release_id,application_id,payload_hash,created_by,created_at) "
                "VALUES(?,?,?,?,?)",
                (release_id, application_id, payload_hash, actor_id, self._now()),
            )
            connection.execute(
                "UPDATE access_applications SET released_at=? WHERE application_id=?",
                (manifest["released_at"], application_id),
            )
            self._audit(connection, actor_id=actor_id, action="application.released",
                        resource_type="access_application", resource_id=application_id,
                        detail={"release_id": release_id, "payload_hash": payload_hash,
                                "entry_count": len(entries)})
            return {"application_id": application_id, "release_id": release_id,
                    "payload_hash": payload_hash, "manifest": manifest}

    def record_consumption(self, *, actor_id: str, application_id: str,
                           items: list[dict[str, Any]]) -> dict[str, Any]:
        """登记一次（可部分）实际消耗，预留转消耗，数量守恒由账本保证。"""

        application_id = self._identifier(application_id, "application_id")
        normalized = self._normalize_items(items)
        self._auto_apply_due(actor_id)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *BIOBANK_ROLES)
            app = connection.execute("SELECT * FROM access_applications WHERE application_id=?",
                                     (application_id,)).fetchone()
            if app is None:
                raise NotFoundError("访问申请不存在")
            if app["status"] != "approved":
                raise ConflictError("只有已批准申请可以登记消耗")
            records = []
            for item in normalized:
                reservation = connection.execute(
                    "SELECT * FROM reservations WHERE application_id=? AND sample_id=?",
                    (application_id, item["sample_id"]),
                ).fetchone()
                if reservation is None or reservation["state"] != "held":
                    raise RuleViolation("样本不在该申请的有效预留中", [
                        {"code": "consumption_within_reservation", "passed": False,
                         "detail": {"sample_id": item["sample_id"]}}])
                remaining = reservation["quantity"] - reservation["consumed_qty"]
                if item["quantity"] > remaining + _EPS:
                    raise RuleViolation("消耗超过预留余量", [
                        {"code": "consumption_within_reservation", "passed": False,
                         "detail": {"sample_id": item["sample_id"], "requested": item["quantity"],
                                    "remaining": remaining}}])
                connection.execute(
                    "UPDATE reservations SET consumed_qty=consumed_qty+?, "
                    "state=CASE WHEN consumed_qty+?>=(quantity-?) THEN 'consumed' ELSE 'held' END, "
                    "consumed_at=? WHERE reservation_id=?",
                    (item["quantity"], item["quantity"], _EPS, self._now(),
                     reservation["reservation_id"]),
                )
                connection.execute(
                    "UPDATE samples SET quantity_reserved=quantity_reserved-?, "
                    "quantity_consumed=quantity_consumed+?, "
                    "status=CASE WHEN quantity_total-quantity_consumed-quantity_reserved<=0 "
                    "THEN 'depleted' ELSE 'available' END WHERE sample_id=?",
                    (item["quantity"], item["quantity"], item["sample_id"]),
                )
                self._ledger(connection, sample_id=item["sample_id"],
                             delta_reserved=-item["quantity"], delta_consumed=item["quantity"],
                             reason="consumed", ref_type="access_application",
                             ref_id=application_id, actor_id=actor_id)
                records.append({"sample_id": item["sample_id"], "consumed": item["quantity"]})
            self._audit(connection, actor_id=actor_id, action="reservation.consumed",
                        resource_type="access_application", resource_id=application_id,
                        detail={"items": records})
            return {"application_id": application_id, "consumed": records}

    def close_application(self, *, actor_id: str, application_id: str) -> dict[str, Any]:
        """结案申请：尚未消耗的预留余量退回样本池。"""

        application_id = self._identifier(application_id, "application_id")
        self._auto_apply_due(actor_id)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            app = connection.execute("SELECT * FROM access_applications WHERE application_id=?",
                                     (application_id,)).fetchone()
            if app is None:
                raise NotFoundError("访问申请不存在")
            if app["status"] == "closed":
                return {"application_id": application_id, "status": "closed", "released": []}
            if app["status"] != "approved":
                raise ConflictError("只有已批准申请可以结案")
            released = self._release_holds(connection, application_id=application_id,
                                           participant_id=None, reason="hold_closed",
                                           actor_id=actor_id)
            connection.execute("UPDATE access_applications SET status='closed' WHERE application_id=?",
                               (application_id,))
            self._audit(connection, actor_id=actor_id, action="application.closed",
                        resource_type="access_application", resource_id=application_id,
                        detail={"released": released})
            return {"application_id": application_id, "status": "closed", "released": released}

    def _release_holds(self, connection, *, application_id: str, participant_id: str | None,
                       reason: str, actor_id: str) -> list[dict[str, Any]]:
        query = ("SELECT r.* FROM reservations r JOIN access_applications a "
                 "ON r.application_id=a.application_id WHERE r.state='held' AND r.application_id=?")
        parameters: list[Any] = [application_id]
        if participant_id is not None:
            query += " AND r.participant_id=?"
            parameters.append(participant_id)
        released: list[dict[str, Any]] = []
        for reservation in connection.execute(query, parameters):
            remaining = reservation["quantity"] - reservation["consumed_qty"]
            if remaining <= _EPS:
                continue
            connection.execute(
                "UPDATE samples SET quantity_reserved=quantity_reserved-? WHERE sample_id=?",
                (remaining, reservation["sample_id"]),
            )
            self._ledger(connection, sample_id=reservation["sample_id"], delta_reserved=-remaining,
                         reason=reason, ref_type="access_application", ref_id=application_id,
                         actor_id=actor_id)
            connection.execute(
                "UPDATE reservations SET state='released', released_at=? WHERE reservation_id=?",
                (self._now(), reservation["reservation_id"]),
            )
            released.append({"sample_id": reservation["sample_id"], "quantity": remaining})
        return released

    # ----------------------------------------------------------------- 撤回

    def _apply_withdrawal(self, connection, wd, actor_id: str) -> dict[str, Any]:
        """把一条已到生效时点的撤回级联到尚未发生的使用。可幂等重放。"""

        withdrawal_id = wd["withdrawal_id"]
        participant_id = wd["participant_id"]
        scope = json.loads(wd["scope_json"])
        affected_apps: dict[str, dict[str, Any]] = {}

        def in_scope(purpose: str) -> bool:
            return bool(scope.get("all")) or purpose in scope.get("purposes", [])

        # 候选申请：仍有 held 预留的、已发生消耗的、或已向研究方发放数据的。
        candidate_rows = connection.execute(
            "SELECT a.application_id, a.purpose, a.released_at, a.status, "
            "COALESCE(SUM(r.consumed_qty),0) AS consumed_total "
            "FROM access_applications a JOIN reservations r "
            "ON a.application_id=r.application_id "
            "WHERE r.participant_id=? AND a.status IN ('approved','closed') "
            "GROUP BY a.application_id, a.purpose, a.released_at, a.status",
            (participant_id,),
        ).fetchall()
        held_rows = connection.execute(
            "SELECT r.application_id FROM reservations r "
            "JOIN access_applications a ON r.application_id=a.application_id "
            "WHERE r.participant_id=? AND r.state='held' AND a.status='approved'",
            (participant_id,),
        ).fetchall()
        held_app_ids = {row["application_id"] for row in held_rows}
        app_ids = sorted({row["application_id"] for row in candidate_rows
                          if in_scope(row["purpose"])})
        for row in candidate_rows:
            if row["application_id"] not in app_ids:
                continue
            application_id = row["application_id"]
            purpose = row["purpose"]
            released: list[dict[str, Any]] = []
            if application_id in held_app_ids:
                released = self._release_holds(
                    connection, application_id=application_id, participant_id=participant_id,
                    reason="withdrawn", actor_id=actor_id)
            consumed_total = row["consumed_total"]
            generated: list[str] = []
            # 既往使用不追溯：已发放数据生成销毁义务，已消耗样本生成停用义务。
            kinds: tuple[str, ...] = ()
            if row["released_at"] is not None:
                kinds = ("destroy_data", "cease_use")
            elif consumed_total > _EPS:
                kinds = ("cease_use",)
            for kind in kinds:
                obligation_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO obligations(obligation_id,participant_id,application_id,"
                    "kind,detail_json,status,created_at) VALUES(?,?,?,?,?,'open',?)",
                    (obligation_id, participant_id, application_id, kind,
                     canonical_json({"withdrawal_id": withdrawal_id, "purpose": purpose}),
                     self._now()),
                )
                generated.append(obligation_id)
            remaining_holds = connection.execute(
                "SELECT COUNT(*) AS count FROM reservations WHERE application_id=? AND state='held'",
                (application_id,),
            ).fetchone()["count"]
            if remaining_holds == 0 and row["status"] == "approved":
                connection.execute(
                    "UPDATE access_applications SET status='closed' WHERE application_id=?",
                    (application_id,),
                )
                status_after = "closed"
            else:
                status_after = row["status"]
            affected_apps[application_id] = {"released": released, "obligations": generated,
                                             "status_after": status_after}
        connection.execute("UPDATE withdrawals SET applied_at=? WHERE withdrawal_id=?",
                           (self._now(), withdrawal_id))
        self._audit(connection, actor_id=actor_id, action="withdrawal.applied",
                    resource_type="withdrawal", resource_id=withdrawal_id,
                    detail={"participant_id": participant_id, "scope": scope,
                            "affected_applications": affected_apps})
        return affected_apps

    def _apply_due_withdrawals(self, connection, *, now: str, actor_id: str) -> int:
        """应用所有已到生效时点但尚未级联的撤回，返回处理条数。"""

        rows = connection.execute(
            "SELECT * FROM withdrawals WHERE applied_at IS NULL AND effective_at<=?", (now,)
        ).fetchall()
        for wd in rows:
            self._apply_withdrawal(connection, wd, actor_id)
        return len(rows)

    def withdraw_participant(self, *, request_id: str, actor_id: str, participant_id: str,
                             purposes: list[str] | None = None,
                             effective_at: str | None = None) -> WriteReceipt:
        """登记撤回并级联处置：只阻断尚未发生的使用，已发生的保留并生义务。"""

        payload = {"actor_id": actor_id, "participant_id": participant_id, "purposes": purposes,
                   "effective_at": effective_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            participant_id = self._identifier(participant_id, "participant_id")
            participant_id = self._canonical(connection, participant_id)
            scope = {"all": purposes is None}
            if purposes is not None:
                scope["purposes"] = self._purposes(purposes)
            effective_at = self._timestamp(effective_at, "effective_at")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                withdrawal_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO withdrawals(withdrawal_id,participant_id,scope_json,effective_at,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?)",
                    (withdrawal_id, participant_id, canonical_json(scope), effective_at,
                     actor_id, now),
                )
                affected_apps: dict[str, Any] = {}
                if effective_at <= now:
                    wd = connection.execute("SELECT * FROM withdrawals WHERE withdrawal_id=?",
                                            (withdrawal_id,)).fetchone()
                    affected_apps = self._apply_withdrawal(connection, wd, actor_id)
                self._audit(connection, actor_id=actor_id, action="participant.withdrawn",
                            resource_type="withdrawal", resource_id=withdrawal_id,
                            detail={"participant_id": participant_id, "scope": scope,
                                    "effective_at": effective_at, "applied": effective_at <= now,
                                    "affected_applications": affected_apps})
                return "withdrawal", withdrawal_id, {"withdrawal_id": withdrawal_id,
                                                      "participant_id": participant_id,
                                                      "applied": effective_at <= now}

            return self._idempotent(connection, request_id=request_id, action="biobank.withdraw",
                                    payload=payload, create=create)

    def _auto_apply_due(self, actor_id: str) -> None:
        """在独立事务中应用到期撤回，确保级联不会随后续业务校验失败而回滚。"""

        with self.database.transaction(immediate=True) as connection:
            self._actor(connection, actor_id)
            self._apply_due_withdrawals(connection, now=self._now(), actor_id=actor_id)

    def apply_due_withdrawals(self, *, actor_id: str) -> dict[str, Any]:
        """主动应用所有已到生效时点的撤回（通常由定时维护调用）。"""

        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES, "auditor")
            count = self._apply_due_withdrawals(connection, now=self._now(), actor_id=actor_id)
            return {"applied": count}

    def withdrawal_impact(self, *, actor_id: str, withdrawal_id: str) -> dict[str, Any]:
        """列出撤回波及的未完成流程、已生义务与保留的既有授权。"""

        withdrawal_id = self._identifier(withdrawal_id, "withdrawal_id")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES, "auditor")
            wd = connection.execute("SELECT * FROM withdrawals WHERE withdrawal_id=?",
                                    (withdrawal_id,)).fetchone()
            if wd is None:
                raise NotFoundError("撤回通知不存在")
            participant_id = wd["participant_id"]
            scope = json.loads(wd["scope_json"])

            sample_ids = {row["sample_id"] for row in connection.execute(
                "SELECT sample_id FROM samples WHERE participant_id=?", (participant_id,))}
            pending: list[dict[str, Any]] = []
            for app in connection.execute(
                "SELECT * FROM access_applications WHERE status='pending' ORDER BY created_at"
            ):
                items = json.loads(app["items_json"])
                hit = [i for i in items if i["sample_id"] in sample_ids]
                if hit and (scope.get("all") or app["purpose"] in scope.get("purposes", [])):
                    pending.append({"application_id": app["application_id"],
                                    "purpose": app["purpose"],
                                    "researcher_actor_id": app["researcher_actor_id"],
                                    "samples": [i["sample_id"] for i in hit]})
            obligations = [dict(obligation_id=row["obligation_id"], application_id=row["application_id"],
                                kind=row["kind"], status=row["status"])
                           for row in connection.execute(
                               "SELECT * FROM obligations WHERE participant_id=? ORDER BY created_at",
                               (participant_id,))]
            # 撤回生效时将被释放（held）或已因撤回释放（released，查账本确认原因）的预留。
            affected_holds: list[dict[str, Any]] = []
            for row in connection.execute(
                "SELECT r.application_id, r.sample_id, r.quantity, r.consumed_qty, r.state, a.purpose "
                "FROM reservations r JOIN access_applications a "
                "ON r.application_id=a.application_id "
                "WHERE r.participant_id=? AND a.status IN ('approved','closed') AND ("
                "r.state='held' OR (r.state='released' AND EXISTS ("
                "SELECT 1 FROM sample_ledger l WHERE l.sample_id=r.sample_id "
                "AND l.ref_type='access_application' AND l.ref_id=r.application_id "
                "AND l.reason='withdrawn')))",
                (participant_id,),
            ):
                if scope.get("all") or row["purpose"] in scope.get("purposes", []):
                    affected_holds.append({"application_id": row["application_id"],
                                           "sample_id": row["sample_id"], "purpose": row["purpose"],
                                           "state": row["state"],
                                           "remaining_quantity": row["quantity"] - row["consumed_qty"]})
            retained = []
            for app in connection.execute(
                "SELECT a.application_id, a.purpose, a.status, b.basis_hash, a.released_at "
                "FROM access_applications a LEFT JOIN authorization_basis b "
                "ON a.application_id=b.application_id "
                "WHERE a.application_id IN (SELECT DISTINCT application_id FROM reservations "
                "WHERE participant_id=? AND consumed_qty>0)",
                (participant_id,),
            ):
                outputs = [dict(output_id=row["output_id"], kind=row["kind"], title=row["title"],
                                citation=row["citation"], basis_hash=row["basis_hash"])
                           for row in connection.execute(
                               "SELECT * FROM research_outputs WHERE application_id=?",
                               (app["application_id"],))]
                retained.append({"application_id": app["application_id"], "purpose": app["purpose"],
                                 "status": app["status"], "basis_hash": app["basis_hash"],
                                 "released_at": app["released_at"], "outputs": outputs})
            return {"withdrawal_id": withdrawal_id, "participant_id": participant_id, "scope": scope,
                    "effective_at": wd["effective_at"], "applied_at": wd["applied_at"],
                    "pending_applications": pending,
                    "affected_holds": affected_holds,
                    "open_obligations": [o for o in obligations if o["status"] == "open"],
                    "discharged_obligations": [o for o in obligations if o["status"] == "discharged"],
                    "retained_prior_use": retained}

    def discharge_obligation(self, *, actor_id: str, obligation_id: str) -> dict[str, Any]:
        obligation_id = self._identifier(obligation_id, "obligation_id")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES)
            row = connection.execute("SELECT * FROM obligations WHERE obligation_id=?",
                                     (obligation_id,)).fetchone()
            if row is None:
                raise NotFoundError("处置义务不存在")
            if row["status"] == "discharged":
                return {"obligation_id": obligation_id, "status": "discharged"}
            now = self._now()
            connection.execute(
                "UPDATE obligations SET status='discharged', discharged_at=? WHERE obligation_id=?",
                (now, obligation_id),
            )
            self._audit(connection, actor_id=actor_id, action="obligation.discharged",
                        resource_type="obligation", resource_id=obligation_id,
                        detail={"application_id": row["application_id"], "kind": row["kind"]})
            return {"obligation_id": obligation_id, "status": "discharged",
                    "application_id": row["application_id"], "kind": row["kind"]}

    # ----------------------------------------------------------------- 成果

    def record_output(self, *, request_id: str, actor_id: str, application_id: str,
                      kind: str, title: str, citation: str,
                      published_at: str | None = None) -> WriteReceipt:
        """登记论文等成果并固化其授权依据；撤回不追溯删除既有成果。"""

        payload = {"actor_id": actor_id, "application_id": application_id, "kind": kind,
                   "title": title, "citation": citation, "published_at": published_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES)
            application_id = self._identifier(application_id, "application_id")
            basis = connection.execute(
                "SELECT * FROM authorization_basis WHERE application_id=? ORDER BY basis_version DESC LIMIT 1",
                (application_id,),
            ).fetchone()
            if basis is None:
                raise NotFoundError("只有已批准（具有授权依据）的申请才能登记成果")
            kind = self._text(kind, "kind", 40)
            title = self._text(title, "title")
            citation = self._text(citation, "citation", 500)
            published_at = self._timestamp(published_at, "published_at")

            def create() -> tuple[str, str, dict[str, Any]]:
                output_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO research_outputs(output_id,application_id,kind,title,citation,"
                    "published_at,basis_hash,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (output_id, application_id, kind, title, citation, published_at,
                     basis["basis_hash"], actor_id, self._now()),
                )
                self._audit(connection, actor_id=actor_id, action="output.recorded",
                            resource_type="research_output", resource_id=output_id,
                            detail={"application_id": application_id, "kind": kind,
                                    "basis_hash": basis["basis_hash"]})
                return "research_output", output_id, {"output_id": output_id,
                                                      "basis_hash": basis["basis_hash"]}

            return self._idempotent(connection, request_id=request_id, action="biobank.record_output",
                                    payload=payload, create=create)

    # ------------------------------------------------------------- 查询与解释

    def explain_application(self, *, actor_id: str, application_id: str) -> dict[str, Any]:
        """解释一次访问为何获准或阻止；待审批申请给出当前时点的预演。"""

        application_id = self._identifier(application_id, "application_id")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *ETHICS_ROLES, "auditor")
            app = connection.execute("SELECT * FROM access_applications WHERE application_id=?",
                                     (application_id,)).fetchone()
            if app is None:
                raise NotFoundError("访问申请不存在")
            if app["status"] == "pending":
                evaluation = self._evaluate(connection, app, self._now())
                return {"application_id": application_id, "status": "pending",
                        "prospective": True, **evaluation}
            checks = json.loads(app["decision_reason_json"]) if app["decision_reason_json"] else []
            basis_row = connection.execute(
                "SELECT * FROM authorization_basis WHERE application_id=? ORDER BY basis_version DESC LIMIT 1",
                (application_id,),
            ).fetchone()
            return {
                "application_id": application_id,
                "status": app["status"],
                "prospective": False,
                "evaluated_at": app["decided_at"],
                "checks": checks,
                "basis": None if basis_row is None else {
                    "basis_version": basis_row["basis_version"],
                    "basis_hash": basis_row["basis_hash"],
                    **json.loads(basis_row["basis_json"]),
                },
            }

    def get_sample(self, *, actor_id: str, sample_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES, "auditor")
            sample_id = self._identifier(sample_id, "sample_id")
            row = connection.execute("SELECT * FROM samples WHERE sample_id=?", (sample_id,)).fetchone()
            if row is None:
                raise NotFoundError("样本不存在")
            return self._sample_view(connection, row)

    @staticmethod
    def _sample_view(connection, row) -> dict[str, Any]:
        held = connection.execute(
            "SELECT COALESCE(SUM(quantity-consumed_qty),0) AS held FROM reservations "
            "WHERE sample_id=? AND state='held'", (row["sample_id"],),
        ).fetchone()["held"]
        return {"sample_id": row["sample_id"], "participant_id": row["participant_id"],
                "parent_sample_id": row["parent_sample_id"], "site_id": row["site_id"],
                "material_type": row["material_type"], "unit": row["unit"],
                "quantity_total": row["quantity_total"], "quantity_reserved": row["quantity_reserved"],
                "quantity_consumed": row["quantity_consumed"],
                "quantity_available": row["quantity_total"] - row["quantity_reserved"]
                - row["quantity_consumed"],
                "open_holds_recomputed": held, "status": row["status"]}

    def sample_conservation(self, *, actor_id: str, sample_id: str | None = None) -> dict[str, Any]:
        """逐样本核对：余量非负、预留/消耗与预留表和账本一致、跨分装总量守恒。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *STAFF_ROLES, "auditor")
            query = "SELECT * FROM samples"
            parameters: list[Any] = []
            if sample_id is not None:
                query += " WHERE sample_id=?"
                parameters.append(self._identifier(sample_id, "sample_id"))
            rows = connection.execute(query + " ORDER BY sample_id", parameters).fetchall()
            if sample_id is not None and not rows:
                raise NotFoundError("样本不存在")
            # 家族树始终基于全库样本构建，单样本查询时也要能追溯到最初登记量。
            all_rows = connection.execute("SELECT * FROM samples").fetchall()
            views: list[dict[str, Any]] = []
            balanced = True
            by_id = {row["sample_id"]: row for row in all_rows}

            def root_of(sample_id: str) -> str:
                seen: set[str] = set()
                current = sample_id
                while True:
                    row = by_id.get(current)
                    parent = row["parent_sample_id"] if row is not None else None
                    if parent is None or parent not in by_id:
                        return current
                    if current in seen:
                        return current
                    seen.add(current)
                    current = parent

            families: dict[str, list] = {}
            for row in rows:
                families.setdefault(root_of(row["sample_id"]), []).append(row)
            family_totals: dict[str, float] = {}
            for root_id, members in families.items():
                family_totals[root_id] = sum(member["quantity_total"] for member in members)

            for row in rows:
                agg = connection.execute(
                    "SELECT COALESCE(SUM(CASE WHEN state='held' THEN quantity-consumed_qty ELSE 0 END),0)"
                    " AS held, COALESCE(SUM(consumed_qty),0) AS consumed "
                    "FROM reservations WHERE sample_id=?",
                    (row["sample_id"],),
                ).fetchone()
                ledger = connection.execute(
                    "SELECT COALESCE(SUM(delta_total),0) AS total, "
                    "COALESCE(SUM(delta_reserved),0) AS reserved, "
                    "COALESCE(SUM(delta_consumed),0) AS consumed FROM sample_ledger WHERE sample_id=?",
                    (row["sample_id"],),
                ).fetchone()
                root_id = root_of(row["sample_id"])
                registered_row = connection.execute(
                    "SELECT COALESCE(SUM(delta_total),0) AS total FROM sample_ledger "
                    "WHERE sample_id=? AND reason='registered'", (root_id,),
                ).fetchone()
                # 跨分装守恒：整棵分装树现存总量之和必须等于最初登记量。
                family_preserved = (root_id != row["sample_id"]) or abs(
                    family_totals[root_id] - registered_row["total"]) <= _EPS
                checks_local = {
                    "available_non_negative": row["quantity_total"] - row["quantity_reserved"]
                    - row["quantity_consumed"] >= -_EPS,
                    "reserved_matches_reservations": abs(row["quantity_reserved"] - agg["held"]) <= _EPS,
                    "consumed_matches_reservations": abs(row["quantity_consumed"] - agg["consumed"]) <= _EPS,
                    "reserved_matches_ledger": abs(row["quantity_reserved"] - ledger["reserved"]) <= _EPS,
                    "consumed_matches_ledger": abs(row["quantity_consumed"] - ledger["consumed"]) <= _EPS,
                    "total_matches_ledger": abs(row["quantity_total"] - ledger["total"]) <= _EPS,
                    "family_total_preserved": family_preserved,
                }
                ok = all(checks_local.values())
                balanced = balanced and ok
                views.append({"sample_id": row["sample_id"], "parent_sample_id": row["parent_sample_id"],
                              "root_sample_id": root_id,
                              "total": row["quantity_total"], "reserved": row["quantity_reserved"],
                              "consumed": row["quantity_consumed"],
                              "available": row["quantity_total"] - row["quantity_reserved"]
                              - row["quantity_consumed"],
                              "family_total": family_totals[root_id],
                              "checks": checks_local, "balanced": ok})
            return {"balanced": balanced, "samples": views}
