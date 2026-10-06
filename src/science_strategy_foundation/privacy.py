"""实现不可逆身份映射与最小披露原语。

受试者在各中心的本地编号只以加盐 HMAC 摘要形式落库；服务无法从摘要反查
原始编号，只能在再次见到同一编号时识别它。研究方拿到的研究化名同样是
HMAC 派生值且按用途/申请隔离，跨数据集不可关联，也无法回溯到中心编号
或参与者主键。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from .audit import canonical_json

_PEPPER_LENGTH = 32


def generate_pepper() -> str:
    """生成数据库级别的身份映射随机盐。"""

    return secrets.token_hex(_PEPPER_LENGTH)


def subject_code_hash(pepper: str, site_id: str, local_code: str) -> str:
    """把中心本地编号映射为不可逆摘要。

    站点与编号一同参与哈希，避免不同中心的同号碰撞；原始编号无法恢复。
    """

    material = canonical_json({"site_id": site_id, "local_code": str(local_code).strip()})
    return hmac.new(pepper.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def research_pseudonym(pepper: str, application_id: str, participant_id: str) -> str:
    """为一次访问申请生成隔离的研究化名。

    化名与申请绑定：同一参与者在不同申请中得到不同化名，研究方无法跨
    数据集关联，也无法由化名反推参与者主键或中心编号。
    """

    material = canonical_json({"application_id": application_id, "participant_id": participant_id})
    digest = hmac.new(pepper.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()
    return "P-" + digest[:24].upper()


def release_fingerprint(pepper: str, value: Any) -> str:
    """对最小披露载荷计算带盐摘要，用于审计与去重。"""

    return hmac.new(pepper.encode("utf-8"), canonical_json(value).encode("utf-8"),
                    hashlib.sha256).hexdigest()
