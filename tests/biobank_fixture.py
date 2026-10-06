"""参与者权益域的测试夹具。"""

from datetime import datetime, timezone

from science_strategy_foundation.clock import FixedClock
from science_strategy_foundation.participant_service import ParticipantService
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database


class BioBankFixture:
    """构建一个两中心联盟的最小完整环境。"""

    def __init__(self, clock: FixedClock | None = None) -> None:
        self.database = Database()
        self.clock = clock or FixedClock(datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc))
        self.service = DomainService(self.database, self.clock)
        self.participants = ParticipantService(self.database, self.clock)
        self.service.register_organization(request_id="org-1", actor_id="bootstrap",
                                           organization_id="o1", name="研究联盟")
        self.service.register_actor(request_id="actor-admin", actor_id="bootstrap",
                                    new_actor_id="admin1", display_name="管理员",
                                    role="admin", organization_id="o1")
        for actor_id, display, role in [
            ("op1", "甲中心样本管理员", "operator"),
            ("op2", "乙中心样本管理员", "operator"),
            ("rev1", "伦理审查员", "reviewer"),
            ("res1", "研究员甲", "researcher"),
            ("res2", "研究员乙", "researcher"),
            ("au1", "审计员", "auditor"),
        ]:
            self.service.register_actor(
                request_id=f"actor-{actor_id}", actor_id="admin1", new_actor_id=actor_id,
                display_name=display, role=role, organization_id="o1")
        self.service.register_site(request_id="site-a", actor_id="op1", site_id="siteA",
                                   organization_id="o1", name="甲中心",
                                   timezone_name="Asia/Shanghai")
        self.service.register_site(request_id="site-b", actor_id="op2", site_id="siteB",
                                   organization_id="o1", name="乙中心",
                                   timezone_name="Asia/Shanghai")

    def close(self) -> None:
        self.database.close()
