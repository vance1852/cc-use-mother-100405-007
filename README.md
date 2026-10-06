# 保护重大疾病研究样本权益协作服务

本项目提供科技创新协作场景共用的服务端基础能力，用于登记科研机构、创新节点、操作者和结构化业务资料，并提供角色权限、请求幂等、SQLite 事务与哈希串联审计。重大项目、科研证据、成果转化和国际合作等领域可以在这些稳定边界上扩展自己的状态、规则和接口。

在此基础上，项目实现了**研究参与者权益与样本使用协作域**：多家医院联合开展重大疾病队列研究时，用不可逆身份映射把知情同意版本、研究方案、用途范围、伦理许可、样本分装、数据集、访问申请、撤回通知和成果引用串联到同一参与者，按“当时有效”的授权原子预留样本，最小披露防止研究方反查身份。

## 核心规则

- **不可逆身份映射**：中心本地编号只以加盐 HMAC 摘要落库（`subject_links.code_hash`），服务无法反查原始编号；同一编号重复登记不会产生第二人，两个中心的不同编号可通过参与者合并归并。
- **时点授权**：审批按决策时点有效的同意版本（签署时间、用途集合、被取代时间）与伦理许可（有效期、中心范围、用途）逐项判定；授权依据（同意版本、许可、逐项检查、样本项）固化为 `authorization_basis` 并计算 `basis_hash`。
- **原子预留**：审批在单个 `BEGIN IMMEDIATE` 事务内重算各样本未消耗预留余量并写入预留，数据库触发器保证余量非负且预留+消耗不超过总量；重复内容申请以指纹部分唯一索引拦截，并发批准必有一方因余量不足被阻止。
- **前瞻效力**：补签、用途变更、部分消耗、中心合并与参与者撤回只影响尚未发生的使用；既有预留消耗、已发放数据集和论文保留当时的授权依据，并生成销毁数据/停止使用等后续处置义务。未来生效的撤回在生效时点（或审批/发放/消耗前自动应用）才释放预留。
- **最小披露**：发放清单只含按申请隔离的研究化名与分装码（同一参与者在不同申请中化名不同，且无法回溯中心编号或参与者主键）。
- **可解释与可核对**：
  - `GET /access-applications/{id}/explanation` 返回逐项原子检查与固化授权依据；
  - `GET /withdrawals/{id}/impact` 列出撤回波及的待审批申请、已批准预留、处置义务和保留的既往使用/成果；
  - `GET /sample-conservation` 逐样本核对余量、预留表与账本一致性，以及跨分装家族总量守恒。

## HTTP 接口（参与者权益域）

写入接口均通过 `X-Actor-Id` 标识操作者；除审批、发放、消耗、结案、履行义务外，写操作支持 `request_id` 幂等。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/subject-links` | 登记中心本地编号的不可逆映射 |
| POST | `/participant-merges` | 合并重复参与者（资源归并到规范身份） |
| POST | `/consents` | 登记知情同意版本 |
| POST | `/protocols` | 登记研究方案 |
| POST | `/protocol-purpose-amendments` | 修订方案用途（仅向前有效） |
| POST | `/irb-approvals` | 登记伦理许可（可中心专属或联盟通用） |
| POST | `/samples` / `/sample-splits` | 登记样本 / 分装（家族总量守恒） |
| POST | `/datasets` / `/dataset-participants` | 登记数据集与成员 |
| POST | `/access-applications` | 提交访问申请（重复内容指纹拦截） |
| POST | `/access-applications/{id}/decide` | 伦理审批（原子预留或逐项阻断理由） |
| POST | `/access-applications/{id}/release` | 最小披露发放（不可重复发放） |
| POST | `/access-applications/{id}/consumptions` | 登记（可部分）实际消耗 |
| POST | `/access-applications/{id}/close` | 结案并退回未消耗预留 |
| POST | `/withdrawals` / `/withdrawals/apply-due` | 登记撤回（可未来生效）/ 应用到期撤回 |
| GET | `/withdrawals/{id}/impact` | 撤回波及范围与处置义务 |
| POST | `/obligations/{id}/discharge` | 履行处置义务 |
| POST | `/research-outputs` | 登记论文等成果并固化授权依据 |
| GET | `/access-applications/{id}/explanation` | 解释获准或阻止原因 |
| GET | `/samples/{id}` / `/sample-conservation` | 样本余量 / 数量守恒核对 |

角色：`operator`（样本管理员/中心操作）、`reviewer`（联盟伦理）、`researcher`（申请研究方）、`auditor`（只读审计）、`admin`。

## 目录

- `src/science_strategy_foundation/`：领域模型、SQLite 存储、权限服务、审计链、HTTP 路由、隐私原语和离线验收；
  - `participant_service.py`：参与者权益与样本使用域的全部业务规则；
  - `privacy.py`：不可逆编号映射、按申请隔离的化名与发放指纹；
- `tests/`：基础规则、事务边界、接口路由、隐私原语、并发预留和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.acceptance
```

验收命令会在临时 SQLite 数据库中完成：双中心不同编号归并、早期同意不含 AI 的阻断、当时有效同意/许可下的基础研究批准与原子预留、部分消耗、最小披露发放、撤回级联（未消耗预留退回、已发放数据生义务、既有论文保留授权依据）以及数量守恒核对。成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m science_strategy_foundation.api --database science_strategy.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。服务重启后 SQLite 中的业务状态、授权依据快照和审计历史继续保留。
