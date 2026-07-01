# 全场景图模型 · v1.0 · 🔒 已锁定

> **权威定义 = [`../../model/graph_model.json`](../../model/graph_model.json)（单一事实源）。** 可视化：`../../model/graph-model.html`（`python scripts/build_graph_viz.py` 重生成）。
> 迭代史：v0.1 草案 → v0.2 结构分层 → v0.3 实现级收口 → v0.4 经验层 → **v1.0 锁定**（加 BusinessBaseline）。

## 规模
**32 个实体类型 · 62 条关系 · 5 层。** 12 类典型告警覆盖全闭合（见 JSON `alert_coverage`）。

## 五层
| 层 | 实体 |
|---|---|
| **L1 观测·对象** | Host, Account, Process, File, RegistryKey, Ticket, LogonSession |
| **L1 观测·事件** | AuthEvent, DirectoryAccess, DnsQuery, NetworkFlow, HttpRequest, FileWriteEvent, RegistryEvent, WafHit |
| **L2 资源** | IPAddress, Domain, Uri, Service, Application, DirectoryObject |
| **L3 富化知识** | IoC, Technique, AssetProfile, IdentityBaseline, **BusinessBaseline**, AttackPattern |
| **L4 研判产物** | Alert, ActivityCluster, Case, Finding, Experience |

## 三层检索能力
- **事实检索**：观测对象/事件 + 结构/认证/访问/网络/应用关系。
- **相似召回**：`AttackPattern` + `pattern_key` + `MATCHES_PATTERN`。
- **经验复用**：`Experience` + `Case/Finding` + `APPLIES_TO/HAS_EVIDENCE`。
- **正向基线**：`AssetProfile / IdentityBaseline / BusinessBaseline`（判"是否正常业务/正常身份/关键资产"）。

## 关键约束（实现时遵守）
- `event_uid = hash(source+sensor+record_id+event_time+raw_ref)` 为强键；`event_code`(4624/4769…) 只是类型键，**不可当强键**。
- 连接键分级：强键 / 弱键(ip) / 事件类型键 / 时序规则 / 派生指纹（pattern_key、technique_id 是指纹/映射键，非事实键）。
- 观测事件必带 Observation 元字段；可变状态属性(账号权限/SPN/委派、资产 IP、Profile/Baseline)带时效 `valid_from/valid_to/source/updated_at`。
- 经验复用 = **图召回相似 + RAG 读文本 + Agent 判适用**（不直接丢向量库）。

## 🔒 锁定含义
本模型作为第一版**定稿**。后续如需变更，走"稳定核心 + 场景扩展"：**只改 `graph_model.json` 再重生成视图**，不推倒。

## 下一步（不再改模型）
**逐 skill 深挖研究**：每类告警一个知识包（方法学 + 精确证据映射到本模型 + 判定规则 + DSL 查询模板），累积成研判 skill 库。建议从**应用层**起（研究最薄、最吃经验）。
