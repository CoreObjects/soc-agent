# 全场景图模型设计 · v0.3（可落库前 · 定稿候选）

> 迭代自 v0.2（已被取代）。v0.2 解决了**结构性**问题（事实/事件/富化/研判四分）；**v0.3 解决实现级：唯一性、方向语义、事件粒度、落库**。
> 依据研究：[`../research/alert-triage-methodology.md`](../research/alert-triage-methodology.md)。**本轮只做图模型，不含数据接入/Agent/实现。**

---

## 一、设计边界
- 稳定核心 + 场景扩展演进；不追求一次定义全世界；四类对象严格分层。
- **对象 vs 事件原则**：凡是动作、有时间、有"因果 vs 相关"之争或需跨源融合 → **事件化**（auth / dns / 目录访问 / **文件写 / 注册表改** / 网络 / http）；纯状态留作对象。
- **Observation 是逻辑抽象**（不一定作为图库真实标签）；**所有事件型节点必须携带 Observation 元字段**：`raw_ref, source, sensor, event_time, ingest_time, confidence`，外加 `event_uid`（唯一）与 `event_code`（类型）。

---

## 二、核心对象分层

### L1 观测事实层
**事实对象（状态/可复用）**
- **Host** — hostname, os, role, criticality, zone　（IP 经 `HAS_IP` 边）
- **Account** — sid, sam, upn, domain, type；**可变状态属性带时效** `{value, valid_from, valid_to, source}`：privileged / spn / delegation_flag / preauth_flag
- **Process** — process_guid, pid, image, command_line, start_time　[+obs]
- **File** — path, md5, sha256　[+obs]
- **RegistryKey** — hive, key_path, value_name（状态对象；改动经 RegistryEvent）
- **Ticket** — ticket_id / ticket_hash, kind(TGT/TGS/AS-REP), client_account, service_spn, enc_type, issue_time, expire_time, renew_until, flags, **s4u_flag**, forwardable　（凭据对象，可被 PtT 复用；**不承载请求动作**）
- **LogonSession** — logon_id, logon_guid, logon_type, start_time

**观测事件（动作，全部带 obs 元 + event_uid + event_code）**
- **AuthEvent** ★ — **event_code**(4624/4768/4769/…), **event_uid**, auth_type(AS/TGS/NTLM/interactive), protocol(Kerberos/NTLM), logon_type, status, failure_reason
- **DirectoryAccess** ★ — event_code(4662), event_uid, access_mask, properties, operation(replication/read/write)
- **DnsQuery** ★ — event_uid, query, query_type, answers[], rcode, ttl　（resolver 经 `SENT_TO` 边，resolver_ip 属性冗余）
- **NetworkFlow** — event_uid, src_port, dst_port, proto, bytes, start/end　（src/dst 经 FROM_IP/TO_IP 边）
- **HttpRequest** — event_uid, method, host_header, user_agent, params
- **FileWriteEvent** — event_uid, path, operation, time
- **RegistryEvent** ★新增 — event_uid, event_code, operation(set/delete/create), key_path, value_name, value_data, time
- **WafHit** — event_uid, rule_id, severity, payload

### L2 资源对象层
- **IPAddress** — ip, version, type(public/private), geo, asn, reputation, first_seen, last_seen
- **Domain** — fqdn, first_seen, reputation
- **Uri** — path, host
- **Service** ★（原 Service/Application 更名，去掉 `/`）— service_id, name, kind(web/db/spn/port), port, protocol, host_header
- **Application**（扩展）— app_id, name, system, owner
- **DirectoryObject** — dn, guid, object_class

### L3 富化知识层（进图；均加时效）
- **IoC** — kind, value, reputation, source
- **Technique** — attack_id(Txxxx), tactic
- **AssetProfile** — criticality, owner, os, patch, zone　`{valid_from, valid_to, source, updated_at}`
- **IdentityBaseline** — role, dept, usual_hours, geo, history　`{valid_from, valid_to, source, updated_at}`

### L4 研判产物层
- **Alert** — source, rule_id, severity, **pattern_key(IP无关)**, **techniques[]（冗余快照，权威以 `MAPS_TO` 边为准）**, raw_ref, time
- **ActivityCluster** — cluster_id, strategy, confidence, time_range, features（聚类结果，非真实攻击者）
- **【研判扩展层 · 保留模型位置，第一阶段可不落库】 Case / Finding** — 待 Agent 工作流明确后细化

---

## 三、核心关系

**归属/结构**：Process `ON_HOST` Host｜Process `RAN_AS` Account｜File `ON_HOST` Host｜RegistryKey `ON_HOST` Host｜Service `ON_HOST` Host｜Service `BELONGS_TO` Application｜Host `HAS_IP` IPAddress`{first_seen,last_seen,source}`｜Process `PARENT_OF` Process

**认证（AuthEvent 中转，Host 角色拆清）**：Account `PERFORMED` AuthEvent｜AuthEvent `OBSERVED_ON` Host（记录在哪台）｜AuthEvent `FROM_IP` IPAddress｜AuthEvent `FROM_HOST` Host（来源）｜AuthEvent `TARGET_HOST` Host（目标）｜AuthEvent `TARGET_SERVICE` Service｜AuthEvent `ESTABLISHED` LogonSession｜AuthEvent `REQUESTED`/`ISSUED` Ticket｜Ticket `FOR_SERVICE` Account/Service｜LogonSession `AUTHENTICATED_AS` Account｜LogonSession `ON_HOST` Host

**访问/写入（均事件化）**：Process `WROTE` FileWriteEvent｜FileWriteEvent `WROTE_FILE` File｜FileWriteEvent `ON_HOST` Host｜Process `MODIFIED` RegistryEvent｜RegistryEvent `TARGETS` RegistryKey｜RegistryEvent `ON_HOST` Host｜Account `PERFORMED` DirectoryAccess｜DirectoryAccess `TARGETS` DirectoryObject｜DirectoryAccess `ON_HOST` Host(DC)

**网络**：Process `OPENED` NetworkFlow｜NetworkFlow `FROM_IP`/`TO_IP` IPAddress｜NetworkFlow `TO_HOST` Host｜Host/Process `MADE_DNS_QUERY` DnsQuery｜DnsQuery `SENT_TO` IPAddress(resolver)｜DnsQuery `QUERIED` Domain｜Domain `RESOLVES_TO` IPAddress

**应用**：HttpRequest `FROM` IPAddress｜HttpRequest `TARGETS` Uri/Service｜HttpRequest `TO_DEST` Host/IPAddress｜WafHit `ON` HttpRequest｜HttpRequest `CORRELATED_WITH` FileWriteEvent

**映射/富化（知识）**：Alert `MAPS_TO` Technique｜IoC `MATCHES` IPAddress/Domain/File｜Host `HAS_PROFILE` AssetProfile｜Account `HAS_BASELINE` IdentityBaseline

**推理（带置信度）**：LogonSession `DERIVED_FROM` LogonSession`{confidence, evidence_keys, correlation_rule, time_window}`｜ActivityCluster `GROUPS` <observable>`{strategy, confidence}`｜Alert `ABOUT` <observable/event>

**研判产物（扩展层，延后）**：Case `ABOUT` Alert｜Case `HAS_FINDING` Finding｜Finding `SUPPORTED_BY` <evidence/event>｜Finding `MAPS_TO` Technique

---

## 四、连接键 vs 关联规则（拆开）

**A. 实体主键 / 连接键（事实性，可直接 JOIN）**
- **强键**：`event_uid`、`logon_guid`、`process_guid`、`sid`/`upn`（身份键）、`asset_id`
- **弱键**：`ip` / `target-ip`（SNAT/NAT 干扰，需佐证）
- **事件类型键**：`event_code` / `event_type`（4624/4769/4662/Sysmon EID —— **类型，非唯一**，不可当强键）

> **`event_uid` 生成规则**：`hash(source + sensor + record_id + event_time + raw_ref)` —— 保证每条原始事件唯一，杜绝海量 4624/4769 被 collapse 成一个。

**B. 时序 / 推理关联规则（非键，是规则/推断）**
- 时间窗口关联：`timestamp + SEQ within N`
- 派生指纹：`pattern_key`（告警指纹，IP 无关）、`attack technique id`（知识映射键）

---

## 五、典型告警覆盖校验（12 类，全闭合）

| 告警 | 承载方式 | 状态 |
|---|---|---|
| Kerberoast | Account(spn) ·PERFORMED· AuthEvent(TGS-REQ,enc=RC4) ·REQUESTED· Ticket(TGS)；4769 → Alert ABOUT | ✅ |
| AS-REP Roast | Account(preauth_flag=off,时效) · AuthEvent(AS-REQ no-preauth) ·ISSUED· Ticket(AS-REP)；4768 | ✅ |
| Pass-the-Ticket | AuthEvent(用 TGS 无前置 AS/TGT——时序规则) · LogonSession · logon_id | ✅ |
| Pass-the-Hash | AuthEvent(protocol=NTLM, logon_type=3/9, 无交互) · LogonSession | ✅ |
| **DCSync** | DirectoryAccess(operation=replication, access_mask=DS-Repl-Get-Changes) ·TARGETS· DirectoryObject ·ON_HOST· DC；Account PERFORMED；4662 | ✅ 硬证据 |
| **NTLM relay** | AuthEvent(protocol=NTLM) ·FROM_HOST/FROM_IP· + ·TARGET_HOST· + ·TARGET_SERVICE· + NetworkFlow 关联 | ✅（Host 角色拆清后可表达 relay 三方） |
| 委派滥用(约束/非约束) | AuthEvent(S4U2Self/Proxy) · Ticket(s4u_flag) · Account(delegation_flag,时效) | ✅ |
| Webshell | HttpRequest ·TARGETS· Service + WafHit ON；Process ·WROTE· FileWriteEvent ·WROTE_FILE· File；HttpRequest ·CORRELATED_WITH· FileWriteEvent | ✅ 相关非因果 |
| **注册表持久化**(RunKey/服务/IFEO/计划任务) | Process ·MODIFIED· RegistryEvent(set) ·TARGETS· RegistryKey ·ON_HOST· Host | ✅ 新增 |
| DNS beacon | DnsQuery(query_type/rcode/周期) ·SENT_TO· resolver + ·QUERIED· Domain + IoC(域信誉) | ✅ |
| 服务执行 | Process ·PARENT_OF·(services.exe→cmd.exe) + command_line | ✅ |
| 横向移动 | LogonSession ·DERIVED_FROM·{confidence} LogonSession + AuthEvent(远程登录) + logon_guid | ✅ |

---

## 六、v0.2 开放点 · 已定稿决策

1. **Ticket** = 凭据对象（补齐字段：ticket_id/hash、client_account、service_spn、issue/expire/renew、flags、s4u_flag、forwardable）；请求动作由 AuthEvent 承载。✅
2. **AssetProfile / IdentityBaseline** 加时效 `valid_from/valid_to/source/updated_at`。✅
3. **Case / Finding** 保留模型位置，标注"研判扩展层，第一阶段可不落库"。✅
4. **抽象基类**：仅文档层定义 Observation 元字段规范；实现层不强制真实继承（Nebula 无需继承）。✅

---
_评级：v0.3 = 可落库前定稿候选。待你最终 ✔ 后作为第一版定稿；之后才进数据接入 / Agent 设计。_
