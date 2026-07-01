# 全场景图模型设计 · v0.2（评审后收敛）

> 迭代自 v0.1（见 `design-v0.1.md`，已被本文件取代）。本版落实评审核心意见：
> **事实对象 ≠ 事件对象 ≠ 研判结论 ≠ 推理聚类** —— 四类分层，不再把事件语义塞进状态节点。
> 依据研究：[`../research/alert-triage-methodology.md`](../research/alert-triage-methodology.md)。**本轮只做图模型，不含数据接入/Agent/实现。**

---

## 一、设计边界

- 覆盖安全告警研判图谱的**稳定核心层**；**不追求一次定义全世界**。
- 演进方式：**稳定核心 + 场景扩展**（核心稳定不返工，新场景加实体/关系而非重构）。
- **建模第一原则**：四类对象严格分层——观测事实 / 资源对象 / 富化知识 / 研判产物。
- **对象 vs 事件边界原则**：**哪里有"因果 vs 相关"之争、或需跨源融合，就事件化**（auth / dns / 目录访问 / 文件写 / 网络 / http）；纯状态留作对象（host/account/process/file/registry/ticket/logon-session）。
- **通用 Observation 元字段**（所有证据/事件实体必带）：`raw_ref`（回原文指针）、`source`、`sensor`、`event_time`、`ingest_time`、`confidence`。

---

## 二、核心对象分层

### L1 观测事实层
**事实对象（状态/可复用实体，被事件引用）**
- **Host** — hostname, os, role(dc/member/…), criticality, zone　（IP 经 `HAS_IP` 边，不用数组）
- **Account** — sid, sam, upn, domain, type(user/service/computer)；**可变状态属性带时效** `{value, valid_from, valid_to, source}`：privileged / spn / delegation_flag / preauth_flag
- **Process** — process_guid, pid, image, command_line, start_time　[+obs 元]
- **File** — path, md5, sha256　[+obs 元]
- **RegistryKey** — path, value　[+obs 元]
- **Ticket** — kind(TGT/TGS/AS-REP), spn, enc_type　（凭据对象；请求/签发经 AuthEvent；可被 PtT 复用）
- **LogonSession** — logon_id, logon_guid, logon_type, start_time　（会话状态；建立经 AuthEvent）

**观测事件（动作，全部带 obs 元）**
- **AuthEvent** ★ — event_id, auth_type(AS/TGS/NTLM/interactive…), protocol(Kerberos/NTLM), logon_type, status, failure_reason
- **DirectoryAccess** ★ — event_id, access_mask, properties, operation(replication/read/write)　（4662）
- **DnsQuery** ★ — query, query_type, answers[], rcode, resolver_ip, ttl
- **NetworkFlow** — src/dst 经 FROM_IP/TO_IP 边, src_port, dst_port, proto, bytes, start/end
- **HttpRequest** — method, host_header, user_agent, params
- **FileWriteEvent** ★ — path, time　（Process 写文件的动作；替代武断的 WROTE_FILE）
- **WafHit** — rule_id, severity, payload

### L2 资源对象层（稳定被引用体，常跨事件去重）
- **IPAddress** ★ — ip, version, type(public/private), geo, asn, reputation, first_seen, last_seen
- **Domain** — fqdn, first_seen, reputation
- **Uri** — path, host
- **Service/Application** ★ — name, kind(web/db/spn-service/port-svc), port, host_header
- **DirectoryObject** — dn, guid, object_class　（DCSync 的目标；naming context / 对象）

### L3 富化知识层（进图，图上可关联查证）
- **IoC** — kind(ip/domain/hash/url), value, reputation, source
- **Technique** — attack_id(Txxxx), tactic
- **AssetProfile** — criticality, owner, os, patch, zone　（每 Host）
- **IdentityBaseline** — role, dept, usual_hours, geo, history　（每 Account）

### L4 研判产物层（研判/推理输出，非事实）
- **Alert** — source(waf/ndr/hids/edr/auth), rule_id, severity, **pattern_key(IP无关)**, techniques[], raw_ref, time
- **Case** — 研判工件（Alert→Case），verdict, confidence, timeline
- **ActivityCluster** ★（原 Actor 更名）— cluster_id, strategy, confidence, time_range, features　（聚类结果，非真实攻击者身份）
- **Finding** — 结论（真伪/技术归因），confidence

---

## 三、核心关系（按语义分类）

**归属/结构**：Process `ON_HOST` Host｜Process `RAN_AS` Account｜File `ON_HOST` Host｜RegistryKey `ON_HOST` Host｜Service `ON_HOST` Host｜Host `HAS_IP` IPAddress `{first_seen,last_seen,source}`｜Process `PARENT_OF` Process

**认证（经 AuthEvent 中转，不再用静态 REQUESTED）**：Account `PERFORMED` AuthEvent｜AuthEvent `ON_HOST` Host｜AuthEvent `FROM_IP` IPAddress｜AuthEvent `ESTABLISHED` LogonSession｜AuthEvent `REQUESTED`/`ISSUED` Ticket｜Ticket `FOR_SERVICE` Account/Service｜LogonSession `AUTHENTICATED_AS` Account｜LogonSession `ON_HOST` Host

**访问/写入**：Process `WROTE` FileWriteEvent → FileWriteEvent `WROTE_FILE` File｜Process `MODIFIED` RegistryKey｜Account `PERFORMED` DirectoryAccess｜DirectoryAccess `TARGETS` DirectoryObject｜DirectoryAccess `ON_HOST` Host(DC)

**网络**：Process `OPENED` NetworkFlow｜NetworkFlow `FROM_IP`/`TO_IP` IPAddress｜NetworkFlow `TO_HOST` Host｜Host/Process `MADE_DNS_QUERY` DnsQuery｜DnsQuery `QUERIED` Domain｜Domain `RESOLVES_TO` IPAddress

**应用**：HttpRequest `FROM` IPAddress｜HttpRequest `TARGETS` Uri/Service｜HttpRequest `TO_DEST` Host/IPAddress｜WafHit `ON` HttpRequest｜HttpRequest `CORRELATED_WITH` FileWriteEvent

**映射/富化（知识）**：Alert `MAPS_TO` Technique｜IoC `MATCHES` IPAddress/Domain/File｜Host `HAS_PROFILE` AssetProfile｜Account `HAS_BASELINE` IdentityBaseline

**推理（带置信度，非事实）**：LogonSession `DERIVED_FROM` LogonSession `{confidence, evidence_keys, correlation_rule, time_window}`｜ActivityCluster `GROUPS` <observable> `{strategy, confidence}`｜Alert `ABOUT` <observable/event>｜Case `ABOUT` Alert｜Finding `SUPPORTS` Case

---

## 四、连接键 vs 关联规则（拆开表达）

**A. 实体主键 / 连接键（事实性，可直接 JOIN）**
- 强键：`logon_id` / `logon_guid`、`process_guid`、`event_id`、`sid` / `upn`（身份键）、asset 主键
- 弱键：`ip` / `target-ip`（可被 SNAT/NAT 干扰，需佐证）

**B. 时序关联规则 / 推理关联规则（非键，是规则/推断）**
- 时间窗口关联：`timestamp + SEQ within N`（Kerberos 序列异常、beacon 周期）
- 派生指纹：`pattern_key`（告警指纹，IP 无关）、`attack technique id`（知识映射键）

> 区别：强/弱键是"同一事物"的事实标识；时间窗口与指纹是"可能相关"的推断——图里必须可区分，否则把推理当事实。

---

## 五、典型告警覆盖校验（11 类，全部闭合）

| 告警 | 承载方式 | 状态 |
|---|---|---|
| Kerberoast | Account(spn) ·PERFORMED· AuthEvent(TGS-REQ,enc=RC4) ·REQUESTED· Ticket(TGS)；4769 → Alert ABOUT | ✅ |
| AS-REP Roast | Account(preauth_flag=off,时效) · AuthEvent(AS-REQ no-preauth) ·ISSUED· Ticket(AS-REP)；4768 | ✅ |
| Pass-the-Ticket | AuthEvent(用 TGS 无前置 AS/TGT——时序规则) · LogonSession · logon_id | ✅ |
| Pass-the-Hash | AuthEvent(protocol=NTLM, logon_type=3/9, 无交互) · LogonSession | ✅（AuthEvent 带 protocol） |
| **DCSync** | DirectoryAccess(operation=replication, access_mask=DS-Repl-Get-Changes) ·TARGETS· DirectoryObject ·ON_HOST· DC；Account PERFORMED；4662 → Alert ABOUT | ✅（硬证据） |
| **NTLM relay** | AuthEvent(protocol=NTLM, 来源异常) ·FROM_IP· + NetworkFlow 关联 | ✅ |
| **委派滥用(约束/非约束)** | AuthEvent(S4U2Self/Proxy) · Ticket(s4u flag) · Account(delegation_flag,时效) | ✅ |
| Webshell | HttpRequest ·TARGETS· Service + WafHit ON；Process ·WROTE· FileWriteEvent ·WROTE_FILE· File；HttpRequest ·CORRELATED_WITH· FileWriteEvent → Alert ABOUT | ✅（相关非因果） |
| DNS beacon | DnsQuery(query_type/rcode/周期) ·QUERIED· Domain + IoC(域信誉)；Host/Process MADE_DNS_QUERY | ✅ |
| 服务执行 | Process ·PARENT_OF·(services.exe→cmd.exe) + command_line | ✅ |
| 横向移动 | LogonSession ·DERIVED_FROM·{confidence} LogonSession + AuthEvent(远程登录) + logon_guid | ✅ |

---

## 六、v0.2 仍待你确认的开放点

1. **Ticket 定位**：保留为"凭据对象"（可被 PtT 复用），签发/请求经 AuthEvent——确认这个语义对不对。
2. **富化知识层的更新频率/时效**：AssetProfile / IdentityBaseline 也是会变的，是否同样上 `valid_from/valid_to`？
3. **Case / Finding 是否本轮就要**，还是研判产物层 v1 先只要 Alert + ActivityCluster、Case/Finding 等 Agent 设计时再定？
4. 是否需要一个**抽象基类**（Observation / Entity）在实现层承载通用元字段，还是只在文档约定。

---
_下一步（本轮内）：据你确认收敛到 v0.3（或定稿）；模型稳定后才进数据接入/Agent。_
