# 图模型 v3 设计稿 —— 两层事实(实体结构 + 无损事件)+ 告警 + 经验

> 状态:**草案,待用户过目定稿**。定稿后重构 `model/graph_model.json` + 接入层 mapper + 重灌图。
> 本稿**取代 v2**(`design-v2.md`)。v2 把"分类型观测节点"当作图的**唯一结构**、路径全从观测节点穿——
> 会造成路径查询笛卡尔积爆炸(A-B 100 边 × B-C 100 边 = 1万条路径,变长路径搜索跑死),
> 且观测节点星型化 ≈ 拿节点存日志。v3 分层:**聚合关系边扛结构/路径,事件节点扛无损细节**,两者并存互不干扰;
> 告警之后再接**经验层(研判/处置结论)**沉淀历史。

---

## 0. 硬需求(用户反复强调,是一切前提,不得违背)
1. **图里数据无损** —— 凡进图的事件,每一次 occurrence 全字段保留;不聚合掉、不砍字段、不 offload 到 ES。
2. **Agent 只从图取证** —— 绝不回 ES;图必须自足。(为此把图放在靶场 server1。)
3. **用图去取证,不是取证完再灌图** —— 图 = 取证的**输入底座(全量原始事实)**,不是把分析结论回填的输出库。
4. **入图门槛(过滤,与"无损"是两件事)** —— 一个事件要进图,须同时:① 能解析成实体、② 对取证有用。
   噪声(海量 4624/4634 登录流水那种)、解析不进来的、对取证毫无帮助的 → **根本不进图,绝不强行拿节点装**。
   现 pipeline 的 noise-drop + unmapped-drop 已经这么做,**过滤逻辑正确、保留;v3 只改模型表示,不改过滤**。

**事实层 vs 分析概念的边界(修正版):**
- **事实层(事件/实体/聚合边)保持纯净** —— `pattern_key` / 快慢通道路由 / 相似召回**机制**等 Agent 运行时概念**不进事实层**。
- **但研判结论、处置结论要进图** —— 作为挂在告警之后的**经验层(§7)**,供 Agent 复用历史、自进化。
- 二者不矛盾:**事实层是取证输入**(先在图里、用来查);**经验层是研判产出**(查完写回,叠加在告警之后)。

---

## 1. 全局:两层事实 + 告警 + 经验
```
实体层(结构的名词) ── Host / Account / Process / File / IP / Service / …(强键去重,持久)
      ▲                         ▲
      │ 聚合关系边(结构/路径层)  │   一对实体·一种谓语 = 一条边,带 count/first/last
      └───[:ACCESSED {count,…}]─┘   ← 路径查询只走这层,不爆炸

事件层(无损的细节)  ── (:Event {time, 少量标量})  每次 occurrence 一个,只存"何时"
      -[:BY]→ 主语实体      -[:<谓语>]→ 宾语实体     (-[:FROM]→IP / -[:ON_HOST]→Host … 次要参与者)

告警层(检测产物)   ── (:Event)-[:TRIGGERED]→(:Alert)-[:INDICATES]→(:Technique)

经验层(研判/处置产出)─ (:Alert)-[:CONCLUDED]→(:Verdict)-[:LED_TO]→(:Disposition)-[:ON]→(实体)   历史经验,供复用
```
节点种类,永不混表:**实体 · 事件 · 告警 · 技战术 · 研判结论(Verdict) · 处置结论(Disposition)**。

**边命名原则(用户定):精简、尽量不含宾语名词** —— 边指向的节点标签已表明宾语,故 `TRIGGERED`(→:Alert)不叫 `TRIGGERED_ALERT`、`ACCESSED`(→DirectoryObject)不叫 `ACCESSED_OBJECT`、`REQUESTED`(→服务/CA)不叫 `REQUESTED_TICKET`。介词保留(`AUTHENTICATED_TO`/`CONNECTED_TO` 里的 TO 不是宾语)。

---

## 2. 实体节点(名词,结构的承载者)
持久、强键去重、跨事件共享(同一账号/主机/进程在所有事件里是同一节点)。**语义信息主要落在实体上**。

初版实体类型(取自真实 ES 校准 + OCSF/ECS 词汇):
`Host / Account / Group / Process / File / RegistryKey / RegistryValue / IPAddress / Domain / Service / LogonSession / Certificate / DirectoryObject / Ticket / Uri / Module`

强键(实测存在,跨事件缝合可行):Process=`ProcessGuid`;LogonSession=`LogonGuid`/`TargetLogonId`;Account=`SID`(兜底 upn/sam);Host=计算机名 FQDN;IPAddress=`ip`;File=`path`(+hash);WafHit 关联=`transaction.unique_id`。

---

## 3. 事件节点(动词的一次发生 = 无损细节层)
**每一次 occurrence 一个节点。节点本身只存"何时"(`time`)+ 个别本次独有、非实体的标量**(如 `granted_access`、`enc_type`、`logon_type`)。**单一 `:Event` 标签**即可。

> 为什么单 `:Event` 在这里**不是**当初骂的"偷懒 blob":blob 坏在把一切**塞进**节点;这里相反,节点几乎空,
> **一切语义被推出到边和实体上** —— 谓语在边的类型上、参与者是实体。方向完全相反。

**边(主谓宾 + 次要参与者):**
- `(:Event)-[:BY]→(主语实体)` —— 谁做的(actor)。**主语边**。
- `(:Event)-[:<谓语>]→(宾语实体)` —— **边的类型就是谓语/动词**(ACCESSED / SPAWNED / AUTHENTICATED_TO / REQUESTED / CONNECTED_TO …)。**谓语边**。
- `(:Event)-[:FROM]→(IPAddress)` / `-[:ON_HOST]→(Host)` / …—— **次要参与者边**(多元事件用,参与者仍是实体,保无损、可 pivot)。

例(Sysmon EID10,rundll32 访问 lsass):
```
(:Event {time:10:01, granted_access:0x1fffff, call_trace:…})
    -[:BY]→        (:Process {rundll32, guid})
    -[:ACCESSED]→  (:Process {lsass, guid})
    -[:ON_HOST]→   (:Host {castelblack})
```
例(4769 Kerberoast,多元):
```
(:Event {time, enc:RC4})
    -[:BY]→        (:Account {vagrant@NORTH})     主语
    -[:REQUESTED]→ (:Account {sam:jon.snow})      宾语(服务账号)
    -[:FROM]→      (:IPAddress {::1})             次要参与者
    -[:ON_HOST]→   (:Host {winterfell})           次要参与者(DC)
```
**时间线天然在图里**:某实体挂的事件节点按 `time` 排 = 它的时间线;攻击链 = 沿共享实体把事件按时序走一遍。

---

## 4. 聚合关系边(结构/路径层 —— 躲开笛卡尔积爆炸)
**一对实体、每种谓语,只一条聚合边**;边上带从所有该类 occurrence 汇总出的统计:`count / first_seen / last_seen`。
```
(:Process rundll32) -[:ACCESSED {count:60, first_seen, last_seen}]→ (:Process lsass)
```
- **路径查询只走这层** → 一对实体一条边,变长路径不笛卡尔积、不爆炸。
- 谓语用**同一套词表**(§5),与事件节点的谓语边同名。
- **事件 ↔ 聚合边的归属靠"谓语 + 端点"推出,不用存指针**:
  "`A-[:ACCESSED]→B` 背后是哪些事件?" = `MATCH (e:Event)-[:BY]→(A), (e)-[:ACCESSED]→(B) RETURN e`。
  → 这正是那个"A-B 之间两条不同聚合边、100 个事件挂着分不清谁归谁"的解:**谓语在事件的宾语边上,按谓语类型即可分开**。谓语一旦从边上拿掉、只剩时间,才会分不清——所以"只存时间"必须配"谓语在边上"。
- 统计初版只放 `count/first/last`;`distinct 源IP集合`、`max 权限` 这类摘要**先不放**(全量细节本就在事件节点里,随时能算),真有高频查询卡住再往边上加。

---

## 5. 谓语/聚合边词表(事件类型 → 谓语 → 主宾 + 次要参与者)
受控、可扩展登记表。初版(取自真实 winlogbeat 事件清单;mapper 重写时逐类补全/校准)。**谓语名精简、不含宾语名词:**

| 来源事件 | 谓语(聚合边) | 主语 `:BY` | 宾语 `:<谓语>` | 次要参与者 |
|---|---|---|---|---|
| ProcessCreate (Sysmon 1) | `SPAWNED` | 父 Process | 子 Process | ON_HOST;子进程结构边 RAN_AS→Account |
| ProcessAccess (Sysmon 10) | `ACCESSED` | 源 Process | 目标 Process | ON_HOST |
| ImageLoad (Sysmon 7) | `LOADED` | Process | Module | ON_HOST |
| FileCreate (Sysmon 11) | `WROTE` | Process | File | ON_HOST |
| RegistrySet (Sysmon 13) | `SET` | Process | RegistryValue | ON_HOST |
| NetworkConnect (Sysmon 3) | `CONNECTED_TO` | Process | IPAddress | ON_HOST |
| DnsQuery (Sysmon 22) | `QUERIED` | Process | Domain | ON_HOST |
| Authentication (4624/4625/4768) | `AUTHENTICATED_TO` | Account | Host | FROM→IP;LogonSession |
| CredentialRequest (4769 TGS) | `REQUESTED` | 请求者 Account | 服务 Account/Service | FROM→IP;ON_HOST→DC(enc 作事件标量) |
| NTLM (4776) | `AUTHENTICATED_TO` | Account | Host(Workstation) | — |
| DirectoryAccess (4662) | `ACCESSED` | Account | DirectoryObject | ON_HOST |
| CertRequest (4886/4887) | `REQUESTED` | Account | Service(CA) | ON_HOST(request_type 作事件标量) |
| GroupManagement (4728/4732/4756) | `ADDED` | 操作 Account | 被加 Account | TO→Group |
| ScriptExec (PowerShell 4104) | `EXECUTED` | Process/Account | 脚本块(File/Uri 摘要) | ON_HOST(弱关联) |
| WafHit(=告警,见 §6) | 不是事件,是 Alert | — | — | — |

> 谓语命名原则:**业界可读动词、不含宾语名词**;同一语义合并(4624/4768→AUTHENTICATED_TO;票据/证书请求都→REQUESTED,靠宾语类型 + 事件标量区分)。新增事件 = 加一行登记表,不改 schema。

---

## 6. 告警层(检测产物,单一溯源入口)
```
(:Event 触发它的那一条) -[:TRIGGERED]→ (:Alert) -[:INDICATES]→ (:Technique)
```
- **一条告警 = 一个触发事件 = 一个溯源入口**(唯一)。研判永远从这一个明确的点起步;实体经该事件的 BY/谓语/次要边**一跳可达**,告警自身不直接乱挂一堆实体。
- **告警是检测产物、不是事实** → 挂在触发它的**事实(事件)**旁边。Alert 保持精简:入边 `TRIGGERED` + 出边 `INDICATES→Technique`。
- **`TRIGGERED` 永不落空**:Wazuh/WAF 告警 payload **自带底层事件全量数据**;哪怕那条事件平时被当噪声没单独入图,**告警会用自己 payload 把触发事件补成一个 `:Event` 节点**(按 event_uid MERGE:图里已有就并、没有就新建)。→ 每条告警恒有且仅有一条触发事件。
- `WafHit` / Suricata / Wazuh 规则命中 **都是 Alert**(不是观测)。其触发事件分别 = 那条 HTTP 请求 / 那条流 / 那条主机事件。

---

## 7. 经验层(研判结论 + 处置结论 = 图里的历史经验)
Agent 调查完把**结论写回图**,挂在告警之后,沉淀为可查询、可复用的经验(自进化的载体)。

```
(:Alert) -[:CONCLUDED]→ (:Verdict) -[:LED_TO]→ (:Disposition) -[:ON]→ (实体 Host/Account/IPAddress)
```
- **`(:Verdict)` 研判结论**:`verdict`(true_positive/false_positive/benign/suspicious…)、`confidence`、`summary/rationale`(研判依据)、`investigated_at`、`agent`(版本/标识)。
- **`(:Disposition)` 处置结论**:`action`(block_ip/isolate_host/disable_account/kill_process/none…)、`target`、`status`(proposed/executed/failed)、`decided_at`、`by`(auto/analyst)。
- **`-[:ON]→ 实体`**:处置作用在哪个实体上 → "这台主机被隔离过几次""这个 IP 被封过没"可从实体一跳查到。

**这是唯一"取证后写回图"的东西,且与硬需求#3不冲突:** 事实层(事件/实体/聚合边)始终是**取证输入**(先在图、用来查);经验层是**研判产出**,叠加在告警之后,不替代事实取证。相似召回/快慢通道等**机制**仍在 Agent 运行时,图里只沉淀**结论节点**作为经验。

**经验怎么被复用:** 新告警进来 → 顺 `TRIGGERED→事件→实体` 找到涉及实体 → 从实体一跳看它历史上的 `Alert/Verdict/Disposition` → 把过去"同类告警怎么判、怎么处置"作为先例喂给 Agent。图天然连通:实体 ← 事件 ← 告警 ← 研判 ← 处置。

---

## 8. 研判走法(全程只在图里)
```
告警 →(反查 TRIGGERED)触发事件 →(BY/谓语/次要边)涉及实体
     →(聚合关系边)pivot 到相关实体/事件 →(事件按 time)还原时序/攻击链
     →(实体一跳)看历史 Verdict/Disposition 经验 →(研判后)写回 Verdict/Disposition
```
告警是发令枪,事件节点是案发现场,实体是当事人,聚合边是地图,事件的 time 是时间线,经验层是判例库。Agent 不碰 ES。

---

## 9. 体量与迁移
- **体量**:事件节点数 ≈ 入图事件数(无损的物理下限),靠**已建的 30 天留存窗口**扛(窗口内无损),不靠丢数据/不靠回 ES。聚合边一对实体一条,不随频次增长。经验层(Verdict/Disposition)与身份实体一样**长期保留**(判例不随事件裁掉)。
- **迁移 = 必须重新入图**:模型从 v1.1 单 `:Event`(角色边 Event→Object)彻底变为"实体 + 事件(BY/谓语)+ 聚合边 + 告警 + 经验"。需 wipe + 全量 backfill(mapper 按本稿重写)+ 新增告警入图。

---

## 10. 待办(定稿后)
1. 重写 `model/graph_model.json` 为 v3(实体/事件/聚合边/告警/经验 + §5 词表 + 边命名原则)。
2. 重写 soc-graph-ingest mapper:每类事件 → 建事件节点(BY/谓语/次要边)+ upsert 聚合边(count/first/last)。
3. 新增告警入图:读 `soc-hids-alert-*` / WAF → materialize 触发事件 + `TRIGGERED` + `INDICATES`。
4. 经验层落地(Agent 侧,server2):研判/处置完写回 `Verdict`/`Disposition`(留存永久)。
5. wipe + 全量重灌 + tail/留存沿用。
6. §5 词表逐类补全/校准(mapper 重写时对真实样本核对主谓宾)。
