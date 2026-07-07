# 图模型 v2 设计稿 —— 分类型观测 + 告警(Finding)分层 · OCSF/ECS/ATT&CK 对齐

> 状态:**草案,待用户逐条过目定稿**。定稿后重构 `model/graph_model.json` + 接入层 mapper + 重灌图。
> 本稿是对 v1.1「单 :Event 超类泛化」的推翻重来 —— 那次把所有观测拍平成一个 Event + category 标签,
> 对"实体级精确溯源"是偷懒。v2 回到"每类观测是它自己的具体类型",地基取业界权威 schema,一次做全做对。

## 0. 动机(为什么推翻 v1.1)
- v1.1 单 `:Event` + category:观测被拍平成一坨,溯源时"这条告警从哪个具体实体切入"含糊;不是通用平台该有的粒度。
- 目标是**通用研判平台**,模型要能承载各种事件、不缺东少西;不能拿 GOAD 手头十类硬凑。
- 三条硬要求(用户反复强调):① 观测解析成**具体类型**、不是 Event blob;② 告警和观测**彻底分层**(WafHit=告警,不是观测);③ **一个告警一个溯源入口**,但要能挂到具体实体。

## 1. 权威地基(实测调研,非印象)
- **OCSF**(schema.ocsf.io,1.5/1.6):8 大 category → activity class;每事件 base_event = `actor(主)+activity_id(谓)+target(宾)+device(上下文)+observables[](可枢轴实体)`;**Findings(Cat 2)= 告警/检测**,经 `evidences→观测`、`observables→实体`、`attack→技术` 挂出去;内建 `observable/graph/node/edge` 原语。
- **ECS**:`event.kind` 顶层区分**观测 vs 告警**(event / alert / enrichment / asset / metric / state);`category×type` 行为矩阵;55 个字段组=实体词汇;`related.*`=pivot 键。
- **ATT&CK v18**(Data Sources 已废,改 **Data Component** 为观测原子 + Detection Strategy/Analytic 为检测层):每 Data Component=一个可观测事件类型,谓词收敛为 8 原语。
- 三套在"观测事件类型"上高度交集;强键 ProcessGuid/LogonGuid/SID 与我们 56.8 万条真实 ES 校准一致。

## 2. 原则
1. **入图节点只承载原始数据真有的属性**;下游分析概念(pattern_key/相似召回/研判结论/经验)不进事实模型,归 Agent 层。
2. **顶层按 `kind` 四分,永不混表**:观测 / 实体 / 告警 / 富化。
3. **观测 = 分类型的"活动"节点**(粒度=activity class,不是单 Event、也不是一 EID 一类);每类 = `主(actor实体)—谓(动作)—宾(target实体)`。
4. **谓词封闭 8 原语**:create · modify · delete · access · exec · enum · lifecycle(start/end) · authenticate。
5. **告警 = Finding**:`(:Alert)-[:ABOUT]→(:那一条触发观测)` 单一溯源入口;实体经该观测的 actor/target 挂上;`-[:INDICATES]→(:Technique)`。
6. **强键去重、跨观测共享实体**:同一账号/主机/进程在不同观测里是同一节点。

## 3. 四层(按 event.kind)
| 层 | kind | 内容 |
|---|---|---|
| **观测** | event / state | 分类型活动节点(§5) |
| **实体** | asset | 持久对象节点,强键(§6) |
| **告警** | alert | 探测器检测产物 = Finding(§7);WAF/IPS/NDR/HIDS |
| **富化** | enrichment | Technique(ATT&CK)/IoC/情报(§8) |

## 4. 观测节点通用信封
每个观测节点(不论类型)共有:`obs_uid`(强键,=v1 的 event_uid 规则 hash(source+host+sensor+native_record_id))、`obs_type`(见 §5)、`action`(8 原语之一)、`time`、`ingest_time`、`source`、`sensor`、`event_code`、`outcome`(success/fail/blocked/allowed)、`raw_ref`。**类型专属叶子属性**按类型定(见 §5)。节点 label = 具体观测类型(如 `:ProcessCreate`),不再是 `:Event`。

## 5. 观测节点类型清单(主谓宾 + 映射我们真实 EID)
> 收敛自 OCSF class × ATT&CK Data Component × ECS category。粒度=活动类。

### 进程域
| 类型(label) | 主 →谓→ 宾 | 真实来源 EID | 关键叶子属性 |
|---|---|---|---|
| `ProcessCreate` | Process(父)/Account →create→ Process(子) | Sysmon 1、Security 4688 | command_line、integrity_level、parent 链 |
| `ProcessAccess` | Process(源) →access→ Process(目标,如 lsass) | Sysmon 10、8(远程线程) | granted_access、call_trace |
| `ProcessTerminate` | (主体) →end→ Process | Sysmon 5 | — |
| `ModuleLoad` | Process →load→ Module | Sysmon 7 | signed、hash |
| `ScriptExec` | Process/Host →exec→ Script(文本叶子) | PowerShell 4104(+4103/4100) | script_block(超长,回取)|

### 文件 / 注册表域
| `FileActivity` | Process →create/modify/delete→ File | Sysmon 11/23/2 | target_filename、hashes |
| `RegistryActivity` | Process →create/set/delete→ RegistryKey/Value | Sysmon 12/13/14 | operation、value_data |

### 身份 / 认证域
| `Authentication` | Account →authenticate/logon→ Host/Service | 4624/4625(logon)、4776(NTLM) | logon_type、auth_protocol、**产出 LogonSession**、FROM IP |
| `SessionEnd` | Account →end→ LogonSession | 4634/4647 | logon_type |
| `CredentialRequest` | Account(请求者) →request→ Service(SPN)/Ticket | 4768(TGT)/4769(TGS)/4770(renew) | enc_type(0x17=RC4)、ticket_options |
| `ExplicitCredLogon` | Account →use-explicit-cred→ Host(目标,as Account) | 4648 | target_server(横向指标) |
| `CredentialAccess` | Account →read→ 凭据库 | 5379(vault)、5058-5061(key) | — |
| `AccountChange` | Account(管理员) →create/modify/delete→ Account | 4720/4722/4724/4738/4740/4767/4781、4741/4742(计算机) | uac、attributes |
| `GroupManagement` | Account(管理员) →add/remove/modify→ Group(+成员 Account) | 4727-4737/4754-4757 | member |
| `DirectoryAccess` | Account →access→ DirectoryObject | 4662(DCSync) | access_mask、properties(DS-Repl-Get-Changes) |
| `PrivilegeUse` | Account →assigned→ 特权 | 4672、4673/4674 | privilege_list(弱链上下文) |
| `AccountEnumeration` | Account →enum→ Account/Group | 4798/4799 | — |

### 证书 / ADCS 域
| `CertificateActivity` | Account(请求者) →request/issue/deny→ Service(CA)/Certificate | 4886/4887/4888、4898(模板) | template、request_id、disposition |

### 网络域
| `NetworkConnection` | Process/Host →connect→ IPAddress(目的);源 IP | Sysmon 3 | dest_port、protocol、direction(=一次会话) |
| `DnsQuery` | Process →query→ Domain;解析出 IP | Sysmon 22、DNS-Client 8010/1014 | query_results |
| `HttpRequest` | IPAddress(client) →request→ Uri/Service | nginx access / WAF transaction 的请求部分 | method、http_status、user_agent |
| `ShareAccess` | Account →access→ 网络共享 | (GOAD 暂无,SMB) | share_name |

### 配置 / 持久化域
| `ServiceActivity` | Account/Process →install/modify→ Service | System 7045(装)/7040、Sysmon | image_path、start_type |
| `ScheduledJobActivity` | Account/Process →create/modify→ 计划任务 | 4698/4699/4702、Sysmon 19-21(WMI) | task_name |
| `DriverLoad` | System →load→ Driver | Sysmon 6 | signed |

### 策略 / 抗取证域
| `PolicyChange` | Account →change→ 审计/域/信任策略 | 4719/4713/4739/4706/4716/4907 | policy |
| `LogClear` | Account →clear→ 审计日志(Host) | 1102/1100/1108 | (弱链) |

> **噪声/运维事件**(System 的 kernel/time/dhcp/boot、Sysmon 16 配置、PowerShell 引擎 40961/40962/53504 等)按接入层黑名单剔除,不入图 —— 沿用 v1 的 dropset 机制。

## 6. 实体节点类型(OCSF observable 词汇 + ECS 字段组)
持久、强键、跨观测共享:
`Host`(asset_id/hostname)· `Account`(sid/upn)· `Group`(sid)· `Process`(process_guid)· `File`(sha256 / path+host)· `LogonSession`(logon_guid/logon_id)· `IPAddress`(ip)· `Domain`(fqdn)· `Uri`(host+path)· `Service`(service_id;kind=web/mssql/certificate_authority…)· `Certificate`(thumbprint/serial)· `RegistryKey`/`RegistryValue`· `Module`(hash)· `DirectoryObject`(guid/dn)· `Ticket`(有真实物料时)· `Email`/`CloudResource`(未来扩)。

## 7. 告警层 = Finding(kind=alert)
- **`Alert`** 节点:`alert_uid`(hash(source+host+native_alert_id))、source(wazuh/waf/suricata/edr)、rule_id、rule_name、severity、technique_ids(原始快照)、disposition(blocked/detected)、time、raw_ref。**无 pattern_key**。
- 边(**一个告警一个溯源入口**):
  - `(:Alert)-[:ABOUT]→(:观测)` —— **只连它触发的那一条观测**(Wazuh 用 eventRecordID+computer 重算出该观测的 obs_uid 精确连;best-effort:该观测被噪声剔除则无此边)。那条观测的 `ACTOR/TARGET` 就把告警引到具体实体上。
  - `(:Alert)-[:INDICATES]→(:Technique)` —— MITRE 技战术。
  - (可选)`(:Alert)-[:ON_HOST]→(:Host)` —— 被监控主机上下文。
- **WAF/Suricata/Wazuh/EDR 命中全是 Alert**,不是观测。原始 HTTP 请求(nginx access)才是 `HttpRequest` 观测,二者经 ABOUT 关联。

## 8. 富化层(kind=enrichment)
`Technique`(attack_id/tactic)· `IoC`(kind/value/reputation)。资产/身份/业务基线(AssetProfile/IdentityBaseline/BusinessBaseline)保留作占位,单独富化时填,非核心入图。

## 9. 边(关系)总表
- **角色边(观测→实体,承载主谓宾)**:`ACTOR`(主)· `TARGET`(宾)· `PRODUCES`(新产出,如 LogonSession)· `FROM`/`TO`(端点)· `USES`(票据/工具)· `ON_HOST`(观测主机)· `RELATED_TO`(松关联,必带 reason/confidence)。
- **结构边(实体↔实体)**:`PARENT_OF`(进程父子)· `RAN_AS`(进程→账号)· `MEMBER_OF`(账号→组)· `HAS_IP`(主机→IP)· `RESOLVES_TO`(域→IP)· `AUTHENTICATED_AS`(会话→账号)· `HAS_CERT`。
- **告警边**:`ABOUT`(告警→观测)· `INDICATES`(告警→技术)。

## 10. 强键 / 连接键
强:`obs_uid` · `process_guid` · `logon_guid` · `sid`/`upn` · `asset_id` · `alert_uid`。弱:`ip`(SNAT 干扰)· 字符串名。时序:timestamp + SEQ within N。**跨观测同实体靠强键 MERGE**。

## 11. 迁移:要不要重灌?
**这次要重灌日志**(与"只加告警"那次不同)—— 因为观测节点的 label 从单一 `:Event` 变成分类型(`:ProcessCreate`/`:Authentication`/…),现有 41 万节点类型全变。做法:改完模型 + mapper → `wipe` → 全量 backfill(unwind,~6 分钟)+ 增量灌告警。观测事件数据源不变(还是 winlogbeat+soc-app),只是映射成新类型。

## 12. 待你拍板的开放点
1. **观测类型粒度**:§5 这 ~22 类,合适?要不要再合并(如 File/Registry 各三动作合一类带 action)或再拆?
2. **角色边**:沿用 v1 的 ACTOR/TARGET/PRODUCES/FROM/TO/USES/ON_HOST(观测→实体方向)可否?还是你要"实体→观测"方向(entity 做主语)?
3. **观测通用信封**里要不要保留 `event_code`/`action`(派生分类,非原始)—— 这算不算"强加"?我倾向保留(它是从原始事件号确定性派生的分类,非臆造)。
4. **告警 ABOUT 只连一条观测** vs 也允许连 Host 上下文 —— 严格单入口你要哪种?
