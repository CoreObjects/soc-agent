# 接入层事件落图映射 spec（graph_model v1.1 · 事件层泛化）

> 单一事实源 = `model/graph_model.json`。本文件是它的**落地实现规范**：把 ES 原始事件映射成 `:Event` 超类节点 + 共享对象 + 8 条角色边。改模型先改 JSON，再据此更新本文件。经真实 ES 证据湖（56.8 万事件）校准。

## 0. 设计原则（为什么是"一个 Event 超类 + tag"而非"一类事件一 label"）

- 所有观测事件 = **单一 `:Event` 超类** + `category` 第二 label（`(:Event:Authentication)`）+ `action`。
- 事件与对象的关系 = **8 条通用角色边（Event → Object 出边）**，不是每类事件专属边。
- **新事件类型 = 新 category/action 值 + 复用角色边**，不加 label、不改 schema（EID10/ADCS 就是这么并进来的，零 schema 改动）。
- **category = 观测种类，非判决**：`process·access`（EID10）本身不代表"凭据转储"，是否恶意由 L3 Technique / L4 Alert·Finding 判（证据湖里 14418 条 EID10 大多是 VBoxService 良性访问，就是这个道理）。

## 1. `event_uid` 生成

| 分支 | 公式 | 用于 |
|---|---|---|
| **优先** | `hash(source + host + sensor + native_record_id)` | Windows：`host = winlog.computer_name`、`native = winlog.record_id`；WAF：`native = transaction.unique_id`（本就全局唯一，host 可空） |
| **兜底** | `hash(source + host + sensor + event_time + raw_hash)` | 无原生记录号时；`raw_hash = hash(原始文档体)` |

- **必须含 host**：`winlog.record_id` 是"每主机每通道"计数器，不含 host 会跨主机撞（dc01/dc02/dc03 同号）→ `MERGE by event_uid` 静默塌图。（v1.1.1 修正）
- **不强依赖 event_time**；event_time 仅在兜底分支出现，且必与 raw_hash 同用。
- 实测：当前证据湖无重复（Beats 至今未重投），但幂等 `MERGE by event_uid` 仍必须做（"至少一次"投递的防御）。

## 2. 受控可扩展词表（category 和 action 都要注册）

新增 category **或** action 都须先在 `graph_model.json` 的 `category_registry` / `action_registry` 注册（值 + 定义 + 示例 event_code），禁止临时臆造。当前登记见 JSON。

## 3. 八条通用角色边（全部 Event → Object 出边方向）

| 角色边 | → 对象 | 语义 | 备注 |
|---|---|---|---|
| `ON_HOST` | Host | **观测主机/sensor 记录点** | **≠ 攻击目标**；目标用 TARGET/TO |
| `ACTOR` | Account \| Process | 已知主体（谁干的） | 观测性，**非攻击者归因** |
| `TARGET` | Account/Service/Process/File/RegistryKey/Domain/DirectoryObject | 被作用的**既有**客体 | |
| `PRODUCES` | LogonSession/Process/File | 事件**新产生**的对象 | 建新对象用它，作用既有对象用 TARGET |
| `FROM` | IPAddress \| Host | 来源端点（含外部/未知发起方） | 外部 HTTP/网络发起方走 FROM，不用 ACTOR |
| `TO` | IPAddress \| Host | 目标端点 | |
| `USES` | Ticket/File/Service | 使用的工具/凭据/票据 | v1 多前瞻，有物料才落 |
| `RELATED_TO` | 任意 observable | 松关联逃生口 | **必带 `reason`+`confidence`+`time_window`+`correlation_rule`，禁裸连**；仅当确实不落前 7 类时用 |

## 4. `weak_link=true` 触发条件（满足任一）

- 无强键连主体：除 `event_uid` 外无 `ProcessGuid/LogonGuid/SID` 可把事件连到 ACTOR/TARGET（如 4104 无 ProcessGuid）
- 仅时间窗关联
- 仅字符串名（不可解析为 asset_id/SID，如 4776 的 NetBIOS Workstation）
- 仅 Host 时间线辅助（如 1102）

→ 仍入图（ON_HOST + time），但标 `weak_link`；Agent 据此降权 / 仅作旁证。

## 5. 对象结构边（Object → Object，非角色边）

`Process-PARENT_OF→Process`（父→子）· `Process-RAN_AS→Account` · `Process-ON_HOST→Host` · `File/RegistryKey/Service/LogonSession-ON_HOST→Host` · `Host-HAS_IP→IPAddress` · `Service-BELONGS_TO→Application` · `LogonSession-AUTHENTICATED_AS→Account` · `Domain-RESOLVES_TO→IPAddress`。

**Sysmon-1 显式建进程对象图**：`PRODUCES` 子 Process（ProcessGuid）+ 结构边 `(parent)-PARENT_OF→(child)`、`child-RAN_AS→Account(User)`、`child-ON_HOST→Host`。

## 6. 逐事件映射（block 形式，避免宽表列错位）

> 通用约定：所有事件 `ON_HOST → Host(=winlog.computer_name)`，下略。对象用强键落图：Account=SID、Process=ProcessGuid、LogonSession=LogonGuid。`event_uid` 除 WAF 外均 = `hash(winlogbeat + winlog.computer_name + <channel> + winlog.record_id)`（含 host，见 §1）。

```
■ 4624  authentication·logon·success
  ACTOR    → Account(TargetUserSid)        # 主体身份，非攻击者归因
  PRODUCES → LogonSession(TargetLogonId / LogonGuid)
  FROM     → IPAddress(IpAddress)          # 常为 "-"（Kerberos 本地）
  叶子     : logon_type, auth_package(AuthenticationPackageName), elevated_token(ElevatedToken)

■ 4625  authentication·logon·fail
  ACTOR → Account(TargetUserName)          # 主体身份，非攻击者归因
  FROM  → IPAddress(IpAddress)
  叶子  : logon_type, status(Status), sub_status(SubStatus), failure_reason(FailureReason)

■ 4768  authentication·tgt_request·{success|fail←Status}
  ACTOR  → Account(TargetSid)
  TARGET → Account(ServiceName=krbtgt)
  FROM   → IPAddress(IpAddress)
  叶子   : enc_type(TicketEncryptionType), ticket_options(TicketOptions), preauth_type(PreAuthType)

■ 4769  authentication·service_ticket·{success|fail}
  ACTOR  → Account(TargetUserName=请求者)
  TARGET → Account|Service(ServiceName=被请求服务账号)   # Kerberoast 目标
  FROM   → IPAddress(IpAddress)
  叶子   : enc_type(TicketEncryptionType，0x17=RC4=roast 信号), ticket_options(TicketOptions)
  # LogonGuid 可连 LogonSession

■ 4776  authentication·ntlm_validate·{success|fail}
  ACTOR → Account(TargetUserName)
  FROM  → Host|IPAddress(Workstation=NetBIOS 名)         # 不可解析→ weak_link
  叶子  : auth_package(PackageName), status(Status)

■ 4662  directory·object_access
  ACTOR  → Account(SubjectUserSid)
  TARGET → DirectoryObject(ObjectName)
  叶子   : access_mask(AccessMask), properties(Properties，含 DS-Repl-Get-Changes GUID → DCSync 判据), operation(OperationType)
  # SubjectLogonId 可连 LogonSession

■ 4886  certificate·request
  ACTOR  → Account(Requester)
  TARGET → Service(kind=certificate_authority, name=CA 名←computer_name/域推导)
  叶子   : request_id(RequestId), attributes(Attributes)      # 不建 Certificate 对象

■ 4887  certificate·issue·success
  ACTOR  → Account(Requester)
  TARGET → Service(kind=certificate_authority)
  叶子   : request_id(RequestId), subject(Subject), subject_key_id(SubjectKeyIdentifier), disposition(Disposition)
  # 盲区：证书模板名不在 4886/4887 里，ESC 判定需 CA 侧 certutil 补

■ Sysmon-1  process·create
  PRODUCES → Process(child, ProcessGuid)
  结构边   : (ParentProcessGuid)-PARENT_OF→(child) ; child-RAN_AS→Account(User) ; child-ON_HOST→Host
  ACTOR    → Account(User)
  叶子     : command_line(CommandLine), integrity_level(IntegrityLevel), hashes(Hashes→File.sha256)

■ Sysmon-3  network·connect
  ACTOR  → Process(ProcessGuid)
  FROM   → IPAddress(SourceIp) ; TO → IPAddress(DestinationIp)
  TARGET → Host(DestinationHostname，可选)
  叶子   : src_port(SourcePort), dst_port(DestinationPort), proto(Protocol), initiated(Initiated)

■ Sysmon-10  process·access
  ACTOR  → Process(SourceProcessGUID)
  TARGET → Process(TargetProcessGUID，如 lsass)
  叶子   : granted_access(GrantedAccess), call_trace(CallTrace), target_image(TargetImage)
  # category 只说 process·access；是否凭据转储由 Technique/Alert 用 granted_access+call_trace 判

■ Sysmon-11  file·create
  ACTOR    → Process(ProcessGuid)
  PRODUCES → File(TargetFilename, path 键)
  叶子     : path(TargetFilename), creation_time(CreationUtcTime)
  变体     : file·modify / file·delete → ACTOR→Process ; TARGET→File(既有)

■ Sysmon-13  registry·set
  ACTOR  → Process(ProcessGuid)
  TARGET → RegistryKey(拆 TargetObject → hive/key_path/value_name)
  叶子   : operation(EventType), value_data(Details)

■ Sysmon-22  dns·query
  ACTOR  → Process(ProcessGuid)
  TARGET → Domain(QueryName)
  叶子   : query_status(QueryStatus), answers(QueryResults)
  # QueryResults 可派生 Domain-RESOLVES_TO→IPAddress

■ WafHit  web·waf_match·{blocked|allowed|detected←is_interrupted/http_code}
  FROM   → IPAddress(client_ip)            # 外部客户端，无 ACTOR
  TARGET → Uri|Service(request.uri / request.hostname)
  叶子   : rule_ids[](messages[].details.ruleId，命中规则数组，非主键!), severity, http_method(request.method), http_status(response.http_code), payload(request.uri)
  event_uid: hash(filebeat + ModSecurity + transaction.unique_id)

■ 4104  script·scriptblock        [weak_link：无 ProcessGuid，仅 Host 时间线]
  ON_HOST → Host
  叶子    : script_block_text(ScriptBlockText), message_no/total(MessageNumber/MessageTotal)
  # ScriptBlockText 超长会被 ES _ignored（_source 可读、全文搜不了）

■ 1102  log_management·cleared     [weak_link：body 空，仅 Host 时间线，抗取证旁证]
  ON_HOST → Host
  ACTOR   → Account(SubjectUserName，若有)
```

## 7. 大结论（接入策略，重要）

证据湖 99.9% 是 provisioning/bot/正常运营噪声，攻击是针尖。**接入层不做"全量 56 万灌图"，而是告警驱动/调查驱动**：从一条告警出发，顺强连接键（ProcessGuid/LogonGuid/SID/时间窗）拉取相关事件入图。与图模型 L4 Alert 驱动研判一致。
