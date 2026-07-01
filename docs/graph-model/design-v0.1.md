# 全场景图模型设计 · v0.1（草案，评审迭代中）

> **原则**：图模型是一切的基础，必须先设计到**稳定、完备**再往下走。模型**独立于现有数据、面向全场景（四层全覆盖）、一次定义不返工**、自定义最小充分集、单一事实源。
> **设计方法**：四层告警类型（见 [`../research/alert-triage-methodology.md`](../research/alert-triage-methodology.md)）→ 每类必需取证证据 → 反推实体/关系/属性/连接键 → **覆盖核对表逐条验收**（缺口显式标注）。
> **状态**：v0.1，待评审。开放点见文末。**本轮只做图模型，不含数据接入/Agent/实现。**

---

## 一、四层告警 → 取证证据需求（模型必须承载的"米"）

| 层 | 主流告警 | 必需取证证据/字段 |
|---|---|---|
| 应用 | SQLi/XSS/认证绕过/OWASP、Webshell 落地 | HTTP 方法/URI/参数/UA/host头、源IP、WAF 命中(rule_id/payload)、落地文件、IP/域信誉、业务基线 |
| 网络 | DNS 信标/C2、异常外连、横向 | DNS 查询(域名/频率/周期)、NetFlow(src/dst/port/proto/bytes/时序)、Zeek/PCAP、C2 情报 |
| 主机 | 服务执行/可疑进程、凭据转储、持久化 | 进程(image/命令行/ProcessGuid/pid)、**父子进程链**、文件(路径/哈希)、注册表键、Sysmon EID1/3、4688(命令行) |
| 身份 | Kerberoast/AS-REP/PtT/PtH/DCSync/委派 | 4768(TGT)/4769(TGS)/4624(登录)/4662(目录访问)、票据(类型/SPN/加密)、账号(SID/SPN/委派标志)、**logon session/GUID** |
| 富化(横切) | 所有层 | 资产上下文(关键度/属主/OS/网段)、身份基线(角色/部门/时段/历史)、情报信誉(IP/域/哈希 IoC) |

## 二、实体类型（16 类，跨四层统一，带关键属性）

**观测/证据类**
1. **Asset/Host** — hostname, ip[], os, role(dc/member), criticality, zone
2. **Account** — sid, sam, upn, domain, type(user/service/computer), privileged, spn, delegation_flag, preauth_flag
3. **LogonSession** ★连接键核心 — logon_id, logon_guid, logon_type, start_time（→Account, →Host）
4. **Ticket** — kind(TGT/TGS), spn, enc_type, time
5. **Process** — process_guid, pid, image, command_line, start_time（→Host, →Account）
6. **File** — path, md5, sha256, write_time（→Host）
7. **RegistryKey** — path, value, time（→Host）
8. **NetworkFlow** — src_ip, dst_ip, src_port, dst_port, proto, bytes, start/end
9. **Domain** — fqdn, first_seen, reputation
10. **HttpRequest** — method, src_ip, host_header, user_agent, params, time（→Uri）
11. **Uri** — path, host（跨层枢纽）
12. **WafHit** — rule_id, severity, payload, time（→HttpRequest）

**研判/富化类**
13. **Alert** — source(waf/ndr/hids/edr/auth), rule_id, severity, pattern_key(IP无关), techniques[], raw_ref(回原文指针), time
14. **IoC** — kind(ip/domain/hash/url), value, reputation, source
15. **Technique** — attack_id(Txxxx), tactic
16. **Actor** — 合成攻击者身份（去 SNAT 分散）

## 三、关系类型（方向承载语义）

- Process **PARENT_OF** Process
- Process **ON_HOST** Host ; Process **RAN_AS** Account
- Process **WROTE_FILE** File ; File **ON_HOST** Host ; Process **MODIFIED** RegistryKey
- LogonSession **AUTHENTICATED_AS** Account ; LogonSession **ON_HOST** Host
- LogonSession **DERIVED_FROM** LogonSession ★跨机横向（HADES）
- Account **REQUESTED** Ticket ; Ticket **FOR_SERVICE** Account/spn
- Process **OPENED** NetworkFlow（Sysmon EID3：主机↔网络桥）; NetworkFlow **TO_HOST** Host
- HttpRequest **FROM** IP/Actor ; HttpRequest **TARGETS** Uri ; HttpRequest **TO_DEST** Host/IP ★跨层缝合 ; HttpRequest **WROTE_FILE** File（webshell）
- WafHit **ON** HttpRequest
- IP **QUERIED** Domain ; Domain **RESOLVES_TO** IP
- Alert **ABOUT** <observable>（进程/请求/登录会话/流/票据…）; Alert **MAPS_TO** Technique
- IoC **MATCHES** IP/Domain/File
- Actor **PERFORMED** <observable>

## 四、连接键（跨层缝合的核心机制）

`logon_id / logon_guid`（身份↔主机、跨机）· `process_guid`（进程稳健标识）· `timestamp + 时序(SEQ within N)` · `ip / target-ip`（TO_DEST：应用↔网络↔主机）· `account sid/upn` · `asset id` · `attack technique id` · `pattern_key`（IP 无关告警指纹）

## 五、覆盖核对表（每类告警 → 承载它的实体/关系/键 → 缺口）

| 告警 | 承载方式 | 状态 |
|---|---|---|
| Kerberoast | Account(spn,service)+Ticket(TGS,enc=RC4)+REQUESTED+4769 → Alert ABOUT Ticket | ✅ |
| AS-REP Roast | Account(preauth_flag)+Ticket(AS-REP)+4768 | ✅ |
| Pass-the-Ticket | LogonSession/Ticket 无前置 TGT（时序键判定）+logon_id | ✅（靠时序） |
| 服务执行/横向(主机) | Process PARENT_OF(services.exe→cmd.exe)+command_line+Sysmon EID1 | ✅ |
| 跨机横向(身份+主机) | LogonSession DERIVED_FROM + logon_guid | ✅ |
| Webshell(应用+主机) | HttpRequest WROTE_FILE File ON_HOST + WafHit ON | ✅ |
| DNS 信标(网络) | IP QUERIED Domain(频率/周期)+NetworkFlow+IoC(域信誉) | ✅ |
| **DCSync** | 需目录复制访问(4662/replication)——Account(privileged) PERFORMED + Alert ABOUT | ⚠️ 需确认是否加 AuthEvent/DirectoryAccess 实体 |
| **NTLM relay** | NetworkFlow + LogonSession(NTLM) + auth 事件——需 auth 协议属性 | ⚠️ 需 LogonSession 加 auth_protocol,或加 AuthEvent 实体 |
| **委派滥用(约束/非约束)** | Account(delegation_flag)+Ticket(S4U) | ⚠️ 需确认 Ticket 是否加 s4u/delegation 属性 |

## 六、待评审/补充的开放点

1. **认证事件是否单列 `AuthEvent` 实体**（承载 4768/4769/4624/4662/NTLM 原子事件），还是把语义压进 LogonSession/Ticket + Alert？→ 直接决定 DCSync / NTLM relay / 委派 三类能否干净承载。**倾向：加**。
2. **富化/经验类（资产画像、身份基线、IP/域信誉）进不进图？** 进图=图上可关联查证；不进图=agent 查外部经验库。（应用/网络层"判良性"多靠经验库——影响承载方式。）
3. 实体/关系命名与最小集是否再收敛或补充。
4. 是否在模型里**显式区分**"观测实体(证据)" vs "研判产物(Alert/Actor/Technique)"两类。

---
_下一步（本轮内）：据评审意见收敛到 v0.2；模型稳定后才进数据接入/Agent 设计。_
