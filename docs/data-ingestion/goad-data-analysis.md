# GOAD 现有数据分析（数据接入层 · 第一步）

> 目的：数据接入层要把真实遥测喂进[图模型 v1.0](../graph-model/MODEL-LOCKED-v1.0.md)。先搞清 **GOAD 现在产出什么、缺什么、怎么映射到我们的实体**。
> 依据：GOAD 仓库配置分析（`C:\Users\Core_Objects\Code\GOAD`）。**live 实机状态待核实**（命令见文末）。

## 0. 一句话结论
GOAD **自带**一套完整遥测栈（**Sysmon SwiftOnSecurity v74 + Winlogbeat 7.17.6 + ELK 7.x**，在 `roles/logs_windows` + `elk.yml`），但：
- **默认全部禁用**：`elk.yml` 在 `ansible/main.yml:12` 被注释；`config.json` 里没有任何主机标为 `elk_log/elk_server`，`logs_windows` 角色**从不执行**。
- **我们部署跑的链**（build→…→servers→security→vulnerabilities）**不含 elk.yml**。
→ **当前实机：无 Sysmon、无 Winlogbeat、无集中采集、无高级审计,只有各 VM 默认 Windows 事件日志。**

好消息：**这套栈是现成且经测试的**（Sysmon 全量 EID 1-25），我们不必重造采集端,**启用 + 补审计 + 改指向**即可。

## 1. GOAD 能产出的遥测 → 映射到我们的图模型（启用 logs_windows 后）

| GOAD 数据源 | 事件 | → 我们的实体 / 关系 | 层 | 状态 |
|---|---|---|---|---|
| **Sysmon EID1** | ProcessCreate(guid/parent/cmdline) | `Process` · `PARENT_OF` · `RAN_AS` | 主机 | ✅ 启用后有 |
| **Sysmon EID3** | NetworkConnect | `NetworkFlow` · `Process OPENED` · `FROM_IP/TO_IP` | 主机/网 | ✅ |
| **Sysmon EID11** | FileCreate | `FileWriteEvent` · `WROTE_FILE` · `File` | 主机 | ✅ |
| **Sysmon EID12-14** | RegistryEvent | `RegistryEvent` · `MODIFIED` · `RegistryKey` | 主机 | ✅ |
| **Sysmon EID22** | DnsQuery | `DnsQuery` · `MADE_DNS_QUERY` · `QUERIED Domain` | 主机/网 | ✅ |
| **Sysmon EID8/10/17/18** | 远程线程/进程访问/命名管道 | 凭据转储 / PsExec 横向 证据 | 主机 | ✅ |
| **Security 4624/4625** | 登录/失败 | `AuthEvent` · `ESTABLISHED LogonSession` · `AUTHENTICATED_AS` · `FROM_IP` | 身份 | ◐ DC 默认有 |
| **Security 4768/4769** | Kerberos AS/TGS | `AuthEvent` · `ISSUED Ticket(TGT/TGS)` | 身份 | ◐ DC 默认多半有 |
| **Security 4662** | 目录对象访问 | `DirectoryAccess` · `TARGETS DirectoryObject` (DCSync) | 身份 | ✗ 需 SACL+审计 |
| **Security 4672/4720…** | 特权登录/账户管理 | `Account.privileged` / 账户变更 | 身份 | ◐ |
| **PowerShell 4104** | 脚本块 | 命令/脚本证据(→Process) | 主机 | ✗ 源端需启用 |
| — 无 HTTP/WAF/IIS 日志采集 — | — | `HttpRequest`/`WafHit`/`Uri`/`Service` | **应用** | ✗ **GOAD 无 Web 应用** |
| — 无 Zeek/NetFlow/NDR — | — | `NetworkFlow`(全量网络) | 网络 | ✗ 仅主机侧 EID3 |
| — 无情报/画像源 — | — | `IoC`/`AssetProfile`/`IdentityBaseline`/`BusinessBaseline` | 富化 | ✗ 我们自建 |
| 我们的 Agent 产出 | — | `Alert`/`Case`/`Finding`/`Experience`/`ActivityCluster`/`AttackPattern` | 研判 | 我们产 |

**要点：GOAD(启用后)能把我们模型的「主机层 + 身份层」喂得很满,网络层只有主机侧、应用层几乎空、富化层要我们自建。** 与调研结论一致(GOAD 强于主机/身份,弱于应用)。

## 2. 12 类告警在 GOAD 的可得性
✅ 可得(主机/身份): Kerberoast(4769)、AS-REP(4768)、PtT/PtH(4624/logon type)、**DCSync(4662,需开审计)**、NTLM relay(4624/EID3)、委派(4769 S4U)、服务执行/横向(EID1/17/18)、注册表持久化(EID12-14)、DNS beacon(EID22)。
✗ 不可得: **Webshell/SQLi 等应用层**(GOAD 无 Web 应用) —— 应用层需另找数据源。

## 3. 必补的缺口
1. **启用采集**：跑 `logs_windows`(Sysmon+Winlogbeat)于全部 5 VM(默认没跑)。
2. **补高级审计**(GOAD 完全没配)：进程创建含命令行(4688 或直接用 Sysmon EID1)、**目录访问 4662 + SACL**(DCSync 关键)、PowerShell ScriptBlock(4104)、logon type 细分。
3. **采集出口**：GOAD 默认 Winlogbeat→自带 ELK。我们要决定:**复用 ELK(我们的接入从 ES 读)** 还是 Winlogbeat/shipper 直连我们的接入管道。
4. **应用层数据**：GOAD 没有 → 后续加 Web 靶标或合成(模型侧已留位,不缩水)。
5. **富化层**：IoC/信誉/画像/基线由我们自建接入(外部情报 + 资产/身份/业务基线)。

## 4. 采集架构建议（复用而非重造）
```
5 台 Windows VM
  ├─ Sysmon(SwiftOnSecurity v74, EID1-25)   ← 启用 logs_windows
  ├─ Winlogbeat 7.17.6 (Security/Sysmon/PowerShell 通道)
  └─ + 补:高级审计策略(4688cmdline/4662+SACL/4104)
     → Elasticsearch(复用 GOAD ELK)
        → 【我们的数据接入层】读 ES → 归一化(按上表映射) → 知识图谱
```
理由：Sysmon 配置、Winlogbeat 通道、ELK 都现成且测过;我们只加"高级审计"和"ES→图 的归一化",不重造采集端。旧 SOC 也是"读 SIEM/ES 归一"，路子一致。

## 5. 实机核实结果（2026-07-01 · 5 台 VM 全可达）

| 主机 | Sysmon/Winlogbeat | Process Creation | DS Access | Kerberos | 近 2h Security |
|---|---|---|---|---|---|
| dc01 | ABSENT / ABSENT | No Auditing | **Success** | **Success** | 4624:297 · 4769:11 · 4768:5 · 4662:2 |
| dc02 | ABSENT / ABSENT | No Auditing | Success | Success | 4624:514 · 4769:456 · 4768:210 |
| dc03 | ABSENT / ABSENT | No Auditing | Success | Success | 4624:312 · 4769:8 · 4768:8 · 4662:2 |
| srv02 | ABSENT / ABSENT | No Auditing | Success | Success | 4624:487 |
| srv03 | ABSENT / ABSENT | No Auditing | Success | Success | 4624:7 |

**关键修正（实机比配置分析乐观）：**
- ✅ **身份层审计已开**（比预期好）：Logon=Success+Failure(4624/4625，全机)、Kerberos AS/TGS=Success(4768/4769，DC 在产)、**DS Access=Success(4662，DC 在产)**。→ Kerberoast / AS-REP / DCSync / PtT / PtH / 委派 的**身份层证据现在就在生成，无需补审计**。（配置分析误判为"高级审计 0%"，实为 security 阶段/GPO 已开——故实机核实必要。）
- ✗ **Sysmon / Winlogbeat 全无** → 无集中采集，**主机层完全无数据**（Process/File/Registry/DNS/NetworkFlow）。
- ✗ **Process Creation=No Auditing**（4688 不产）→ 主机层进程靠 **Sysmon**（EID1 带 guid/parent/cmdline，优于 4688）。

**结论：真正要做的只有两件——(1) 部署 `logs_windows`(Sysmon+Winlogbeat) 补主机层 + 集中采集；(2) 立起 ELK 落库点。身份层审计已就绪，不用补。**

---
_下一步：数据接入层落地——(a) 立 ELK(宿主容器 or 一台 Linux VM)；(b) 部署 logs_windows→ELK；(c) 接入层从 ES 读、按第 1 节映射进图。应用层另议。_
