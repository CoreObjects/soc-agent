# 告警研判 Playbook · 四层操作级(落到 v3 图)

> **本文是什么**：研判 Agent 的**知识底座**。针对我们**实际有的每一类告警**,给出"研判决策树 → 每步取什么证据 → 映射成 v3 图的具体 Cypher pivot → 误报场景 → 判定逻辑(TP/FP)"。目标是让 Agent 有章可循,而不是靠大模型凭空发挥。
>
> **与 `alert-triage-methodology.md` 的关系**:那份是**战略层**存档(四层各自偏哪种研判方法的方法论梯度,105-agent 深度调研);本文是**操作层**落地(每类告警怎么查、查什么、怎么判),锚在我们真实的 v3 图 label/谓语/字段上。两份互补,战略在前、操作在后。
>
> **来源**:四层并行调研(身份/主机/应用/网络各一个专家 agent,Web 核对技战术判据与误报 + 强制映射到 v3 图),经统稿 + 接地 QA(修正 `attack_id`/`Verdict.verdict` 等接地错、标出模型缺口)。
>
> **Cypher 免责**:所有 Cypher 是**草图**——label / 谓语 / 键均取自 v3 图(`model/graph_model.json`),可直接对照;但 (a) 时间算术(`event_time ± 窗口`)的确切写法取决于 `event_time` 的存储类型(epoch ms vs ISO datetime),落地时以图内实际类型为准;(b) `event_code` 取值(如 `'4769'`/`'10'`)为示意;(c) 标 ⚠️ 的字段是**当前图取不到**的,见每层末尾及 §6 跨层缺口表。

---

## 0. 覆盖的告警 → 我们实际告警库的映射

| 层 | 本文小节 | 我们图里的实际告警(技战术 / 规则) | 图内量级 |
|---|---|---|---|
| 主机 | LSASS 凭据转储 | **T1003.001**(Sysmon EID10 → lsass) | 413 |
| 主机 | Ingress Tool Transfer | **T1105**(Wazuh 内置,极吵) | 6706(占 93%) |
| 主机 | 注册表持久化 | T1547.001/T1112(Sysmon EID13) | 场景已设计 |
| 主机 | 可疑进程/LOLBin | T1059/T1055/T1218(Sysmon EID1 父子链) | 场景已设计 |
| 身份 | Kerberoasting | **T1558.003**(4769 + RC4 + 非机器账号) | 30 |
| 身份 | ADCS 证书滥用 | **T1649**(4886/4887) | 6 |
| 身份 | DCSync | T1003.006(4662 + 复制 GUID) | 场景已设计 |
| 身份 | 横向/PtH/PtT | T1550.002/.003 / T1021(4624/4768/4776) | 场景已设计 |
| 应用 | SQLi / XSS / 路径遍历 / RCE | T1190 / OWASP A03(CRS 942/941/930-931/932) | WAF `soc-app-*` |
| 应用 | Webshell 落地 | T1505.003(WAF + Sysmon EID11/EID1) | 跨层 |
| 网络 | C2 / DNS beacon | T1071/.004 / T1568(Sysmon EID3/22 聚合节律) | 主机网络切片 |
| 网络 | 可疑外连 / 横向网络维度 | T1571/T1090 / T1021(EID3 + 4624 关联) | 主机网络切片 |

---

## 1. 统一研判骨架(四层共用)

```
(:Alert) →(反查 [:TRIGGERED])→ (:Event 触发事件,唯一溯源入口)
        →(BY / <谓语> / FROM / ON_HOST / TO / PRODUCED)→ 涉及实体(谁、对谁、从哪、在哪)
        →(实体↔实体 聚合边 count/first_seen/last_seen)→ 看基线与新颖度(是不是头一回)
        →(同主语/同会话的 :Event 按 event_time 排)→ 还原时序 / 攻击链
        →(实体一跳:实体 <-[:ON]- Disposition <-[:LED_TO]- Verdict <-[:CONCLUDED]- Alert)→ 复用历史结论
        →(研判完)→ 写回 (:Verdict) / (:Disposition) 经验层
```

**资深分析师的判序(所有小节共用,固定五步):**
1. **先证伪(null hypothesis)** —— 这条告警最可能的良性解释是什么?能不能一眼排掉(是 AV/EDR/运维/更新/正常业务/信任拓扑)?
2. **看基线新颖度** —— 这个"主体×客体×行为"是头一回,还是历史常态?(聚合边 `first_seen`/`count`)
3. **看权限与资产价值** —— 涉及的账号是否特权?主机是否高价值(域控/DMZ)?
4. **看时序与扇出** —— 单发还是批量?短时打了几个目标?规不规律?
5. **看横向落地后行为** —— 打完之后干了什么?(外连 C2 / 读 LSASS / 写自启 / 派生 shell / 换机登录)——这一步把"尝试"升级为"得手"。

**经验层(自进化)贯穿始终**:每类告警都先从涉及实体一跳看历史 `Verdict/Disposition`——"这个源 IP 上周封过""这台主机这个源进程判过 FP""这个账号是已知扫描器"——把过去的判例作为先例喂给当前研判,并在研判完写回,越用越准。

---

## 2. 主机/端点层(Host / Endpoint)

> 通用骨架:**告警 →(反查 `TRIGGERED`)触发事件 →(`BY`/谓语/`ON_HOST`)锁定涉事进程与主机 →(沿 `SPAWNED` 迭代)还原父子进程树 →(读 `command_line`)看意图 →(`RAN_AS`/`AUTHENTICATED_AS`)看身份 →(`CONNECTED_TO`/`WROTE`/`SET`/`ACCESSED`)看后续行为 →(实体 `<-[:ON]-Disposition<-[:LED_TO]-Verdict`)看历史经验**。全程只在图里 pivot,先证伪(是不是 AV/EDR/运维/安装器的正常行为),证伪不掉再升级。

### LSASS 凭据转储 (T1003.001,主机层)

**攻击本质**:攻击者用 `OpenProcess` 拿到 lsass.exe 句柄并读其内存,导出 NTLM 哈希 / Kerberos 票据 / (WDigest 开时)明文口令,用于后续 Pass-the-Hash、横向、提权。

**触发逻辑(我们栈)**:Wazuh 规则匹配 Sysmon **EID10(ProcessAccess)** 且 `TargetImage=lsass.exe`,且 `GrantedAccess` ∈ {0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff},并对 `SourceImage` 做了白名单约束。图里 413 条,落为 `(:Event event_code:10)-[:ACCESSED]->(:Process{image:'lsass.exe'})`,标量 `granted_access`、`call_trace`。

**grantedAccess 掩码语义(研判核心,先读懂这一列)** —— 掩码是"工具指纹",关键看**是否含内存读/写位**(Splunk / Elastic / TrustedSec Sysmon Guide):

| 位 | 名称 | 含义 |
|---|---|---|
| `0x0008` | PROCESS_VM_OPERATION | 改内存保护/分配(注入前置) |
| `0x0010` | **PROCESS_VM_READ** | **读目标内存 —— 凭据被读走的关键位** |
| `0x0020` | PROCESS_VM_WRITE | 写目标内存(注入) |
| `0x0040` | PROCESS_DUP_HANDLE | 复制句柄(常见于 comsvcs/句柄二次利用) |
| `0x0400` | PROCESS_QUERY_INFORMATION | 完整查询 |
| `0x1000` | PROCESS_QUERY_LIMITED_INFORMATION | 受限查询(**最良性**,不读内存) |
| `0x1FFFFF` | PROCESS_ALL_ACCESS | 全权限(ProcDump `-ma`、调试器) |

- `0x1010` = VM_READ+QUERY_INFO → **Mimikatz `sekurlsa`** 经典指纹。
- `0x1410` = VM_READ+QUERY_INFO+QUERY_LIMITED → **ProcDump / 任务管理器"创建转储"**(整进程 dump)。
- `0x1438 / 0x143a` = 叠加 VM_WRITE(0x20)+VM_OPERATION(0x08)(0x143a 再加 CREATE_THREAD 0x02)→ **Mimikatz `lsadump` / 注入类**,含写内存位,恶意度最高。
- `0x1fffff` = ProcDump 全权限 dump。
- **判据锚点**:掩码**含 `0x10`(VM_READ)** = 有人在读 LSASS 内存,才与凭据窃取相关;纯 `0x1000`/`0x1400`(仅查询、无 0x10)基本是良性查询,可直接降权。

**研判决策树**:

1. **Q:源进程是谁?它是否在 LSASS 访问白名单内?** → 证据:`SourceImage`、`command_line`、掩码 → 图:
   ```cypher
   MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:10})-[:BY]->(src:Process)
   MATCH (e)-[:ACCESSED]->(:Process {image:'lsass.exe'})
   MATCH (e)-[:ON_HOST]->(h:Host)
   RETURN h.hostname, src.image, src.command_line,
          e.granted_access, e.call_trace, e.event_time
   ```
   源进程若是 `MsMpEng.exe`(Defender 引擎)、`csrss/wininit/lsm/wmiprvse`、`svchost` 等系统/AV 进程 → 强证伪信号(Elastic 明确要求排除 MsMpEng)。

2. **Q:父子进程链正常吗?源进程从哪来?** → 证据:父/祖父进程 → 图:沿 `SPAWNED` 回溯
   ```cypher
   MATCH (p:Process)-[:SPAWNED]->(src:Process {process_guid:$guid})
   OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p)
   RETURN gp.image, gp.command_line, p.image, p.command_line
   ```
   `services.exe→MsMpEng`(正常)vs `w3wp/powershell/cmd/rundll32→未知源进程`(恶意)。源进程若由 webshell/编码 PowerShell 链派生 → TP 佐证。

3. **Q:调用栈来自签名系统模块,还是可疑/无支撑内存?** → 证据:`call_trace` → 图:读 `e.call_trace` 标量。含 `dbghelp.dll`/`dbgcore.dll`(转储库)或 `UNKNOWN`/无模块支撑地址(反射加载、注入)→ 强 TP;全为 `ntdll.dll+…`/`kernel32.dll+…` 且源进程签名可信 → 偏良性(TrustedSec)。

4. **Q:访问身份与权限?** → 证据:运行账户 → 图:
   ```cypher
   MATCH (src:Process {process_guid:$guid})-[:RAN_AS]->(acct:Account)
   RETURN acct.sam, acct.domain, acct.privileged
   ```
   SYSTEM/域管访问 + 源进程可疑 → 高危;普通 IIS AppPool 身份读 LSASS = 几乎必恶意。

5. **Q:读完之后干了什么(横向/外连/落地)?** → 证据:同一 `process_guid` 的后续行为 → 图:
   ```cypher
   MATCH (src:Process {process_guid:$guid})
   OPTIONAL MATCH (src)-[:CONNECTED_TO]->(ip:IPAddress)
   OPTIONAL MATCH (src)-[:SPAWNED*1..3]->(c:Process)
   OPTIONAL MATCH (src)-[:WROTE]->(f:File)
   RETURN ip.ip, ip.reputation, c.image, c.command_line, f.path
   ```
   读 LSASS 后紧跟外连坏 IP / 写 dump 文件 / 派生 PsExec 横向 → 闭环 TP。

**误报/良性场景(null hypothesis,逐条列全)**:
- **Defender/AV/EDR 自身**:`MsMpEng.exe`、各家 EDR 传感器会以 `0x1000/0x1400/0x101000` 甚至含读位访问 LSASS 做扫描 —— 真实企业头号 FP,必须按**源进程签名+路径白名单**排除。GOAD:靶场默认 Defender 常关或弱化,此类 FP 较少,但一旦装 EDR 就会出现。
- **系统进程**:`csrss.exe`、`wininit.exe`、`lsm.exe`、`wmiprvse.exe`、`svchost.exe` 常态查询 LSASS(多为无 `0x10` 的查询掩码)。GOAD 里同样出现,靠 `SourceImage` + 掩码(无 VM_READ)区分。
- **备份/凭据管理/性能监控软件**:企业里备份代理、密码保险箱、APM 探针可能读进程内存 —— 真实企业有,GOAD 一般没有。靠源进程签名/发布者 + 运维报备区分。
- **管理员正常排障**:任务管理器"创建转储文件"、Process Explorer/ProcDump 手动抓 dump(`0x1410`/`0x1fffff`)。GOAD 里做题时也会出现。区分:**父进程是否交互式 explorer/管理员会话 + 命令行是否明确带 `lsass`**;ProcDump 由脚本静默调用则可疑。
- **良恶区分总则**:白名单源进程 + 掩码无 `0x10` + `call_trace` 全签名模块 → FP;非白名单源进程(尤其 cmd/powershell/rundll32/未知路径)+ 掩码含 `0x10`(更含 `0x20`)+ `call_trace` 含 dbghelp 或 UNKNOWN → TP。

**判定逻辑(证据组合→verdict)**:
- **TP**:`GrantedAccess` 含 `0x10`(尤其 0x1438/0x143a/0x1fffff)**且** `SourceImage` 非白名单(cmd/powershell/rundll32/temp/downloads 路径)**且**(父链可疑 **或** call_trace 含 dbghelp/dbgcore/UNKNOWN **或** 读后有外连/横向)。
- **suspicious**:掩码含 `0x10` 但源进程签名可信、无后续恶意行为 —— 挂起等运维确认。
- **FP/benign**:源进程 ∈ {MsMpEng、系统进程、已报备备份/AV}**且**掩码无 `0x10`(或为已知良性组合)**且** call_trace 全签名。

**经验层复用**:
```cypher
MATCH (src:Process {image:$srcimg})<-[:ON]-(d:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(pa:Alert)
MATCH (pa)-[:INDICATES]->(:Technique {attack_id:'T1003.001'})
RETURN v.verdict, count(*) AS n ORDER BY n DESC
```
"这台主机 / 这个源进程近 30 天被判过 FP(如某备份代理)"→ 直接降权;若历史全 TP 或该源进程从未合法访问过 LSASS → 升权。可进一步按 `Host{criticality:'high'}`(dc01/dc02/dc03 域控)加权。

**⚠️图盲区**:
- **源进程 EXE 的签名/发布者/自身哈希**:`Process` 无 `signed`/`signer`/`sha256` 属性(`signed` 只在 `Module` 上,`sha256` 只在被 `WROTE` 的 `File` 上)。白名单"按签名放行"这一核心判据取不到,只能退化到 `image` 路径匹配 —— 易被同名/路径伪装绕过。
- **call_trace 语义化**:`granted_access`、`call_trace` 作为 `Event` 标量保留(存在),但是否已解析成"模块名+偏移"列表、能否直接判定"含 dbghelp/UNKNOWN"未知,可能仍是原始串需二次解析。
- **是否真落地 dump 文件**:LSASS dump 常写盘(`.dmp`),但除非 Sysmon EID11 命中且 `File.sha256` 被填充,否则拿不到落地文件哈希/信誉。
- **句柄复制类转储**(comsvcs.dll MiniDump、任务管理器 `DUP_HANDLE` 二段)可能不体现直接 VM_READ,当前掩码白名单可能漏检 —— 需 `0x40` 位关注。

### Ingress Tool Transfer (T1105,主机层)

**攻击本质**:攻击者把外部工具/载荷(木马、C2 beacon、提权工具、mimikatz)拉进已控主机并落地,为后续执行做准备。

**触发逻辑(我们栈)**:Wazuh 内置规则命中(下载类行为/命令行特征),**极吵,占告警 93%(6706 条)**。多数并非攻击 —— 关键是**降噪**,不是逐条深挖。图里多落为下载进程的 `CONNECTED_TO`(IP,标量 `dest_port`)、`QUERIED`(Domain)、`WROTE`(File)。

**研判决策树(降噪优先:先批量证伪,再对残余深挖)**:

1. **Q:哪些"源进程 × 主机"在刷屏?先聚类,不逐条看。** → 证据:按下载进程 image 聚合计数 → 图:
   ```cypher
   MATCH (a:Alert)-[:INDICATES]->(:Technique {attack_id:'T1105'})
   MATCH (a)<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process)
   MATCH (e)-[:ON_HOST]->(h:Host)
   OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
   RETURN h.hostname, p.image, parent.image, count(a) AS n
   ORDER BY n DESC
   ```
   头部若是浏览器/更新器/包管理器(见下白名单)→ **整簇批量判 FP**,一次性降噪。

2. **Q:下载进程与父进程是"正常下载器"还是"攻击 LOLBin"?** → 证据:`p.image` + 父链 + `command_line`。良性:`msedge/chrome/firefox`、`svchost`(WU)、`TrustedInstaller/TiWorker`、`MsMpEng`(签名更新)、`OneDrive/Teams` 更新、`msiexec`。恶意/可疑:`certutil -urlcache -f`、`powershell (New-Object Net.WebClient).DownloadString/iwr/curl.exe`、`bitsadmin /transfer`、`mshta http…`、且父进程是 `w3wp/cmd/wscript` → 保留深挖。

3. **Q:外连目的地是否可疑?** → 证据:目的 IP 信誉 / 域 → 图:
   ```cypher
   MATCH (p:Process {process_guid:$guid})-[:CONNECTED_TO]->(ip:IPAddress)
   OPTIONAL MATCH (p)-[:QUERIED]->(d:Domain)
   RETURN ip.ip, ip.reputation, ip.asn, ip.geo, d.fqdn, p.command_line
   ```
   目的是微软/厂商 CDN(信誉良好、ASN 属大厂)→ FP;裸 IP、坏信誉、DDNS/新注册域、非常见端口(`dest_port` 标量)→ 升权。

4. **Q:落地文件是什么、写在哪、随后是否被执行?** → 证据:`WROTE`→File 路径/哈希,及后续 `SPAWNED` → 图:
   ```cypher
   MATCH (p:Process {process_guid:$guid})-[:WROTE]->(f:File)
   RETURN f.path, f.sha256
   // 是否随即从该路径起进程(下载→执行闭环):
   MATCH (p)-[:SPAWNED*1..2]->(c:Process)
   RETURN c.image, c.command_line
   ```
   落到 `Temp/AppData/ProgramData/Public` 的可执行文件 **且随即被 `SPAWNED` 执行** = 高危闭环;落到软件安装目录且未执行 = 偏良性。

5. **Q:这台主机此刻是否伴随其他攻击面告警?** → 证据:同主机同时段告警 → 图:
   ```cypher
   MATCH (h:Host {hostname:$h})<-[:ON_HOST]-(e:Event)-[:TRIGGERED]->(a:Alert)
   WHERE e.event_time > $t0 - 900 AND e.event_time < $t0 + 900
   RETURN a.rule_description, a.technique_ids
   ```
   若同窗口有 LSASS/webshell/持久化告警 → T1105 从"孤立噪声"升为攻击链一环。

**误报/良性场景(逐条列全,T1105 的降噪主战场)**:
- **浏览器正常下载**(msedge/chrome/firefox 下文件)—— 真实企业最大宗 FP,GOAD 里做题时下工具也会命中。区分:父进程=explorer/浏览器 + 目的=大厂 CDN。
- **系统/软件更新**:Windows Update(`svchost -k netsvcs` / `wuauclt`)、`TiWorker/TrustedInstaller`、Defender 签名更新(MsMpEng)、Chrome/Edge/Teams/OneDrive 自更新。企业普遍,GOAD 也有(域控/成员机联网时)。
- **软件分发/包管理**:SCCM/Intune、`msiexec`、`choco/winget/pip/npm`、内部软件仓库拉包。企业常见,GOAD 少。
- **管理员正常运维**:管理员手动 `curl/Invoke-WebRequest` 下工具、`git clone` —— 企业与 GOAD 都有。区分靠**账户是否交互式管理员会话 + 目的信誉 + 是否落到运维目录而非 Temp**。
- **良恶区分总则**:下载进程 ∈ 白名单更新器/浏览器 且 目的 IP/域信誉良好 且 无"落地即执行" → FP;LOLBin(certutil/bitsadmin/mshta/编码 PowerShell)+ 坏信誉目的 + 落 Temp 即 `SPAWNED` + 父进程可疑 → TP。Wazuh 侧长期应把此规则降级(child rule 降到 level 3-5)并按资产组分档,而非逐条报。

**判定逻辑(证据组合→verdict)**:
- **FP/benign(占绝大多数)**:源进程 ∈ 白名单 **或** 目的信誉良好且落安装目录且未执行。
- **suspicious**:LOLBin 下载但目的信誉未知、未见落地执行 —— 观察挂起。
- **TP**:非白名单 LOLBin/编码下载 **且**(目的坏信誉 **或** 落 Temp/AppData 即被执行 **或** 同主机同时段有其他攻击链告警)。

**经验层复用**:"这台主机上 msedge/svchost 下载上周已判 FP(白名单)"→ 直接批量抑制,是把 6706 条压下来的关键手段。仅对**历史无 FP 记录的新源进程/新目的**投入深挖。

**⚠️图盲区**:
- **完整下载 URL / 文件名**:`QUERIED`→Domain 只给域名,`CONNECTED_TO`→IP 给地址,但**具体 URL 路径、下载的文件名**取不到(除非是 PowerShell 脚本块经 `EXECUTED`→Uri)。
- **落地文件哈希/信誉**:`File.sha256` 仅当 Sysmon EID11 命中且被填充才有;Sysmon FileCreate 默认不带哈希,多数下载落地拿不到哈希去查信誉。
- **下载进程 EXE 签名**:同 LSASS,`Process` 无签名属性,白名单只能按 image 路径,易被伪装。
- **IP 信誉时效**:`IPAddress.reputation` 存在但是否实时更新、覆盖大厂 CDN 判定未知,可能误伤良性 CDN。
- **协议/内容**:无 TLS SNI、无载荷字节,无法辨"HTTPS 到大厂 CDN"与"HTTPS 到 C2"除信誉外的差异。

### 注册表持久化 (T1547.001 / T1112,主机层)

**攻击本质**:攻击者写 `Run`/`RunOnce`/`Winlogon`/`Services` 等自启键,让载荷在开机/登录时自动执行,获得重启存活的持久化。

**触发逻辑(我们栈)**:Sysmon **EID13(RegistrySet)** 命中受监控自启键。图里落为 `(:Event event_code:13)-[:BY]->(:Process)-[:SET]->(:RegistryValue{hive,key_path,value_name})`,标量 `value_data` = 被写入的启动命令(**研判最关键字段**)。

**研判决策树**:

1. **Q:写的是哪个键、值指向什么?** → 证据:键路径 + `value_data` → 图:
   ```cypher
   MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:13})-[:BY]->(p:Process)
   MATCH (e)-[:SET]->(rv:RegistryValue)
   MATCH (e)-[:ON_HOST]->(h:Host)
   RETURN h.hostname, rv.hive, rv.key_path, rv.value_name,
          e.value_data, p.image, p.command_line
   ```
   `value_data` 指向 `Temp/AppData/ProgramData/Public`、带编码 PowerShell/`rundll32`/`mshta`/无引号可疑路径 → 高危;指向 `Program Files\<厂商>\...exe` 且值名=已知软件 → 偏良性。

2. **Q:是谁写的键 —— 安装器还是攻击工具?** → 证据:写入进程 + 父链 → 图:沿 `SPAWNED` 回溯 `p`。
   `msiexec/setup/TiWorker/软件自身` 写 Run 键 = 正常安装/更新;`cmd/powershell/rundll32/reg.exe/wscript` 且父进程可疑写 Run 键 = 恶意持久化。

3. **Q:被持久化的那个载荷从哪来(溯源)?** → 证据:关联 T1105 落地与执行 → 图:
   ```cypher
   MATCH (p2:Process)-[:WROTE]->(f:File)
   WHERE f.path CONTAINS <value_data 中的路径>
   MATCH (writer:Process)-[:SPAWNED*0..3]->(p2)
   RETURN f.path, f.sha256, writer.image
   ```
   若持久化目标文件正是此前被下载/释放的 → 与 T1105/dropper 串成链,TP 佐证。

4. **Q:写键账户与主机权限?** → 证据:`RAN_AS` + 主机重要性 → 图:`(p)-[:RAN_AS]->(:Account)`;`Host.criticality`。域控/高价值主机上非安装器写自启 → 高危。

**误报/良性场景(逐条列全)**:
- **安装器/更新器写自启**:海量合法软件开机自启(杀软、显卡/声卡驱动托盘、OneDrive、Teams、`ctfmon`、企业代理),由 `msiexec/setup/TiWorker` 或软件本体写入 —— 真实企业**最大宗** FP。GOAD:成员机/域控装软件时同样出现。
- **GPO/登录脚本/企业管理**:SCCM/Intune、GPP 下发的自启项。企业常见,GOAD(有域)也可能通过 GPO 出现。
- **管理员手动配置**:运维手动加自启工具。企业+GOAD 都有,靠交互式会话 + 目标为合法路径区分。
- **良恶区分总则**:写入进程 ∈ 安装器/更新器 且 `value_data` 指向签名软件目录 → FP;写入进程 = LOLBin/脚本宿主 且 `value_data` 指向 Temp/AppData 或含编码命令 且 父链可疑 → TP。

**判定逻辑(证据组合→verdict)**:
- **TP**:`value_data` 指向非标准路径(Temp/AppData/Public)或含编码/LOLBin **且** 写入进程为 cmd/powershell/rundll32/reg/wscript **且** 父链或写入账户可疑 **或** 目标文件可溯到下载/释放。
- **suspicious**:非常见但指向合法目录、写入进程可信度中等 —— 挂起。
- **FP/benign**:安装器/更新器/GPO 写入,`value_data` 指向签名软件安装目录,值名匹配已知软件。

**经验层复用**:"这台主机这个 `value_name`(某软件托盘)历史判过 benign"→ 抑制该值名重复告警;新出现的 `value_name` 优先深挖。

**⚠️图盲区**:
- **被持久化文件的哈希/签名**:`value_data` 是字符串路径,要判"这个 exe 是否恶意"需该文件的 `File.sha256`/签名 —— 除非该文件恰有 `WROTE` 事件被抓且哈希填充,否则取不到,只能靠路径启发式。
- **写入进程 EXE 签名**:同前,`Process` 无签名属性,无法直接区分"合法更新器"与"伪装成更新器的进程"。
- **键的删除/前值**:EID13 记新值,图里 `RegistryValue` 以 `value_data` 为标量,**无历史前值/是否覆盖既有合法值**,难判"篡改 vs 新建"。
- **RunOnce 之外的持久化面**:Winlogon `Shell/Userinit`、`Image File Execution Options`、COM 劫持等键是否都纳入 EID13 监控与入图,取决于 Sysmon 配置,未覆盖的键 = 盲区。

### 可疑进程 / LOLBin / 恶意子进程 (T1059 / T1055 / T1218,主机层)

**攻击本质**:攻击者借合法二进制(LOLBin:rundll32/mshta/regsvr32/certutil)或从异常父进程(webshell、被利用服务)派生 shell,执行编码命令、下载执行、注入,规避基于"陌生 EXE"的检测。

**触发逻辑(我们栈)**:Sysmon **EID1(ProcessCreate)** 命中异常父子链或可疑命令行(w3wp/services 派生 cmd/powershell、rundll32 无参、`-enc`/`EncodedCommand`)。图里落为 `(:Process 父)-[:SPAWNED]->(:Process 子)`,子进程带 `command_line`,并派生 `RAN_AS`→Account。

**研判决策树(端点分析师主判法:父子链还原 + 命令行)**:

1. **Q:父进程是不是"不该生 shell 的进程"?** → 证据:父/祖父链 → 图:
   ```cypher
   MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:1})-[:BY]->(parent:Process)
   MATCH (parent)-[:SPAWNED]->(child:Process)
   MATCH (e)-[:ON_HOST]->(h:Host)
   OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(parent)
   RETURN h.hostname, gp.image, parent.image, child.image, child.command_line
   ```
   **高危父进程**:`w3wp.exe`/`httpd`/`tomcat`(webshell)、`services.exe`/`spoolsv.exe`/`wmiprvse.exe`/`sqlservr.exe` 派生 `cmd/powershell/rundll32/mshta` —— 强 TP 信号(Splunk WebServer child / Elastic Exchange worker)。

2. **Q:命令行有无恶意特征?** → 证据:`child.command_line` → 图:读该属性。关注 `-enc/-EncodedCommand`、`-nop -w hidden`、`DownloadString/IEX/FromBase64String`、`rundll32` 无参或调可疑导出、`regsvr32 /s /u /i:http`、`mshta http`、`certutil -decode`。

3. **Q:子进程以什么身份运行(webshell 判定关键)?** → 证据:`RAN_AS` → 图:
   ```cypher
   MATCH (child:Process {process_guid:$guid})-[:RAN_AS]->(acct:Account)
   RETURN acct.sam, acct.domain, acct.privileged
   ```
   `IIS APPPOOL\*` / `NT AUTHORITY\NETWORK SERVICE` 身份跑 powershell/cmd → webshell 强指纹。

4. **Q:子进程随后做了什么(把链拉全)?** → 证据:后代进程 + 外连 + 落地 + LSASS/持久化 → 图:
   ```cypher
   MATCH (child:Process {process_guid:$guid})
   OPTIONAL MATCH (child)-[:SPAWNED*1..3]->(desc:Process)
   OPTIONAL MATCH (child)-[:CONNECTED_TO]->(ip:IPAddress)
   OPTIONAL MATCH (child)-[:ACCESSED]->(:Process {image:'lsass.exe'})
   OPTIONAL MATCH (child)-[:SET]->(rv:RegistryValue)
   RETURN desc.image, desc.command_line, ip.ip, ip.reputation, rv.key_path
   ```
   派生 → 外连 C2 / 读 LSASS / 写 Run 键 = 攻击链闭环,直接 TP。

5. **Q:是不是运维/软件的正常派生?** → 证据:父链是否交互式、命令行是否有业务意义 → 见误报场景。

**误报/良性场景(逐条列全)**:
- **管理运维正常调 shell**:管理员 explorer/终端派生 powershell/cmd、`psexec`、`schtasks`、登录脚本(`gpscript`→cmd)。真实企业大量,GOAD 做题时更密集。区分:父=交互式 explorer/终端 + 无编码 + 账户为管理员会话。
- **合法软件用 LOLBin**:安装器/更新器调 `rundll32`(带正常导出+参数)、`regsvr32` 注册 DLL、`msiexec`、SCCM/GPO 触发脚本。企业常见,GOAD 有(域 GPO)。区分:`rundll32` **有**合法导出参数 vs 无参/可疑导出。
- **管理/监控软件父进程派生**:企业 RMM、备份、监控代理以服务身份派生子进程。真实企业有,GOAD 少。靠父进程签名/白名单区分。
- **开发/CI**:开发机 `node/python/msbuild` 派生 shell。真实企业有,GOAD 无。
- **良恶区分总则**:父=交互式/合法安装器 且 命令行有明确业务语义 且 无编码/下载执行 → FP;父=服务/Web 进程 且 子=shell/LOLBin 且 命令行含编码/下载/隐藏 且 `RAN_AS` 为服务账户 且 有后续外连/落地 → TP。

**判定逻辑(证据组合→verdict)**:
- **TP**:异常父进程(w3wp/services/spoolsv/wmiprvse/sqlservr)派生 shell/LOLBin **或** 命令行含 `-enc`/下载执行 **且**(以服务/低权账户运行 **或** 有后续 SPAWNED→外连/LSASS/持久化)。
- **suspicious**:命令行可疑但父链交互式、无后续恶意行为 —— 挂起等运维确认。
- **FP/benign**:交互式管理员会话 或 合法安装器/GPO 派生,命令行有业务语义、无编码/下载。

**经验层复用**:"这台主机 `parent.image` + `child.image` 这个组合上周判过 FP(某运维脚本 explorer→powershell)"→ 降权;历史无此组合 或 该父进程从不该生 shell(w3wp)→ 升权。可用聚合边看基线:`(:Process{image:'w3wp'})-[:SPAWNED{count,first_seen}]->(:Process)` 是否从无到有首次派生 cmd(count=1、first_seen=近) = 强异常。

**⚠️图盲区**:
- **进程 EXE 签名/信誉/是否 LOLBin 原版**:`Process` 无签名/哈希,无法验证 `rundll32.exe` 是系统原版还是同名伪装,也无法查子进程二进制信誉。
- **进程完整性级别 / Token 提权**:图里无 integrity level、无 token 提权/模拟信息,难判"服务账户被 impersonate 提权"。
- **命令行解码后语义**:`-EncodedCommand` 的 Base64 是否已解码入图未知;若只存原始编码串,判"编码内容恶意"需二次解码(可结合 4104 `EXECUTED`→脚本块摘要,但为弱关联)。
- **注入类子行为**:T1055(进程注入)体现为 `ACCESSED` 含 VM_WRITE/CREATE_THREAD,但注入的目标线程/shellcode 内容、被注入进程是否行为异常,图里靠掩码+call_trace 间接推断,细节盲区。
- **DLL 侧加载**:LOLBin 侧加载恶意 DLL 走 `LOADED`→Module(`Module.signed` 可用),但需 EID7 命中且与本进程关联,若未采集则盲。

### 主机层·模型缺口汇总

| # | 图盲区(取不到的证据) | 影响的告警 | 补哪个实体/属性/谓语/字段 |
|---|---|---|---|
| 1 | **进程 EXE 自身的签名/发布者/哈希** —— 白名单只能按 `image` 路径,易被同名伪装绕过 | 全部四类 | 给 `Process` 增 `sha256`、`signed`(bool)、`signer`/`company`、`is_lolbin`(bool);或把进程镜像也建成 `File` 节点并加 `(:Process)-[:IMAGE_OF]->(:File)` |
| 2 | **落地文件的哈希/信誉** —— `File.sha256` 常因 Sysmon FileCreate 不带哈希而空 | T1105、注册表持久化 | 补采 Sysmon EID1 镜像哈希 / 启用 FileCreate 哈希;给 `File` 加 `reputation`、`signed`;`value_data` 路径解析为 `-[:REFERS_TO]->(:File)` |
| 3 | **call_trace / granted_access 的语义化** —— 存为标量但可能是原始串 | LSASS、注入类 | 解析 `call_trace` 为模块列表 + `has_unbacked`/`has_dbghelp`(bool);`granted_access` 解成位标志(`vm_read`/`vm_write`/`create_thread`) |
| 4 | **完整下载 URL / 文件名** | T1105 | 给网络事件加 `url`/`uri` 标量;下载事件 `WROTE`→File 与 `CONNECTED_TO`→IP 用同 `process_guid`+时间关联成"下载-落地"链 |
| 5 | **命令行解码后内容**(`-EncodedCommand`) | LOLBin/可疑进程 | 入图时解码 `-enc` 存 `decoded_command`;强化 4104 `EXECUTED` 与 EID1 进程的 `process_guid` 强关联 |
| 6 | **进程完整性级别 / Token 提权 / 模拟** | LOLBin、LSASS | `Process` 加 `integrity_level`、`elevated`、`impersonation_level`;`LogonSession` 加 `elevated_token` |
| 7 | **注册表前值/是否覆盖** | 注册表持久化 | `SET` 事件加 `old_value_data` 或版本化 `value_data` |
| 8 | **IP 信誉的时效与覆盖** | T1105、LSASS 后续外连 | 明确 `IPAddress.reputation` 刷新策略,补 `is_known_cdn`/`asn_owner` |
| 9 | **EDR / ASR / Defender 侧遥测与排除态** | LSASS、LOLBin | 上真实企业时接 EDR/Defender 告警为独立 `Alert`,与 Sysmon 事件按 `process_guid`/`Host` 互证 |
| 10 | **持久化/自启监控面覆盖度**(Winlogon/IFEO/COM) | 注册表持久化 | 扩展 Sysmon 注册表监控范围并确认这些 `key_path` 入图 |

> 优先级:**#1(进程签名/哈希)与 #3(掩码/call_trace 语义化)** 对 LSASS 与 LOLBin 判准影响最大,优先;**#2+#4+#5** 三者合力才能把 T1105 从"6706 条噪声"稳定降噪并串成"下载→落地→执行→持久化"链。

---

## 3. 身份层(Identity / AD)

> 研判总走法:`(:Alert)` →(反查 `TRIGGERED`)→ `(:Event)` →(`BY`/谓语/`FROM`/`ON_HOST`/`PRODUCED`)→ 涉及实体 →(实体↔实体**聚合边** `count/first_seen/last_seen`)看基线与新颖度 →(同主语/同会话的 `(:Event)` 按 `event_time`)还原时序 →(实体一跳到 `Verdict/Disposition`)复用历史结论。判序固定:**先证伪 → 看基线新颖度 → 看权限/资产价值 → 看时序与扇出 → 看横向落地后行为**。

### Kerberoasting (T1558.003,身份层)

**攻击本质**:任意域用户向 DC 请求某个带 SPN 账号的服务票据(TGS),票据的一段用该服务账号的 NTLM 哈希加密;攻击者离线爆破还原服务账号明文口令。RC4(etype `0x17`)是爆破工具(Rubeus/Impacket GetUserSPNs)刻意索取的可离线破解格式。

**触发逻辑(我们栈)**:Wazuh 命中 Security **4769**(TGS-REQ)且 `ticketEncryptionType=0x17`(RC4-HMAC)且 `serviceName` 非机器账号(不以 `$` 结尾)。入图后:`(:Alert{rule_id, technique_ids:['T1558.003']})<-[:TRIGGERED]-(:Event{event_code:'4769', enc_type:'0x17'})-[:REQUESTED]->(服务Account/Service)`。RC4 是首要信号,现代域几乎不该出现用户 SPN 的 RC4 票据,应视为异常直到被证伪(adsecurity / Splunk)。

**研判决策树**:
1. **Q:请求者是普通用户,还是服务/机器账号?(先证伪)** → 证据:触发事件的 `BY` 主语账号类型/是否特权。服务账号本就常年请求 TGS,机器账号($)规则已排除。 → 图:
   `MATCH (a:Alert{alert_uid:$id})<-[:TRIGGERED]-(e:Event{event_code:'4769'})-[:BY]->(req:Account) RETURN req.sam, req.domain, req.type, req.privileged, e.enc_type, e.ticket_options`
2. **Q:目标 SPN 账号价值几何?是特权服务账号吗?** → 证据:`REQUESTED` 宾语(Service/服务Account)及其组成员;`privileged` 状态。 → 图:
   `MATCH (e)-[:REQUESTED]->(tgt) OPTIONAL MATCH (tgt)-[:MEMBER_OF]->(g:Group) RETURN tgt.sam, tgt.privileged, collect(g.name)`
3. **Q:RC4 对这个请求者/这个目标是否属于历史异常?(看基线)** → 证据:请求者历史 4769 的 `enc_type` 分布 + 聚合边 `first_seen`(是否首次接触该目标)。 → 图:
   `MATCH (req:Account)<-[:BY]-(ev:Event{event_code:'4769'}) RETURN ev.enc_type, count(*)` 与 `MATCH (req:Account)-[r:REQUESTED]->(tgt) RETURN r.first_seen, r.count`。若该目标一贯 RC4 → 老应用基线,降权。
4. **Q:单票还是 SPN 扫描(扇出)?** → 证据:窗口内该请求者的 4769 命中的**去重目标数**。 → 图:
   `MATCH (req:Account)<-[:BY]-(ev:Event{event_code:'4769'})-[:REQUESTED]->(tgt) WHERE ev.event_time>$t0 RETURN count(DISTINCT tgt)`。短时大量去重 SPN = GetUserSPNs 式扫描,是强 TP 信号(Vectra)。
5. **Q:请求从哪台机器/会话发出?符合该用户日常吗?** → 证据:`FROM`→IP,回溯是否有该用户的前置 4624 会话。 → 图:
   `MATCH (e)-[:FROM]->(ip:IPAddress) OPTIONAL MATCH (h:Host)-[:HAS_IP]->(ip) RETURN ip.ip, h.hostname, h.role`
6. **Q:爆破是否已成功?(看横向落地)** → 证据:被 roast 的服务账号在告警后是否从**新主机/新 IP** 发起 `AUTHENTICATED_TO`。 → 图:
   `MATCH (tgt:Account)<-[:BY]-(ev2:Event{event_code:'4624'})-[:AUTHENTICATED_TO]->(h:Host) WHERE ev2.event_time>$roast RETURN h.hostname, ev2.logon_type`

**误报/良性场景(null hypothesis,逐条)**:
- **漏扫/AD 评估工具**(Nessus/Qualys 凭据扫描、PingCastle、Purple Knight、BloodHound)会批量枚举 SPN 并取票 → 长得像 SPN 扫描。GOAD:默认无,但蓝队跑评估工具会复现。
- **只支持 RC4 的老应用/设备**(NetApp、老 JBoss/Java、部分 SQL 链接服务器、打印机)→ 合法 RC4 4769(Microsoft Learn)。GOAD:mssql 等服务本就弱配,RC4 常见。
- **跨林/跨域信任**默认 RC4(除非在信任上启用 AES)→ 跨域 4769 携 RC4。GOAD:多域(SEVENKINGDOMS/NORTH/ESSOS)带信任,**跨域 RC4 必然良性出现**,是本靶场头号 FP。
- **服务账号正常票据流失**:服务账号海量请求 TGS(规则已排 `$` 机器账号,但人名服务账号取票仍正常)。GOAD:是。
- **用户映射网络驱动器/访问共享**触发单张该服务的 4769 → 单张良性 RC4。GOAD:是。

**判定逻辑(证据组合→verdict)**:
- **true_positive**:非服务类普通用户 → 对从未接触过的人名/服务 SPN 请 RC4,且**短时扇出 ≥5 个去重 SPN(<10 min)**,来源非扫描器主机;或后续目标服务账号从新主机登录(=爆破成功已用凭据)。命中蜜罐 SPN(若有)= 铁定 TP(Zscaler)。
- **false_positive**:来源为已知扫描器账号/主机;或对历史一贯 RC4 的老应用 SPN 的单张票(基线 `first_seen` 久、`count` 高);或匹配信任拓扑的跨域 RC4。
- **suspicious(升级)**:对高价值 SPN(`privileged=true`)的 RC4、但低量无扇出、请求者无基线 → 可能是定点单票 roast,升级做口令强度/可爆破性复核。

**经验层复用**:
`MATCH (req:Account)<-[:ON]-(:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(:Alert)-[:INDICATES]->(:Technique{attack_id:'T1558.003'}) RETURN v.verdict, v.confidence, v.summary`
若同请求者/同扫描器此前判 false_positive 且处置为"白名单扫描器",直接降级;若目标服务账号此前 TP,优先。

**⚠️图盲区**:
- 目标 SPN 的**服务类别**(MSSQLSvc/HTTP/CIFS)与**账号是否 high-value/受保护层级**——仅有 `privileged` 布尔 + 组成员,缺业务分级。
- **蜜罐/decoy SPN 标记**——Account 无 `is_decoy` 属性,最强 FP 消解手段取不到。
- **已授权扫描器**标记——Account/IPAddress 无"sanctioned scanner"属性,只能靠经验层兜。
- **离线爆破本身**(T1110)不可见,只能由后续登录反推成功与否。

### ADCS 证书滥用 (T1649,身份层)

**攻击本质**:滥用错配的证书模板或 Web 注册端点获取一张能"以他人身份认证"的证书。ESC1:模板开 `ENROLLEE_SUPPLIES_SUBJECT` + 客户端认证 EKU → 请求时自填任意 SAN(冒充管理员)。ESC8:向 CA Web 注册端点做 NTLM 中继,替被中继账号(常是机器账号/DC)取证书。证书=长期域内持久化。

**触发逻辑(我们栈)**:Wazuh 命中 **4886**(CertRequest 收到)/ **4887**(证书签发)。入图:`(:Alert{technique_ids:['T1649']})<-[:TRIGGERED]-(:Event{event_code:'4887'})-[:BY]->(req:Account)`,`(:Event)-[:REQUESTED]->(:Service{kind:'certificate_authority'})`,标量 `request_type,template`。核心判据是**证书主体/SAN 与请求者不一致**(Medium/shamhus / CrowdStrike)。

**研判决策树**:
1. **Q:请求者是谁、对哪个 CA/模板?** → 证据:`BY` 账号、`REQUESTED` 的 CA Service、标量 `template`/`request_type`。 → 图:
   `MATCH (a:Alert{alert_uid:$id})<-[:TRIGGERED]-(e:Event{event_code:'4887'})-[:BY]->(req:Account), (e)-[:REQUESTED]->(ca:Service{kind:'certificate_authority'}) RETURN req.sam, req.privileged, ca.name, e.template, e.request_type`
2. **Q:证书主体/SAN 是否 ≠ 请求者?(冒充,ESC1/ESC6 首要判据)** → ⚠️ **SAN 未建模,请求者↔主体 mismatch 无法在图内直接判**(见盲区);当前只能取到 `Certificate.subject` 字符串。
3. **Q:模板本身危险吗?(ESS 标志 + 客户端认证 EKU)** → ⚠️ 仅有 `template` 名字符串,EKU/是否 enrollee-supplies-subject/是否需审批未建模,需外部模板清单交叉。
4. **Q:低权用户在换取特权认证能力?** → 证据:`req.privileged`、组成员。 → 图:
   `MATCH (req)-[:MEMBER_OF]->(g:Group) RETURN req.privileged, collect(g.name)`
5. **Q:ESC8 角度——是否经 Web 注册端点、且"请求者"实为机器账号并伴随中继/NTLM?** → 证据:`request_type`(web vs RPC)、`FROM`→IP、时间邻近的一条被中继 NTLM 认证(4624/4776)。 → ⚠️ 中继链无显式建模,只能时序关联。
6. **Q:证书随后被用来认证了吗?(落地)** → 证据:被冒充主体随后 PKINIT(4768 TGT / 4624)从新上下文出现。 → 图:
   `MATCH (victim:Account)<-[:BY]-(ev:Event{event_code:'4768'}) WHERE ev.event_time>$issue RETURN victim.sam, ev.event_time`

**误报/良性场景(逐条)**:
- **正常证书注册/自动注册**:用户/机器为合法模板(用户认证、机器认证、EFS、802.1x/WiFi、代码签名)注册,真实企业量极大。GOAD:ESSOS 有 ADCS,量小但存在。
- **自动注册续期**(`request_type=renewal`):机器账号为自己续期,subject==requester → 良性。GOAD:是。
- **合法 Web 注册**:少数组织正常用 Web 注册。GOAD:罕见。
- **requester==subject 的合法申请**:即便模板技术上脆弱,主体与请求者一致即非冒充。

**判定逻辑(证据组合→verdict)**:
- **true_positive**:SAN/主体 ≠ 请求者 **且**该主体为特权(或请求者低权),模板为已知脆弱模板,尤其随后出现以被冒充主体的 PKINIT 认证。ESC8:机器账号证书经 Web 端点签发 + 时间邻近的入站 NTLM 中继。
- **false_positive**:requester==subject;已有机器/用户证书的续期;身份一致的已知自动注册模板。
- **suspicious(升级)**:低权用户注册带客户端认证 EKU 的异常模板但主体与自己一致;或**因 SAN 盲区无法判定**——一律升级到 suspicious 并人工拉 CA 日志(标记为模型缺口)。

**经验层复用**:按模板名(`Certificate.template`/事件标量)与请求者跨历史。某模板此前 TP → 该模板任何新注册高优先。
`MATCH (req:Account)<-[:ON]-(:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(:Alert)-[:INDICATES]->(:Technique{attack_id:'T1649'}) RETURN v.verdict, v.confidence`

**⚠️图盲区**:
- **证书 SAN + 请求者↔主体 mismatch**——ESC1/ESC6 头号判据,不在 schema(Certificate 有 `subject` 无 `san`;4887 标量无 SAN)。**最关键缺口**。
- **模板 EKU / `ENROLLEE_SUPPLIES_SUBJECT` / 经理审批标志**——只有模板名,无法判模板是否脆弱。
- **ESC8 中继/强制认证链路**——无显式建模。
- CA 审计日志是否开启/转发(4886/4887 依赖 CA 审计,真实企业常缺)。

### DCSync (T1003.006,身份层)

**攻击本质**:攻击者持有(或自授)目录复制权限,伪装成 DC 发起复制(GetNCChanges),把任意/全部账号的口令哈希(尤其 `krbtgt`→金票)拉取下来。

**触发逻辑(我们栈)**:Wazuh 命中 **4662** 且访问的对象权限 `properties` 含 `DS-Replication-Get-Changes`(`1131f6aa-…`)/ `-Get-Changes-All`(`1131f6ad-…`)。入图:`(:Alert{technique_ids:['T1003.006']})<-[:TRIGGERED]-(:Event{event_code:'4662'})-[:BY]->(actor:Account)`,`(:Event)-[:ACCESSED]->(:DirectoryObject)`,`ON_HOST`→DC,复制 GUID 在标量 `properties`。核心是"**发起复制的是不是 DC**"——需排除 DC 机器账号,只在**非 DC 来源**时告警(BlackLantern / Elastic)。

**研判决策树**:
1. **Q:发起者是不是 DC 机器账号?(先证伪,决定性)** → 证据:`BY` 账号、`type`、是否为已知 DC。 → 图:
   `MATCH (a:Alert{alert_uid:$id})<-[:TRIGGERED]-(e:Event{event_code:'4662'})-[:BY]->(actor:Account) RETURN actor.sam, actor.type, actor.privileged`。`actor` 为用户账号或非 DC 机器账号 → 告警成立。
2. **Q:`properties` 是否真含复制 GUID(尤其 Get-Changes-**All**)?** → 证据:标量 `properties`;`ACCESSED` 的 DirectoryObject。 → 图:
   `MATCH (e)-[:ACCESSED]->(obj:DirectoryObject) RETURN e.properties, obj.dn, obj.object_class`。`1131f6ad`(All)才是拉哈希权限。
3. **Q:请求来源是不是 DC?** → 证据:`ON_HOST`(观测 DC)+ actor 当时登录会话所在主机。 → 图:
   `MATCH (e)-[:ON_HOST]->(dc:Host) RETURN dc.hostname, dc.role` + 旁证 `MATCH (actor)<-[:BY]-(l:Event{event_code:'4624'})-[:AUTHENTICATED_TO]->(src:Host)`。**从非 DC IP 发起复制是经典铁证**。
4. **Q:该账号是否本就是复制伙伴?(基线新颖度)** → 证据:actor↔DirectoryObject 聚合边 `first_seen/count`。 → 图:
   `MATCH (actor:Account)-[r:ACCESSED]->(obj:DirectoryObject) RETURN r.count, r.first_seen`。窗口内首见 = 强信号。
5. **Q:范围——定点(如仅 krbtgt)还是全域同步?** → ⚠️ 4662 不逐对象列出,难判具体拉了谁的哈希(见盲区)。
6. **Q:后续有无金票征兆或用凭据横移?** → 证据:同 actor/主机上后续异常 Kerberos(无 TGT 的 RC4 TGS、超长生命周期)或横向告警。 → 关联同源的 T1558/T1550 告警。

**误报/良性场景(逐条)**:
- **DC-to-DC 正常复制**:每台 DC 持续复制,规则必须排除 DC 机器账号。GOAD:dc01/dc02/dc03 持续复制 → 海量携该 GUID 的良性 4662,**头号 FP**。
- **Azure AD/Entra Connect 同步账号**(`MSOL_*`)做密码哈希同步 → 良性但来自非 DC 服务器,真实企业**巨量 FP**,必须精确白名单。GOAD:无 Entra Connect → **在 GOAD 非 DC 复制几乎必然恶意**。
- **备份/AD 审计/安全产品**(Quest/Netwrix、DSInternals、Semperis)合法请求复制,真实企业 FP。GOAD:仅当蓝队跑此类工具。

**判定逻辑(证据组合→verdict)**:
- **true_positive**:actor 为非 DC、非同步账号(尤其普通用户),`properties` 含复制 GUID(尤其 -All),来源非 DC,无复制伙伴基线。
- **false_positive**:actor 为已知 DC 机器账号;或来自其已知主机的受权 Entra Connect/备份同步账号。
- **suspicious(升级)**:特权管理员账号(非 DC)交互式发起复制——可能合法管理工具,也可能攻击者用窃取的 DA 凭据 → 升级核实变更工单。
- **判定阈值**:`actor.type=user` 且不在 DC/同步白名单 → TP;含 `1131f6ad`(All)→ 置信 +。

**经验层复用**:受权同步账号白名单实际沉在经验层——若该 actor 此前判 false_positive 且处置为"benign: AD Connect 同步",直接抑制。
`MATCH (actor:Account)<-[:ON]-(:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(:Alert)-[:INDICATES]->(:Technique{attack_id:'T1003.006'}) RETURN v.verdict, v.summary`

**⚠️图盲区**:
- **复制范围**(拉了 krbtgt 还是全部)——4662 固有限制,影响面无法评估。
- **授权前置**(攻击者刚给自己加复制 ACL:5136 / 域对象 DACL 变更)——谓语登记表**无对象 ACL 修改事件**,"谁授的 DCSync 权限"这条前置链取不到。
- **DC / 同步账号身份**——Host 无 `is_domain_controller`、Account 无 `is_sync_account` 标志(仅 `role`)。
- 复制时 **actor 真实工作站**——4662 记在 DC 上,攻击者机器只能靠登录会话弱关联。

### 横向移动 / PtH / PtT / 异常登录 (T1550.002 / .003 / T1021,身份层)

**攻击本质**:复用窃取的认证材料横向移动而无需明文——PtH(4624 type 3/9 + NTLM)、PtT(伪造/窃取的 TGT/TGS,含金票 T1558.001/银票 T1558.002)、异常远程登录(type 10 RDP)。

**触发逻辑(我们栈)**:Wazuh 基于 **4624** type 3/9/10 远程、**4768** TGT、**4776** NTLM 的异常登录规则(新来源、罕见主机、特权账号异常落点)。入图:`(:Event{event_code:'4624'})-[:AUTHENTICATED_TO]->(:Host)`,`FROM`→IP,`PRODUCED`→LogonSession,标量 `logon_type,result`。PtH 特征=type 3/9 + NtLmSsp + KeyLength 0 + 无前置交互会话(CyberArk);银票特征=成员机上有 Kerberos 登录但 DC 上无对应 4768/4769(ManageEngine)。

**研判决策树**:
1. **Q:谁、什么登录类型、登到哪台、从哪来?** → 图:
   `MATCH (a:Alert{alert_uid:$id})<-[:TRIGGERED]-(e:Event{event_code:'4624'})-[:BY]->(acc:Account), (e)-[:AUTHENTICATED_TO]->(h:Host) OPTIONAL MATCH (e)-[:FROM]->(ip:IPAddress),(e)-[:PRODUCED]->(s:LogonSession) RETURN acc.sam, acc.privileged, h.hostname, h.criticality, e.logon_type, ip.ip, s.logon_guid`
2. **Q:是否 PtH 特征?** type 3/9 + NTLM,且该用户在源机上无前置 type 2 交互登录。 → 图:
   `MATCH ... WHERE e.logon_type IN [3,9]` + 反证 `WHERE NOT EXISTS { (acc)<-[:BY]-(:Event{event_code:'4624', logon_type:2}) }`。type 9(NewCredentials)+ NTLM + 无对应交互会话几乎不合法(MITRE DET0409)。
3. **Q:是否 PtT 特征?** 成员机上的 Kerberos 登录在 DC 上**无对应 4768/4769**(银票),或 4768/4769 `enc_type`=RC4(AES 环境里)/异常 `ticket_options`/超长生命周期(金票)。 → 图:
   `MATCH (acc)<-[:BY]-(tgt:Event{event_code:'4768'}) RETURN tgt.enc_type, tgt.ticket_options`;缺 TGT 而有 Kerberos 登录=银票征兆(生命周期 ⚠️ 未建模)。
4. **Q:该账号↔主机组合是否属正常?(基线)** → 图:
   `MATCH (acc:Account)-[r:AUTHENTICATED_TO]->(h:Host) RETURN r.count, r.first_seen`。窗口内首见 + 特权 + 高价值主机 = 告警。
5. **Q:来源信誉/地理/不可能旅行?** → 图:
   `MATCH (e)-[:FROM]->(ip:IPAddress) RETURN ip.geo, ip.reputation, ip.first_seen`。纯内网 GOAD 用"该账号从未关联过的 IP"替代地理判据。
6. **Q:横向扩散/扇出?** 单身份短时登多台,或 host→host→host 链。 → 图:
   `MATCH (acc:Account)-[:AUTHENTICATED_TO]->(h:Host) WHERE ... RETURN count(DISTINCT h)`;沿会话 `AUTHENTICATED_AS`/进程 `RAN_AS`/`SPAWNED` 逐跳追。
7. **Q:落地后做了什么?** → 证据:目标机上以该账号 `RAN_AS` 的进程(psexec/wmic/winrm),或 Sysmon10 `ACCESSED` 对 LSASS。 → 图:
   `MATCH (p:Process)-[:RAN_AS]->(acc) RETURN p.image, p.command_line`

**误报/良性场景(逐条)**:
- **正常远程运维**:IT/助台用 RDP(type 10)+ 管理共享(type 3)横跨多机 → 像横向扩散。真实企业量大;GOAD:蓝队管理活动。
- **扫描器/配置核查**批量 type 3 登录多机 → 扇出 FP。
- **服务账号广泛认证**(应用、计划任务、SCCM/补丁、备份代理)type 3 遍布。
- **NTLM 合法使用**:按 IP 访问、非域主机、老应用仍用 NTLM → type 3 NTLM 不等于 PtH。GOAD:常见(弱配)。
- **域信任认证**:DC 上跨域 NTLM 的 4776。GOAD:多域带信任 → 跨信任 4776 良性遍布。
- **runas /netonly** 合法产生 type 9 NewCredentials。

**判定逻辑(证据组合→verdict)**:
- **true_positive**:账号↔主机首见(无基线)+ 特权账号 + PtH 特征(type 3/9 NTLM 无前置交互)或 PtT 特征(Kerberos 登录缺 TGT / AES 环境 RC4),尤其伴随**扇出多台 + 落地远程执行/LSASS 访问**,来源 IP 新/外部/差信誉。银票(成员机 Kerberos 登录 DC 无对应票)=高置信 TP。
- **false_positive**:来源为已知管理跳板/扫描器/管理服务器;账号是基线广泛的服务账号;到已知老应用的 NTLM;匹配信任拓扑的跨域 4776。
- **suspicious(升级)**:特权账号登上罕见主机但单跳无后续;或因生命周期盲区无法完全验证的 Kerberos 异常。
- **判定阈值**:acc↔host 聚合 `first_seen` 落在告警窗口 + `acc.privileged=true` → TP 倾向;单身份 <15 min 从非管理主机扇出 ≥3-5 台 → TP 倾向;银票征兆 → 高置信 TP。

**经验层复用**:按**来源主机**与**账号**跨历史。管理跳板/扫描器会被反复判 false_positive → 形成事实白名单。
`MATCH (h:Host)<-[:ON]-(:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(:Alert)-[:INDICATES]->(t:Technique) WHERE t.attack_id IN ['T1550.002','T1550.003','T1021.001'] RETURN v.verdict, v.confidence`

**⚠️图盲区**:
- **认证包(NTLM/Kerberos)+ KeyLength + 冒充级别**——PtH 首要签名依赖 package=NTLM & KeyLength 0,4624 只有 `logon_type` 标量,缺这三者(可借 4776 存在部分推断)。
- **票据生命周期 / renew-till**——金票判据(超长生命周期)取不到。
- **银票"缺 TGT"关联**——需"成员机 Kerberos 登录 + DC 无 4768/4769",依赖 DC 全覆盖;成员机 4624 与 DC 票据当前只能靠账号+时间弱关联(非硬键)。
- **来源工作站名解析**——NTLM type 3 常只有 WorkstationName;Host 以 asset_id/fqdn 为键,弱键 IP/主机名可能解析不到 Host 实体。

### 身份层·模型缺口汇总

| # | 缺口(取不到的证据) | 影响的研判 | 建议补法 |
|---|---|---|---|
| 1 | 证书 **SAN** 及请求者↔主体 mismatch | ADCS ESC1/ESC6 头号判据 | `Certificate` 加 `san`、`san_upn`;4887 告警补 `SubjectAltName`;主体≠请求者时派生 `(:Event)-[:IMPERSONATES]->(Account)` |
| 2 | 证书**模板 EKU / ENROLLEE_SUPPLIES_SUBJECT / 是否需审批** | 判模板是否脆弱 | 新增 `Template` 实体(键=模板名/oid),属性 `eku[]`、`enrollee_supplies_subject`、`requires_manager_approval`、`vulnerable_esc[]`;经 `USES_TEMPLATE` 关联 |
| 3 | **对象 ACL 修改**(5136 / 域对象 DACL 授予复制权)前置链 | DCSync"谁授的权"、ADCS ESC5/7 | 谓语登记表新增 5136 → `MODIFIED_ACL`:主 Account → 宾 DirectoryObject,标量 `granted_right/ace` |
| 4 | 4624 **认证包 + KeyLength + 冒充级别** | PtH 核心签名 | Authentication 事件加标量 `auth_package`、`key_length`、`impersonation_level` |
| 5 | **票据生命周期 / renew-till** | 金票(超长生命周期) | 4768/4769 事件加标量 `ticket_lifetime`、`renew_till`;或 `Ticket` 加 `lifetime/renew_till` |
| 6 | 4768/4769 ↔ 成员机 4624 的**硬键关联** | 银票(缺 TGT)判定 | 令 4768/4769 也引用同一 `LogonSession`(共享 `logon_guid`),使"缺 TGT"从时间启发式变硬连接 |
| 7 | **DC / 同步账号 / 扫描器 / 蜜罐 / 跳板**身份标记 | 各告警 null-hypothesis 白名单 | Host 加 `is_domain_controller`;Account 加 `is_sync_account`、`is_scanner`、`is_decoy`、`is_service`、`tier` |
| 8 | **来源工作站名解析**(NTLM type3 只给 WorkstationName) | 横向溯源到真实攻击机 | 事件加标量 `source_workstation`,建立 workstation-name→Host 弱键消解 |
| 9 | **复制范围**(拉了 krbtgt / 全部) | DCSync 影响面评估 | 4662 固有限制,标为固有盲区 |
| 10 | **离线爆破成功**(T1110)、SPN 服务类别细分 | Kerberoast 成败/优先级 | 爆破本身不可观测;SPN 服务类别可从 `REQUESTED` 的 `Service.kind`/名称补全 |

> 优先级:**#1(SAN)、#4(认证包/KeyLength)、#5(票据生命周期)、#7(身份标记)** 是四类告警从"suspicious 只能升级"变"图内可自动定性"的关键四补;#3、#6 让 DCSync 前置链与银票判定从"取不到/弱关联"变硬证据。

---

## 4. 应用层(Application / Web)

> **两条贯穿全篇的现实主义原则**
> **(1) CRS 签名命中 ≠ 攻击成功、甚至 ≠ 恶意。** CRS 3.x 是**异常评分(anomaly scoring)**模型:单条 942/941/930/932 规则**只加分、不拦截**,真正拦截决定发生在 949110 / 959xxx「blocking evaluation」——累计分 ≥ 阈值才动作(CRS Anomaly Scoring)。所以图里一条 `:Alert{rule_id:'942100'}` 只证明「**有人试了一下**」,既不代表被拦,也不代表打穿。CRS 高误报是业界共识。
> **(2) WAF 只看请求侧,判「是否得手」必须跨层看主机落地。** WAF 看不到响应体、看不到 SQL 是否真执行、文件是否真落盘。应用层告警的「影响判定」证据天生最薄,**必须 pivot 到被打 Web 主机上的 Sysmon 遥测**(EID11 落 webshell / EID1 w3wp 派生 shell)才能从「尝试」升级到「得手」。
>
> ⚠️ **接地说明(重要缺口)**:下文用 `(:Event)-[:TARGETED]->(:Uri)` 表示"HTTP 请求事件 → 被打 URL"。**这个谓语当前不在 v3 谓语登记表里**——WAF 告警的触发事件(HTTP 请求)如何 materialize 成 `:Event`、用什么谓语连 `Uri`,尚未在模型/ mapper 中定死(mapper 现对 WAF `transaction` 走告警路径)。这是应用层落地前必须先补的模型项(见 §6 缺口 G15)。以下 `TARGETED` 为占位,确切名以 mapper 定稿为准。

### SQL 注入 (T1190 / OWASP A03,应用层)

**攻击本质**:把 SQL 语法注入应用参数,欺骗后端把数据当代码执行,实现拖库 / 绕过认证 / 写文件落地。

**触发逻辑(我们栈)**:CRS **942xxx** 族。942100 用 libinjection 的 `@detectSQLi` 检测;942190/942210/942260 等为正则补充。命中位置含 `ARGS`、`REQUEST_COOKIES`、`REQUEST_HEADERS:User-Agent/Referer`、XML 体。

**研判决策树**:
1. **Q:这是一条请求还是一片扫描?** → 证据:同源 IP 近 1h 触发的告警总数、去重规则数、去重请求数。单发精准 payload 与 sqlmap 批量扫画像完全不同。 → 图:
   ```cypher
   MATCH (ip:IPAddress {ip:$ip})<-[:FROM]-(e:Event)-[:TRIGGERED]->(a:Alert)
   WHERE a.time > datetime() - duration('PT1H')
   RETURN count(DISTINCT a)         AS alerts,
          count(DISTINCT a.rule_id) AS distinct_rules,
          count(DISTINCT e)         AS requests
   ```
2. **Q:同一条请求命中了几条规则(异常评分广度)?** → 证据:一条真 SQLi payload 常同时点亮 942100 + 942190 + 942260;单条 942100 孤零零命中更像误报。 → 图:
   ```cypher
   MATCH (e:Event {event_uid:$euid})-[:TRIGGERED]->(a:Alert)
   RETURN collect(a.rule_id) AS rules_hit, count(a) AS rule_count
   ```
3. **Q:打的是哪个 URL / 哪个 Web 站点?是登录/搜索这类高价值入口吗?** → 证据:Uri.path + 归属 `Service{kind:'web'}` 与宿主 Host 的 criticality/zone。 → 图:
   ```cypher
   MATCH (a:Alert {rule_id:'942100', alert_uid:$auid})<-[:TRIGGERED]-(e:Event)
   OPTIONAL MATCH (e)-[:FROM]->(ip:IPAddress)
   OPTIONAL MATCH (e)-[:TARGETED]->(u:Uri)
   OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host)
   OPTIONAL MATCH (svc:Service {kind:'web'})-[:BELONGS_TO]->(h)
   RETURN ip.ip, ip.reputation, u.path, h.hostname, h.criticality, h.zone, svc.name
   ```
4. **Q:源 IP 有前科吗?** → 证据:经验层历史裁决/处置(见下)。

**误报/良性场景(null hypothesis,逐条列全)**:
- **正文含 SQL 关键字的正常业务**:搜索框搜 `select ... from`、含 `union` 的公司/组织名(真实案例 "Manufacturing Workers' Union" 打中 942100)。区分:参数是否自然语言/业务实体名,而非 `' OR 1=1--` 式语法结构。
- **感叹号+括号缩写**:如 "Yahoo! (Y!)" 触发 libinjection。区分:payload 无引号闭合/无注释符/无堆叠查询。
- **非 ASCII 编码误判**:中文/西里尔字符被 libinjection 解析成伪英文 token。区分:字段本身是中文富文本 / i18n 字段。
- **JSON body / 富文本编辑器**:正常提交含 `--`、`;`、`/*`。区分:结合命中字段是否为已知白名单业务字段。
- **WAF 只看请求,无法知道 SQL 是否真执行**:即便真 payload,若后端用参数化查询,攻击也失败——图里补不了,靠跨层与响应侧(见盲区)。

**判定逻辑(证据组合 → verdict)**:
- **FP(关掉)**:单条 942100、命中字段是自然语言/业务字段、同源 IP 无扫描画像、`ip.reputation` 干净、历史多为 FP → 建议做**该字段该端点的定向排除**(scoped exclusion),不是关整条规则。
- **可疑 TP(尝试)**:payload 有真实注入语法(引号闭合 + 布尔/联合/注释)、单请求命中≥2 条 942、但无跨层落地 → 记「探测/尝试」,中优先。
- **确认 TP + 影响(得手)**:上 + **跨层**发现该 Web Host 紧接着有 Sysmon11 WROTE 脚本 / Sysmon1 w3wp 派生进程 / Sysmon3 Web 进程外连(`SELECT ... INTO OUTFILE`、`xp_cmdshell` 落地)→ 高优先,按入侵处置。
- **阈值参考**:同源 IP 1h 内 distinct_rules ≥ 5 或 requests ≥ 20 → 判「自动化扫描」;单发 + 跨层落地 → 判「定向且得手」。

**跨层关联(应用→主机)**:因当前图未把 MSSQL Service 与 Web 请求做参数级绑定,主要靠「同 Host + 时间窗」关联:
```cypher
MATCH (a:Alert {alert_uid:$auid})<-[:TRIGGERED]-(e:Event)-[:ON_HOST]->(h:Host)
MATCH (h)<-[:ON_HOST]-(pc:Event)-[:BY]->(parent:Process)
MATCH (parent)-[:SPAWNED]->(child:Process)
WHERE child.image =~ '(?i).*(cmd|powershell)\\.exe'
  AND pc.event_time >= e.event_time AND pc.event_time <= e.event_time + duration('PT10M')
RETURN parent.image, child.image, child.command_line
```

**经验层复用**:
```cypher
MATCH (ip:IPAddress {ip:$ip})
OPTIONAL MATCH (ip)<-[:ON]-(d:Disposition)<-[:LED_TO]-(v:Verdict)<-[:CONCLUDED]-(pa:Alert)
RETURN v.verdict AS prior_verdict, d.action AS prior_disposition,
       count(pa) AS prior_alerts, ip.reputation
```
历史封过/多次判 TP → 直接升级;历史稳定 FP(同字段同规则)→ 强 FP 先验,转排除建议。

**⚠️图盲区**:
- **HTTP 响应码 / 响应体大小**:判「拖库成功 vs 被拦 vs 报错」头号证据,`Alert` 无此字段;`Event.outcome` 可能带 WAF 动作但≠ HTTP 状态码。
- **完整请求参数与 payload 原文**:只在标量叶 / `raw_ref`,未实体化,无法按 payload 特征结构化查询(区分真语法 vs 自然语言全靠它)。
- **命中的具体字段 & 匹配子串**(ARGS 名 / MATCHED_VAR):判 FP 关键,图不可查。
- **累计异常评分数值 & 是否达拦截阈值**:规则广度可由多 Alert 数出,但 CRS 总分与「blocked/passed」最终动作是否 materialize 存疑。
- **源 IP 情报信誉是否真有值**:`IPAddress.reputation` 有槽位,实际常为空。

### XSS (OWASP A03,应用层)

**攻击本质**:把脚本注入页面,令受害者浏览器执行,窃 cookie/会话、钓鱼、打后台。**危害发生在受害者浏览器端,服务器侧几乎无落地信号**——这是 XSS 研判最难之处。

**触发逻辑(我们栈)**:CRS **941xxx** 族。941100(libinjection XSS)、941110(`<script`)、941160、941320(HTML 标签模式)等。

**研判决策树**:
1. **Q:payload 是「反射点」还是「存储点」?** → 证据:命中的 Uri.path / method。打到评论、资料、富文本保存接口(存储型)危害远高于一次性反射。 → 图:`MATCH (a:Alert {rule_id:'941100'})<-[:TRIGGERED]-(e:Event)-[:TARGETED]->(u:Uri) RETURN u.host, u.path`(method 见盲区)。
2. **Q:单发还是批量 fuzz?** → 证据:同源 IP 941 族告警数与规则广度(同 SQLi Q1,`rule_id` 换 941*)。XSS 扫描器(XSStrike)会连打几十种变体。
3. **Q:命中字段像真 XSS 还是像正常 HTML?** → 证据:请求原文(⚠️多在盲区)。真 payload 有事件处理器/协议头(`onerror=`、`javascript:`、`<svg/onload>`);正常 HTML 只有排版标签。
4. **Q:目标站点/主机价值?** → 同 SQLi Q3 的 `Service{kind:'web'}`→Host 查询。

**误报/良性场景(逐条列全)**:
- **CMS/富文本正文含 HTML 标签**:941320 因 WordPress 文章正文里的 `<h1>` 命中。区分:命中字段是否为允许富文本的内容字段。
- **所见即所得编辑器 / Markdown 渲染提交**:正常带 `<b>`、`<a href>`。
- **URL 参数里带 HTML 片段的正常业务**(预览、模板名)。
- **前端框架模板串**(`{{}}`、`<component>`)被泛化 XSS 正则命中。
- **本质局限**:WAF 看不到输出点是否转义——就算存了 `<script>`,若前端输出编码,XSS 不成立;反之 WAF 漏掉的编码绕过也可能成功。TP/FP 地面真相在浏览器端,图里没有。

**判定逻辑(证据组合 → verdict)**:
- **FP**:单条 941 命中富文本/正文字段、同源无扫描、payload 只是排版标签 → 定向排除该字段。
- **可疑 TP(尝试)**:payload 含事件处理器/协议头、打到反射参数、单发 → 记探测。
- **较高危 TP**:payload 打到**存储型**接口(评论/资料保存)且返回 2xx(响应码⚠️盲区)→ 需人工验证输出点是否转义;存储型一旦成立影响所有访问者。
- XSS 几乎无主机落地,**判定权重靠:是否存储型 + 是否批量 + payload 真实性 + 源 IP 信誉**,跨层几乎帮不上。

**跨层关联(应用→主机)**:**基本无直接主机落地**(脚本在受害者浏览器执行)。唯一价值:若 XSS 目标是内部管理后台,可关注被钓的**管理员账号**随后在别处的异常登录/进程行为——但这已跨到身份/主机层,与本告警只能靠「同 Host + 账号」弱关联。诚实结论:XSS 是本清单里跨层补强最弱的一类。

**经验层复用**:同 SQLi,查源 IP 历史 Verdict/Disposition;XSS 扫描源常反复触发,历史标签对快速定性帮助大。

**⚠️图盲区**:请求 method(GET/POST,区分反射 vs 存储的关键)、完整 payload(判是否含事件处理器/协议头)、HTTP 响应码 & 响应体(判是否原样回显)、输出点是否转义(XSS 是否真成立的地面真相,天生不在服务器遥测里)、命中字段名(判富文本白名单 FP)——均盲区。

### 路径遍历 / LFI / RFI (OWASP A03,应用层)

**攻击本质**:**路径遍历/LFI**——用 `../` 或绝对路径读取应用不该给的本地文件(`/etc/passwd`、`web.config`、源码、密钥);**RFI**——让应用去 include 一个远程 URL 上的恶意脚本,直接 RCE。

**触发逻辑(我们栈)**:**930xxx**(LFI/路径遍历,930100 检 `../`、930120 检敏感 OS 文件名)+ **931xxx**(RFI,931130 检参数里的外部 URL)。

**研判决策树**:
1. **Q:是 LFI(读文件)还是 RFI(拉远程)?危害等级不同。** → 证据:命中规则族(930 vs 931)+ Uri/参数。RFI ≈ 直接 RCE,优先级最高。 → 图:
   ```cypher
   MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)-[:FROM]->(ip:IPAddress)
   WHERE a.rule_id STARTS WITH '930' OR a.rule_id STARTS WITH '931'
   OPTIONAL MATCH (e)-[:TARGETED]->(u:Uri)
   OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host)
   RETURN a.rule_id, ip.ip, u.path, h.hostname
   ```
2. **Q:遍历深度 / 目标文件像不像真攻击?** → 证据:payload(⚠️盲区)里 `../` 层数、是否点名 `/etc/passwd`、`win.ini`、`web.config`。深层遍历 + 敏感文件名 = 强 TP 信号。
3. **Q:单发精准还是字典爆破?** → 证据:同源 IP 930/931 告警数(LFI 扫描器会遍历大量路径字典)。
4. **Q:RFI 指向的远程主机是谁?** → 证据:payload 里的外部 URL 域名/IP。⚠️ 当前 URL 在 payload 文本里未实体化,无法直接 pivot 到 `Domain`/`IPAddress`。

**误报/良性场景(逐条列全)**:
- **图片/文件上传**:正常上传流量打中 930 LFI 族。区分:命中端点是否为上传接口、内容是否 multipart 文件体。
- **OIDC / OAuth 回调**:`redirect_uri` 参数带完整外部 URL,打中 931130。区分:参数名是否 `redirect_uri`/`return_url`、目标域是否自家可信域。
- **正常带路径的业务参数**:文件下载、静态资源 `?file=reports/2026/q2.pdf`。
- **CDN / 富前端**:请求路径含 `..`、`%2e%2e` 的正常资源引用。
- **本质局限**:WAF 看不到应用是否真返回了文件内容——遍历「尝试」与「读到了」是两回事。

**判定逻辑(证据组合 → verdict)**:
- **FP**:930 命中上传端点、或 931 命中 `redirect_uri` 且目标是可信域、单发 → 定向排除该参数。
- **可疑 TP(尝试)**:深层 `../` + 敏感文件名、非上传端点、单发 → 探测,中高优先。
- **确认 TP + 影响**:LFI 读成功(响应码 200 且响应体非空,⚠️响应侧盲区)/ RFI 转 RCE 得手——**跨层**:Web Host 上 Web 进程派生 shell、或 Sysmon3 该 Web 进程外连到 payload 里的远程主机(RFI 拉马)、或 Sysmon11 落脚本。**这是把「尝试」升级为「得手」的决定性证据**。
- **阈值参考**:字典爆破(1h 内 930/931 告警 ≥ 20)→ 判扫描;单发深遍历 + 跨层落地 → 判定向得手。

**跨层关联(应用→主机)**:RFI 是本清单里跨层最直接的一类——远程 include 成功 = 服务器主动外连拉恶意脚本 + 执行:
```cypher
MATCH (a:Alert {alert_uid:$auid})<-[:TRIGGERED]-(e:Event)-[:ON_HOST]->(h:Host)
MATCH (h)<-[:ON_HOST]-(nc:Event)-[:BY]->(p:Process)
MATCH (nc)-[:CONNECTED_TO]->(dst:IPAddress)
WHERE p.image =~ '(?i).*(w3wp|php-cgi|httpd|nginx)\\.exe?'
  AND nc.event_time >= e.event_time AND nc.event_time <= e.event_time + duration('PT5M')
RETURN p.image, dst.ip, dst.reputation, nc.event_time
```

**经验层复用**:同 SQLi;LFI/RFI 扫描源信誉与前科对定性帮助大。

**⚠️图盲区**:完整 payload / 参数值(遍历深度、目标文件名、RFI 远程 URL——判 TP 核心证据全在 `raw_ref`)、RFI 目标域/IP 未实体化、HTTP 响应码 / 响应体大小、请求 method、命中字段名——均盲区。

### 命令注入 / RCE (OWASP A03,应用层)

**攻击本质**:把 OS 命令拼进应用参数,让服务器执行任意系统命令——**一旦得手即完整主机沦陷**,危害上限最高。

**触发逻辑(我们栈)**:CRS **932xxx** 族,按 OS 分。检测「shell 元字符起始序列 + 系统命令名清单」两要素。932100(Unix 命令注入)、932110(Windows 命令注入)等。

**研判决策树**:
1. **Q:payload 里是真的命令拼接,还是恰好撞到命令名单词?** → 证据:请求原文(⚠️盲区)——真注入有分隔符/管道/反引号(`;`、`|`、`&&`、`$(...)`、`` ` ``)+ 命令名;误报常是**孤立的命令名单词**。
2. **Q:单发还是探测多变体?** → 证据:同源 IP 932 族告警数与规则广度。
3. **Q:打的 Web Host 是什么角色/权限面?** → 证据:`Service{kind:'web'}`→Host 的 role/criticality/zone。
4. **Q:命令若执行,进程该是谁?** → 直接进跨层:查该 Host 上 Web 进程有无派生子进程。**RCE 类告警必须无条件跑跨层**——这是唯一能证明得手的证据。

**误报/良性场景(逐条列全)**:
- **参数值恰含命令名单词**:Windows 平台 POST 参数含 `del` 命中 932110;`cat`、`net`、`type`、`mail`、`find` 在正常英文/业务里极常见。932100 本身就以高误报著称。区分:命令名周边是否有 shell 分隔符/管道。
- **正常业务里的 shell 风格字符串**:路径、命令行帮助文本、代码片段提交(IDE/工单系统贴命令)。
- **User-Agent / Referer 里的杂串**被泛化命中。
- **本质局限**:WAF 命中只证明请求里「长得像命令」,命令是否真被 `system()`/`exec()` 执行,请求侧完全看不到。

**判定逻辑(证据组合 → verdict)**:
- **FP**:孤立命令名单词、命中字段是自由文本/代码字段、无 shell 语法、单发、源 IP 干净 → 定向排除。
- **可疑 TP(尝试)**:真 shell 语法拼接、但跨层无任何子进程落地 → 探测/尝试,高优先。
- **确认 TP + 完全沦陷(得手)**:**跨层**发现 Web Host 上 Web 进程(w3wp/php-cgi)在告警后短时间内 **SPAWNED cmd/powershell/whoami/net/nltest** 子进程——RCE 已执行,最高优先,立即处置。w3wp 派生 shell 是业界公认的高保真 RCE/webshell 信号(Splunk)。

**跨层关联(应用→主机)——本告警的核心**:
```cypher
MATCH (a:Alert {rule_id:'932110', alert_uid:$auid})<-[:TRIGGERED]-(e:Event)-[:ON_HOST]->(h:Host)
MATCH (h)<-[:ON_HOST]-(pc:Event)-[:BY]->(parent:Process)
MATCH (parent)-[:SPAWNED]->(child:Process)
OPTIONAL MATCH (pc)-[:RAN_AS]->(acct:Account)
WHERE parent.image =~ '(?i).*(w3wp|php-cgi|httpd|nginx|tomcat|java)\\.exe?'
  AND child.image  =~ '(?i).*(cmd|powershell|pwsh|whoami|net1?|nltest|systeminfo|cscript|wscript|bash|sh)\\.exe?'
  AND pc.event_time >= e.event_time AND pc.event_time <= e.event_time + duration('PT10M')
RETURN parent.image, child.image, child.command_line, acct.sam
```
命中即「尝试→得手」跃迁,`child.command_line` 还能看侦察意图(`whoami /priv`、`net user`)。再顺 Sysmon3 看该子进程/父进程有无 C2 外连。

**经验层复用**:同 SQLi;命令注入源 IP 若历史封过/多判 TP,直接高优先,无需等跨层坐实即可预处置。

**⚠️图盲区**:完整 payload(区分「真命令拼接 vs 撞词」的唯一证据)、命中字段名 & 匹配子串、HTTP 响应码 / 响应体(命令回显)、请求 method、源 IP 情报信誉——均盲区。

### Webshell 上传与落地 (T1505.003,应用层→主机层)

**攻击本质**:把可执行脚本(`.aspx/.ashx/.php/.jsp`)写进 Web 可访问目录,获得**持久化远程命令通道**。**这是应用层证据最薄、最必须靠跨层坐实的旗舰案例**:WAF 只看到「一个上传请求」,是否真落盘成 webshell、能否被回连执行,全在主机侧。

**触发逻辑(我们栈)**:WAF 侧信号**弱且不稳**——上传请求可能命中 932/933、或 multipart 规则,但**很多 webshell 上传对 CRS 是「干净」的**(就是一个正常 multipart 表单)。**真正高保真的信号在主机侧**:Sysmon **EID11 FileCreate** —— Web 工作进程(w3wp/php-cgi)在 wwwroot/inetpub 下写出一个脚本扩展名文件(微软 IIS webshell 检测 / Splunk)。

**研判决策树**:
1. **Q:Web 主机上,Web 进程有没有写出脚本文件到 web 目录?**(核心问句,主机侧起手)→ 证据:Sysmon11 `WROTE`,主 Process=w3wp、宾 File.path 落在 web 根 + 脚本扩展名。 → 图:
   ```cypher
   MATCH (p:Process)-[:WROTE]->(f:File)
   WHERE p.image =~ '(?i).*(w3wp|php-cgi)\\.exe?'
     AND f.path  =~ '(?i).*(wwwroot|inetpub|htdocs|webapps).*\\.(aspx?|asmx|ashx|asax|php\\d?|jspx?)$'
   RETURN p.process_guid, p.image, f.path, f.sha256
   ```
2. **Q:这个落盘能不能对上一条 Web 上传告警/请求?(跨层拼链)** → 证据:同 Host(asset_id 强键)+ 时间窗。 → 图:
   ```cypher
   MATCH (a:Alert {alert_uid:$auid})<-[:TRIGGERED]-(e:Event)-[:ON_HOST]->(h:Host)
   MATCH (h)<-[:ON_HOST]-(fc:Event)-[:WROTE]->(f:File)
   MATCH (fc)-[:BY]->(p:Process)
   WHERE p.image =~ '(?i).*(w3wp|php-cgi)\\.exe?'
     AND f.path =~ '(?i).*(wwwroot|inetpub).*\\.(aspx?|ashx|php\\d?|jspx?)$'
     AND fc.event_time >= e.event_time AND fc.event_time <= e.event_time + duration('PT10M')
   RETURN e.event_uid, f.path, f.sha256, fc.event_time
   ```
3. **Q:这个 webshell 有没有被执行(回连/命令)?** → 证据:Sysmon1 —— 该 w3wp 随后 `SPAWNED` cmd/powershell(webshell 被调用的铁证);Sysmon3 该进程外连 C2。 → 见下「跨层」。
4. **Q:文件是不是已知恶意?** → 证据:`File.sha256` 对经验层/情报(sha256 是强键,可与历史裁决/黑名单比对)。

**误报/良性场景(逐条列全)**:
- **合法部署/发布**:CI/CD、管理员或部署账号(非 w3wp)写 `.aspx`/`.php` 到站点目录——**区分靠「谁写的」**:正常发布是部署进程/msdeploy,不是 w3wp 应用池身份;w3wp 自己写脚本文件本就极罕见。
- **应用自身生成脚本/缓存**:部分 CMS(编译缓存、模板生成 `.php`)会由 Web 进程写文件。区分:路径是否已知缓存目录、文件名是否框架规律命名、是否随后被 include 执行且无外连。
- **临时上传目录**:正常上传落到非可执行目录(图片/附件区)不是 webshell。区分:落盘路径是否可被 URL 直接访问 + 是否脚本扩展名。
- **WAF 侧上传告警本身**:正常带脚本样例/代码的 multipart 提交命中 932/933 —— 只看 WAF 会误判,必须等主机侧落盘确认。

**判定逻辑(证据组合 → verdict)**:
- **FP**:脚本文件由**部署/管理账号或部署进程**写入、落已知缓存目录、无 w3wp 派生 shell、无外连 → 良性发布/缓存。
- **可疑**:w3wp 写出脚本到 web 目录,但暂无执行迹象 → 高优先,file.sha256 送分析、隔离文件。
- **确认 TP(落地 webshell)**:w3wp `WROTE` 脚本到 web 根 + 能对上一条上传请求(时间窗)→ webshell 已落地。
- **确认 TP + 活跃利用(最高危)**:上 + w3wp 随后 `SPAWNED` cmd/powershell 或该进程外连 C2 → webshell 正在被使用,立即处置(隔离主机、封源 IP、删文件、取证)。
- **判定核心**:webshell 是本清单里**跨层证据链最完整**的——`WROTE`(落盘)+ `SPAWNED`(执行)+ `CONNECTED_TO`(回连)三段齐全时置信度可到确定级,无需依赖薄弱的 WAF 请求侧。

**跨层关联(应用→主机)——三段式完整链**:
```cypher
MATCH (a:Alert {alert_uid:$auid})<-[:TRIGGERED]-(e:Event)-[:ON_HOST]->(h:Host)
MATCH (h)<-[:ON_HOST]-(:Event)-[:BY]->(w:Process)          // w3wp
WHERE w.image =~ '(?i).*w3wp\\.exe$'
OPTIONAL MATCH (w)-[:WROTE]->(f:File)
  WHERE f.path =~ '(?i).*(wwwroot|inetpub).*\\.(aspx?|ashx|php\\d?|jspx?)$'
OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process)
  WHERE c.image =~ '(?i).*(cmd|powershell|pwsh|whoami|net1?)\\.exe$'
OPTIONAL MATCH (w)-[:CONNECTED_TO]->(dst:IPAddress)
RETURN f.path AS dropped_shell, c.command_line AS exec_cmd, dst.ip AS c2, dst.reputation
```

**经验层复用**:`File.sha256` 与源 `IPAddress` 双维度查前科——同 sha256 的 webshell 之前判过 TP / 同源 IP 封过 → 秒级定性。
```cypher
MATCH (ip:IPAddress {ip:$ip})<-[:ON]-(d:Disposition)<-[:LED_TO]-(v:Verdict)
RETURN v.verdict, d.action    // 该源 IP 历史是否已被判定/封禁
```

**⚠️图盲区**:
- **上传请求的文件名 / multipart 内容 / 目标落盘路径**:WAF 告警侧无法给出,只能靠主机侧 EID11 反推——应用↔主机的**精确绑定**(哪条 HTTP 请求导致哪个文件落盘)目前只能靠「同 Host + 时间窗」弱关联,无请求级强关联键。
- **HTTP 响应码**:上传是否 200 成功,缺。
- **File 与触发它的 HTTP 请求之间无直接边**:跨层是「同 Host + 时间近邻」推断,非因果强键(存在同窗多请求归因歧义)。
- **Web 目录清单/可执行性判断**:落盘路径是否真 URL 可达 + 可执行,图无站点物理路径映射。

### 应用层·模型缺口汇总

> 应用层证据天生最薄(WAF 只看请求侧),下列缺口直接决定「签名命中能否升级为可判定的 TP/影响」。

| # | ⚠️ 缺失证据 | 影响的研判 | 建议补法(落到 v3 结构) |
|---|---|---|---|
| 1 | **HTTP 响应码 / 响应体大小** | 判「攻击是否得手 vs 被拦 vs 报错」——所有 5 类头号影响证据 | 把响应码/响应体长度提为**触发事件(HTTP 请求 Event)标量**(`e.status_code`、`e.resp_bytes`),明确 `Event.outcome` 语义。投入产出比最高。 |
| 2 | **完整请求 payload / 参数值 / 命中子串(MATCHED_VAR)** | 区分「真 payload vs 正常业务撞签名」——CRS 去噪根本 | 请求方法、URI 全量、关键参数、matched_var 提为可结构化查询字段,而非只存 `raw_ref`。 |
| 3 | **请求 method(GET/POST/PUT)** | XSS 反射 vs 存储、上传判定、命令注入位置 | 提为触发事件属性 `e.http_method`。 |
| 4 | **命中的字段名 / 位置(ARGS 名 / header / cookie)** | 判富文本/上传/`redirect_uri` 定向 FP,指导 scoped exclusion | 提为 Alert 属性 `matched_var`。 |
| 5 | **累计异常评分数值 & 最终动作(blocked/passed)** | 单规则命中≠拦截;判「是否真被挡下」 | 把 949110/959xxx 结果 materialize 为该请求事件的汇总 Alert 或事件属性(总分 + 动作)。 |
| 6 | **源 IP 威胁情报信誉真实值** | 所有 5 类源信誉加权;扫描器/已知恶意源快速定性 | `IPAddress.reputation/geo/asn` 槽位已存在但常空——**对接情报源填充**(GreyNoise/AbuseIPDB/自建)。 |
| 7 | **UA / Referer 原文** | 扫描器指纹(sqlmap/XSStrike/nikto UA)、命中位置判定 | 提为触发事件属性 `e.user_agent`、`e.referer`。 |
| 8 | **RFI 远程 URL / webshell 上传目标路径未实体化** | RFI 目标主机信誉、上传落盘归因 | RFI payload 里外部 URL 抽为 `Domain`/`IPAddress` 实体连边;上传请求与落盘 File 建请求级关联键。 |
| 9 | **应用↔主机的请求级强绑定** | Webshell/RCE「哪条请求导致哪个落地」因果归因(现仅时间窗弱推断) | Web 层与 Sysmon 层共享关联键(如注入进程环境/日志的 request_id),在两个 `:Event` 间建直接边。 |

**一句话总结给 Agent**:应用层务必默认「签名命中 = 有人试了」,**FP 优先假设**(先按 #2/#4/#6 去噪),再用**跨层三件套**——EID11 `WROTE`(落盘)/ EID1 `SPAWNED`(w3wp→shell)/ EID3 `CONNECTED_TO`(C2 回连)——把「尝试」升级为「得手」;凡是判「影响/得手」而**证据只停在 WAF 请求侧**的,一律标为**证据不足**而非 TP。

---

## 5. 网络层(Network)

> **现实约束(贯穿全篇)**:本靶场 **host-only,无独立 NDR/Zeek/NetFlow 探针**。网络层可见性 = 主机侧 Sysmon 的网络维度 —— **EID3 NetworkConnect**(进程发起的外连,带目标 IP + `dest_port`)与 **EID22 DnsQuery**(进程发起的 DNS 查询,带被查域名)。我们**没有包级/流级四元组、没有字节数/时长/方向、没有 TLS/JA3、没有 DNS 记录类型与响应**。所以"网络层告警"本质是**规则判的主机遥测网络切片**。信标判定靠**聚合边 `count`/`first_seen`/`last_seen` 定粗信号 + 事件节点按 `event_time` 排序算节律**。**IP 是弱键**(SNAT/NAT/云 IP 复用),`reputation` 字段在图里存在但**当前很可能是空的**——凡依赖它的判据都要能降级。

### C2 信标 / DNS beacon (T1071 / T1071.004 / T1568,网络层)

**攻击本质**:植入体按固定节律(可带 jitter)周期性回连 C2,取指令/回传心跳。载体可以是 HTTP(S) 外连(EID3 维度)或 DNS 查询(EID22 维度,把域名当信道),常配可疑/低信誉/DGA/动态解析域名(FIRST DNS Beacons 指南)。

**触发逻辑(我们栈)**:不是 DPI,而是从 Sysmon 聚合/时序里找**规整周期性**——同一 `Process→IPAddress`(EID3)或 `Process→Domain`(EID22)的 `count` 异常高、`first_seen↔last_seen` 跨度长、事件间隔低方差。规则一般对聚合边设 `count` 与时间跨度阈值触发候选,研判阶段再回事件节点算节律。sleep mask / 长周期 beacon 会稀释单位时间频次,需长观察窗(Netskope:典型 jitter 60±20%)。

**研判决策树**(先证伪"是不是正常轮询",再逐层坐实):

1. **Q:告警落在哪个"进程→目标"对上?先取粗信号(count + 时间跨度)。** → 证据:聚合边 `count` 高 + `first_seen↔last_seen` 跨度长(跨多小时/多天且 count 上千 → 强嫌疑)。 → 图:
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e0:Event)-[:BY]->(p:Process)
   OPTIONAL MATCH (e0)-[:CONNECTED_TO]->(ip:IPAddress)   // HTTP beacon 维度
   OPTIONAL MATCH (e0)-[:QUERIED]->(d:Domain)             // DNS beacon 维度
   WITH p, ip, d
   OPTIONAL MATCH (p)-[c:CONNECTED_TO]->(ip)
   OPTIONAL MATCH (p)-[q:QUERIED]->(d)
   RETURN p.image, p.command_line,
          ip.ip, c.count  AS ip_count,  c.first_seen, c.last_seen,
          d.fqdn, q.count AS dom_count, q.first_seen, q.last_seen
   ```

2. **Q:节律真的规整吗(周期性 vs 随机突发)?——TP/FP 的分水岭。** → 证据:相邻事件间隔的**中位数 + 变异系数**。低方差/强单一周期 = 机器节律;重尾/随机 = 人操作或事件驱动。带 jitter 的 beacon 需看"去抖后仍存在的主频"。 → 图(聚合边只给 count 和首末,**精确节律必须回事件节点按 time 排**):
   ```cypher
   MATCH (e:Event)-[:BY]->(p:Process {process_guid:$pg})
   MATCH (e)-[:CONNECTED_TO]->(:IPAddress {ip:$ip})   // 或 (e)-[:QUERIED]->(:Domain {fqdn:$fqdn})
   RETURN e.event_time ORDER BY e.event_time           // deltas/CV/自相关在图外算
   ```

3. **Q:目标域名/IP 信誉如何?是新出现/DGA/动态解析吗?** → 证据:`reputation`(若非空)、`Domain.first_seen`(首次出现很晚=新域名,强信号)、DGA 形态(高熵/随机串——图只存 `fqdn`,熵在图外算)、`RESOLVES_TO` 扇出大(一个域名短时解析到大量 IP = fast-flux)。 → 图:
   ```cypher
   MATCH (d:Domain {fqdn:$fqdn})
   OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)
   RETURN d.fqdn, d.reputation, d.first_seen,
          count(DISTINCT ip) AS resolve_fanout,
          collect(DISTINCT {ip:ip.ip, rep:ip.reputation, asn:ip.asn, geo:ip.geo})
   ```

4. **Q:发起进程正常吗?是浏览器/更新程序,还是可疑进程/可疑父进程?** → 证据:`Process.image`(`rundll32`/`powershell`/`regsvr32`/无名进程直接外连 = 高危;`chrome/edge` 外连 = 高度良性)、`SPAWNED` 父链(Office→powershell→外连 = 典型攻击链)、`RAN_AS` 账号。 → 图:
   ```cypher
   MATCH (p:Process {process_guid:$pg})
   OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
   OPTIONAL MATCH (p)-[:RAN_AS]->(acct:Account)
   RETURN p.image, p.command_line, parent.image AS parent_image, parent.command_line AS parent_cmd, acct.sam
   ```

**误报/良性场景(null hypothesis,先逐条排除再谈 TP)**:真实企业里"周期性外连/查询"绝大多数是良性——
- **软件更新/补丁轮询**(Windows Update、Chrome/Edge updater、winget、厂商 agent)——极规整,周期分钟~小时级。区分:进程是已知更新程序、目标是厂商官方域/CDN、`reputation` 好或至少非新域。
- **EDR/监控/管理 agent 心跳**(Wazuh/Sysmon 转发、Defender 云、Zabbix/SCCM)——本就是"信标"。区分:进程=已知 agent、目标=自家 SIEM/管理域、`IPAddress.type`=内部。
- **CDN / 反代 / DNS 负载均衡**——一个域名解析到大量 IP(易被当 fast-flux)。区分:域名是知名 CDN(Akamai/Cloudflare/Fastly)、`ASN`/`geo` 属 CDN、进程是浏览器。
- **遥测/许可校验/云 API 周期调用**(Office 遥测、许可 ping、OneDrive/Dropbox 同步)——规整。区分:进程与目标域匹配已知供应商。
- **NTP / 内部 DNS 递归**——固定节律。区分:`dest_port` 123 且目标是时间源;DNS 递归到内部解析器。
- **DNS 负载/健康探测的高 QPS 单域名**——易触发 DNS beacon 的 count 阈值。区分:查的是自家服务域、发起进程是业务进程。
> 判据:以上"良性信标"共同特征是**进程已知 + 目标域信誉好/非新 + 目标是供应商/CDN/内部**。任一项站住就应先假定 FP,要求周期性之外的坐实证据。

**判定逻辑(证据组合 → verdict)**:核心是**三者叠加才判 TP,单独任一项都高误报**——
- **① 周期性**:聚合边 `count` 高(HTTP 维度经验阈:单进程→单外部 IP `count ≥ 数百` 且 `last_seen−first_seen ≥ 数小时`;DNS 维度:单进程→单域 `count` 异常高)**且** 事件间隔变异系数低。
- **② 目标可疑**:`reputation` 差 **或** `Domain.first_seen` 很新 **或** DGA 形态 **或** `RESOLVES_TO` 扇出异常。
- **③ 发起进程异常**:非浏览器/非更新程序 **或** 可疑父链(Office/脚本宿主派生)**或** 无签名。
- **裁决**:①+②+③ → **TP(C2 信标)**;仅① + 进程是已知更新/agent + 目标信誉好 → **FP(正常轮询/心跳)**;①+③ 但 ② 缺(reputation 空且域名不新、非 DGA)→ **可疑待定**,升级为主动情报查询/沙箱,不直接封。**周期性单独出现绝不判 TP。**

**经验层复用**:沿 `(:Alert)-[:CONCLUDED]->(:Verdict)-[:LED_TO]->(:Disposition)-[:ON]->(目标 IP/Domain)` 查该目标历史——历史 TP/已封 → 本次高置信复用;历史多次 FP(某更新 CDN)→ 强降噪、可自动收敛。
```cypher
MATCH (v:Verdict)-[:LED_TO]->(disp:Disposition)-[:ON]->(t)
WHERE (t:IPAddress AND t.ip=$ip) OR (t:Domain AND t.fqdn=$fqdn)
MATCH (al:Alert)-[:CONCLUDED]->(v)
RETURN al.time, v.verdict, disp.action ORDER BY al.time DESC
```

**⚠️图盲区**:节律精度/jitter 显著性(节律*可*算但需事件不被下采样;jitter 统计显著性、多重交织周期、去抖主频要图外算)、包级 inter-arrival/字节量/会话时长/上下行比(无流级数据)、DNS 深度特征(记录类型 TXT/NULL/CNAME、响应内容、子域熵/长度、NXDOMAIN 率、TTL——DNS 隧道/DGA 核心判据)、TLS/JA3/SNI/证书、`reputation` 大概率空。

### 可疑外连 / 罕见进程 C2 通道 (T1571 非标准端口 / T1090 代理,网络层)

**攻击本质**:C2 走**非常用端口**(绕基于端口的策略)或经**代理/中继**跳板外连;或由**本不该联网的进程**(LOLBin:`rundll32`/`regsvr32`/`mshta`/`powershell`)直接对外发起连接。

**触发逻辑(我们栈)**:EID3 上匹配 (a) `dest_port` 落在非常用集合(非 80/443/53,尤其高位随机端口、4444/8080/1080);(b) 发起进程 `image` ∈ LOLBin 且目标 `IPAddress.type`=外部;(c) 短链路多跳(进程→内部代理→外部)结合两段 EID3。

**研判决策树**:
1. **Q:目标是外部还是内部?端口是不是非常用?** → 图:
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process)
   MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress)
   RETURN p.image, p.command_line, ip.ip, ip.type, ip.asn, ip.geo, e.dest_port
   ```
2. **Q:发起进程是不是"不该联网"的进程?父链可疑吗?** → 图:
   ```cypher
   MATCH (parent:Process)-[:SPAWNED]->(p:Process {process_guid:$pg})
   OPTIONAL MATCH (p)-[:RAN_AS]->(acct:Account)
   RETURN parent.image, parent.command_line, p.image, p.command_line, acct.sam
   ```
3. **Q:这个"进程→该外部 IP:端口"是一次性还是反复?**(与信标交叉)→ 图:`MATCH (p:Process {process_guid:$pg})-[c:CONNECTED_TO]->(ip:IPAddress {ip:$ip}) RETURN c.count, c.first_seen, c.last_seen, ip.reputation`
4. **Q:这个外部 IP 背后是不是某域名?** → 图:`MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress {ip:$ip}) RETURN d.fqdn, d.reputation, d.first_seen`

**误报/良性场景(null hypothesis)**:
- **PowerShell/脚本正当外连**:DevOps 调 REST API、`Invoke-WebRequest` 拉包、包管理经代理。区分:目标是内部制品库/已知供应商域、账号是 CI/服务账号、命令行明显运维意图。
- **rundll32/regsvr32 的正常联网**:某些合法软件用它们;但直接外连外部 IP 罕见。区分:目标信誉、父进程是否可信安装器。
- **企业出网强制走代理**:所有外连 `dest_port`=代理端口(3128/8080)且目标=内部代理 IP——**易被当"非标准端口 C2"**。区分:`IPAddress.type`=内部、目标就是已知代理。
- **非标准端口的正当业务**:数据库/消息队列/被管设备(22/1433/3306/5672/8443)、协作软件动态端口。区分:目标是内部或已知 SaaS、进程是对应客户端。

**判定逻辑(证据组合 → verdict)**:**罕见进程 + 外部目标 + (非常用端口 或 目标信誉差/新域) + 反复性/可疑父链** → **TP**。仅"非标准端口"单条件 → 高 FP,必须叠加**发起进程异常**或**目标可疑**。企业强制代理环境下"非标准端口"这条几乎作废——应改判"进程是否本该联网 + 代理外目标信誉"。可操作:LOLBin 外连**外部** IP 即使单次也升级为**可疑待定**并拉父链;叠加目标信誉差/新域即 TP。

**经验层复用**:目标 IP/域名历史 Verdict(封过/判过 TP → 直接 TP);该 LOLBin 在其它主机是否也有"进程→外部"异常(形态弱匹配横向佐证)。

**⚠️图盲区**:代理之后真实外部目标(T1090 经代理的真实 C2 落点在 host-only 下取不到)、协议 vs 端口错配(无 DPI,判不了"443 跑的不是 TLS")、`dest_port` 之外无四元组(无源端口/字节量/时长)、`reputation` 多半空。

### Ingress Tool Transfer(网络维度)(T1105,网络层)

**攻击本质**:从外部拉取二阶段载荷/工具(`certutil`/`bitsadmin`/`curl`/`powershell -c IWR`)。主机层同技战术已从"下载进程+落盘"判;网络层从**外连目标(IP/端口/域名信誉)**侧补强。

**触发逻辑(我们栈)**:EID3——下载类进程向**外部** `IPAddress` 发起连接(常 80/443,或直连 IP 无域名);EID22——同进程先查了一个新/低信誉域。与主机层 EID1(下载命令行)、EID11(落盘)交叉。

**研判决策树**:
1. **Q:是不是"下载工具类进程"在对外连接?** → 图:
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process)
   MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress)
   WHERE ip.type='public'
   RETURN p.image, p.command_line, ip.ip, ip.reputation, ip.asn, ip.geo, e.dest_port
   ```
2. **Q:目标是直连裸 IP 还是有域名?信誉与新鲜度?** → 证据:直连**裸 IP(无 `RESOLVES_TO` 域名)**下载 = 更可疑;`Domain.first_seen` 新 = 加权。 → 图:`MATCH (ip:IPAddress {ip:$ip}) OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip) RETURN ip.reputation, d.fqdn, d.reputation, d.first_seen`
3. **Q:命令行/父链坐实下载意图吗?** → 证据:`command_line` 含 URL / `IWR` / `DownloadString` / `-urlcache`;父链是脚本宿主/Office。 → 图:`MATCH (parent:Process)-[:SPAWNED]->(p:Process {process_guid:$pg}) RETURN parent.image, p.command_line`

**误报/良性场景(null hypothesis)**:
- **`certutil`/`bitsadmin` 正当用法**:certutil 校验证书、BITS 正常传输更新——但从外部 URL 拉文件罕见。区分:目标信誉、命令行是否 `-urlcache -f`。
- **`curl`/`powershell IWR` 运维取包**:管理员/CI 拉制品、装依赖。区分:目标=内部制品库/已知供应商、账号=服务/运维账号。
- **浏览器/更新程序正常下载**、**安全工具自身下载规则/情报**。区分:进程已知、目标自家/供应商。

**判定逻辑(证据组合 → verdict)**:**下载类进程 + 外部目标(尤其裸 IP 或新域/低信誉) + 可疑父链/下载命令行** → **TP**。仅"certutil/curl 外连"单条件 → 中高 FP,必须叠加**目标可疑**或**可疑父链**。裸 IP 直连下载 + LOLBin + 非浏览器父链,即便信誉字段空也判**可疑待定→TP 倾向**。

**经验层复用**:目标 IP/域名封禁史(payload 分发点常复用);该下载进程形态在其它主机的历史处置。

**⚠️图盲区**:载荷本身不可见(网络侧无字节量/文件大小/哈希,落地取证要靠主机层 EID11)、URL 路径/UA/Referer/MIME 无、TLS 内容无、`reputation` 多半空。

### 横向移动(网络维度)(T1021 SMB/RDP/WinRM,网络层)

**攻击本质**:攻击者用已控凭据在**内网主机间**跳转,走 SMB(445)/RDP(3389)/WinRM(5985/5986)。网络维度看**内网主机对主机的异常管理端口连接**,须与主机层**登录事件**联合坐实(Type3 网络登录 + 445/5985 关联是 T1021 核心)。

**触发逻辑(我们栈)**:EID3——源主机进程 `CONNECTED_TO` 一个**内部** `IPAddress`(`HAS_IP` 属某 `Host`)且 `dest_port` ∈ {445,3389,5985,5986};与 4624 **`logon_type=3`** / RDP 的 type10 在目标主机上按 IP + 时间关联;`AUTHENTICATED_TO` 给出"谁、从哪、到哪"。异常 = **平时不发起管理连接的源主机/账号**、**扇出多台目标**、**发起进程异常**(`powershell`/`wmic`/`psexec`/`cmd` 而非 `mmc`/`mstsc`)。

**研判决策树**:
1. **Q:源主机→目标主机的哪个管理端口?目标是内部资产吗?** → 图:
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process)
   MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress)
   MATCH (e)-[:ON_HOST]->(src:Host)
   OPTIONAL MATCH (dst:Host)-[:HAS_IP]->(ip)
   WHERE e.dest_port IN [445,3389,5985,5986]
   RETURN src.hostname, p.image, ip.ip, dst.hostname, dst.role, dst.criticality, e.dest_port
   ```
2. **Q:目标主机上有没有对应的网络登录(4624 type3 / RDP type10),哪个账号、从哪个源 IP?**(关键关联,坐实"连接→成功登录")→ 图:
   ```cypher
   MATCH (auth:Event {event_code:'4624'})-[:BY]->(acct:Account)
   MATCH (auth)-[:AUTHENTICATED_TO]->(dst:Host {hostname:$dst})
   OPTIONAL MATCH (auth)-[:FROM]->(srcip:IPAddress)
   OPTIONAL MATCH (auth)-[:PRODUCED]->(ls:LogonSession)
   WHERE ls.logon_type IN [3,10]
   RETURN acct.sam, srcip.ip, ls.logon_type, auth.event_time ORDER BY auth.event_time
   ```
3. **Q:这个账号/源主机平时就干管理吗?扇出多台?** → 图:
   ```cypher
   MATCH (acct:Account {sam:$sam})<-[:BY]-(auth:Event {event_code:'4624'})-[:AUTHENTICATED_TO]->(h:Host)
   WHERE auth.event_time > $since
   RETURN count(DISTINCT h) AS host_fanout, collect(DISTINCT h.hostname)
   ```
4. **Q:发起进程/父链是不是攻击工具形态?** → 图:`MATCH (parent:Process)-[:SPAWNED]->(p:Process {process_guid:$pg}) RETURN parent.image, p.image, p.command_line`(`services.exe`→远程装服务=PsExec 味;`wsmprovhost`/`wmiprvse` 派生 = WinRM/WMI 横向)

**误报/良性场景(null hypothesis)—— 内网 445/5985 正常管理流量极多,本告警最大噪声源**:
- **管理跳板/运维站日常管理**:admin 从堡垒机对多台 445/5985。区分:源主机 `role`=jump/admin、账号是已知管理账号、目标集合稳定。
- **域控/成员机 SMB 基础流量**:SYSVOL/NETLOGON、组策略、`\\dc\share`、打印/文件共享。区分:源/目标是 DC 或文件服务器、账号是机器账号/普通用户日常。
- **配置管理/补丁**(SCCM、WSUS、Ansible/WinRM、DSC):批量 5985 扇出多台**就是**其工作方式——**极易误判为横向扩散**。区分:源=管理服务器、账号=服务账号、目标=受管资产全集。
- **监控/备份/AV 拉取**走 SMB/WinRM 采集;**漏洞扫描器**对全网 445/3389/5985 探测。区分:进程=对应 agent / 源=扫描器主机。

**判定逻辑(证据组合 → verdict)**:**异常源(非管理站/非服务账号) + 管理端口连接 + 目标侧成功网络登录(type3/10) + (账号或源的目标扇出突增 或 发起进程是攻击工具形态 或 使用非常规凭据)** → **TP(横向移动)**。仅"内网 445/5985 连接"单条件 → **极高 FP**,必须叠加**"平时不这么连"的基线偏离** + **成功登录关联** + **进程/账号异常**。可操作:新出现的"源主机×账号×目标"三元组 + type3 成功 + 短时扇出≥N 台 + 发起进程为 `powershell/wmic/psexec/cmd` → TP。**注意 IP 是弱键**——EID3(源侧)与 4624(目标侧)跨主机对齐要靠 IP+时间窗,NAT/多网卡下可能错配,尽量用 `HAS_IP` 把 IP 归到 `Host` 再按 `asset_id`(强键)对齐。

**经验层复用**:源/目标 IP、涉事账号历史 Verdict;已知管理站×服务账号的路径若历史反复 FP → 建立"合法管理路径"白名单式收敛。

**⚠️图盲区**:EID3↔4624 跨主机关联靠弱键 IP + 时间(无流级会话 ID 硬绑定)、端口≠协议/操作(445 上分不清"读共享 vs PsExec 装服务 vs SMB 漏洞利用",需 5140/5145/7045 主机日志)、无 NetFlow 四元组/字节量/时长、失败连接/被拒(EID3 记发起,未必反映连接结果)。

### 网络层·模型缺口汇总 + host-only 天花板

**A. 去重后的⚠️图盲区**:① `reputation` 字段大概率为空(目标可疑度近乎失明);② 信标节律精度(jitter 显著性、多重周期、去抖主频、长周期/sleep-mask 需长留存+事件不下采样);③ 流/包级四元组(字节量、时长、方向、源端口、inter-arrival);④ DNS 深度特征(记录类型、响应、子域熵、NXDOMAIN、TTL);⑤ TLS/JA3/SNI/证书/HTTP 元数据;⑥ 代理后真实落点、445 上 SMB 操作级语义;⑦ EID3 与 4624 跨主机只能靠弱键 IP+时间。

**B. 不加探针也能做的图侧增强**:
- **给 `IPAddress`/`Domain` 接真实威胁情报**:填 `reputation`(分值/分类/来源/时效)、`first_seen_global`、DGA 判定标志——**当前性价比最高的补强**,直接激活"目标可疑度"整环。
- **聚合边加信标周期摘要**:在 `CONNECTED_TO`/`QUERIED` 聚合边补 `interval_median`、`interval_cv`、`dominant_period`、`jitter_est`——让"周期性"不必每次回拉全序列。
- **补主机侧已有但未入图的事件谓语**:SMB 共享访问(5140/5145)、服务安装(7045)、显式凭据(4648)、NTLM(4776) 建成对应事件/谓语——横向移动"操作级语义"立刻上台阶(属数据接入,非探针)。
- **事件节点补 Sysmon3 已有字段**:`source_port`、`initiated`、`protocol`、`dest_hostname`(目前只用了 `dest_port`)。

**C. host-only + Sysmon 下"能判到什么程度" vs "必须靠探针"**:
- **能判**(当前栈够用):粗粒度**周期性外连/DNS beacon 的存在性**、**罕见进程/LOLBin 外连**、**下载类进程对外拉取**、**内网管理端口异常 + 登录关联的横向移动**——即"**哪个进程、连了谁、多规律、进程正不正常**"这条主机中心链,配合真实 TI 后可达可用 TP/FP 分离。
- **必须靠加探针(NDR/Zeek/NetFlow/DNS 全量)**:加密 C2 的 TLS/JA3 指纹与"端口≠协议"识别、DNS 隧道的记录类型/熵/响应、beacon 字节量/请求-响应大小比、数据外带体量、代理后真实目标、流级会话把连接与登录硬绑定、无 agent 覆盖设备的网络行为。**这是 host-only 主机遥测的原理性天花板,不是调阈值能补的——信标的"存在与嫌疑"我们能报,信标的"内容与确证"要探针。**

---

## 6. 跨层模型缺口 · 统一优先级(本文核心副产物)

> 把四层的"缺口汇总"去重、跨层合并、按**投入产出**排序。这是从"要能研判"倒推"图/告警/采集还差什么"的**行动清单**,直接指导下一步补图模型(`graph_model.json` + mapper)、补 Wazuh 告警字段、补采集配置。
> **类型**:`富化`=接外部情报/打标(不改采集);`接入`=Sysmon/Wazuh 已有字段,只需入图(改 mapper);`模型`=改 v3 schema(加实体/属性/谓语);`探针`=host-only 原理上取不到,须加 NDR/Zeek 才有。

### Tier 1 — 最高性价比(便宜、解锁面最广,先做)

| ID | 缺口 | 影响的告警 | 类型 | 建议 |
|---|---|---|---|---|
| G1 | **IPAddress/Domain `reputation` 是空的** —— 目标可疑度整环失明 | 应用(源IP)、网络(C2目标)、主机(T1105 目的) | 富化 | 接威胁情报(GreyNoise/AbuseIPDB/OTX/自建)填 `reputation`+`asn_owner`+`is_known_cdn`+`first_seen_global`。**一补激活三层的"目标可疑"判据**。 |
| G2 | **WAF 请求侧字段未实体化**:HTTP 响应码/响应体大小、method、payload/matched_var、UA | 应用全 5 类 | 接入 | 把这些提为 WAF 触发事件(HTTP 请求 `:Event`)的标量 / Alert 属性。响应码=判"得手 vs 被拦"的头号证据,ROI 最高。 |
| G3 | **Process 无签名/发布者/哈希** —— 白名单只能按 image 路径,易被同名伪装绕过 | 主机全 4 类(LSASS/T1105/持久化/LOLBin)、网络(发起进程) | 接入 | 给 `Process` 加 `sha256`/`signed`/`signer`/`is_lolbin`(Sysmon EID1 原生带镜像哈希与签名,只需入图)。 |
| G4 | **身份/资产标记缺失**:DC、同步账号、扫描器、蜜罐、跳板、服务账号、tier | 身份/网络所有 null-hypothesis 白名单 | 富化 | Host 加 `is_domain_controller`;Account 加 `is_sync_account/is_scanner/is_decoy/is_service/tier`。把"先证伪"从经验层兜底变图内一等属性。 |

### Tier 2 — 让高价值告警从"只能升级 suspicious"变"图内可自动定性"

| ID | 缺口 | 影响的告警 | 类型 | 建议 |
|---|---|---|---|---|
| G5 | **证书 SAN + 请求者↔主体 mismatch** —— ESC1/ESC6 头号判据 | ADCS T1649 | 模型+接入 | `Certificate` 加 `san`/`san_upn`;4887 告警补 SubjectAltName;主体≠请求者派生 `IMPERSONATES` 边。 |
| G6 | **证书模板 EKU / ENROLLEE_SUPPLIES_SUBJECT / 需否审批** | ADCS T1649 | 模型 | 新增 `Template` 实体(`eku[]`/`enrollee_supplies_subject`/`vulnerable_esc[]`),经 `USES_TEMPLATE` 关联。 |
| G7 | **4624 认证包 + KeyLength + 冒充级别** —— PtH 首要签名 | 横向 T1550 | 接入 | Authentication 事件加标量 `auth_package`/`key_length`/`impersonation_level`。 |
| G8 | **票据生命周期 / renew-till** —— 金票判据 | 横向/金票 | 接入 | 4768/4769 事件加 `ticket_lifetime`/`renew_till`。 |
| G9 | **call_trace / granted_access 语义化**(现为原始串) | LSASS T1003.001、注入 | 接入 | 解析 `call_trace`→模块列表+`has_dbghelp`/`has_unbacked`;`granted_access`→位标志。 |
| G10 | **缺一批高价值事件谓语**:5136(ACL改)、5140/5145(SMB共享访问)、7045(服务安装)、4648(显式凭据)、4776(NTLM) | DCSync 前置链、横向操作级语义、PtH | 接入 | 谓语登记表加对应行(如 5136→`MODIFIED_ACL`)。**纯数据接入、不加探针,横向/DCSync 立刻上台阶**。 |

### Tier 3 — 结构性增强(改 schema / 建强关联)

| ID | 缺口 | 影响 | 类型 | 建议 |
|---|---|---|---|---|
| G11 | 聚合边缺**信标周期摘要** | 网络 C2/beacon | 模型 | `CONNECTED_TO`/`QUERIED` 聚合边加 `interval_median`/`interval_cv`/`dominant_period`/`jitter_est`,免每次回拉全序列。 |
| G12 | **应用↔主机请求级强绑定**(现仅"同 Host+时间窗"弱推断) | Webshell/RCE 因果归因 | 模型 | Web 层与 Sysmon 层共享 `request_id`,在两个 `:Event` 间建直接边,消同窗归因歧义。 |
| G13 | **落地文件哈希/信誉**(`File.sha256` 常空) | T1105、持久化、webshell | 接入+富化 | 启用 Sysmon FileCreate 哈希;`File` 加 `reputation`/`signed`。 |
| G14 | **4768/4769 ↔ 成员机 4624 硬键**(现靠账号+时间弱关联) | 银票(缺 TGT) | 模型 | 令票据事件与登录事件共享 `LogonSession`(`logon_guid`),把"缺 TGT"从启发式变硬连接。 |
| G15 | **WAF 请求事件建模未定**:HTTP 请求→Uri 的谓语不在登记表(本文用 `TARGETED` 占位) | 应用全层落地前提 | 模型 | 在 verb_registry 定死 WAF 触发事件如何 materialize + 用什么谓语连 `Uri`/`Service(web)`。**应用层 playbook 落地的第一块砖**。 |

### 天花板 — 图侧补不了,须加探针(记录在案,不在当前范围)

加密 C2 的 **TLS/JA3/SNI 指纹**、**DNS 隧道**的记录类型/子域熵/响应/NXDOMAIN、beacon 的**字节量/请求-响应大小比**、**数据外带体量**、**代理后真实落点**、**流级会话把连接与登录硬绑定**、无 agent 覆盖设备的网络行为 —— 这些是 host-only + Sysmon 的原理性盲区,要 NDR/Zeek/NetFlow 才有。**结论**:网络层我们能报"存在与嫌疑",要"内容与确证"须上探针;这是产品路线选择,不是 bug。

---

## 7. 对建研判 Agent 的启示(承上启下)

这份 playbook 不只是文档,它直接定义了 **Agent 该怎么建**:

1. **Agent 有章可循,不靠裸 LLM 发挥**:§1 的**五步判序**(先证伪→看基线→看权限→看时序→看落地)是所有告警共用的**方法论**,应注入 system prompt;每类告警的**决策树 + Cypher pivot**是**分技战术的行动库**,按告警的 `technique_id` 取用。第一版可以先把这套方法论 + schema 注进提示,让 LLM 自己按 playbook 查图;成熟后把决策树固化为工具/子流程。

2. **判定是结构化的,不是一句话**:每类都有明确的 **TP / FP / suspicious 三档** + 可操作阈值。Agent 的输出契约应是 `verdict ∈ {true_positive, false_positive, benign, suspicious} + confidence + rationale + 引用的关键证据(事件/实体)`,与经验层 `Verdict` 节点结构对齐,研判完**写回图**。

3. **跨层是核心能力,不是加分项**:最有价值的坐实几乎都靠跨层——应用→主机(webshell 落盘/RCE 派生 shell)、身份→主机(登录会话→进程)、网络→主机(发起进程→父链)。Agent 必须能顺**共享实体 + 聚合边**做跨层 pivot,单层判几乎都停在"尝试/嫌疑"。

4. **诚实的"证据不足"是特性,不是失败**:§6 的图盲区意味着 Agent 常会遇到"关键判据取不到"(如 ADCS 无 SAN、应用无响应码)。此时正确行为是**输出 suspicious/证据不足 + 明确说缺什么**,而不是硬判 TP/FP。Agent 要能把"缺的证据"报出来——这既是研判质量,也持续反哺 §6 的补图优先级。

5. **经验层复用 = 自进化的抓手**:每类 playbook 都有"从涉及实体一跳看历史 `Verdict/Disposition`"这一步。Agent **第一版就要接上**这个查询(先例召回)并在研判完写回,越用越准——这正是把图放在服务器、让 Agent 只跟图交互的意义。

> **下一步**:据此在 `soc-agent`(server2)起研判 Agent 的 walking skeleton —— LLM 客户端(`trust_env=False`)+ `query_graph(cypher)` 工具(打 server1 Neo4j)+ 本 playbook 的方法论/schema 注入 + 经验层写回。先点亮"喂一条真告警 → 按 playbook 查图 → 出结构化 verdict → 写回"的端到端闭环。

