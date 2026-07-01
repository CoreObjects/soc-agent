# 告警研判方法学 · 四层调研报告（存档）

> **来源**：deep-research harness（105 agents · ~3.6M tokens · 5 搜索角度 · 23 源 · 114 claims → 25 验证 → **21 确认 / 4 否证 / 0 未决**）。所有结论经 3 票对抗式验证（2/3 反驳才淘汰）、带出处。
> **用途**：这是一次昂贵调研的**持久存档**，避免重复研究。构建"全场景图模型 / 研判 Agent"的需求依据。
> **调研问题**：企业 SOC 在应用/网络/主机/身份四个遥测层级分别怎么研判告警？各层主流告警类型、研判工作流、证据需求；三类方法（A 行为取证 / B 经验情报 / C 关联富化）在各层的分布；并反推统一知识图谱应覆盖的实体/关系/取证场景。

---

## 0. 一句话总览

企业 SOC 在四个遥测层级的研判方法呈现清晰的"方法类型分布梯度"：**应用层**最偏经验库与业务基线判定；**网络层**三类方法均衡（DNS 信标同时用行为模式、情报信誉、样本逆向三路径——FIRST 官方）；**主机层**以行为取证为绝对主导（父子进程链 + 命令行还原 kill-chain——Red Canary 最高命中检测器即此）；**身份层**是认证序列异常检测（"TGS 后无后续"判 AS-REP、"TGS 前无 TGT"判 PtT——HADES），并需与主机遥测经 logon GUID/session ID 融合。标准研判工作流是 5–6 阶段流水线（接入→初判→富化→定级→处置）。要支撑跨四层、覆盖尽量多告警类型的统一研判，知识图谱必须**同时建模实体与关系**、收敛到少数规范维度（资产—技术—对抗措施骨架）、并以**共享连接键**（logon session、时间戳、ATT&CK 数据源、target-ip）做跨源关联，而非按单一场景定制。

---

## 1. 四层研判方法分布梯度（核心结论）

| 层级 | 主流告警 | 研判方法（主导） | 关键证据/字段 | 信心 |
|---|---|---|---|---|
| **应用层** | SQLi/XSS/认证绕过/OWASP、Webshell | **偏 B 经验库**：签名 + IP/域信誉 + 业务基线 + 白名单 | HTTP 方法/URI/参数/UA、WAF 命中(rule_id/payload)、IP/域信誉、业务基线 | 低（证据最薄） |
| **网络层** | DNS 信标/C2、异常外连、横向 | **A+B+C 均衡**：行为模式 + 情报信誉 + 样本逆向（FIRST 官方三路径） | DNS 日志、NetFlow/IPFIX、Zeek、PCAP、C2 域名/IP 情报 | 高 |
| **主机层** | 服务执行/可疑进程、凭据转储、持久化 | **偏 A 行为取证**：父子进程链 + 命令行还原 kill-chain | Sysmon EID1/3、4688(含命令行)、ProcessGuid、父子关系、文件/注册表 | 高 |
| **身份层** | Kerberoast/AS-REP/PtT/PtH/DCSync/委派 | **A+C 认证序列异常 + 跨层融合** | 4768/4769/4624/4662、logon GUID/session ID、票据、Sysmon | 高（单一学术源） |
| **富化（横切）** | 所有层 | **B+C**：资产上下文 + 身份基线 + 情报信誉 | 关键度/属主/OS/网段；角色/部门/时段/地理/历史；VT/AbuseIPDB/OTX/Shodan | 高 |

> 用户经验被证实：应用层确实偏"查经验库/判是否正常业务"，主机层确实偏"行为取证还原攻击"。

---

## 2. 经对抗验证确认的 9 条结论（带证据与出处）

### F1 · 网络/DNS 层横跨三类方法（信心：高，票 3-0/2-1/3-0）
FIRST 官方对 DNS 信标明确给三条互补研判路径：(A) 对常规 DNS 查询做行为模式分析、(B) 比对已知恶意 DNS 服务器与 C2 域名情报信誉、(C) 逆向恶意样本发现信标域名。ATT&CK 本体把网络层技术下钻到 Zeek 日志、NetFlow、SPAN 抓包、PCAP；Network Connection Creation 同时映射 Sysmon EID3（主机）与 Zeek conn.log（网络）——证明网络层可与主机层共用一套本体。
**证据需求**：DNS 查询日志、解析器日志、C2 域名情报、NetFlow/IPFIX、Zeek、PCAP。
**源**：first.org/DNS-SIG · attack.mitre.org DS0029/DC0078/DC0085 · arxiv 2502.10825

### F2 · 主机层以行为取证还原为绝对主导（信心：高，票 2-1/3-0/3-0/3-0）
分析师发现可疑进程后，沿父子关系跨多代追溯还原发生了什么；最高保真检测就是父子进程行为模式（`parent==services.exe && process==cmd.exe && cmdline 含 echo|'/c'` = PsExec/smbexec 命名管道签名），而非 IP/域信誉。**核心实体=进程，核心关系=parent-of**。还原进程树最小数据源 = Sysmon EID1 或 Windows Security 4688（需开命令行）；方法=把返回的 pid 迭代当作下次搜索的 parent pid。
**字段需求**：ParentImage/Image/ParentProcessId/ProcessId/CommandLine（更稳健用 ProcessGuid）。方法分布：行为取证 >> 情报信誉（文件哈希→VT 为辅）。
**源**：redcanary.com/threat-detection-report/service-execution · lantern.splunk.com（进程父子可视化）

### F3 · 身份/AD 层 = 认证序列异常检测 + 与主机层融合（信心：高，票 3-0×3）
对每个认证事件做前向/后向追溯，按 Kerberos 期望序列检测异常——**"TGS 请求后无后续"判 AS-REP Roasting、"TGS 前无 TGT"判 Pass-the-Ticket**。研判需从域控采认证日志 + 每台主机登录日志，经 **logon GUID** 关联，再与 Windows Security + Sysmon 经 **logon session ID** 融合成全网溯源图。HADES 核心创新"logon session based execution partitioning"：用登录会话把进程归属到某认证会话，做因果跨机追溯——一台机器用户登入另一台时，第二台 logon session 由第一台某 logon session 派生，支持 cross-machine forward/backward tracing。溯源图节点 = AD 实体（users, machines）+ 系统实体（processes, files, network sockets, logon sessions）。
**数据需求**：域控认证日志、主机登录日志、4768/4769/4624、Sysmon；**连接键 = logon GUID / logon session ID**。
**源**：arxiv 2407.18858（HADES）

### F4 · 应用层偏"查经验/特征库判是否正常业务"（信心：低，票 3-0 但仅博客源）
WAF 告警按来源归类：SQLi/XSS/认证绕过/OWASP Top 10，与主机 EDR、网络 IDS 并列。该层研判更偏签名匹配 + IP/域信誉 + 业务基线 + 白名单，而非主机式行为链取证。**局限**：本轮应用层是覆盖最薄的一层，"偏经验库"部分来自研究问题自身框架而非独立强主源。
**源**：inventivehq.com/blog/soc-alert-triage

### F5 · 标准研判工作流 = 5–6 阶段流水线（信心：中，票 3-0×3 但厂商/博客源）
Rapid7（厂商）：**告警接入 → 初步验证/分类 → 上下文富化 → 优先级/严重度评估 → 处置决策**，目标是"基于现有证据快速决策而非穷尽调查"。inventivehq 扩为 6 阶段带时间预算（初判 1-5min、富化 5-15min、影响评估 10-30min、调查取证 30min-4hr、遏制上报 15-60min、文档 15-30min），映射 NIST 800-61r2 + SANS。**注意**：分钟预算是博客自造，NIST/SANS 本身不规定。
**源**：rapid7.com/soc-alert-triage · inventivehq

### F6 · 三类方法（A 行为取证 / B 经验情报 / C 关联富化）独立且分布随层迁移（信心：高，票综合）
富化阶段本身就把"情报信誉查询"与"资产/身份关联富化"区分为两类独立证据：资产上下文（关键度/属主/OS/补丁/网段）、用户身份基线（角色/部门/时段/地理/历史）、威胁情报信誉（VT/AbuseIPDB/OTX/Shodan）。**分布**：应用层偏 B，主机层偏 A，身份层偏 A+C，网络层三类均衡，富化阶段集中体现 B+C。
**源**：rapid7 · inventivehq · first.org · arxiv 2407.18858 · splunk

### F7 · 调查/取证阶段按层规定证据源（信心：中）
端点（EDR/Sysmon/Windows Event Log——进程父子、文件/注册表修改、登录/注销）、网络（防火墙/代理/DNS/VPN/NetFlow）、邮件（头部/附件哈希/SPF/DKIM/DMARC）、云（CloudTrail/Azure/GCP IAM）。此为统一 KG 的跨层取证场景清单。
**源**：inventivehq（+socautomators/prophetsecurity/cyberdefenders 佐证）

### F8 · 统一知识图谱必须建模实体+关系、收敛到规范维度（信心：高，票 3-0×5）★
一个统一（而非场景定制）的安全知识图谱必须**同时建模实体类型与关系类型**（节点+边，非仅实体清单），收敛到少数规范维度：漏洞/攻击/防御三维；实体={漏洞,工具,技术,组织,资产}、关系={discovers,uses,causes,reflects,mitigates,solves}（TRACE，注：此为抽取子集，全图 56 节点类型/112 边类型）；威胁建模骨架=资产—ATT&CK 技术—防御/对抗措施（enterpriseLang/MAL）；并把异构告警/数据模式映射进一套统一本体（UCO 映射 STIX/CVE/CVSS/CAPEC/CybOX/KillChain）。LADDER 抽取实体+关系三元组构建 CTI 图。
**源**：arxiv 2602.11211(TRACE) · 2502.10825(enterpriseLang) · UMBC 781.pdf(UCO) · 2407.18858(HADES)

### F9 · 跨层关联靠"共享连接键/溯源"缝合异构证据（信心：高，票 3-0×4）★
支撑"跨层、非场景定制"的关键机制是跨源关联：UCO 规则把外部 web 文本、产品版本、运行进程、扫描日志、外连端口按时序融合推断攻击；HADES 用 **logon session ID** 把身份层认证与主机层进程溯源缝成全网因果图；ATT&CK 用统一本体把主机（Sysmon/Windows）与网络（Zeek/NetFlow/PCAP）遥测桥接。**连接键**：logon session、时间戳时序约束、ATT&CK 数据源/组件、资产与身份标识。**含义**：统一 KG 的价值在于关系与连接键使跨层关联成为通用能力，而非为每场景重写规则。
**源**：UMBC 781.pdf · arxiv 2407.18858 · 2502.10825

---

## 3. ⚠️ 被否证的 4 条（不要采信，避免误用）

1. **【0-3 否】UCO 的具体实体类清单**（Means/Consequences 及 BufferOverflow/SynFlood/PortScan 等子类、DenialOfService/PrivilegeEscalation 等）——**不要照抄 UCO 细类清单**；统一 KG 的实体清单以 TRACE/enterpriseLang 的规范维度为准，我们自定义最小充分集。
2. **【1-2 否】ATT&CK 技术→数据源→缓解 的具体路径推理示例**（如 APT41 T1190→DS0015→M1051→CAR-...）——不要当强结论。
3. **【0-3 否】"每条告警初判即映射到 ATT&CK 战术、并有 类别→战术→优先级 对照表"**——非普遍标准做法。
4. **【0-3 否】某"五阶段告警研判固定序列"表述**（networkershome 版）——工作流阶段划分各源不一，不要当唯一标准。

---

## 4. 空白与注意（caveats）

1. **覆盖不均**：应用层（WAF/API）是本轮最薄的一层；身份层几乎全来自单一论文 HADES（arXiv 2407.18858），缺商业 ITDR/UEBA 产品侧佐证。
2. **源质量分层**：主机/网络/身份/KG 结论有学术主源与权威源（Red Canary/FIRST/MITRE/Splunk/UMBC/TRACE），置信高；工作流与按层证据源主要为单一博客 inventivehq（WebFetch 403，靠搜索复现），仅 medium/low。
3. **TRACE 的 5 实体/6 关系是抽取子集**（全图 56 节点/112 边），勿以子集代全集。
4. **时效**：TRACE(2026-02)、HADES(2024/2025) 为较新预印本，未大规模工程复现。

## 5. 待补研究（openQuestions）——尤其第 4 条与我们 PBC 40% 目标相关

1. 应用层研判的具体方法学：如何区分恶意 vs 正常业务流量（业务基线、白名单、参数画像、会话上下文），应用层告警需哪些确切字段与经验库结构？
2. 商业 UEBA/ITDR（相对学术 HADES）如何工程化落地身份层行为基线与偏离评分？与 HADES 的 logon-session 溯源图能否统一？
3. 跨四层统一 KG 是否存在被广泛认可、可直接落地的规范实体清单（UCO 细类已否）——各层关键实体（IP/域/进程/文件/注册表/用户/主机/logon session/票据/告警/IoC/ATT&CK 技术）与关系的最小充分集到底是什么？
4. **告警去重、聚合、时序关联、误报抑制**在跨层场景下的算法与工程实践（SIEM 关联规则 vs SOAR triage/enrichment vs 图上路径推理）——研究问题点名但本轮证据几乎空白。（★这是 PBC 里"攻击链视角告警聚合"目标，v2 需补专项研究。）

---

## 6. 来源清单（23 源，按质量）

**primary（主源）**：redcanary.com（Service Execution）· first.org（DNS 信标）· ebiquity.umbc.edu 781.pdf（UCO）· arxiv 2602.11211（TRACE）· arxiv 2407.18858（HADES）
**secondary**：lantern.splunk.com（进程父子）· rapid7.com（研判流水线）· arxiv 2502.10825（enterpriseLang）
**blog（佐证）**：inventivehq · networkershome · d3security(×2) · vectra.ai · cymulate · wazuh(AD 检测) · netwrix(ITDR) · splunk(Sysmon codes) · any.run(富化) · corelight(triage) · indusface(WAF 误报) · horizon3.ai(GOAD walkthrough) · adsecurity.org · labs.lares.com(ADCS)
