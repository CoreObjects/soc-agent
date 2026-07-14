# SOC Agent 覆盖清单(skills × 遥测/检测 × 取证验证状态)

> **核心原则:skills 与遥测/环境无关。** 每个 skill 研判**图里到达的任何该类告警**,不认识探测器/部署。"休眠"= 对应遥测/检测尚未把这类告警送进图,不是能力缺失。
>
> **★取证(recipe)的验证只能靠真实数据。** recipe 是照方法论+图模型写的**假设**,对不对得等该类真告警流入才能验、且大概率要**校准**(已验的 5 个每个都被真数据校准过:死字段、跨域漏报等)。**合成 fixture 不算验证**(它拿我们脑补的图形状测 recipe,是套套逻辑、假信心)。

## 全清单(16 skills)

| 层 | skill | technique | 遥测/检测现状 | 取证验证状态 |
|---|---|---|---|---|
| identity | **kerberoast** | T1558.003 | ✅ 自研规则 100801(RC4 4769) | ✅ **真机验通**:FP(跨域机器账号引荐票)+ **TP**(vagrant 同域 roast;修过一个漏报) |
| identity | **adcs** | T1649 | ✅ 自研规则 100803(4886/4887) | ✅ **真机验通**:suspicious **带 lean 分诊**(subject_dn 比对;SAN 仍盲) |
| identity | dcsync | T1003.006 | ❌ 无检测规则 | ⚠️ **未校准假设**(取证未经真数据) |
| identity | lateral_movement | T1550.002/003 · T1021.* | ❌ 无检测规则 | ⚠️ **未校准假设** |
| host | **lsass_dump** | T1003.001 | ✅ 自研规则 100802(EID10) | ✅ **真机验通**:FP(安全代理自检)+ **TP**(comsvcs 转储) |
| host | **ingress_tool_transfer** | T1105 | ⚠️ 默认 Sysmon EID11 | ✅ **真机验**:FP 通路(配管供给噪声);TP 通路未见真样本 |
| host | **suspicious_process** | T1059/.001 · T1055 · T1218 | ⚠️ 默认 Sysmon EID1/11 · PS4104 | ✅ **真机验**:FP 通路(配管供给噪声);TP 通路未见真样本 |
| host | **registry_persistence** | T1547.001 · T1112 | ✅ 自研规则 100804(EID13 Run/自启位) | ✅ **真机验通**:取证正确(写入进程/键路径/值/账号/主机);顺带修了 ingest key_path 反斜杠归一 |
| network | c2_beacon | T1071/.* · T1568/.* | ⚠️ **日志够、缺告警**:EID3/22 已采+已映射(CONNECTED_TO/QUERIED);缺检测规则;信誉是盲区 | ⚠️ **未校准假设**(可靶场验:加规则+周期外连) |
| network | suspicious_outbound | T1571 · T1090 · T1041 · T1048 | ⚠️ 同上(日志够、缺告警+信誉盲区) | ⚠️ **未校准假设**(可靶场验) |
| application | web_exploit | T1190 · T1059.007 | ❌ **遥测缺**:WAF(ModSecurity)未接进 ingest | ⚠️ **未校准假设**(需先建 WAF 接入) |
| application | webshell | T1505.003 | ❌ WAF 未接;主机侧落盘(EID11)部分可用 | ⚠️ **未校准假设**(需先建 WAF 接入) |
| ×4 | **generic_\<layer\>** | 该层兜底 | 该层任意告警 | ⚠️ 路由从未选中、未行使 |

## 验证进度小结

- **已真机验+校准(6):** kerberoast · lsass_dump · adcs · ingress_tool_transfer · suspicious_process · **registry_persistence**(靶场完善 B1:良性发生器造 T1547.001 告警→取证验通,不造攻击)。其中 kerberoast/lsass_dump 的 TP 通路已用真攻击走通;adcs 用 subject_dn 分诊;registry_persistence 用良性 Run 键写入验取证。
- **未校准假设(10):** 6 个具体 skill(dcsync/lateral/c2/outbound/web/webshell)+ 4 个 generic。取证逻辑只过了"空图不崩"冒烟,**未经真实数据验证**。
- **验证方式:** 只在隔离靶场造出该类真告警去验(不裸上生产——生产研判错致命)。**不做合成 fixture**(假信心)。

## 各层"要造告警来验"的成本差

| 层 | 差什么 | 要做 |
|---|---|---|
| identity/host(dcsync/lateral/persistence)| 日志都在,**只缺检测规则** | 加规则(靶场/采集侧,不耦合 SOC)+ 靶场跑攻击 → 研判校准 |
| network(c2/outbound)| **日志够、只缺告警**(EID3/22 已映射);信誉是盲区 | 加信标规则 + 靶场跑周期外连 → 研判校准 |
| application(web/webshell)| **遥测都缺**:WAF 未接进 ingest | 先建 ModSecurity→图 接入(soc-graph-ingest 的一块新工程)|

> 检测规则/遥测接入都在**靶场/采集侧**,**不耦合通用 SOC**(SOC 按 description 路由、不认识规则 ID)。

## 未覆盖但可能出现的攻击(当前落 generic 兜底,高频再升级专门 skill)
AS-REP Roasting(T1558.004)、Golden/Silver Ticket(T1558.001/002)、GPO 滥用(T1484)、NTLM 中继/强制认证(T1557)、委派滥用、SID History(T1134.005)、计划任务/服务持久化(T1053/T1543)。

## 如何新增覆盖
1. 新增 `skills/<layer>/<name>/{SKILL.md,recipe.py}`(设备无关 description + 确定性取证)。
2. **绑定约束是上游遥测/检测**:能否收到该类告警取决于探测器/规则是否产出 —— 在采集/检测侧,不在本仓。
3. 判别只用**通用模式**(`recipe_lib` 的 security_agent/provisioning_noise/decode_chain、跨域 TRUSTS 边等),**绝不硬编码环境实例**。
