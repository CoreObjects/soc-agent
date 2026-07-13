# SOC Agent 覆盖清单(skills × 遥测依赖)

> **核心原则:skills 与遥测/环境无关。** 每个 skill 是一类告警的研判方法论 + 确定性取证脚本,它研判**图里到达的任何该类告警**,不关心告警来自哪种探测器、哪套部署。
>
> 因此"**休眠(dormant)**"= **对应遥测/检测尚未把这类告警送进图**,不是能力缺失。上游一旦产出该类告警,对应 skill 立即生效(可能需按真实数据微调 recipe,如已发生过的几例)。

## 全清单(16 skills)

| 层 | skill | 覆盖 technique | 依赖遥测(产出该类告警的前提) | 状态 | 已验证 |
|---|---|---|---|---|---|
| identity | **kerberoast** | T1558.003 | Kerberos 4769(RC4/0x17 TGS 请求) | active | ✅ FP 通路(跨域信任) |
| identity | **adcs** | T1649 | CA 审计 4886/4887 | active | ✅ suspicious/escalate |
| identity | dcsync | T1003.006 | DC 4662(目录复制权限) | dormant · 需 4662 检测 | — |
| identity | lateral_movement | T1550.002/003 · T1021.001/002/006 | 4624 登录型 + 票据/认证包 | dormant · 需登录/票据检测 | — |
| host | **lsass_dump** | T1003.001 | Sysmon EID10(进程访问 lsass) | active | ✅ FP 通路(安全代理自检) |
| host | **ingress_tool_transfer** | T1105 | Sysmon EID11(建文件)/ 外连 | active | ✅ FP 通路(配管供给噪声) |
| host | **suspicious_process** | T1059/.001 · T1055 · T1218 | Sysmon EID1/11 · PS 4104 | active | ✅ FP 通路(配管供给噪声) |
| host | registry_persistence | T1547.001 · T1112 | Sysmon EID13(注册表设值) | dormant · 需 EID13 检测 | — |
| network | c2_beacon | T1071/.001/.004 · T1568/.002 | NDR/Zeek,或主机 EID3/22 网络维度 | dormant · 需网络遥测/NDR | — |
| network | suspicious_outbound | T1571 · T1090 · T1041 · T1048 | NDR/Zeek,或主机 EID3 外连 | dormant · 需网络遥测/NDR | — |
| application | web_exploit | T1190 · T1059.007 | WAF 告警 / Web 访问日志 | dormant · 需 WAF 遥测 | — |
| application | webshell | T1505.003 | WAF + 主机侧落盘(Web 进程 WROTE) | dormant · 需 WAF/落盘遥测 | — |
| identity/host/application/network | **generic_\<layer\>** ×4 | 该层未覆盖类型的兜底 | 该层任意告警 | active(兜底) | ✅(deobfuscate 走 host 兜底/具体 skill) |

## 已验证 = 仅 FP 通路,TP 通路待真实攻击

上表"已验证"的 active skills,当前只在**噪声实例**上验过(配管供给 / 传感器自检 / 跨域机器账号)→ 结论都是 **false_positive / escalate**。**"判成 true_positive + 出处置"这条通路尚未在真机走通** —— 需要真实攻击告警流入才能验证(见 `soc-agent-v3-architecture-plan.md` 之后的 P2 收尾:通用采样挖存量真 TP + 补真攻击后研判,均为**观察**,SOC 侧不含任何环境特异逻辑)。

## 缺口与优先级

- **休眠 skill 的瓶颈在检测,不在 skill**:dcsync/lateral_movement/registry_persistence 需上游加对应检测规则(4662 / 4624+票据 / EID13);网络、应用两层需 NDR / WAF 探针。这些是**部署/检测侧**的事,skill 已就绪。
- **未覆盖但可能出现的攻击类型**(当前落 `generic_<layer>` 兜底,按通用五步判序研判;高频出现再升级为专门 skill):AS-REP Roasting(T1558.004)、Golden/Silver Ticket(T1558.001/002)、GPO 滥用(T1484)、NTLM 中继/强制认证(T1557)、委派滥用、SID History(T1134.005)、计划任务/服务持久化(T1053/T1543)。

## 如何新增覆盖

1. 新增 `skills/<layer>/<name>/SKILL.md`(设备无关的 `description` 供 LLM 路由 + 方法论)+ `recipe.py`(确定性取证)。
2. **绑定约束是上游遥测**:能不能收到这类告警,取决于探测器/检测规则是否产出它 —— 这不在本仓库,而在采集/检测侧。
3. skill 判别只用**通用模式**(如 `recipe_lib` 的 `security_agent`/`provisioning_noise`/`decode_chain`、跨域 TRUSTS 边),**绝不硬编码任何环境实例**(主机名/账号/IP)。
