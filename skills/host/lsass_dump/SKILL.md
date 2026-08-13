---
name: lsass_dump
layer: host
technique_ids: [T1003.001]
description: 研判 LSASS 凭据转储告警。当告警涉及"进程访问/读取 lsass.exe 内存""OpenProcess 拿 lsass 句柄""转储 LSASS/导出 NTLM 哈希或票据""mimikatz/procdump/comsvcs 抓密码"时选它。关键词 LSASS/credential dump/凭据转储/mimikatz/procdump/comsvcs/sekurlsa/GrantedAccess/进程内存读取。
needs: [process_access_telemetry, process_spawn_telemetry, file_write_telemetry, network_flow_telemetry]
---
# LSASS 凭据转储研判(T1003.001)

**攻击本质**:用 OpenProcess 拿 lsass.exe 句柄读其内存,导出 NTLM 哈希/Kerberos 票据/(WDigest 开时)明文口令,用于 PtH、横向、提权。

**触发**:进程访问事件(Sysmon EID10)且目标 = lsass.exe。触发事件在 seed:`(:Event)-[:BY]->源Process`、`-[:ACCESSED]->Process(lsass)`,标量 `granted_access`(工具指纹)、`call_trace`。

**grantedAccess 掩码语义(先读懂)**:关键看**是否含 `0x10`(PROCESS_VM_READ)** = 有人在读 LSASS 内存,才与凭据窃取相关。`0x1010`=Mimikatz sekurlsa;`0x1410`=ProcDump/任务管理器转储;`0x1438/0x143a`=含写位(注入类)恶意度最高;`0x1fffff`=ProcDump 全权限;纯 `0x1000/0x1400`(仅查询、无 0x10)基本良性。

## ★先看 recipe 已判好的一项:源进程是否安全代理
- **「源进程是否已知安全代理」= 是**(Wazuh/OSSEC/Defender/Sysmon/Beats)→ **头号 FP**:这类代理为做完整性检查/遥测会 OpenProcess 读进程内存,包括 LSASS。结合 `call_trace 指纹`:**不含转储库(dbghelp/dbgcore/comsvcs/UNKNOWN)且末端是系统/代理自身模块 → 判 false_positive**。
- ⚠️**绝不能因安全代理自身触发的告警去 kill/隔离该代理或其主机 —— 那等于把监控戳瞎。** 即便留疑,处置只能 `escalate`(人工加白名单)或 `monitor`,**禁止 disable_account/kill_process/isolate_host 作用于传感器或其主机**。

## 研判决策树
1. **源进程是安全/监控代理吗?**(recipe 已判)→ 是且 call_trace 无转储库指纹 → FP,到此为止。
2. **源进程是谁?掩码含 0x10 吗?**(recipe「源进程与访问掩码」)—— `csrss/wininit/lsm/wmiprvse/svchost` 系统进程 = 证伪;掩码无 0x10 = 降权。
3. **父子链正常吗?**(recipe「父进程链」)—— `services.exe→代理` 正常;`w3wp/powershell/cmd/rundll32→未知源` 恶意。
4. **调用栈可疑吗?**(recipe「call_trace 指纹」含转储库 = 强 TP)—— ⚠️ 是否已语义化未知。
5. **运行身份/权限?**(recipe「运行账号」)—— IIS AppPool/低权身份读 LSASS = 几乎必恶意。
6. **读完干了什么?**(recipe「读后行为」)—— 读后外连坏 IP/写 dump/派生 PsExec = 闭环 TP。

## 误报/良性场景(逐条证伪)
- **★HIDS/EDR/传感器自身**(Wazuh/OSSEC、Defender MsMpEng、Sysmon、Beats)读进程内存做遥测/完整性检查 —— **真企业头号 FP**,recipe 已把它判出来;call_trace 无转储库即 FP。**处置绝不动传感器。**
- **系统进程**(csrss/wininit/lsm/wmiprvse/svchost)常态查询 LSASS(多为无 0x10 的查询掩码)。
- **备份/凭据管理/APM**读进程内存;**管理员任务管理器/ProcDump 手动抓 dump**(0x1410/0x1fffff,父进程交互式)。

**★资产价值(补图第二弹)**:recipe「源进程与访问掩码」现带 `host_role`/`host_criticality`。在 `domain_controller`(读 DC 的 LSASS = 域凭据全暴露)/`certificate_authority` 上的真实转储 → 最高优先级。但资产价值**不改**"源进程是安全代理→FP"的判断,只影响真 TP 的紧急度。

## 判定逻辑
- **true_positive**:`granted_access` 含 0x10(尤其 0x1438/0x143a/0x1fffff)**且**源进程**非**安全代理、非白名单(cmd/powershell/rundll32/temp 路径)**且**(父链可疑 **或** call_trace 含转储库指纹 **或** 读后外连/横向)。
- **false_positive/benign**:源进程 ∈ 已知安全代理(且 call_trace 无转储库)**或** 系统进程且掩码无 0x10。
- **suspicious**:掩码含 0x10 但源进程签名可信/无后续恶意行为 → 挂起(⚠️签名是图盲区,写 missing_evidence)。

## ⚠️处置红线
源进程是安全代理/系统进程时,**禁止建议对该进程或其主机做 kill/isolate/disable**;至多 `escalate`+`monitor`。别拿传感器自身的信号去关传感器。

## 图盲区(取不到就写 missing_evidence)
源进程 EXE 签名/发布者/哈希(白名单只能按 image 路径,易伪装)、call_trace 是否已语义化、是否真落地 dump 文件及其哈希。
